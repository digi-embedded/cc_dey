/*
 * Copyright (c) 2022 Digi International Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Digi International Inc., 9350 Excelsior Blvd., Suite 700, Hopkins, MN 55343
 * ===========================================================================
 */

#include <alloca.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "services_util.h"
#include "cc_logging.h"

/*
 * This module encapsulates the local tcp/ip communication between cc_dey and
 * processes that use DRM services via the connector.
 *
 * Messages are composed of a sequence of values that are serialised into the
 * stream and deserialised by the receiver.
 *
 * There are only three value basic types supported at this point in time:
 *
 * 	Integer
 * 	String
 * 	Binary Blob 	(opaque data)
 *
 * The current encoding targets the following goals:
 *
 * 	* Easy for a scripted client (eg a Bash script) to compose and parse. No
 * 	  endianess considerations, values terminated by new line '\n' characters.
 *
 * 	* Serialised value boundaries are verified so that loss of stream
 * 	  synchronisation is detected and doesn't cause mis-interpretation of
 * 	  serialised data.
 *
 * 	* The receiver can verify that the data type of any serialised value is
 * 	  exactly what was expected rather then relying on some implicit contract
 * 	  between sender and receiver.
 *
 * The encoding schema has a hint of the PHP serialisation format:
 *
 * 	<serised value> <=	<type><separator><value><terminator>
 * 				--	where <type> is a single character
 * 				--	'i' == Integer
 * 				--	's' == String
 * 				--	'b' == Binary blob
 * 	<separator>	<= :
 * 	<terminator><= '\n'
 * 	<integer>	<=	i<separator>{[+/-]ascii digits}<terminator>
 * 	<length>	<=	<integer>
 * 	<string>	<=	s<separator><length><'length' ascii chars><terminator>
 * 	<blob>		<=	b<separator><length><'length' bytes><terminator>
 *
 * So, an integer value 3645 would be encoded
 *
 * 	i:3645\n
 *
 * And a string "Hello World"
 *
 * 	s:i:11\nHello World\n
 *
 * Using '\n' as the terminator makes it easy for scripted clients reading line
 * by line input as well as Python clients using stream.readline() to parse the
 * stream.
 *
 * Having the prefix data length for strings and blobs allows their payload to
 * read in a single non-parsed binary read of length+1 then to verify that the
 * last byte read was a '\n' before discarding that byte.
 *
 * The only purpose of the String type vs blob is that it makes the intent of
 * functions like read_string() and write_string() clear. It also allows a
 * receiver expecting a string to ensure that a string was sent rather than
 * some unexpected mismatched data.
 *
 * All the functions required to read/write values from/to socket streams are
 * provided by this module.
 */

/* Serialisation Protocol constants */

#define	TERMINATOR	'\n'
#define SEPARATOR	':'

/* Data types ... */

#define	DT_INTEGER	'i'
#define	DT_STRING	's'
#define	DT_BLOB		'b'

/* Upper protocol constants */

#define RESP_END_OF_MESSAGE	0
#define RESP_ERROR			1

#define concat_va_list(arg) __extension__({		\
	__typeof__(arg) *_l;				\
	va_list _ap;					\
	int _n;						\
							\
	_n = 0;						\
	va_start(_ap, arg);				\
	do { ++_n;					\
	} while (va_arg(_ap, __typeof__(arg)));		\
	va_end(_ap);					\
	_l = alloca((_n + 1) * sizeof(*_l));		\
							\
	_n = 0;						\
	_l[0] = arg;					\
	va_start(_ap, arg);				\
	do { _l[++_n] = va_arg(_ap, __typeof__(arg));	\
	} while (_l[_n]);				\
	va_end(_ap);					\
	_l;						\
})


const char *to_send_error_msg(ccapi_send_error_t error) {
	switch (error) {
		case CCAPI_SEND_ERROR_NONE:
			return "Success";
		case CCAPI_SEND_ERROR_CCAPI_NOT_RUNNING:
			return "CCAPI not running";
		case CCAPI_SEND_ERROR_TRANSPORT_NOT_STARTED:
			return "Transport not started";
		case CCAPI_SEND_ERROR_FILESYSTEM_NOT_SUPPORTED:
			return "Filesystem not supported";
		case CCAPI_SEND_ERROR_INVALID_CLOUD_PATH:
			return "Invalid cloud path";
		case CCAPI_SEND_ERROR_INVALID_CONTENT_TYPE:
			return "Invalid content type";
		case CCAPI_SEND_ERROR_INVALID_DATA:
			return "Invalid data";
		case CCAPI_SEND_ERROR_INVALID_LOCAL_PATH:
			return "Invalid local path";
		case CCAPI_SEND_ERROR_NOT_A_FILE:
			return "Not a file";
		case CCAPI_SEND_ERROR_ACCESSING_FILE:
			return "Error accessing file";
		case CCAPI_SEND_ERROR_INVALID_HINT_POINTER:
			return "Invalid hint pointer";
		case CCAPI_SEND_ERROR_INSUFFICIENT_MEMORY:
			return "Out of memory";
		case CCAPI_SEND_ERROR_LOCK_FAILED:
			return "Lock failed";
		case CCAPI_SEND_ERROR_INITIATE_ACTION_FAILED:
			return "Initiate action failed";
		case CCAPI_SEND_ERROR_STATUS_CANCEL:
			return "Cancelled";
		case CCAPI_SEND_ERROR_STATUS_TIMEOUT:
			return "Timeout";
		case CCAPI_SEND_ERROR_STATUS_SESSION_ERROR:
			return "Session error";
		case CCAPI_SEND_ERROR_RESPONSE_BAD_REQUEST:
			return "Bad request";
		case CCAPI_SEND_ERROR_RESPONSE_UNAVAILABLE:
			return "Response unavailable";
		case CCAPI_SEND_ERROR_RESPONSE_CLOUD_ERROR:
			return "Cloud error";
		default:
			log_error("unknown internal connection error: ccapi_send_error_t[%d]", error);
			return "Internal connector error";
	}
}

static int read_amt(int sock_fd, void *buf, size_t count, struct timeval *timeout)
{
	int ret;
	fd_set socket_set;
	ssize_t nr = 0;

	FD_ZERO(&socket_set);
	FD_SET(sock_fd, &socket_set);

	while (count > 0) {
		if (timeout) {
			ret = select(sock_fd + 1, &socket_set, NULL, NULL, timeout);
			if (ret != 1)
				return ret == 0 ? -ETIMEDOUT : ret;
		}

		nr = read(sock_fd, buf, count);
		if (nr <= 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		count -= nr;
		buf = ((char *) buf) + nr;
	}
	return (count > 0) ? -1 : 0;
}

static ssize_t read_line( int socket, void *buffer, size_t capacity, struct timeval *timeout )
{
	ssize_t bytes_read;
	size_t total_read = 0, remaining = capacity;
	char *buf = buffer, *end;
	char ch;
	int result;
	fd_set socket_set;

	if (capacity == 0 || buffer == NULL) {
		errno = EINVAL;
		return -1;
	}

	total_read = 0;

	FD_ZERO(&socket_set);
	FD_SET(socket, &socket_set);

	for (;;) {
		if (timeout) {
			result = select(socket + 1, &socket_set, NULL, NULL, timeout);
			if (result != 1)
				return result == 0 ? -ETIMEDOUT : result;
		}
		if (remaining) {

			/*
			 * Minimise the number of system calls by reading in largest
			 * possible chunks.
			 * More complex than simply reading char by char but typically only
			 * requires one pass and two context switches rather than one
			 * context switch per char received when reading one char at a time.
			 */

			bytes_read = recv(socket, buf, remaining, MSG_PEEK);
			if ( bytes_read < 0 ) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			if ((end = memchr(buf, TERMINATOR, bytes_read)) != 0) {/* Found terminator */
				bytes_read = end - buf + 1;
				recv(socket, buf, bytes_read, 0);					/* Consume the segment up to and including the terminator */
				*end = '\0';										/* terminate line */
				return total_read + bytes_read;						/* & return length of received line, excluding the terminator */
			}
			recv(socket, buf, bytes_read, 0);						/* Consume the last chunk */
			total_read += bytes_read;
			remaining -= bytes_read;
			buf += bytes_read;
		} else {
			/* Only get here if 'capacity' exhausted before seeing a terminator */
			/* Slowly read char by char until terminator found */
			bytes_read = recv(socket, &ch, 1, 0);
			if (bytes_read < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			if (ch == TERMINATOR) {
				buf[-1] = '\0';			/* Terminate what was read */
				return total_read-1;	/* Return line length excluding terminator */
			}
		}
	}

	/* Should never get here */
	return -1;
}

static int send_amt(int sock_fd, const void *buffer, size_t length)
{
	const char *p = buffer;
	ssize_t chunk_sent;

	while (length > 0) {
		chunk_sent = send(sock_fd, p, length, 0);
		if (chunk_sent <= 0) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		p += chunk_sent;
		length -= chunk_sent;
	}

	return 0;
}

static int send_end_of_response(int fd)
{
	return write_uint32(fd, RESP_END_OF_MESSAGE);
}

int send_ok(int fd)
{
	return send_end_of_response(fd);
}

int send_error(int fd, const char *msg) {

	if (write_uint32(fd, RESP_ERROR) == 0 && write_blob(fd, msg, strlen(msg)) == 0) {
		return send_end_of_response(fd);
	}
	return -1;
}

int read_uint32(int fd, uint32_t * const result, struct timeval *timeout)
{
	char text[50], *end;
	int length = read_line(fd, text, sizeof(text) -1, timeout);		/* Read up to '\n' */

	if (length > 2							/* Minimum req'd type, separator, terminator */
		&& text[0] == DT_INTEGER			/* Verify correct type */
		&& text[1] == SEPARATOR) {			/* A valid integer... so far */
		*result = (uint32_t)strtoul( text+2, &end, 10);
		if (*end == '\0')					/* All chars valid for an int */
			return 0;
	}

	return -1;
}

int write_uint32(int fd, const uint32_t value)
{
	char text[20];
	int length;

	length = snprintf(text, (sizeof text)-1, "i:%u%c", value, TERMINATOR);
	if (length > -1)
		return send_amt( fd, text, length );

	return -1;
}

static int send_blob(int fd, const char *type, const void *data, size_t data_length )
{
	char terminator = TERMINATOR;

	if (send_amt(fd, type, strlen(type)) > -1			/* Send the blob type */
		&& write_uint32(fd, data_length) > -1			/* & length */
		&& send_amt(fd, data, data_length) > -1 ) {		/* then the data */
		return write(fd, &terminator, 1) == 1 ? 0 : -1;	/* and terminator */
	}

	return -1;
}

static int recv_blob(int fd, char type, void **data, size_t *data_length, struct timeval *timeout)
{
	char rxtype[12];
	uint32_t length = 0;
	uint8_t *buffer;

	if (data_length)
		*data_length = 0;

	*data = NULL;	/* Ensure that in caller's space it is safe to free(data) even if recv_blob() fails */
	rxtype[2] = '\0';
	if (read_amt(fd, rxtype, 2, timeout) == 0					/* Read the type */
		&& rxtype[0] == type									/* & confirm against expected */
		&& rxtype[1] == ':'
		&& read_uint32(fd, &length, timeout) == 0) {			/* Read the payload length */
		buffer = malloc(length + 1);
		if (buffer) {
			if (read_amt(fd, buffer, length+1, timeout) == 0	/* Read the payload + terminator */
				&& (char)buffer[length] == TERMINATOR) {		/* Verify terminator where expected */
				buffer[length] = 0;								/* Replace terminator... for type 's:'tring */
				if (data_length)
					*data_length = length;			/* & report the length to the caller if needed */
				*data = buffer;

				return 0;
			}
			free(buffer);
		} else {
			return -ENOMEM;
		}
	}

	return -1;
}

int write_string(int fd, const char *string )
{
	return send_blob(fd,"s:",string,strlen(string));
}

int read_string(int fd, char **string, size_t *length, struct timeval *timeout)
{
	return recv_blob(fd, DT_STRING, (void **)string, length, timeout );
}

int read_blob(int fd, void **buffer, size_t *length, struct timeval *timeout)
{
	return recv_blob(fd, DT_BLOB, buffer, length, timeout);
}

int write_blob(int fd, const void *data, size_t data_length)
{
	return send_blob(fd, "b:", data, data_length );
}

int execute_cmd(const char *cmd, char **resp, int timeout)
{
	FILE *f_cmd, *f_out;
	int bytes_available, rc;
	pid_t pid;
	char *timeout_str = NULL;

	f_cmd = tmpfile();
	if (!f_cmd) {
		if (asprintf(resp, "Error executing '%s' (cmd tmpfile)", cmd) < 0)
			log_error("Error executing '%s' (cmd tmpfile): %s, %d", cmd, strerror(errno), errno);
		return 1;
	}

	if (write(fileno(f_cmd), cmd, strlen(cmd)) < 0
		|| write(fileno(f_cmd), "\n", 1) < 1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			fclose(f_cmd);
			if (asprintf(resp, "Error executing '%s'", cmd)  < 0)
				log_error("Error executing '%s': %s, %d", cmd, strerror(errno), errno);
			return 1;
		}
	}

	f_out = tmpfile();
	if (!f_out) {
		fclose(f_cmd);
		if (asprintf(resp, "Error executing '%s' (out tmpfile)", cmd) < 0)
			log_error("Error executing '%s' (out tmpfile): %s, %d", cmd, strerror(errno), errno);
		return 1;
	}

	fseek(f_cmd, 0, SEEK_SET);
	fseek(f_out, 0, SEEK_SET);

	if (asprintf(&timeout_str, "%d", timeout) < 0)
		timeout_str = NULL;

	pid = process_exec_fd(fileno(f_cmd), fileno(f_out), fileno(f_out),
				"timeout", timeout_str != NULL ? timeout_str : "0", "/bin/sh");
	free(timeout_str);

	rc = process_wait(pid);
	if (rc != 0)
		log_debug("%s: Failed to execute '%s' (%d)", __func__, cmd, rc);

	fseek(f_out, 0, SEEK_SET);
	ioctl(fileno(f_out), FIONREAD, &bytes_available);
	if (bytes_available > 0) {
		int read_rc = -1;

		*resp = calloc(bytes_available + 1, sizeof(char));
		read_rc = read(fileno(f_out), *resp, bytes_available);
		if (read_rc < 0) {
			rc = 1;
			log_debug("%s: Failed to get response for %s (%d)", __func__, *resp, read_rc);
		}
	}

	fclose(f_cmd);
	fclose(f_out);

	if (rc && !*resp) {
		if (asprintf(resp, "Error executing '%s'", cmd) < 0)
			log_error("Error executing '%s': %s, %d", cmd, strerror(errno), errno);
	}

	return rc;
}

pid_t _process_exec_fd(int infd, int outfd, int errfd, const char *cmd, ...)
{
	const char **cmd_list = NULL;
	struct sigaction sa = { .sa_handler = SIG_DFL };
	pid_t pid;
	va_list argp;

	va_start(argp, cmd);
	cmd_list = concat_va_list(cmd);

	pid = fork();
	if (pid != 0)
		return pid;

	if (infd < 0)
		infd = open("/dev/null", O_RDONLY);
	fcntl(infd, F_SETFD, fcntl(infd, F_GETFD) & ~FD_CLOEXEC);
	if (infd != STDIN_FILENO) {
		dup2(infd, STDIN_FILENO);
		if (infd != outfd && infd != errfd)
			close(infd);
	}

	if (outfd < 0)
		outfd = open("/dev/null", O_WRONLY);
	fcntl(outfd, F_SETFD, fcntl(outfd, F_GETFD) & ~FD_CLOEXEC);
	if (outfd != STDOUT_FILENO) {
		dup2(outfd, STDOUT_FILENO);
		if (outfd != errfd)
			close(outfd);
	}

	if (errfd < 0)
		errfd = open("/dev/null", O_WRONLY);
	fcntl(errfd, F_SETFD, fcntl(errfd, F_GETFD) & ~FD_CLOEXEC);
	if (errfd != STDERR_FILENO) {
		dup2(errfd, STDERR_FILENO);
		close(errfd);
	}

	sigaction(SIGPIPE, &sa, NULL);

	execvp(cmd_list[0], (char * const *)cmd_list);

	_exit(1);
}

int process_wait(pid_t pid)
{
	int status;
	int ret;

	if (pid <= 0)
		return -256;

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret != pid)
		return -257;

	if (WIFEXITED(status)) {
		return WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		return -WTERMSIG(status);
	} else
		return -258;
}
