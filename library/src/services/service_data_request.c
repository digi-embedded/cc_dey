/*
 * Copyright (c) 2022, 2023 Digi International Inc.
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

#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <unistd.h>

#include "cc_config.h"
#include "cc_logging.h"
#include "ccapi/ccapi.h"
#include "services_util.h"
#include "service_data_request.h"
#include "_utils.h"

#define TARGET_EDP_CERT_UPDATE	"builtin/edp_certificate_update"

#define DATA_REQUEST_TAG		"DREQ:"

/**
 * log_dr_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_dr_debug(format, ...)				\
	log_debug("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)

/**
 * log_dr_warning() - Log the given message as warning
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_dr_warning(format, ...)				\
	log_warning("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)

/**
 * log_dr_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_dr_error(format, ...)				\
	log_error("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)

typedef struct {
	/* If IPv6 support gets added, this will change to struct sockaddr_storage.*/
	struct sockaddr_in recipient;
	char *target;
} request_data_t;

typedef struct {
#define INITIAL_MAX_SIZE 16
	request_data_t *array;
	size_t size;
	size_t max_size;
} request_data_darray_t;

static request_data_darray_t active_requests = { 0 };

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
extern bool edp_cert_downloaded;
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */

static const char *to_user_error_msg(ccapi_receive_error_t error) {
	switch (error) {
		case CCAPI_RECEIVE_ERROR_NONE:
			return "Success";
		case CCAPI_RECEIVE_ERROR_INVALID_TARGET:
			return "Invalid target";
		case CCAPI_RECEIVE_ERROR_TARGET_NOT_ADDED:
			return "Target is not registered";
		case CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED:
			return "Target already registered";
		case CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY:
			return "Out of memory";
		case CCAPI_RECEIVE_ERROR_STATUS_TIMEOUT:
			return "Timeout";
		default:
			log_dr_error("Unknown internal connection error: ccapi_receive_error_t[%d]", error);
			return "Internal connector error";
	}
}

static int add_registered_target(const request_data_t *target)
{
	/* If needed, (re)alloc memory */
	if (active_requests.size == active_requests.max_size) {
		size_t new_max_size = active_requests.max_size ? 2 * active_requests.max_size : INITIAL_MAX_SIZE;
		request_data_t *new_array = realloc(active_requests.array, new_max_size * sizeof(request_data_t));

		if (!new_array)
			return -1;

		active_requests.array = new_array;
		active_requests.max_size = new_max_size;
	}

	active_requests.array[active_requests.size].target = strdup(target->target);
	if (active_requests.array[active_requests.size].target == NULL)
		return -1;
	memcpy(&active_requests.array[active_requests.size++].recipient, &target->recipient, sizeof(target->recipient));

	return 0;
}

static request_data_t *find_request_data(const char *target)
{
	size_t i;

	for (i = 0; i < active_requests.size; i++) {
		if (!strcmp(active_requests.array[i].target, target))
			return &active_requests.array[i];
	}

	return NULL;
}

static int remove_registered_target(const char * target) {
	request_data_t * req = find_request_data(target);
	size_t elements_to_move;

	if (!req)
		return -1;

	free(req->target);
	/* Count number of valid elements after req */
	elements_to_move = active_requests.size - (req - active_requests.array) - 1;
	if (elements_to_move > 0)
		memmove(req, req + 1, elements_to_move * sizeof(request_data_t));

	active_requests.size--;

	return 0;
}

static int get_socket_for_target(const char *target)
{
	request_data_t *req = find_request_data(target);
	int sock_fd = -1;
	int ret = -1; /* Assume error */

	if (!req) {
		log_dr_error("Could not get port for registered target %s", target);
		goto out;
	}

	if ((sock_fd = socket(req->recipient.sin_family, SOCK_STREAM, 0)) < 0) {
		log_dr_error("Could not open connection for data request: %s", strerror(errno));
		goto out;
	}

	if (connect(sock_fd, (struct sockaddr *)&req->recipient, sizeof(struct sockaddr_in)) < 0) {
		log_dr_error("Could not connect to deliver data request: %s", strerror(errno));
		goto out;
	}

	ret = 0;

out:
	if (ret == 0) {
		return sock_fd;
	} else {
		close(sock_fd);
		return ret;
	}
}

static ccapi_receive_error_t data_request(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	int ret = 1; /* Assume errors */
	int sock_fd = get_socket_for_target(target);
	ccapi_receive_error_t error = CCAPI_RECEIVE_ERROR_NONE;
	struct timeval timeout = {
		.tv_sec = SOCKET_READ_TIMEOUT_SEC,
		.tv_usec = 0
	};

	UNUSED_ARGUMENT(transport);

	if (sock_fd < 0) {
		goto out;
	}

	/* Send: request_type, request_target_name, request_payload */
	if (write_string(sock_fd, REQ_TYPE_REQUEST_CB)  ||					/* The request type */
		write_string(sock_fd, target) ||						/* The registered target device name */
		write_blob(sock_fd, request_buffer_info->buffer, request_buffer_info->length)) {/* The payload data passed to the device callback */
		log_dr_error("Could not write data request: %s (%d)", strerror(errno), errno);
		error = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		goto out;
	}
	/* Read the blob response from the device */
	ret = read_uint32(sock_fd, &error, &timeout);
	if (ret == 0)
		ret = read_blob(sock_fd, &response_buffer_info->buffer, &response_buffer_info->length, &timeout);

	if (ret == -ETIMEDOUT)
		log_dr_error("Could not receive request data: %s", "Timeout");
	else if (ret == -ENOMEM)
		log_dr_error("Could not receive request data: %s", "Out of memory");
	else if (ret == -EPIPE)
		log_dr_error("Could not receive request data: %s", "Socket closed");
	else if (ret)
		log_dr_error("Could not receive request data: %s (%d)", strerror(errno), errno);

	if (ret) {
		error = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		goto out;
	}
out:
	if (ret)
		/* An error occurred, send empty response to DRM */
		response_buffer_info->length = 0;

	if (sock_fd >= 0)
		close(sock_fd);

	return error;
}

static void data_request_done(const char *target,
		ccapi_transport_t transport,
		ccapi_buffer_info_t *response_buffer_info,
		ccapi_receive_error_t receive_error)
{
	int error_code = receive_error;
	const char *err_msg = to_user_error_msg(receive_error);
	int sock_fd = get_socket_for_target(target);

	if (receive_error != CCAPI_RECEIVE_ERROR_NONE)
		log_dr_error("Error on data request response, target='%s' - transport='%d' - error='%d'",
			target, transport, receive_error);

	if (sock_fd < 0)
		goto out;

	/* Send the status callback to the target device */
	if (write_string(sock_fd, REQ_TYPE_STATUS_CB)	/* The Status callback type */
		|| write_string(sock_fd, target)	/* The registered target name */
		|| write_uint32(sock_fd, error_code)	/* The DRM call return status code */
		|| write_string(sock_fd, err_msg)) {	/* And a text description of the status code */
		log_dr_error("Could not write data request: %s (%d)", strerror(errno), errno);
		goto out;
	}
out:
	if (response_buffer_info)
		free(response_buffer_info->buffer);

	if (sock_fd >= 0)
		close(sock_fd);
}

static int read_request(int fd, request_data_t *out, bool expect_ip, int expected_ip_af)
{
	/* Receive a device registration request */
	uint32_t end, port;
	struct timeval timeout = {
		.tv_sec = SOCKET_READ_TIMEOUT_SEC,
		.tv_usec = 0
	};
	int ret;

	if (expect_ip) {
		char *ip = NULL;
		int valid_ip;

		ret = read_string(fd, &ip, NULL, &timeout);
		if (ret == -ETIMEDOUT)
			send_error(fd, "Timeout reading IP");
		else if (ret == -ENOMEM)
			send_error(fd, "Failed to read IP: Out of memory");
		else if (ret == -EPIPE)
			/* Do not send anything */
			;
		else if (ret)
			send_error(fd, "Failed to read IP");

		if (ret)
			return -1;

		/* Parse the IP address string directly into .sin_addr */
		valid_ip = inet_pton(expected_ip_af, ip, &out->recipient.sin_addr);
		/* Either way, we no longer need this string */
		free(ip);

		if (!valid_ip) {
			send_error(fd, "Invalid IP");
			return -1;
		}
		out->recipient.sin_family = expected_ip_af;
	}

	ret = read_uint32(fd, &port, &timeout);
	if (ret == -ETIMEDOUT)
		send_error(fd, "Timeout reading port");
	else if (ret)
		send_error(fd, "Failed to read port");

	if (ret)
		return -1;

	out->recipient.sin_port = htons(port);

	ret = read_string(fd, &out->target, NULL, &timeout);
	if (ret == -ETIMEDOUT)
		send_error(fd, "Timeout reading target");
	else if (ret == -ENOMEM)
		send_error(fd, "Failed to read target: Out of memory");
	else if (ret == -EPIPE)
		/* Do not send anything */
		;
	else if (ret)
		send_error(fd, "Failed to read target");

	if (ret)
		return -1;

	ret = read_uint32(fd, &end, &timeout);
	if (ret == -ETIMEDOUT)
		send_error(fd, "Timeout reading message end");
	else if (ret || end != 0)
		send_error(fd, "Failed to read message end");

	if (ret)
		return -1;

	return 0;
}

static ccapi_receive_error_t unregister_target(const char *target)
{
	ccapi_receive_error_t ret = ccapi_receive_remove_target(target);

	if (ret != CCAPI_RECEIVE_ERROR_NONE)
		return ret;

	if (remove_registered_target(target)) {
		/*
		 * This should never happen, and if it does happen still return OK to
		 * the calling process, as the CCAPI did unregister the target
		 */
		log_dr_error("Could not remove registered target %s", target);
	}

	return ret;
}

/* Note: fd is ignored if < 0 (when there is no need to write the error messages) */
static int register_data_request(int fd, const request_data_t *req_data)
{
	int result = 0;
	request_data_t *previously_registered_req = NULL;
	ccapi_receive_error_t status = ccapi_receive_add_target(req_data->target, data_request, data_request_done, CCAPI_RECEIVE_NO_LIMIT);

	if (status == CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED) {
		previously_registered_req = find_request_data(req_data->target);
		if (!previously_registered_req) {
			/* This should never happen */
			log_dr_error("%s", "Target already registered in CCAPI, but not registered on service_data_request!!");
			if (fd >= 0)
				send_error(fd, "Internal connector error");
		} else {
			/* Future: Log remote IP address, if not localhost */
			log_dr_warning("Target %s has been overriden by new process listening on port %d",
				req_data->target, ntohs(req_data->recipient.sin_port));
			memcpy(&previously_registered_req->recipient, &req_data->recipient,
					sizeof(req_data->recipient));
		}
	} else if (status != CCAPI_RECEIVE_ERROR_NONE) {
		log_dr_error("Could not register data request: %d", status);
		if (fd >= 0)
			send_error(fd, to_user_error_msg(status));
		result = status;
		goto exit;
	}

	if (!previously_registered_req) {
		if (add_registered_target(req_data)) {
			if (fd >= 0)
				send_error(fd, "Could not register data request, out of memory");
			result = -1;
		}
	}

exit:
	return result;
}

static int
_handle_register(int fd, request_data_t *req, bool expect_to_read_ip, int expected_ip_af)
{
	if (read_request(fd, req, expect_to_read_ip, expected_ip_af))
		return -1;

	if (register_data_request(fd, req))
		return -1;

	send_ok(fd);

	return 0;
}

static int
_handle_unregister(int fd, request_data_t *req, bool expect_to_read_ip, int expected_ip_af)
{
	ccapi_receive_error_t status;

	if (read_request(fd, req, expect_to_read_ip, expected_ip_af))
		return -1;

	status = unregister_target(req->target);
	if (status != CCAPI_RECEIVE_ERROR_NONE) {
		send_error(fd, to_user_error_msg(status));
		return status;
	}

	send_ok(fd);

	return 0;
}

int handle_register_data_request(int fd, const cc_cfg_t *const cc_cfg)
{
	request_data_t req_data;

	UNUSED_ARGUMENT(cc_cfg);

	/* This registration command assumes localhost IPv4 */
	req_data.recipient.sin_family = AF_INET;
	req_data.recipient.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	return _handle_register(fd, &req_data, false, 0);
}

int handle_register_data_request_ipv4(int fd, const cc_cfg_t *const cc_cfg)
{
	request_data_t req_data;

	UNUSED_ARGUMENT(cc_cfg);

	/* Registration request payload is expected to include an IPv4 string */
	return _handle_register(fd, &req_data, true, AF_INET);
}

int handle_unregister_data_request(int fd, const cc_cfg_t *const cc_cfg)
{
	request_data_t req_data;

	UNUSED_ARGUMENT(cc_cfg);

	/* This un-registration command assumes localhost IPv4.
	   NOTE: Technically unregister_target doesn't even look at these;
	   but we set these fields to be forward-looking */
	req_data.recipient.sin_family = AF_INET;
	req_data.recipient.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	return _handle_unregister(fd, &req_data, false, 0);
}

int handle_unregister_data_request_ipv4(int fd, const cc_cfg_t *const cc_cfg)
{
	request_data_t req_data;

	UNUSED_ARGUMENT(cc_cfg);

	/* Unregistration request payload is expected to include an IPv4 string.
	   NOTE: Technically unregister_target doesn't even look at the address;
	   but we take it in to be forward-looking */
	return _handle_unregister(fd, &req_data, true, AF_INET);
}

int import_datarequests(const char *file_path)
{
	int ret = -1;
	size_t n;
	size_t i;
	FILE *file = fopen(file_path, "r");
	request_data_t temp;
	char *temp_string;
	size_t string_len;
	long fpos, flen;

	if (!file) {
		log_dr_error("Could not read registered targets from %s: %s (%d)",
			file_path, strerror(errno), errno);
		return -1;
	}

	if (fread(&n, sizeof n, 1, file) != 1) {
		log_dr_error("Could not read number of registered targets: %s (%d)",
			strerror(errno), errno);
		goto out;
	}

	for (i = 0; i < n; i++) {
		if (fread(&temp.recipient, sizeof temp.recipient, 1, file) != 1
			|| fread(&string_len, sizeof string_len, 1, file) != 1) {
			log_dr_error("Could not read registered target %zu", i);
			goto out;
		}

		/* Verify that the str_len is at less than the EOF */
		fpos = ftell(file);
		if (fseek(file, 0, SEEK_END) != 0)
			goto out;

		flen = ftell(file);
		if (fpos < 0 || flen < 0 || flen < fpos || string_len <= 0 || (long)string_len > (flen - fpos))
			goto out;

		if (fseek(file, fpos, SEEK_SET) != 0)
			goto out;

		temp_string = malloc(string_len + 1);
		/*
		 * We need to check for overflow (as this data can be exposed to an
		 * attacker). If there is an overflow it will be caused by string_len
		 * equalling the maximum memory and then the +1 causing the overflow.
		 * We can't just check that its equal in size as this will just check
		 * that 0 is equal to 0, we need to check that the allocated memory
		 * is greater than string_len as this means that it hasn't wrapped
		 * around e.g. 0 < 0xfffffffffff
		 */
		if (!temp_string || malloc_usable_size(temp_string) < (size_t) (string_len)) {
			log_dr_error("Could not read registered target: %s", "Out of memory");
			free(temp_string);
			goto out;
		}
		if (fread(temp_string, string_len, 1, file) != 1) {
			log_dr_error("Could not read registered target %zu", i);
			free(temp_string);
			goto out;
		}
		temp_string[string_len] = '\0';
		temp.target = temp_string;

		register_data_request(-1, &temp);
		free(temp_string);
	}

out:
	fclose(file);

	return ret;
}

int dump_datarequests(const char *file_path)
{
	int ret = -1;
	size_t n = active_requests.size;
	size_t i;
	FILE *file;

	if (active_requests.size == 0)
		return 0;

	if (!(file = fopen(file_path, "w"))) {
		log_dr_error("Could not dump registered targets to '%s': %s (%d)",
			file_path, strerror(errno), errno);
		return -1;
	}

	if (fwrite(&n, sizeof n, 1, file) != 1) {
		log_dr_error("Could not write registered targets: %s (%d)",
			strerror(errno), errno);
		goto out;
	}

	for (i = 0; i < n; i++) {
		const request_data_t *dr = &active_requests.array[i];
		size_t target_len = strlen(dr->target);

		if (fwrite(&dr->recipient, sizeof dr->recipient, 1, file) != 1
			|| fwrite(&target_len, sizeof target_len, 1, file) != 1
			|| fwrite(dr->target, target_len, 1, file) != 1) {
			log_dr_error("Could not write registered targets: %s (%d)",
				strerror(errno), errno);
			goto out;
		}
	}

	ret = 0;

out:
	fclose(file);

	return ret;
}

/******************** Built-in data requests ********************/

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
static ccapi_receive_error_t edp_cert_update_cb(const char *const target,
			const ccapi_transport_t transport,
			const ccapi_buffer_info_t *const request_buffer_info,
			ccapi_buffer_info_t *const response_buffer_info)
{
	FILE *fp;
	ccapi_receive_error_t ret;

	UNUSED_ARGUMENT(response_buffer_info);

	edp_cert_downloaded = false;

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);
	if (request_buffer_info && request_buffer_info->buffer && request_buffer_info->length > 0) {
		char *client_cert_path = get_client_cert_path();

		if (!client_cert_path) {
			log_dr_error("%s", "Invalid client certificate");
			return CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		}

		fp = fopen(client_cert_path, "w");
		if (!fp) {
			log_dr_error("Unable to open certificate '%s': %s (%d)",
				client_cert_path, strerror(errno), errno);
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
		if (fwrite(request_buffer_info->buffer, sizeof(char), request_buffer_info->length, fp) < request_buffer_info->length) {
			log_dr_error("Unable to write certificate '%s'", client_cert_path);
			ret = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		} else {
			log_dr_debug("%s: certificate saved at '%s'", __func__, client_cert_path);
			edp_cert_downloaded = true;
			ret = CCAPI_RECEIVE_ERROR_NONE;
		}
		fclose(fp);
	} else {
		log_dr_error("%s: received invalid data", __func__);
		ret = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
	}

	return ret;
}
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */

static void builtin_request_status_cb(const char *const target,
			const ccapi_transport_t transport,
			ccapi_buffer_info_t *const response_buffer_info,
			ccapi_receive_error_t receive_error)
{
	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE) {
		log_dr_error("Error on data request response: target='%s' - transport='%d' - error='%d'",
			      target, transport, receive_error);
	}
	/* Free the response buffer */
	if (response_buffer_info != NULL)
		free(response_buffer_info->buffer);
}

ccapi_receive_error_t register_builtin_requests(void)
{
	ccapi_receive_error_t receive_error = CCAPI_RECEIVE_ERROR_NONE;

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
	receive_error = ccapi_receive_add_target(TARGET_EDP_CERT_UPDATE,
						 edp_cert_update_cb,
						 builtin_request_status_cb,
						 CCAPI_RECEIVE_NO_LIMIT);
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE) {
		log_dr_error("Cannot register target '%s', error %d", TARGET_EDP_CERT_UPDATE,
				receive_error);
		return receive_error;
	}
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */

	return receive_error;
}

/**
 * receive_default_accept_cb() - Default accept callback for non registered
 *                               data requests
 *
 * @target:	Target ID associated to the data request.
 * @transport:	Communication transport used by the data request.
 *
 * Return: CCAPI_FALSE if the data request is not accepted,
 *         CCAPI_TRUE otherwise.
 */
static ccapi_bool_t receive_default_accept_cb(char const *const target,
		ccapi_transport_t const transport)
{
	switch (transport) {
		case CCAPI_TRANSPORT_TCP:
			return CCAPI_TRUE;
#if (defined CCIMP_UDP_TRANSPORT_ENABLED)
		case CCAPI_TRANSPORT_UDP:
			/* intentional fall-through */
#endif /* CCIMP_UDP_TRANSPORT_ENABLED */
#if (defined CCIMP_SMS_TRANSPORT_ENABLED)
		case CCAPI_TRANSPORT_SMS:
			/* intentional fall-through */
#endif /* CCIMP_SMS_TRANSPORT_ENABLED */
		default:
			/* Don't accept requests from SMS and UDP transports */
			log_dr_debug("%s: not accepted request - target='%s' - transport='%d'",
				      __func__, target, transport);
			return CCAPI_FALSE;
	}
}

/**
 * receive_default_data_cb() - Default data callback for non registered
 *                             data requests
 *
 * @target:			Target ID associated to the data request.
 * @transport:			Communication transport used by the data request.
 * @request_buffer_info:	Buffer containing the data request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and sends an answer to Device
 * Cloud indicating that the data request with that target is not registered.
 */
static ccapi_receive_error_t receive_default_data_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info)
{
	char *request_buffer = NULL, *request_data = NULL;

	/* Log request data */
	log_dr_debug("%s: not registered target - target='%s' - transport='%d'",
		     __func__, target, transport);
	if (request_buffer_info->length > 0) {
		request_buffer = calloc(request_buffer_info->length + 1, sizeof(char));
		if (request_buffer == NULL) {
			log_dr_error("Could not read received data request: %s", "Out of memory");
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
		memcpy(request_buffer, request_buffer_info->buffer, request_buffer_info->length);
		request_data = trim(request_buffer);
		if (request_data == NULL) {
			log_dr_error("Could not read received data request: %s", "Out of memory");
			free(request_buffer);

			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
	}

	log_dr_debug("%s: not registered target - request='%s'", __func__, request_data);
	free(request_buffer);

	/* Provide response to Remote Manager */
	if (response_buffer_info != NULL) {
		size_t len = snprintf(NULL, 0, "Target '%s' not registered", target);

		response_buffer_info->buffer = calloc(len + 1, sizeof(char));
		if (response_buffer_info->buffer == NULL) {
			log_dr_error("Could not read received data request: %s", "Out of memory");
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
		response_buffer_info->length = sprintf(response_buffer_info->buffer,
				"Target '%s' not registered", target);
	}

	return CCAPI_RECEIVE_ERROR_NONE;
}

/**
 * receive_default_status_cb() - Default status callback for non registered
 *                               data requests
 *
 * @target:			Target ID associated to the data request.
 * @transport:			Communication transport used by the data request.
 * @response_buffer_info:	Buffer containing the response data.
 * @receive_error:		The error status of the receive process.
 *
 * This callback is executed when the receive process has finished. It doesn't
 * matter if everything worked or there was an error during the process.
 *
 * Cleans and frees the response buffer.
 */
static void receive_default_status_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t *const response_buffer_info,
		ccapi_receive_error_t receive_error)
{
	log_dr_debug("%s: target='%s' - transport='%d' - error='%d'",
		      __func__, target, transport, receive_error);
	/* Free the response buffer */
	if (response_buffer_info != NULL)
		free(response_buffer_info->buffer);
}

ccapi_receive_service_t receive_service = {
	.accept = receive_default_accept_cb,
	.data = receive_default_data_cb,
	.status = receive_default_status_cb
};
