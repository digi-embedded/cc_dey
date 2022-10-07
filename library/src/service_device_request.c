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

#include <arpa/inet.h>
#include <errno.h>
#include <json-c/json_object.h>
#include <libdigiapix/bluetooth.h>
#include <libdigiapix/network.h>
#include <malloc.h>
#include <stdbool.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "cc_config.h"
#include "cc_logging.h"
#include "ccapi/ccapi.h"
#include "file_utils.h"
#include "network_utils.h"
#include "services_util.h"
#include "service_device_request.h"
#include "string_utils.h"

#define TARGET_EDP_CERT_UPDATE	"builtin/edp_certificate_update"

#define TARGET_DEVICE_INFO		"device_info"

#define DEVICE_REQUEST_TAG		"DEVREQ:"

#define MAX_RESPONSE_SIZE		512

#define EMMC_SIZE_FILE				"/sys/class/mmc_host/mmc0/mmc0:0001/block/mmcblk0/size"
#define NAND_SIZE_FILE				"/proc/mtd"
#define RESOLUTION_FILE				"/sys/class/graphics/fb0/modes"
#define RESOLUTION_FILE_CCMP		"/sys/class/drm/card0/card0-DPI-1/modes"
#define RESOLUTION_FILE_CCMP_HDMI	"/sys/class/drm/card0/card0-HDMI-A-1/modes"

/**
 * log_dr_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_dr_debug(format, ...)									\
	log_debug("%s " format, DEVICE_REQUEST_TAG, __VA_ARGS__)

/**
 * log_dr_warning() - Log the given message as warning
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_dr_warning(format, ...)									\
	log_warning("%s " format, DEVICE_REQUEST_TAG, __VA_ARGS__)

/**
 * log_dr_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_dr_error(format, ...)									\
	log_error("%s " format, DEVICE_REQUEST_TAG, __VA_ARGS__)

typedef struct {
	uint16_t port;
	char *target;
} request_data_t;

typedef struct {
#define INITIAL_MAX_SIZE 16
	request_data_t *array;
	size_t size;
	size_t max_size;
} request_data_darray_t;

static const char REQUEST_CB[] = "request";
static const char STATUS_CB[] = "status";

static request_data_darray_t active_requests = { 0 };

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

	active_requests.array[active_requests.size++] = *target;

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
	struct sockaddr_in serv_addr;
	int sock_fd = -1;
	int ret = -1; /* Assume error */

	if (!req) {
		log_dr_error("Could not get port for registered target %s", target);
		goto out;
	}

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_dr_error("Could not open socket to send device request: %s", strerror(errno));
		goto out;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(req->port);
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		log_dr_error("Could not set serv_addr.sin_addr: %s", strerror(errno));
		goto out;
	}

	if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof serv_addr) < 0) {
		log_dr_error("Could not connect to socket to deliver device request: %s", strerror(errno));
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

static ccapi_receive_error_t device_request(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	int ret = 1; /* Assume errors */
	int sock_fd = get_socket_for_target(target);
	struct timeval timeout = {
		.tv_sec = SOCKET_READ_TIMEOUT_SEC,
		.tv_usec = 0
	};

	UNUSED_ARGUMENT(transport);

	if (sock_fd < 0) {
		goto out;
	}

	/* Send: request_type, request_target_name, request_payload */
	if (write_string(sock_fd, REQUEST_CB)  ||											/* The request type */
		write_string(sock_fd, target) ||												/* The registered target device name */
		write_blob(sock_fd, request_buffer_info->buffer, request_buffer_info->length)) {/* The payload data passed to the device callback */
		log_dr_error("Could not write device request to socket: %s", strerror(errno));
		goto out;
	}
	/* Read the blob response from the device */
	if (read_blob(sock_fd, &response_buffer_info->buffer, &response_buffer_info->length, &timeout)) {
		log_dr_error("Could not recv device request data from socket: %s", strerror(errno));
		response_buffer_info->length = 0;
		goto out;
	}

	/* If we reach this point, all went well */
	ret = 0;

out:
	if (ret)
		/* An error occurred, send empty response to DRM */
		response_buffer_info->length = 0;

	if (sock_fd >= 0)
		close(sock_fd);

	return CCAPI_RECEIVE_ERROR_NONE;
}

static void device_request_done(const char *target,
		ccapi_transport_t transport,
		ccapi_buffer_info_t *response_buffer_info,
		ccapi_receive_error_t receive_error)
{
	int error_code = receive_error;
	const char *err_msg = to_user_error_msg(receive_error);
	int sock_fd = get_socket_for_target(target);

	if (receive_error != CCAPI_RECEIVE_ERROR_NONE)
		log_dr_error("Error on device request response, target='%s' - transport='%d' - error='%d'",
			target, transport, receive_error);

	if (sock_fd < 0)
		goto out;

	/* Send the status callback to the target device */
	if (write_string(sock_fd, STATUS_CB)	/* The Status callback type */
		|| write_string(sock_fd, target)		/* The registered target name */
		|| write_uint32(sock_fd, error_code)	/* The DRM call return status code */
		|| write_string(sock_fd, err_msg)) {		/* And a text description of the status code */
		log_dr_error("Could not write device request to socket: %s", strerror(errno));
		goto out;
	}
out:
	if (response_buffer_info)
		free(response_buffer_info->buffer);

	if (sock_fd >= 0)
		close(sock_fd);
}

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
static ccapi_receive_error_t edp_cert_update_cb(const char *const target,
			const ccapi_transport_t transport,
			const ccapi_buffer_info_t *const request_buffer_info,
			ccapi_buffer_info_t *const response_buffer_info)
{
	FILE *fp;
	ccapi_receive_error_t ret;

	UNUSED_ARGUMENT(response_buffer_info);

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);
	if (request_buffer_info && request_buffer_info->buffer && request_buffer_info->length > 0) {
		char *client_cert_path = get_client_cert_path();

		if (!client_cert_path) {
			log_dr_error("%s", "Invalid client certificate");
			return CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		}

		fp = fopen(client_cert_path, "w");
		if (!fp) {
			log_dr_error("Unable to open certificate %s: %s", client_cert_path, strerror(errno));
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
		if (fwrite(request_buffer_info->buffer, sizeof(char), request_buffer_info->length, fp) < request_buffer_info->length) {
			log_dr_error("Unable to write certificate %s", client_cert_path);
			ret = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		} else {
			log_dr_debug("%s: certificate saved at %s", __func__, client_cert_path);
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
		log_dr_error("Error on device request response: target='%s' - transport='%d' - error='%d'",
			      target, transport, receive_error);
	}
	/* Free the response buffer */
	if (response_buffer_info != NULL)
		free(response_buffer_info->buffer);
}

/*
 * register_builtin_requests() - Register built-in device requests
 *
 * Return: Error code after registering the built-in device requests.
 */
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

static int read_request(int fd, request_data_t *out)
{
	/* Receive a local device registration request */
	uint32_t end, port;
	struct timeval timeout = {
		.tv_sec = SOCKET_READ_TIMEOUT_SEC,
		.tv_usec = 0
	};

	if (read_uint32(fd, &port, &timeout)) {
		send_error(fd, "Failed to read port");
		return -1;
	}
	out->port = port;

	if (read_string(fd, &out->target, NULL, &timeout)) {
		send_error(fd, "Failed to read target");
		return -1;
	}

	if (read_uint32(fd, &end, &timeout) || end != 0) {
		send_error(fd, "Failed to read message end");
		return -1;
	}

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
static int register_device_request(int fd, const request_data_t *req_data)
{
	int result = 0;
	bool target_used = false;
	request_data_t *previously_registered_req = NULL;
	ccapi_receive_error_t status = ccapi_receive_add_target(req_data->target, device_request, device_request_done, CCAPI_RECEIVE_NO_LIMIT);

	if (status == CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED) {
		previously_registered_req = find_request_data(req_data->target);
		if (!previously_registered_req) {
			/* This should never happen */
			log_dr_error("%s", "Target already registered in CCAPI, but not registered on service_device_request!!");
			if (fd >= 0)
				send_error(fd, "Internal connector error");
		} else {
			log_dr_warning("Target %s has been overriden by new process listening on port %d",
				req_data->target, req_data->port);
			previously_registered_req->port = req_data->port;
		}
	} else if (status != CCAPI_RECEIVE_ERROR_NONE) {
		log_dr_error("Could not register device request: %d", status);
		if (fd >= 0)
			send_error(fd, to_user_error_msg(status));
		result = status;
		goto exit;
	}

	if (!previously_registered_req) {
		if (add_registered_target(req_data)) {
			if (fd >= 0)
				send_error(fd, "Could not register device request, out of memory");
			result = -1;
		} else {
			target_used = true;
		}
	}

exit:
	if(!target_used)
		free(req_data->target);

	return result;
}

int handle_register_device_request(int fd)
{
	request_data_t req_data;

	if (read_request(fd, &req_data))
		return -1;

	if (register_device_request(fd, &req_data))
		return -1;

	send_ok(fd);

	return 0;
}

int handle_unregister_device_request(int fd)
{
	request_data_t req_data;
	ccapi_receive_error_t status;

	if (read_request(fd, &req_data))
		return -1;

	status = unregister_target(req_data.target);
	if (status != CCAPI_RECEIVE_ERROR_NONE) {
		send_error(fd, to_user_error_msg(status));
		return status;
	}

	send_ok(fd);

	return 0;
}

int import_devicerequests(const char *file_path)
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
		log_dr_error("Could not read registered targets from %s: %s", file_path, strerror(errno));
		return -1;
	}

	if (fread(&n, sizeof n, 1, file) != 1) {
		log_dr_error("Could not read number of registered targets: %s", strerror(errno));
		goto out;
	}

	for (i = 0; i < n; i++) {
		if (fread(&temp.port, sizeof temp.port, 1, file) != 1
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
			log_dr_error("%s", "Could not read registered target, out of memory");
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

		if (register_device_request(-1, &temp))
			free(temp_string);
	}

out:
	fclose(file);

	return ret;
}

int dump_devicerequests(const char *file_path)
{
	int ret = -1;
	size_t n = active_requests.size;
	size_t i;
	FILE *file;

	if (active_requests.size == 0)
		return 0;

	if (!(file = fopen(file_path, "w"))) {
		log_dr_error("Could not dump registered targets to %s: %s", file_path, strerror(errno));
		return -1;
	}

	if (fwrite(&n, sizeof n, 1, file) != 1) {
		log_dr_error("Could not write registered targets: %s", strerror(errno));
		goto out;
	}

	for (i = 0; i < n; i++) {
		const request_data_t *dr = &active_requests.array[i];
		size_t target_len = strlen(dr->target);

		if (fwrite(&dr->port, sizeof dr->port, 1, file) != 1
			|| fwrite(&target_len, sizeof target_len, 1, file) != 1
			|| fwrite(dr->target, target_len, 1, file) != 1) {
			log_dr_error("Could not write registered targets: %s", strerror(errno));
			goto out;
		}
	}

	ret = 0;

out:
	fclose(file);

	return ret;
}

/**
 * get_emmc_size() - Returns the total eMMC storage size.
 *
 * Return: total size read.
 */
static long get_emmc_size(void)
{
	char data[MAX_RESPONSE_SIZE] = {0};
	long total_size = 0;

	if (read_file(EMMC_SIZE_FILE, data, MAX_RESPONSE_SIZE) <= 0)
		log_dr_error("%s", "Error getting storage size: Could not read file");
	if (sscanf(data, "%ld", &total_size) < 1)
		log_dr_error("%s", "Error getting storage size: Invalid file contents");

	return total_size * 512 / 1024; /* kB */
}

/**
 * get_nand_size() - Returns the total NAND storage size.
 *
 * Return: total size read.
 */
static long get_nand_size(void)
{
	char buffer[MAX_RESPONSE_SIZE] = {0};
	long total_size = 0;
	FILE *fd;

	fd = fopen(NAND_SIZE_FILE, "r");
	if (!fd) {
		log_dr_error("%s", "Error getting storage size: Could not open file");
		return total_size;
	}
	/* Ignore first line */
	if (fgets(buffer, sizeof(buffer), fd) == NULL) {
		log_dr_error("%s", "Error getting storage size: Could not read file");
		fclose(fd);
		return total_size;
	}
	/* Start reading line by line */
	while (fgets(buffer, sizeof(buffer), fd)) {
		char partition_id[20] = {'\0'};
		char partition_name[20] = {'\0'};
		char size_hex[20] = {'\0'};
		char erase_size_hex[20] = {'\0'};
		unsigned long size;

		sscanf(buffer,
			"%s %s %s %s",
			partition_id,
			size_hex,
			erase_size_hex,
			partition_name);

		size = strtol(size_hex, NULL, 16);
		total_size = total_size + size;
	}
	if (ferror(fd))
		log_dr_error("%s", "Error getting storage size: File read error");
	fclose(fd);

	return total_size / 1024; /* kB */
}

/**
 * receive_default_accept_cb() - Default accept callback for non registered
 *                               device requests
 *
 * @target:		Target ID associated to the device request.
 * @transport:	Communication transport used by the device request.
 *
 * Return: CCAPI_FALSE if the device request is not accepted,
 *         CCAPI_TRUE otherwise.
 */
static ccapi_bool_t receive_default_accept_cb(char const *const target,
		ccapi_transport_t const transport)
{
	ccapi_bool_t accept_target = CCAPI_TRUE;

#if (defined CCIMP_UDP_TRANSPORT_ENABLED || defined CCIMP_SMS_TRANSPORT_ENABLED)
	switch (transport) {
#if (defined CCIMP_UDP_TRANSPORT_ENABLED)
		case CCAPI_TRANSPORT_UDP:
#endif
#if (defined CCIMP_SMS_TRANSPORT_ENABLED)
		case CCAPI_TRANSPORT_SMS:
#endif
			/* Don't accept requests from SMS and UDP transports */
			log_dr_debug("%s: not accepted request - target='%s' - transport='%d'",
				      __func__, target, transport);
			accept_target = CCAPI_FALSE;
			break;
	}
#else
	UNUSED_ARGUMENT(transport);
	UNUSED_ARGUMENT(target);
#endif

	return accept_target;
}

/**
 * receive_default_data_cb() - Default data callback for non registered
 *                             device requests
 *
 * @target:					Target ID associated to the device request.
 * @transport:				Communication transport used by the device request.
 * @request_buffer_info:	Buffer containing the device request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and sends an answer to Device
 * Cloud indicating that the device request with that target is not registered.
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
			log_dr_error("Could not read received device request: %s", "Out of memory");
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
		memcpy(request_buffer, request_buffer_info->buffer, request_buffer_info->length);
		request_data = trim(request_buffer);
		if (request_data == NULL) {
			log_dr_error("Could not read received device request: %s", "Out of memory");
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
			log_dr_error("Could not read received device request: %s", "Out of memory");
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
		response_buffer_info->length = sprintf(response_buffer_info->buffer,
				"Target '%s' not registered", target);
	}

	return CCAPI_RECEIVE_ERROR_NONE;
}

/**
 * receive_default_status_cb() - Default status callback for non registered
 *                               device requests
 *
 * @target:					Target ID associated to the device request.
 * @transport:				Communication transport used by the device request.
 * @response_buffer_info:	Buffer containing the response data.
 * @receive_error:			The error status of the receive process.
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

/*
 * device_info_cb() - Data callback for 'device_info' device requests
 *
 * @target:					Target ID of the device request (device_info).
 * @transport:				Communication transport used by the device request.
 * @request_buffer_info:	Buffer containing the device request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 */
static ccapi_receive_error_t device_info_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info)
{
	json_object *root = NULL;
	char *response = NULL;
	ccapi_receive_error_t status = CCAPI_RECEIVE_ERROR_NONE;

	UNUSED_ARGUMENT(request_buffer_info);

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);

	/*
		target "device_info"

		Request: -

		Response:
		{
			"total_st": 0,
			"total_mem": 2002120,
			"resolution": "1920x1080p-0",
			"bt-mac": "00:40:9d:7d:1b:8f",
			"lo": {
				"mac": "00:00:00:00:00:00",
				"ip": "127.0.0.1"
			},
			"eth0": {
				"mac": "00:40:9d:ee:b6:96",
				"ip": "192.168.1.44"
			},
			"can0": {
				"mac": "00:00:00:00:00:00",
				"ip": "0.0.0.0"
			},
			"wlan0": {
				"mac": "00:40:9d:dd:bd:13",
				"ip": "0.0.0.0"
			}
		}
	*/

	root = json_object_new_object();
	if (!root) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	}

	{
		long total_st = 0;

		/* Check first emmc, because '/proc/mtd' may exists although empty */
		if (file_readable(EMMC_SIZE_FILE))
			total_st = get_emmc_size();
		else if (file_readable(NAND_SIZE_FILE))
			total_st = get_nand_size();
		else
			log_dr_error("%s", "Error getting storage size: File not readable");

		if (json_object_object_add(root, "total_st", json_object_new_int64(total_st)) < 0) {
			log_dr_error("Cannot generate response for target '%s': Out of memory", target);
			status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto done;
		}
	}

	{
		struct sysinfo s_info;
		long total_mem = -1;

		if (sysinfo(&s_info) != 0)
			log_dr_error("Error getting total memory: %s (%d)", strerror(errno), errno);
		else
			total_mem = s_info.totalram / 1024;

		if (json_object_object_add(root, "total_mem", json_object_new_int64(total_mem)) < 0) {
			log_dr_error("Cannot generate response for target '%s': Out of memory", target);
			status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto done;
		}
	}

	{
		char data[MAX_RESPONSE_SIZE] = {0};
		char resolution[MAX_RESPONSE_SIZE] = {0};
		char *resolution_file = "";

		if (file_readable(RESOLUTION_FILE))
			resolution_file = RESOLUTION_FILE;
		else if (file_readable(RESOLUTION_FILE_CCMP))
			resolution_file = RESOLUTION_FILE_CCMP;
		else if (file_readable(RESOLUTION_FILE_CCMP_HDMI))
			resolution_file = RESOLUTION_FILE_CCMP_HDMI;

		if (!file_readable(resolution_file))
			log_dr_error("%s", "Error getting video resolution: File not readable");
		else if (read_file(resolution_file, data, MAX_RESPONSE_SIZE) <= 0)
			log_dr_error("%s", "Error getting video resolution");
		else if (sscanf(data, "U:%s", resolution) < 1) {
			if (sscanf(data, "%s", resolution) < 1)
				log_dr_error("%s", "Error getting video resolution");
		}

		if (json_object_object_add(root, "resolution", json_object_new_string(resolution)) < 0) {
			log_dr_error("Cannot generate response for target '%s': Out of memory", target);
			status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto done;
		}
	}

	{
		bt_state_t bt_state;
		uint8_t *mac = NULL;
		char mac_str[18];

		ldx_bt_get_state(0, &bt_state);
		mac = bt_state.mac;

		snprintf(mac_str, sizeof(mac_str), MAC_FORMAT,
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		if (json_object_object_add(root, "bt-mac", json_object_new_string(mac_str)) < 0) {
			log_dr_error("Cannot generate response for target '%s': Out of memory", target);
			status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto done;
		}
	}

	{
		net_names_list_t list_ifaces;
		int i;

		ldx_net_list_available_ifaces(&list_ifaces);

		for (i = 0; i < list_ifaces.n_ifaces; i++) {
			net_state_t net_state;
			uint8_t *mac = NULL, *ip = NULL;
			char mac_str[MAC_STRING_LENGTH], ip_str[IP_STRING_LENGTH];
			json_object *iface_item = json_object_new_object();

			ldx_net_get_iface_state(list_ifaces.names[i], &net_state);
			mac = net_state.mac;
			ip = net_state.ipv4;

			if (!iface_item || json_object_object_add(root, list_ifaces.names[i], iface_item) < 0) {
				log_dr_error("Cannot generate response for target '%s': Out of memory", target);
				if (iface_item)
					json_object_put(iface_item);
				status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
				goto done;
			}
			
			snprintf(mac_str, sizeof(mac_str), MAC_FORMAT,
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			snprintf(ip_str, sizeof(ip_str), IP_FORMAT,
				ip[0], ip[1], ip[2], ip[3]);
		
			if (json_object_object_add(iface_item, "mac", json_object_new_string(mac_str)) < 0) {
				log_dr_error("Cannot generate response for target '%s': Out of memory", target);
				status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
				goto done;
			}

			if (json_object_object_add(iface_item, "ip", json_object_new_string(ip_str)) < 0) {
				log_dr_error("Cannot generate response for target '%s': Out of memory", target);
				status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
				goto done;
			}
		}
	}

	response = strdup(json_object_to_json_string(root));
	if (response == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto done;
	}

	response_buffer_info->buffer = response;
	response_buffer_info->length = strlen(response);

	log_dr_debug("%s: response: %s (len: %zu)", __func__,
		(char *)response_buffer_info->buffer, response_buffer_info->length);

done:
	json_object_put(root);

	return status;
}

/*
 * register_device_requests() - Register custom device requests
 *
 * Return: Error code after registering the custom device requests.
 */
ccapi_receive_error_t register_cc_device_requests(void)
{
	ccapi_receive_error_t error = ccapi_receive_add_target(TARGET_DEVICE_INFO,
			device_info_cb, receive_default_status_cb, 0);
	if (error != CCAPI_RECEIVE_ERROR_NONE)
		log_error("Cannot register target '%s', error %d", TARGET_DEVICE_INFO,
				error);

	return error;
}

ccapi_receive_service_t receive_service = {
	.accept = receive_default_accept_cb,
	.data = receive_default_data_cb,
	.status = receive_default_status_cb
};
