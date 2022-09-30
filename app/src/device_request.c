/*
 * Copyright (c) 2017-2022 Digi International Inc.
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

#include <json-c/json_object_iterator.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <libdigiapix/gpio.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "device_request.h"
#include "services_util.h"

/*------------------------------------------------------------------------------
                             D E F I N I T I O N S
------------------------------------------------------------------------------*/
#define TARGET_GET_TIME		"get_time"
#define TARGET_STOP_CC		"stop_cc"
#define TARGET_USER_LED		"user_led"
#define TARGET_PLAY_MUSIC	"play_music"

#define RESPONSE_ERROR		"ERROR"
#define RESPONSE_OK			"OK"

#define USER_LED_ALIAS		"USER_LED"

#define DEVREQ_TAG			"DEVREQ:"

#define FIELD_PLAY			"play"
#define FIELD_MUSIC_FILE	"music_file"

#define CMD_PLAY_MUSIC		"setsid mpg123 %s"
#define CMD_STOP_MUSIC		"pkill -KILL -f mpg123"

#define MAX_RESPONSE_SIZE	256

#if !(defined UNUSED_ARGUMENT)
#define UNUSED_ARGUMENT(a)	(void)(a)
#endif

/*------------------------------------------------------------------------------
                                  M A C R O S
------------------------------------------------------------------------------*/
/*
 * log_dr_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_dr_debug(format, ...)									\
	log_debug("%s " format, DEVREQ_TAG, __VA_ARGS__)

/*
 * log_dr_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_dr_error(format, ...)									\
	log_error("%s " format, DEVREQ_TAG, __VA_ARGS__)

/*------------------------------------------------------------------------------
                    F U N C T I O N  D E C L A R A T I O N S
------------------------------------------------------------------------------*/
static ccapi_receive_error_t stop_cb(char const *const target, ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info);
static ccapi_receive_error_t get_time_cb(char const *const target, ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info);
static ccapi_receive_error_t update_user_led_cb(char const *const target, ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info);
static ccapi_receive_error_t play_music_cb(char const *const target, ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info);
static void request_status_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t *const response_buffer_info,
		ccapi_receive_error_t receive_error);

/*------------------------------------------------------------------------------
                     F U N C T I O N  D E F I N I T I O N S
------------------------------------------------------------------------------*/

/*
 * register_custom_device_requests() - Register custom device requests
 *
 * Return: Error code after registering the custom device requests.
 */
ccapi_receive_error_t register_custom_device_requests(void)
{
	ccapi_receive_error_t receive_error;

	receive_error = ccapi_receive_add_target(TARGET_GET_TIME, get_time_cb,
			request_status_cb, 0);
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE) {
		log_error("Cannot register target '%s', error %d", TARGET_GET_TIME,
				receive_error);
	}
	receive_error = ccapi_receive_add_target(TARGET_STOP_CC, stop_cb,
			request_status_cb, 0);
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE) {
		log_error("Cannot register target '%s', error %d", TARGET_STOP_CC,
				receive_error);
	}
	receive_error = ccapi_receive_add_target(TARGET_USER_LED, update_user_led_cb,
			request_status_cb, 5); /* Max size of possible values (on, off, 0, 1, true, false): 5 */
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE) {
		log_error("Cannot register target '%s', error %d", TARGET_USER_LED,
				receive_error);
	}
	receive_error = ccapi_receive_add_target(TARGET_PLAY_MUSIC, play_music_cb,
			request_status_cb, 255);
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE) {
		log_error("Cannot register target '%s', error %d", TARGET_PLAY_MUSIC,
				receive_error);
	}

	return receive_error;
}

/*
 * stop_cb() - Data callback for 'stop_cc' device requests
 *
 * @target:					Target ID of the device request (stop_cc).
 * @transport:				Communication transport used by the device request.
 * @request_buffer_info:	Buffer containing the device request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 */
static ccapi_receive_error_t stop_cb(char const *const target, ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info)
{
	static char const stop_response[] = "I'll stop";

	UNUSED_ARGUMENT(request_buffer_info);

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);

	response_buffer_info->buffer = calloc(MAX_RESPONSE_SIZE + 1, sizeof(char));
	if (response_buffer_info->buffer == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	}

	response_buffer_info->length = snprintf(response_buffer_info->buffer,
			strlen(stop_response) + 1, "%s", stop_response);

	return CCAPI_RECEIVE_ERROR_NONE;
}

/*
 * get_time_cb() - Data callback for 'get_time' device requests
 *
 * @target:					Target ID of the device request (get_time).
 * @transport:				Communication transport used by the device request.
 * @request_buffer_info:	Buffer containing the device request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 */
static ccapi_receive_error_t get_time_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info)
{
	UNUSED_ARGUMENT(request_buffer_info);

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);

	response_buffer_info->buffer = calloc(MAX_RESPONSE_SIZE + 1, sizeof(char));
	if (response_buffer_info->buffer == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	}

	time_t t = time(NULL);
	response_buffer_info->length = snprintf(response_buffer_info->buffer,
			MAX_RESPONSE_SIZE, "Time: %s", ctime(&t));

	return CCAPI_RECEIVE_ERROR_NONE;
}

/*
 * update_user_led_cb() - Data callback for 'user_led' device requests
 *
 * @target:					Target ID of the device request (user_led).
 * @transport:				Communication transport used by the device request.
 * @request_buffer_info:	Buffer containing the device request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 */
static ccapi_receive_error_t update_user_led_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info)
{
	ccapi_receive_error_t ret = CCAPI_RECEIVE_ERROR_NONE;
	char *val = NULL, *error_msg = NULL;
	gpio_t *led = NULL;
	gpio_value_t led_value = GPIO_LOW;

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);

	response_buffer_info->buffer = calloc(MAX_RESPONSE_SIZE + 1, sizeof(char));
	val = calloc(request_buffer_info->length + 1, sizeof(char));
	if (response_buffer_info->buffer == NULL || val == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		ret = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto exit;
	}

	strncpy(val, request_buffer_info->buffer, request_buffer_info->length);
	log_dr_debug("%s=%s", target, val);

	if (strcmp(val, "true") == 0 || strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
		led_value = GPIO_HIGH;
	} else if (strcmp(val, "false") == 0 || strcmp(val, "off") == 0 || strcmp(val, "0") == 0) {
		led_value = GPIO_LOW;
	} else {
		error_msg = "Unknown LED status";
		ret = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		goto done;
	}

	/* Request User LED GPIO */
	led = ldx_gpio_request_by_alias(USER_LED_ALIAS, GPIO_OUTPUT_LOW, REQUEST_SHARED);
	if (led == NULL) {
		error_msg = "Failed to initialize LED";
		ret = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		goto done;
	}

	if (ldx_gpio_set_value(led, led_value) != EXIT_SUCCESS) {
		error_msg = "Failed to set LED";
		ret = CCAPI_RECEIVE_ERROR_STATUS_SESSION_ERROR;
		goto done;
	}

done:
	if (ret != CCAPI_RECEIVE_ERROR_NONE) {
		response_buffer_info->length = sprintf(response_buffer_info->buffer, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	} else {
		response_buffer_info->length = sprintf(response_buffer_info->buffer, "OK");
	}

exit:
	ldx_gpio_free(led);
	free(val);

	return ret;
}

/*
 * play_music_cb() - Data callback for 'play_music' device requests
 *
 * @target:					Target ID of the device request (play_music).
 * @transport:				Communication transport used by the device request.
 * @request_buffer_info:	Buffer containing the device request.
 * @response_buffer_info:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 */
static ccapi_receive_error_t play_music_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const request_buffer_info,
		ccapi_buffer_info_t *const response_buffer_info)
{
	char *request = request_buffer_info->buffer, *error_msg = NULL, *resp = NULL, *music_file = NULL;
	json_object *req = NULL, *json_element = NULL;
	ccapi_receive_error_t ret = CCAPI_RECEIVE_ERROR_NONE;
	bool play = false;

	log_dr_debug("%s: target='%s' - transport='%d'", __func__, target, transport);

	if (request_buffer_info->length == 0)
		goto bad_format;

	request[request_buffer_info->length] = '\0';
	req = json_tokener_parse(request);
	if (!req)
		goto bad_format;

	/* Read the "play" value. */
	if (json_object_object_get_ex(req, FIELD_PLAY, &json_element)) {
		if (!json_object_is_type(json_element, json_type_boolean))
			goto bad_format; /* Must be a boolean field. */
		play = json_object_get_boolean(json_element);
	} else {
		goto bad_format; /* Required field. */
	}

	/* Read the "music_file" value. */
	if (play) {
		if (json_object_object_get_ex(req, FIELD_MUSIC_FILE, &json_element)) {
			if (!json_object_is_type(json_element, json_type_string))
				goto bad_format; /* Must be a string field. */
			music_file = (char *)json_object_get_string(json_element);
		} else {
			goto bad_format; /* Required field. */
		}
	}

	response_buffer_info->buffer = calloc(MAX_RESPONSE_SIZE + 1, sizeof(char));
	if (response_buffer_info->buffer == NULL) {
		error_msg = "Insufficient memory";
		ret = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		log_dr_error("Cannot generate response for target '%s': %s", target, error_msg);
		goto done;
	}

	/* Stop any mpg123 process. Do not check for error because it will not return 0 if no music was playing. */
	execute_cmd(CMD_STOP_MUSIC, &resp, 2);

	/* If music is set to play, reproduce the sound. */
	if (play) {
		char *cmd = NULL;
		int cmd_len = 0;

		/* Verify that music file exists. */
		if (access(music_file, F_OK) != 0) {
			error_msg = "File does not exist";
			ret = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
			log_error("Error executing target '%s': Music file '%s' does not exist", target, music_file);
			goto done;
		}
		/* Build play command. */
		cmd_len = snprintf(NULL, 0, CMD_PLAY_MUSIC, music_file);
		cmd = calloc(cmd_len + 1, sizeof(char));
		if (cmd == NULL) {
			error_msg = "Insufficient memory";
			ret = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			log_error("Error executing target '%s': %s", target, error_msg);
		} else {
			sprintf(cmd, CMD_PLAY_MUSIC, music_file);
			/* Do not check for error because 'setsid' always returns -15. */
			execute_cmd(cmd, &resp, 2);
			free(cmd);
		}
	}

	goto done;

bad_format:
	error_msg = "Invalid format";
	ret = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
	log_dr_error("Cannot parse request for target '%s': Invalid request format", target);

done:
	if (ret != CCAPI_RECEIVE_ERROR_NONE) {
		response_buffer_info->length = sprintf(response_buffer_info->buffer, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	} else {
		response_buffer_info->length = sprintf(response_buffer_info->buffer, "OK");
	}

	/* Free resources. */
	free(resp);
	if (req && !json_object_is_type(req, json_type_string))
		json_object_put(req);

	return ret;
}

/*
 * request_status_cb() - Status callback for application device requests
 *
 * @target:                 Target ID of the device request.
 * @transport:              Communication transport used by the device request.
 * @response_buffer_info:   Buffer containing the response data.
 * @receive_error:          The error status of the receive process.
 *
 * This callback is executed when the receive process has finished. It doesn't
 * matter if everything worked or there was an error during the process.
 *
 * Cleans and frees the response buffer.
 */
static void request_status_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t *const response_buffer_info,
		ccapi_receive_error_t receive_error)
{
	log_dr_debug(
			"%s: target='%s' - transport='%d' - error='%d'", __func__, target,
			transport, receive_error);

	/* Free the response buffer */
	if (response_buffer_info != NULL)
		free(response_buffer_info->buffer);

	if (receive_error == CCAPI_RECEIVE_ERROR_NONE && strcmp(TARGET_STOP_CC, target) == 0)
		kill(getpid(), SIGINT);
}
