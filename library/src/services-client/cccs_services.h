/*
 * Copyright (c) 2023 Digi International Inc.
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

#ifndef _CCCS_SERVICES_H_
#define _CCCS_SERVICES_H_

#include <stdbool.h>

#include "cc_logging.h"
/* Keep 'cccs_datapoints.h' before 'cc_utils.h' because:
  'cc_utils.h' uses 'ccapi_timestamp_t' defined in 'cccs_datapoints.h' and in
  'ccapi/ccapi_datapoints.h'
*/
#include "cccs_datapoints.h"
#include "cccs_receive.h"
#include "cc_utils.h"

typedef enum {
	CCCS_SEND_ERROR_NONE,
	CCCS_SEND_ERROR_ERROR_FROM_DAEMON,
	CCCS_SEND_ERROR_INVALID_ARGUMENT,
	CCCS_SEND_ERROR_OUT_OF_MEMORY,
	CCCS_SEND_ERROR_LOCK,
	CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON,
	CCCS_SEND_ERROR_BAD_RESPONSE,
	CCCS_SEND_ERROR_FROM_CLOUD,
} cccs_comm_error_t;

typedef struct {
	int code;
	char *hint;
} cccs_resp_t;

typedef ccapi_receive_error_t (*cccs_request_data_cb_t)(char const * const target,
	ccapi_buffer_info_t const * const request_buffer_info,
	ccapi_buffer_info_t * const response_buffer_info);
typedef void (*cccs_request_status_cb_t)(char const * const target,
	ccapi_buffer_info_t * const response_buffer_info,
	int receive_error, const char * const receive_error_hint);

/*
 * cccs_send_dp_csv_file() - Send provided CSV file with data points to CCCS daemon
 *
 * @path:	Absolute path of the CSV file.
 * @timeout:	Number of seconds to wait for a CCCS daemon response.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Each line of the CSV file represents a data point following the format:
 *
 * DATA,TIMESTAMP,QUALITY,DESCRIPTION,LOCATION,DATA_TYPE,UNITS,FORWARD_TO,STREAM_ID
 *
 * Where:
 *    - DATA:			Value of the data point.
 *      				It must be in the format specified by 'DATA_TYPE'.
 *    - TIMESTAMP:		Specifies when the value was captured.
 *      				It can be a:
 *      					- 64-bit unsigned integer with the number of milliseconds since 00:00:00 UTC on 1 January 1970.
 *      					- A quoted string with the timestamp in ISO 8601 format.
 *      				If it is empty, Remote Manager will add it according to the time of the upload.
 *    - QUALITY:		Value to define the quality of the sample.
 *      				It must be an integer value.
 *    - DESCRIPTION:	Sample description.
 *      				Empty not to use it.
 *    - LOCATION:		Value to establish the device location when the sample was taken.
 *      				Three float values separated by commas with leading and trailing quotes:
 *      							"X.x,Y.y,H.h"
 *      				Empty not to use it.
 *    - DATA_TYPE:		Type of the data point. One of the following:
 *      				INTEGER, LONG, FLOAT, DOUBLE, STRING, JSON, GEOJSON
 *    - UNITS:			String to define the unit of the data, such as, seconds, C, etc.
 *      				Empty not to use it.
 *    - FORWARD_TO:		Name of the data stream to replicate data points to.
 *      				Empty not to use it.
 *    - STREAM_ID:		Name of the data stream destination in Remote Manager.
 *
 * For example:
 *
 * 3600,1685440800000,,,,INTEGER,seconds,,/mystream/integer
 * 27.450000,1685440800000,,,,FLOAT,%,,/mystream/float
 * 21987692,1685440800000,,,,LONG,bytes,,/mystream/long
 * "string test",1685440800000,,,,STRING,,/mystream/string
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_csv_file(const char *path, unsigned long const timeout, cccs_resp_t *resp);

/*
 * cccs_send_dp_collection() - Send provided data point collection to CCCS daemon
 *
 * @dp_collection:	Data point collection to send to CCCS daemon.
 * @resp:		Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_collection(ccapi_dp_collection_handle_t const dp_collection, cccs_resp_t *resp);

/*
 * cccs_send_dp_collection_tout() - Send provided data point collection to CCCS daemon
 *
 * @dp_collection:	Data point collection to send to CCCS daemon.
 * @timeout:		Number of seconds to wait for response from the daemon.
 * @resp:		Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_collection_tout(ccapi_dp_collection_handle_t const dp_collection,
	unsigned long const timeout, cccs_resp_t *resp);

/*
 * cccs_add_request_target() - Register a request target
 *
 * @target:	Target name to register.
 * @data_cb:	Callback function executed when a request for the provided
 *		target is received.
 * @status_cb:	Callback function executed when the receive process has completed.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_add_request_target(char const * const target,
	cccs_request_data_cb_t data_cb, cccs_request_status_cb_t status_cb,
	cccs_resp_t *resp);

/*
 * cccs_add_request_target_tout() - Register a request target
 *
 * @target:	Target name to register.
 * @data_cb:	Callback function executed when a request for the provided
 *		target is received.
 * @status_cb:	Callback function executed when the receive process has completed.
 * @timeout:	Number of seconds to wait for response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_add_request_target_tout(char const * const target,
	cccs_request_data_cb_t data_cb, cccs_request_status_cb_t status_cb,
	unsigned long timeout, cccs_resp_t *resp);

/*
 * cccs_remove_request_target() - Unregister a request target
 *
 * @target:	Target name to unregister.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_remove_request_target(char const * const target, cccs_resp_t *resp);

/*
 * cccs_remove_request_target_tout() - Unregister a request target
 *
 * @target:	Target name to unregister.
 * @timeout:	Number of seconds to wait for response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_remove_request_target_tout(char const * const target,
	unsigned long timeout, cccs_resp_t *resp);

#endif /* _CCCS_SERVICES_H_ */
