/*
 * Copyright (c) 2017 Digi International Inc.
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
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */

#ifndef CC_DEVICE_REQUEST_H_
#define CC_DEVICE_REQUEST_H_

#include "ccapi/ccapi.h"

#define UNUSED_PARAMETER(a) (void)(a)

ccapi_bool_t app_receive_default_accept_cb(char const *const target, ccapi_transport_t const transport);
void app_receive_default_data_cb(char const *const target, ccapi_transport_t const transport, ccapi_buffer_info_t const *const request_buffer_info, ccapi_buffer_info_t *const response_buffer_info);
void app_receive_default_status_cb(char const *const target, ccapi_transport_t const transport, ccapi_buffer_info_t *const response_buffer_info, ccapi_receive_error_t receive_error);

#endif /* CC_DEVICE_REQUEST_H_ */
