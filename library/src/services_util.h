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

#ifndef SERVICES_UTIL_H
#define SERVICES_UTIL_H

#include "ccapi/ccapi.h"

/*
 * DRM imposes a timeout of 75 seconds for synchronous SCI requests, so
 * it does not make sense for the connector to wait any longer for
 * the response.
 */

/* TODO: Move to a DAL configuration option */
#define SOCKET_READ_TIMEOUT_SEC		75

const char *to_send_error_msg(ccapi_send_error_t error);

int read_uint32(int fd, uint32_t * const ret, struct timeval *timeout);
int write_uint32(int fd, const uint32_t value);

int read_string(int fd, char **string, size_t *length, struct timeval *timeout);
int write_string(int fd, const char *string );

int read_blob(int fd, void **buffer, size_t *length, struct timeval *timeout);
int write_blob(int fd, const void *data, size_t data_length);

int send_ok(int fd);
int send_error(int fd, const char *msg);

int execute_cmd(const char *cmd, char **resp, int timeout);
pid_t _process_exec_fd(int infd, int outfd, int errfd, const char *cmd, ...);
#define process_exec_fd(tout, ...) _process_exec_fd(tout, __VA_ARGS__, NULL)
int process_wait(pid_t pid);

#endif
