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

#include <errno.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include "ccapi/ccapi.h"
#include "cc_logging.h"
#include "service_device_request.h"
#include "service_dp_upload.h"
#include "services.h"
#include "services_util.h"

#define REQUEST_TAG_MAX_LENGTH	64

static pthread_t listen_thread;
static bool listen_thread_valid;
static volatile bool stop_listening = false;

typedef int (*request_handler_t)(int socket_fd);

struct handler_t {
	const char *request_tag;
	request_handler_t request_handler;
} request_handlers[] = {
	{
		REQ_TAG_DP_FILE_REQUEST,
		handle_datapoint_file_upload
	},
	{
		REQ_TAG_REGISTER_DR,
		handle_register_device_request
	},
	{
		REQ_TAG_UNREGISTER_DR,
		handle_unregister_device_request
	}
};

static void handle_requests(int fd)
{
	int request_sock;

	while (!stop_listening && (request_sock = accept4(fd, NULL, NULL, SOCK_CLOEXEC)) != -1) {
		char *request_tag = NULL;
		unsigned long i;
		bool handled = false;
		struct timeval timeout = {
			.tv_sec = 20,
			.tv_usec = 0
		};
		/* Read request tag (to select handler for this request) */
		if (read_string(request_sock, &request_tag, NULL, &timeout) < 0) {
			send_error(request_sock, "Failed to read request code");
			log_error("Error reading request tag, %s", strerror(errno));
			close(request_sock);
			continue;
		}

		/* Invoke the corresponding handler (only one handler per request */
		for (i = 0; i < ARRAY_SIZE(request_handlers); i++) {
			const struct handler_t *handler = &request_handlers[i];

			if (!strcmp(request_tag, handler->request_tag)) {
				if (handler->request_handler(request_sock))
					log_error("Error handling request tagged with: '%s'", request_tag);

				handled = true;

				break;
			}
		}

		/* Error on requets that cannot be handled, and clean up */
		if (!handled)
			send_error(request_sock, "Invalid request type");

		if (close(request_sock) < 0)
			log_warning("Could not close service socket after attending request: %s", strerror(errno));

		free(request_tag);
	}
}

static void *listen_threaded(void *unused)
{
	struct sockaddr_in addr;
	int fd;
	int n_options = 1;

	UNUSED_ARGUMENT(unused);

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return NULL;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &n_options, sizeof(n_options)) < 0)
		log_warning("Failed to set SO_REUSE* on request serversocket: %s", strerror(errno));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(CONNECTOR_REQUEST_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *) &addr, sizeof addr) || listen(fd, 3)) {
		log_error("%s", "Failed to bind to local socket");
		goto done;
	}

	handle_requests(fd);

done:
	close(fd);

	pthread_exit(NULL);

	return NULL;
}

void start_listening_for_local_requests(void)
{
	pthread_attr_t attr;

	listen_thread_valid = (pthread_attr_init(&attr) == 0);
	if (!listen_thread_valid) {
		log_error("Unable to start listening for requests (%d)", listen_thread_valid);
		return;
	}

	listen_thread_valid = (pthread_create(&listen_thread, &attr, listen_threaded, NULL) == 0);
	if (!listen_thread_valid)
		log_error("Unable to start sending response (%d)", listen_thread_valid);

	pthread_attr_destroy(&attr);
}

void stop_listening_for_local_requests(void)
{
	if (stop_listening)
		return;

	stop_listening = true;

	if (listen_thread_valid) {
		pthread_cancel(listen_thread);
		pthread_join(listen_thread, NULL);
	}
}
