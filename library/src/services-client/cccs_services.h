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

#include "cc_logging.h"
/* Keep 'cccs_datapoints.h' before 'cc_utils.h' because 'cc_utils.h' uses:
     1. 'ccapi_timestamp_t' defined in 'ccapi/ccapi_datapoints.h'
     2. or 'cccs_timestamp_t' defined in 'cccs_datapoints.h' when building
        'services-client' code.
*/
#include "cccs_datapoints.h"
#include "cccs_receive.h"
#include "cc_utils.h"

#endif /* _CCCS_SERVICES_H_ */
