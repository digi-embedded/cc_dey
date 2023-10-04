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

#include "ccimp/ccimp_logging.h"

#if (defined UNIT_TEST)
#define ccimp_hal_logging_vprintf       ccimp_hal_logging_vprintf_real
#endif

/******************** LINUX IMPLEMENTATION ********************/

#if (defined CCIMP_DEBUG_ENABLED)
#include <stdio.h>
#include <stdlib.h>

void ccimp_hal_logging_vprintf(debug_t const debug, char const * const format, va_list args)
{
    if ((debug == debug_all) || (debug == debug_beg))
    {
        /* lock mutex here. */
        printf("CCAPI: ");
    }

    vprintf(format, args);

    if ((debug == debug_all) || (debug == debug_end))
    {
        /* unlock mutex here */
        printf("\n");
        fflush(stdout);
    }
}
#else
 /* to avoid ISO C forbids an empty translation unit compiler error */
typedef int dummy;
#endif
