/* alert_map_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNanoTLS.
 *
 * wolfNanoTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNanoTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "wn_alert.h"
#include <stdio.h>

static int fails = 0;

static void check(int ok, const char* name)
{
    printf("%s %s\n", ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", name);
    if (!ok) {
        fails++;
    }
}

int main(void)
{
    check(wn_ErrToAlert(WOLFNANO_E_UNEXPECTED_MSG) == WN_ALERT_UNEXPECTED_MESSAGE,
          "unexpected_message -> 10");
    check(wn_ErrToAlert(WOLFNANO_E_BAD_MAC) == WN_ALERT_BAD_RECORD_MAC,
          "bad_record_mac -> 20");
    check(wn_ErrToAlert(WOLFNANO_E_DECODE) == WN_ALERT_DECODE_ERROR,
          "decode_error -> 50");
    check(wn_ErrToAlert(WOLFNANO_E_ILLEGAL_PARAM) == WN_ALERT_ILLEGAL_PARAMETER,
          "illegal_parameter -> 47");
    check(wn_ErrToAlert(WOLFNANO_E_BAD_CERT) == WN_ALERT_BAD_CERTIFICATE,
          "bad_certificate -> 42");

    check(wn_ErrToAlert(WOLFNANO_E_CRYPTO) == WN_ALERT_INTERNAL_ERROR,
          "generic crypto error -> internal_error 80");
    check(wn_ErrToAlert(WOLFNANO_E_INVALID_ARG) == WN_ALERT_INTERNAL_ERROR,
          "invalid arg -> internal_error 80");
    check(wn_ErrToAlert(WOLFNANO_E_BAD_STATE) == WN_ALERT_INTERNAL_ERROR,
          "bad state -> internal_error 80");
    check(wn_ErrToAlert(WOLFNANO_SUCCESS) == WN_ALERT_INTERNAL_ERROR,
          "success (should never alert) -> internal_error 80");

    if (fails == 0) {
        printf("alert_map_test: all checks passed\n");
    }
    else {
        printf("alert_map_test: %d FAILED\n", fails);
    }

    return fails == 0 ? 0 : 1;
}
