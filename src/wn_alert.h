/* wn_alert.h
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

/**
 * Maps a wolfNanoTLS internal error to a TLS 1.3 alert description
 * (RFC 8446 6.2). Pure logic, header-only so wn_connect.c and the unit test
 * share one copy.
 */

#ifndef WN_ALERT_H
#define WN_ALERT_H

#include "wolfnano.h"

#define WN_ALERT_UNEXPECTED_MESSAGE   10
#define WN_ALERT_BAD_RECORD_MAC       20
#define WN_ALERT_ILLEGAL_PARAMETER    47
#define WN_ALERT_DECODE_ERROR         50
#define WN_ALERT_BAD_CERTIFICATE      42
#define WN_ALERT_INTERNAL_ERROR       80

/* Return the RFC 8446 6.2 alert description for an internal error code. */
static byte wn_ErrToAlert(int ret)
{
    byte d;

    switch (ret) {
        case WOLFNANOTLS_E_UNEXPECTED_MSG: d = WN_ALERT_UNEXPECTED_MESSAGE; break;
        case WOLFNANOTLS_E_BAD_MAC:        d = WN_ALERT_BAD_RECORD_MAC;     break;
        case WOLFNANOTLS_E_DECODE:         d = WN_ALERT_DECODE_ERROR;       break;
        case WOLFNANOTLS_E_ILLEGAL_PARAM:  d = WN_ALERT_ILLEGAL_PARAMETER;  break;
        case WOLFNANOTLS_E_BAD_CERT:       d = WN_ALERT_BAD_CERTIFICATE;    break;
        default:                        d = WN_ALERT_INTERNAL_ERROR;     break;
    }

    return d;
}

#endif /* WN_ALERT_H */
