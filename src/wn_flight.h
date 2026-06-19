/* wn_flight.h
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
 * TLS 1.3 server-flight message-ordering gate (RFC 8446 4.4): the encrypted
 * flight must be EncryptedExtensions, [CertificateRequest], Certificate,
 * CertificateVerify, Finished, in that order, no duplicates, nothing else.
 * Pure logic, header-only so wn_connect.c and the unit test share one copy.
 */

#ifndef WN_FLIGHT_H
#define WN_FLIGHT_H

#include "wolfnano.h"

#define WN_FLIGHT_EE        8
#define WN_FLIGHT_CERT      11
#define WN_FLIGHT_CERT_REQ  13
#define WN_FLIGHT_CERT_VFY  15
#define WN_FLIGHT_FINISHED  20

/* Validate handshake message type mType against the messages seen so far,
 * updating the flags. Returns WOLFNANOTLS_SUCCESS or WOLFNANOTLS_E_UNEXPECTED_MSG. */
static int wn_FlightOrder(byte mType, int* gotEE, int* gotCert, int* gotCv)
{
    int ret = WOLFNANOTLS_SUCCESS;

    if (mType == WN_FLIGHT_EE) {
        if (*gotEE) {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
        }
        *gotEE = 1;
    }
    else if (mType == WN_FLIGHT_CERT_REQ) {
        if ((*gotEE == 0) || *gotCert) {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
        }
    }
    else if (mType == WN_FLIGHT_CERT) {
        if ((*gotEE == 0) || *gotCert) {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
        }
        *gotCert = 1;
    }
    else if (mType == WN_FLIGHT_CERT_VFY) {
        if ((*gotCert == 0) || *gotCv) {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
        }
        *gotCv = 1;
    }
    else if (mType == WN_FLIGHT_FINISHED) {
        if (*gotCv == 0) {
            ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
        }
    }
    else {
        ret = WOLFNANOTLS_E_UNEXPECTED_MSG;
    }

    return ret;
}

#endif /* WN_FLIGHT_H */
