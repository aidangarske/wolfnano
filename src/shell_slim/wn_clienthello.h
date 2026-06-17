/* wn_clienthello.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfNano.
 *
 * wolfNano is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfNano is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * TLS 1.3 ClientHello encoder (RFC 8446 section 4.1.2). Offers
 * TLS_AES_128_GCM_SHA256, X25519, and the signature algorithms wolfNano
 * supports. Caller-provided output buffer; no allocation.
 */

#ifndef WN_CLIENTHELLO_H
#define WN_CLIENTHELLO_H

#include "wolfnano.h"

#define WN_CIPHER_AES_128_GCM_SHA256 0x1301

/* Encode a ClientHello handshake message (type 1 + length + body) into out.
 * random32 is the 32-byte ClientHello.random; sessionId/sessionIdLen is the
 * legacy_session_id (0..32); x25519Pub is the 32-byte X25519 key share. */
WOLFNANO_API int wn_ClientHello_Build(byte* out, word32* outLen, word32 outCap,
                                      const byte* random32,
                                      const byte* sessionId, word32 sessionIdLen,
                                      const byte* x25519Pub, word32 x25519PubLen);

#endif /* WN_CLIENTHELLO_H */
