/* wn_keyshare.h
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
 * TLS 1.3 (EC)DHE key share (RFC 8446 section 4.2.8). X25519 over the wc_* seam.
 * Caller holds the context; no allocation.
 */

#ifndef WN_KEYSHARE_H
#define WN_KEYSHARE_H

#include "wolfnano.h"
#include "wolfnano_crypto.h"
#ifdef WOLFNANOTLS_HAVE_ECDHE_P256
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef WOLFNANOTLS_HAVE_MLKEM_HYBRID
    #include "wn_hybrid.h"
#endif

/* TLS supported_groups code points. */
#define WN_GROUP_X25519    0x001d
#define WN_GROUP_SECP256R1 0x0017

#define WN_X25519_KEY_SZ 32

#if defined(WOLFNANOTLS_HAVE_MLKEM_HYBRID)
    #define WN_KEYSHARE_MAX_PUB    WN_HYBRID_CLIENT_SHARE
    #define WN_DEFAULT_GROUP       WN_GROUP_X25519MLKEM768
    #define WN_DEFAULT_PUB_SZ      WN_HYBRID_CLIENT_SHARE
    #define WN_DEFAULT_SRV_SHARE_SZ WN_HYBRID_SERVER_SHARE
    #define WN_DEFAULT_SECRET_SZ   WN_HYBRID_SECRET
#elif defined(WOLFNANOTLS_HAVE_ECDHE_P256)
    #define WN_SECP256R1_PUB_SZ    65   /* uncompressed point 0x04||X||Y */
    #define WN_SECP256R1_SECRET_SZ 32   /* X coordinate */
    #define WN_KEYSHARE_MAX_PUB    65
    #define WN_DEFAULT_GROUP       WN_GROUP_SECP256R1
    #define WN_DEFAULT_PUB_SZ      WN_SECP256R1_PUB_SZ
    #define WN_DEFAULT_SRV_SHARE_SZ WN_SECP256R1_PUB_SZ
    #define WN_DEFAULT_SECRET_SZ   WN_SECP256R1_SECRET_SZ
#else
    #define WN_KEYSHARE_MAX_PUB    32
    #define WN_DEFAULT_GROUP       WN_GROUP_X25519
    #define WN_DEFAULT_PUB_SZ      WN_X25519_KEY_SZ
    #define WN_DEFAULT_SRV_SHARE_SZ WN_X25519_KEY_SZ
    #define WN_DEFAULT_SECRET_SZ   WN_X25519_KEY_SZ
#endif

typedef struct wn_KeyShare {
#if defined(WOLFNANOTLS_HAVE_MLKEM_HYBRID)
    wn_Hybrid hybrid;
#elif defined(WOLFNANOTLS_HAVE_ECDHE_P256)
    ecc_key ecc;
#else
    curve25519_key x25519;
#endif
    int group;
} wn_KeyShare;

/* Initialise a key share for the given group. */
WOLFNANOTLS_API int wn_KeyShare_Init(wn_KeyShare* ks, int group);

/* Generate the ephemeral key pair; pub receives the wire-format public key
 * (little-endian for X25519), pubLen its length. */
WOLFNANOTLS_API int wn_KeyShare_Generate(wn_KeyShare* ks, WC_RNG* rng,
                                      byte* pub, word32* pubLen);

/* Compute the shared secret from the peer public key. */
WOLFNANOTLS_API int wn_KeyShare_Shared(wn_KeyShare* ks, const byte* peerPub,
                                    word32 peerPubLen, byte* out,
                                    word32* outLen);

/* Release the key share. */
WOLFNANOTLS_API int wn_KeyShare_Free(wn_KeyShare* ks);

#endif /* WN_KEYSHARE_H */
