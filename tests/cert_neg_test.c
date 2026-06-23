/* cert_neg_test.c
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

/* Negative authentication coverage for the X.509 cert path: a tampered chain
 * must fail wn_VerifyChain, and a tampered ECDSA CertificateVerify (0x0403)
 * must fail wn_CertVerify. Guards against the auth checks being silently
 * neutralized (mutation survival).
 */

#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/certs_test.h>
#include <stdio.h>

#include "../src/wn_connect.c"

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
    WC_RNG rng;
    ecc_key ek;
    byte th[32];
    byte tbs[64 + 33 + 1 + 32];
    byte spki[256];
    byte hash[32];
    byte sig[256];
    byte tamper[sizeof(serv_ecc_der_256)];
    byte leafSpki[512];
    const byte* certs[1];
    word32 certLens[1];
    word32 tbsLen = 0;
    word32 sigLen;
    word32 leafSpkiLen;
    int spkiLen, rc, vr, ekInit = 0;
    word32 i;

    printf("wolfNano X.509 negative auth test (chain + ECDSA CertificateVerify)\n");

    for (i = 0; i < sizeof(th); i++) {
        th[i] = (byte)i;
    }
    wn_BuildCvTbs(tbs, &tbsLen, th, sizeof(th));

    rc = wc_InitRng(&rng);
    check(rc == 0, "RNG init");

    rc = wc_ecc_init(&ek);
    if (rc == 0) {
        ekInit = 1;
        rc = wc_ecc_make_key(&rng, 32, &ek);
    }
    check(rc == 0, "P-256 keygen");

    spkiLen = wc_EccPublicKeyToDer(&ek, spki, (word32)sizeof(spki), 1);
    check(spkiLen > 0, "export public key to SPKI DER");

    rc = wc_Hash(WC_HASH_TYPE_SHA256, tbs, tbsLen, hash, sizeof(hash));
    sigLen = (word32)sizeof(sig);
    if (rc == 0) {
        rc = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, &rng, &ek);
    }
    check(rc == 0, "sign CertificateVerify TBS (ECDSA)");

    vr = wn_CertVerify(0x0403, spki, (word32)spkiLen, th, sizeof(th), sig,
                     sigLen);
    check(vr == WOLFNANO_SUCCESS, "ECDSA CertificateVerify accepted (0x0403)");

    sig[10] ^= 0x01;
    vr = wn_CertVerify(0x0403, spki, (word32)spkiLen, th, sizeof(th), sig,
                     sigLen);
    check(vr != WOLFNANO_SUCCESS, "tampered ECDSA signature rejected");

    certs[0] = serv_ecc_der_256;
    certLens[0] = (word32)sizeof_serv_ecc_der_256;
    leafSpkiLen = (word32)sizeof(leafSpki);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, leafSpki,
                        &leafSpkiLen);
    check(rc == WOLFNANO_SUCCESS, "valid ECC chain verified");

    XMEMCPY(tamper, serv_ecc_der_256, sizeof(serv_ecc_der_256));
    tamper[sizeof(tamper) - 1] ^= 0x01;
    certs[0] = tamper;
    certLens[0] = (word32)sizeof(tamper);
    leafSpkiLen = (word32)sizeof(leafSpki);
    rc = wn_VerifyChain(certs, certLens, 1, ca_ecc_cert_der_256,
                        (word32)sizeof_ca_ecc_cert_der_256, leafSpki,
                        &leafSpkiLen);
    check(rc == WOLFNANO_E_BAD_CERT, "tampered ECC chain rejected");

    if (ekInit) {
        wc_ecc_free(&ek);
    }
    wc_FreeRng(&rng);

    printf("\n%s (%d failure%s)\n", fails ? "\033[31mFAILED\033[0m" : "\033[32mALL PASS\033[0m",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
