/* main.c
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
 * wolfNanoTLS crypto-floor self-test, run on an emulated Cortex-M33 (STM32H563)
 * under m33mu. Exercises the Thumb2 wolfcrypt floor with deterministic KATs,
 * prints results over UART, and traps bkpt #0x7e on success so m33mu's
 * --expect-bkpt=0x7e gates the run. No entropy or transport needed.
 */

#include <stdio.h>
#include <string.h>
#include "emu_app.h"
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>

static int g_fail = 0;

static void report(const char* name, int ok)
{
    printf("  %s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        g_fail = 1;
    }
}

/* SHA-256("abc") (FIPS 180-4). */
static void kat_sha256(void)
{
    static const byte exp[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    wc_Sha256 sha;
    byte out[32];
    int rc;

    rc  = wc_InitSha256(&sha);
    rc |= wc_Sha256Update(&sha, (const byte*)"abc", 3);
    rc |= wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    report("SHA-256 KAT (abc)", (rc == 0) && (memcmp(out, exp, 32) == 0));
}

/* AES-128-GCM all-zero key/iv/pt (NIST). */
static void kat_aesgcm(void)
{
    static const byte zero[16] = {0};
    static const byte iv[12] = {0};
    static const byte ct_exp[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const byte tag_exp[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    Aes aes;
    byte ct[16], tag[16], dec[16];
    int rc, ok;

    rc  = wc_AesInit(&aes, NULL, INVALID_DEVID);
    rc |= wc_AesGcmSetKey(&aes, zero, sizeof(zero));
    rc |= wc_AesGcmEncrypt(&aes, ct, zero, sizeof(zero), iv, sizeof(iv),
                           tag, sizeof(tag), NULL, 0);
    ok = (rc == 0) && (memcmp(ct, ct_exp, 16) == 0) &&
         (memcmp(tag, tag_exp, 16) == 0);
    rc = wc_AesGcmDecrypt(&aes, dec, ct, sizeof(ct), iv, sizeof(iv),
                          tag, sizeof(tag), NULL, 0);
    ok = ok && (rc == 0) && (memcmp(dec, zero, 16) == 0);
    wc_AesFree(&aes);
    report("AES-128-GCM KAT", ok);
}

int main(void)
{
    emu_uart_init();
    printf("wolfNanoTLS m33mu floor self-test (Cortex-M33 / STM32H563)\n");

    kat_sha256();
    kat_aesgcm();

    if (g_fail == 0) {
        printf("wolfNanoTLS floor: all KATs pass\n");
        __asm volatile("bkpt #0x7e");
    }
    else {
        printf("wolfNanoTLS floor: KAT FAILURE\n");
        __asm volatile("bkpt #0x01");
    }

    while (1) {
        __asm volatile("wfi");
    }
}
