/* interop_cert_test.c
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

/* Live interop: wolfNanoTLS TLS 1.3 ECDHE + certificate client against a peer
 * presenting the pinned ECDSA P-256 certificate. */

#include "wn_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int sock_send(void* ctx, const byte* buf, word32 len)
{
    return (int)send(*(int*)ctx, buf, len, 0);
}

static int sock_recv(void* ctx, byte* buf, word32 len)
{
    return (int)recv(*(int*)ctx, buf, len, 0);
}

int main(int argc, char** argv)
{
    const char* anchorPath;
    byte anchor[4096];
    struct sockaddr_in sa;
    WC_RNG rng;
    byte scratch[16384];
    FILE* f;
    size_t anchorLen;
    int fd, port, rc, tries;

    port = (argc > 1) ? atoi(argv[1]) : 4433;
    anchorPath = (argc > 2) ? argv[2] : "tests/pki/server/ec-cert.der";

    f = fopen(anchorPath, "rb");
    if (f == NULL) {
        printf("cannot open anchor %s\n", anchorPath);
        return 2;
    }
    anchorLen = fread(anchor, 1, sizeof(anchor), f);
    fclose(f);
    if (anchorLen == 0) {
        printf("empty anchor\n");
        return 2;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    XMEMSET(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    rc = -1;
    tries = 0;
    while ((tries < 50) && (rc != 0)) {
        rc = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
        if (rc != 0) {
            usleep(50000);
            tries++;
        }
    }
    if (rc != 0) {
        printf("connect failed\n");
        return 2;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng failed\n");
        return 2;
    }

    rc = wn_Connect_Cert(&rng, sock_send, sock_recv, &fd, anchor,
                         (word32)anchorLen, scratch, sizeof(scratch));

    wc_FreeRng(&rng);
    close(fd);

    printf("wn_Connect_Cert = %d\n", rc);
    printf("%s\n", (rc == 0) ? "PASS TLS 1.3 cert handshake" : "FAIL handshake");
    return (rc == 0) ? 0 : 1;
}
