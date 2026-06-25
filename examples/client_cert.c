/* client_cert.c
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
 * Minimal wolfNano TLS 1.3 client: ECDHE handshake with X.509 server-cert
 * authentication, then one application-data round trip and a clean close.
 * The server leaf must verify against the pinned trust anchor (DER). Shows
 * the cert lifecycle: wn_Connect_CertName_ex -> wn_Send -> wn_Recv -> wn_Close.
 *
 * host is resolved (so it can be a DNS name) and matched against the leaf's
 * SAN/CN; it must match the served certificate's name.
 *
 * Usage: client_cert <host> <port> <anchor.der>
 *        (default localhost 4433 tests/pki/server/ec-cert.der)
 * Try it against wolfSSL's example server presenting that cert:
 *   examples/server/server -v 4 -c tests/pki/server/ec-cert.pem \
 *     -k tests/pki/server/ec-key.pem -d -i -p 4433
 */

#include "wn_connect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

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
    static const byte msg[] = "hello from wolfNano\n";
    const char* host = (argc > 1) ? argv[1] : "localhost";
    const char* port = (argc > 2) ? argv[2] : "4433";
    const char* anchorPath =
        (argc > 3) ? argv[3] : "tests/pki/server/ec-cert.der";
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* ai;
    WC_RNG rng;
    wn_Session sess;
    byte anchor[4096];
    byte scratch[12288];
    byte in[512];
    FILE* f;
    size_t anchorLen;
    word32 got = 0;
    int fd = -1, rc;

    f = fopen(anchorPath, "rb");
    if (f == NULL) {
        printf("cannot open anchor %s\n", anchorPath);
        return 1;
    }
    anchorLen = fread(anchor, 1, sizeof(anchor), f);
    fclose(f);
    if (anchorLen == 0) {
        printf("empty anchor %s\n", anchorPath);
        return 1;
    }

    XMEMSET(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        printf("resolve %s failed\n", host);
        return 1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        printf("connect to %s:%s failed\n", host, port);
        return 1;
    }

    if (wc_InitRng(&rng) != 0) {
        printf("rng init failed\n");
        close(fd);
        return 1;
    }

    /* Bind the server identity to <host>: the leaf must chain to the anchor and
     * present <host> in its SAN/CN. Pass an SPKI pin instead of host (or both)
     * to authenticate one fixed server by key. host must match the cert. */
    rc = wn_Connect_CertName_ex(&sess, &rng, sock_send, sock_recv, &fd, anchor,
                                (word32)anchorLen, host, NULL, 0,
                                scratch, sizeof(scratch));
    if (rc != 0) {
        printf("handshake failed: %d\n", rc);
        wc_FreeRng(&rng);
        close(fd);
        return 1;
    }
    printf("TLS 1.3 cert handshake complete\n");

    rc = wn_Send(&sess, msg, (word32)(sizeof(msg) - 1));
    if (rc == 0) {
        rc = wn_Recv(&sess, in, sizeof(in), &got);
    }
    if (rc == 0) {
        printf("received %u bytes: %.*s\n", (unsigned)got, (int)got, in);
    }
    else {
        printf("application data failed: %d\n", rc);
    }

    wn_Close(&sess);
    wc_FreeRng(&rng);
    close(fd);

    return (rc == 0) ? 0 : 1;
}
