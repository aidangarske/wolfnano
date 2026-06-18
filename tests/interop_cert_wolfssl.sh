#!/bin/sh
# Live interop: stock wolfSSL example server presenting the pinned ECDSA P-256
# cert, wolfNano certificate client against it.
set -u
PORT=14436
SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
WOLFSSL_DIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
CERT="$(pwd)/test-pki/server/ec-cert.pem"
KEY="$(pwd)/test-pki/server/ec-key.pem"
ANCHOR="$(pwd)/test-pki/server/ec-cert.der"

if [ ! -x "$SERVER" ] || [ ! -f "$CERT" ]; then
    echo "SKIP wolfSSL cert interop (server or cert not found)"
    exit 0
fi

( cd "$WOLFSSL_DIR" && "$SERVER" -v 4 -c "$CERT" -k "$KEY" -d -i -p "$PORT" ) \
    >/tmp/wn_cert_wssl.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    echo "SKIP wolfSSL cert interop (server did not start)"
    exit 0
fi

./build/interop_cert_client "$PORT" "$ANCHOR"
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
