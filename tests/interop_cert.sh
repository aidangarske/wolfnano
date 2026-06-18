#!/bin/sh
# Live interop: openssl s_server with the pinned ECDSA P-256 cert, wolfNanoTLS
# certificate client against it.
set -u
PORT=14435
CERT=test-pki/server/ec-cert.pem
KEY=test-pki/server/ec-key.pem

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "SKIP cert interop (test cert missing; run the cert generation step)"
    exit 0
fi

openssl s_server -cert "$CERT" -key "$KEY" -tls1_3 -accept "$PORT" -quiet \
    >/tmp/wn_cert_srv.log 2>&1 &
SPID=$!

sleep 1
if ! kill -0 "$SPID" 2>/dev/null; then
    echo "SKIP cert interop (server did not start)"
    exit 0
fi

./build/interop_cert_client "$PORT" test-pki/server/ec-cert.der
RC=$?

kill "$SPID" 2>/dev/null
wait "$SPID" 2>/dev/null
exit $RC
