#!/bin/sh
# Run every wolfNano example that talks to a local TLS 1.3 peer against stock
# wolfSSL's example server: the PSK example (-s -i), the X.509 cert example
# (-c -k -d -i), and the PQC hybrid example (--pqc X25519MLKEM768). Each example
# is the same binary a user builds from examples/, exercised end to end. Skips
# cleanly when the relevant server binary or build artifact is absent so it is
# safe to run anywhere. The live HTTPS example needs the public internet and is
# run separately by live-connect.yml.
set -u

SERVER=${WOLFSSL_SERVER:-$HOME/wolfssl/examples/server/server}
PQC_SERVER=${WOLFSSL_PQC_SERVER:-}
CERT_HOST=${CERT_HOST:-wolfNano-test}
BUILD=${BUILD:-./build}
FAILED=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }
red() { printf "\033[31m%s\033[0m\n" "$1"; }

run_psk() {
    PORT=14480
    if [ ! -x "$SERVER" ]; then
        yellow "SKIP PSK example (wolfSSL server not found at $SERVER)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
    ( cd "$WDIR" && "$SERVER" -v 4 -s -i -p "$PORT" ) >/tmp/wn_ex_psk.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP PSK example (server did not start; may lack PSK support)"
        return 0
    fi
    "$BUILD/example_client" 127.0.0.1 "$PORT"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS PSK example"
    else
        red "FAIL PSK example (rc=$RC)"
        FAILED=1
    fi
}

run_cert() {
    PORT=14481
    CERT="$(pwd)/tests/pki/server/ec-cert.pem"
    KEY="$(pwd)/tests/pki/server/ec-key.pem"
    ANCHOR="$(pwd)/tests/pki/server/ec-cert.der"
    if [ ! -x "$SERVER" ] || [ ! -f "$CERT" ]; then
        yellow "SKIP cert example (wolfSSL server or cert not found)"
        return 0
    fi
    if ! getent hosts "$CERT_HOST" >/dev/null 2>&1 \
            && ! grep -q "$CERT_HOST" /etc/hosts 2>/dev/null; then
        yellow "SKIP cert example ($CERT_HOST does not resolve; map it to"
        echo "     127.0.0.1 in /etc/hosts to run the hostname-checked path)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$SERVER")")")
    ( cd "$WDIR" && "$SERVER" -v 4 -c "$CERT" -k "$KEY" -d -i -p "$PORT" ) \
        >/tmp/wn_ex_cert.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP cert example (server did not start)"
        return 0
    fi
    "$BUILD/example_client_cert" "$CERT_HOST" "$PORT" "$ANCHOR"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS cert example"
    else
        red "FAIL cert example (rc=$RC)"
        FAILED=1
    fi
}

run_pqc() {
    PORT=14482
    PSRV=${PQC_SERVER:-$SERVER}
    if [ ! -x "$BUILD/example_client_pqc" ]; then
        yellow "SKIP PQC example (example_client_pqc not built)"
        return 0
    fi
    if [ ! -x "$PSRV" ]; then
        yellow "SKIP PQC example (wolfSSL server not found at $PSRV)"
        return 0
    fi
    WDIR=$(dirname "$(dirname "$(dirname "$PSRV")")")
    ( cd "$WDIR" && "$PSRV" -v 4 -s -i --pqc X25519MLKEM768 -p "$PORT" ) \
        >/tmp/wn_ex_pqc.log 2>&1 &
    SPID=$!
    sleep 1
    if ! kill -0 "$SPID" 2>/dev/null; then
        yellow "SKIP PQC example (server did not start; may lack ML-KEM support)"
        return 0
    fi
    "$BUILD/example_client_pqc" 127.0.0.1 "$PORT"
    RC=$?
    kill "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    if [ "$RC" -eq 0 ]; then
        green "PASS PQC example"
    else
        red "FAIL PQC example (rc=$RC)"
        FAILED=1
    fi
}

run_psk
run_cert
run_pqc

exit $FAILED
