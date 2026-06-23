#!/bin/sh
# Build the wolfNano STM32H563 image and run it under m33mu, gating on the
# success breakpoint (bkpt #0x7e) and the UART pass marker. Skips cleanly if
# m33mu is not installed (it ships in the wolfboot-ci-m33mu container).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
M33MU=${M33MU:-$(command -v m33mu || true)}
LOG=${LOG:-/tmp/wn_m33mu.log}

sh scripts/m33mu_build.sh

if [ -z "$M33MU" ]; then
    printf "\033[33mSKIP m33mu run (emulator not installed; use the\033[0m\n"
    echo "     ghcr.io/wolfssl/wolfboot-ci-m33mu container). Image built OK."
    exit 0
fi

"$M33MU" --cpu stm32h563 build/m33mu/app.bin --uart-stdout --timeout 60 \
    --expect-bkpt=0x7e --quit-on-faults | tee "$LOG"

grep -q "wolfNano floor: all KATs pass" "$LOG"
grep -q "\[EXPECT BKPT\] Success" "$LOG"
echo "m33mu: PASS (wolfNano floor on emulated Cortex-M33)"
