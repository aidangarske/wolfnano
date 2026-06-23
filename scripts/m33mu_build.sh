#!/bin/sh
# Build the wolfNano STM32H563 emulator self-test image (app.bin) for m33mu.
# Cross-compiles the bare-metal harness + the Thumb2 wolfcrypt floor (SHA-256,
# AES-GCM) with the configs/user_settings_stm32h563.h profile. Output: app.bin.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
CC=${CC:-arm-none-eabi-gcc}
OBJCOPY=${OBJCOPY:-arm-none-eabi-objcopy}
WC=wolfssl/wolfcrypt/src
ARM=$WC/port/arm
OUT=build/m33mu
mkdir -p "$OUT"
cp configs/user_settings_stm32h563.h "$OUT/user_settings.h"

CFLAGS="-mcpu=cortex-m33 -mthumb -Os -ffreestanding -fdata-sections \
  -ffunction-sections -g -DWOLFSSL_USER_SETTINGS \
  -I$OUT -Itests/m33mu -I. -Iwolfssl -Iinclude/wolfnano -Isrc"
LDFLAGS="-nostartfiles -T tests/m33mu/target.ld -Wl,--gc-sections \
  --specs=nano.specs --specs=nosys.specs"

HARNESS="tests/m33mu/emu_ivt.c tests/m33mu/emu_startup.c \
  tests/m33mu/emu_syscalls.c tests/m33mu/uart.c tests/m33mu/main.c"
FLOOR="$WC/wc_port.c $WC/memory.c $WC/error.c $WC/hash.c $WC/logging.c \
  $WC/sha256.c $WC/aes.c $ARM/thumb2-aes-asm_c.c $ARM/thumb2-sha256-asm_c.c"

# shellcheck disable=SC2086
$CC $CFLAGS $HARNESS $FLOOR $LDFLAGS -o "$OUT/app.elf"
$OBJCOPY -O binary "$OUT/app.elf" "$OUT/app.bin"
echo "built $OUT/app.bin ($(wc -c < "$OUT/app.bin") bytes)"
