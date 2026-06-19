/* fuzz_serverhello.c
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
 * libFuzzer harness for the TLS 1.3 ServerHello parser. Feeds arbitrary bytes
 * to wn_ServerHello_Parse; the sticky-error reader must never read out of
 * bounds or crash on any input (ASan-instrumented). Complements the curated
 * negative tests in parser_negative_test.c with coverage-guided fuzzing.
 */

#include "wn_serverhello.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    wn_ServerHello sh;

    if (size > 0) {
        (void)wn_ServerHello_Parse((const byte*)data, (word32)size, &sh);
    }
    return 0;
}
