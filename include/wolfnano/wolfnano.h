/* wolfnano.h
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
 * wolfNano public API surface: shared types and return codes.
 */

#ifndef WOLFNANO_H
#define WOLFNANO_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#define WOLFNANO_API
#define WOLFNANO_LOCAL

/* Return codes: success is 0, errors are negative. */
#define WOLFNANO_SUCCESS         0
#define WOLFNANO_E_INVALID_ARG (-1)
#define WOLFNANO_E_CRYPTO      (-2)
#define WOLFNANO_E_UNSUPPORTED (-3)

#endif /* WOLFNANO_H */
