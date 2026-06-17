/* user_settings.h
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

#ifndef WOLFNANOTLS_USER_SETTINGS_H
#define WOLFNANOTLS_USER_SETTINGS_H

/* The one wolfNanoTLS config file. Provider backend = src (default). */

/* Phase 1: crypto floor only (no TLS shell yet). */
#define WOLFCRYPT_ONLY

/* ---- wolfNanoTLS feature selection (WOLFNANOTLS_HAVE_*) ---- */
#define WOLFNANOTLS_HAVE_SHA256
#define WOLFNANOTLS_HAVE_SHA384
#define WOLFNANOTLS_HAVE_HKDF
#define WOLFNANOTLS_HAVE_AESGCM
#define WOLFNANOTLS_HAVE_ECC
#define WOLFNANOTLS_HAVE_ECC384
#define WOLFNANOTLS_HAVE_CURVE25519
#define WOLFNANOTLS_HAVE_ED25519

#include "wolfnano_target.h"   /* target → asm/SP bundle (one macro selects) */
#include "wolfnano_config.h"   /* WOLFNANOTLS_HAVE_* → wolfSSL macros + size cuts */

#endif /* WOLFNANOTLS_USER_SETTINGS_H */
