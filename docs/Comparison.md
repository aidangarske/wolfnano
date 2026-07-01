# Comparison vs mbedTLS / wolfSSL

wolfNanoTLS's own size and speed numbers live in [Footprint](Footprint.md) and
[Benchmarks](Benchmarks.md). This page is the head-to-head against
hard-minimized / stock mbedTLS and full wolfSSL, for the cases where a
comparison is useful. Reproduce with `sh bench/footprint-clients.sh` (size,
needs an mbedTLS tree at `$MBEDTLS_DIR`) and `make bench` (speed).

## Footprint: whole TLS 1.3 client (Cortex-M33, `.text` bytes)

Linked from source for Cortex-M33 (X25519, AES-128-GCM, SHA-256),
`arm-none-eabi-gcc -Os -flto -ffunction-sections -fdata-sections
-Wl,--gc-sections` + nano specs (ArmGNU 14.2), with wolfNanoTLS and mbedTLS 4.1.0
**both hard-minimized to the identical scope**. (mbedTLS 4.x is markedly leaner
than 3.6 - the cert client dropped from 101,232 to 70,832 B - so this is a
tougher comparison than the 3.6 numbers shown in older revisions.)

| Client | wolfNanoTLS | mbedTLS 4.1.0 (hard-min) | full wolfSSL | smaller by |
|---|--:|--:|--:|--:|
| PSK + ECDHE, X25519 | **18680** | 36512 | - | 49% |
| PSK + ECDHE, P-256 | **26604** | 42284 | - | 37% |
| cert / X.509, P-256 | **54396** | 70832 | 150949 | 23% |

The cert row uses wolfNanoTLS's native `wn_x509` parser (`WOLFNANO_X509_LITE`,
53.1 KB). The **default** cert backend is wolfSSL's full `asn.c` (complete,
proven) at 63877 B (62.4 KB), ~10% under mbedTLS 4.1.0; `WOLFNANO_X509_LITE` opts
into the smaller native parser. Both use the same crypto floor and shell; only
the X.509 parser differs. Reproduce the mbedTLS 4.x rows with
`sh bench/footprint-mbedtls4.sh` (cert) and `sh bench/footprint-mbedtls4-psk.sh`
(PSK). See [Footprint](Footprint.md).

mbedTLS is given its smallest config too (`MBEDTLS_ECP_FIXED_POINT_OPTIM 0`,
`ECP_WINDOW_SIZE 2`) so the comparison is not inflated in wolfNanoTLS's favor. Both
sides are hard-minimized to **SHA-256 only** (verified: zero SHA-384/512/3, MD5,
SHA-1, DES, ChaCha, CBC/CTR, RSA, ECDSA symbols in either PSK binary). SHA-256
is mandatory in TLS 1.3 (HKDF key schedule, transcript hash, Finished MAC, PSK
binder) and present on both. The remaining gap is architectural: wolfNanoTLS uses
specialized `fe_*` X25519 field arithmetic and direct `wc_*` calls; mbedTLS
routes X25519 through its general ECP + bignum and the mandatory PSA dispatch
layer, and links full AES tables.

The honest framing:

- **Hard-minimized both sides (the fair number): ~49% / 37% (PSK) / 23% (cert)
  smaller.** Getting mbedTLS this small required a custom minimal `PSA_WANT_*`
  crypto config and stripping restartable-ECP, SHA-384/512, and the non-GCM AES
  modes, because mbedTLS's PSA layer pulls in RSA, SHA-1/3, Camellia, DES,
  ChaCha by default.
- **Exact configs:** `bench/min/mbedtls4_config.h` +
  `bench/min/mbedtls4_crypto_config.h` (cert), `bench/min/mbedtls4_config_psk.h`
  + `mbedtls4_crypto_config_psk_*.h` (PSK) for mbedTLS 4.1.0;
  `configs/user_settings_*.h` (wolfNanoTLS).
- **Both harness clients use opaque (volatile) I/O stubs**, so neither side is
  dead-stripped (making the mbedTLS bio opaque too moved its PSK number by
  <30 bytes).
- **Raw crypto primitives are ~parity** (mbedTLS's compact bignum/ECP is its
  design strength); wolfNanoTLS's win is the TLS layer plus whole-stack assembly.
- Full wolfSSL with X.509 is ~147 KB, which is the reason a slim shell exists.

At ~17 KB the X25519 PSK client fits where even a hard-minimized mbedTLS 4.1.0
(36 KB) cannot, and a stock mbedTLS is out of the question. mbedTLS and stock
wolfSSL also ship **no ML-KEM / ML-DSA**, so wolfNanoTLS's PQC client rows have no
counterpart.

## TLS-layer source + `.text` (host clang, `-Os`)

The crypto floor is the same wolfcrypt objects in both, so it is not the
differentiator; the TLS layer is.

| | `__TEXT` bytes | source lines |
|---|--:|--:|
| wolfNanoTLS slim shell (full TLS 1.3 PSK+ECDHE client) | 8,724 | 1,351 |
| wolfSSL TLS layer (`tls13.c` + `tls.c` only) | 52,318 | (subset) |
| wolfSSL `tls13.c`+`tls.c`+`internal.c`+`ssl.c` | n/a | 96,433 |

The complete wolfNanoTLS TLS 1.3 client is roughly 6x smaller in compiled `.text`
than just `tls13.c` + `tls.c`, and omits `internal.c` and `ssl.c` entirely (the
`WOLFSSL` object model), which is the bulk of the wolfSSL TLS-layer size.

## Speed (i7-7920HQ, 1 KB block)

> **Under re-validation (do not cite yet).** A fresh AES-NI-confirmed mbedTLS
> 3.6.0 benchmark on this host measured ~2-4x higher than the mbedTLS figures
> below (e.g. AES-128-GCM 279 not 119 MiB/s, SHA-256 223 not 58) - the original
> mbedTLS numbers appear to have been captured without AES-NI/optimization, so
> the `faster` ratios here overstate wolfNanoTLS's lead. The wolfNanoTLS SHA rows
> also need an asm-build recheck. A corrected both-sides table is pending; treat
> the crypto-speed rows below as provisional.

wolfNanoTLS's `intel` build (= wolfCrypt asm through the seam) vs mbedTLS 3.6.0
stock fast config (AES-NI + `MBEDTLS_HAVE_ASM`, `-O2 -march=native`), both on the
same host, 1 KB block:

| Operation | wolfNanoTLS | mbedTLS | faster |
|---|--:|--:|--:|
| AES-128-GCM | 1682 MiB/s | 119 MiB/s | ~14x |
| AES-256-GCM | 1402 MiB/s | 116 MiB/s | ~12x |
| ChaCha20-Poly1305 | 391 MiB/s | 60 MiB/s | ~6.5x |
| SHA-384 | 255 MiB/s | 78 MiB/s | ~3.3x |
| SHA-256 | 173 MiB/s | 58 MiB/s | ~3.0x |
| ECDSA P-256 verify | 9386 op/s | 130 op/s | ~72x |
| RSA-2048 public | 30427 op/s | 954 op/s | ~32x |
| ECDSA P-256 sign | 20799 op/s | 721 op/s | ~29x |
| ECDH P-256 agree | 9472 op/s | 390 op/s | ~24x |
| RSA-2048 private | 861 op/s | 95 op/s | ~9x |
| ML-KEM-768 keygen | 49572 op/s | n/a | n/a |
| ML-KEM-768 encap | 52906 op/s | n/a | n/a |
| ML-KEM-768 decap | 38360 op/s | n/a | n/a |
| ML-DSA-44 sign | 6226 op/s | n/a | n/a |
| ML-DSA-44 verify | 17580 op/s | n/a | n/a |

mbedTLS ships no ML-KEM / ML-DSA, so the post-quantum rows have no counterpart
(plus EdDSA, also absent from mbedTLS). The block size matches mbedTLS's
benchmark (1 KB) for a fair symmetric comparison.
