# Algorithms

## Crypto floor (current)

The minimal set required for a TLS 1.3 handshake, all building and passing KATs
locally:

| Area | Algorithm |
|---|---|
| Hash | SHA-256, SHA-384/512 |
| KDF | HKDF (HMAC-based) |
| AEAD | AES-128/256-GCM |
| Key exchange | ECDHE P-256/P-384, X25519 |
| Signature | ECDSA P-256/P-384, Ed25519 |
| RNG | Hash-DRBG, seeded via the `wn_seed` hook |

ChaCha20-Poly1305 is available behind `WOLFNANOTLS_HAVE_CHACHA`.

## PQC adders (done)

| Adder | Algorithm | Status |
|---|---|---|
| `WOLFNANOTLS_MLKEM` | ML-KEM-768 (KEM) | done, allocation-free |
| `WOLFNANOTLS_MLKEM` | X25519MLKEM768 hybrid key share (group 0x11ec) | done, client+server agreement |
| `WOLFNANOTLS_MLDSA` | ML-DSA-65 verify (no-malloc) | done, allocation-free |
| `WOLFNANOTLS_MLDSA` + `WOLFNANOTLS_MLDSA_SIGN` | ML-DSA-65 keygen/sign | done (needs working memory) |

ML-KEM-768 and ML-DSA-65 verify are both **allocation-free** under
`WOLFSSL_NO_MALLOC`. ML-DSA keygen/sign (server side) needs working memory, so
it is gated behind `WOLFNANOTLS_MLDSA_SIGN`. The hybrid concatenation is ML-KEM
component first, then X25519 (draft-kwiatkowski-tls-ecdhe-mlkem).

## Planned adders

| Adder | Algorithm | Status |
|---|---|---|
| `WOLFNANOTLS_X509` | minimal cert path validation | planned (Phase 4) |
| `WOLFNANOTLS_HAVE_RSA_VERIFY` | RSA verify for real-world chains | planned (Phase 4) |

## Backend boundary note

The offered cipher suites and groups are a function of the active backend. A
`fips` build excludes primitives outside its boundary (for example
ChaCha20-Poly1305 and X25519), and PQC under FIPS is pending, not validated.
