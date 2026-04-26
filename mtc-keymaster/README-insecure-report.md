# Insecure Crypto Audit — postWolf

**Date:** 2026-04-26
**Branch:** phase-16
**Scope:** wolfcrypt/ (what's available) ↔ mtc-keymaster/ (what's used)
**Standard for "insecure":** broken primitives + pre-quantum
primitives in a stack that bills itself as PQ-secure.

## Insecure / pre-quantum primitives in wolfcrypt/

### Broken (any use is a problem)

| Primitive | Implementation | Public header |
|---|---|---|
| DES / 3DES | `wolfcrypt/src/des3.c` | `wolfssl/wolfcrypt/des3.h` |
| RC4 / ARC4 | `wolfcrypt/src/arc4.c` | `wolfssl/wolfcrypt/arc4.h` |
| RC2 | `wolfcrypt/src/rc2.c` | `wolfssl/wolfcrypt/rc2.h` |
| MD2 | `wolfcrypt/src/md2.c` | `wolfssl/wolfcrypt/md2.h` |
| MD4 | `wolfcrypt/src/md4.c` | `wolfssl/wolfcrypt/md4.h` |
| MD5 | `wolfcrypt/src/md5.c` | `wolfssl/wolfcrypt/md5.h` |
| SHA-1 | `wolfcrypt/src/sha.c` | `wolfssl/wolfcrypt/sha.h` |
| RIPEMD | `wolfcrypt/src/ripemd.c` | `wolfssl/wolfcrypt/ripemd.h` |

### Pre-quantum (broken under CRQC, deprecated for PQ-secure systems)

| Primitive | Implementation | Public header |
|---|---|---|
| RSA | `wolfcrypt/src/rsa.c` | `wolfssl/wolfcrypt/rsa.h` |
| DSA | `wolfcrypt/src/dsa.c` | `wolfssl/wolfcrypt/dsa.h` |
| ECDSA | `wolfcrypt/src/ecc.c` (sign/verify variant) | `wolfssl/wolfcrypt/ecc.h` |
| Ed25519 | `wolfcrypt/src/ed25519.c` | `wolfssl/wolfcrypt/ed25519.h` |
| Ed448 | `wolfcrypt/src/ed448.c` | `wolfssl/wolfcrypt/ed448.h` |
| classic DH | `wolfcrypt/src/dh.c` | `wolfssl/wolfcrypt/dh.h` |
| ECDH | `wolfcrypt/src/ecc.c` (KEX variant) | `wolfssl/wolfcrypt/ecc.h` |
| X25519 | `wolfcrypt/src/curve25519.c` | `wolfssl/wolfcrypt/curve25519.h` |
| X448 | `wolfcrypt/src/curve448.c` | `wolfssl/wolfcrypt/curve448.h` |

## mtc-keymaster usage

### Broken primitives

**None.** Zero hits across mtc-keymaster/ for MD5, SHA-1, DES,
3DES, RC4, RC2, MD2, MD4, RIPEMD, RSA, or DSA in active code.

As of 2026-04-26, the entire family is also gone from the linked
binary: `configure.sh` now disables MD5, SHA-1, DES3, ARC4, RC2,
MD4, MD2, RIPEMD, plus the OpenSSL-compat / OSP / QUIC / CRL
shims that transitively force them on. `nm -D` on the installed
`libpostWolf.so` reports zero exported symbols for any of the
seven hash/cipher families.

### Pre-quantum primitives — 1 active finding (was 3)

#### ~~1. ECDSA in revocation acceptance~~ — **RESOLVED 2026-04-26**

The `EC-P256` / `EC-P384` branch in `handle_revoke`
(`mtc_http.c:1759-1769`) and its companion signing helper in
`tools/c/revoke-key.c:194-213` have been removed. The
`<wolfssl/wolfcrypt/ecc.h>` include and the SHA-256 message-hash
precompute (no longer needed without ECDSA) were dropped at the
same time.

#### ~~2. Ed25519 in revocation acceptance~~ — **RESOLVED 2026-04-26**

The `Ed25519` branch in `handle_revoke` (`mtc_http.c:1771-1783`)
and its companion signing helper in `tools/c/revoke-key.c:215-225`
have been removed. The `<wolfssl/wolfcrypt/ed25519.h>` include was
dropped. `revoke-key.c`'s default `algo` fallback flipped from
`"EC-P256"` to `"ML-DSA-87"` for consistency with the new
post-quantum-only policy.

`handle_revoke` now accepts only `ML-DSA-{44,65,87}` signed
revocation requests; any other `ca_algo` value returns
`400 unsupported key algorithm for revocation`.

#### 1. X25519 in DH bootstrap KEX

`mtc-keymaster/server2/c/mtc_bootstrap.c:498-549` (port 8445):

```c
wc_curve25519_init(&server_key);
wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &server_key);
wc_curve25519_export_public(&server_key, server_pub, &server_pub_sz);
wc_curve25519_init(&client_key);
wc_curve25519_import_public(client_pub, CURVE25519_KEYSIZE, &client_key);
wc_curve25519_shared_secret(&server_key, &client_key,
                            shared_secret, &shared_sz);
```

CLAUDE.md and the architectural docs call this "DH bootstrap"; the
audit pins it to specifically X25519. Session key derived from the
X25519 shared secret then drives AES-256-GCM, but the KEX itself is
classical.

### Migration / legacy markers (informational)

- `server2/c/mtc_store.c:29` — comment about migrating from legacy
  Ed25519 `ca_key.der` layout
- `tools/c/migrate-cosigner.c` — one-shot cosigner Ed25519 → ML-DSA-87
  rotation tool (already used)

## Bottom line

The signing axis is clean: **CA, leaf, and cosigner all sign with
ML-DSA-87**. The MQC channel KEX uses **ML-KEM-768**. Hashing is
**SHA-256 / HMAC-SHA-256**, KDF is **HKDF**, symmetric is
**AES-256-GCM**.

One pre-quantum attack surface remains in active code:

1. **Bootstrap port 8445 uses X25519.** Anything sent over the
   bootstrap (CA-pubkey discovery, initial enrollment) is
   record-now-decrypt-later vulnerable. *Fix:* swap
   `wc_curve25519_*` → `wc_MlKemKey_*` in `mtc_bootstrap.c`. The
   pattern is already proven in `socket-level-wrapper-MQC/mqc.c`;
   this is a copy-and-adapt, not a design problem. Not urgent if
   bootstrap traffic carries no long-lived secret, but it is the
   last classical primitive in the live code path.

Resolved 2026-04-26:

- ECDSA + Ed25519 revocation acceptance was dropped from
  `handle_revoke`; tool defaults flipped to ML-DSA-87. Server
  now refuses any non-ML-DSA `ca_algo`.
- Broken hash/cipher family (MD5, SHA-1, DES3, ARC4, RC2, MD4,
  MD2, RIPEMD) compiled out of `libpostWolf.so` via
  `configure.sh` flags. Verified with `nm -D` on the installed
  shared object.
