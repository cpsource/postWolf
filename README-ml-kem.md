# CRYSTALS-Kyber / ML-KEM in postWolf

How the post-quantum key-exchange primitive works, and where the
code lives in this repository.

## Nomenclature

**CRYSTALS-Kyber** was one of the NIST Post-Quantum Cryptography
Round 3 winners for key exchange (2022). In August 2024 NIST
standardized it as **ML-KEM** (Module-Lattice-based Key-Encapsulation
Mechanism) in **FIPS 203**. The two names refer to essentially the
same algorithm — Kyber is the pre-standard name, ML-KEM is the
standard. wolfSSL (and therefore postWolf) uses the ML-KEM names:
`wc_MlKemKey_*`, `WC_ML_KEM_768`.

"CRYSTALS" = **CRY**ptographic **S**uite for **A**lgebraic **L**attices.
The suite has two members: Kyber (KEM, → ML-KEM / FIPS 203) and
Dilithium (signatures, → ML-DSA / FIPS 204). postWolf uses both —
ML-KEM-768 for MQC's key exchange and ML-DSA-87 for leaf/CA identity
signatures.

## What it is

A **Key Encapsulation Mechanism**, not a cipher. It doesn't encrypt
your data — it produces a fresh 32-byte shared secret that you then
feed into HKDF → AES-GCM (exactly the pattern MQC uses).

## KEM vs. classical DH — the asymmetry

Classical X25519 is symmetric: both sides generate ephemeral keypairs,
and both compute the shared secret the same way. KEMs are asymmetric:

```
           Alice                           Bob
           ─────                           ───
                          Bob's pubkey
           ┌──────────────────────────────┐
           │    KeyGen → (pk_B, sk_B)     │
           │──────────── pk_B ───────────▶│      (pk_B can be ephemeral
           │                              │       or a long-term identity)
  Encapsulate(pk_B):
    → (ct, ss)
           │────────────── ct ───────────▶│
                                            Decapsulate(sk_B, ct):
                                              → ss
           both now hold the same 32-byte ss
```

Only one side (Bob) runs `KeyGen` and `Decapsulate`; the other
(Alice) runs `Encapsulate` on Bob's public key. Alice picks the
shared secret and wraps it in a ciphertext only Bob can unwrap.

## ML-KEM-768 sizes

The variant postWolf uses:

| | X25519 | ML-KEM-768 |
|---|---|---|
| Public key | 32 bytes | 1184 bytes |
| Ciphertext | 32 bytes | 1088 bytes |
| Shared secret | 32 bytes | 32 bytes |

The shared-secret size matches, so downstream HKDF + AES-GCM stays
unchanged. The on-wire cost is ~30× larger — that's the price of
post-quantum.

## Three parameter sets (NIST security categories)

| Variant | Classical security | Typical use |
|---|---|---|
| ML-KEM-512 | ~AES-128 (category 1) | embedded / constrained |
| **ML-KEM-768** | ~AES-192 (category 3) | **general purpose — TLS, Signal PQXDH, iMessage PQ3, MQC** |
| ML-KEM-1024 | ~AES-256 (category 5) | highest margin |

768 is the sensible default most serious deployments pick. Good
quantum-resistance margin without the size blow-up of 1024.

## Underlying math (brief)

Security reduces to the hardness of **Module-Learning-With-Errors**
(Module-LWE): given a matrix of polynomials `A` over a quotient ring
`Z_q[X]/(X^n + 1)` and a vector `b = A·s + e` where `s` (the secret)
and `e` (the noise) have small coefficients drawn from a narrow
binomial distribution, recover `s`. The noise makes lattice reduction
(LLL, BKZ) and quantum algorithms (Grover / Shor) ineffective even
with the public `A, b`. Kyber builds a CPA-secure public-key
encryption from Module-LWE and elevates it to IND-CCA2 security via
the Fujisaki-Okamoto transform.

## Where the bits are in this repository

| Layer | Path |
|---|---|
| Algorithm implementation (upstream wolfSSL) | `wolfcrypt/src/wc_mlkem.c`, `wc_mlkem_poly.c`, `wc_mlkem_asm.S` (+ ARM NEON / Thumb2 specializations under `wolfcrypt/src/port/arm/`) |
| Public header | `wolfssl/wolfcrypt/mlkem.h`, `wc_mlkem.h`, `ext_mlkem.h` |
| Already-built object files | `wolfcrypt/src/.libs/src_libpostWolf_la-wc_mlkem.o`, `wc_mlkem_poly.o`, `wc_mlkem_asm.o` |
| Protocol consumer (MQC handshake) | `socket-level-wrapper-MQC/mqc.c` — `wc_MlKemKey_Init(..., WC_ML_KEM_768, ...)` at L701, `MakeKey` L705, `EncodePublicKey` L713, `Encapsulate` L1005, `Decapsulate` L829 |
| Protocol consumer (MQCP / QUIC) | `socket-level-wrapper-QUIC/mqcp_handshake.c` uses the same API |

## The handshake in MQC, condensed

```c
// server side (simplified)
wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, ...);    // mqc.c:701
wc_MlKemKey_MakeKey(&mlkem, &rng);               // mqc.c:705
wc_MlKemKey_EncodePublicKey(&mlkem, pk, pk_sz);  // mqc.c:713
// ... server sends pk + ML-DSA-87 signature over pk + ephemeral pubkey

// client side
wc_MlKemKey_DecodePublicKey(&mlkem, pk, pk_sz);  // mqc.c:997
wc_MlKemKey_Encapsulate(&mlkem, ct, ss, &rng);   // mqc.c:1005
// ... client sends ct; now both have ss

// server side
wc_MlKemKey_Decapsulate(&mlkem, ss, ct, ct_sz);  // mqc.c:829
// both sides feed ss into HKDF-SHA256 → 32-byte AES-256-GCM key
```

So: the NIST-standardized FIPS 203 algorithm is in-tree via wolfCrypt,
and the live MQC handshake on factsorlie.com:8446 is running it every
time a client connects.

## See also

- `socket-level-wrapper-MQC/README-MQC-specifications.md` — the MQC
  protocol spec, including the symmetric-cipher choice
  (AES-256-GCM) that consumes the ML-KEM shared secret.
- `mtc-keymaster/README-ml-dsa-87.md` — the sibling document for
  ML-DSA-87 (the signature algorithm from the same CRYSTALS suite).


---

## Appendix: Does MQC use CRYSTALS-Kyber / ML-KEM?

**Yes.** MQC uses **ML-KEM-768** (CRYSTALS-Kyber at the category-3
parameter set) as its key-exchange primitive.

Evidence, all in `socket-level-wrapper-MQC/mqc.c`:

| Line | Call | Role |
|---|---|---|
| 701 | `wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, ...)` | pick the 768 parameter set |
| 705 | `wc_MlKemKey_MakeKey(&mlkem, &rng)` | server's ephemeral keypair |
| 713 | `wc_MlKemKey_EncodePublicKey(&mlkem, ...)` | server serializes pk for the wire |
| 997 | `wc_MlKemKey_DecodePublicKey(&mlkem, ...)` | client parses the pk |
| 1005 | `wc_MlKemKey_Encapsulate(&mlkem, ct, ss, &rng)` | client picks shared secret, wraps as ct |
| 829 | `wc_MlKemKey_Decapsulate(&mlkem, ss, ct, ct_sz)` | server unwraps to get ss |

And from the file's own module header (`mqc.c` lines 7-13):

> *"ML-KEM-768 key exchange, ML-DSA-87 signed authentication, and
> AES-256-GCM… Both derive AES-256-GCM key from ML-KEM shared secret."*

So every live MQC handshake on `factsorlie.com:8446` runs ML-KEM-768
— the shared secret goes through HKDF-SHA256 to produce the 32-byte
AES-256-GCM session key.  The DH bootstrap port (8445) is the only
place postWolf still uses classical X25519.


---

## Appendix: Does postWolf use HKDF?

**Yes** — HKDF-SHA256 is used everywhere postWolf turns a shared
secret into a symmetric key.  All calls go through `wc_HKDF()` from
wolfCrypt (RFC 5869, Extract + Expand in one call).

### Where it's used

| Location | What it derives | Purpose |
|---|---|---|
| `mtc-keymaster/server2/c/mtc_bootstrap.c:538` | AES-128 key for DH bootstrap port (8445) | Info string: `"mtc-dh-bootstrap"`; IKM: X25519 shared secret; salt: random 16 bytes |
| `socket-level-wrapper-MQC/mqc.c:837, 1047, 1250, 1465, 1735, 1817` | AES-256-GCM key for MQC port (8446) | IKM: ML-KEM-768 shared secret (32 bytes); hashed with SHA-256 |
| `mtc-keymaster/tools/c/bootstrap_ca.c`, `bootstrap_leaf.c` | client-side mirror of the bootstrap port's AES-128 | Client runs the same HKDF so both sides derive the identical key |
| `socket-level-wrapper-QUIC/mqcp_crypto.c` | MQCP (QUIC-inspired) session keys | Same shape, different transport |

### What `wc_HKDF` looks like on the wire (example: MQC)

```c
// socket-level-wrapper-MQC/mqc.c:837 (shortened)
uint8_t aes_key[32];                          // 32 bytes = AES-256
ret = wc_HKDF(WC_SHA256,                      // Extract + Expand both use HMAC-SHA256
              shared_secret, WC_ML_KEM_SS_SZ, // IKM: 32-byte ML-KEM output
              salt, salt_sz,                  // 16-byte random salt
              info, info_sz,                  // domain-separation string
              aes_key, sizeof(aes_key));      // OKM: 32-byte AES-256 key
```

Both parties run this after the ML-KEM handshake.  Because they share
the ML-KEM secret, the same salt (transmitted in the handshake), and
agree on the info string, both compute the identical 32-byte key.

### Why HKDF specifically (vs just SHA-256 of the secret)

1. **Extract stage** whitens the non-uniform ML-KEM / X25519 output
   into a uniformly-random PRK.
2. **Expand stage** gives you any output length with the same strong
   pseudorandomness.
3. **Info-based domain separation** lets you derive multiple
   independent keys from one secret by changing `info` — critical
   once you need a session key *and* a MAC key, or when you rekey.
4. **Formal security reduction** to HMAC's PRF property — something
   ad-hoc SHA-256 hashing doesn't give you.

postWolf uses it on every channel that derives a symmetric key from
a shared secret.  The only places symmetric keys *aren't* HKDF-derived
are purely-local state operations (revocation list manipulation,
internal bookkeeping) — no exchange means no secret to mix.
