# MQC (Merkle Quantum Connect) Specification

## What is MQC?

MQC is a post-quantum authenticated encrypted connection protocol that
replaces TLS 1.3 + X.509 certificates with:

- **ML-KEM-768** key exchange (post-quantum key encapsulation)
- **ML-DSA-87** signed authentication (post-quantum digital signatures)
- **Merkle tree** proof verification (transparency log, no certificate chains)
- **AES-256-GCM** session encryption

No TLS. No X.509. No public keys on the wire. Peers identify each other
by `cert_index` — an integer referencing their entry in the Merkle
transparency log. Public keys are resolved from the log on demand and
cached locally.

## How It Works

### Signed Key Exchange (1 Round Trip)

Each side sends its `cert_index` + an ephemeral ML-KEM key + an ML-DSA-87
signature over that key. The signature proves identity (verified against
the Merkle-authenticated public key). The ML-KEM exchange produces a
shared secret for session encryption.

Authentication and key exchange happen simultaneously in a single message
each direction.

### Peer Key Resolution

When you receive a `cert_index` you haven't seen before:

1. Check local cache: `~/.TPM/peers/<index>/certificate.json`
2. If cache miss: `GET /certificate/<index>` from the MTC server
3. Verify Merkle inclusion proof against the log's root hash
4. Verify ML-DSA-87 cosignature from the CA
5. Check revocation status
6. Check validity period
7. Cache the verified cert for next time

Subsequent connections to the same peer hit the cache — zero network
overhead.

## Protocol Modes

MQC supports two handshake modes. The server auto-detects which mode
the client is using (`mqc_accept_auto`).

### Clear Mode (1 round trip) — `mqc_connect` / `mqc_accept`

Both `cert_index` and ML-KEM keys are sent in a single plaintext JSON
message each direction. Fastest handshake, but an eavesdropper can see
who is connecting to whom.

```
NodeA (Client)                          NodeB (Server)
--------------                          --------------

1. Generate ephemeral ML-KEM keypair
2. Sign transcript_hash_sig("client") with
   own ML-DSA-87 private key
   (covers version/suite/mode/EK_c/cert_index)

            -------- Step 1 -------->
            {
              "version":    0,
              "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
              "mode":       "clear",
              "cert_index": 72,
              "kem_pub":    "<1184 bytes hex>",
              "signature":  "<4627 bytes hex>"
            }

                                        3. Look up NodeA's public key
                                           (cache or MTC server fetch)
                                        4. Verify Merkle proof + cosignature
                                        5. Verify NodeA's signature over
                                           the transcript hash
                                        6. ML-KEM encapsulate -> ciphertext
                                           + shared secret
                                        7. Sign transcript_hash_sig("server")
                                           with own ML-DSA-87 private key

            <------- Step 2 ---------
            {
              "version":    0,
              "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
              "mode":       "clear",
              "cert_index": 73,
              "kem_pub":    "<1088 bytes hex>",
              "signature":  "<4627 bytes hex>"
            }

8. Verify NodeB's signature against transcript_hash_sig("server")
9. ML-KEM decapsulate -> shared secret
10. Derive per-direction AES-256-GCM keys + IVs + Finished MAC keys
    via HKDF-Extract+Expand (salt = transcript_hash_full)

            ----- Finished frame (HMAC-SHA256 over txn) -----
            (AEAD-sealed in each direction at sequence 0;
             mismatch aborts before any application data flows)

            ===== Encrypted Channel (sequence 1+) =====
```

### Encrypted Identity Mode (1.5 round trips, 4 frames) — `mqc_connect_encrypted` / `mqc_accept_encrypted`

The ML-KEM key exchange happens first in plaintext. Once both sides
have the shared secret, the `cert_index` + signatures are sent encrypted.
An eavesdropper sees ML-KEM bytes only, never the trust graph.

```
NodeA (Client)                          NodeB (Server)
--------------                          --------------

Phase 1: anonymous ML-KEM exchange (plaintext)

1. Generate ephemeral ML-KEM keypair

            -------- Frame 1 -------->
            {
              "version":  0,
              "suite":    "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
              "mode":     "encrypted",
              "kem_pub":  "<hex(EK_c)>"
            }

                                        2. ML-KEM encapsulate
                                           -> ciphertext + shared secret

            <------- Frame 2 ---------
            {
              "version":  0,
              "suite":    "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
              "mode":     "encrypted",
              "kem_pub":  "<hex(CT_s)>"
            }

3. ML-KEM decapsulate -> shared secret
4. Both derive an EARLY key set via HKDF off transcript_hash_phase1
   (early_c2s_key/iv, early_s2c_key/iv) — used only to seal the
   phase-2 identity blobs.

Phase 2: AEAD-sealed identity (under early_*_key)

5. Sign transcript_hash_sig("client") with full transcript

            -------- Frame 3 (AEAD) ------->
            [seal early_c2s] { "cert_index": 72, "signature": "<hex>" }

                                        6. Decrypt + verify peer via Merkle
                                        7. Verify signature
                                        8. Sign transcript_hash_sig("server")

            <------- Frame 4 (AEAD) --------
            [seal early_s2c] { "cert_index": 73, "signature": "<hex>" }

9. Decrypt + verify peer via Merkle
10. Verify signature
11. Both derive the DATA key set + Finished MAC keys via HKDF off
    transcript_hash_full (data_*_key/iv/finished).

            ----- Finished frame (HMAC-SHA256 over txn) -----
            ===== Encrypted Channel (sequence 1+) =====
```

### Server Auto-Detection — `mqc_accept_auto`

The server reads the first length-prefixed handshake frame, strict-parses
the JSON, and dispatches on the `"mode"` field:

- `"clear"` → single-round-trip handshake (continues with the
  existing frame as `mqc_accept`).
- `"encrypted"` → 4-frame handshake (continues as
  `mqc_accept_encrypted`).

The pre-mqc-2-P1 implementation peeked the wire with `MSG_PEEK +
strstr` for `"mode":"encrypted"`; that was structurally fragile (a
`"mode"` substring buried in another field could spoof it) and is
gone.  The current dispatcher reads the frame in full under
`mqc-handshake-stall-sec` / `mqc-handshake-total-sec` budgets and
parses it with the same strict-mode parser used downstream.

**Privacy trade-off (Gemini MQC-01).**  `mqc_accept_auto` serves
both modes by **client choice**.  Operators who require
**server-identity privacy** (no `cert_index` in plaintext on the
wire) MUST set `cfg.encrypt_identity = 1` on the listener
context.  As a fail-loud guard, `mqc_accept_auto` rejects a
clear-mode ClientHello with `REQUIRE_ENCRYPTED_REJECT` when
`encrypt_identity = 1`, so an accidental misconfiguration aborts
visibly instead of silently serving cleartext-identity
handshakes.

## Wire Format

### Handshake Messages (length-prefixed JSON over TCP)

Every unit on an MQC connection — handshake or data — is a
length-prefixed frame:

```
[4 bytes: 32-bit big-endian payload length N]
[N bytes: payload]
```

For handshake frames the payload is a UTF-8 JSON object (strict-mode
parsing: no parser extensions, no trailing bytes, each defined field
exactly once on the raw bytes, no unknown keys, lowercase-hex with
exact byte length, integer fields bounded with explicit ERANGE).
The brace-counting reader used in pre-mqc-2-P1 builds is gone.

**Client → Server (clear mode):**
```json
{
  "version":    0,
  "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
  "mode":       "clear",
  "cert_index": 72,
  "kem_pub":    "<1184-byte ML-KEM-768 encapsulation key, hex>",
  "signature":  "<4627-byte ML-DSA-87 signature, hex>"
}
```

**Server → Client (clear mode):**
```json
{
  "version":    0,
  "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
  "mode":       "clear",
  "cert_index": 73,
  "kem_pub":    "<1088-byte ML-KEM-768 ciphertext, hex>",
  "signature":  "<4627-byte ML-DSA-87 signature, hex>"
}
```

The ML-DSA-87 `signature` covers a structured **transcript hash**
that binds version, suite, mode, both ML-KEM contributions
(with byte-length prefixes), both `cert_index` values, and a
6-byte role tag.  See `draft-page-mqc-protocol-00.md` §6.0.

### AEAD Frames (Finished + application data)

Every AEAD-sealed frame uses the same length-prefixed wire shape
plus a fixed 31-byte AAD bound into the GCM tag:

```
[4 bytes: 32-bit big-endian payload length N]
[N bytes: AES-256-GCM ciphertext || 16-byte GCM tag]

AAD = "mqc-frame/v01\n\x00"  (16 bytes)
   || u8(version)             (1)
   || u8(direction)           (1; 0 = c2s, 1 = s2c)
   || u8(frame_type)          (1; 0x02 = Finished, 0x03 = data)
   || u64be(sequence)         (8)
   || u32be(plaintext_length) (4)
```

The first AEAD frame in each direction is a **Finished frame**
sealed at sequence 0 carrying `HMAC-SHA256(data_<role>_finished,
transcript_hash_full)` (32 bytes) — both peers commit to their
view of the joint transcript before any application data flows.
Application data starts at sequence 1.

### Nonce Construction

Per-direction IVs derived in HKDF-Expand drive the per-frame
nonce in TLS-1.3 fashion:

```
nonce = data_<dir>_iv  XOR  (0x00 0x00 0x00 0x00 || u64be(seq))
```

The 4-byte zero prefix and 8-byte big-endian sequence form a
12-byte mask XOR'd into the per-direction IV.  Per-direction
keys make `(key, nonce)` collisions across directions
cryptographically impossible; the IV is per-connection secret
material so the on-wire nonce is unpredictable.

## Symmetric Cipher Choice: AES-256-GCM

MQC uses **AES-256-GCM** with a 256-bit key (`MQC_AES_KEY_SZ =
32`).  Per-direction keys (`data_c2s_key`, `data_s2c_key`) are
derived via HKDF-Extract+Expand off the ML-KEM-768 shared
secret with the transcript hash as Extract salt.  The DH
bootstrap port (8445) uses the same primitive post-TODO #62
(2026-04-30); both ports now share the AEAD shape:

| | Bootstrap port (8445) | MQC port (8446) |
|---|---|---|
| **Key exchange** | X25519 (classical) | ML-KEM-768 (post-quantum) |
| **Identity auth** | DNSSEC pin + PoP signature on enrolment | ML-DSA-87 signed handshake bound to transcript |
| **KDF** | HKDF-SHA256 (per-direction) | HKDF-SHA256 (per-direction) |
| **Cipher** | AES-256-GCM (32-B key) | AES-256-GCM (32-B key) |
| **AAD** | label + direction + plaintext_length | LABEL + version + direction + frame_type + sequence + plaintext_length |
| **Channel scope** | one enrolment exchange | full bidirectional stream |

Three reasons MQC (and now the bootstrap port) standardise on
GCM-256:

1. **AEAD.** GCM provides confidentiality *and* integrity in one
   primitive — no separate MAC step, no padding-oracle surface.
   The pre-TODO-#62 bootstrap port used AES-CBC zero-IV with no
   MAC; that construction is retired.
2. **256-bit key against quantum.** ML-KEM-768 is already
   post-quantum, so AES-256 keeps the whole stack balanced —
   ~128 bits against Grover's quantum search, matching
   ML-KEM-768's security category.  AES-128 would halve to ~64
   bits under Grover, becoming the weakest link.
3. **Standard IETF practice.** TLS 1.3 and most modern protocols
   converge on AES-256-GCM with a 256-bit key HKDF-expanded from
   the shared secret — same shape MQC uses, just with an ML-KEM
   shared secret feeding the HKDF extract step instead of ECDHE.

## Security Properties

| Attack | Status | Rationale |
|--------|--------|-----------|
| **MITM** | SAFE | Attacker cannot sign the transcript hash without the ML-DSA-87 identity key bound to the in-log cert |
| **Replay** | SAFE | Ephemeral ML-KEM keypair + transcript-bound signatures + per-connection IVs |
| **Impersonation** | SAFE | Public key bound to `cert_index` via Merkle inclusion proof + ML-DSA-87 cosignature, AND verifier checks `subject_public_key_hash` matches the loaded PEM |
| **Harvest now, decrypt later** | SAFE | ML-KEM-768 + ML-DSA-87 are post-quantum (NIST Cat 3+) |
| **Compromised MTC server** | PARTIALLY SAFE | Cannot forge cosignatures without the cosigner private key; cosigner-key rotation invalidates cached peer certs (`~/.TPM/peers/<n>/cosigner-fp.hex` mismatch) |
| **Identity-substitution under valid cert** | SAFE | Expected-identity check (§10.7): subject from the verified cert MUST equal/prefix-match the dialed name; dial-by-IP without an explicit name fails closed |
| **Transcript divergence between honest peers** | SAFE | Finished-MAC frame at sequence 0 in each direction commits both peers to `transcript_hash_full` before any data flows |
| **Length-prefix tampering** | SAFE | 31-byte AAD on every AEAD frame includes `plaintext_length`; tampering produces immediate GCM failure |
| **Duplicate-key / trailing-garbage smuggling** | SAFE | Strict-mode JSON parse rejects parser extensions, trailing bytes, duplicate keys (on raw bytes), unknown fields, ERANGE integer saturation |
| **Pre-crypto DoS** | MITIGATED | Hex-length filter on `kem_pub`/`signature` fields runs before any ML-KEM / ML-DSA invocation; rejections count against the per-IP failure bucket |
| **DoS — connection flood** | MITIGATED | Per-IP buckets via `mqc-rl-connect-per-{min,hour}` (defaults 100/min, 1000/hour); per-IP `cert_index` rotation capped via `mqc-rl-cert-per-{min,hour}` (defaults 10/min, 100/hour); fork backpressure via `mqc-max-children` (default 20) |
| **Slowloris-style stall** | MITIGATED | `mqc-handshake-stall-sec` per-read deadline (3s default) + `mqc-handshake-total-sec` total budget (5s default) |
| **Stale revocation cache** | FAIL-CLOSED | Default `mqc-revocation-policy=mandatory`: peers query the log on cache miss and abort on query failure |
| **Downgrade** | N/A | Single protocol version, single suite, no negotiation; mode declared in `mode` field and bound into transcript |
| **Metadata leakage (passive)** | CONFIGURABLE | Clear mode: `cert_index` visible.  Encrypted mode: 4-frame handshake hides identity behind ML-KEM bytes.  Set `cfg.encrypt_identity = 1` (or `--encrypted` on CLI tools) |

## API Reference

### Types

```c
typedef struct mqc_ctx  mqc_ctx_t;   /* Opaque context handle */
typedef struct mqc_conn mqc_conn_t;  /* Opaque connection handle */

typedef enum {
    MQC_CLIENT,
    MQC_SERVER
} mqc_role_t;

typedef struct {
    mqc_role_t  role;           /* MQC_CLIENT or MQC_SERVER */
    const char *tpm_path;       /* ~/.TPM/<domain> — our identity */
    const char *mtc_server;     /* MTC server (e.g., "localhost:8444") */
    const unsigned char *ca_pubkey;  /* CA Ed25519 cosigner public key */
    int ca_pubkey_sz;           /* Size of ca_pubkey (typically 32) */
} mqc_cfg_t;
```

### Context Management

| Function | Description |
|----------|-------------|
| `mqc_ctx_t *mqc_ctx_new(const mqc_cfg_t *cfg)` | Create MQC context. Loads identity from tpm_path. Returns NULL on failure. |
| `void mqc_ctx_free(mqc_ctx_t *ctx)` | Free context and zero key material. |

### Connection Lifecycle

| Function | Description |
|----------|-------------|
| `mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port)` | Clear mode: TCP connect + MQC handshake (1 round trip). cert_index visible to eavesdroppers. |
| `mqc_conn_t *mqc_connect_encrypted(mqc_ctx_t *ctx, const char *host, int port)` | Encrypted identity mode: TCP connect + two-phase handshake (1.5 round trips). cert_index hidden. |
| `int mqc_listen(const char *host, int port)` | Create TCP listening socket. Pure POSIX, no crypto. Returns fd or -1. |
| `mqc_conn_t *mqc_accept(mqc_ctx_t *ctx, int listen_fd)` | Clear mode: TCP accept + MQC handshake. |
| `mqc_conn_t *mqc_accept_encrypted(mqc_ctx_t *ctx, int listen_fd)` | Encrypted identity mode: TCP accept + two-phase handshake. |
| `mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd)` | Auto-detecting: reads first JSON, routes to clear or encrypted based on cert_index presence. Recommended for servers. |

### I/O

| Function | Description |
|----------|-------------|
| `int mqc_read(mqc_conn_t *conn, void *buf, int sz)` | Read and decrypt data. Returns bytes read, 0 on close, -1 on error. |
| `int mqc_recv(mqc_conn_t *conn, void *buf, int sz)` | Alias for mqc_read. |
| `int mqc_write(mqc_conn_t *conn, const void *buf, int sz)` | Encrypt and send data. Returns bytes written, -1 on error. |
| `int mqc_send(mqc_conn_t *conn, const void *buf, int sz)` | Alias for mqc_write. |

### Cleanup and Utility

| Function | Description |
|----------|-------------|
| `void mqc_close(mqc_conn_t *conn)` | Close connection, zero session keys, free resources. |
| `int mqc_get_fd(mqc_conn_t *conn)` | Get raw file descriptor for select/poll. |
| `int mqc_get_peer_index(mqc_conn_t *conn)` | Get peer's cert_index (after handshake). |

## Configuration

### mqc_cfg_t Fields

| Field | Required | Description |
|-------|----------|-------------|
| `role` | Yes | `MQC_CLIENT` or `MQC_SERVER` |
| `tpm_path` | Yes | Path to `~/.TPM/<domain>/` containing `certificate.json` + `private_key.pem` |
| `mtc_server` | Yes | MTC CA server for peer key resolution (e.g., `"localhost:8444"`) |
| `ca_pubkey` | Yes | CA's ML-DSA-87 cosigner public key (2592 bytes) for cosignature verification |
| `ca_pubkey_sz` | Yes | Size of ca_pubkey |
| `encrypt_identity` | No | 1 = encrypted identity mode (default: 0).  Also selectable by calling `mqc_connect_encrypted` directly.  When set on a listener context it makes `mqc_accept_auto` fail-loud reject any clear-mode ClientHello (`REQUIRE_ENCRYPTED_REJECT`). |
| `expected_name` | No | Override the expected-identity name set via `mqc_ctx_set_expected_name`.  Defaults to the dialed hostname; required when dialing by IP. |

### TPM Directory Layout

**Our identity:**
```
~/.TPM/<domain>/
    certificate.json    # MTC certificate (cert_index, Merkle proof, cosignature)
    private_key.pem     # ML-DSA-87 private key
    public_key.pem      # ML-DSA-87 public key
```

**Peer cache (populated automatically):**
```
~/.TPM/peers/<cert_index>/
    certificate.json    # peer's MTC certificate from server
    checkpoint.json     # tree state at verification time
```

## Example Usage

### Client

```c
#include "mqc.h"

int main(void)
{
    mqc_cfg_t cfg = {0};
    cfg.role       = MQC_CLIENT;
    cfg.tpm_path   = "/home/user/.TPM/factsorlie.com";
    cfg.mtc_server = "localhost:8444";
    cfg.ca_pubkey  = ca_mldsa87_key;
    cfg.ca_pubkey_sz = 2592;

    mqc_ctx_t *ctx = mqc_ctx_new(&cfg);

    mqc_conn_t *conn = mqc_connect(ctx, "peer.example.com", 4433);
    if (!conn) { /* handshake failed */ }

    mqc_write(conn, "Hello MQC!", 10);

    char buf[256];
    int n = mqc_read(conn, buf, sizeof(buf));

    mqc_close(conn);
    mqc_ctx_free(ctx);
}
```

### Server

```c
#include "mqc.h"

int main(void)
{
    mqc_cfg_t cfg = {0};
    cfg.role       = MQC_SERVER;
    cfg.tpm_path   = "/home/user/.TPM/factsorlie.com-ca";
    cfg.mtc_server = "localhost:8444";
    cfg.ca_pubkey  = ca_mldsa87_key;
    cfg.ca_pubkey_sz = 2592;

    mqc_ctx_t *ctx = mqc_ctx_new(&cfg);
    int fd = mqc_listen(NULL, 4433);

    for (;;) {
        mqc_conn_t *conn = mqc_accept(ctx, fd);
        if (!conn) continue;

        char buf[256];
        int n = mqc_read(conn, buf, sizeof(buf));
        mqc_write(conn, buf, n);  /* echo */

        mqc_close(conn);
    }

    mqc_ctx_free(ctx);
}
```

## Comparison with TLS 1.3

| Feature | TLS 1.3 | MQC |
|---------|---------|-----|
| Round trips | 1-2 | 1 (clear) or 1.5 (encrypted identity) |
| Certificate on wire | Full X.509 cert (~2.8KB for ML-DSA-87) | cert_index integer (~10 bytes) |
| Key exchange | ECDHE or ML-KEM hybrid | ML-KEM-768 |
| Authentication | X.509 certificate chain | Merkle proof + cosignature |
| Post-quantum key exchange | Optional (hybrid only) | Native (ML-KEM-768) |
| Post-quantum signatures | Requires ML-DSA cert in X.509 wrapper | Native ML-DSA-87 |
| Public key resolution | Sent in handshake | Fetched from Merkle log (cached) |
| Repeat connection overhead | Full cert every time | Zero (cache hit) |
| Dependencies | Full TLS stack (wolfSSL ~500KB) | wolfSSL crypto only (~100KB) |
| X.509 required | Yes | No |

## Server Defense Layers

MQC servers enforce six layers of connection defense.  All
operator-tunable knobs live in `/etc/postWolf/config` under
`[global]` (Augeas-managed); defaults below match the reference
implementation.

### 1. Per-IP rate limiting (Redis)

Requires Redis on `127.0.0.1:6379`.  Operator policy
(`mqc-rl-redis-fail-policy`) selects between fail-open
(grace window) and closed-after:N seconds when Redis is
unavailable; default is closed-after:8s.

| Counter | Default | TTL | Knob | Redis key |
|---|---|---|---|---|
| Connections per minute | 100 | 60s | `mqc-rl-connect-per-min` | `mqc:<ip>:conn:m` |
| Connections per hour | 1000 | 3600s | `mqc-rl-connect-per-hour` | `mqc:<ip>:conn:h` |
| Failed handshakes per minute | 10 | 60s | `mqc-rl-fail-per-min` | `mqc:<ip>:fail:m` |
| Failed handshakes per hour | 100 | 3600s | `mqc-rl-fail-per-hour` | `mqc:<ip>:fail:h` |
| Distinct `cert_index` per minute | 10 | 60s | `mqc-rl-cert-per-min` | `mqc:<ip>:cert:m` (Redis SET) |
| Distinct `cert_index` per hour | 100 | 3600s | `mqc-rl-cert-per-hour` | `mqc:<ip>:cert:h` (Redis SET) |

Counters increment on every attempt (even rejected ones).
The distinct-`cert_index` SET defeats `cert_index` rotation
attacks: rotating index per connection forces a fresh fetch +
inclusion-proof verification + cosignature verification, which
is millisecond-scale work per cheap client byte.

### 2. Fork backpressure

Before each `accept()`, the listener checks an active-child
counter (incremented per fork, decremented on SIGCHLD).  When
at or above `mqc-max-children` (default 20), it sleeps briefly
and re-checks instead of fanning out into hundreds of
concurrent forks.  This is a process-level cap independent of
the per-IP limits — a single legitimate IP can drive many
parallel connections, and this cap keeps host memory bounded.
Closes TODO #65.

### 3. Handshake timeouts

`mqc-handshake-stall-sec` (default 3s) is the per-read
deadline; `mqc-handshake-total-sec` (default 5s) is the total
wall-clock budget from accept to handshake completion.  Both
are dropped after the handshake completes; the data-plane uses
a separate ~60s per-read deadline.  Slowloris-style stalls are
denied multi-minute windows.

### 4. AbuseIPDB screening

Checks the client IP against the AbuseIPDB API when
`ABUSEIPDB_TOKEN` is set (env or `~/.env`).  Rejects at
`abuse_confidence_score >= 25` for enrolment, `>= 75` for any
connection.  Cached for 5 days in the `abuseipdb` Postgres
table.

### 5. Strict JSON parser, fail-closed

The handshake JSON parser runs with
`JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8`, then
`mqc_json_no_duplicates` + `mqc_json_no_unknown_keys` +
`mqc_json_get_int_strict` (explicit ERANGE).  Hex fields
(`kem_pub`, `signature`) are length-checked against the
chosen suite *before* any ML-KEM / ML-DSA invocation, so
garbage cannot exercise the asymmetric primitives.  Duplicate
keys are detected on the raw JSON bytes (not the parsed
object) so a smuggled duplicate cannot diverge between signer
and verifier views of the transcript.

### 6. Security logging

All failures logged with `[MQC-SECURITY]` prefix including:

- `RATE_LIMITED` / `FAIL_RATE_LIMITED` — per-IP rate limits exceeded
- `CERT_RATE_LIMITED` — per-IP `cert_index` rotation cap exceeded
- `MAX_CHILDREN_THROTTLED` — fork backpressure stretched the burst
- `ABUSEIPDB_REJECTED` — IP rejected (score above threshold)
- `SIG_VERIFY_FAILED` — invalid ML-DSA-87 signature (MITM attempt)
- `PEER_VERIFY_FAILED` — Merkle inclusion proof or cosignature failure
- `PUBKEY_HASH_MISMATCH` — `subject_public_key_hash` mismatch (with `source=` tag)
- `CERT_REVOKED` / `CERT_EXPIRED` / `CERT_NOT_YET_VALID` — peer cert lifecycle
- `NAME_CHECK_FAILED` — verified subject does not match dialed name (§10.7)
- `REQUIRE_ENCRYPTED_REJECT` — clear-mode ClientHello on a listener with `encrypt_identity = 1`
- `GCM_AUTH_FAILED` — tampered AEAD frame (with peer index + sequence)
- `FINISHED_MAC_FAILED` — Finished-frame MAC mismatch (transcript divergence)
- `PUBKEY_MISSING` — peer public key not resolvable

All entries include function name + line number for tracing.

## Cryptographic Algorithms

| Purpose | Algorithm | Standard | Key/Output Size |
|---------|-----------|----------|-----------------|
| Key exchange | ML-KEM-768 | FIPS 203 | 1184B pub / 1088B ct / 32B secret |
| Authentication | ML-DSA-87 | FIPS 204 | 2592B pub / 4627B sig |
| Session encryption | AES-256-GCM | FIPS 197 + SP 800-38D | 32B key / 12B nonce / 16B tag |
| Key derivation | HKDF-SHA256 | RFC 5869 | Variable |
| Merkle proofs | SHA-256 | FIPS 180-4 | 32B hash |
| Cosignatures | ML-DSA-87 | FIPS 204 | 2592B pub / 4627B sig |
