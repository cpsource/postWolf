# postWolf `mtc_server` — detailed design spec

This document is the consolidated reference for the C `mtc_server`
process (`mtc-keymaster/server2/c/mtc_server`).  It describes
the three TCP ports, the protocol on each port, every endpoint,
and the JSON message format flowing in each direction.

It supersedes and absorbs the following files (now deleted; the
original content is recoverable via `git show <commit>~1:<path>`
on the commit that introduced this spec):

| Absorbed file | What it covered |
|---|---|
| `mtc-keymaster/README.md` | top-level overview, three keys, identity dirs |
| `mtc-keymaster/README-ca-registration.md` | CA enrollment workflow + state |
| `mtc-keymaster/README-leaf-registration.md` | leaf enrollment + reservation nonces |
| `mtc-keymaster/README-nonce.md` | enrollment-nonce data model |
| `mtc-keymaster/README-mqc-cli.md` | `mqc` CLI tool surface |
| `mtc-keymaster/README-parsing.md` | JSON parsing invariants |
| `mtc-keymaster/README-db-schema.md` | Neon schema |
| `mtc-keymaster/README-insecure-report.md` | observed insecurities + status |

Files that intentionally stay separate:

| File | Why |
|---|---|
| `mtc-keymaster/README-bugsandtodo.md` | open-work tracker, not design |
| `mtc-keymaster/README-clean-install.md` | install procedure, not design |
| `mtc-keymaster/augeas/README.md` | config-parser package, separate concern |

---

## 1. Process model

`mtc_server` runs as a systemd-managed process
(`mtc-ca.service`).  At startup it:

1. Loads the ML-DSA-87 keypair from
   `~/.mtc-ca-data/ca_key_mldsa.der`.  This single key is used
   both to issue certs (CA role) and to cosign Merkle subtree
   roots (cosigner role).  Same key, two roles.
2. Connects to Neon Postgres via `MERKLE_NEON` DSN read from
   `~/.env`.  Postgres is **required**: TODO #74 phase 3
   (2026-05-07) retired file mode entirely — `mtc_store_init`
   refuses to start when `MERKLE_NEON` is unset.
3. Opens the tiled Merkle tree
   (`mtc_tiled_tree_open`).  Resident state is just the top-K
   inner-node hashes (levels >= `MTC_TOP_K_LEVEL_THRESHOLD`)
   plus the bounded `mtc_tile_cache` LRU; the tree size is read
   from `MAX(index)+1` in `mtc_log_entries`.  Lower levels live
   in `mtc_merkle_tiles` (Section 7.4) and fault in on demand.
4. Spawns the three port listeners (TLS 8444, DH bootstrap
   8445, MQC 8446).
5. fork()s a child per accepted connection on each port.

The fork-after-accept model gives each child a copy-on-write
view of the parent's caches (`mtc_cert_cache`, `mtc_tile_cache`,
top-K hash array).  Mutating children write their changes
straight to Neon under a `pg_advisory_xact_lock(<log_id-key>)`
so concurrent appends serialize cleanly at the DB layer.  There
is no parent-side reload, no SIGHUP, no rwlock around the fork
sites — TODO #74 phase 3 retired the entire `reload_thread` /
`reload_lock` plumbing along with the in-memory `certificates[]`
/ `revoked_indices[]` arrays that justified it (phases 2 + 3).
Other forks see the new state on their next cache miss; the
parent picks it up the same way the next time it touches an
affected cert or tile.

---

## 2. Listener overview

| Port | Protocol | Default bind | Purpose | Source |
|---|---|---|---|---|
| **8444** | HTTPS over TLS 1.3 | `0.0.0.0:8444` | Public read-only API + CA-/operator-authenticated POSTs | `mtc_http.c::mtc_http_serve` |
| **8445** | Plaintext TCP + per-connection X25519 DH for confidentiality | `0.0.0.0:8445` | Pre-trust-anchor enrollment (CA + leaf), public-key fetch, HTTP-API proxy for clients without TLS | `mtc_bootstrap.c::bootstrap_thread` |
| **8446** | MQC (post-quantum authenticated transport) | `0.0.0.0:8446` | Same endpoint set as 8444 + MQC-only endpoints (issue-leaf-nonce, cancel-nonce) — caller's MQC peer cert is the auth token | `mtc_http.c::mtc_http_serve` (TLS off) |

All three ports are operator-tunable via `/etc/postWolf/config`
(`global/url-local`, `global/url-bootstrap`, `global/url-server`).
Wire-format invariants are NOT operator-tunable per CLAUDE.md.

**Port 8444 is disabled by default.**  The operator knob
`global/url-local-port-disabled` defaults to `Yes` — `mtc_server`
starts the bootstrap (8445) and MQC (8446) listeners but does not
bind 8444 at all.  This removes the plain-HTTP attack surface
that ChatGPT review item #7 flagged.  Nothing internal to
postWolf needs 8444: the C clients (show-tpm, bootstrap_*, mqc)
all speak MQC, and the bootstrap port's `http_get` proxy reaches
`dispatch_get` in-process without a network round-trip.  Flip
the knob to `No` only if some external tool (e.g., Python
verify.py) needs the TLS API.

---

## 3. Port 8444 — HTTPS API (TLS 1.3)

Standard HTTP/1.1 wrapped in TLS 1.3.  The server presents a
publicly-issued X.509 certificate (e.g., Let's Encrypt) for
authenticity and confidentiality; clients verify it against the
system CA store.  All endpoints below are also reachable on port
**8446** under MQC; the MQC variant skips TLS overhead and binds
the caller's identity to the request.

Buffer cap: `HTTP_BUF_SZ` (~64 KB) holds headers + body for a
single request.  `Content-Length` over 1 MB is rejected with
`413`.

Rate-limit classes referenced below (defaults from
`mtc_ratelimit.c`; the per-IP buckets are `{per-min, per-hr}`):

| Class | Default bucket |
|---|---|
| `RL_READ` | 60 / min, 600 / hr per IP |
| `RL_NONCE_LEAF` | 10 / min, 100 / hr per IP |
| `RL_NONCE_CA` | 3 / min, 10 / hr per IP |
| `RL_ENROLL` | 3 / min, 10 / hr per IP |
| `RL_REVOKE` | 5 / min, 100 / hr per IP |
| `RL_BOOTSTRAP` | 3 / min, 30 / hr per IP (port 8445 enrollment) |

### 3.1 GET endpoints (read-only, public)

#### `GET /`
Server identity banner.

Response (`200 application/json`):
```json
{
  "server":    "MTC CA/Log Server (C)",
  "version":   "0.1.0",
  "draft":     "draft-ietf-plants-merkle-tree-certs-02",
  "ca_name":   "MTC-CA-C",
  "log_id":    "32473.2",
  "tree_size": 79
}
```

#### `GET /log`
Current log state.

Response:
```json
{
  "log_id":      "32473.2",
  "ca_name":     "MTC-CA-C",
  "cosigner_id": "32473.2.ca",
  "tree_size":   <int>,
  "root_hash":   "<hex>"
}
```

The pre-2026-05-07 `landmarks` array was dropped when TODO #76
retired `mtc_landmarks`; the Python verifier tolerates its
absence (defaults to `[]`).

#### `GET /log/entry/<index>`
Fetch a single log entry.

Response: `{"index": N, "entry_type": 1, "tbs_data": {...}, "serialized_hex": "...", "leaf_hash_hex": "..."}`.

`404` if `index >= tree_size` or the entry is sparse-deleted.

#### `GET /log/proof/<index>`
Inclusion proof for a single leaf against the current root.

Response:
```json
{
  "index":      N,
  "entry_hash": "<hex>",
  "subtree":    {"start": 0, "end": <tree_size>},
  "root_hash":  "<hex>",
  "proof":      ["<hex>", ...],
  "valid":      true
}
```

#### `GET /log/checkpoint`
Latest tree-root snapshot.

Response:
```json
{
  "log_id":    "32473.2",
  "tree_size": N,
  "root_hash": "<hex>",
  "timestamp": <unix-double>
}
```

Cosignatures are NOT carried in the checkpoint object itself —
they live inside each `standalone_certificate` (see §8.3) and
sign the cert's specific power-of-2 subtree root rather than the
current full-tree root.  Verifiers reconstruct
"my cert is in this log" by checking the inclusion proof against
the cosigned subtree root, then optionally cross-checking the
checkpoint's `root_hash` to confirm the live tree extends that
subtree.

#### `GET /log/consistency?old=N&new=M`
Consistency proof between two tree sizes.  `old <= new <= tree_size`.

Response:
```json
{
  "old_size": N,
  "new_size": M,
  "old_root": "<hex>",
  "new_root": "<hex>",
  "proof":    ["<hex>", ...]
}
```

#### `GET /certificate/search?q=<subject>`
Find live certs whose subject contains the query string
(case-insensitive substring match).  `400` if `q` is missing or
empty.

Response:
```json
{
  "query":   "<the q parameter, echoed>",
  "results": [
    {"index": N, "subject": "..."},
    ...
  ]
}
```

#### `GET /certificate/<index>`
Fetch the wire-form cert wrapper at a given log index — see §8.3
for the full shape.

Response (`200`): `{"status": "ok", "index": N, "standalone_certificate": {...}, "checkpoint": {...}}`.
`404 certificate not found` if the index is unknown or
sparse-deleted.

#### `GET /trust-anchors`
Trust-anchor list.  Single `standalone` entry for the log
itself.

Response:
```json
{
  "trust_anchors": [
    {"id": "<log_id>", "type": "standalone"}
  ]
}
```

The pre-2026-05-07 form also enumerated one `landmark` entry
per cached power-of-2 subtree size (backed by `mtc_landmarks`).
TODO #76 retired both the table and the landmark anchors after
no live client was found to consume the landmark format.

The cosigner public key itself is served at `GET /ca/public-key`
(below), not on this endpoint.

#### `GET /revoked`
Full revocation list.

Response: `{"revoked": [<cert_index>, ...]}`.

#### `GET /revoked/<index>`
Single-cert revocation status.  Used by `mqc_peer_verify` for
mandatory revocation checks.

Response: `{"cert_index": N, "revoked": <bool>}`.  No `reason`
field on the GET path — that's only emitted by `POST /revoke`.

#### `GET /ca/public-key`
The CA-cosigner ML-DSA-87 public key in PEM form.

Response:
```json
{
  "ca_name":        "MTC-CA-C",
  "cosigner_id":    "<log_id>.ca",
  "algorithm":      "ML-DSA-87",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

PEM header is `-----BEGIN PUBLIC KEY-----` (PUBLICKEY_TYPE) post-TODO #9a — earlier emissions used the misleading `BEGIN ML_DSA_LEVEL5 PRIVATE KEY` label.  Header-agnostic clients that only `strstr("-----END")` continue to work.

#### `GET /public-key/<name>`
Fetch the leaf or CA public key by name (subject, optionally
`<subject>-<label>`).

Response: `{"public_key_pem": "..."}` (response always ends with a
trailing newline — fixed in TODO #53/post-#9a hygiene).

`404 public key not found` if no `mtc_public_keys` row matches.

#### `GET /ech/configs`
Encrypted Client Hello config blob (base64).  Used by the SLC
(TLS 1.3 wrapper) layer in `socket-level-wrapper/`.

### 3.2 POST endpoints

#### `POST /enrollment/nonce`
Mint a new enrollment nonce.

**Auth (CA-type nonces):** none — auth happens at consume time
via DNSSEC TXT validation on `_mqc-ca.<domain>`.

**Auth (leaf-type nonces):** **MQC peer-cert required**, AND
the peer's subject must be exactly `<domain>-ca` for the
requested `domain`.  Plain HTTP gets `403 leaf nonce issuance
requires MQC peer-cert auth`; an MQC peer whose subject is not
`<domain>-ca` gets `403 only the CA for this domain may mint
leaf nonces`.  Closes TODO #64 (cross-CA leaf hopping by
already-in-log peers).

Per-IP rate-limited via `RL_NONCE_LEAF` or `RL_NONCE_CA`.  For
leaf nonces, the server additionally requires that a registered
CA exists for the domain (else `403 no registered CA`).

Request (CA nonce, default):
```json
{
  "domain": "example.com",
  "public_key_fingerprint": "sha3-256:<64-hex>"
}
```

Request (leaf nonce, fp-bound):
```json
{
  "domain": "example.com",
  "type":   "leaf",
  "public_key_fingerprint": "sha256:<64-hex>",
  "label":  "alice"               // optional
}
```

Request (leaf reservation nonce, late-binding):
```json
{
  "domain":    "example.com",
  "type":      "leaf",
  "label":     "alice",
  "ttl_days":  7
}
```

`public_key_fingerprint` accepts `sha3-256:` (CA-side, SPKI DER)
or `sha256:` (leaf-side, PEM-text) prefix; both are valid.  Bare
hex (no prefix) is also accepted.

`ttl_days` (or `ttl_seconds`) is clamped to the range
`[MTC_NONCE_TTL_SECS, MTC_NONCE_MAX_TTL_DAYS*86400]` (default
caps: 15 min minimum, 30 days maximum).  Long-lived reservations
require a `label`.

Response (`200`):
```json
{
  "nonce":          "<64-hex>",
  "expires":        <unix-int>,
  "type":           "ca" | "leaf",
  "ca_index":       <int>,           // leaf only
  "label":          "alice",         // if provided
  "ca_cosigner_fp": "<64-hex>",      // SHA-256(DER(SPKI(cosigner pem)))
                                     // P0 / TODO #9b leaf branch
  "dns_record_name":  "_mqc-ca.example.com.",     // CA only
  "dns_record_value": "v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<hex>; n=<nonce>; exp=<unix>"
}
```

`409 Conflict` if a pending nonce for the same `(domain,
fingerprint)` already exists (or `(domain, label)` for a
reservation).

#### `POST /certificate/request`
Removed in phase-23.  Always returns `410 Gone — endpoint removed
— use DH bootstrap port for enrollment`.

#### `POST /renew-cert`
Re-issue an expiring cert at a new log index.  **MQC-only**
(returns `403 /renew-cert requires MQC transport` on plain HTTP).

Request:
```json
{
  "new_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "validity_days":      90       // optional, default 90; bounds [1, 3650]
}
```

The caller's MQC peer `cert_index` identifies which existing
cert is being renewed; the new cert inherits the old subject and
algorithm.  Revoked certs are refused (`403`).

Response: same shape as `GET /certificate/<index>` but for the
new index.

#### `POST /cancel-nonce`
Retract a pending reservation nonce early.  **MQC-only**
(returns `403` on plain HTTP).

Request:
```json
{
  "domain": "example.com",
  "label":  "alice"
}
```

Authorization: caller's MQC peer must be the same CA that issued
the reservation (the cancel is gated by `ca_index == peer_idx`
in the DB).  Cannot cancel a CA's reservation if you're not that
CA.

Response (`200`):
```json
{
  "cancelled": true,
  "domain":    "example.com",
  "label":     "alice"
}
```

`404` if no matching pending nonce (already consumed, expired,
or wrong CA).

#### `POST /revoke`
Revoke a cert by index.

Request:
```json
{
  "ca_cert_index":     <int>,    // index of the CA submitting the revocation
  "cert_index":        <int>,    // target cert index to revoke
  "reason":            "key compromise",   // optional
  "timestamp":         <unix-int>,
  "ca_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "signature":         "<hex>"   // CA-key signature over the canonical revocation message
}
```

Server verifies the signature is valid under `ca_public_key_pem`,
checks the public key matches `mtc_certificates[ca_cert_index]`,
checks `ca_cert_index` has authority over `cert_index` (target's
subject is a child of the CA's subject), and appends a row to
`mtc_revocations`.

Public-key import uses `wc_Dilithium_PublicKeyDecode` on the SPKI
DER produced by `wc_PubKeyPemToDer` — NOT `wc_dilithium_import_public`,
which expects the raw 2592-byte ML-DSA-87 key and returns -173 on
the SPKI form.  The latter would silently funnel into the
"signature verification failed" 403 branch, masking the real
cause; this was uncovered by the TODO #19 matrix on 2026-05-07.

`mtc_store_revoke` writes the revocation row directly to
`mtc_revocations`; subsequent `/revoked/<n>` lookups (from any
fork) hit the DB through the cert cache's revoke-aware path, so
no parent-side reload is needed.  The pre-phase-3 `SIGHUP` raise
was retired with the in-memory `revoked_indices[]` array (TODO
#74 phase 3, commit 26368ab3a).

Response (`200`): `{"revoked": true, "cert_index": N, "ca_cert_index": M, "target_subject": "...", "reason": "..."}`.

The signed reference client `revoke-key` does not exit on the 200
— it polls `/revoked/<target>` over the bootstrap port until the
parent's view is consistent (5 × 2s).  This makes the tool's exit
code a meaningful signal that downstream readers will agree.

End-to-end coverage of the authorization matrix lives at
`mtc-keymaster/tests/c/test_revoke_matrix.c` + the
`mtc-keymaster/tests/run-revoke-matrix.sh` wrapper.  See TODO #19
in `README-bugsandtodo.md`.

---

## 4. Port 8445 — DH bootstrap

Plaintext TCP.  Intended for clients that do NOT yet have a
trusted MQC identity AND cannot rely on the system CA store
(e.g., they're enrolling for the first time).  Confidentiality
comes from a per-connection X25519 DH exchange; authenticity of
the server's response comes from an ML-DSA-87 signature under the
cosigner key bound to a DNSSEC-published TXT record (P0 / TODO
#9b).

Three top-level message types — the first two are plaintext-only
ops, the third is the multi-step DH-encrypted enrollment flow.

### 4.1 `{"op":"ca_pubkey"}` — fetch CA cosigner pubkey

Plaintext request:
```json
{"op": "ca_pubkey"}
```

Plaintext response (same shape as `GET /ca/public-key` on 8444):
```json
{
  "ca_name":        "MTC-CA-C",
  "cosigner_id":    "<log_id>.ca",
  "algorithm":      "ML-DSA-87",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

Used by `mqc_load_ca_pubkey` (`socket-level-wrapper-MQC/mqc_peer.c`)
when the client has no per-leaf cosigner pin.  Combined with the
DNSSEC pin at `_mqc-cosigner.<host>` the response is authenticated
against MitM.

### 4.2 `{"op":"http_get","path":"<path>"}` — HTTP-API proxy

Plaintext request:
```json
{"op": "http_get", "path": "/certificate/72"}
```

Plaintext response: the JSON body that `GET <path>` would return
on port 8444, plus a trailing line with the HTTP status code.

Used by clients that want to reach the read-only API without
having a TLS trust anchor.  Internally calls
`mtc_http_dispatch_get_capture` so the response shape exactly
matches port 8444.

### 4.3 DH-encrypted enrollment (CA + leaf)

A four-message exchange.  Triggered when the client's first
plaintext message contains `dh_public_key` instead of an `op`
field.

#### Message 1 — client → server (plaintext)
```json
{"dh_public_key": "<X25519 pubkey hex, 64 chars>"}
```

#### Message 2 — server → client (plaintext)
```json
{
  "dh_public_key": "<X25519 pubkey hex>",
  "salt":          "<32-hex>",
  "pop_nonce":     "<64-hex>"
}
```

Both peers compute `shared_secret = X25519(my_priv, their_pub)`,
then derive **two** AES-256 keys (one per direction) via HKDF:
```
keys[0..63] = HKDF-SHA256(shared_secret, salt, "mtc-dh-bootstrap", 64)
c2s_key     = keys[0..31]
s2c_key     = keys[32..63]
```
Per-direction keys eliminate any GCM-nonce collision risk
across directions even with random per-message nonces.  Closes
TODO #62 — replaces the historical AES-CBC zero-IV no-MAC
construction.

`pop_nonce` is the 32-byte proof-of-possession nonce the client
must sign with the CA private key (CA enrollment only — leaf
enrollment proves possession via the issued nonce).

**AEAD frame format (TODO #62).**  Each AES-256-GCM frame on the
wire is `[12-byte nonce][N-byte ciphertext][16-byte GCM tag]`,
length-prefixed with the existing 4-byte big-endian frame
header.  Total wire bytes per frame = `4 + 12 + plaintext_length
+ 16`.  AAD bound into every tag:

```
"mtc-bootstrap-aead/v1\n"   (23 bytes incl. compiler NUL)
|| direction_byte            (1 byte: 0x01 c2s, 0x02 s2c)
|| plaintext_length          (4 bytes BE)
```

Direction is in the AAD AND selects the per-direction key, so a
MitM cannot replay a request frame as a response.  Nonces are
freshly RNG-generated per encode; per-direction keys make
nonce-collision-across-directions a non-event.

#### Message 3 — client → server (AES-256-GCM, length-prefixed)

CA enrollment payload (no `enrollment_nonce`; the server detects
this is a CA by the presence of `ca_certificate_pem` inside
`extensions`):
```json
{
  "subject":        "example.com-ca",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "key_algorithm":  "ML-DSA-87",
  "validity_days":  365,
  "extensions": {
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
  },
  "pop_signature": "<hex>"   // ML-DSA-87 sig over MQC-CA-REGISTER|<domain>|<subject>|<spki_hash_hex>|<pop_nonce_hex>
}
```

Leaf enrollment payload (`enrollment_nonce` required; no
`ca_certificate_pem` in extensions):
```json
{
  "subject":          "example.com",
  "public_key_pem":   "-----BEGIN PUBLIC KEY-----\n...",
  "key_algorithm":    "ML-DSA-87",
  "validity_days":    90,
  "enrollment_nonce": "<64-hex>",
  "label":            "alice",       // optional; mirrors the label baked into the reservation
  "extensions":       { ... }         // optional arbitrary metadata
}
```

Server-side validation depending on the path:

- **CA enrollment**: parses + validates the X.509 cert (matches
  `<domain>-ca` subject and SPKI matches `public_key_pem`),
  fetches `_mqc-ca.<domain>` TXT via DNSSEC and matches
  `kh=sha3-256:<SHA3-256(SPKI DER)>`, verifies the PoP signature.
- **Leaf enrollment**: looks up the nonce in
  `mtc_enrollment_nonces`, matches `(domain, fp)`, marks
  consumed atomically.

#### Message 4 — server → client (AES-256-GCM, length-prefixed)

```json
{
  "status":                 "ok",
  "index":                  <int>,
  "standalone_certificate": {... see §8 ...},
  "checkpoint":             {... cosigned tree-root ...},
  "label":                  "alice",                // leaf only, in-flight metadata
  "ca_cosigner_pem":        "-----BEGIN PUBLIC KEY-----\n...",  // P0 #9b
  "ca_response_sig":        "<9254-hex ML-DSA-87 sig>"          // P0 #9b
}
```

`ca_response_sig` covers the canonical JSON of the response with
the `ca_response_sig` field absent, signed under the cosigner key
with ctx label `"mtc-bootstrap/v1\n\x00"`.  Verifier strips the
field, re-serializes with `JSON_C_TO_STRING_PLAIN`, and verifies.
Both sides use json-c's PLAIN flag, which preserves insertion
order across the parse → mutate → serialize cycle.

Error response:
```json
{
  "status":  "error",
  "message": "<human-readable diagnostic>"
}
```

(Error responses are NOT signed — an attacker can fake a `status:
error` reply, but cannot inject a successful enrollment.  This is
an availability-only attack surface, equivalent to dropping the
TCP connection.)

### 4.4 CA `ca_certificate_pem` is NOT a trust object

The `ca_certificate_pem` field in CA-enrollment requests is
parsed with `NO_VERIFY` in `mtc_ca_validate.c`.  The X.509
wrapper exists as a STRUCTURED CONTAINER for two pieces of
data only:

1. The Subject Alternative Name (SAN) DNS name — used to look
   up `_mqc-ca.<SAN>` in DNSSEC.
2. The `SubjectPublicKeyInfo` DER — its SHA3-256 must match
   the `kh=sha3-256:<HEX>` field in the DNSSEC TXT record.

The cert's signature chain, issuer, validity dates, Basic
Constraints, KeyUsage, and any embedded extensions are
**explicitly not trusted**.  A self-signed cert, a cert
chained to a real WebPKI CA, and a cert with a
syntactically-valid but cryptographically-invalid signature
are treated identically — the only thing that matters is
whether `(SAN, SHA3-256(SPKI DER))` lines up with the
DNSSEC pin.

This is deliberate:

- Adding `wolfSSL_CertManagerVerifyBuffer` here would not
  improve the trust story (DNSSEC pinning already
  authenticates the SPKI).
- It would not prove control of the private key (a
  self-signed cert can be re-submitted by any attacker).
  Real proof-of-possession is the separate `pop_signature`
  field.
- Importing an external trust root (Let's Encrypt, system
  CA bundle) into this code path would invert the threat
  model — the operator's DNSSEC zone would no longer be the
  single source of truth.

**Implication for future maintainers.**  Any code path that
reuses the `DecodedCert` parsed in `mtc_validate_ca_cert`
must NOT assume the cert is signed by a trusted issuer or
treat its `notBefore` / `notAfter` / `keyUsage` /
`basicConstraints` as authority claims.  A loud banner at
the top of `mtc_ca_validate.c` calls this out (TODO #71 /
ChatGPT review item #12, closed 2026-05-06).

---

## 5. Port 8446 — MQC API

MQC = Merkle Quantum Connect.  Post-quantum authenticated
transport defined in
`socket-level-wrapper-MQC/draft-page-mqc-protocol-00.md`.
Briefly:

- ML-KEM-768 key exchange.
- ML-DSA-87 signed identity (ClientHello + ServerHello carry
  the peer's `cert_index`; both sides verify Merkle proofs +
  cosignatures against the in-log cert at that index).
- AES-256-GCM session encryption with per-direction keys.
- HMAC-SHA256 Finished MAC committing to the full transcript.
- 31-byte AAD on every AEAD frame (LABEL || version || direction
  || frame_type || sequence || plaintext_length).

Once the handshake completes, the server runs the SAME HTTP
dispatcher as port 8444 — same paths, same JSON, same response
shapes.  The MQC peer's `cert_index` is exposed to handlers via
`io->mqc`, so endpoints that need caller-identity-as-auth
(`/cancel-nonce`, leaf nonces) can introspect it.

### 5.1 MQC-only / MQC-preferred endpoints

| Endpoint | 8444 (TLS HTTP) | 8446 (MQC) |
|---|---|---|
| `POST /enrollment/nonce` type=ca | works (rate-limited only) | works (same code path) |
| `POST /enrollment/nonce` type=leaf | `403` requires MQC | works; MQC peer subject must be `<domain>-ca` for the requested domain |
| `POST /cancel-nonce` | `403` requires MQC | works; MQC peer must be the CA that issued the reservation |
| `POST /renew-cert` | `403` requires MQC | works; MQC peer cert is the cert being renewed |
| `POST /revoke` | works (request body carries CA-key signature) | works (same) |

CA-type nonces (`type=ca` or absent) stay open on either port:
the auth happens at consume time via DNSSEC TXT validation on
`_mqc-ca.<domain>`.  Leaf-type nonces are MQC-gated by the
domain's CA — closes TODO #64 (cross-CA leaf hopping by
already-in-log peers).

Tools that always speak MQC (port 8446):

- `issue_leaf_nonce` — CA operator mints a leaf nonce.
- `cancel-nonce` — CA operator retracts a reservation.
- `renew-cert` / `check-renewal-cert` — leaf or CA renewal.
- `show-tpm --verify` — verifies all local identities against
  the live server.
- `revoke-key` — operator-side cert revocation.

### 5.2 MQC handshake mode dispatch

`mqc_accept_auto` reads the first length-prefixed frame, parses
its `mode` field, and dispatches:

- `"mode": "clear"` — single-roundtrip identity-in-the-clear
  handshake.  Carries `cert_index` in plaintext ServerHello.
- `"mode": "encrypted"` — two-phase 4-frame handshake.  Phase 1
  is anonymous KEM; phase 2 is AEAD-sealed identity under an
  early secret derived from phase 1.  A passive observer learns
  ML-KEM bytes only.

The dispatcher refuses clear-mode handshakes when the listener's
`ctx->encrypt_identity == 1` (MQC-01 guard, see Gemini triage in
`socket-level-wrapper-MQC/reviews/README-gemini.txt`).

Full wire format: `socket-level-wrapper-MQC/draft-page-mqc-protocol-00.md`.

---

## 6. Authentication chain

```
IANA root KSK (DNSSEC root of trust)
        │
        │  signs
        ▼
parent zone (e.g. com)
        │
        │  signs DS for example.com
        ▼
example.com zone
        │
        │  signs:
        │    _mqc-cosigner.example.com TXT  (cosigner SPKI fingerprint)
        │    _mqc-ca.<sub>.example.com TXT  (each enrolled CA's SPKI fingerprint)
        ▼
DNSSEC-validated TXT records consumed by:
    - bootstrap_ca       (enrolling CAs verify cosigner pin)
    - mqc_load_ca_pubkey (every libmqc tool verifies cosigner pin)
    - mtc_server         (validates enrolling CA's domain control)
        │
        ▼
Cosigner ML-DSA-87 key  ←  cosigns Merkle subtree roots
        │
        ▼
Domain CA cert (e.g. example.com-ca)  ←  in-log entry, cosigned
        │
        │  signs MQC handshakes for its own identity
        ▼
Leaf cert (e.g. example.com)  ←  in-log entry, cosigned
        │
        │  signs MQC handshakes for its own identity
        ▼
Authenticated MQC sessions
```

Every step is post-quantum-signed (ML-DSA-87) except the DNSSEC
chain itself, which is classical RSA/ECDSA per IANA.  TODO #47
already migrated the cosigner from Ed25519 to ML-DSA-87; closing
the DNSSEC algorithm dependency is a separate IETF concern.

---

## 7. Database schema (Neon Postgres)

Connection: `MERKLE_NEON` env var or `~/.env` `MERKLE_NEON=...`
line.  All tables live in the default Neon database; none require
extensions.

### 7.1 `mtc_log_entries` — append-only Merkle log

```sql
CREATE TABLE mtc_log_entries (
    index       INTEGER PRIMARY KEY,
    entry_type  SMALLINT NOT NULL,
    tbs_data    JSONB,
    serialized  BYTEA NOT NULL,
    leaf_hash   BYTEA NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

| Column | Description |
|---|---|
| `index` | 0-based log position |
| `entry_type` | `0x01` for TBS entries (only type today) |
| `tbs_data` | Parsed TBS (subject, algorithm, validity, extensions) |
| `serialized` | Raw bytes for Merkle hashing |
| `leaf_hash` | `SHA-256(0x00 \|\| serialized)` |

### 7.2 `mtc_certificates` — issued standalone certs

```sql
CREATE TABLE mtc_certificates (
    index       INTEGER PRIMARY KEY,
    certificate JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

`certificate` carries the full standalone form (see §8).  Sparse
deletes (testing) leave `mtc_log_entries` rows orphaned but keep
the tree structurally consistent.

### 7.3 `mtc_checkpoints` — tree-state snapshots

```sql
CREATE TABLE mtc_checkpoints (
    id          SERIAL PRIMARY KEY,
    log_id      TEXT NOT NULL,
    tree_size   INTEGER NOT NULL,
    root_hash   TEXT NOT NULL,
    ts          DOUBLE PRECISION NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

### 7.4 `mtc_merkle_tiles` — packed inner-node hashes (TODO #74 phase 3)

```sql
CREATE TABLE mtc_merkle_tiles (
    level       INTEGER NOT NULL,
    tile_index  BIGINT  NOT NULL,
    tile_height INTEGER NOT NULL,
    first_node  BIGINT  NOT NULL,
    node_count  INTEGER NOT NULL,
    hashes      BYTEA   NOT NULL,        -- packed 32-byte hashes
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (level, tile_index)
);
CREATE INDEX idx_mtc_merkle_tiles_level ON mtc_merkle_tiles(level);
```

Each tile covers `2^MTC_TILE_HEIGHT = 256` consecutive inner
nodes at one level.  A tile at `(level, tile_index)` covers
positions `[tile_index * 256, (tile_index+1) * 256)`; the
rightmost incomplete tile at any level stores only `node_count`
hashes in its `hashes` blob.  Levels 1..11 (i.e. up to 2048
leaves under one node) live here; level 0 is the leaf hash on
`mtc_log_entries.leaf_hash` and is never duplicated, levels >=
12 live in `mtc_merkle_top_nodes`.

### 7.5 `mtc_merkle_top_nodes` — top-K inner-node hashes (TODO #74 phase 3)

```sql
CREATE TABLE mtc_merkle_top_nodes (
    level      INTEGER NOT NULL,
    node_index BIGINT  NOT NULL,
    hash       BYTEA   NOT NULL,
    PRIMARY KEY (level, node_index)
);
```

Inner nodes at level >= `MTC_TOP_K_LEVEL_THRESHOLD = 12` live
here (one row per node, not packed) so the server can hold
them all in a sorted in-RAM array (`mtc_merkle_tiled.c`'s
`top_nodes`).  At a 10 M-leaf tree (~23 levels), the top 12
levels are ~4096 inner nodes ≈ 128 KB resident.

### 7.6 `mtc_revocations`

```sql
CREATE TABLE mtc_revocations (
    id          SERIAL PRIMARY KEY,
    cert_index  INTEGER NOT NULL,
    reason      TEXT,
    revoked_at  DOUBLE PRECISION NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT now()
);
```

### 7.7 `mtc_enrollment_nonces`

```sql
CREATE TABLE mtc_enrollment_nonces (
    nonce       TEXT PRIMARY KEY,             -- 64 lowercase-hex chars
    domain      TEXT NOT NULL,
    fp          TEXT,                         -- nullable for reservation mode
    ca_index    INTEGER NOT NULL DEFAULT -1,
    label       TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_nonce_domain_fp
    ON mtc_enrollment_nonces (domain, fp)
    WHERE status = 'pending';

CREATE UNIQUE INDEX ux_nonce_domain_label_pending
    ON mtc_enrollment_nonces (domain, label)
    WHERE status = 'pending' AND label IS NOT NULL;
```

State machine:

```
        POST /enrollment/nonce
                │
                ▼
            pending  ──── TTL elapses ────►  expired
                │
                │  bootstrap_leaf consumes (atomic UPDATE)
                ▼
            consumed  (terminal)
```

Constants:

| Name | Value | Source |
|---|---|---|
| `MTC_NONCE_HEX_LEN` | 64 | `mtc_db.h` |
| `MTC_NONCE_TTL_SECS` | 900 (15 min) | `mtc_db.h` |
| `MTC_NONCE_MAX_TTL_DAYS` | 30 | `mtc_db.h` |

### 7.8 `mtc_public_keys` — peer-key resolution

```sql
CREATE TABLE mtc_public_keys (
    idx         BIGSERIAL PRIMARY KEY,
    key_name    VARCHAR(255) UNIQUE NOT NULL,
    key_value   TEXT NOT NULL,
    created_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

`key_name` is the directory-style identity (`<subject>` for
unlabeled identities, `<subject>-<label>` for labeled ones, plus
`<subject>-ca` for CA certs).  Backs `GET /public-key/<name>`.

### 7.9 `abuseipdb` — IP-reputation cache

```sql
CREATE TABLE abuseipdb (
    idx                     SERIAL PRIMARY KEY,
    ipaddr                  TEXT NOT NULL,
    response                JSONB,
    abuse_confidence_score  INTEGER NOT NULL,
    requested_at            TIMESTAMPTZ DEFAULT now(),
    updated_at              TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX abuseipdb_ipaddr_idx ON abuseipdb (ipaddr);
```

Score thresholds: enrollment rejected at ≥ 25; all connections
rejected at ≥ 75.  TTL = 5 days.  Implementation in
`mtc_checkendpoint.c`.

---

## 8. Canonical JSON forms

### 8.1 `tbs_entry` (the TBS object inside a cert)

```json
{
  "subject":                       "example.com",
  "subject_public_key_algorithm":  "ML-DSA-87",
  "subject_public_key_hash":       "<hex>",
  "not_before":                    <unix-double>,
  "not_after":                     <unix-double>,
  "extensions":                    { "is_ca": true, ... }
}
```

`subject_public_key_hash` is `SHA-256(PEM-text-bytes)` of the
public-key PEM.  Verifiers re-hash the loaded PEM and constant-
time-compare.

### 8.2 Merkle-tree leaf serialization

`serialized` field of `mtc_log_entries`:

```
0x01   (entry_type byte)
   ||  JSON({"extensions": {...},
              "not_after":  <double>,
              "not_before": <double>,
              "spk_algorithm": "...",
              "spk_hash":   "...",
              "subject":    "..."},
            JSON_C_TO_STRING_PLAIN, alphabetical-key-order)
```

Used both for `serialized` storage and for SHA-256 leaf-hash
input: `leaf_hash = SHA-256(0x00 || serialized)`.

### 8.3 Cert wire object (what `GET /certificate/<index>` returns)

The cert as persisted in `mtc_certificates` and served to clients
is a wrapper around the standalone-certificate proper:

```json
{
  "status":                 "ok",
  "index":                  <int>,
  "standalone_certificate": { ... see below ... },
  "checkpoint": {
    "log_id":    "<log_id>",
    "tree_size": <int>,
    "root_hash": "<hex>",
    "timestamp": <unix-double>
  }
}
```

The `standalone_certificate` itself:

```json
{
  "index":           <int>,
  "tbs_entry":       { ... see §8.1 ... },
  "inclusion_proof": ["<hex>", ...],
  "subtree_start":   <int>,
  "subtree_end":     <int>,
  "subtree_hash":    "<hex>",
  "cosignatures": [
    {
      "cosigner_id":  "<log_id>.ca",
      "log_id":       "<log_id>",
      "start":        <int>,
      "end":          <int>,
      "subtree_hash": "<hex>",
      "signature":    "<9254-hex-char ML-DSA-87 sig>",
      "algorithm":    "ML-DSA-87"
    }
  ],
  "trust_anchor_id": "<log_id>"
}
```

Notes:
- `subtree_start` / `subtree_end` are duplicated inside each
  `cosignatures[]` element as `start` / `end` — the cosignature
  field set is independent of the outer cert's because it has to
  be self-contained for verification.
- `index` appears at both the top wrapper level and inside the
  standalone certificate; both refer to the same log index.
- The outer `checkpoint` is captured at issue time and reflects
  the live root that included this leaf; it's frozen alongside
  the cert.

The cosigner signature payload (per `mtc_store.c::mtc_store_cosign`):

```
"mtc-subtree/v1\n\x00"   (16 bytes incl. NUL)
||  cosigner_id          (e.g. "32473.2.ca")
||  log_id               (e.g. "32473.2")
||  start  (8 bytes BE)
||  end    (8 bytes BE)
||  subtree_hash         (32 bytes)
```

Signed by `wc_dilithium_sign_ctx_msg(NULL, 0, ...)` (no ctx
label; the prefix is part of the message).

### 8.4 Bootstrap-response signature (P0 / TODO #9b)

`ca_response_sig` payload:

```
ctx_label   = "mtc-bootstrap/v1\n\x00"   (16 bytes)
message     = json_object_to_json_string_ext(response,
                                              JSON_C_TO_STRING_PLAIN)
              with ca_response_sig field absent
```

Signed by `wc_dilithium_sign_ctx_msg(MTC_BOOTSTRAP_LABEL, 16, ...)`.

### 8.5 Strict JSON parsing

The strict-mode pipeline below applies to MQC handshake parsing
(`socket-level-wrapper-MQC/mqc_common.c`) and to the bootstrap
port's enrollment-response verifier (`bootstrap_leaf` /
`bootstrap_ca` client side).  The HTTP-API handlers in
`mtc_http.c` use plain `json_tokener_parse` for POST request
bodies — duplicate keys + unknown keys are NOT systematically
rejected on the public REST surface.  This is acceptable for
HTTP request bodies because each handler explicitly extracts the
fields it cares about and ignores the rest, but it does mean the
HTTP path lacks the depth-of-defense against duplicate-key
smuggling that the MQC handshake has.

The strict pipeline (where it applies):

1. `json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8)`
2. Length-prefixed framing — no buffer rolling, no implicit
   continuation.
3. `mqc_json_no_duplicates` — every named field appears exactly once.
4. `mqc_json_no_unknown_keys` — fields not in the allow-list reject.
5. `mqc_json_get_int_strict` — explicit `ERANGE` check, bounds
   `[min, max]` enforced.
6. Pre-crypto length filters on hex-string fields (KEM / signature
   / fingerprint sizes are exact-match before any ML-KEM or
   ML-DSA invocation).

Closes Gemini MQC-03 (ERANGE desync) and the duplicate-key
smuggling class flagged by every reviewer pass — within the
MQC handshake.  Hardening the HTTP path the same way is open
follow-up work.

---

## 9. File layout summary

| Path | Role |
|---|---|
| `~/.mtc-ca-data/ca_key_mldsa.der` | Server's ML-DSA-87 cosigner private key (DER, chmod 0600) |
| `~/.mtc-ca-data/<domain>-ca/` | CA-side enrollment workspace (keys, X.509 cert, nonce.txt) |
| `~/.mtc-ca-data/server-cert.pem` | TLS 1.3 cert for port 8444 (Let's Encrypt) |
| `~/.mtc-ca-data/server-key.pem` | TLS 1.3 private key for port 8444 |
| `~/.TPM/<subject>[-<label>][-ca]/` | Client-side identity (per-leaf or per-CA) |
| `~/.TPM/<id>/ca-cosigner.pem` | Per-leaf or per-CA pinned cosigner PEM (P0 #9b) |
| `~/.TPM/ca-cosigner.pem` | Global cosigner cache (DNSSEC-verified post-#9b) |
| `~/.TPM/default` | Symlink to the active identity dir |
| `~/.TPM/peers/<cert_index>/` | Cached MQC-peer state (cert, pubkey, cosigner-fp, revocation status) |
| `/etc/postWolf/config` | Operator-tunable knobs (Augeas-managed) |

The pre-2026-05-07 on-disk JSON mirrors
(`entries.json`, `certificates.json`, `landmarks.json`,
`revocations.json`) were retired together with file mode in
TODO #74 phase 3.  Neon is the only authoritative store.

---

## 10. Source map

| Concern | File(s) |
|---|---|
| Process entry + signal handling | `mtc_server.c` |
| TLS 8444 + MQC 8446 dispatcher | `mtc_http.c` |
| 8445 DH bootstrap | `mtc_bootstrap.c`, `mtc_bootstrap_transcript.c` |
| Merkle store (DB-backed) | `mtc_store.c` |
| Tiled Merkle tree (TODO #74 phase 3) | `mtc_merkle_tiled.{c,h}`, `mtc_tile.h`, `mtc_tile_store.h`, `mtc_tile_store_pg.c`, `mtc_tile_cache.{c,h}` |
| Legacy in-memory Merkle (rebuild tool only) | `mtc_merkle.{c,h}` |
| Cert blob LRU (TODO #74 phase 2) | `mtc_cert_cache.{c,h}` |
| Neon DB layer | `mtc_db.{c,h}` |
| AbuseIPDB cache | `mtc_checkendpoint.c` |
| Rate-limit buckets | `mtc_ratelimit.c` |
| AES-256-GCM helpers (8445) | `mtc_crypt.c` |
| CA X.509 validation | `mtc_ca_validate.c` |
| DNSSEC TXT validation | `mtc_dnssec_pin.c` |
| Domain canonicalisation | `mtc_domain.c` |
| Augeas config parser | `../read-config/read-config.{c,h}` |

The tiled-tree call surface (`mtc_tiled_tree_open` /
`_root_hash` / `_subtree_hash` / `_inclusion_proof` /
`_consistency_proof` / `_append_leaf`) is identical to the
legacy `MtcMerkleTree` API by design; callers in `mtc_http.c`
+ `mtc_bootstrap.c` + `mtc_store.c` were ported by changing
the type of the embedded tree on `MtcStore`.  Storage routing
inside the tiled tree is: level 0 → `mtc_log_entries.leaf_hash`
(via `mtc_tile_store_get_leaf_hash`); level 1..11 →
`mtc_tile_cache` LRU → `mtc_merkle_tiles`; level >= 12 →
in-RAM sorted top-K array → `mtc_merkle_top_nodes`.

The legacy `mtc_merkle.{c,h}` stays in the source tree because
the migration tool (`tools/c/mtc_rebuild_tiles.c`) loads leaves
into a legacy in-memory tree (compacting any historical gaps)
and walks it bottom-up to populate `mtc_merkle_tiles` /
`mtc_merkle_top_nodes`.  No new server-side caller of
`mtc_merkle.h` should be added — the tiled tree is the only
production path.

