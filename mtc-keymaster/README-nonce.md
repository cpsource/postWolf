# MTC Enrollment Nonces

Enrollment nonces ("tokens") are single-use, short-lived, server-issued
secrets that authorize a specific principal to submit a certificate
request.  They exist because `POST /certificate/request` is public — the
nonce is how the server decides *who* is allowed to enroll *what*.

Two flavors share one data model:

| Flavor | Who requests it | Who it's for | Domain check |
|---|---|---|---|
| **CA nonce** (`type=ca`) | A domain owner who wants to run a CA | Themselves | DNS TXT `_mtc-ca.<domain>` after the request |
| **Leaf nonce** (`type=leaf`) | The CA operator for that domain | A third party holding the private key | A registered CA for `<domain>` must already exist |

This document describes both, but the question "what format is *my* token
in?" is answered the same way for either: **64 lowercase hex characters.**

## Format

A nonce is a **256-bit random value** generated server-side by wolfCrypt's
CSPRNG (`wc_RNG_GenerateBlock`, 32 raw bytes) and serialized as
**64 lowercase hex characters**:

```
8f3c9a1b2d4e5f60112233445566778899aabbccddeeff000102030405060708
```

The hex string is the only wire form.  It is the primary key of the
`mtc_enrollment_nonces` table (see
[`README-db-schema.md`](README-db-schema.md) § `mtc_enrollment_nonces`)
and appears verbatim in every request/response that carries it.

Constants:

| Constant | Value | Defined in |
|---|---|---|
| Raw size | 32 bytes (256 bits) | `mtc_db.c:1056` |
| Wire size | 64 hex chars + NUL | `mtc_db.h` (`MTC_NONCE_HEX_LEN`) |
| TTL | 900 s (15 minutes) | `mtc_db.h:305` (`MTC_NONCE_TTL_SECS`) |

## Binding

A nonce is not interchangeable.  Every nonce row binds four fields at
issuance time, and the server checks all four during consumption:

| Field | Meaning |
|---|---|
| `nonce` | The 64-hex string itself (primary key) |
| `domain` | Subject the nonce was issued for (e.g. `factsorlie.com`) |
| `fp` | SHA-256 hex of the enrollee's ML-DSA-87 public key (the same hex that appears after `sha256:` on the wire) |
| `ca_index` | For leaf nonces, the log index of the CA that authorized it; `-1` for CA nonces |

If a later `POST /certificate/request` comes in with a matching nonce but
a different `domain` or `public_key_fingerprint`, the server rejects it.
This prevents a leaked nonce from being used to enroll a cert for a
different domain or a different key.

## State machine

```
   (none)
     │
     │  POST /enrollment/nonce         ← nonce created
     ▼
  ┌──────────┐       TTL elapses        ┌──────────┐
  │  pending │ ───────────────────────▶ │  expired │    (query filter prunes)
  └──────────┘                          └──────────┘
       │
       │  POST /certificate/request + valid (nonce, domain, fp)
       ▼
  ┌──────────┐
  │ consumed │    (terminal — cannot be reused)
  └──────────┘
```

Implementation notes:
- Expiry is enforced by the query `WHERE … expires_at > now()` in
  `mtc_db.c`.  Rows older than TTL are never returned to consumers but
  remain in the table until manually cleaned.
- Consumption is a single SQL `UPDATE mtc_enrollment_nonces SET status
  = 'consumed' …` (`mtc_db.c:1234`), gated on `status = 'pending' AND
  expires_at > now()`.  Race-free: two concurrent enrollments cannot
  both consume the same row.
- The `(domain, fp)` pair can have at most one `pending` row at a time
  — a duplicate request while one is outstanding gets `409 Conflict`
  ("pending enrollment already exists for this domain and key").

## Issuing a nonce

### HTTP

**Endpoint:** `POST /enrollment/nonce` (same endpoint for CA and leaf,
differentiated by `type`)

**Request body** (leaf example — omit `type` or set `type=ca` for a CA
nonce):

```json
{
  "domain": "example.com",
  "public_key_fingerprint": "sha256:8a1b2c…",
  "type": "leaf"
}
```

The `sha256:` prefix on `public_key_fingerprint` is optional on the
wire; the server strips it before hex validation (`mtc_http.c:550`).

**Response** (HTTP 200):

```json
{
  "nonce":    "8f3c9a1b2d4e5f60112233445566778899aabbccddeeff000102030405060708",
  "expires":  1744918234,
  "type":     "leaf",
  "ca_index": 17
}
```

- `expires` is a Unix timestamp (seconds), not a TTL.  It equals
  `issued_at + 900`.
- `ca_index` appears only on leaf nonces and points at the CA that
  authorized the issuance.

### Tooling

For the common case of a CA operator issuing a leaf nonce:

```bash
cd ~/postWolf/mtc-keymaster/tools/python
python3 issue_leaf_nonce.py \
    --domain example.com \
    --key-file /path/to/leaf-pubkey.pem \
    --server https://localhost:8444
```

The script:
1. Computes `SHA-256(pubkey PEM text)` to produce the fingerprint.
2. POSTs to `/enrollment/nonce` with `type=leaf`.
3. Saves the returned nonce to `~/.mtc-ca-data/<domain>/nonce.txt`.
4. Prints the command the leaf holder should run next.

`bootstrap_ca.c` carries the equivalent flow for CA nonces (which
additionally require the caller to publish a DNS TXT record —
documented in `README.md`).

### Server-side checks at issuance

Before inserting the pending row, `handle_enrollment_nonce`
(`mtc_http.c:510`) verifies:

1. Body is valid JSON with `domain` and `public_key_fingerprint`
   present.
2. Fingerprint is exactly 64 hex characters (after stripping
   `sha256:`).
3. Rate limit window for the caller's IP has room
   (`mtc_ratelimit_check` — see Rate limits below).
4. For leaf nonces, a registered CA exists for the domain
   (`mtc_db_find_ca_for_domain`).  Without this, any third party could
   preauthorize their own leaf for any domain — the CA-first rule is
   what prevents that.
5. No `pending` nonce is already outstanding for `(domain, fp)`.

## Consuming a nonce

The leaf holder sends the nonce verbatim in the `enrollment_nonce`
field of `POST /certificate/request`:

```json
{
  "subject":              "example.com",
  "public_key":           "-----BEGIN PUBLIC KEY-----…",
  "signature":            "…",
  "enrollment_nonce":     "8f3c9a1b2d4e5f60…060708"
}
```

`bootstrap_leaf.c` handles this automatically; it reads the nonce from
`~/.mtc-ca-data/<domain>/nonce.txt` (or `--nonce <hex>` on the command
line — see `bootstrap_leaf.c:680` for the JSON field construction).

At consumption the server re-checks binding: the request's subject must
equal the nonce's `domain`, and `SHA-256(public_key_der)` must equal
the nonce's `fp`.  Either mismatch → `400 Bad Request` / `403 Forbidden`
and the nonce stays `pending` (no state change on failure).

## Rate limits

Enrollment nonce issuance is rate-limited by source IP through
`mtc_ratelimit.c`:

| Nonce type | Per minute | Per hour | Bucket |
|---|---|---|---|
| CA | 3 | 10 | `RL_NONCE_CA` |
| Leaf | 10 | 100 | `RL_NONCE_LEAF` |

Exceeding the limit returns `429 Too Many Requests`.  Leaf limits are
looser because a single CA operator may legitimately provision many
leaves in quick succession during a rollout.

## Error responses

| HTTP code | Condition |
|---|---|
| 400 | Malformed JSON, missing field, non-hex or non-64-char fingerprint |
| 403 | Leaf request where no CA is registered for the domain |
| 409 | A `pending` nonce already exists for `(domain, fp)` — wait for TTL or consume it |
| 429 | Rate limit exceeded for this IP |
| 500 | CSPRNG or DB write failure |
| 503 | Database connection unavailable |

Consumption-side errors (wrong subject, wrong fingerprint, expired
nonce) surface at `POST /certificate/request`, not here.

## Security properties

- **Server-gated authorization.**  Clients cannot mint their own nonce;
  the server is the only source.  This is the point of the nonce — any
  holder of a valid pending nonce has been pre-authorized, and forgery
  would require breaking wolfCrypt's CSPRNG.
- **Single-use.**  A `consumed` nonce cannot be replayed.  The
  `status = 'pending'` filter in the consumption `UPDATE` enforces it
  at the database level, not application level.
- **Short TTL.**  15 minutes narrows the window for a leaked nonce to be
  exploited.  Set at 900 s to give operators time to hand off the
  nonce and run `bootstrap_leaf` without being so long that a stolen
  nonce is durable.
- **Bound to domain + key fingerprint.**  A nonce cannot be redirected:
  swapping the subject or the key DER at consumption time fails the
  fingerprint check.  The CA-for-domain requirement adds an outer
  authorization boundary for leaves.
- **No trust in the caller.**  Fingerprint format is validated (length
  + hex only, `mtc_http.c:552`), the JSON body is parsed in isolation,
  and the IP-based rate limit precedes any DB work.

## Related

- `README-db-schema.md` § `mtc_enrollment_nonces` — table definition.
- `README.md` § Enrollment — CA and leaf flows end to end.
- `README-bugsandtodo.md` #3 and #4 — background on why nonces exist
  (they were added to close the "anyone can enroll a leaf" hole).
- Source:
  - `mtc-keymaster/server/c/mtc_http.c` — `handle_enrollment_nonce` (issue)
  - `mtc-keymaster/server/c/mtc_db.c` — `mtc_db_create_nonce` (issue), consumption logic
  - `mtc-keymaster/server/c/bootstrap_leaf.c` — nonce consumption on the client
  - `mtc-keymaster/tools/python/issue_leaf_nonce.py` — CA operator helper
