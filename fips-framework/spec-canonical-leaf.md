# spec-canonical-leaf v1

## Status

Frozen 2026-05-08.  Any change to this document is a flag-day
protocol-version bump (`schema_version` increment) and requires a
coordinated cutover of `fips-manifest-submit`, `fips-manifest-verify`,
and the server-side `POST /fips/manifest` validator.

## Purpose

Defines the canonical bytes that constitute a FIPS-manifest leaf in
the MTC transparency log.  These bytes are:

1. The thing the publisher signs with its ML-DSA-87 leaf key.
2. The thing the server hashes for the Merkle leaf.
3. The thing the verifier reconstructs to check both signatures.

The format is parallel to the existing cert-leaf format
(`entry_type=0x01`); FIPS manifests use `entry_type=0x02`.

## Wire format

A log entry is a contiguous byte string:

```
entry_bytes := 0x02 || canonical_json_text
```

where `canonical_json_text` is the UTF-8-encoded JSON form defined
below (no BOM, no leading/trailing whitespace).  No length prefix:
the byte count is whatever the storage layer records.

The Merkle leaf hash follows RFC 6962:

```
leaf_hash := SHA-256( 0x00 || entry_bytes )
```

This matches the construction already used by `mtc_hash_leaf` for
cert leaves (`mtc-keymaster/server2/c/mtc_merkle.c`).

## Canonical JSON

Hard rules (server MUST reject otherwise):

- **UTF-8.**  No BOM.
- **Object keys sorted lexicographically by codepoint** (`LC_ALL=C`-style
  byte order on the unescaped key string).
- **No whitespace** between tokens.  `{"a":1,"b":2}`, never
  `{ "a" : 1, "b" : 2 }`.
- **No trailing newline.**
- **Strings:** UTF-8.  Only the escapes `\"`, `\\`, `\b`, `\f`,
  `\n`, `\r`, `\t`, and `\uXXXX` are accepted.  Forward-slash escape
  `\/` is rejected (no spec extension); literal `/` is required.
- **Numbers:** integers use no leading zeros, no leading `+`, no
  trailing `.0`; floats use exactly one `.` with at least one digit
  on each side, no exponent form.  No `NaN`, no `Infinity`.  This
  matches the conservative shape already produced by
  `json_object_to_json_string_ext(..., JSON_C_TO_STRING_PLAIN)`
  in the server when sort+strip-whitespace is applied.
- **No duplicate keys** anywhere (top-level or nested).
- **No unknown keys** at any level.  Strict-parse rejection.
- **Arrays:** elements appear in the order specified below; for
  `files`, that order is alphabetical by `path`.

These rules mirror the strict-parse posture in MQC spec §5.2 and
§12.10 (project CLAUDE.md "Strict JSON parsing" entry) so the same
mental model applies at every JSON boundary in the system.

## Top-level fields

All fields are REQUIRED unless marked OPTIONAL.  Length and value
limits are checked before any signature validation runs (matches
the §12.6 "Pre-crypto length filter" pattern).

| Key | Type | Limit | Description |
|---|---|---|---|
| `alg` | string | exact `"ML-DSA-87"` | Signature algorithm.  Locked to ML-DSA-87 in v1; future PQ algorithms require a `schema_version` bump. |
| `expires` | float | `not_before <= expires <= not_before + 31536000.0` (1 year) | Unix epoch seconds.  After this instant the manifest MUST be rejected by verifiers. |
| `files` | array | `1 <= len(files) <= 65535` | See "Files array" below. |
| `git_commit` | string | OPTIONAL.  When present: 40-char or 64-char lowercase hex; OPTIONAL `-dirty` suffix. | Forensic anchor.  Submitter MAY refuse to submit dirty manifests; server accepts either form. |
| `not_before` | float | `not_before > 0`, `not_before < expires` | Unix epoch seconds.  Before this instant the manifest is not yet valid. |
| `package` | string | `1..64` chars, regex `^[A-Za-z0-9._-]+$` | Package identifier.  Stable across versions of the same package. |
| `publisher` | string | `1..253` chars, lowercase ASCII LDH per RFC 1035 (no IDN, no wildcards, no leading/trailing dot, no underscore-prefixed labels) | The cert subject.  MUST match the subject of the cert at `publisher_cert_index`. |
| `publisher_cert_index` | integer | `0..2147483647` (signed 32-bit, matches DB column) | Index in `mtc_log_entries` of the publisher's leaf cert.  The cert at this index MUST: (a) have entry_type 1, (b) have subject equal to `publisher`, (c) be cosigned by the current cosigner, (d) not appear in `mtc_revocations`. |
| `schema_version` | integer | exact `1` | This document.  Bumping is a flag-day cutover. |
| `signature` | string | base64 (RFC 4648 §4, no URL-safe variant, no padding optional, exact 6128 chars including `=`) | ML-DSA-87 signature over the canonical bytes with `signature` set to the empty string.  See "Signature input rule" below. |
| `version` | string | `1..64` chars, regex `^[A-Za-z0-9._+~-]+$` | Package version.  No semver enforcement; opaque to the server. |

## Files array

Each element is an object with exactly these keys (no extras):

| Key | Type | Limit |
|---|---|---|
| `path` | string | `1..512` bytes UTF-8.  Forward slashes only.  No `\\`, no leading `/`, no `.` or `..` segments, no embedded NUL.  Must be normalized (no `//`, no trailing `/`). |
| `sha256` | string | exact 64 lowercase hex chars |

Order constraint: `files` MUST be sorted alphabetically by `path`
using byte order (`LC_ALL=C` sort).  Server MUST reject unsorted or
non-unique paths.

## Signature input rule

The signature covers the canonical-JSON bytes of the *same* object
with the `signature` field set to the empty string `""`.  Concretely:

```
signing_input := canonical_json( manifest with signature := "" )
sig          := MLDSA87_sign( publisher_priv_key, signing_input )
manifest.signature := base64( sig )
final_bytes  := 0x02 || canonical_json( manifest )
```

Two boundary properties this produces:

- **Self-contained verify.**  The verifier strips `signature`, sets it
  to `""`, recomputes the canonical bytes, and feeds those into
  `MLDSA87_verify` with the publisher's pubkey.  No out-of-band
  context.
- **Identical sort order.**  Because the placeholder is `""`, not
  absent, the field count and key order in `signing_input` matches
  the final form exactly.  No sort drift.

The signature is computed using **pure ML-DSA-87** (FIPS 204
deterministic-or-randomized signing over the message bytes).  No
external pre-hash; SHAKE-256 absorbs the message internally.  This
matches the `openssl40 pkeyutl -sign -rawin` invocation already used
by `tools/sh/sign-dir.sh`.

## Server-side validation order

A `POST /fips/manifest` handler MUST run these checks in order, abort
on the first failure, and return 400 (or 403 for revocation) without
disclosing which check failed beyond the necessary minimum:

1. **Pre-crypto length filter.**  Reject if `body.len > 16 MiB` or
   any field exceeds its limit above.  No JSON parse yet.
2. **Strict JSON parse.**  Per "Canonical JSON" rules.  Reject on
   any extension, duplicate key, unknown field, malformed UTF-8,
   non-canonical number form.
3. **Re-canonicalize and byte-compare.**  Server reserialises the
   parsed object (with `signature=""`) and confirms the result is
   what the client sent (modulo the signature field).  Defends
   against canonicalization disagreements.
4. **Cert lookup.**  Load `mtc_log_entries` row at
   `publisher_cert_index`.  Reject if absent, wrong entry_type,
   subject mismatch, or in `mtc_revocations`.
5. **Cert cosignature freshness.**  Confirm the cert is in the
   current cosigned tree (subtree_end >= cert_index, cosignature
   verifies under the current cosigner pub key).
6. **Manifest signature verify.**  ML-DSA-87 verify of the
   `signature` field against the recomputed `signing_input` under
   the cert's `spk_hash`-bound public key.
7. **Time bounds.**  Server clock is in `[not_before-300s,
   expires+0s]` (300-second backward skew tolerance, no forward
   slack).
8. **Append.**  `mtc_store_add_entry` with
   `entry_type=2, entry=0x02 || canonical_json`.  Wraps the existing
   `pg_advisory_xact_lock` per spec §11.6.
9. **Receipt.**  Return `{leaf_index, leaf_bytes_b64,
   inclusion_proof[], tree_size, tree_root, cosignatures[]}` per
   `README-implement.md`.

## Verifier-side check order

`fips-manifest-verify` receives a receipt + a source dir + a trusted
cosigner public-key fingerprint (DNSSEC-pinned in the deployed flow,
local file in dev).  Order:

1. **Strict-parse the receipt and the embedded canonical leaf.**
2. **Cosignature.**  Verify each `cosignatures[].sig` over
   `(tree_size, tree_root)` under the trusted cosigner pubkey.
   Reject on no valid cosignature.
3. **Inclusion proof.**  Replay the proof from `leaf_hash` to
   `tree_root`; reject on mismatch.
4. **Manifest signature.**  Fetch the publisher cert (or accept it
   if the receipt embeds enough — out of scope for v1).  Verify the
   manifest signature as in server step 6.
5. **Time bounds.**  Local clock is in `[not_before-300s, expires]`.
6. **File hashes.**  For every entry in `files`, recompute the
   on-disk SHA-256 and compare.  Reject on any mismatch, missing
   path, or extra path not in the manifest.

## Open issues / explicitly deferred

- **Witness cosignatures** (split-view freshness) — TODO 8 in
  `README-fips-todo.md`.  v1 receipts may carry only the primary
  log cosigner.  v2 will require ≥1 witness as a verify rule.
- **TUF Snapshot / Timestamp roles** — `FIPS.md` Appendix A.
  Single-publisher is fine for v1; a TUF-style role split is a v2+
  concern.
- **`extensions` field** — left out of v1 deliberately.  Adding it
  later is a v2 concern (and a flag-day cutover); meanwhile, anyone
  needing per-package metadata must encode it in `package` or
  `version` strings.
- **Compressed file lists** — at 65535 files × 64 hex + path the
  manifest can grow.  v1 keeps the inline list; v2 may add
  `files_root_hash` + a separate fetchable file-tree proof.

## Conformance test vectors

Will be added under `fips-framework/test-vectors/canonical-leaf/`
when `fips-manifest-submit --dry-run` lands (next deliverable in
`README-implement.md`).  At minimum:

- minimal valid manifest (1 file, no `git_commit`)
- maximal valid manifest (65535 files, `git_commit` with `-dirty`)
- canonical-form negative cases (unsorted keys, whitespace,
  duplicate keys, trailing newline, `\/` escape, leading `+` on
  number, exponent form, `NaN`)
- signature negative cases (signed with a non-publisher key,
  signed with `signature` populated rather than empty)
- file-list negative cases (unsorted, duplicate path, `..` segment,
  embedded NUL, path > 512 bytes)

Each vector is a directory with `manifest.json` (the canonical
bytes) plus a `verdict.txt` (`ACCEPT` or one of the rejection
reasons in §"Server-side validation order").

## Manifest revocation

Once a manifest is appended at `log_index N`, two parties may
revoke it:

- The **publisher** itself (the leaf identity at the manifest's
  `publisher_cert_index`) — self-revoke for "I'm pulling back this
  release".
- That publisher's **CA** (subject ends in `-ca`, leaf in CA's
  domain) — for compliance / takedown.

Both paths use the same wire envelope; the `revoker_kind` field
selects the auth branch.

### Wire envelope (`POST /fips/revoke`)

```json
{
  "log_index":          <int>,
  "revoker_kind":       "publisher" | "ca",
  "revoker_cert_index": <int>,
  "reason":             "<string, ≤256 chars>",
  "timestamp":          <unix epoch int>,
  "public_key_pem":     "-----BEGIN PUBLIC KEY-----\n...",
  "signature":          "<lowercase hex of ML-DSA-87 sig>"
}
```

### Signing input

ML-DSA-87 over the raw bytes of:

```
fips-revoke:<revoker_kind>:<revoker_cert_index>:<log_index>:<reason>:<timestamp>
```

Field separators are literal `:`; reasons containing `:` are
ambiguous on the wire and rejected by the ≤256-char + JSON-strict
checks at the request layer.

### Server-side validation order

1. Strict JSON parse (reject unknown fields, non-object body,
   oversized body — pre-DB filter).
2. Freshness window ±300s on `timestamp`.
3. `mtc_fips_manifest_entries` row at `log_index` MUST exist.
4. `mtc_log_entries.tbs_data->>'publisher_cert_index'` recovered
   for the manifest leaf.
5. Revoker cert at `revoker_cert_index` MUST exist with
   `entry_type=1` and `spk_algorithm = ML-DSA-87`.
6. Authority branch:
   - `publisher`: `revoker_cert_index` MUST equal the manifest's
     `publisher_cert_index`.
   - `ca`: revoker subject ends in `-ca`; manifest's publisher cert
     subject MUST equal the derived CA domain or end in `.<ca-domain>`
     (same rule as `/revoke`).
7. `sha256(public_key_pem) == revoker.spk_hash` (defends against
   PEM-substitution).
8. `wc_dilithium_verify_ctx_msg(NULL, 0, ...)` over the signing
   input above (pure mode, no context).
9. INSERT one row into `mtc_fips_manifest_revocations`.

### Storage invariant

Revocations are **DB-only**, not appended to the merkle log —
identical posture to cert revocation (`mtc_revocations`).  Multiple
rows per `log_index` are allowed; "revoked" means at least one row
exists, mirroring the cert-revoke idempotency contract.

### Verifier integration (opt-in)

`fips-manifest-verify --check-revocation` is offline-by-default
to preserve the receipt-only audit story.  When set, between
stage 5 (time bounds) and stage 6 (file hashes) the verifier opens
MQC and queries:

- `GET /fips/revoked/<log_index>` — manifest-level revocation
- `GET /revoked/<publisher_cert_index>` — publisher cert revocation

Either reporting revoked aborts the verify with non-zero exit.
Transport / parse failures fail-closed (also non-zero).
