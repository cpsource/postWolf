# fips-framework — implementation plan from local manifest to server-cosigned receipt

Connects the local tamper-evidence layer (`tools/sh/sign-dir.sh` +
`MANIFEST.sha256` + `MANIFEST.sig`, established 2026-05-08, commits
`7f34fe636` … `3e7d7799b`) to the server-side transparency-log layer
that's still mostly TODO.  Read this alongside:

- `README.md` — original user-facing tool spec (some Ed25519 / 32-byte
  pubkey references are stale; TODO 25 is the sweep)
- `FIPS.md` — three-layer trust-chain rationale
- `README-fips-todo.md` — master worklist (this doc references TODO
  0c, 10, 14, 16, 25, 27)
- `README-discussions.md` — threat-model Q&A on MitM and the
  signing-scheme trust posture

## Layered picture: what's local vs what's server-side

| Layer | What we have now | What's still missing |
|---|---|---|
| **Per-file integrity** | `MANIFEST.sha256` (recursive SHA-256 + `# git-commit:` anchor) | nothing — done |
| **Authorship binding** | `MANIFEST.sig` — ML-DSA-87 over the manifest by the local key in `fips-keys/` | Make the *publisher* identity that key — i.e., have it cosigned by the MTC CA's leaf cert (TODO 16 + TODO 25) |
| **Transparency / freshness** | nothing | Submit to a Merkle log on the server; receive an inclusion proof + cosigner signature (the *receipt*); ship the receipt with the kit (TODO 0c + 10 + 14) |
| **Verifier's offline check** | nothing yet | `fips-manifest-verify` reads receipt + source dir, replays inclusion proof, checks cosigner sig under DNSSEC-pinned key (TODO 27 server side, TODO 25 sweep Ed25519→ML-DSA-87 in docs) |

## What the server stores

One row per submitted manifest, in a new `mtc_fips_manifest_entries`
table parallel to the existing `mtc_log_entries` (cert log).  Each
row holds the **canonical-JSON leaf bytes** — that's the durable
artifact, byte-identical to what got hashed into the Merkle tree.
Schema sketch:

```sql
CREATE TABLE mtc_fips_manifest_entries (
    index        BIGSERIAL PRIMARY KEY,
    leaf_hash    BYTEA NOT NULL,        -- SHA-256 of the canonical leaf bytes
    leaf_bytes   BYTEA NOT NULL,        -- the canonical JSON envelope below
    publisher    TEXT  NOT NULL,        -- subject string from the leaf cert
    package      TEXT  NOT NULL,        -- e.g. "postWolf"
    version      TEXT  NOT NULL,        -- e.g. "v5.9.0"
    submitted_at TIMESTAMPTZ DEFAULT now()
);
```

Plus the existing log infrastructure (Merkle tiles + signed
checkpoints) handles the inclusion-proof + cosigner-signature side;
the phase-2/3 tiled-tree work already paid for that.

## What the publisher submits (canonical leaf bytes)

A single JSON object — sorted keys, no whitespace, UTF-8 — that
envelopes the manifest plus identity metadata:

```json
{
  "alg": "ML-DSA-87",
  "expires": "2026-08-08T00:00:00Z",
  "files": [
    {"path":".gitignore","sha256":"a8e28ec..."},
    {"path":"FIPS.md","sha256":"410137f0..."}
  ],
  "git_commit": "8a285a547aa7cb532a04f3a0c308c1e7e6d19302",
  "package": "postWolf",
  "publisher": "factsorlie.com",
  "publisher_cert_index": 72,
  "signature": "<base64 ML-DSA-87 sig over this object minus the signature field>",
  "version": "v5.9.0"
}
```

Where the body of `MANIFEST.sha256` becomes the `files[]` array
(parsed back into structured form), `# git-commit:` becomes
`git_commit`, and the signature is computed with `signature` field
absent or set to empty string (canonical-form trick already used in
the MTC cert format).

The `publisher_cert_index` is the leaf cert's index in the existing
**cert log** (the `mtc_log_entries` table) — that's the bridge from
"anyone with an ML-DSA-87 key" to "an authorized publisher whose key
is cosigned and DNSSEC-pinned".  Without it, the server has nothing
to authorize against.

## What the receipt looks like

Server returns one JSON object the verifier keeps with the kit:

```json
{
  "leaf_index": 42,
  "leaf_bytes_b64": "<base64 of the canonical leaf above>",
  "inclusion_proof": ["<sibling_hash_1>", "<sibling_hash_2>"],
  "tree_size": 43,
  "tree_root": "<root_hash>",
  "cosignatures": [
    {"key_id":"<cosigner_fp>","sig":"<base64 ML-DSA-87 over (tree_size,tree_root)>"}
  ]
}
```

Verifier needs **only** this file + the trusted cosigner key
fingerprint (DNSSEC-pinned) + the source dir.  No live server
contact required for offline verification.

## What this would actually cost to build

Three deliverables, in order:

1. **Server endpoint** `POST /fips/manifest` (TLS 8444) and the same
   over MQC (8446).  Validates publisher leaf cert is in the cert
   log + cosigned + not revoked + signature on the envelope is
   correct under that cert's key.  Appends to
   `mtc_fips_manifest_entries`.  Returns the receipt.  Rough
   estimate: ~400 lines of `mtc_http.c` glue + a new file
   `mtc_fips_manifest.c` for the validation logic.

2. **`fips-manifest-submit` client** that:
   - reads `MANIFEST.sha256` + the publisher's `cert_index` (from
     local `~/.TPM/`),
   - reformats into the canonical JSON envelope,
   - signs with the publisher's ML-DSA-87 leaf key,
   - POSTs over MQC,
   - saves the receipt next to the kit.

3. **`fips-manifest-verify` client** that:
   - reads the receipt,
   - recomputes file SHA-256s and matches against `files[]`,
   - replays the Merkle inclusion proof against `tree_root`,
   - verifies the cosigner signature under the DNSSEC-pinned key.

The README.md and FIPS.md *plans* exactly this, but they still talk
about Ed25519 + 32-byte CA pubkey.  TODO 25 captured that sweep;
the actual code should be ML-DSA-87 end-to-end since that's what
the rest of the system uses now.

## Recommendation for the next slice

Start with the **canonical-leaf schema** (TODO 14) and freeze it
before any C goes in — once submitted leaves exist on the server
they're hard to migrate.  Concretely:

1. Write `fips-framework/spec-canonical-leaf.md` defining the JSON
   shape, sort order, signature-input rule (which field to omit),
   and length limits.
2. Then `fips-manifest-submit.c` to *build* a canonical leaf locally
   (no network yet) — call it with `--dry-run` and dump the bytes.
   This lets us validate the schema by round-tripping through
   parse/canonicalize/sign/verify before any wire protocol exists.
3. Then the server endpoint.
4. Then `fips-manifest-verify.c`.

## What stays out of this work

- **Wire formats already frozen.**  MQC protocol byte layout, MTC
  cert format, cosigner-signature input bytes — none of those change
  for fips-manifest support.  We're adding a new leaf type to the
  log infrastructure, not modifying existing ones.
- **TUF Snapshot / Timestamp roles** (per FIPS.md Appendix A) —
  punt to a later phase.  The first cut is targets-only.
- **Witness cosignatures** for split-view freshness (TODO 8) —
  defer to Phase 4 of the README-fips-todo roadmap.  This phase is
  cosigner-only.
