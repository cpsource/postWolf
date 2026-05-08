# FIPS Integrity System — TODO

## Priority 0: Code TODOs (in-tree)

### 0a. MTC verification during TLS handshake
**File:** `socket-level-wrapper/slc.c:273`

`slc_connect` and `slc_accept` need to verify the peer's certificate against
the MTC Merkle tree when MTC is configured (`slc_ctx_set_mtc` was called).
Currently stubbed — TLS 1.3 cert chain validation works, but the Merkle proof
+ Ed25519 cosignature checks are not yet wired in.

**What's needed:**
1. Hash the peer cert's subject key ID after TLS handshake completes
2. Query MTC server: `GET /certificate/search?subject_key_hash=<hash>`
3. Retrieve inclusion proof for the leaf
4. Replay Merkle proof (hash chain from leaf to root)
5. Verify Ed25519 cosignature against `ctx->ca_pubkey` using `wc_ed25519_verify_msg()`
6. Check revocation: `GET /revoked/<index>`
7. Reject connection if any step fails

**Depends on:** FIPS framework tools being functional (same verification logic).

### 0b. Pin actual CA public key
**File:** `fips-framework/config/ca-pubkey.h:20`

The placeholder is 32 zero-bytes. Replace with the real CA Ed25519 public key
exported from `~/.mtc-ca-data/ca_key.der`.

**How:**
```bash
# Extract public key from the DER private key
openssl35 pkey -in ~/.mtc-ca-data/ca_key.der -inform DER -pubout -outform DER | \
    tail -c 32 | xxd -i
```

Then paste the bytes into `ca-pubkey.h`.

---

## Priority 1: Easy Wins (add now)

### 1. Manifest `expires` field
Add an `expires` timestamp to the FIPS build manifest. Verifiers reject
kits whose manifest has expired, preventing stale kits from being accepted
indefinitely.

**Changes:**
- `fips-manifest-submit.sh`: add `"expires": "<timestamp>"` to manifest JSON
  (default: 1 year from build time, configurable)
- `fips-manifest-verify.sh`: check `expires` against current time, fail if past
- `mtc_http.c` (`handle_fips_manifest_submit`): validate `expires` field if present
- `README-fips.md`: document the field and its default

### 2. Version rollback detection
Prevent an attacker from replaying an older (but valid) signed manifest for
the same package. The verifier should reject a manifest whose version is
older than one it has previously accepted.

**Changes:**
- `fips-manifest-verify.sh`: maintain a local state file
  (`~/.config/mtc-fips/last-verified.json`) recording the highest accepted
  version per package
- On verify, compare manifest `git_tag` / `version` against last-accepted;
  warn or fail if older
- `README-fips.md`: document rollback detection behavior and override flag
  (`--allow-rollback` for legitimate downgrades)

### 3. Self-contained kit bundle
Formalize what ships inside the release tarball so verification needs nothing
but the pinned root CA key. Currently `fips-manifest-receipt.json` is shipped
but the publisher's leaf cert and CA chain are not.

**Bundle layout:**
```
kit.tar.gz
  source files
  fips-manifest-receipt.json    (manifest + inclusion proof + cosignature)
  fips-publisher.crt            (leaf cert that signed this manifest)
  fips-chain.pem                (intermediate certs up to but not including root)
```

**Changes:**
- `fips-manifest-submit.sh`: copy `publisher.crt` and `chain.pem` into the
  build directory alongside the receipt
- `Makefile.am` / `EXTRA_DIST`: include `fips-publisher.crt` and `fips-chain.pem`
- `fips-manifest-verify.sh`: if `--offline`, verify cert chain from bundled
  certs + pinned root CA key (no server contact needed for cert lookup)
- `README-fips.md`: document the bundle layout and cert chain verification step

---

## Priority 2: TUF Roles (defer until core is deployed)

### 4. Timestamp role (freeze attack protection)
A short-lived signed token that says "as of time T, the latest manifest for
package X is index N." Prevents a compromised server from withholding newer
releases while serving stale-but-valid ones.

**Design:**
- New key pair: Timestamp key (short-lived, rotated frequently)
- New endpoint: `GET /fips/timestamp/<package>` returns signed
  `{package, latest_index, signed_at, expires}` with ~24h expiry
- Verifier (online mode): fetch timestamp, confirm the manifest index is
  not older than what the timestamp claims is current
- Verifier (offline mode): skip (timestamp is inherently online)

**Changes:**
- `mtc_store.h`: add timestamp key pair to `MtcStore`
- `mtc_http.c`: add `handle_fips_timestamp()` endpoint
- `mtc_store.c`: add timestamp key generation/rotation
- `fips-manifest-verify.sh` (online mode): fetch and check timestamp
- `README-fips.md`: document timestamp verification

### 5. Snapshot role (mix-and-match protection)
A signed snapshot listing all current package versions, preventing an attacker
from combining files from different valid releases into an inconsistent kit.

**Design:**
- New key pair: Snapshot key
- New endpoint: `GET /fips/snapshot` returns signed
  `{packages: [{name, latest_index, git_tag}, ...], signed_at}`
- Verifier: confirm the manifest index for this package matches the snapshot
- Useful when multiple packages or components are released together

**Changes:**
- `mtc_store.h`: add snapshot key pair to `MtcStore`
- `mtc_http.c`: add `handle_fips_snapshot()` endpoint
- `mtc_store.c`: add snapshot generation on each manifest submission
- `fips-manifest-verify.sh`: optionally fetch and verify snapshot
- `README-fips.md`: document snapshot verification

**Note:** Snapshot is most valuable when the system manages multiple packages
or multi-component releases. For a single-package system (postWolf only),
the Timestamp role provides most of the freeze protection value. Implement
Snapshot if/when the system expands to multiple packages.

### 6. Scoped delegation (TUF-style)
> **Subsumes** ChatGPT review P1 ("publisher authorization is
> underspecified") and Addition #6 ("namespace authorization
> table"); see `README-fips-chatgpt-issues.md`.

Currently any valid leaf cert can sign a manifest for any package name. TUF's
delegation model allows scoping authority: "Key A may only sign packages
matching `wolfssl-*`." This prevents a compromised leaf from signing manifests
for packages outside its authority.

**Design:**
- Add a `scope` field to the leaf certificate's MTC log entry at enrollment
  time. The scope is a list of package name patterns (e.g., `["wolfssl-*"]`).
- At verification time, the verifier checks that the manifest's `package`
  field matches at least one pattern in the signing leaf's `scope`.
- If the leaf has no `scope` field, it is unrestricted (backward compatible).

**Changes:**
- `mtc_http.c` (`handle_certificate_request`): accept optional `scope` array
  in the leaf enrollment request; store in the log entry
- `fips-manifest-verify.sh`: after verifying the cert chain, fetch the leaf's
  log entry and check that `package` matches the leaf's `scope`
- `README-fips.md`: document scoped delegation

**Future extensions (defer further):**
- **Threshold signing**: require N-of-M leaf keys to co-sign a manifest
  (useful for high-value releases)
- **Chained delegation**: allow a leaf to sub-delegate authority to another
  key without going back to the CA (useful for build bots)

### 7. GPG keyserver cross-signing of CA public key
The CA Ed25519 public key is the single most important trust anchor. Currently
all channels that publish it (DNS TXT, server endpoint, source code) are
controlled by the same entity. An attacker who compromises that entity can
replace the CA key everywhere.

Publishing a GPG-signed statement of the CA key to an independent keyserver
adds a second trust path the attacker cannot control.

**Design:**
- Publish Cal Page's GPG key (`E9C059EC0D3264FAB35F94AD465BF9F6F8EB475A`)
  to `keys.openpgp.org`
- Create a signed cleartext statement binding the CA Ed25519 public key to
  the GPG identity:
  ```
  I, Cal Page (E9C059EC...), certify that the MTC CA Ed25519 public key
  for factsorlie.com is: <32 bytes hex>
  ```
- Publish the signed statement (e.g., in the git repo, project website, or
  as a keyserver notation)
- `fips-manifest-verify` (optional flag `--verify-gpg`): fetch GPG key from
  keyserver, verify the signed statement, compare CA key against what the
  server claims

**Trust channels after this change:**

| Channel | Controlled By | What It Pins |
|---------|--------------|--------------|
| DNS TXT | Domain registrar | CA public key |
| GPG keyserver | Third party (openpgp.org) | CA key, signed by GPG identity |
| Source code | Git repo | CA key in `ca-pubkey.h` |
| Git signed tag | Git + GPG keyserver | Commit hash + CA key |

Two independent channels agreeing on the same key is much harder to forge
than one.

**Prerequisites:**
- Upload GPG key: `gpg --keyserver keys.openpgp.org --send-keys E9C059EC0D3264FAB35F94AD465BF9F6F8EB475A`
- See `README-keyserver.md` for current keyserver status

---

## Priority 3: ChatGPT review triage (2026-05-08)

[`README-fips-chatgpt-issues.md`](./README-fips-chatgpt-issues.md)
is a fresh external review of the FIPS-framework design with 9
numbered concerns (P0 / P1 / P2) plus a 10-item "Additions I
would require" list.  Triage below — every item that doesn't
already collapse into an existing TODO becomes its own numbered
entry.  Verdicts:

| ChatGPT row | Verdict | Lands as |
|---|---|---|
| P0 #1 — receipt freshness / split-view | **AGREE** — biggest open gap | TODO 8 |
| P0 #2 — define what "FIPS mode" means | **AGREE** — pure terminology + doc | TODO 9 |
| P0 #3 — manifest must bind more than file hashes | **AGREE** — current schema underspecified | TODO 10 |
| P1 #4 — publisher authorization underspecified | **SUBSUMED** by item **6** (scoped delegation, TUF roles) | item 6 cross-ref added |
| P1 #5 — "latest tag" ambiguity | **AGREE** — policy decision needed | TODO 11 |
| P1 #6 — offline revocation/staleness policy | **AGREE** — partial overlap with item 1 (`expires`) but adds revocation + max-age semantics | TODO 12 |
| P1 #7 — SHA-256 vs PQ story / dual hashes | **PARTIAL AGREE** — defensible as written; dual-hash is defense-in-depth | TODO 13 |
| P2 #8 — canonicalization risk | **AGREE** — JCS / canonical CBOR is the standard fix | TODO 14 |
| P2 #9 — build system trust remains | **AGREE** — cross-cuts master TODO #8 (compiler integrity) | TODO 15 |
| Addition #1 — manifest signature by leaf key | **AGREE** — distinct from log signature | TODO 16 |
| Addition #2 — log signature over checkpoint | **SUBSUMED** by `[ISSUE #1]` (online log key + offline CA-checkpoint cosig) | already in plan |
| Addition #3 — witness cosignatures | **SUBSUMED** by TODO 8 (freshness) |
| Addition #4 — immutable package/tag policy | **SUBSUMED** by TODO 11 |
| Addition #5 — revocation records in same log | **PARTIAL** — already in `mtc_revocations`; the offline-receiver bit is TODO 12 |
| Addition #6 — namespace authorization table | **SUBSUMED** by item 6 |
| Addition #7 — verifier fail-closed enumeration | **AGREE** — missing/extra/mode/symlink/generated all worth listing | TODO 17 |
| Addition #8 — canonical manifest + schema version | **SUBSUMED** by TODO 14 |
| Addition #9 — audit CLI gate (`--strict`) | **AGREE** — small, useful default | TODO 18 |
| Addition #10 — "not FIPS 140-3 validated" disclaimer | **SUBSUMED** by TODO 9 (terminology) |

### TODO 8. Receipt freshness — witness cosignatures + freshness policy (P0)

> Closes ChatGPT P0 #1 + Addition #3.

The current scheme proves "this manifest was logged under
*some* tree root."  An attacker who controls the log server
can serve a verifier-specific *split-view* — a forked tree
that's append-only and self-consistent but disjoint from the
public root.  Offline verification using only a cached receipt
cannot detect this.

**Required behaviour.**

- Periodic checkpoints (offline CA cosignature on tree-head per
  [`README-fips.plan`](./README-fips.plan) `[ISSUE #1]`) get
  *witness cosignatures* — N independent third parties each
  sign the same `(tree_size, root_hash)` tuple.  `N` and the
  witness identities are operator-tunable; current
  recommendation `N=3` minimum.
- Verifier policy: a receipt is accepted only if the embedded
  checkpoint carries cosignatures from `≥ N witnesses` OR the
  same checkpoint is publicly available on `≥ 1 independent
  mirror` (URL allowlist).  Pure CA-checkpoint with no witness
  attestation is no longer sufficient for offline use.
- Witness keys are pinned, not TOFU'd.  Distribution: same
  channels as the CA pubkey (DNS TXT, GPG-keyserver, project
  website — see existing item 7 for the GPG keyserver path).

**Where this lands.**

- `mtc-keymaster/server2/c/mtc_db.c` — new `mtc_witnesses` /
  `mtc_witness_signatures` schema (or fold into
  `mtc_checkpoints`).
- `fips-framework/fips-manifest-verify.c` — witness-policy
  enforcement; pinned witness pubkey list in
  `config/witnesses.h`.
- `README-fips.md` — document the witness model + the "≥ N or
  ≥ 1 mirror" verifier policy.

This is the highest-impact open item in the FIPS arc.

### TODO 9. Terminology: "FIPS source-integrity mode" (P0)

> Closes ChatGPT P0 #2 + Addition #10.

Rename the feature in user-facing text.  postWolf is **not**
CMVP-validated — calling this "FIPS mode" implies FIPS 140-3
validation that does not exist and would be misleading.

**Required text changes.**

- `fips-framework/README-fips.md` — title + every running
  reference: "FIPS Source Integrity" → keep as-is; "FIPS mode"
  → "FIPS source-integrity mode" or "FIPS build attestation
  mode".  Add a one-paragraph disclaimer at the top:
  *"This system provides tamper-evident source integrity
  anchored in a transparency log.  It is not a FIPS 140-3
  cryptographic-module validation; postWolf does not appear in
  NIST's CMVP validated-modules database."*
- `fips-framework/FIPS.md`, `fips-framework/README.md`,
  `README-fips.plan`, `README-fips-issues.md` — same sweep.
- CLI `--help` text on `fips-manifest-{submit,verify}` —
  language tweak.
- `fips.txt` (early-design notes) — left alone; historical.

No code changes; pure prose.  Land before any external
publicity push (master TODO #46).

### TODO 10. Expand manifest binding — bind more than file hashes (P0)

> Closes ChatGPT P0 #3.

Today's manifest carries `package`, `git_tag`, `expires`, and a
`files: [{path, sha256}]` array.  Insufficient: a verifier can
only check that *those particular files* match those particular
hashes, not that they came from the named package's named
release built with the expected toolchain in the expected
configuration.

**Required additions to the canonical manifest schema:**

- `package` — already present
- `version` / `tag` — already present (`git_tag`)
- `git_commit` (full SHA, not just tag — tags can be moved)
- `source_tarball_sha256` — bind the upstream tarball, not just
  individual files
- `build_scripts: [{path, sha256}]` — `configure`,
  `Makefile.am`, `debian/rules`, etc.
- `toolchain` — `{cc: {path, sha256}, cc1, as, ld, sysroot}`
  (overlaps TODO 15 / master TODO #8)
- `dependencies: [{name, version, sha256}]` — apt / pip /
  vendored
- `configure_flags` — argv to `./configure`
- `fips_boundary` — list of source dirs/files that constitute
  the FIPS module boundary
- `approved_algorithms` — explicit list (AES-256-GCM,
  ML-DSA-87, ML-KEM-768, SHA-256, …)
- `self_test_files` — paths to the self-test source(s)
- `generated_files_policy` — opaque allowed/disallowed enum
- `timestamp` — already present (`expires`); also add
  `signed_at`
- `publisher_leaf_cert_fp` — SHA-256 of the leaf cert that
  signed this manifest (TODO 16)
- `log_id` + `tree_size` + `checkpoint_hash` — bind the
  manifest to a specific transparency-log state

**Where this lands.**

- `fips-framework/fips-manifest-submit.c` — schema build.
- `fips-framework/fips-manifest-verify.c` — re-verification of
  every field.
- `mtc-keymaster/server2/c/mtc_http.c` —
  `handle_fips_manifest_submit` validates required fields.
- `README-fips.md` §"Manifest format" — full schema + each
  field's verifier semantics.
- Schema version field (TODO 14) gates the cutover.

### TODO 11. Immutable `(package, tag)` policy (P1)

> Closes ChatGPT P1 #5 + Addition #4.

`GET /fips/manifest/search?package=X&tag=Y` today silently
returns the newest matching manifest.  Equivocation risk: an
attacker who can submit a manifest could overwrite a published
release with a tampered one carrying the same `(package, tag)`.

**Required policy:**

- Either:
  - **Immutable** — the first manifest for `(package, tag)`
    wins; subsequent submissions for that pair are rejected
    with `409 Conflict`.  Re-publishing requires a new tag.
  - **Or all-versions-returned** — `search` returns every
    manifest matching `(package, tag)` with `submitted_at`
    timestamps; verifier policy decides which to trust.
    Used together with TODO 8 (witness cosignatures) so an
    attacker cannot withhold older entries.
- Default: immutable.  Operator opt-in to multi-version mode
  for "we re-cut a release with the same tag" workflows.

**Where this lands.**

- `mtc-keymaster/server2/c/mtc_http.c`
  (`handle_fips_manifest_submit`,
  `handle_fips_manifest_search`).
- `mtc_fips_manifests` schema — UNIQUE index on
  `(package, tag)` for the immutable mode.
- `fips-manifest-verify.c` — explicit "immutable" /
  "all-versions" mode flag, fail-closed on ambiguity.

### TODO 12. Offline revocation + max-age policy (P1)

> Closes ChatGPT P1 #6 + Addition #5 (offline half).

A cached receipt today survives publisher-key revocation: the
verifier never re-checks the log.  Plus there's no upper bound
on how stale a receipt can be — a 5-year-old "valid" receipt
would still verify offline.

**Required policy:**

- **Bundle revocation snapshot.**  Receipt carries
  `{revocations_as_of: <unix>, revocations:
  [{cert_index, revoked_at}, ...]}` — a CA-cosigned snapshot
  of the revocation list at receipt-issue time.
- **Max-age.**  Receipts carry `signed_at`.  Verifier rejects
  if `now - signed_at > MAX_RECEIPT_AGE` (default 90 days,
  knob).  Fresh-from-server fetch resets the clock.
- **Offline revocation check.**  Verifier compares the
  publisher leaf cert's index against the revocation snapshot
  before accepting.
- **Revocation snapshot freshness.**  If `now -
  revocations_as_of > MAX_REVOCATION_AGE` (default 7 days),
  receipt fails offline; online refetch required.

**Where this lands.**

- `fips-framework/fips-manifest-submit.c` — embed snapshot
  at receipt-emit time.
- `fips-framework/fips-manifest-verify.c` — both age checks +
  the revocation lookup.
- `mtc-keymaster/server2/c/mtc_http.c` —
  `GET /revoked` returns a cosigned snapshot, not just a JSON
  array.
- `README-fips.md` — document MAX_RECEIPT_AGE +
  MAX_REVOCATION_AGE knobs.

### TODO 13. Dual-hash (SHA-256 + SHA3-384/512) for PQ alignment (P1)

> Closes ChatGPT P1 #7.

postWolf brands itself as post-quantum, but FIPS source hashes
are SHA-256-only — a 64-bit Grover margin against second-
preimage that doesn't match ML-KEM/ML-DSA's Cat-3 stance.
Defense-in-depth: emit both `sha256` AND `sha3-384` (or
`sha3-512`) per file in the manifest; verifier checks both
and fails closed on mismatch.

**Required behaviour.**

- Manifest entry shape becomes
  `{path, sha256: "...", sha3_384: "..."}`.
- Both hashes computed at submit-time; both verified at
  verify-time.
- Schema version (TODO 14) carries the algorithm set so older
  receipts (sha256-only) still verify under their declared
  schema.

**Where this lands.**

- `fips-manifest-submit.c` / `fips-manifest-verify.c` — add
  SHA3 paths.
- `README-fips.md` — document the algorithm set.
- Receipt sizes grow ~50%; not a blocker.

### TODO 14. Canonical manifest format + schema version (P2)

> Closes ChatGPT P2 #8 + Addition #8.

The manifest is signed today over `json_object_to_json_string`
output, which is not byte-stable across libraries / language
runtimes.  Two valid serialisations of the "same" object hash
to different roots.

**Required behaviour.**

- Pick one canonical encoder.  Recommended: **RFC 8785 JCS**
  (JSON Canonicalization Scheme) — single deterministic byte
  output for any JSON object, library bindings widely
  available (Python, JS, Go; C is thinner — may need to
  vendor a small implementation).  Alternative: canonical
  CBOR (RFC 7049 §3.9) — smaller but breaks the
  "human-readable receipt" property.
- Add `schema_version: <int>` as the first field of every
  manifest.  Verifiers reject unknown versions.  Bump on any
  manifest schema change (TODO 10, 13).
- The CANONICAL bytes (after JCS encoding) are what
  `mtc_store_add_entry` stores in `mtc_log_entries.serialized`
  and what the leaf signature (TODO 16) covers.

**Where this lands.**

- `fips-manifest-submit.c` — JCS encoder before sig + submit.
- `mtc-keymaster/server2/c/mtc_http.c` — re-canonicalise
  on receive, reject if input != canonical bytes.
- `fips-manifest-verify.c` — canonicalise before verify.
- `README-fips.md` §"Canonical manifest" — full byte-form
  specification.

### TODO 15. Build-system trust — reproducible-build hooks (P2)

> Closes ChatGPT P2 #9.  Cross-cuts master TODO #8 (compiler
> integrity).

Source-integrity does not protect against a compromised
compiler, poisoned dep, or a subverted build host (Ken
Thompson's "Reflections on Trusting Trust").  Two practical
defenses:

- **Reproducible builds.**  Build the same source on two
  independent hosts with independently-obtained toolchains;
  bit-for-bit binary equality proves no target-specific code
  was injected.  Requires deterministic flags
  (`-frandom-seed`, fixed `SOURCE_DATE_EPOCH`, normalised
  build paths).  postWolf already stashes some of this in
  `.build_params`; extend.
- **Toolchain manifest.**  Include compiler/linker/assembler
  hashes in the manifest (TODO 10) so a verifier can detect
  unexpected toolchain changes.

**Where this lands.**

- `debian/rules`, `Makefile.am` — deterministic build flags.
- `fips-manifest-submit.c` — collect `cc -dumpversion`,
  `sha256(/usr/bin/gcc)`, etc.
- Out-of-band: at least one independent rebuilder running
  parallel CI (community / kit-publisher choice).  Track in
  `README-fips.md`; mostly an operational change.

Coordinate with master TODO #8 — same threat surface, the FIPS
arc just needs the manifest binding.

### TODO 16. Per-manifest leaf-key signature (P0)

> Closes Addition #1.  Distinct from the log signature
> (`mtc_store_log_sign`) and from the offline CA checkpoint
> cosig.

Currently the only signature on a manifest is the log key's
signature on the tree-root that includes it.  An attacker who
compromises the log server (online) can sign any manifest into
the log under the log key.  The CA checkpoint cosig prevents
*split-view* but NOT *current-view forgery* during the window
between checkpoints.

**Required behaviour.**

- The publisher's leaf cert (the one enrolled in the MTC log
  for `(package_namespace)`) signs the canonical manifest
  bytes (TODO 14) under ML-DSA-87 with ctx label
  `"mtc-fips-manifest/v1\n\x00"`.
- Signature is part of the manifest payload submitted to the
  server.
- Server verifies the leaf signature *before* appending —
  rejects on mismatch + counts against the failure rate
  bucket.
- Verifier (online + offline) re-verifies the leaf signature
  against the leaf cert resolved from the log.
- This puts the attacker on the wrong side of two independent
  signing keys (leaf private + log private) instead of just
  the log key.

**Where this lands.**

- `fips-manifest-submit.c` — sign with the leaf private key
  (`~/.TPM/<subject>/private_key.pem`).
- `mtc-keymaster/server2/c/mtc_http.c`
  (`handle_fips_manifest_submit`) — verify before append.
- `fips-manifest-verify.c` — re-verify on every verify.

### TODO 17. Verifier fail-closed enumeration (P1)

> Closes Addition #7.

Fully enumerate the set of conditions that fail an offline
verify, document them, test them.  ChatGPT's list:

- File listed in manifest, missing on disk → fail
- File on disk, not in manifest → fail (default; flag
  override for build artefacts allowlisted in
  `generated_files_policy`)
- File mode mismatch (executable bit, sticky, etc.) → fail if
  manifest carries mode (which it should — extension to
  TODO 10)
- Symlink found where regular file expected (or vice versa) →
  fail
- Generated file present but not on the
  `generated_files_policy` allowlist → fail
- Manifest carries a path outside the source tree (`..`
  traversal) → fail at submit + verify

**Where this lands.**

- `fips-manifest-verify.c` — explicit checks; fail-closed
  default.
- Test suite under `fips-framework/tests/` (NEW) covering
  each negative case.
- `README-fips.md` §"Verifier failure modes" — exhaustive
  list.

### TODO 18. `fips-manifest-verify --strict` audit gate (P2)

> Closes Addition #9.

A single explicit CLI mode that turns on every defence-in-
depth check (TODO 8 freshness, TODO 12 max-age, TODO 17
fail-closed enumeration, leaf-cert chain validation,
revocation snapshot lookup) — defaults relaxed for
back-compat, `--strict` gates the audit-grade run.

**Required behaviour.**

```
fips-manifest-verify --strict --manifest fips-manifest-receipt.json .
```

- Implies all of: revocation check, max-age check, witness
  cosig policy, dual-hash verify (TODO 13), leaf-sig verify
  (TODO 16), fail-closed enumeration (TODO 17), schema
  version match.
- Non-zero exit on any failure with a specific failure tag in
  the output.
- Non-`--strict` runs print warnings but exit 0 on legacy
  receipts (back-compat for receipts predating these
  features).

**Where this lands.**

- `fips-framework/fips-manifest-verify.c` — flag handling +
  the gate predicate.
- `README-fips.md` §"Verifier modes" — strict vs
  back-compat.

---

## Reference

- Current design: `README-fips.md` and `README-fips.plan`
- Design rationale: `FIPS.md`
- External reviews: `README-fips-issues.md` (12-item review),
  `README-fips-chatgpt-issues.md` (9-item ChatGPT review,
  triaged above)
- Keyserver status: `README-keyserver.md`
- TUF spec: https://theupdateframework.github.io/specification/latest/
- TUF overview: https://theupdateframework.io/overview/
