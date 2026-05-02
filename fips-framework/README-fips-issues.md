# Response to Independent Review of `README-fips.md`

This document addresses the 12 issues raised in an independent review of
the FIPS Source Integrity Verification design. Where the reviewer is
right, the issue is conceded and a concrete fix to `README-fips.md` (or
to the underlying design) is named. Where the reviewer is partly right
or where the spec is defensible as written, that is stated explicitly.

The reviewer's overall thesis — *"the design is promising, but the spec
overclaims what offline verification proves"* — is accepted. Most of the
overclaiming is in the prose, not in the actual cryptography, but the
prose is what users will read.

---

## 1. CA / server role confusion

**Reviewer:** Early text says the server signs the tree root with its
ML-DSA-87 key; later text claims the CA key is "held elsewhere." Pick
one.

**Response:** Conceded. The current README conflates two distinct
roles into one signing key:

- **Log signing key** — must be online, must sign tree roots in
  near-real-time as entries are appended. Server holds it. If the
  server is compromised, the attacker can forge inclusion proofs.
- **CA cosigning key** — held offline by the CA operator. Periodically
  signs *checkpoints* (signed tree-head + size + timestamp), not every
  individual root. Used by verifiers as the long-term trust anchor.

**Fix:** Rewrite §"The Solution" and §"Initial Server Setup" to
distinguish:
1. `log_key.der` — online, on the MTC server, signs every tree root.
2. `ca_key.der` — offline, held by CA operator, signs periodic
   checkpoints. The CA also signs the initial **log key certificate**
   that binds the log key to the log identity.

Verifiers anchor on the offline CA key and on a regularly-published
checkpoint. A compromised log server can forge proofs for new entries
but cannot forge a checkpoint older than the compromise.

---

## 2. Receipt-with-tarball problem

**Reviewer:** Replacing the tarball lets you replace
`fips-manifest-receipt.json`. The pinned CA key is the only thing
that defeats this — make pinning a *requirement*, not an option.

**Response:** Conceded. The README currently lists website, DNS TXT,
and pinned config as equivalent options. They are not. Website and DNS
are usable for *initial* key acquisition but the verifier *must* pin
locally before using the receipt; otherwise the same attacker who
swapped the tarball can swap the published key.

**Fix:** Edit §"What You Need" to make local pinning mandatory:

> The CA ML-DSA-87 public key, **pinned to a path under
> `/etc/postWolf/ca-pubkey/` (system) or `~/.config/mtc-fips/ca-pubkey/`
> (user)**. The first-time acquisition channel (DNS TXT, project
> website, package metadata) is for bootstrapping only. Once pinned,
> verification reads only the local file. Receipts not chaining to a
> pinned key MUST fail closed.

Also add an explicit warning: receipts shipped *inside* the tarball are
authenticated only by the CA signature, not by the tarball's own
provenance. The receipt is not a "self-validating package."

---

## 3. Offline mode is not "equally secure"

**Reviewer:** Offline cannot check revocation, current log
consistency, or split-view/rollback. Drop "equally secure."

**Response:** Conceded. Line 278's "As long as you trust the CA public
key, this is equally secure" is wrong. The §"When Online Verification
Adds Value" table later in the same document already enumerates what
offline misses — the contradiction needs fixing.

**Fix:** Replace the offending sentence with:

> Offline verification proves: (a) the local files match the manifest
> in the receipt; (b) the manifest was logged at the claimed index at
> some point in the past, signed by the CA key. It does **not** prove:
> (c) the leaf or CA has not since been revoked; (d) the log has not
> since been rewritten or split-viewed; (e) the entry is the latest
> known version. Use offline mode for short-window verification, or
> when network is unavailable; use online mode otherwise.

Also retitle the section to "Offline Verification (Limited Guarantees)."

---

## 4. Rollback check is too weak

**Reviewer:** `~/.config/mtc-fips/last-verified.json` is
user-writable; rollback check is best-effort at most. String
comparison of `v5.10.0` vs `v5.9.0` also fails.

**Response:** Conceded on both counts. The "rollback detection" claim
is currently presented as a guarantee. With unprotected local state
it's a UX feature, not a security control.

**Fix:** Two edits:

1. Demote the rollback check from a security guarantee to a *defense
   in depth*. Edit §"What Each Check Proves" to label it explicitly:
   "Best-effort, dependent on integrity of local state file."
2. Replace string comparison with semver parsing (`semver_cmp` or
   equivalent). Document that pre-release tags (`v5.10.0-rc1`) sort
   before `v5.10.0`, and that non-semver tags (`v5_9_0`) cause the
   check to be skipped with a warning, not silently accepted.

Optional hardening (out of scope for v1, mention in TODO): bind state
to a TPM-sealed counter, system-wide root-only file under
`/var/lib/mtc-fips/`, or external attestation server.

---

## 5. Manifest must include the file set, not just hashes

**Reviewer:** Verification must fail on extras, missing, renamed,
symlinked, generated, path-traversal files. Canonicalize paths, reject
`..`, absolute paths, dup paths, Unicode confusables, symlinks unless
explicitly allowed, case-folding collisions.

**Response:** Conceded. The current spec implies "verifier walks the
manifest and checks each listed file" — which doesn't catch files the
attacker *adds* to the source tree. The manifest must be a *closed
set*, not an allowlist.

**Fix:** Add a new section §"Manifest Path Rules" specifying:

- Paths are POSIX, NFC-normalized UTF-8, lowercase-on-Windows,
  forward-slash separated.
- Reject any path containing `..`, leading `/`, embedded `\0`, control
  characters, or matching reserved Windows device names (`CON`, etc.).
- Reject any path that case-folds to another path already in the
  manifest.
- Reject duplicates (same canonical path appearing twice).
- Verifier MUST: (a) compute the set of files actually present in the
  source tree under the FIPS-relevant prefix(es); (b) compare set
  equality with manifest paths; (c) fail on either side's surplus.
- Symbolic links: reject by default. If the manifest opts into them
  via an explicit `allow_symlinks` flag, the link target is hashed
  (not the link itself), and the target must also appear in the
  manifest.
- Generated files are out of scope: if a build step writes a file the
  manifest didn't list, the verifier rejects it. Build systems must
  either commit the file or arrange for the FIPS prefix to exclude
  the build output directory.

---

## 6. Canonical JSON needs a formal definition

**Reviewer:** "Canonical JSON" must specify UTF-8, key order, number
encoding, newline handling, array order, timestamps, duplicate-key
rejection, exact bytes signed/hashed.

**Response:** Conceded. Two implementations of this spec must produce
byte-identical signing input or the receipt is non-portable.

**Fix:** Don't invent our own. Cite **RFC 8785 (JSON Canonicalization
Scheme, JCS)** as the normative definition, with these additions:

- Timestamps are RFC 3339 with `Z` (no offset), no fractional seconds
  unless explicitly required.
- Hash values are lowercase hex, no `0x` prefix.
- Arrays inside `files[]` are sorted lexicographically by `path`
  (stable sort; paths are already unique per §5).
- Duplicate keys at any object level cause the parser to abort with
  an error (not last-wins, not first-wins).
- The signed bytes are exactly the JCS output of the manifest object,
  with no surrounding whitespace, BOM, or trailing newline.

Provide a fixture set: `fips-framework/test/canonical/` containing
several `manifest-N.json` inputs and `manifest-N.canonical.txt`
expected outputs, so independent implementations can self-check.

---

## 7. The leaf must sign the manifest

**Reviewer:** Server cosignature proves the *log* accepted a manifest,
not that the *authorized leaf publisher* submitted it. Add
`leaf_cert_id`, `leaf_pubkey_hash`, package/domain scope, and a leaf
signature over the canonical manifest.

**Response:** Conceded. This is the single most important design fix.
Without a leaf signature, an attacker who reaches the MTC server's
submission endpoint can log any manifest under any package name; the
log/CA signature only certifies that the entry was logged, not that
the rightful publisher submitted it.

**Fix:** Add to the manifest:

```json
{
  "package": "postWolf",
  "publisher": {
    "leaf_cert_id": 55,
    "leaf_pubkey_hash": "sha256:...",
    "domain_scope": ["postWolf"]
  },
  "git_commit": "...",
  ...
}
```

And add to the receipt:

```json
{
  "manifest": {...},
  "leaf_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "...",
    "signed_input": "JCS(manifest)"
  },
  "log_inclusion": {
    "index": 42,
    "inclusion_proof": [...],
    "log_signature": {...},
    "ca_checkpoint": {...}
  }
}
```

Verifier flow:
1. Verify leaf signature on `JCS(manifest)` using leaf cert pubkey.
2. Verify leaf cert chains to pinned CA (issuance proof + log entry).
3. Verify the leaf cert's `domain_scope` includes `manifest.package`.
4. Verify log inclusion proof + log signature + CA checkpoint.
5. Verify file hashes.

Server policy: reject submissions whose `publisher.leaf_pubkey_hash`
does not match the leaf cert presented at the TLS layer (see §12).

---

## 8. Revocation should not be optional for online mode

**Reviewer:** For normal online verification, check CA and leaf
revocation by default. `--no-revocation-check` should be the
exception.

**Response:** Conceded. The current §"Verifying a Kit End-to-End"
labels revocation as Step 6 (optional). That ordering invites users to
skip it.

**Fix:** Restructure online verification so revocation is unconditional:

1. Pinned CA key load (mandatory).
2. Leaf cert revocation check.
3. CA cert revocation check.
4. Manifest signature + inclusion + file hashes.

Failure at step 2 or 3 fails the whole verification. Provide
`--allow-revoked` (single explicit flag, prints loud warning) for
forensics and recovery scenarios. Drop the existing "Step 6
(optional)" framing.

---

## 9. Key rotation instructions are dangerous

**Reviewer:** "Delete the key and generate a new one" is not enough.
Need signed key-transition records.

**Response:** Conceded. The current §"Key Rotation" is a denial-of-
service waiting to happen — every existing receipt becomes invalid
the moment the key is regenerated, with no machine-readable hint that
a planned rotation occurred vs. a compromise.

**Fix:** Replace the entire §"Key Rotation" with a key-transition
protocol:

A **key transition record** is a JSON object:

```json
{
  "type": "ca-key-transition",
  "old_pubkey_hash": "...",
  "new_pubkey_hash": "...",
  "effective_at": "2027-01-01T00:00:00Z",
  "reason": "scheduled-rotation" | "suspected-compromise" | "...",
  "revoked_indices": [101, 102, 103]   // optional
}
```

The transition record is **double-signed**: by the old key and by the
new key. It is published as a log entry of type `ca-key-transition`
in the same Merkle tree, so verifiers can fetch it like any other
entry.

Verifier behavior:
- A receipt signed by an *old* key is still valid if its
  `manifest.timestamp < transition.effective_at` AND its index is not
  in `transition.revoked_indices`.
- A receipt signed by an old key after the effective time is rejected.
- The new key is trusted for receipts after `effective_at`.

Compromise rotations skip the old-key signature (it can no longer be
trusted) and require an out-of-band trust re-bootstrap (DNS TXT update
+ explicit re-pinning by every verifier). Document this loudly.

---

## 10. Algorithm / name inconsistencies

**Reviewer:** ML-DSA-87 is named, but examples show `ed25519:`,
`wc_dilithium_verify_ctx_msg()` (fine — ML-DSA = Dilithium), and a
"64-byte cosignature" (wrong size for ML-DSA-87, which is 4627
bytes).

**Response:** Conceded. The README is the result of a partial
migration from Ed25519 to ML-DSA-87 and several artifacts of the
old algorithm remain. Specifically:

| Location | Currently shows | Should show |
|----------|-----------------|-------------|
| Line 36 example pubkey | `MCowBQYDK2VwAyEA...` (Ed25519 SPKI prefix) | An ML-DSA-87 SPKI byte string (header + 2592-byte key) |
| Line 222, 528 example | Same Ed25519 string | Same fix |
| Line 496 DNS TXT example | `pk=ed25519:<hex>` | `pk=ml-dsa-87:<hex>` |
| Line 525 dig output | Ed25519 sample | ML-DSA-87 sample |
| Line 592 "2592 bytes" | Correct (ML-DSA-87 pubkey size) | Keep |
| Line 665 "cosignature 64 bytes" | Wrong | **4627 bytes** for ML-DSA-87 |
| Line 191 `wc_dilithium_verify_ctx_msg()` | OK (ML-DSA = Dilithium) | Add comment "ML-DSA-87 uses the Dilithium API in wolfCrypt" |

**Fix:** Sweep the document for `ed25519` (case-insensitive), replace
example bytes with ML-DSA-87-shaped placeholders, correct the
signature size, add a one-line note clarifying the Dilithium / ML-DSA
naming overlap. Add a §"Algorithm Sizes" table near the top:

| Item | Bytes |
|------|-------|
| ML-DSA-87 public key | 2592 |
| ML-DSA-87 signature | 4627 |
| ML-DSA-87 private key | 4896 |
| SHA-256 hash | 32 |

---

## 11. Threat model needs explicit limits

**Reviewer:** This proves "local files match a logged manifest," not
that the source is safe, FIPS-certified, or uncompromised before
logging. The §"What It Does NOT Prove" table says this; the
marketing language doesn't.

**Response:** Conceded. The opening §"The Problem" / §"The Solution"
overstates. The system addresses *post-log tampering*; it has nothing
to say about pre-log compromise.

**Fix:** Insert a §"What This Does and Does Not Prove" immediately
after §"The Solution," before any user-facing instructions. Lift the
NOT-PROVE column from the existing §"What Each Layer Proves" table
into prose so a casual reader can't miss it:

> **What this proves:** the source files in your kit are
> byte-identical to a manifest that was submitted to an append-only
> Merkle log at the claimed index, signed by an authorized CA.
>
> **What this does NOT prove:** that the submitted source is free of
> bugs or backdoors; that the CA was not compromised before
> submission; that a FIPS validation lab has approved the build; that
> the leaf publisher's intent was honest. Source-integrity logging is
> a supply-chain control. It complements but does not replace code
> review, FIPS CMVP validation, and reproducible builds.

---

## 12. Transport security missing

**Reviewer:** Manifest submission must require authenticated TLS,
server identity validation, and preferably leaf-client signing/auth.

**Response:** Conceded. The current spec talks about HTTPS but doesn't
require it, doesn't mandate cert validation, and doesn't say how the
submission endpoint authenticates the leaf.

**Fix:** New §"Transport Requirements" section before §"Publishing a
FIPS Build":

- Submission endpoint (`POST /fips/manifest`) MUST be served over
  TLS 1.3 with the server's cert chaining to a publicly trusted CA
  *or* to the same CA root used for leaf certs (mTLS within the
  postWolf trust domain). Plain HTTP submissions MUST be rejected.
- Client (publisher) MUST validate the server certificate against a
  pinned set of acceptable issuers. The pinning policy lives in
  `~/.config/mtc-fips/server-pins.json`.
- The submission MUST present the leaf certificate via mTLS. The
  server SHALL reject the submission if the TLS-presented leaf cert
  does not match `manifest.publisher.leaf_pubkey_hash` (see §7).
- Verification endpoints (`GET /fips/manifest/...`) SHOULD also
  require TLS but MAY allow unauthenticated GETs if the response
  includes the log signature (the receipt is self-authenticating;
  TLS is defense in depth).
- All endpoints SHOULD support an MQC (post-quantum) variant on the
  MQC port (`MTC_MQC_DEFAULT_PORT = 8446`) for forward secrecy
  against quantum adversaries; ML-KEM key exchange + ML-DSA leaf
  authentication.

---

## Summary: changes that must land in `README-fips.md`

The following edits are non-negotiable based on the review:

1. Split §"The Solution" into log key (online) vs CA key (offline);
   fix the contradiction in §1.
2. Make CA-key pinning mandatory in §"What You Need" (§2).
3. Remove "equally secure" from §"Offline Verification" (§3).
4. Demote rollback check to defense in depth, fix version comparison
   (§4).
5. Add §"Manifest Path Rules" specifying file-set closure and path
   canonicalization (§5).
6. Cite RFC 8785 + ship a canonicalization fixture set (§6).
7. Add leaf signature to manifest format and verifier flow (§7).
8. Reorder online verification so revocation is mandatory; rename
   `--offline` warnings (§8).
9. Replace §"Key Rotation" with the key-transition protocol (§9).
10. Sweep Ed25519 artifacts; fix the 64-byte signature size (§10).
11. Add §"What This Does and Does Not Prove" up front (§11).
12. Add §"Transport Requirements" before §"Publishing a FIPS Build"
    (§12).

The following are recommended but not blocking:

- Test fixture set under `fips-framework/test/canonical/` to lock
  down the JCS canonicalization (§6).
- TPM-sealed monotonic counter for hardened rollback detection
  (§4 — TODO note, not v1 requirement).
- MQC-port submission endpoint as the default in postWolf-internal
  deployments (§12 — design preference).
