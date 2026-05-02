# FIPS Source Integrity Verification via MTC Transparency Log

## The Problem

Traditional FIPS source checksum systems (like OpenSSL's `fips-sources.checksums`) store SHA256 hashes of source files **in the same repository** as the source code. An attacker with write access to the repository can modify a source file and update its checksum simultaneously. Nothing downstream detects the tampering — the checksums are self-referential.

## The Solution

postWolf anchors FIPS source checksums in an **external, append-only Merkle Tree transparency log** maintained by the MTC server. Two distinct ML-DSA-87 keys protect the log; this separation is load-bearing and is described before any other detail because earlier drafts conflated the two:

- **Log key** — held *online* by the MTC server. Signs every tree root as new entries are appended. Lets the server return a fresh, self-consistent inclusion proof in real time. If the log key is stolen, the attacker can forge entries and signed roots from the moment of compromise forward.
- **CA key** — held *offline* by the CA operator (ideally air-gapped, never on the log server's host). Signs (a) the initial **log key certificate** binding the log identity to the log key, and (b) periodic **checkpoints** — `(tree_size, tree_root, timestamp)` tuples that anchor the log's history. Verifiers pin the **CA public key**, never the log public key directly.

At build time, a manifest of every FIPS source file's SHA-256 hash is submitted to the server, logged as a new leaf, and bound to a tree root signed by the log key. A subsequent CA-signed checkpoint that covers the entry's tree size gives the receipt its long-term audit weight. The manifest cannot be altered after submission without detection, because:

1. The Merkle tree is append-only — modifying a leaf changes the root hash.
2. The CA-signed checkpoints anchor any historical root that a receipt's inclusion proof traces to. Forging a checkpoint requires compromising the offline CA key.
3. A receipt (inclusion proof + log signature + a covering CA checkpoint) ships with the package. Verification works offline against the pinned CA public key.

A compromised log key lets an attacker forge entries and roots **going forward**, but cannot forge a CA checkpoint for any tree state that existed before the compromise. Receipts whose covering checkpoint pre-dates the compromise remain verifiable; receipts whose covering checkpoint post-dates it require an out-of-band re-validation. (Compromise recovery is detailed in §"Key Rotation.")

## Algorithm Sizes

All signing in this scheme is **ML-DSA-87** (FIPS 204). All hashing is **SHA-256** (FIPS 180-4). The wolfCrypt API for ML-DSA-87 is named `wc_dilithium_*` for historical reasons; the parameter set is the standardized FIPS 204 ML-DSA-87, and the wire bytes are interoperable.

| Item | Bytes | Notes |
|------|-------|-------|
| ML-DSA-87 public key | 2592 | Distributed via DNS TXT pkhash + side-channel pubkey fetch (TXT cannot inline 2592 bytes). |
| ML-DSA-87 signature | 4627 | Per signature, every appearance — log signature, CA checkpoint signature, leaf signature on manifest. |
| ML-DSA-87 private key | 4896 | Held under physical control; never on the log host for the CA key. |
| SHA-256 hash | 32 | All Merkle-tree node hashes, file hashes, and pubkey hashes. |
| Manifest hash (SHA-256 of JCS bytes) | 32 | Becomes the Merkle leaf for the entry. |

These are the canonical sizes; an implementation that produces a different size for any item is non-conformant. (The previous draft of this document erroneously listed the cosignature as 64 bytes — that was an Ed25519 leftover and is fixed.)

---

## For Administrators

### Prerequisites

- The MTC C server (`mtc-keymaster/server2/c/mtc_server`) built and running
- PostgreSQL (Neon) database configured, or a local data directory for file-based storage
- `jq` and `curl` installed on the build machine

### Initial Server Setup

The two-key model from §"The Solution" requires a one-time CA bootstrap on a separate (ideally air-gapped) machine, plus a per-deployment log-key handover:

```bash
# Build the MTC server (and the CA tooling)
cd mtc-keymaster/server2/c
make

# ---- ON THE OFFLINE CA MACHINE (run once per CA identity) -----------
# Generate the offline CA key. Keep ca_key.der under physical control.
./mtc_ca_init --datadir /var/lib/mtc-ca
#   writes /var/lib/mtc-ca/ca_key.der    (PRIVATE — never copy to the log host)
#   writes /var/lib/mtc-ca/ca_pubkey.der (PUBLIC  — ship to verifiers)

# Sign the log key certificate. log_pubkey.der is generated on the log host
# (see below) and brought across to the CA machine on removable media.
./mtc_ca_sign --ca-key /var/lib/mtc-ca/ca_key.der \
              --log-pubkey log_pubkey.der \
              --validity-days 365 \
              --out log_cert.der

# ---- ON THE LOG HOST (the MTC server) -------------------------------
# Generate the online log key.
./mtc_log_keygen --out-priv log_key.der --out-pub log_pubkey.der

# Take log_pubkey.der to the CA machine, run mtc_ca_sign (above),
# bring log_cert.der back. Then start the server with both keys:
./mtc_server --port 8080 --datadir /var/lib/mtc-fips \
             --log-key log_key.der \
             --log-cert log_cert.der

# The server prints the CA public key fingerprint on startup so the
# operator can sanity-check that the log_cert installed matches the
# CA the verifiers will pin:
#   CA public key fingerprint: <hex SHA-256 of ca_pubkey.der>
```

The log host stores (online — recoverable from filesystem snapshot in event of compromise):
- `log_key.der` — ML-DSA-87 log private key. Signs every new tree root in real time.
- `log_cert.der` — log key certificate signed by the offline CA. Lets verifiers confirm the log key is the one the CA endorsed.
- `entries.json` — all Merkle tree entries (file-based fallback).
- `fips_manifests.json` — FIPS manifest metadata.
- `checkpoints/` — most recent CA-signed checkpoints, fetched periodically (see below).
- PostgreSQL tables if `MERKLE_NEON` is configured.

The CA operator holds (offline — must never appear on the log host):
- `ca_key.der` — ML-DSA-87 CA private key. Signs log key certs and checkpoints only.
- `ca_pubkey.der` — distributed to verifiers via the bootstrap channels (DNS TXT, package metadata, etc.) and pinned locally by every verifier. This is the one and only long-term trust anchor.

**Periodic checkpoint signing.** On a cadence the operator picks (e.g., daily, or after every N entries), the log server emits a `checkpoint-request.json` containing the current `(tree_size, tree_root, timestamp)`. The CA operator brings this to the offline machine, signs it with `ca_key.der`, and uploads the resulting `checkpoint-NNN.sig` back to the log host's `checkpoints/` directory. Receipts issued between checkpoints are verifiable but reach their full audit weight only once a covering checkpoint exists.

### Publishing a FIPS Build

After a successful FIPS build, the administrator runs the manifest submission script. This is typically integrated into the build system (`debian/rules` or `Makefile`) but can also be run manually.

**Step 1: Build postWolf with FIPS**

```bash
./configure --enable-fips ...
make
./fips-hash.sh       # Generate runtime integrity hash
make                 # Rebuild with updated hash in fips_test.c
```

**Step 2: Submit the manifest**

```bash
# Set the MTC server URL
export MTC_SERVER=https://mtc.example.com:8080

# Submit checksums of all FIPS source files to the server
./fips-framework/fips-manifest-submit
```

The script:
1. Computes SHA256 of every FIPS source file (the same files listed in `fips-check.sh`)
2. Builds a canonical JSON manifest with the git commit, tag, timestamp, and expiration (default: 1 year)
3. POSTs the manifest to `$MTC_SERVER/fips/manifest`
4. Saves the server's response to `fips-manifest-receipt.json`

The receipt contains everything needed for offline verification:
```json
{
  "index": 42,
  "manifest": { ... },
  "inclusion_proof": ["a1b2c3...", "d4e5f6...", ...],
  "subtree_start": 0,
  "subtree_end": 43,
  "subtree_hash": "7f8e9d...",
  "cosignature": {
    "signature": "b3c4d5...",
    "algorithm": "ML-DSA-87"
  }
}
```

**Step 3: Ship the receipt**

Include `fips-manifest-receipt.json` in the release tarball or `.deb` package. This single file contains the manifest, inclusion proof, and ML-DSA-87 cosignature — everything needed for offline verification using only the pinned CA public key.

### Automated Build Integration

In `debian/rules`:

```makefile
override_dh_auto_build:
ifeq ($(ENABLED_FIPS),yes)
    $(MAKE)
    ./fips-hash.sh
    $(MAKE)
    ./fips-framework/fips-manifest-submit
else
    dh_auto_build
endif
```

Or with Make:

```bash
make fips-manifest-submit   # after the FIPS build completes
```

### Managing the Server

**View all logged manifests:**
```bash
curl http://localhost:8080/fips/manifest/search?package=postWolf
```

**Retrieve a specific manifest:**
```bash
curl http://localhost:8080/fips/manifest/42
```

**Get a fresh inclusion proof** (proof updates as the tree grows):
```bash
curl http://localhost:8080/fips/manifest/42/proof
```

**Check log consistency** (verify the tree has only grown, never been rewritten):
```bash
curl "http://localhost:8080/log/consistency?old=42&new=100"
```

**Export the CA public key** (for distribution to verifiers):
```bash
curl http://localhost:8080/ca/public-key
```

### Key Rotation

Rotation comes in two flavors with very different procedures: **scheduled** (planned, both keys still trusted) and **compromise** (old key trust must be revoked). The dangerous earlier "delete the key and regenerate" procedure has been replaced because it leaves verifiers with no machine-readable signal about what happened — every existing receipt becomes invalid simultaneously, and a freshly-spun-up new key is indistinguishable from an attacker's substitution.

#### Key transition record (the foundation)

Every rotation, scheduled or compromise, is announced by a **key transition record** logged in the same Merkle tree as a new entry of type `ca-key-transition`:

```json
{
  "type": "ca-key-transition",
  "schema_version": 1,
  "old_pubkey_hash": "sha256:a1b2c3...",
  "new_pubkey_hash": "sha256:d4e5f6...",
  "effective_at": "2027-01-01T00:00:00Z",
  "reason": "scheduled-rotation",
  "revoked_indices": []
}
```

`reason` is one of:
- `scheduled-rotation` — planned rollover; old key continues to verify pre-`effective_at` receipts.
- `suspected-compromise` — old key is no longer trusted from `effective_at` onward; the absence of an old-key signature on this record is itself a signal.
- `key-loss` — old private key is destroyed/inaccessible; semantically similar to compromise but the old public key still verifies pre-`effective_at` receipts because no fraudulent signing is possible.

`revoked_indices` (optional) lists log indices the old key signed but that are explicitly being revoked alongside the rotation (e.g., entries the operator has reason to believe were forged in the run-up to discovering the compromise). These take precedence over `manifest.timestamp < effective_at`.

#### Scheduled rotation

The old key is trusted to bless its successor. Both keys are still trusted; the old key signs the transition record, the new key co-signs it, and verifiers see an unambiguous handoff.

```bash
# ---- ON THE OFFLINE CA MACHINE ----
# 1. Generate the new CA key (separate file, side by side with the old).
./mtc_ca_init --datadir /var/lib/mtc-ca --label new

# 2. Build the transition record JSON locally.
./mtc_ca_transition --old-key /var/lib/mtc-ca/ca_key.der \
                    --new-key /var/lib/mtc-ca/ca_key_new.der \
                    --reason scheduled-rotation \
                    --effective-at 2027-01-01T00:00:00Z \
                    --out transition-001.json

# 3. The tool double-signs: old key first, then new key. Both signatures
#    appear in the record. Verifiers refuse a scheduled-rotation record
#    that lacks the old-key signature.

# 4. Upload the signed record to the log host for inclusion.
scp transition-001.signed.json log-host:/tmp/
ssh log-host \
  './mtc_log_submit_transition --in /tmp/transition-001.signed.json'

# 5. After the log returns the inclusion proof + log signature,
#    publish the receipt to verifiers via the same channels used
#    for the original CA pubkey distribution (DNS TXT, project
#    website, package metadata).
```

Verifier behavior on a scheduled rotation receipt:

- A receipt whose `manifest.timestamp < effective_at` is verified with the **old** key.
- A receipt whose `manifest.timestamp >= effective_at` is verified with the **new** key.
- Receipts in `revoked_indices` are rejected regardless of timestamp.
- An unsigned-by-old-key transition record with `reason: scheduled-rotation` is rejected — that pattern is reserved for compromise rotations.

#### Compromise rotation

The old key cannot be trusted to sign anything new (it may already be in the attacker's hands). The transition record is signed by the **new** key only, and verifiers MUST re-bootstrap the new pubkey through an out-of-band channel — they cannot accept the new key on the old key's say-so.

```bash
# ---- ON THE OFFLINE CA MACHINE (assumed clean) ----
# 1. Generate the new CA key on a freshly-imaged offline machine
#    (do not reuse the host that held the compromised key).
./mtc_ca_init --datadir /var/lib/mtc-ca-new

# 2. Build the transition record. NOTE: --reason suspected-compromise
#    forbids the --old-key argument; the tool will not double-sign.
./mtc_ca_transition --new-key /var/lib/mtc-ca-new/ca_key.der \
                    --old-pubkey-hash sha256:a1b2c3... \
                    --reason suspected-compromise \
                    --effective-at 2026-09-15T00:00:00Z \
                    --revoked-indices 101,102,103 \
                    --out compromise-transition.json

# 3. Submit to the log via mtc_log_submit_transition (as above).

# 4. Re-distribute the new pubkey via at least two independent
#    bootstrap channels (DNS TXT update + GPG-signed git tag, or
#    similar). Verifiers MUST re-pin manually before accepting any
#    receipt under the new key. There is no automatic upgrade path.
```

Verifier behavior on a compromise rotation:

- All receipts under the old key — including those whose `manifest.timestamp < effective_at` — are downgraded to "untrusted" pending operator review. Loud warning is printed; verification fails closed unless `--accept-pre-compromise` is explicitly passed (analogous to `--allow-revoked`, with the same audit logging).
- The new key is NOT auto-trusted. Verifier configuration must be updated to add the new pinned pubkey via the operator's normal pin-management process. A receipt under the new key is rejected until the new pubkey appears in the verifier's pinned set.
- If the verifier has not re-bootstrapped, *any* receipt fails until the operator intervenes. This is by design — silent recovery from a compromise is worse than a failure.

#### Key loss

If the old private key is irretrievable but not necessarily compromised (hardware failure, lost passphrase), the procedure is the compromise procedure with `reason: key-loss`. Pre-`effective_at` receipts remain verifiable (the public key still works), but no new entries can be signed under the old key. The transition record is signed only by the new key; verifiers re-bootstrap the same way.

#### Recovery scenarios summary

| Scenario | Old-key sig on transition? | Pre-effective_at receipts | Verifier action |
|----------|---------------------------|---------------------------|-----------------|
| Scheduled rotation | Yes (mandatory) | Auto-verified under old key | Update config; transition record auto-discovered from log |
| Suspected compromise | No (reserved as the signal) | Downgraded to untrusted pending review | Manual re-pin via two independent bootstrap channels |
| Key loss | No | Auto-verified under old key (no new signing possible) | Manual re-pin via two independent bootstrap channels |
| Key rotation announced but old key still signs after effective_at | — | — | The new entries are rejected; the old key has gone "rogue" — treat as a fresh suspected-compromise |

---

## For Users (Downstream Verification)

### What You Need

- The postWolf source code (tarball, `.deb` source package, or git clone)
- The `fips-manifest-receipt.json` file (shipped with the release — contains the manifest, inclusion proof, and the CA-signed checkpoint covering the entry)
- The `fips-manifest-verify` tool (built from `fips-framework/`, linked against wolfCrypt)
- The CA ML-DSA-87 public key (2592 bytes), **pinned to a local file under one of**:
    - `/etc/postWolf/ca-pubkey/<name>.der` (system-wide, root-only writable; recommended for production hosts)
    - `~/.config/mtc-fips/ca-pubkey/<name>.der` (per-user; recommended for developer workstations)
    - `fips-framework/config/ca-pubkey.h` (compiled into a custom build of `fips-manifest-verify` for embedded / CI use)

No OpenSSL or shell dependencies (`curl`, `jq`) are required. All
cryptographic verification (SHA-256, ML-DSA-87 signature, Merkle proof replay)
uses wolfCrypt natively.

#### Pinning is mandatory, not optional

The CA public key MUST be obtained out-of-band on first contact and then **pinned** to one of the locations above. After pinning, `fips-manifest-verify` reads the key only from the pinned file — it never re-fetches from the network, the project website, or the receipt itself. Receipts that do not chain to a key already present in the pinned set MUST fail closed; they will not trigger a "trust on first use" prompt.

The bootstrap channels in §"CA Identity Verification" (DNS TXT, project website, package metadata, GPG-signed git tag, CMVP certificate) exist **only to perform the initial acquisition and to detect a key change later**. They are not equivalent substitutes for a local pinned file at verification time. A new key encountered through one of those channels must be reviewed and explicitly pinned by the operator before any receipt signed with it is accepted.

#### The receipt is not a self-validating package

`fips-manifest-receipt.json` ships *inside* the release tarball. The same attacker who can substitute the tarball can substitute the receipt — including replacing the embedded CA-signed checkpoint and inclusion proof with values that match a forged manifest. **The only thing that defeats this is the pinned CA public key**, which lives outside the tarball and which the attacker cannot reach.

In particular: if you find yourself running verification using a CA key that came from the same archive (or the same upload host) as the tarball you are verifying, you are not actually verifying anything. The pinned key must come from a channel the attacker does not control.

### Online Verification (Recommended)

Online verification queries the MTC server for the latest proof and compares your local source files against the logged manifest.

```bash
# Set the MTC server URL
export MTC_SERVER=https://mtc.example.com:8080

# Verify your local source against the server
./fips-framework/fips-manifest-verify
```

What happens (in order, with each earlier failure short-circuiting later steps):

1. **Pinned CA key load** (mandatory). Read the CA public key from the pinned file (`/etc/postWolf/ca-pubkey/` or `~/.config/mtc-fips/ca-pubkey/` or `config/ca-pubkey.h`). Receipts not chaining to a pinned key fail closed.
2. **Receipt parse + manifest expiry check.** Parse `fips-manifest-receipt.json`. Reject if `manifest.expires` is past.
3. **Leaf signature verify.** Verify `leaf_signature` over `JCS(manifest)` using the leaf cert at `manifest.publisher.leaf_cert_id` (per §"Leaf Signature on the Manifest").
4. **Leaf cert revocation check** (mandatory in online mode). `GET /revoked/<leaf_cert_id>`. If revoked, fail closed unless `--allow-revoked` is explicitly passed (see §"Verifying a Kit End-to-End" Step 5).
5. **CA revocation check** (mandatory in online mode). `GET /revoked/<ca_cert_id>`. If revoked, fail closed unless `--allow-revoked` is explicitly passed.
6. **Domain scope.** Confirm `manifest.publisher.domain_scope` includes `manifest.package`.
7. **Rollback check** (best-effort). Semver compare against local state; warn or hard-fail under `--strict-rollback`. State is in `/var/lib/mtc-fips/last-verified.json` (preferred) or `~/.config/mtc-fips/last-verified.json` (fallback). See §"Rollback Detection (Best-Effort)" for limitations.
8. **File set + hashes.** Apply §"Manifest Path Rules": walk the FIPS prefix(es), compare set equality with manifest paths, then SHA-256 each file.
9. **Fresh log inclusion proof.** `GET /fips/manifest/<index>/proof`. Replay the inclusion proof (SHA-256 hash chain from leaf to root).
10. **Log signature verify.** Verify the log signature on the returned root using the log key cert (which itself chains to the pinned CA per §"The Solution").
11. **CA-signed checkpoint verify.** Verify the CA signature on the covering checkpoint using the pinned CA key (`wc_dilithium_verify_ctx_msg()`).

**Output on success:**
```
FIPS Manifest Verification: PASS
  Package:    postWolf
  Git tag:    v5.9.0
  Log index:  42
  Expires:    2027-04-05T00:00:00Z (valid)
  Publisher:  example.com-builder (log entry verified)
  Rollback:   OK (v5.9.0 >= last accepted v5.8.0)
  Files:      127 verified
  Proof:      inclusion proof valid (depth 7)
  Signature:  ML-DSA-87 cosignature valid
```

**Output on failure (tampered source):**
```
FIPS Manifest Verification: FAIL
  MISMATCH: wolfcrypt/src/aes.c
    Local:  a1b2c3d4e5f6...
    Logged: 0e22ea0cf34e...
  1 file(s) do not match the server-logged manifest.
```

### Offline Verification (Limited Guarantees)

Offline verification uses the cached inclusion proof, log signature, and CA-signed checkpoint from the receipt file. No network access is required — only the **pinned** CA public key (see §"What You Need" → "Pinning is mandatory").

```bash
# Verify without contacting the server. The pinned CA key is read
# from /etc/postWolf/ca-pubkey/ or ~/.config/mtc-fips/ca-pubkey/
# automatically; no environment variable required.
./fips-framework/fips-manifest-verify --offline
```

What happens:
1. The script reads `fips-manifest-receipt.json` (contains the manifest, inclusion proof, log signature, and covering CA-signed checkpoint).
2. It checks the manifest `expires` field — rejects if expired.
3. It checks for version rollback against local state (best-effort; see §"Rollback Detection (Best-Effort)" for caveats).
4. It computes SHA-256 of every FIPS source file on your local disk.
5. It recomputes the manifest hash from local files and compares to the receipt's manifest hash.
6. It replays the inclusion proof: walks the hash chain from the leaf hash up to the root that the receipt's log signature covers.
7. It verifies the log signature on that root using the log key cert from the receipt.
8. It verifies the CA signature on the covering checkpoint using the **pinned** CA public key (`wc_dilithium_verify_ctx_msg()`), and confirms the log key cert chains to the same CA.

If any source file has been modified since the manifest was submitted, the local manifest hash will differ from the receipt's manifest hash, and verification fails.

#### What offline verification proves — and what it does not

Offline mode is designed for short-window verification (e.g., immediately after download, on an air-gapped build host) and for fallback when the network is unavailable. It is **not** equivalent to online verification.

| | Offline proves | Offline does NOT prove |
|---|----------------|------------------------|
| File integrity | ✓ Local files match the manifest in the receipt | — |
| Log inclusion | ✓ Manifest was logged at the claimed index, signed by a covering CA checkpoint *at the time the receipt was issued* | ✗ Whether the log has since been rewritten, split, or otherwise tampered with |
| Revocation | — | ✗ Whether the leaf certificate or the CA itself has been revoked since the receipt was issued |
| Freshness / split-view | — | ✗ Whether the log operator has shown a different view of the tree to other verifiers (split-view attack) |
| Latest-version | — | ✗ Whether a newer release exists that supersedes this one |

Use offline mode when you must (no network, hardened/air-gapped host) or when you can (you downloaded both the kit and a fresh CA-signed checkpoint within the same short window). Use online mode otherwise — see the §"When Online Verification Adds Value" table near the end of this document for the specific guarantees online adds.

### What Each Check Proves

| Check | What It Proves |
|-------|----------------|
| Manifest not expired | The kit is still within its validity period |
| Publisher log entry valid | The publisher was enrolled by the CA and their leaf is in the Merkle tree |
| Version rollback check (best-effort) | This is not an older version than one you previously accepted **on this verifier**. Defence-in-depth only: relies on the integrity of the local state file, which is user-writable and trivially deletable. See §"Rollback Detection (Best-Effort)" for the precise threat model. |
| Local SHA256 matches manifest | Your source files are identical to what was submitted to the server |
| Inclusion proof is valid | The manifest was genuinely logged in the Merkle tree at the claimed index |
| ML-DSA-87 cosignature is valid | The Merkle tree root was signed by the CA's private key — not forged |
| Consistency proof (optional) | The tree has only grown since the manifest was logged — no entries removed or rewritten |

### Rollback Detection (Best-Effort)

The verifier maintains a local state file recording the highest version it has previously accepted for each package:

- `/var/lib/mtc-fips/last-verified.json` (system-wide; created mode `0644`, owned by root)
- `~/.config/mtc-fips/last-verified.json` (per-user fallback if no system file is writable)

When a new receipt is verified, the verifier compares `manifest.git_tag` against the stored value for `manifest.package`. A *lower* version triggers a rollback warning by default and a hard failure under `--strict-rollback`.

#### Comparison rules

Version strings are parsed as **semantic version 2.0.0** (semver) where possible:

- `v5.10.0 > v5.9.0` (numeric component compare, not lexicographic — fixes the `"v5.10.0" < "v5.9.0"` string-compare bug present in the original draft).
- Pre-release identifiers sort **before** the corresponding final release: `v5.10.0-rc1 < v5.10.0`. A pre-release receipt does not "raise" the stored version above its base version.
- Build metadata (`+sha.abcdef`) is ignored for ordering, per semver §10.
- Tags that fail to parse as semver (e.g., `v5_9_0`, `release-2026-04-30`) cause the rollback check to be **skipped with a warning**, not silently accepted. The state file records the unparseable tag verbatim so subsequent identical tags don't re-warn, but no ordering is inferred.

#### What this defends against — and what it does not

| | Defends | Does not defend |
|---|---------|-----------------|
| Accidental downgrade via stale mirror | ✓ Verifier remembers it once accepted v5.10.0 and warns on a v5.9.0 receipt | — |
| Targeted rollback against a single host | Partial — only if the local state file is intact | ✗ If the attacker can write/delete `last-verified.json`, they can suppress the warning |
| Rollback against a *fresh* host | — | ✗ A first-time install has no prior state and accepts any version |
| Coordinated rollback across an organization | — | ✗ Each verifier has independent state; no fleet-wide signal |

#### Hardening (TODO, not v1)

For environments that need rollback protection as a **security control** rather than a usability feature, the planned hardening paths are:

- TPM-sealed monotonic counter — bind the stored version to a sealed PCR-bound counter that cannot be rewound without TPM reset.
- Anchored remote attestation — verifier pushes its accepted-version manifest to an external append-only log; the server refuses to accept a verification report whose claimed version is older than the last one it logged for the same host identity.
- System-wide root-only state — already supported via `/var/lib/mtc-fips/`; document it as the production-recommended path and require `0600` perms with `chattr +i` for high-assurance deployments.

These are not in v1. Until they ship, treat the rollback check as defense in depth only.

### Common Scenarios

**"I downloaded the source tarball and want to verify it hasn't been tampered with"**

```bash
tar xzf wolfssl-5.9.0.tar.gz
cd wolfssl-5.9.0
./fips-framework/fips-manifest-verify
```

The receipt file is included in the tarball. If the source matches what was logged to the server, you have cryptographic proof that your copy is authentic.

**"I cloned the git repo and want to check a specific tag"**

```bash
git clone https://github.com/cpsource/wolfssl.git
cd wolfssl
git checkout v5.9.0
./fips-framework/fips-manifest-verify
```

**"I want to verify but the MTC server is down"**

```bash
./fips-framework/fips-manifest-verify --offline
```

The offline mode uses the receipt's cached proof and CA-signed checkpoint. **It is not equivalent to online verification** — it cannot detect post-issuance revocation, log rewriting, or split-view attacks. See §"Offline Verification (Limited Guarantees)" for the precise scope of what offline proves and does not prove. For a kit you have just downloaded over an unauthenticated channel, prefer online verification when you can; treat offline as a fallback, not the default.

**"I patched a source file for my own use — how do I confirm what changed?"**

```bash
./fips-framework/fips-manifest-verify 2>&1 | grep MISMATCH
```

The script reports exactly which files differ from the logged manifest. This is useful for auditing your own modifications.

---

## How It Compares to OpenSSL's Approach

| | OpenSSL | postWolf (this system) |
|---|---------|--------------------------|
| **Checksums stored** | In the repo (`fips-sources.checksums`) | In an external append-only Merkle tree |
| **Signed by** | No signature (plain SHA256) | ML-DSA-87 cosignature on tree root |
| **Tamper detection** | Only if attacker forgets to update checksums | Always — attacker cannot forge server-side log |
| **Offline verification** | Yes (but no signature to verify) | Yes — receipt contains proof + signature |
| **Requires server** | No | No (offline mode); Yes for fresh proofs |
| **Append-only audit trail** | No (checksums can be rewritten) | Yes — full history preserved in Merkle tree |
| **Trust anchor** | CMVP certification (external process) | ML-DSA-87 CA key + CMVP certification |

---

## Manifest Path Rules

The manifest is a **closed set** description of the FIPS-relevant file tree, not an allowlist. Verification fails if the local tree contains files the manifest does not list, or vice versa. This prevents the "attacker adds an extra file" bypass that pure hash allowlists are vulnerable to.

### Path canonicalization

All paths in the manifest, and all paths the verifier enumerates locally, are canonicalized identically before any comparison or hashing:

- **Encoding:** UTF-8, NFC-normalized (Unicode normalization form C). Reject paths whose NFC form differs from the as-stored form (this catches NFD/NFKC homoglyphs).
- **Separator:** forward slash (`/`) only. Reject `\`, mixed separators, and embedded path separators in single components.
- **Case:** preserved on POSIX. On case-insensitive filesystems (Windows, macOS HFS+ default), the verifier additionally checks that no two manifest paths case-fold to the same string; collision is a hard error.
- **Leading characters:** reject leading `/`, leading `~`, leading `.` followed by `/` or end-of-string (`./` and `.` as a path component are rejected as unhelpful).
- **Forbidden components:** reject any path containing `..`, `\0`, ASCII control characters (`< 0x20`), or matching reserved Windows device names case-insensitively (`CON`, `PRN`, `AUX`, `NUL`, `COM[1-9]`, `LPT[1-9]`).
- **Length:** reject any single component longer than 255 bytes; reject any total path longer than 4096 bytes.

A path that fails any of the above causes the entire manifest to be rejected at submission time and at verification time.

### Set-equality requirement

The verifier:

1. Walks the source tree under the FIPS-relevant prefix(es) named in `manifest.scope_paths` (a new manifest field — see §"Manifest Schema (v2)"), applying the same canonicalization rules.
2. Builds the set of canonicalized local paths.
3. Builds the set of canonicalized manifest paths (with duplicate-detection — repeated paths are rejected at parse time).
4. Computes set difference in **both directions**:
    - `local \ manifest` → "extra files present locally" → **fail**.
    - `manifest \ local` → "files missing locally" → **fail**.
5. For paths present in both sets, computes SHA-256 of the local file and compares to the manifest hash.

Set comparison precedes per-file hashing so that adding or removing files is reported clearly, separately from "this file's contents changed."

### Symbolic links

Symbolic links are **rejected by default**. The walker treats a symlink in the FIPS prefix as a hard error.

A manifest may opt in to symlinks per-prefix via `manifest.scope_paths[].allow_symlinks: true`. When opted in:

- The link's *target path* (after resolution, with the same canonicalization) must also appear in the manifest under that prefix or under another prefix that opts in.
- The hashed bytes are the **target file's** contents, not the link's target string. The link itself is not hashed.
- Links pointing outside the FIPS prefix set are rejected even when `allow_symlinks: true`.
- Cycles in the link graph cause hard rejection (no infinite walks).

### Generated and out-of-tree files

The framework does not handle generated files. If a build step writes a file under the FIPS prefix that the manifest did not list, the verifier rejects the kit. Build systems must arrange one of:

- Commit the generated file and include it in the manifest.
- Configure the FIPS prefix to exclude the build output directory (`scope_paths[].exclude_subdirs`).
- Run verification before the build (the recommended pattern: extract → verify → build).

### Manifest schema (v2)

The closed-set requirement adds `scope_paths` and renames `version` to `schema_version` to make the bump explicit:

```json
{
  "type": "fips-build-manifest",
  "schema_version": 2,
  "package": "postWolf",
  "git_commit": "...",
  "git_tag": "v5.9.0",
  "timestamp": "2026-04-05T00:00:00Z",
  "expires": "2027-04-05T00:00:00Z",
  "scope_paths": [
    {
      "prefix": "wolfcrypt/src/",
      "allow_symlinks": false,
      "exclude_subdirs": [".libs/", ".deps/"]
    },
    {
      "prefix": "wolfcrypt/include/",
      "allow_symlinks": false
    }
  ],
  "files": [
    {"path": "wolfcrypt/src/aes.c",  "sha256": "0e22ea0c..."},
    {"path": "wolfcrypt/src/fips.c", "sha256": "c049a936..."}
  ]
}
```

Schema v1 receipts (no `scope_paths`) remain verifiable but produce a startup warning — they cannot detect "extra file" attacks. New submissions MUST use schema v2.

---

## Canonical JSON

Every signed object in this scheme — manifest, receipt, leaf signature input, CA-signed checkpoint — is signed and hashed over its **canonical** byte serialization. Two implementations of this spec MUST produce byte-identical canonical output for byte-identical inputs, or signatures issued by one will not verify on the other.

### Normative reference

The canonical serialization is **JCS — JSON Canonicalization Scheme, RFC 8785**. Implementations MUST follow RFC 8785 in full. The summary below is for orientation only; in any conflict, RFC 8785 governs.

JCS pins:

- UTF-8 output, no BOM, no leading or trailing whitespace, no surrounding newline.
- Object members sorted lexicographically by **UTF-16 code unit** order of the key (RFC 8785 §3.2.3) — *not* by UTF-8 byte order. Important corner case: e.g., `"ﬀ"` (ﬀ) sorts after `"﻿"` only if compared as UTF-16; a naive byte-sort gives a different answer.
- Numbers serialized via the ECMAScript `Number.prototype.toString()` algorithm as profiled in RFC 8785 §3.2.2.
- Strings JSON-escape only the characters required by RFC 8259 §7 (`"`, `\`, and `U+0000`–`U+001F`); all other characters, including non-ASCII, are emitted verbatim.

### postWolf-specific tightenings on top of JCS

JCS leaves a few choices to the application; this spec pins them:

- **Timestamps** are RFC 3339 `date-time` with literal `Z` (no numeric offsets), no fractional seconds. Example: `"2026-04-05T12:34:56Z"`. Submissions with offsets, fractional seconds, or non-UTC timestamps are rejected.
- **Hash and key values** are lowercase hex without `0x` prefix or interior separators. Example: `"sha256": "0e22ea0c..."`. Uppercase, base64, or `0x...` forms are rejected.
- **`files[]` array order** is sorted lexicographically by `path` (UTF-16 code units, like JCS object keys). Paths are unique by construction (see §"Manifest Path Rules"); duplicate paths cause the parser to reject the manifest.
- **Duplicate object keys** at any nesting level cause the parser to abort. JSON parsers that silently last-wins-on-duplicate are non-conformant. The parser used MUST surface duplicate-key errors as parse failures.
- **Numbers in this spec** are restricted to integers in `[0, 2^53 − 1]` (signed JavaScript-safe integer range, but only non-negative values are used). Implementations MUST reject non-integer numbers, negatives, and out-of-range values rather than silently coerce.

### What gets signed

The byte sequence presented to `wc_dilithium_sign_ctx_msg()` (or to SHA-256 when computing `manifest_hash`) is the JCS-canonical serialization of the object, exactly. No surrounding container, no length prefix, no trailing newline, no BOM. The same bytes go into the verification call.

Implementations that re-parse and re-serialize a JCS-canonical document MUST get back the same bytes. This is a useful self-test.

### Test fixtures (planned)

A normative fixture set will live under `fips-framework/test/canonical/` and ship alongside the verifier:

```
fips-framework/test/canonical/
├── 01-empty-manifest.input.json
├── 01-empty-manifest.canonical.bin
├── 02-out-of-order-keys.input.json
├── 02-out-of-order-keys.canonical.bin
├── 03-unicode-bmp.input.json
├── 03-unicode-bmp.canonical.bin
├── 04-unicode-supplementary.input.json
├── 04-unicode-supplementary.canonical.bin
├── 05-numeric-edge-cases.input.json
├── 05-numeric-edge-cases.canonical.bin
├── 06-duplicate-keys.input.json     (parser MUST reject)
├── 07-non-utc-timestamp.input.json  (parser MUST reject)
└── README.md                        (how to run)
```

Independent implementations self-check by JCS-canonicalizing each `.input.json` and comparing the byte output to the corresponding `.canonical.bin`. Cases ending in "MUST reject" assert parse failure.

These fixtures do not exist in the v1 source tree yet (`[TODO]` in `README-todo.md`); the fixture set is mandatory before any second implementation of this spec is considered conformant.

---

## Leaf Signature on the Manifest

The CA-signed checkpoint and the log signature together prove that *some* manifest was logged. They do **not** prove that the rightful publisher submitted it. Without a leaf signature, an attacker who reaches the submission endpoint (network MITM, server compromise, stolen API key) can log any manifest under any package name; the log's signature only certifies that the entry is in the tree.

The fix is to require an end-to-end leaf signature over the canonical manifest, bound to the publisher's identity at the cert layer.

### Manifest fields the leaf signs

The manifest carries a `publisher` block that names the leaf and the scope of authority the leaf claims:

```json
{
  "publisher": {
    "leaf_cert_id": 55,
    "leaf_pubkey_hash": "sha256:a1b2c3...",
    "domain_scope": ["postWolf"]
  }
}
```

- `leaf_cert_id` — the Merkle log index where the leaf certificate was registered. Verifiers fetch the cert from the log to obtain the public key bytes.
- `leaf_pubkey_hash` — SHA-256 of the leaf's ML-DSA-87 public key, as a defence in depth against the leaf cert being substituted at verification time.
- `domain_scope` — the package names (or namespaces, dot-separated) the leaf is authorized to publish for. The CA enforces this at issuance time; the verifier re-checks it.

### What gets signed

The leaf signs `JCS(manifest)` — the canonical bytes of the manifest object including the `publisher` block, with `leaf_signature` itself excluded (the signature can't cover itself). The exact rule:

```
signed_input = JCS({ ... entire manifest object as described in §"Manifest Schema (v2)" ... })
leaf_signature.signature = ML-DSA-87.sign(leaf_priv, signed_input)
```

The `leaf_signature` object lives **outside** the manifest, alongside it in the receipt and in the submission request body. This keeps the manifest object self-contained and re-verifiable independent of any specific signature.

### Verifier flow with leaf signatures

When verifying a receipt, the verifier performs these checks in order. Earlier failures short-circuit later ones.

1. **Parse and canonicalize.** Parse the receipt JSON (rejecting duplicate keys per §"Canonical JSON"). Re-canonicalize the manifest object and confirm the byte sequence matches `leaf_signature.signed_input`.
2. **Leaf signature.** Verify `leaf_signature.signature` over the canonical bytes using the public key from the leaf cert at `manifest.publisher.leaf_cert_id`. Confirm SHA-256 of that public key matches `manifest.publisher.leaf_pubkey_hash`.
3. **Leaf cert chain.** Verify the leaf cert chains to the **pinned** CA (per §"What You Need" → "Pinning is mandatory"), via the leaf cert's own log inclusion proof and CA cosignature.
4. **Domain scope.** Confirm `manifest.publisher.domain_scope` includes `manifest.package`. Reject otherwise — the leaf is not authorized for this package.
5. **Log inclusion + log signature.** Replay the inclusion proof for the manifest's leaf hash up to the root in the receipt; verify the log signature on that root using the log key cert (which itself chains to the pinned CA per §"The Solution").
6. **CA-signed checkpoint.** Verify the covering checkpoint's CA signature against the **pinned** CA key, and confirm `checkpoint.tree_size >= manifest_tree_size_at_inclusion`.
7. **File set + file hashes.** Apply §"Manifest Path Rules" (set equality + per-file SHA-256).
8. **Revocation, freshness** (online mode only — see §"Verifying a Kit End-to-End").

A receipt missing `leaf_signature` is rejected as schema-v1 (older format) with a hard error if `--strict` is set, otherwise with a loud warning. New submissions MUST always include the leaf signature.

### Server policy

To keep the leaf signature meaningful, the MTC server's submission endpoint enforces a defence-in-depth check on top of leaf signature validity:

- Submission MUST be over mTLS. The TLS leaf certificate the client presents MUST match `manifest.publisher.leaf_pubkey_hash` byte-for-byte.
- The TLS-presented cert's `leaf_cert_id` MUST match `manifest.publisher.leaf_cert_id`.
- If either mismatch, the server returns `401 Unauthorized` and does not log the entry.

This means a stolen leaf signing key alone does not let an attacker submit; they also need a TLS handshake under the same key. (Both compromised → defence reduces to the leaf cert revocation timeline.)

---

## Architecture Diagram

```
BUILD MACHINE                         MTC SERVER
==============                         ==========

Source files                           Merkle Tree (append-only)
    |                                      |
    +-- sha256sum each file                |
    |                                      |
    +-- Build manifest JSON                |
    |                                      |
    +-- POST /fips/manifest  ----------->  |
    |                                      +-- Append manifest hash as leaf
    |                                      +-- Compute inclusion proof
    |                                      +-- Sign tree root (ML-DSA-87)
    |                                      |
    +-- Save receipt  <------------------  +-- Return {index, proof, signature}
    |
    +-- Ship receipt with package


VERIFIER (downstream user)             MTC SERVER
==========================             ==========

Source files + receipt
    |
    +-- sha256sum each file
    |
    +-- Compare to receipt manifest
    |       |
    |       +-- MISMATCH? --> FAIL
    |
    +-- [Online] GET /fips/manifest/<index>/proof
    |       |                              |
    |       +-- Verify inclusion proof <---+
    |       +-- Verify ML-DSA-87 signature
    |
    +-- [Offline] Verify proof from receipt
    |       +-- Verify inclusion proof (cached)
    |       +-- Verify ML-DSA-87 signature (cached)
    |
    +-- PASS or FAIL
```

---

## API Reference

### POST /fips/manifest

Submit a FIPS build manifest to the transparency log. The submission MUST include a leaf signature over the canonical manifest (see §"Leaf Signature on the Manifest").

**Request:**
```json
{
  "manifest": {
    "type": "fips-build-manifest",
    "schema_version": 2,
    "package": "postWolf",
    "publisher": {
      "leaf_cert_id": 55,
      "leaf_pubkey_hash": "sha256:a1b2c3...",
      "domain_scope": ["postWolf"]
    },
    "git_commit": "abc123def456...",
    "git_tag": "v5.9.0",
    "timestamp": "2026-04-05T12:34:56Z",
    "expires": "2027-04-05T00:00:00Z",
    "scope_paths": [
      {"prefix": "wolfcrypt/src/", "allow_symlinks": false}
    ],
    "files": [
      {"path": "wolfcrypt/src/aes.c", "sha256": "0e22ea0c..."},
      {"path": "wolfcrypt/src/fips.c", "sha256": "c049a936..."}
    ]
  },
  "leaf_signature": {
    "algorithm": "ML-DSA-87",
    "signed_input": "JCS(manifest)",
    "signature": "<4627-byte ML-DSA-87 signature, hex>"
  }
}
```

The server rejects the submission (HTTP 401) if any of the following hold:

- The TLS leaf certificate presented over mTLS does not match `manifest.publisher.leaf_pubkey_hash`.
- The leaf certificate at index `manifest.publisher.leaf_cert_id` does not exist, has been revoked, or has expired.
- The leaf certificate's `domain_scope` extension does not include `manifest.package`.
- `leaf_signature` does not verify under `wc_dilithium_verify_ctx_msg()` against `JCS(manifest)` and the leaf cert's public key.

**Response (201 Created):**
```json
{
  "index": 42,
  "manifest_hash": "8a7b6c5d...",
  "inclusion_proof": ["a1b2c3...", "d4e5f6..."],
  "subtree_start": 0,
  "subtree_end": 43,
  "subtree_hash": "7f8e9d...",
  "log_signature": {
    "algorithm": "ML-DSA-87",
    "signed_input": "JCS({\"tree_size\":43,\"tree_root\":\"7f8e9d...\",\"timestamp\":\"...\"})",
    "signature": "<4627-byte ML-DSA-87 signature, hex>"
  },
  "covering_checkpoint": {
    "tree_size": 50,
    "tree_root": "9c8d7e...",
    "timestamp": "2026-04-05T13:00:00Z",
    "ca_signature": {
      "algorithm": "ML-DSA-87",
      "signature": "<4627-byte ML-DSA-87 signature, hex>"
    }
  }
}
```

The receipt the publisher ships (`fips-manifest-receipt.json`) is the request body bundled with this response.

### GET /fips/manifest/{index}

Retrieve a stored manifest by log index.

**Response (200 OK):**
```json
{
  "type": "fips-build-manifest",
  "version": 1,
  "package": "postWolf",
  "git_commit": "abc123def456...",
  "git_tag": "v5.9.0",
  "timestamp": 1712188800.0,
  "expires": "2027-04-05T00:00:00Z",
  "files": [
    {"path": "wolfcrypt/src/aes.c", "sha256": "0e22ea0c..."},
    {"path": "wolfcrypt/src/fips.c", "sha256": "c049a936..."}
  ]
}
```

### GET /fips/manifest/{index}/proof

Get a fresh inclusion proof for a manifest (proof path may change as the tree grows).

**Response (200 OK):**
```json
{
  "index": 42,
  "manifest_hash": "8a7b6c5d...",
  "subtree_start": 0,
  "subtree_end": 100,
  "subtree_hash": "1a2b3c4d...",
  "proof": ["a1b2c3...", "d4e5f6...", "g7h8i9..."],
  "cosignature": {
    "signature": "b3c4d5e6f7...",
    "algorithm": "ML-DSA-87"
  }
}
```

### GET /fips/manifest/search?package=X&tag=Y

Search for manifests by package name or git tag.

**Response (200 OK):**
```json
{
  "results": [
    {"index": 42, "package": "postWolf", "git_tag": "v5.9.0", "timestamp": 1712188800.0},
    {"index": 38, "package": "postWolf", "git_tag": "v5.8.0", "timestamp": 1709510400.0}
  ]
}
```

---

## Identifying Legitimate Kit Publishers

### Roles: CA, Leaf, and Kit Publisher

There are three distinct roles in this system:

| Role | What They Do | What They Hold |
|------|-------------|----------------|
| **CA** | Enrolls once via DNS TXT validation. Vouches for leaf identities. Does not publish kits. | ML-DSA-87 key pair; domain control |
| **Leaf (Kit Publisher)** | Receives a certificate from a CA. Builds software, submits FIPS manifests, ships kits. Operates independently after enrollment. | Own key pair; leaf certificate issued by a CA |
| **Verifier (Downstream User)** | Receives a kit. Verifies the source, the leaf's authority, and the CA's legitimacy. | CA public key (obtained out-of-band) |

The **leaf is the kit publisher**. After the CA issues a leaf certificate, the leaf operates independently — it does not need the CA's private key to build, sign manifests, or ship kits. The CA's role ends at enrollment. The leaf's certificate is the proof that "the CA authorized me to publish for this domain."

### How a Kit Gets Published

```
ONE-TIME SETUP                          EACH RELEASE
==============                          ============

CA enrolls via DNS TXT                  Leaf builds postWolf
    |                                       |
    +-- Proves domain control               +-- make && fips-hash.sh && make
    +-- CA cert logged in Merkle tree       |
    |                                       +-- fips-manifest-submit.sh
    v                                       |   (POSTs manifest to MTC server)
CA issues leaf certificate                  |
    |                                       +-- Server logs manifest
    +-- Leaf cert logged in Merkle tree     +-- Server returns receipt
    +-- Leaf receives cert + key pair       |   (index, proof, cosignature)
    |                                       |
    v                                       +-- Leaf ships kit:
Leaf can now publish                            - source tarball
(CA is no longer involved)                      - fips-manifest-receipt.json
                                                - leaf certificate
```

### The Trust Problem

The Merkle tree and ML-DSA-87 cosignatures prove **consistency** — that an entry was logged and hasn't been tampered with. They do not prove **identity** — that the leaf publisher is who they claim to be. That trust comes from the chain: CA vouches for leaf, and the CA's identity is established out-of-band.

A downstream user must answer three questions:
1. **Is this CA legitimate?** — Does the CA actually control the claimed domain?
2. **Is this leaf authorized by the CA?** — Did this CA issue this leaf certificate?
3. **Did this leaf publish this kit?** — Does the FIPS manifest receipt trace back to this leaf?

### CA Identity Verification

These channels are for **first-time acquisition only**. Each legitimate CA must publish its ML-DSA-87 public key through at least one of them, and a verifier uses one (preferably more, cross-checked) to obtain the key on first contact. Once obtained and reviewed, the key MUST be pinned locally per §"What You Need" → "Pinning is mandatory." Subsequent verification reads the pinned file; it does not re-fetch the key from any channel below.

| Channel | Mechanism | Bootstrap strength |
|---------|-----------|--------------------|
| **DNS TXT record** | `_mtc-ca-key.example.com TXT "v=mtc-ca1; pk=ml-dsa-87:<hex>"` | Strong — requires domain control; can be cross-checked from multiple resolvers |
| **Project website** | Published on an HTTPS page the domain owner controls | Moderate — relies on TLS + domain control; vulnerable if site/CDN compromised |
| **Package metadata** | Pinned in `.deb` control file, RPM spec, or `MANIFEST` | Moderate — relies on the OS package signing chain (and is circular if you obtained the package from the same compromised mirror as the FIPS tarball) |
| **Git signed tag** | CA public key committed and signed with maintainer's GPG key | Strong — relies on GPG web of trust; requires verifier to have the maintainer's GPG key already pinned |
| **CMVP certificate** | Public key referenced in NIST CMVP validation documentation | Strongest — relies on NIST's process; only available for CAs whose validated module bundles the FIPS framework |

**None of these channels are usable as a *verification-time* trust source.** A receipt can only be trusted if it chains to a key already in the verifier's pinned set. If the receipt presents a CA key that the verifier has not pinned, the verifier MUST refuse the receipt and require explicit operator action to add the new key (after independent re-verification through one of the bootstrap channels above, ideally cross-checked across two of them).

### Verifying a Kit End-to-End

When a downstream user receives a kit containing source code, a FIPS manifest receipt, and a leaf certificate:

**Step 1: Identify the leaf publisher**

The receipt and leaf certificate identify who published this kit:
```bash
# Who published this kit?
jq '.leaf_subject' fips-manifest-receipt.json
# Example output: "example.com-builder"

# Which CA authorized them?
jq '.cosignature.cosigner_id' fips-manifest-receipt.json
# Example output: "32473.2.ca"
```

**Step 2: Obtain the CA's public key out-of-band (bootstrap channel)**

The CA — not the leaf — is the trust anchor. Get the CA's key independently and pin it locally per §"What You Need" → "Pinning is mandatory":
```bash
# DNS lookup (TXT record carries the pubkey hash; full pubkey is fetched
# separately and verified against the hash)
dig TXT _mtc-ca-key.example.com +short
# Example output: "v=mtc-ca1; alg=ml-dsa-87; pkhash=sha256:a1b2c3d4..."

# Fetch the full 2592-byte pubkey via the URL listed in the TXT record
# (or via package metadata, GPG-signed git tag, etc.) and pin it:
sudo install -o root -m 0644 ca-pubkey.der /etc/postWolf/ca-pubkey/postwolf-ca.der

# Verify the pinned file's SHA-256 matches the TXT record's pkhash:
sha256sum /etc/postWolf/ca-pubkey/postwolf-ca.der
```

ML-DSA-87 public keys are 2592 bytes — too large to inline in a DNS TXT record verbatim. Hence the indirection: TXT carries `pkhash` (SHA-256 of the DER-encoded pubkey), and the actual pubkey ships via a different channel (project website, package metadata, git tag, etc.). The verifier confirms the channel-fetched pubkey hashes to the value in the TXT record.

**Step 3: Verify the CA was enrolled legitimately**

Query the server for the CA's log entry and confirm its public key hash matches the out-of-band key:
```bash
# Search for the CA certificate in the log
curl "$MTC_SERVER/certificate/search?q=example.com-ca"

# Retrieve the CA entry and check the public key hash
curl "$MTC_SERVER/certificate/42" | jq '.tbs_entry.subject_public_key_hash'

# Compare against the hash of the out-of-band public key
echo -n "$MTC_CA_PUBKEY" | sha256sum
```

If the hashes match, the CA enrollment is confirmed authentic.

**Step 4: Verify the leaf was authorized by this CA**

Confirm the leaf certificate was issued under the verified CA:
```bash
# Retrieve the leaf certificate
curl "$MTC_SERVER/certificate/55" | jq '.tbs_entry'

# Verify:
#   - The leaf's subject domain matches the CA's domain
#   - The leaf's inclusion proof is valid
#   - The leaf has CA:FALSE in extensions (it's a leaf, not a CA)
#   - The leaf was issued while the CA was active (not revoked)
```

**Step 5: Check revocation (mandatory in online mode)**

Online verification MUST check that neither the leaf certificate nor the CA itself has been revoked since the receipt was issued. This is not optional and is performed *before* the source-integrity check, so a compromised leaf cannot smuggle a "valid" kit through after revocation.

```bash
# Check if the leaf certificate has been revoked
curl "$MTC_SERVER/revoked/55"
# Returns: {"revoked": false} or {"revoked": true, "reason": "...", "effective_at": "..."}

# Check if the CA itself has been revoked
curl "$MTC_SERVER/revoked/42"
```

If either returns `revoked: true`, online verification fails. The revocation entry's `effective_at` is compared to `manifest.timestamp`: a leaf revoked *after* the manifest was logged still invalidates the receipt for online use, but the receipt is preserved as a historical record. To accept a revoked-cert receipt anyway (forensics, recovery, post-incident replay), pass `--allow-revoked`. The verifier prints a loud warning and records the override in its audit log.

`--allow-revoked` also implicitly forces `--offline` semantics: revocation cannot be checked offline by definition (the receipt cannot know about future revocations), so passing `--allow-revoked` while online is treated as an explicit acknowledgement that the verifier is choosing to ignore the revocation signal.

**Step 6: Verify the kit's source integrity**

Once the leaf publisher is confirmed legitimate, the leaf signature and CA-checkpoint chain check, and the leaf is not revoked, verify the FIPS manifest they submitted:
```bash
./fips-framework/fips-manifest-verify

# The script checks:
#   - Local file set equals the manifest set (per §"Manifest Path Rules")
#   - Local file hashes match the manifest
#   - Inclusion proof is valid (hash chain to root)
#   - Log signature is valid on that root
#   - CA-signed checkpoint covers the root and verifies under the pinned CA key
```

### Trust Hierarchy Summary

```
Out-of-band trust anchor
(DNS TXT / website / GPG / CMVP)
         |
         v
    CA Public Key
    (ML-DSA-87, 2592 bytes — obtained independently)
         |
         v
    CA Enrollment in Merkle Tree
    (logged with DNS TXT validation at enrollment time)
         |
         v
    Leaf Certificate (the kit publisher)
    (issued by the CA; has own key pair; operates independently)
         |
         v
    FIPS Manifest (submitted by the leaf)
    (inclusion proof + cosignature verifiable with CA public key)
         |
         v
    Source File Integrity
    (individual SHA256 hashes in the manifest)
```

### What Each Layer Proves

| Layer | What It Proves | What It Does NOT Prove |
|-------|----------------|----------------------|
| Out-of-band CA key | The CA public key belongs to the claimed organization | That the CA hasn't been compromised |
| DNS TXT validation | The CA operator controlled the domain at enrollment time | That they still control it today |
| Leaf certificate | The CA authorized this publisher to act for this domain | That the leaf hasn't been compromised |
| Merkle inclusion proof | The entry was logged and hasn't been modified | That the entry content is truthful |
| ML-DSA-87 cosignature | The tree root was signed by the CA's private key | That the CA's key hasn't been stolen |
| File SHA256 hashes | Your local files match what was submitted | That the submitted files were correct |
| Consistency proof | The tree has only grown — no entries removed | That future entries will be honest |
| Revocation check | The CA/leaf certificate has not been explicitly revoked | That an unrevoked cert is still trustworthy |

No single layer is sufficient on its own. Together they form a chain where an attacker must compromise multiple independent systems to forge a kit that passes all checks.

### Key Distinction: CA vs. Leaf

The CA **never** touches the kit. The CA's job is done after issuing the leaf certificate. If the CA goes offline, existing leaf publishers continue operating — their certificates and FIPS manifest receipts remain verifiable because the Merkle proofs and cosignatures are self-contained.

This separation means:
- **Compromising a leaf** only affects kits published by that leaf — other leaves under the same CA are unaffected
- **Compromising a CA** affects all leaves under it — but the CA can be revoked, and a new CA enrolled
- **Compromising the MTC server** could allow fake entries, but cannot forge cosignatures from a CA whose private key is held elsewhere

---

## What Gets Downloaded at Verification Time

The kit ships with `fips-manifest-receipt.json`, which is self-contained — it includes the full manifest (every file path and SHA256 hash), the Merkle inclusion proof, and the ML-DSA-87 cosignature. This means verification requires minimal or zero network traffic.

### By Verification Mode

| Mode | Server Contact | What's Downloaded | Typical Size |
|------|---------------|-------------------|--------------|
| **Offline** | None | Nothing — the receipt has everything needed | 0 bytes |
| **Online (standard)** | One GET request | Fresh inclusion proof + current cosignature | ~500 bytes |
| **Online (full audit)** | Two GET requests | Fresh proof + the server's copy of the manifest for comparison | ~5-20 KB |

### What's Already in the Kit

The verification bundle shipped with the kit contains:

```
fips-manifest-receipt.json
├── manifest            The full file list with SHA256 hashes (~5-20 KB)
│   ├── expires         Manifest expiration timestamp
│   ├── git_tag         Version tag for rollback detection
│   └── files[]         Path + SHA256 for each FIPS source file
├── manifest_hash       SHA256 of the canonical manifest (32 bytes)
├── index               The Merkle tree log index (integer)
├── inclusion_proof     Array of sibling hashes for the proof path (~200 bytes)
├── subtree_start       Proof range start (integer)
├── subtree_end         Proof range end (integer)
├── subtree_hash        Root hash of the subtree (32 bytes)
└── cosignature         ML-DSA-87 signature over the subtree hash (4627 bytes)

```

This is everything needed to verify the kit without contacting the server. The verifier:

1. Checks manifest expiration
2. Checks version rollback against local state
3. Computes SHA256 of each local source file
4. Compares against the manifest in the receipt
5. Replays the inclusion proof (hash chain from leaf to root)
6. Verifies the ML-DSA-87 cosignature on the root using pinned CA key

All of this is local computation — no network required.

### When Online Verification Adds Value

Contacting the server provides two additional guarantees that offline mode cannot:

| Check | What It Adds |
|-------|-------------|
| **Fresh proof** | Confirms the entry is still in the tree as it exists *now*, not just when the receipt was created. Catches a theoretical attack where the server operator rolls back the tree after issuing the receipt. |
| **Revocation check** | Confirms the leaf certificate and CA have not been revoked since the kit was published. The receipt cannot know about future revocations. |
| **Consistency proof** | Confirms the tree has only grown since the receipt was issued — no entries removed or rewritten. |

For most users unpacking a kit, **offline verification is sufficient**. Online verification is recommended for high-assurance environments, CI/CD pipelines, or when the kit is more than a few days old and revocation status matters.
