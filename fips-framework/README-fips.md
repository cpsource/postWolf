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

A compromised log key lets an attacker forge entries and roots **going forward**, but cannot forge a CA checkpoint for any tree state that existed before the compromise. Receipts whose covering checkpoint pre-dates the compromise remain verifiable; receipts whose covering checkpoint post-dates it require an out-of-band re-validation. (Compromise recovery is detailed in §"Key Rotation," which currently still describes the older single-key model and is being rewritten — see `README-fips-issues.md` issue #9.)

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

If the ML-DSA-87 CA key is compromised:
1. Stop the server
2. Delete `ca_key.der` (and the `ca_private_key_hex` row in the DB)
3. Restart the server — it generates a new key
4. Re-submit manifests for any active releases
5. Distribute the new public key to verifiers

Old receipts signed with the compromised key should be considered invalid. The append-only log retains the history, so an auditor can identify which manifests were signed with the old key.

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

What happens:
1. The script reads `fips-manifest-receipt.json` to get the log index
2. It checks the manifest `expires` field — rejects if expired
3. It checks for version rollback (best-effort) — using semver comparison, warns if `git_tag` is older than a previously accepted version for this package; hard-fails under `--strict-rollback`. State is in `/var/lib/mtc-fips/last-verified.json` (preferred) or `~/.config/mtc-fips/last-verified.json` (fallback). See §"Rollback Detection (Best-Effort)" for limitations.
4. It computes SHA256 of every FIPS source file on your local disk
5. It queries `GET /fips/manifest/<index>` from the server
6. It compares each local hash against the server's logged manifest
7. It queries `GET /fips/manifest/<index>/proof` for a fresh inclusion proof
8. It replays the Merkle inclusion proof (SHA-256 hash chain from leaf to root)
9. It verifies the ML-DSA-87 cosignature on the tree root using `wc_dilithium_verify_ctx_msg()` with the pinned CA public key

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

Submit a FIPS build manifest to the transparency log.

**Request:**
```json
{
  "package": "postWolf",
  "git_commit": "abc123def456...",
  "git_tag": "v5.9.0",
  "expires": "2027-04-05T00:00:00Z",
  "files": [
    {"path": "wolfcrypt/src/aes.c", "sha256": "0e22ea0c..."},
    {"path": "wolfcrypt/src/fips.c", "sha256": "c049a936..."}
  ]
}
```

**Response (201 Created):**
```json
{
  "index": 42,
  "manifest_hash": "8a7b6c5d...",
  "inclusion_proof": ["a1b2c3...", "d4e5f6..."],
  "subtree_start": 0,
  "subtree_end": 43,
  "subtree_hash": "7f8e9d...",
  "cosignature": {
    "signature": "b3c4d5e6f7...",
    "algorithm": "ML-DSA-87"
  }
}
```

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

**Step 2: Obtain the CA's public key out-of-band**

The CA — not the leaf — is the trust anchor. Get the CA's key independently:
```bash
# DNS lookup
dig TXT _mtc-ca-key.example.com +short
# Example output: "v=mtc-ca1; pk=ed25519:MCowBQYDK2VwAyEA..."

# Or use a pinned key from local config
export MTC_CA_PUBKEY="MCowBQYDK2VwAyEA..."
```

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

**Step 5: Verify the kit's source integrity**

Now that the leaf publisher is confirmed legitimate, verify the FIPS manifest they submitted:
```bash
./fips-framework/fips-manifest-verify

# The script checks:
#   - Local file hashes match the manifest
#   - Inclusion proof is valid (hash chain to root)
#   - Cosignature is valid (ML-DSA-87 verify with CA public key)
```

**Step 6: Check for revocation (optional)**

```bash
# Check if the leaf certificate has been revoked
curl "$MTC_SERVER/revoked/55"
# Returns: {"revoked": false} or {"revoked": true, "reason": "..."}

# Check if the CA itself has been revoked
curl "$MTC_SERVER/revoked/42"
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
└── cosignature         ML-DSA-87 signature over the subtree hash (64 bytes)

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
