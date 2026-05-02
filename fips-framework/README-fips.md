# FIPS Source Integrity Verification via MTC Transparency Log

## The Problem

Traditional FIPS source checksum systems (like OpenSSL's `fips-sources.checksums`) store SHA256 hashes of source files **in the same repository** as the source code. An attacker with write access to the repository can modify a source file and update its checksum simultaneously. Nothing downstream detects the tampering — the checksums are self-referential.

## The Solution

postWolf anchors FIPS source checksums in an **external, append-only Merkle Tree transparency log** maintained by the MTC server. At build time, a manifest of every FIPS source file's SHA256 hash is submitted to the server, which logs it into the Merkle tree and signs the tree root with ML-DSA-87. The manifest cannot be altered after submission without detection, because:

1. The Merkle tree is append-only — modifying a leaf changes the root hash
2. The tree root is signed with the server's ML-DSA-87 private key — forging a signature requires compromising the server
3. A receipt (inclusion proof + signature) ships with the package — verification works offline

---

## For Administrators

### Prerequisites

- The MTC C server (`mtc-keymaster/server2/c/mtc_server`) built and running
- PostgreSQL (Neon) database configured, or a local data directory for file-based storage
- `jq` and `curl` installed on the build machine

### Initial Server Setup

```bash
# Build the MTC server
cd mtc-keymaster/server2/c
make

# Start the server (first run generates an ML-DSA-87 CA key automatically)
./mtc_server --port 8080 --datadir /var/lib/mtc-fips

# The server prints the CA public key on startup — record it:
#   CA public key: MCowBQYDK2VwAyEA<base64>...
# This key is needed by verifiers for offline checks.
```

The server stores:
- `ca_key_mldsa.der` — ML-DSA-87 private key (keep this secure)
- `entries.json` — all Merkle tree entries (file-based fallback)
- `fips_manifests.json` — FIPS manifest metadata
- PostgreSQL tables if `MERKLE_NEON` is configured

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
- The `fips-manifest-receipt.json` file (shipped with the release — contains manifest, inclusion proof, and ML-DSA-87 cosignature)
- The `fips-manifest-verify` tool (built from `fips-framework/`, linked against wolfCrypt)
- The CA ML-DSA-87 public key (2592 bytes — published on the project website, DNS TXT record, or pinned in `fips-framework/config/ca-pubkey.h`)

No OpenSSL or shell dependencies (`curl`, `jq`) are required. All
cryptographic verification (SHA-256, ML-DSA-87 signature, Merkle proof replay)
uses wolfCrypt natively.

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
3. It checks for version rollback — warns if `git_tag` is older than a previously accepted version for this package (state tracked in `~/.config/mtc-fips/last-verified.json`)
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

### Offline Verification

Offline verification uses the cached inclusion proof and cosignature from the receipt file. No network access is required — only the CA's ML-DSA-87 public key.

```bash
# Set the CA public key (obtain from project website or pinned config)
export MTC_CA_PUBKEY="MCowBQYDK2VwAyEA..."

# Verify without contacting the server
./fips-framework/fips-manifest-verify --offline
```

What happens:
1. The script reads `fips-manifest-receipt.json` (contains the manifest, proof, and signature)
2. It checks the manifest `expires` field — rejects if expired
3. It checks for version rollback against local state
4. It computes SHA256 of every FIPS source file on your local disk
5. It recomputes the manifest hash from local files and compares to the receipt's manifest hash
6. It replays the inclusion proof: walks the hash chain from the leaf hash up to the root
7. It verifies the ML-DSA-87 cosignature on the root using the pinned CA public key (`wc_dilithium_verify_ctx_msg()`)

If any source file has been modified since the manifest was submitted, the local manifest hash will differ from the receipt's manifest hash, and verification fails.

### What Each Check Proves

| Check | What It Proves |
|-------|----------------|
| Manifest not expired | The kit is still within its validity period |
| Publisher log entry valid | The publisher was enrolled by the CA and their leaf is in the Merkle tree |
| Version rollback check | This is not an older version than one you previously accepted |
| Local SHA256 matches manifest | Your source files are identical to what was submitted to the server |
| Inclusion proof is valid | The manifest was genuinely logged in the Merkle tree at the claimed index |
| ML-DSA-87 cosignature is valid | The Merkle tree root was signed by the CA's private key — not forged |
| Consistency proof (optional) | The tree has only grown since the manifest was logged — no entries removed or rewritten |

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

The offline mode uses the receipt's cached proof. As long as you trust the CA public key, this is equally secure.

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

Each legitimate CA must publish its ML-DSA-87 public key through at least one independent channel that the CA operator controls. A verifier obtains the key through that channel and pins it locally.

| Channel | Mechanism | Strength |
|---------|-----------|----------|
| **DNS TXT record** | `_mtc-ca-key.example.com TXT "v=mtc-ca1; pk=ed25519:<hex>"` | Strong — requires domain control; can be verified programmatically |
| **Project website** | Published on an HTTPS page the domain owner controls | Moderate — relies on TLS + domain control |
| **Package metadata** | Pinned in `.deb` control file, RPM spec, or `MANIFEST` | Moderate — relies on package signing chain |
| **Git signed tag** | CA public key committed and signed with maintainer's GPG key | Strong — relies on GPG web of trust |
| **CMVP certificate** | Public key referenced in NIST CMVP validation documentation | Strongest — relies on NIST's process |

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
