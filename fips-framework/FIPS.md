# FIPS Source Integrity Verification Design

## Core Design

Signed Merkle tree system where software kits are integrity-checked without
trusting the distribution server. The key principle:

**TLS authenticates the channel; signed metadata authenticates the artifact.**

## Trust Chain

```
Root CA -> Publisher cert -> Signature -> Merkle root -> File hashes
```

## Three Layers (all required)

| Layer | Protects | Against |
|-------|----------|---------|
| TLS 1.3 (PQ) | Transport | MITM, eavesdropping |
| Merkle tree | Integrity structure | Tampered files |
| Signature (publisher cert) | Authenticity/trust | Compromised server |

## Key Design Decisions

1. **Server is untrusted** -- it is just a content distributor. Even a
   compromised server cannot forge a valid kit without the publisher's
   private key.

2. **Publisher gets a leaf cert** (digitalSignature / code signing) -- CA
   certs only establish *who is allowed*, not *what was signed*. Using CA
   keys directly to sign kits blurs roles and makes compromise total.

3. **Verifiers (end users) do not need their own certs** -- they only need
   the trusted root CA and the publisher's public cert. Verification is
   read-only.

4. **No per-file server checks** -- once you have the signed Merkle root,
   all verification is offline and deterministic.

5. **Signed Merkle root replaces "checksum of checksums"** -- eliminates
   the recursion problem entirely.

## Certificate Hierarchy

| Role | What it says | Usage |
|------|-------------|-------|
| Root / CA | "I trust this identity" | Signs intermediate certs, rarely used (offline) |
| Intermediate / Publisher CA | "This user may release kits" | Issues certs to kit publishers |
| Kit Release Leaf | "I created THIS kit" | Signs Merkle root / manifest |

Leaf cert should be scoped for signing, not TLS:
- Key usage: `digitalSignature`
- Extended usage: code signing / content signing

## Kit Bundle Layout

```
kit.tar
  files/...
  manifest.json        # Merkle root + metadata
  manifest.sig         # signature over manifest
  publisher.crt        # leaf cert
  chain.pem            # intermediate(s)
  proof_<file>.json    # Merkle proof per file (or bundled)
```

## Manifest Format

```json
{
  "merkle_root": "...",
  "created_at": "...",
  "kit_name": "...",
  "version": "...",
  "publisher": "...",
  "expires": "..."
}
```

The `expires` and `version` fields protect against replay / downgrade attacks.

## Verification Flow (3 steps)

### Step 1 -- Verify the certificate chain
```bash
openssl verify -CAfile rootCA.pem -untrusted chain.pem publisher.crt
```
Ensures publisher is trusted and cert chain is valid.

### Step 2 -- Verify the signature on the manifest
```bash
openssl dgst -sha256 \
  -verify <(openssl x509 -in publisher.crt -pubkey -noout) \
  -signature manifest.sig \
  manifest.json
```
Ensures manifest (Merkle root) was signed by publisher.

### Step 3 -- Verify files via Merkle proof
```python
import hashlib, json, sys

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def verify_proof(file_path, proof, expected_root):
    with open(file_path, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    for step in proof:
        if step["position"] == "left":
            h = sha256(bytes.fromhex(step["hash"]) + bytes.fromhex(h))
        else:
            h = sha256(bytes.fromhex(h) + bytes.fromhex(step["hash"]))
    return h == expected_root
```

Ensures each file matches the signed Merkle root. Fully offline.

## Security Properties

Even if the server is compromised, it can only:
- Send wrong files -- detected (hash mismatch)
- Send wrong proofs -- detected (Merkle mismatch)
- Send wrong root -- detected (signature fails)

It **cannot** forge a valid kit without the publisher's private key.

## What the Verifier Needs

| Action | Needs private key? |
|--------|-------------------|
| Publish kit | Yes |
| Verify kit | No |

The average user only needs:
- A trusted root (or pinned publisher key)
- The publisher's public key (via cert)

They do **not** need their own leaf certificate.

## Optional Improvements

- **TUF-style role separation**: root keys (very protected), targets/release
  keys (publishers), timestamp keys (freshness)
- **Certificate transparency / audit log** for publisher certs
- **Flat hash list** as simpler alternative to per-file Merkle proofs

---

## Appendix A: TUF (The Update Framework) Role Separation

**TUF** = The Update Framework -- a security framework designed by NYU for
software update systems. Used in production by Docker, Python/PyPI, and
Rust/crates.io.

The core idea is **role separation** -- different keys for different jobs, so
that compromise of any single key has limited blast radius.

### TUF Roles

| Role | Purpose | Protection Level |
|------|---------|-----------------|
| **Root** | Defines who holds other keys | Offline, highest security |
| **Targets** | Signs actual release artifacts | Your publisher leaf certs |
| **Snapshot** | Signs current state of all targets | Prevents mix-and-match attacks |
| **Timestamp** | Signs freshness proof | Short-lived, prevents freeze/replay |

### Why It Matters

Even if an attacker steals the Targets key, they cannot:
- Redefine who is trusted (Root key required)
- Replay old versions (Timestamp key required)
- Mix artifacts from different releases (Snapshot key required)

Each key compromise has limited blast radius.

### Mapping to This Design

| TUF Role | Equivalent in Our System |
|----------|-------------------------|
| Root | Root CA (offline) |
| Targets | Publisher leaf cert (signs Merkle root) |
| Snapshot | Not yet implemented |
| Timestamp | Not yet implemented |

The Merkle tree design already covers the **Targets** role. Adding Snapshot
and Timestamp layers would provide freeze/replay attack protection on top of
the existing integrity and authenticity guarantees.

### Glossary

- **PQ (Post-Quantum)**: TLS 1.3 with hybrid key exchange adding a
  quantum-resistant algorithm (e.g., ML-KEM/Kyber) alongside classical ECDHE.
  Protects against future quantum computers breaking today's key exchanges.
- **Freeze attack**: Attacker replays an old (valid) signed manifest to
  prevent the user from seeing a newer version.
- **Mix-and-match attack**: Attacker combines files from different valid
  releases into an inconsistent kit.

### TUF References

There is no RFC for TUF. The key resources are:

- **Overview**: https://theupdateframework.io/overview/
- **Full spec**: https://theupdateframework.github.io/specification/latest/
- **Spec source**: https://github.com/theupdateframework/specification
