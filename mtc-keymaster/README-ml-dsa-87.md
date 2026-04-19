# MTC and ML-DSA-87: Post-Quantum TLS Without the Bloat

## The Problem

ML-DSA-87 (formerly CRYSTALS-Dilithium) is post-quantum safe, but its
key and signature sizes are enormous compared to classical algorithms:

| Algorithm | Public Key | Signature |
|-----------|-----------|-----------|
| Ed25519   | 32 bytes  | 64 bytes  |
| ECDSA P-256 | 64 bytes | 64 bytes |
| RSA-2048  | 256 bytes | 256 bytes |
| **ML-DSA-87** | **~2.5 KB** | **~4.6 KB** |

In standard TLS 1.3, the server sends its full certificate chain in the
Certificate message. Each certificate contains the full public key and
a CA signature. With ML-DSA-87:

- Server cert: ~2.5 KB pubkey + ~4.6 KB CA signature
- Intermediate CA cert: another ~2.5 KB + ~4.6 KB
- **Certificate message: easily 10-15 KB**

This bloats the handshake, increases latency, and can cause problems
with UDP-based protocols (DTLS, QUIC) where fragmentation is costly.

## What MTC Does

MTC (Merkle Tree Certificates) replaces the traditional certificate chain
with a compact Merkle inclusion proof. The key insight:

**The Merkle tree stores a hash of the public key, not the key itself.**

When the server proves its identity during TLS, it sends:
- A Merkle inclusion proof (a chain of SHA-256 hashes)
- An Ed25519 cosignature over the tree root (64 bytes)

It does NOT send:
- The full certificate chain
- Any ML-DSA-87 signatures for authentication

## Size Comparison

For a Merkle tree with 1 million enrolled leaves:

| | Traditional TLS (ML-DSA-87) | MTC TLS |
|--|---------------------------|---------|
| Auth data in flight | ~10-15 KB | ~700 bytes |
| Signature type | ML-DSA-87 per cert (~4.6 KB each) | Ed25519 over tree root (64 bytes) |
| Public key in flight | Full ML-DSA-87 pubkey (~2.5 KB) | SHA-256 hash (32 bytes) |
| Proof depth | N/A | ~20 hashes x 32 bytes = 640 bytes |

**~20x reduction in authentication overhead.**

## How It Works

### Enrollment (one-time)

1. Generate ML-DSA-87 key pair locally (`create_leaf_keypair.py`)
2. Enroll the public key with the MTC CA server
3. CA adds SHA-256(public key) to the Merkle tree as a leaf
4. CA signs the tree root with Ed25519 (one signature covers all leaves)
5. Client receives an inclusion proof (path from leaf to root)

### TLS Handshake (every connection)

1. Server sends its ML-DSA-87 public key + Merkle inclusion proof
2. Client already has the CA's Ed25519 public key (bootstrapped once)
3. Client verifies:
   - Hash the server's public key → leaf hash
   - Replay the Merkle proof → should reach the signed tree root
   - Verify the Ed25519 cosignature over the root
4. If all checks pass → server identity is authenticated

### What the ML-DSA-87 Key Is Still Used For

The ML-DSA-87 key pair is still used for the TLS key exchange — the
server signs the handshake transcript with its ML-DSA-87 private key
to prove it possesses the key. This signature is part of the TLS
CertificateVerify message and cannot be avoided.

But the **certificate authentication** — proving "this ML-DSA-87 key
belongs to example.com" — goes through the Merkle tree instead of a
traditional CA signature chain. That is where the size savings come from.

## The Tradeoff

| What | How |
|------|-----|
| "This key belongs to example.com" | Merkle proof + Ed25519 cosignature (~700 bytes) |
| "I possess this key" | ML-DSA-87 signature in CertificateVerify (~4.6 KB) |

The CertificateVerify signature is unavoidable — that is the server
proving live possession of the private key. MTC eliminates the cert
chain overhead but not the handshake signature.

Total handshake auth overhead:
- **Traditional**: ~15 KB (cert chain) + ~4.6 KB (CertificateVerify) = ~20 KB
- **MTC**: ~700 bytes (proof) + ~4.6 KB (CertificateVerify) = ~5.3 KB

Still a ~4x improvement, and the cert chain savings compound with
deeper chains (intermediates, cross-signs).

## Workflow

```
1. Generate ML-DSA-87 key pair
   python3 create_leaf_keypair.py --algorithm ML-DSA-87 example.com

2. Enroll with MTC CA
   python3 main.py enroll example.com

3. CA adds leaf to Merkle tree, returns inclusion proof
   Stored in ~/.TPM/example.com/certificate.json

4. TLS server loads key + proof
   slc_cfg_t cfg = { .cert_file = "cert.pem", .key_file = "key.pem", ... };
   slc_ctx_set_mtc(ctx, "factsorlie.com", ca_pubkey, 32);

5. During handshake, server sends:
   - Merkle proof (~700 bytes) instead of cert chain (~15 KB)
   - CertificateVerify with ML-DSA-87 signature (~4.6 KB)
```

## Why Ed25519 for the Tree Root?

The CA signs the Merkle tree root with Ed25519 (not ML-DSA-87) because:

1. The root signature is computed once per batch, not per-connection
2. Ed25519 signatures are 64 bytes vs ML-DSA-87's ~4.6 KB
3. The root signature is verified by every client on every connection
4. Ed25519 verification is fast (~70 microseconds)

This is acceptable because the tree root signature is a **batch
commitment** — it covers all leaves in the tree. A post-quantum
migration path for the root signature (to ML-DSA or SLH-DSA) is
tracked in the post-quantum appendix of README-bugsandtodo.md.

## What Gets Sent During Enrollment

**Only the public key. Never the private key.**

```
~/tmp/
    private_key.pem   ← STAYS HERE. Never leaves your machine.
    public_key.pem    ← This is what you send to the CA.
```

The enrollment flow:

1. Generate ML-DSA-87 key pair locally (stored in `~/tmp/` or `~/.TPM/`)
2. Send the **public key** to the CA server during enrollment
3. CA computes `SHA-256(public_key)` and adds that hash as a Merkle leaf
4. CA returns an inclusion proof — stored in `~/.TPM/<subject>/certificate.json`

The **private key never leaves your machine**. It is only used during
TLS handshakes to sign the CertificateVerify message — proving live
possession of the key to the connecting peer. Nobody else ever sees it.

## Who Sets the CA Private Key in Neon?

The CA server sets it itself, on first startup. You never set it manually.

**`mtc_ca_config` table** stores the CA's Ed25519 private key in two
formats (one per server implementation):

| Key | Set By | Format |
|-----|--------|--------|
| `ca_private_key_pem` | Python server (`server/python/ca.py`) | PEM |
| `ca_private_key_hex` | C server (`server/c/mtc_store.c`) | Hex-encoded DER |

**Flow on first startup:**

1. Server checks `mtc_ca_config` in Neon for an existing key
2. If found → loads it
3. If not found → generates a new Ed25519 key pair
4. Stores the private key in the config table
5. Key persists in Neon across restarts

Both server implementations (Python and C) follow the same pattern. If
they share the same Neon database, they use the same CA identity — the
keys are the same key in different encodings (PEM vs hex DER).

The C server also writes `ca_key.der` to `~/.mtc-ca-data/` as a local
backup. If the DB entry is missing but the file exists, it loads from
disk and re-stores to DB.

## See Also

- `README.md` — MTC system overview
- `README-bugsandtodo.md` — Appendix: Post-Quantum Readiness
- `tools/python/create_leaf_keypair.py` — key generation
- `tools/python/main.py` — enrollment
