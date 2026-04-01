# MTC Keymaster

Merkle Tree Certificate infrastructure for wolfSSL. Provides a CA/Log
server and client tools for issuing, verifying, and managing MTC
certificates based on
[draft-ietf-plants-merkle-tree-certs-02](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/).

## What This Is

MTC Keymaster is the companion infrastructure for wolfSSL's MTC support.
wolfSSL handles the TLS handshake and Merkle proof verification; this
directory provides the CA/Log server that issues certificates and the
client tools that interact with it.

```
                          +-----------------+
                          |  MTC CA/Log     |
                          |  Server         |
                          |  (port 8443)    |
                          +--------+--------+
                                   |
                    +--------------+--------------+
                    |                             |
             POST /certificate/          GET /log/proof/N
             request                     GET /certificate/N
                    |                             |
            +-------+-------+            +-------+-------+
            |  QUIC Server  |            |  QUIC Client  |
            |  (wolfSSL +   |            |  (wolfSSL +   |
            |   ngtcp2)     |<-- QUIC -->|   ngtcp2)     |
            +---------------+            +---------------+
```

## Directory Structure

```
mtc-keymaster/
  server/
    python/         MTC CA/Log server (Python)
      server.py       HTTP REST API
      ca.py           Certificate Authority + Issuance Log
      merkle.py       Merkle Tree (RFC 9162 Section 2.1)
      db.py           PostgreSQL persistence (Neon)
      client_demo.py  Server-side demo script
    c/              (reserved for C implementation)

  tools/
    python/         MTC client CLI tools (Python)
      main.py         CLI with bootstrap, enroll, verify, monitor commands
      mtc_client.py   Client library (HTTP to server, key generation)
      verify.py       Standalone proof verification (inclusion, consistency, cosignature)
      trust_store.py  Local trust store (cosigner keys, landmark cache)
```

## Prerequisites

Python 3.10+ with:
```bash
pip install cryptography psycopg2-binary
```

A PostgreSQL database (Neon recommended). Set the connection string:
```bash
export MERKLE_NEON="postgresql://user:pass@host/dbname?sslmode=require"
```

## Quick Start

### 1. Start the CA/Log Server

```bash
cd server/python
python3 server.py --port 8443
```

The server initializes the database on first run (creates tables, generates
an Ed25519 CA key pair, seeds the Merkle tree).

### 2. Verify the Server

```bash
curl http://localhost:8443/
```

Returns:
```json
{
  "server": "MTC CA/Log Server",
  "ca_name": "MTC-CA-1",
  "log_id": "32473.1",
  "tree_size": 1
}
```

### 3. Enroll a Certificate (CLI)

```bash
cd tools/python
python3 main.py --server http://localhost:8443 enroll test.example.com
```

This generates an EC-P256 key pair, sends a certificate request to the CA,
and stores the result in `~/.TPM/test.example.com/`.

### 4. Verify a Certificate

```bash
python3 main.py --server http://localhost:8443 verify 1
```

Checks the Merkle inclusion proof, cosignature, and expiry for certificate
index 1.

### 5. Generate X.509 Cert with MTC Proof (for wolfSSL TLS)

```bash
cd ../../examples/quic-mtc
python3 mtc_cert_gen.py --ca-url http://localhost:8443 --index 1
```

Produces `mtc-cert.pem` and `mtc-key.pem` with `id-alg-mtcProof`
(`1.3.6.1.4.1.44363.47.0`) as the signature algorithm. These can be
loaded directly by wolfSSL for TLS 1.3 handshakes over QUIC or TCP.

## Server API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Server info (ca_name, log_id, tree_size) |
| GET | `/log` | Log state (tree size, root hash, landmarks) |
| GET | `/log/entry/<N>` | Individual log entry |
| GET | `/log/proof/<N>` | Inclusion proof with verification |
| GET | `/log/checkpoint` | Latest checkpoint (root hash snapshot) |
| GET | `/log/consistency?old=N&new=M` | Consistency proof between tree sizes |
| POST | `/certificate/request` | Issue a new certificate |
| GET | `/certificate/<N>` | Retrieve issued certificate |
| GET | `/trust-anchors` | List trust anchor IDs |
| GET | `/ca/public-key` | CA's Ed25519 public key |

### Certificate Request Body

```json
{
  "subject": "test.example.com",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "key_algorithm": "EC-P256",
  "validity_days": 90,
  "extensions": {
    "key_usage": "digitalSignature"
  }
}
```

### Certificate Response

```json
{
  "index": 1,
  "standalone_certificate": {
    "tbs_entry": {
      "subject": "test.example.com",
      "not_before": 1774982277.0,
      "not_after": 1782758277.0,
      "subject_public_key_hash": "5db973...",
      "subject_public_key_algorithm": "EC-P256"
    },
    "inclusion_proof": ["96a296...", "66b802..."],
    "subtree_start": 0,
    "subtree_end": 2,
    "subtree_hash": "d03512...",
    "cosignatures": [{
      "cosigner_id": "32473.1.ca",
      "algorithm": "Ed25519",
      "signature": "82a313..."
    }],
    "trust_anchor_id": "32473.1"
  }
}
```

## Client CLI Commands

```
python3 main.py --server URL [command] [args]
```

| Command | Description |
|---------|-------------|
| `bootstrap` | Fetch CA public key and add to local trust store |
| `enroll <subject>` | Generate key pair, request certificate |
| `verify <index>` | Verify certificate by index (proof + cosig + expiry) |
| `monitor` | Check log consistency over time |
| `landmarks` | Fetch and cache landmark subtree hashes |
| `list` | Show local certificates in `~/.TPM` |
| `find <query>` | Search certificates by subject |
| `demo` | Run the full workflow (bootstrap, enroll, verify) |

## Local Storage

Certificates and keys are stored in `~/.TPM/<subject>/`:

```
~/.TPM/
  test.example.com/
    private_key.pem      (mode 0600)
    public_key.pem
    certificate.json     (full MTC cert with proofs)
    index                (certificate index number)
```

The store path is configurable via `--store` flag or
`wolfSSL_MTC_SetStorePath()` in the C API.

## How It Fits Together

1. **CA/Log Server** (`server/python/`) maintains the append-only Merkle
   tree and issues certificates with inclusion proofs and Ed25519
   cosignatures.

2. **Client Tools** (`tools/python/`) enroll certificates, verify proofs,
   and manage the local trust store.

3. **Cert Generator** (`examples/quic-mtc/mtc_cert_gen.py`) wraps MTC
   proof data into X.509 DER/PEM format that wolfSSL can load.

4. **wolfSSL** (`wolfcrypt/src/mtc.c`, `wolfcrypt/src/asn.c`) verifies
   the MTC proof during the TLS handshake when it encounters the
   `id-alg-mtcProof` signature algorithm OID.

5. **QUIC Examples** (`examples/quic-mtc/`) demonstrate the full stack:
   ngtcp2 QUIC transport + wolfSSL TLS 1.3 + MTC certificate verification.

## Standards

- [draft-ietf-plants-merkle-tree-certs-02](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) -- Merkle Tree Certificates
- [draft-ietf-tls-trust-anchor-ids-03](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/) -- Trust Anchor Identifiers
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) -- Certificate Transparency Version 2.0
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) -- QUIC
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) -- TLS 1.3
