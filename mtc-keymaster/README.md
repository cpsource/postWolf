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
| POST | `/revoke` | Revoke a certificate by index |
| GET | `/revoked` | Full revocation list (signed by CA) |
| GET | `/revoked/<N>` | Check if specific index is revoked |

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
| `revoke <index>` | Revoke a certificate by log index |
| `check-revoked <index>` | Check if an index is revoked |
| `list-revoked` | Show all revoked indices |

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

---

## Appendix: Why MTC?

Two parties can talk over QUIC + TLS 1.3 without MTC — regular X.509
certs or even pre-shared keys work fine. MTC solves a different problem:
**how do you trust the cert the server presents when the parties don't
know each other in advance?**

### Traditional X.509

- You need a CA that both parties trust
- The CA signs the server's cert
- The client checks that signature chain

### MTC

- Trust comes from a Merkle tree log instead of a CA signature
- Useful when you want **transparency** (anyone can audit the log)
- Useful for **post-quantum** (Merkle proofs are small even with PQ,
  unlike PQ signatures which are huge)
- Useful for **short-lived certs** at scale (47-day certs x millions
  of domains)

For two parties that already trust each other — like your own client
and server — you don't need MTC. You could pre-share a self-signed
cert, use a PSK, or pin a public key. MTC matters when operating at
**web scale** with parties that don't know each other and need a
public trust mechanism.

### What Gets Downloaded by Whom

When two parties don't trust one another:

**Before any connection:**

1. **Server** enrolls with an MTC CA — gets a certificate anchored in
   the Merkle tree, stored in `~/.TPM/{subject}/`
2. **Client** bootstraps trust with the same MTC CA — fetches the CA's
   public key and log state

**During the QUIC/TLS handshake:**

3. **Server** presents its MTC certificate (the Merkle proof is in the
   signature field)
4. **Client** verifies the proof — checks that the cert is in the
   Merkle tree

**What each side needs:**

| Party | Has | Got it from |
|-------|-----|-------------|
| Server | Private key + MTC cert | MTC CA (enrollment) |
| Client | CA's public key + log state (tree root, landmarks) | MTC CA (bootstrap) |

**The trust model:**

- The client doesn't trust the server directly
- The client trusts the **MTC CA's log** — it's append-only, auditable
- The server's cert is provably in that log (Merkle inclusion proof)
- The CA can't secretly issue certs without them appearing in the log
  (that's the transparency guarantee)

Both parties download from the MTC CA, but different things. The server
gets its cert, the client gets the trust anchor (CA public key + tree
state) to verify it. This is similar to web PKI today — the server
gets a cert from Let's Encrypt, your browser trusts Let's Encrypt's
root CA. The difference is MTC makes the CA's behavior auditable via
the Merkle tree.

---

## Appendix B: Reconnecting Parties

When two parties have communicated before and want to connect again,
the flow is shorter.

**First connection:**
1. Server enrolls with MTC CA (gets cert + key)
2. Client bootstraps trust with MTC CA (gets CA key + tree state)
3. TLS handshake + Merkle proof verification

**Subsequent connections:**
1. TLS handshake + Merkle proof verification

Both sides already have what they need:

- **Server** still has its cert and key in `~/.TPM/{subject}/` — no
  re-enrollment unless the cert expired
- **Client** already has the CA's public key and cached tree state in
  its local trust store — no re-bootstrap needed

The only thing that might change is the client periodically refreshing
the tree state (new root hash, new landmarks) to verify newer
certificates. But for verifying the same server's cert, the cached
state is sufficient.

This is the same as how browsers work — you don't re-download the
Let's Encrypt root CA every time you visit a website. You already
have it.

---

## Appendix C: When Is ~/.TPM Read?

`~/.TPM` is not reloaded on each connection. It is read **once** at
server startup.

1. **Enrollment** (one-time setup, before any connections) —
   `MTC_Enroll` creates the files in `~/.TPM/{subject}/`
2. **Server starts** — `wolfSSL_CTX_use_MTC_certificate()` reads
   `private_key.pem` and `certificate.json` from disk, builds the
   DER cert in memory
3. **All connections** — use the in-memory cert, no disk I/O

`~/.TPM` is only touched again if:
- The cert expires and you re-enroll (`MTC_Renew`)
- You restart the server process

---

## Appendix D: What Gets Downloaded and Where Is It Stored?

### Server Side (Enrollment)

| What | Source | Stored at |
|------|--------|-----------|
| EC-P256 private key | Generated locally | `~/.TPM/{subject}/private_key.pem` |
| EC-P256 public key | Generated locally | `~/.TPM/{subject}/public_key.pem` |
| MTC certificate JSON (inclusion proof, cosignatures, trust anchor ID) | HTTP POST to MTC CA `/certificate/request` | `~/.TPM/{subject}/certificate.json` |
| Certificate index | From the CA response | `~/.TPM/{subject}/index` |

### Client Side (Bootstrap)

| What | Source | Stored at |
|------|--------|-----------|
| CA's Ed25519 public key | HTTP GET to MTC CA `/ca/public-key` | Local trust store (JSON) |
| Log ID, tree size, root hash | HTTP GET to MTC CA `/log` | Local trust store |
| Landmark subtree hashes (optional) | HTTP GET to MTC CA `/log` | Local trust store |

The Python client tools (`tools/python/trust_store.py`) write the
trust state to a local JSON file. In the C examples, `MTC_Verify()`
currently hits the CA's HTTP API at runtime rather than caching —
a production implementation would cache the CA public key and tree
state locally (like a browser's root CA store) and only refresh
periodically.

### What Happens on Each Connection

| When | Server does | Client does |
|------|-------------|-------------|
| Enrollment (once) | POSTs to CA, saves cert + keys to `~/.TPM` | — |
| Bootstrap (once) | — | GETs CA public key + tree state, caches locally |
| Every connection | Presents in-memory MTC cert | Verifies Merkle proof against cached tree state |
| Cert expiry | Re-enrolls (`MTC_Renew`) | Refreshes tree state |
| Revocation | — | Loads revocation list, rejects revoked indices |

---

## Appendix E: Revocation

MTC certificates are revoked by **log index**, not serial number. The
CA maintains a list of revoked indices. Clients load this list and
reject any certificate whose log index appears in it.

### Server Side

The MTC CA server provides revocation endpoints:

```bash
# Revoke a certificate
curl -X POST http://localhost:8444/revoke \
  -H "Content-Type: application/json" \
  -d '{"cert_index": 1, "reason": "key compromise"}'

# Get the full revocation list (signed by CA)
curl http://localhost:8444/revoked

# Check a specific index
curl http://localhost:8444/revoked/1
```

The revocation list is signed by the CA's Ed25519 key to prevent
tampering. It is persisted to both PostgreSQL (Neon) and local files.

### Client Side (wolfSSL)

```c
WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());

/* Mark specific indices as revoked */
wolfSSL_MTC_RevokeIndex(ctx, 1);
wolfSSL_MTC_RevokeIndex(ctx, 42);

/* Or load a batch from the CA's revocation list */
unsigned int revoked[] = {1, 42, 100};
wolfSSL_MTC_LoadRevocationList(ctx, revoked, 3);

/* Now any TLS handshake with a cert at index 1, 42, or 100
 * will fail with CRL_CERT_REVOKED */
```

### How It Works Internally

During the TLS handshake in `ProcessPeerCerts()`:
1. wolfSSL detects the `id-alg-mtcProof` signature algorithm
2. Parses the MTC proof to extract the certificate's log index
3. Checks the index against the `MtcRevocationList` in `WOLFSSL_CTX`
4. If found, returns `CRL_CERT_REVOKED` and the handshake fails

### QUIC+MTC Example

```bash
# Server uses MTC cert (index 1)
./quic_mtc_server -p 4500 --no-mtc -c mtc-cert.pem -k mtc-key.pem

# Client rejects index 1 — handshake fails
./quic_mtc_client -p 4500 --no-mtc -A mtc-ca.pem --revoke-index 1

# Client without revocation — handshake succeeds
./quic_mtc_client -p 4500 --no-mtc -A mtc-ca.pem -m "hello"
```
