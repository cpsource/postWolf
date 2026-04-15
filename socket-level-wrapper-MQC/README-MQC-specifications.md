# MQC (Merkle Quantum Connect) Specification

## What is MQC?

MQC is a post-quantum authenticated encrypted connection protocol that
replaces TLS 1.3 + X.509 certificates with:

- **ML-KEM-768** key exchange (post-quantum key encapsulation)
- **ML-DSA-87** signed authentication (post-quantum digital signatures)
- **Merkle tree** proof verification (transparency log, no certificate chains)
- **AES-256-GCM** session encryption

No TLS. No X.509. No public keys on the wire. Peers identify each other
by `cert_index` — an integer referencing their entry in the Merkle
transparency log. Public keys are resolved from the log on demand and
cached locally.

## How It Works

### Signed Key Exchange (1 Round Trip)

Each side sends its `cert_index` + an ephemeral ML-KEM key + an ML-DSA-87
signature over that key. The signature proves identity (verified against
the Merkle-authenticated public key). The ML-KEM exchange produces a
shared secret for session encryption.

Authentication and key exchange happen simultaneously in a single message
each direction.

### Peer Key Resolution

When you receive a `cert_index` you haven't seen before:

1. Check local cache: `~/.TPM/peers/<index>/certificate.json`
2. If cache miss: `GET /certificate/<index>` from the MTC server
3. Verify Merkle inclusion proof against the log's root hash
4. Verify Ed25519 cosignature from the CA
5. Check revocation status
6. Check validity period
7. Cache the verified cert for next time

Subsequent connections to the same peer hit the cache — zero network
overhead.

## Protocol Diagram

```
NodeA (Client)                          NodeB (Server)
--------------                          --------------

1. Generate ephemeral ML-KEM keypair
2. Sign ML-KEM encaps key with
   own ML-DSA-87 private key

            -------- Step 1 -------->
            {
              "cert_index": 72,
              "mlkem_encaps_key": "<1184 bytes hex>",
              "signature": "<4627 bytes hex>"
            }

                                        3. Look up NodeA's public key
                                           (cache or MTC server fetch)
                                        4. Verify Merkle proof + cosignature
                                        5. Verify NodeA's signature over
                                           the encaps key
                                        6. ML-KEM encapsulate with NodeA's
                                           encaps key -> ciphertext + shared secret
                                        7. Sign ciphertext with own
                                           ML-DSA-87 private key

            <------- Step 2 ---------
            {
              "cert_index": 73,
              "mlkem_ciphertext": "<1088 bytes hex>",
              "signature": "<4627 bytes hex>"
            }

8. Look up NodeB's public key
   (cache or MTC server fetch)
9. Verify Merkle proof + cosignature
10. Verify NodeB's signature over
    the ciphertext
11. ML-KEM decapsulate -> shared secret
12. Derive AES-256-GCM key via HKDF

                                        12. Derive AES-256-GCM key via HKDF
                                            (same shared secret)

            ===== Encrypted Channel =====
            All further traffic encrypted
            with AES-256-GCM using the
            ML-KEM-derived session key.
```

## Wire Format

### Handshake Messages (JSON over TCP)

Each handshake message is a single JSON object terminated by `}`.
The receiver reads bytes until brace depth returns to zero.

**Client -> Server (Step 1):**
```json
{
  "cert_index": 72,
  "mlkem_encaps_key": "a3f8b2c1d4e5...",
  "signature": "728f2fc9eb96..."
}
```

**Server -> Client (Step 2):**
```json
{
  "cert_index": 73,
  "mlkem_ciphertext": "5db4abcd5312...",
  "signature": "23f060265819..."
}
```

### Application Data (after handshake)

Every message is length-prefixed + AES-256-GCM encrypted:

```
[4 bytes: network-order length N]
[N bytes: AES-256-GCM ciphertext]
    = [12-byte nonce (derived from sequence number)]
    + [encrypted payload]
    + [16-byte GCM auth tag]
```

The GCM nonce is derived from a per-connection sequence number
(incremented per message) to ensure uniqueness without transmitting it.

## Security Properties

| Attack | Status | Rationale |
|--------|--------|-----------|
| **MITM** | SAFE | Attacker can't sign ephemeral keys without ML-DSA-87 private key |
| **Replay** | SAFE | Ephemeral ML-KEM keys are fresh per connection |
| **Impersonation** | SAFE | Requires victim's private key; public key bound to cert_index via Merkle tree |
| **Harvest now, decrypt later** | SAFE | ML-KEM is quantum-resistant |
| **Compromised MTC server** | PARTIALLY SAFE | Can't forge cosignatures without CA key; if both MTC server + CA key compromised, fake certs possible |
| **DoS** | VULNERABLE | PQ operations are expensive; rate limit connections |
| **Downgrade** | N/A | Single protocol version, no negotiation |
| **Metadata leakage** | PARTIAL | cert_index sent in plaintext during handshake; reveals who is connecting to whom |

## API Reference

### Types

```c
typedef struct mqc_ctx  mqc_ctx_t;   /* Opaque context handle */
typedef struct mqc_conn mqc_conn_t;  /* Opaque connection handle */

typedef enum {
    MQC_CLIENT,
    MQC_SERVER
} mqc_role_t;

typedef struct {
    mqc_role_t  role;           /* MQC_CLIENT or MQC_SERVER */
    const char *tpm_path;       /* ~/.TPM/<domain> — our identity */
    const char *mtc_server;     /* MTC server (e.g., "localhost:8444") */
    const unsigned char *ca_pubkey;  /* CA Ed25519 cosigner public key */
    int ca_pubkey_sz;           /* Size of ca_pubkey (typically 32) */
} mqc_cfg_t;
```

### Context Management

| Function | Description |
|----------|-------------|
| `mqc_ctx_t *mqc_ctx_new(const mqc_cfg_t *cfg)` | Create MQC context. Loads identity from tpm_path. Returns NULL on failure. |
| `void mqc_ctx_free(mqc_ctx_t *ctx)` | Free context and zero key material. |

### Connection Lifecycle

| Function | Description |
|----------|-------------|
| `mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port)` | TCP connect + MQC handshake (client side). Returns authenticated encrypted connection or NULL. |
| `int mqc_listen(const char *host, int port)` | Create TCP listening socket. Pure POSIX, no crypto. Returns fd or -1. |
| `mqc_conn_t *mqc_accept(mqc_ctx_t *ctx, int listen_fd)` | TCP accept + MQC handshake (server side). Returns authenticated encrypted connection or NULL. |

### I/O

| Function | Description |
|----------|-------------|
| `int mqc_read(mqc_conn_t *conn, void *buf, int sz)` | Read and decrypt data. Returns bytes read, 0 on close, -1 on error. |
| `int mqc_recv(mqc_conn_t *conn, void *buf, int sz)` | Alias for mqc_read. |
| `int mqc_write(mqc_conn_t *conn, const void *buf, int sz)` | Encrypt and send data. Returns bytes written, -1 on error. |
| `int mqc_send(mqc_conn_t *conn, const void *buf, int sz)` | Alias for mqc_write. |

### Cleanup and Utility

| Function | Description |
|----------|-------------|
| `void mqc_close(mqc_conn_t *conn)` | Close connection, zero session keys, free resources. |
| `int mqc_get_fd(mqc_conn_t *conn)` | Get raw file descriptor for select/poll. |
| `int mqc_get_peer_index(mqc_conn_t *conn)` | Get peer's cert_index (after handshake). |

## Configuration

### mqc_cfg_t Fields

| Field | Required | Description |
|-------|----------|-------------|
| `role` | Yes | `MQC_CLIENT` or `MQC_SERVER` |
| `tpm_path` | Yes | Path to `~/.TPM/<domain>/` containing `certificate.json` + `private_key.pem` |
| `mtc_server` | Yes | MTC CA server for peer key resolution (e.g., `"localhost:8444"`) |
| `ca_pubkey` | Yes | CA's Ed25519 public key (32 bytes) for cosignature verification |
| `ca_pubkey_sz` | Yes | Size of ca_pubkey |

### TPM Directory Layout

**Our identity:**
```
~/.TPM/<domain>/
    certificate.json    # MTC certificate (cert_index, Merkle proof, cosignature)
    private_key.pem     # ML-DSA-87 private key
    public_key.pem      # ML-DSA-87 public key
```

**Peer cache (populated automatically):**
```
~/.TPM/peers/<cert_index>/
    certificate.json    # peer's MTC certificate from server
    checkpoint.json     # tree state at verification time
```

## Example Usage

### Client

```c
#include "mqc.h"

int main(void)
{
    mqc_cfg_t cfg = {0};
    cfg.role       = MQC_CLIENT;
    cfg.tpm_path   = "/home/user/.TPM/factsorlie.com";
    cfg.mtc_server = "localhost:8444";
    cfg.ca_pubkey  = ca_ed25519_key;
    cfg.ca_pubkey_sz = 32;

    mqc_ctx_t *ctx = mqc_ctx_new(&cfg);

    mqc_conn_t *conn = mqc_connect(ctx, "peer.example.com", 4433);
    if (!conn) { /* handshake failed */ }

    mqc_write(conn, "Hello MQC!", 10);

    char buf[256];
    int n = mqc_read(conn, buf, sizeof(buf));

    mqc_close(conn);
    mqc_ctx_free(ctx);
}
```

### Server

```c
#include "mqc.h"

int main(void)
{
    mqc_cfg_t cfg = {0};
    cfg.role       = MQC_SERVER;
    cfg.tpm_path   = "/home/user/.TPM/factsorlie.com-ca";
    cfg.mtc_server = "localhost:8444";
    cfg.ca_pubkey  = ca_ed25519_key;
    cfg.ca_pubkey_sz = 32;

    mqc_ctx_t *ctx = mqc_ctx_new(&cfg);
    int fd = mqc_listen(NULL, 4433);

    for (;;) {
        mqc_conn_t *conn = mqc_accept(ctx, fd);
        if (!conn) continue;

        char buf[256];
        int n = mqc_read(conn, buf, sizeof(buf));
        mqc_write(conn, buf, n);  /* echo */

        mqc_close(conn);
    }

    mqc_ctx_free(ctx);
}
```

## Comparison with TLS 1.3

| Feature | TLS 1.3 | MQC |
|---------|---------|-----|
| Round trips | 1-2 | 1 |
| Certificate on wire | Full X.509 cert (~2.8KB for ML-DSA-87) | cert_index integer (~10 bytes) |
| Key exchange | ECDHE or ML-KEM hybrid | ML-KEM-768 |
| Authentication | X.509 certificate chain | Merkle proof + cosignature |
| Post-quantum key exchange | Optional (hybrid only) | Native (ML-KEM-768) |
| Post-quantum signatures | Requires ML-DSA cert in X.509 wrapper | Native ML-DSA-87 |
| Public key resolution | Sent in handshake | Fetched from Merkle log (cached) |
| Repeat connection overhead | Full cert every time | Zero (cache hit) |
| Dependencies | Full TLS stack (wolfSSL ~500KB) | wolfSSL crypto only (~100KB) |
| X.509 required | Yes | No |

## Cryptographic Algorithms

| Purpose | Algorithm | Standard | Key/Output Size |
|---------|-----------|----------|-----------------|
| Key exchange | ML-KEM-768 | FIPS 203 | 1184B pub / 1088B ct / 32B secret |
| Authentication | ML-DSA-87 | FIPS 204 | 2592B pub / 4627B sig |
| Session encryption | AES-256-GCM | FIPS 197 + SP 800-38D | 32B key / 12B nonce / 16B tag |
| Key derivation | HKDF-SHA256 | RFC 5869 | Variable |
| Merkle proofs | SHA-256 | FIPS 180-4 | 32B hash |
| Cosignatures | Ed25519 | RFC 8032 | 32B pub / 64B sig |
