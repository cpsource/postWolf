# QUIC + MTC Echo Examples

QUIC echo server and client using **ngtcp2** for QUIC transport and
**wolfSSL** for TLS 1.3, with optional **Merkle Tree Certificate (MTC)**
enrollment and verification via the MTC C API.

## Overview

These examples demonstrate two modes of operation:

1. **X.509 mode** (default fallback) — standard TLS certificates over QUIC
2. **MTC mode** — server enrolls with an MTC CA/Log server to get a
   Merkle Tree Certificate, client verifies the certificate's inclusion
   proof and cosignatures via the MTC CA

The QUIC handshake uses TLS 1.3 in both modes. MTC adds an out-of-band
trust layer: the server's certificate identity is anchored in a Merkle
tree rather than a traditional CA chain.

## Dependencies

| Library | Purpose | Package |
|---------|---------|---------|
| wolfSSL | TLS 1.3 (built with `--enable-quic`) | `libwolfssl-dev` or from source |
| ngtcp2 | QUIC transport (RFC 9000) | `libngtcp2-dev` or from source |
| ngtcp2_crypto_wolfssl | ngtcp2 wolfSSL crypto backend | built with ngtcp2 `--with-wolfssl` |
| libcurl | HTTP client (MTC CA communication) | `libcurl4-openssl-dev` |
| json-c | JSON parsing (MTC API responses) | `libjson-c-dev` |

**wolfSSL must be configured with `--enable-quic`:**

```bash
cd /path/to/wolfssl
./configure --enable-quic --enable-ech --enable-tls13 --enable-mtc --enable-all
make && sudo make install
```

## Build

```bash
cd examples/quic-mtc
make
```

Produces `quic_mtc_server` and `quic_mtc_client`.

## Usage

### X.509 Mode (no MTC CA required)

Terminal 1 — server:
```bash
./quic_mtc_server -p 4500 --no-mtc \
    -c ../../certs/server-cert.pem \
    -k ../../certs/server-key.pem
```

Terminal 2 — client:
```bash
./quic_mtc_client -p 4500 --no-mtc \
    -A ../../certs/ca-cert.pem \
    -m "Hello QUIC+MTC!"
```

### MTC Mode (requires running MTC CA/Log server)

Terminal 1 — server enrolls with MTC CA, then listens for QUIC:
```bash
./quic_mtc_server -p 4500 \
    --ca-url http://localhost:8443 \
    --subject "urn:myorg:quic-server" \
    -c ../../certs/server-cert.pem \
    -k ../../certs/server-key.pem
```

Terminal 2 — client connects, echoes data, verifies MTC cert:
```bash
./quic_mtc_client -p 4500 \
    --ca-url http://localhost:8443 \
    --verify-index 0 \
    -A ../../certs/ca-cert.pem \
    -m "Hello QUIC+MTC!"
```

When the MTC CA is unreachable, both programs fall back to X.509
automatically.

## Server Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p <port>` | UDP listen port | 4500 |
| `-c <cert>` | Server certificate PEM | `certs/server-cert.pem` |
| `-k <key>` | Server private key PEM | `certs/server-key.pem` |
| `--ca-url <url>` | MTC CA/Log server URL | `http://localhost:8443` |
| `--subject <name>` | MTC certificate subject | `urn:quic-mtc:server` |
| `--store <path>` | Local cert store path | `~/.TPM` |
| `--no-mtc` | Disable MTC, use X.509 only | |
| `-h` | Show help | |

## Client Options

| Flag | Description | Default |
|------|-------------|---------|
| `-h <host>` | Server host | `127.0.0.1` |
| `-p <port>` | Server port | 4500 |
| `-A <ca>` | CA certificate PEM | `certs/ca-cert.pem` |
| `-m <msg>` | Message to echo | `Hello QUIC+MTC!` |
| `--ca-url <url>` | MTC CA/Log server URL | `http://localhost:8443` |
| `--verify-index <N>` | MTC cert index to verify | (none) |
| `--no-mtc` | Disable MTC verification | |
| `-?` | Show help | |

## How It Works

### QUIC Transport

Both client and server use ngtcp2 for the QUIC protocol:

1. Client sends UDP Initial packet to server
2. ngtcp2 drives the TLS 1.3 handshake via wolfSSL QUIC callbacks
3. After handshake, client opens a bidirectional stream and sends message
4. Server echoes the data back on the same stream with FIN
5. Client receives echo and verifies match

### MTC Enrollment (Server)

When `--ca-url` is provided and reachable:

1. Server calls `MTC_Connect()` to bootstrap trust with the MTC CA
2. Server calls `MTC_Enroll()` which:
   - Generates an EC-P256 key pair (via wolfcrypt `wc_ecc_make_key`)
   - Stores private/public keys in `{store_path}/{subject}/`
   - Sends certificate request to the CA
   - Receives a Merkle Tree Certificate with inclusion proof
3. The MTC certificate index is printed for client verification
4. The QUIC handshake still uses traditional X.509 for TLS

### MTC Verification (Client)

When `--ca-url` and `--verify-index` are provided:

1. Client calls `MTC_Connect()` to the same CA
2. After the QUIC echo completes, client calls `MTC_Verify()` which:
   - Fetches the inclusion proof from the CA/Log server
   - Checks cosignature validity
   - Checks certificate expiry
3. Reports VALID or INVALID

### Future: Inline MTC in TLS

In a full implementation, the MTC proof would be carried inside the
TLS Certificate message via the `id-alg-mtcProof` signature algorithm
OID, and verification would happen in wolfSSL's `ProcessPeerCerts()`
rather than out-of-band. The OID is registered (`CTC_MTC_PROOF`) but
the inline verification hook is not yet wired.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `quic_mtc_common.h` | ~290 | Shared peer context, QUIC packet I/O, MTC helpers |
| `server.c` | ~240 | QUIC echo server with MTC enrollment |
| `client.c` | ~260 | QUIC echo client with MTC verification |
| `Makefile` | ~20 | Build rules |

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) — QUIC: A UDP-Based Multiplexed and Secure Transport
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
- [draft-ietf-plants-merkle-tree-certs-02](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) — Merkle Tree Certificates
- [draft-ietf-tls-trust-anchor-ids-03](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/) — Trust Anchor Identifiers
- [ngtcp2](https://github.com/ngtcp2/ngtcp2) — QUIC implementation
- [wolfSSL QUIC](../../doc/QUIC.md) — wolfSSL QUIC integration guide
