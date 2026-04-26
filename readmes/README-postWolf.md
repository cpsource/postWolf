# postWolf

**postWolf** is the integrated security stack built on wolfSSL that combines
four technologies into a single, defence-in-depth communications layer:

| Layer | Technology | What it does |
|-------|-----------|--------------|
| Transport | **TLS 1.3** | Modern encrypted transport with 0-RTT, forward secrecy, and a simplified handshake |
| Privacy | **ECH** (Encrypted Client Hello) | Encrypts the SNI and other metadata so observers cannot see which site a client is connecting to |
| Post-Quantum | **ML-KEM** (hybrid key exchange) | NIST-standardised lattice-based key encapsulation, run as a hybrid with ECDH so today's traffic is safe even if a quantum computer appears later |
| Trust | **MTC** (Merkle Tree Certificates) | Append-only, auditable certificate log with inclusion and consistency proofs — transparent trust anchored in cryptographic evidence, not blind CA faith |

## Why these four together?

Each layer covers a gap the others leave open:

- **TLS 1.3** secures the channel but leaks the server name in the clear.
  ECH closes that gap.
- **ECDH** key exchange is secure today but vulnerable to harvest-now,
  decrypt-later attacks by future quantum computers.  ML-KEM hybrid
  hedges that risk.
- **Traditional X.509 certificates** depend on trusting CAs not to
  mis-issue.  MTC provides a Merkle-tree-based transparency log where
  any observer can verify that a certificate was legitimately issued
  and has not been tampered with.

Together they provide: encrypted transport + metadata privacy +
post-quantum key exchange + auditable certificate trust.

## Build

The fastest path on a fresh checkout is the top-level driver script,
which configures wolfSSL, builds and installs `libpostWolf`, and then
builds and installs the SLC/MQC/QUIC wrappers plus the MTC tools:

```bash
./make-all.sh
```

### Manual sequence

The driver expands to:

```bash
./configure.sh                       # wolfSSL with TLS13 + ECH + MLKEM + MTC
make -f Makefile                     # library
sudo make -f Makefile install        # installs libpostWolf + postWolf.pc
sudo ldconfig
make -f Makefile.tools               # SLC, MQC, QUIC, MTC tools
sudo make -f Makefile.tools install  # installs mtc_server + helpers
```

The intermediate install is required: MQC, QUIC, and the MTC tools
consume postWolf through `pkg-config`, which only resolves once
`/usr/local/lib/pkgconfig/postWolf.pc` is in place.

If you only need to regenerate the raw configure flags:

```bash
./configure --enable-tls13 --enable-ech --enable-mlkem --enable-mtc --enable-all
```

## Components

### wolfSSL Core (TLS 1.3 + ECH + ML-KEM)

The wolfSSL library provides the TLS transport with ECH and post-quantum
hybrid key exchange built in.  No application code changes are needed
beyond loading an ECH config — if the server advertises ECH, the client
uses it automatically.

Key algorithms supported:
- **Key exchange:** ECDHE (P-256, P-384, X25519) + ML-KEM-512/768/1024 hybrids
- **Signatures:** ECDSA, Ed25519, RSA, ML-DSA-44/65/87
- **Bulk encryption:** AES-128/256-GCM, ChaCha20-Poly1305

### MTC Keymaster (`mtc-keymaster/`)

The Merkle Tree Certificates subsystem, consisting of:

**CA/Log Server** (`mtc-keymaster/server2/c/`) — a fork-after-accept C
server that acts as both Certificate Authority and transparency log:

- Issues certificates (CA and leaf) with Merkle tree inclusion proofs
- Provides consistency proofs between tree states
- ML-DSA-87 cosignatures over subtree ranges
- CA enrollment via DNS TXT record validation (`_mtc-ca.<domain>`)
- Leaf enrollment via nonce-based authorization (CA operator issues nonce)
- PostgreSQL (Neon) persistence with file-based fallback
- Per-IP rate limiting (Redis) and AbuseIPDB abuse screening
- Optional TLS 1.3 with ECH via the socket-level-wrapper

**Python Tools** (`mtc-keymaster/tools/python/`) — client-side tooling:

- `main.py` — CLI for enrollment, verification, trust store management
- `mtc_client.py` — client library for MTC server interaction
- `verify.py` — standalone certificate verification
- `ca_dns_txt.py` — DNS TXT record generation for CA enrollment
- `create_leaf_keypair.py` / `create_server_cert.py` — certificate creation
- `trust_store.py` — local trust anchor management

**Socket Level Wrapper** (`socket-level-wrapper/`) — thin C library (`libslc`)
that wraps wolfSSL TLS into a simple connect/accept/read/write/close API
with ECH support.

## API Endpoints (MTC Server)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Server info |
| GET | `/log` | Tree state (size, root hash, landmarks) |
| GET | `/log/entry/<n>` | Single log entry |
| GET | `/log/proof/<n>` | Merkle inclusion proof |
| GET | `/log/checkpoint` | Latest checkpoint |
| GET | `/log/consistency?old=N&new=M` | Consistency proof |
| GET | `/certificate/<n>` | Certificate by index |
| GET | `/certificate/search?q=` | Search by subject |
| GET | `/trust-anchors` | Trust anchor list |
| GET | `/ca/public-key` | CA ML-DSA-87 public key (PEM) |
| GET | `/revoked` | Signed revocation list |
| GET | `/revoked/<n>` | Revocation check |
| GET | `/ech/configs` | ECH config (base64) |
| POST | `/enrollment/nonce` | Issue enrollment nonce |
| POST | `/certificate/request` | Enroll CA or leaf certificate |
| POST | `/revoke` | Revoke a certificate |

## Enrollment Flow

### CA Enrollment (domain owner)

1. Generate an Ed25519 key pair
2. Create a DNS TXT record at `_mtc-ca.<domain>` with the key fingerprint
3. POST to `/certificate/request` with the CA certificate PEM
4. Server validates DNS, issues the CA certificate with a Merkle proof

### Leaf Enrollment (authorized by CA operator)

1. CA operator requests a nonce: POST `/enrollment/nonce` with `type=leaf`
2. Server verifies a registered CA exists for the domain, returns nonce
3. CA operator gives the nonce to the leaf out-of-band
4. Leaf POSTs to `/certificate/request` with the nonce
5. Server atomically validates and consumes the nonce, issues the certificate

## Post-Quantum Readiness

postWolf addresses both sides of the post-quantum threat:

- **Key exchange:** ML-KEM hybrid protects against harvest-now,
  decrypt-later attacks.  Even if a quantum computer breaks the ECDH
  component in the future, the ML-KEM component keeps the session key safe.
- **Signatures:** The MTC server supports ML-DSA-44/65/87 as certificate
  key algorithms, enabling post-quantum authentication alongside
  traditional ECDSA and Ed25519.

## Documentation

- `README-note-ech.md` — ECH architecture and threat model
- `mtc-keymaster/README-bugsandtodo.md` — MTC development status and roadmap
- `mtc-keymaster/README-clean-install.md` — Installation guide
- `mtc-keymaster/server2/c/README-using-mtc-server.md` — Server usage guide
- `make doxygen` (in `mtc-keymaster/server2/c/`) — generates HTML API docs

## License

postWolf is part of wolfSSL.  See [LICENSING](LICENSING) for details.
