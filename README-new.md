# postWolf

**postWolf** extends [wolfSSL](https://www.wolfssl.com/) into a
post-quantum-ready socket layer. It is an implementation of **Merkle
Tree Certificates**
([draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/))
— Google's proposed successor to traditional X.509 CA trust — combined
with an ML-KEM-768 / ML-DSA-87 / AES-256-GCM post-quantum channel.
Upstream wolfSSL supplies the cryptographic primitives; postWolf adds
the socket wrappers (`slc_connect`, `mqc_connect`) and the CA /
transparency-log server that make them a working system.

It ships as a **complete PKI**, not just a protocol library. CA
enrollment (DNS-validated), leaf enrollment (CA-authorised, nonce-based),
certificate renewal, revocation, and public-key distribution via the
transparency log are all first-class and in-box — the same server that
mints a certificate also cosigns the Merkle root that proves its
inclusion, serves the Ed25519 trust root to first-contact clients, and
runs the renewal timer on a schedule.

## The stack

| Layer | Directory | What it does |
|-------|-----------|--------------|
| **wolfSSL core** | `wolfssl/`, `wolfcrypt/`, `src/` | Upstream TLS 1.3, ECH, ML-KEM, ML-DSA. Unmodified by postWolf beyond packaging. |
| **SLC** | `socket-level-wrapper/` | Thin wrapper over TLS 1.3 + ECH. `slc_connect` / `slc_accept` return a fully authenticated connection or `NULL` — no "authenticate later" surface. |
| **MQC** | `socket-level-wrapper-MQC/` | **Merkle Quantum Connect.** A post-quantum authenticated channel with no X.509. ML-KEM-768 for key exchange, ML-DSA-87 for peer identity, AES-256-GCM for bulk traffic, Merkle-transparency-log proofs for peer verification. |
| **MQCP** | `socket-level-wrapper-QUIC/` | QUIC-inspired reliable UDP transport reusing the MQC crypto. Experimental; see `mtc-keymaster/README-bugsandtodo.md §10` for current status. |
| **MTC keymaster** | `mtc-keymaster/` | The CA that issues certificates, the transparency log that holds them, the client tools that enroll against both. |

## How a connection actually works

A post-quantum MQC connection between two peers — say a client with an
enrolled leaf identity and the MTC server acting as a peer — runs like this:

1. **Trust root** — both peers have the CA's 32-byte Ed25519 log-cosigner
   public key pinned locally (cached in `~/.TPM/ca-cosigner.pem`). If a peer
   has never seen it, it fetches it TOFU-style over the DH bootstrap port
   (`{"op":"ca_pubkey"}` on port 8445).
2. **Handshake** — ML-KEM-768 runs inside a signed handshake. Each peer
   signs the transcript with its ML-DSA-87 private key and includes the log
   index of its certificate.
3. **Peer verification** — the verifier fetches the opposite peer's
   certificate by log index, replays the Merkle inclusion proof against the
   current tree root, and checks the Ed25519 cosignature over the subtree
   the root belongs to. Lookups ride the bootstrap port's generic
   `{"op":"http_get","path":...}` proxy (port 8445); no X.509, no classical
   TLS on the critical path.
4. **Session** — if verification passes, the KEM-derived secret keys
   AES-256-GCM and every subsequent frame is authenticated encryption.

The SLC wrapper does the same motions via classical TLS 1.3 + ECH for apps
that still need that compatibility. MQCP wraps MQC's frame format into a
reliable-UDP transport.

## Cryptography at a glance

postWolf mixes three algorithm families on purpose: post-quantum KEM +
post-quantum signatures for the new stack, hash-based transparency for
the trust substrate, and classical TLS for backwards compatibility.
Everything below is provided by upstream wolfSSL/wolfCrypt — postWolf
doesn't ship its own primitives.

### SLC — TLS 1.3 + ECH (classical + hybrid)

| Purpose | Primitive |
|---------|-----------|
| Key exchange | ECDHE (X25519, P-256, P-384) **or** hybrid (ECDHE + ML-KEM-512/768/1024) |
| Server authentication | ECDSA (P-256, P-384), Ed25519, RSA, ML-DSA-44/65/87 (via TLS 1.3 certificate) |
| Record protection | AES-128/256-GCM or ChaCha20-Poly1305 |
| ClientHello privacy | ECH — HPKE(X25519, HKDF-SHA256, AES-128-GCM) inner-CH encryption per RFC 9460 |

### MQC — post-quantum channel (no TLS, no X.509)

| Purpose | Primitive | Notes |
|---------|-----------|-------|
| Key exchange | **ML-KEM-768** | NIST-standardised lattice KEM; 192-bit post-quantum security. Straight PQ, not hybrid. |
| Key derivation | HKDF-SHA256 | Expands the KEM shared secret into a 256-bit AEAD key. Context string: `"mtc-mqc-handshake-v1"`. |
| Peer identity / transcript signing | **ML-DSA-87** | Each peer signs the handshake transcript with its long-term ML-DSA-87 key. 192-bit PQ security. |
| Bulk encryption | **AES-256-GCM** | 256-bit key → 128-bit effective post-quantum security via Grover bound. Single algorithm, no negotiation. |
| Replay protection | Frame counter bound as GCM associated data | Tampered or reordered frames fail the AEAD auth check. |

### MTC — trust substrate

| Purpose | Primitive | Notes |
|---------|-----------|-------|
| Transparency log | SHA-256 Merkle tree | RFC 9162-style, append-only, per-entry inclusion proofs and cross-tree consistency proofs. |
| Log cosigning | **Ed25519** | Every published tree root is signed by the log operator's Ed25519 key; this 32-byte public key is the client's pinned trust root. |
| Peer certificates | **ML-DSA-87** (for CA and leaf identities in this deployment) | The cert binds a subject to a public key; the inclusion proof binds the cert to a cosigned tree state. |

### Why the split

- MQC is the channel we want to live on long-term: single PQ algorithm set
  end-to-end, no classical fallbacks, no X.509 CA trust assumptions.
- SLC/TLS 1.3 stays because a lot of the world still speaks only TLS and
  ECH is the right privacy move for that ecosystem. postWolf keeps SLC
  ready so apps can migrate incrementally.
- MTC anchors both — a leaf's ML-DSA-87 cert is verifiable via the same
  Merkle log whether it presents itself over MQC or over TLS.

Deeper references:
`socket-level-wrapper-MQC/README-MQC-specifications.md` (MQC wire format),
`mtc-keymaster/README-ml-dsa-87.md` (ML-DSA-87 integration),
`README-note-ech.md` (ECH deployment).

## Runtime: three ports

The MTC CA/Log server (`mtc_server`) runs under systemd as `mtc-ca.service`
and exposes three TCP ports:

| Port | Purpose | Transport |
|------|---------|-----------|
| **8444** | HTTP API — kept for ad-hoc `curl` testing. Bound to localhost only on the server. | TLS 1.3 + ECH |
| **8445** | Enrollment bootstrap **and** generic pre-authentication lookup proxy (`ca_pubkey`, `http_get`). The only channel a peer without an MTC identity can use. | Plaintext JSON over raw TCP, optional X25519-DH for enrollment |
| **8446** | Post-quantum authenticated channel for peers that already have an MTC identity. Same HTTP dispatcher as 8444 runs over MQC framing. | MQC (ML-KEM-768 + ML-DSA-87 + AES-256-GCM) |

State lives in two directories:

- `~/.mtc-ca-data/` — server state: Merkle log, certificates, CA key, server
  TLS cert.
- `~/.TPM/` — per-identity client trust store: a leaf or CA's ML-DSA-87
  key, its cached peer certificates, and the Ed25519 cosigner pin.

## Trust model — three keys

| Role | Algorithm | Purpose |
|------|-----------|---------|
| **Log cosigner** | Ed25519 | Signs Merkle tree roots. Every MQC peer verifies cosignatures with it. This is the root of trust. |
| **Domain CA** (e.g. `factsorlie.com-ca`) | ML-DSA-87 | Signs its own handshake transcripts and authorises leaf enrollments under its domain. |
| **Leaf** (e.g. `factsorlie.com`) | ML-DSA-87 | Signs its own handshake transcripts. |

See `mtc-keymaster/README.md` §"Keys and Cosignatures" for the full chain.

## Enrollment at a glance

**CA enrollment** — a new domain operator wants to run a CA:

1. Generate an ML-DSA-87 key pair locally.
2. Publish a DNS TXT record at `_mtc-ca.<domain>` with the fingerprint.
3. `bootstrap_ca --domain <domain>` runs over port 8445: X25519 DH exchange,
   server validates the DNS TXT, issues the CA certificate, writes the
   inclusion proof. No nonce, no CA operator involvement.

**Leaf enrollment** — an already-registered CA operator authorises a new leaf:

1. CA operator runs `issue_leaf_nonce --domain <domain> --key-file <leaf.pub>`
   over MQC (port 8446). Server returns a 15-minute pending nonce, bound to
   the `(domain, public_key_fingerprint)` pair. Calling twice within the
   window returns the same nonce (idempotent).
2. Nonce is delivered to the leaf out-of-band.
3. Leaf runs `bootstrap_leaf --domain <domain> --nonce <hex>` over the DH
   bootstrap port (8445). Server atomically validates and consumes the nonce,
   issues the leaf certificate.

## Tools

Canonical (C) client tools live in `mtc-keymaster/tools/c/` and install to
`/usr/local/bin/`:

- **`show-tpm`** — inspect a local TPM identity; `--verify` walks the full
  trust chain end-to-end against the log.
- **`bootstrap_ca`** — first-time CA enrollment (only tool that needs port 8445/DH).
- **`bootstrap_leaf`** — leaf enrollment with an issued nonce.
- **`issue_leaf_nonce`** — CA operator issues a leaf enrollment nonce.
- **`admin_recosign`** — operational tool for re-cosigning subtrees.
- **`revoke-key`** — CA operator revokes a leaf in its domain; also
  lists/refreshes the local revocation cache (see "Revocation" below).

### Revocation

`revoke-key` has three modes, all routed through the MTC server:

```bash
# CA operator: revoke a leaf in your domain (MQC/8446, signs with the
# CA's private key from the auto-detected *-ca identity under ~/.TPM/).
revoke-key --target-index 73 --reason "key compromise"

# Anyone: list revoked leaves whose subject is DOMAIN or *.DOMAIN.
# Public lookup — no identity needed; rides the bootstrap port (8445).
revoke-key --list factsorlie.com

# Anyone: re-pull /revoked and rewrite every ~/.TPM/peers/<n>/revoked.json
# with fresh mtime + correct flag.  Useful before long-running sessions
# to avoid the 24-hour-TTL cache-refresh drop on first contact.
revoke-key --refresh
```

Authorization rules enforced by the server (signed payload over
`revoke:<ca_idx>:<target_idx>:<reason>:<timestamp>`, ±5 min freshness):

- Caller's cert must be a CA (subject ends in `-ca`).
- Target must be a leaf (subject does not end in `-ca`).
- Target subject must be `<ca-domain>` or `*.<ca-domain>`.
- A CA cannot revoke itself.

Full endpoint spec in `mtc-keymaster/server2/c/README-using-mtc-server.md`
under `POST /revoke`.

The server daemon `mtc_server` lives in `mtc-keymaster/server2/c/`
(fork-after-accept, one child per connection). `mtc-keymaster/server/c/` is
the pre-fork legacy tree, retained as history but not deployed.

## Source

The source kit is on GitHub, and can be obtained by a `git clone https://github.com/cpsource/postWolf.git`.

```
git clone https://github.com/cpsource/postWolf.git
```

## Build

The build is identical whether you're running the CA or just enrolling as
a client — same library, same tools. What differs is the *runtime setup*
afterward, which is covered by the two sections that follow.

```bash
sudo apt install -y build-essential pkg-config autoconf automake libtool \
    libjson-c-dev libpq-dev libcurl4-openssl-dev libhiredis-dev

cd ~/postWolf
./make-all.sh
```

`make-all.sh` runs configure + the autotools library build + install (so
`pkg-config --libs postWolf` resolves), then `make -f Makefile.tools` for
the SLC/MQC/MQCP wrappers and MTC tools, and installs them to
`/usr/local/bin`. Manual equivalent:

```bash
./configure.sh                       # TLS13 + ECH + MLKEM + MTC
make -f Makefile
sudo make -f Makefile install        # /usr/local/{lib,include}/postWolf + pkg-config
sudo ldconfig
make -f Makefile.tools               # SLC, MQC, MQCP, mtc_server, client tools
sudo make -f Makefile.tools install  # /usr/local/bin
```

Installed artifacts:

- `/usr/local/lib/libpostWolf.so*`
- `/usr/local/include/postWolf/wolfssl/…`
- `/usr/local/lib/pkgconfig/postWolf.pc`
- `/usr/local/bin/{mtc_server, show-tpm, bootstrap_ca, bootstrap_leaf,
  admin_recosign, issue_leaf_nonce}`

## Installing as a CA operator (server side)

If you're the one *running* a CA — the `factsorlie.com` operator, in our
reference deployment — you need everything above plus the state the
daemon manages.

**1. External services.** The server persists Merkle-log state in
PostgreSQL (Neon is what we use) and rate-limits via Redis. AbuseIPDB is
optional but recommended.

```bash
sudo apt install -y redis-server postgresql-client dnsutils
sudo systemctl enable --now redis-server

cat > ~/.env << 'EOF'
MERKLE_NEON=postgresql://user:password@host/dbname?sslmode=require
ABUSEIPDB_KEY=...        # optional
EOF
chmod 600 ~/.env
```

Tables are auto-created on first start.

**2. OpenSSL 3.5** (for ML-DSA-87 keygen — the system OpenSSL is typically
older). Install as `openssl35` alongside the system one; see
`mtc-keymaster/README-clean-install.md §2` for the build recipe.

**3. Server TLS certificate** for port 8444 (retained for ad-hoc `curl`
testing). Self-signed is fine:

```bash
cd mtc-keymaster/tools/python
python3 create_server_cert.py factsorlie.com
# writes ~/.mtc-ca-data/server-{cert,key}.pem
```

**4. DNS TXT record** for the CA's own bootstrap. The server later looks up
`_mtc-ca.factsorlie.com` to validate CA-enrollment requests; you add the
record once your CA identity is generated (see `mtc-keymaster/tools/python/ca_dns_txt.py`).

**5. systemd unit.** The canonical unit lives in the repo at
`mtc-keymaster/server2/c/mtc-ca.service`. Deploy it (edit first if your
paths differ):

```bash
sudo cp mtc-keymaster/server2/c/mtc-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtc-ca.service
sudo systemctl status mtc-ca.service
```

On first start the server auto-generates the Ed25519 log-cosigner key
into `~/.mtc-ca-data/`. That key is the trust root — every client pins
its fingerprint.

**6. Firewall.** Open **8444** (HTTP, ad-hoc testing), **8445** (DH
bootstrap + lookup proxy — load-bearing for any non-enrolled client), and
**8446** (MQC). Closing any of these breaks clients.

Full step-by-step in `mtc-keymaster/README-clean-install.md`.

## factsorlie.com — the public reference deployment

`factsorlie.com` is the live, public instance we run. It serves two
purposes:

1. **A working CA you can verify against.** You don't have to stand up
   your own `mtc_server` just to see the stack in motion. A fresh
   `show-tpm --verify` against `factsorlie.com` TOFUs the Ed25519
   cosigner key, replays all published Merkle proofs, and reports a
   pass/fail — the same trust chain a production client would exercise.
2. **The reference CA for leaf enrollments in these docs.** Every
   `--domain factsorlie.com` example in the README and tool output is
   hitting this real server, not a mock. The issued leaf certificates
   and enrollment nonces land in the same Neon-backed Merkle log that
   cosigns every client's verification attempt.

**Trust root.** The CA's Ed25519 log-cosigner public key is what anchors
everything else — every certificate in the tree is only as trusted as
that one 32-byte key. `show-tpm --verify` pins it on first contact
(writes `~/.TPM/ca-cosigner.pem`). If the pinned fingerprint ever
changes under you, that's a signal to investigate, not to accept.

**What's open to the public.** Ports **8445** (DH bootstrap + lookup
proxy) and **8446** (MQC) are internet-reachable. Port **8444** is open
too but used only for ad-hoc `curl` debugging — no client library
touches it. Leaf enrollment still requires a CA-issued nonce handed out
of band; there is no open enrollment.

**What we're doing with it.** We dogfood the stack: every new commit
gets smoke-tested against the live server before it lands on `master`.
Bugs surface here first, which is why several of the entries in
`mtc-keymaster/README-bugsandtodo.md` cite this specific deployment.

## Installing as a client

If you just want to *use* the package — connect to a postWolf server,
enroll a leaf identity, run `show-tpm --verify` against a live log — you
need the build above and nothing else. No database, no Redis, no
`~/.mtc-ca-data/`, no systemd unit.

**1. Install the code.** You have three choices:

   - **Full build.** Build the entire kit from source as described in the
     Build section above. This gives you everything — library, tools,
     CA server, leaf utilities.
   - **CA only.** If you own a domain, use `kit-CA/` to install just the
     Certificate Authority code. CAs control access to their domain's leaves.
   - **Leaf only.** If you are a member of someone else's domain, use
     `kit-leaf/` to install just the client/leaf code.

**2. Get your leaf identity enrolled.** Two steps, one of which is
performed by the CA operator:

   - **CA operator** runs `issue_leaf_nonce` against their MTC server,
     handing you a 64-hex-char nonce out-of-band (15-minute TTL):

     ```bash
     issue_leaf_nonce --domain factsorlie.com \
         --key-file /path/to/your/leaf-pubkey.pem
     ```

   - **You** run `bootstrap_leaf` to submit your public key + the nonce to
     the CA's DH bootstrap port (8445). The server verifies the nonce,
     issues your ML-DSA-87 certificate, and writes everything into
     `~/.TPM/<your-domain>/`:

     ```bash
     bootstrap_leaf --domain factsorlie.com --server factsorlie.com:8445 \
         --nonce <64-hex-chars>
     ```

   After this, `~/.TPM/<your-domain>/` contains your private key, public
   key, and the MTC certificate with its inclusion proof + cosignature.

**3. Verify the log** to confirm trust chain + cached state:

```bash
show-tpm --verify
```

On first run, `show-tpm` TOFUs the CA's Ed25519 cosigner key from port
8445 and caches it at `~/.TPM/ca-cosigner.pem`. Subsequent runs use the
cached copy. If the fingerprint changes, treat it as compromise and
revoke manually.

You do **not** need to open any firewall ports — the client side is
strictly outbound. You do need to be able to reach the CA server on
**8445** (bootstrap + lookup) and **8446** (MQC). Port 8444 is not
required from the client side.

## Directory layout

```
postWolf/
  wolfssl/, wolfcrypt/, src/      upstream wolfSSL — unmodified identifiers
  socket-level-wrapper/           SLC (TLS 1.3 + ECH wrapper)
  socket-level-wrapper-MQC/       MQC (post-quantum TCP)
  socket-level-wrapper-QUIC/      MQCP (post-quantum UDP)
  mtc-keymaster/
    server/c/                     legacy mtc_server (pre-fork — historical)
    server2/c/                    current mtc_server (fork-after-accept)
    tools/c/                      client tools (installed to /usr/local/bin)
    tools/python/                 helpers (cert generation, verify scripts)
    tools/sh/                     admin shell scripts
    tools/mtc-server.sh           systemctl wrapper (start/stop/rebuild)
    tools/mtc-renew.sh            renewal timer wrapper
  Makefile                        autotools library build (generated)
  Makefile.tools                  orchestrator for SLC/MQC/MQCP/MTC
  make-all.sh                     end-to-end bootstrap
```

## Further reading

- `mtc-keymaster/README.md` — MTC architecture and key hierarchy.
- `mtc-keymaster/README-clean-install.md` — step-by-step installation.
- `mtc-keymaster/server2/c/README-using-mtc-server.md` — operating
  `mtc_server`: flags, endpoints, logs, rate limits.
- `mtc-keymaster/README-bugsandtodo.md` — numbered TODO list, known issues,
  design notes.
- `socket-level-wrapper/README.md` — SLC API reference.
- `socket-level-wrapper-MQC/README-MQC-specifications.md` — MQC wire format.
- `README-note-ech.md` — ECH deployment notes.

## License

postWolf is a derivative of wolfSSL, released under the **GNU GPL v3**.
See [LICENSING](https://github.com/cpsource/postWolf/blob/master/LICENSING)
and [COPYING](https://github.com/cpsource/postWolf/blob/master/COPYING)
for full terms.
