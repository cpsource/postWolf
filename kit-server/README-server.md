# postWolf MTC server install kit

**Status: placeholder.** This directory is reserved for a packaged
install kit for the MTC keymaster server itself (`mtc_server`), to
parallel `kit-CA/` (CA-operator client tools) and `kit-leaf/` (leaf
client tools).

Today, standing up an MTC server is a from-source build:

```bash
git clone https://github.com/cpsource/postWolf.git
cd postWolf
./make-all.sh                                          # builds + installs
sudo cp mtc-keymaster/server2/c/mtc-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtc-ca.service
```

When this kit is populated it will follow the same shape as
`kit-CA/` and `kit-leaf/`:

```
kit-server/
  Makefile                 — top-level entry point
  README-server.md         — this file
  buildopenssl4.0.sh       — bundled OpenSSL 4.0.0 build (ML-DSA-87 keygen)
  install-server-kit.sh    — apt prereqs + binary install + systemd unit
  make-server-kit.sh       — package the staged tarball
  payload/                 — staging dir (gitignored)
```

**Tentative payload contents** (subject to design when work begins):

- `bin/mtc_server` — the daemon binary
- `bin/admin_recosign`, `bin/show-tpm`, `bin/issue_leaf_nonce`,
  `bin/revoke-key` — server-side ops tools
- `lib/libpostWolf.so*` — wolfSSL-derived shared library
- `socket-level-wrapper-MQC.tar.gz` + `mqc.pc` — same as the other kits
- `etc/mtc-ca.service` — systemd unit (canonical copy lives at
  `mtc-keymaster/server2/c/mtc-ca.service` in the source tree)
- Sample `~/.env.example` documenting `MERKLE_NEON`, `ABUSEIPDB_KEY`

**Runtime apt prereqs** the installer will need (mirrors the
`-dev` list from the source-build doc, but using runtime `.so`
package names):

```
libjson-c5 libcurl4 libpq5 libhiredis* libunbound8 dns-root-data \
postgresql-client redis-server dnsutils python3 python3-cryptography
```

**External services** the operator must provision separately:

- PostgreSQL (Neon or self-hosted) — `MERKLE_NEON` connection
  string in `~/.env`.
- Redis — bound to `127.0.0.1:6379`.  See TODO #45 for the
  retire-the-docker-compose-redis migration.
- Optional: AbuseIPDB API key (`ABUSEIPDB_KEY`) for the IP-rep
  feed used by MQC rate limiting.

**Open questions for when this kit is built:**

- Whether to bundle `buildopenssl4.0.sh` as the kits already do,
  or assume the CA-operator already has `openssl40` from
  `kit-CA`.  The server side needs ML-DSA-87 cosigner-key keygen
  on first start, so a working `openssl40` is a hard requirement.
- Whether `mtc_server` itself should auto-install the systemd
  unit on first run, or leave that to the kit installer (the
  current source-build path defers to the operator).
- How to ship the parent CA's TLS cert/key for port 8444 — out
  of scope for the kit (operator-supplied), or provide a
  `create_server_cert.py` helper at install time.
