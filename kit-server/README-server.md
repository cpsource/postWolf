# postWolf MTC-server install kit

Packaged install for the MTC keymaster server itself (`mtc_server`),
parallel to `kit-CA/` (CA-operator client tools) and `kit-leaf/`
(leaf client tools).

This kit is for operators standing up a **transparency-log server**
(the daemon that issues Merkle-Tree certificates and publishes
cosigned tree roots).  CA-operator enrollment tooling
(`bootstrap_ca`, `issue_leaf_nonce`, `revoke-key`, etc.) lives in
`kit-CA/` — install both kits if this box also hosts its own CA.

## Files

| File | Purpose |
|------|---------|
| `bin/mtc_server`        | The CA/Log daemon. |
| `bin/admin_recosign`    | Re-cosign Merkle subtrees (operator op). |
| `bin/migrate-cosigner`  | Cosigner-key rotation. |
| `bin/backfill-pubkey`   | One-shot maintenance for legacy DBs. |
| `bin/show-tpm`          | Inspect a local identity; `--verify` walks the trust chain. |
| `bin/create_server_cert.py` | Generate the port-8444 TLS cert via `openssl40`. |
| `bin/verify.py`, `bin/verify_certificate.py` | Python-side log verification helpers. |
| `lib/libpostWolf.so*`   | wolfSSL-derived shared library. |
| `etc/mtc-ca.service.template` | systemd unit, substituted at install time. |
| `socket-level-wrapper-MQC.tar.gz` + `mqc.pc` | MQC source + prebuilt `libmqc.a` and pkg-config. |
| `buildopenssl4.0.sh`    | Builds OpenSSL 4.0.0 into `/usr/local/openssl4/` (needed for ML-DSA-87 cosigner-key keygen on first start). |
| `install-server-kit.sh` | Installs everything to `/usr/local/` — must be run with sudo. |
| `VERSION`               | Git describe of the source tree. |

## Install

```bash
tar xzf postWolf-server-kit-<version>.tar.gz
cd payload
sudo bash install-server-kit.sh --domain example.com
```

The `--domain` flag substitutes the operator's domain into the
shipped systemd unit (which carries the factsorlie.com reference
deployment's paths as defaults).  Omit it to install the unit as a
template only (`/usr/local/share/doc/postWolf-server/mtc-ca.service.template`)
and edit-and-copy it yourself.

Other flags:
- `--user <U>` — user the daemon runs as (defaults to `$SUDO_USER`,
  then `ubuntu`).
- `--data-dir <D>` — `--data-dir` for `mtc_server` (defaults to
  `$HOME/.mtc-ca-data` of the chosen user).

The installer:

1. apt-installs runtime libs (`libjson-c5`, `libcurl4`, `libpq5`,
   a `libhiredis` variant, `libunbound8` + `dns-root-data` for
   DNSSEC TXT-pin verification, `libaugeas0` for the
   `/etc/postWolf/config` parser) plus `redis-server` and
   `postgresql-client` (the daemon's external services).
2. Builds OpenSSL 4.0.0 into `/usr/local/openssl4/` and drops a
   wrapper at `/usr/local/bin/openssl40` (idempotent — skipped if
   already 4.x).  Needed for the ML-DSA-87 cosigner-key keygen the
   daemon runs on first start.
3. Copies `libpostWolf.so*` to `/usr/local/lib/` and runs `ldconfig`.
4. Installs the MQC library: headers to `/usr/local/include/mqc/`,
   `libmqc.a` to `/usr/local/lib/`, `mqc.pc` to
   `/usr/local/lib/pkgconfig/`.
5. Installs `mtc_server` and the four ops tools to `/usr/local/bin/`.
6. Substitutes the systemd unit (if `--domain` given) into
   `/etc/systemd/system/mtc-ca.service`, runs `daemon-reload`.
7. Pre-creates `<MTC_DATA_DIR>` owned by the daemon's user.
8. Final `ldd` check on each binary; prints any unresolved `.so`.

## First-start procedure

The kit installer stops short of starting the daemon — there are
two things only the operator can supply.

```bash
# 1. Database + secrets in <MTC_USER>'s ~/.env (chmod 600)
cat > ~/.env <<EOF
MERKLE_NEON=postgresql://user:password@host/dbname?sslmode=require
ABUSEIPDB_KEY=...        # optional
EOF
chmod 600 ~/.env

# 2. TLS cert for port 8444 (kept for ad-hoc curl testing)
python3 /usr/local/bin/create_server_cert.py example.com
# writes ~/.mtc-ca-data/server-{cert,key}.pem

# 3. Start it.  First start auto-generates the ML-DSA-87 cosigner key.
sudo systemctl enable --now mtc-ca
sudo systemctl status mtc-ca

# 4. Open the firewall on 8444, 8445, 8446.
```

## Three ports

| Port | Purpose | Transport |
|------|---------|-----------|
| **8444** | HTTP API (kept for ad-hoc `curl` testing). | TLS 1.3 + ECH |
| **8445** | Enrollment bootstrap + pre-auth lookup proxy.  Required for any non-enrolled client. | Plaintext JSON / X25519-DH for enrollment |
| **8446** | Post-quantum authenticated channel (MQC) for already-enrolled peers. | ML-KEM-768 + ML-DSA-87 + AES-256-GCM |

## Building the kit

If you cloned the repo and want to rebuild the tarball:

```bash
cd ~/postWolf
./make-all.sh                # ensures all binaries are built
cd kit-server
make build-kit               # produces postWolf-server-kit-<ver>.tar.gz
```

## Uninstall

```bash
sudo systemctl disable --now mtc-ca || true
sudo rm -f /etc/systemd/system/mtc-ca.service
sudo systemctl daemon-reload

sudo rm -f /usr/local/bin/{mtc_server,admin_recosign,migrate-cosigner,backfill-pubkey,show-tpm}
sudo rm -f /usr/local/bin/{create_server_cert.py,verify.py,verify_certificate.py}
sudo rm -f /usr/local/lib/libpostWolf.so*
sudo rm -f /usr/local/lib/libmqc.a
sudo rm -f /usr/local/lib/pkgconfig/mqc.pc
sudo rm -rf /usr/local/include/mqc
sudo rm -rf /usr/local/share/doc/postWolf-server
sudo ldconfig

# Optional: wipe openssl40 too
sudo rm -rf /usr/local/openssl4 /usr/local/bin/openssl40 /usr/local/src/openssl-4.0.0

# Optional: rm -rf <MTC_DATA_DIR>   (deletes the Merkle log + cosigner key!)
```

## More

- Daemon ops: `/usr/local/share/doc/postWolf-server/README-using-mtc-server.md`
- Project overview: https://github.com/cpsource/postWolf
- TODOs / open issues: `mtc-keymaster/README-bugsandtodo.md` in the source tree.
