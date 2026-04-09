# MTC Keymaster — Clean Install Guide

Step-by-step from bare machine to working MTC CA server with enrolled
ML-DSA-87 leaf certificates.

## 1. System Prerequisites

```bash
sudo apt update
sudo apt install -y \
    build-essential pkg-config autoconf automake libtool \
    libjson-c-dev libpq-dev libcurl4-openssl-dev \
    python3 python3-pip postgresql-client \
    dnsutils   # for dig (DNS TXT verification)

pip3 install cryptography psycopg2-binary
```

## 2. Install OpenSSL 3.5 (for ML-DSA-87 support)

The system OpenSSL does not support post-quantum algorithms. OpenSSL 3.5+
includes ML-DSA-44/65/87 (CRYSTALS-Dilithium) natively.

```bash
# Build from source (~/openssl-master or download openssl-3.5.0)
cd ~/openssl-master
./Configure --prefix=/usr/local --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install

# Create the openssl35 symlink so system openssl is not replaced
sudo ln -sf /usr/local/bin/openssl /usr/local/bin/openssl35

# Verify
openssl35 version
# OpenSSL 3.5.0 8 Apr 2025

# Confirm ML-DSA-87 is available
openssl35 list -signature-algorithms | grep ML-DSA-87
# { 2.16.840.1.101.3.4.3.19, id-ml-dsa-87, ML-DSA-87, MLDSA87 } @ default
```

## 3. Set Up Neon Database

The server persists all state (CA key, Merkle tree, certificates,
revocations) in PostgreSQL via Neon. Tables are auto-created on first
server startup.

```bash
# Create ~/.env with your Neon connection string
cat > ~/.env << 'EOF'
MERKLE_NEON=postgresql://user:password@your-neon-host/dbname?sslmode=require
EOF
chmod 600 ~/.env
```

## 4. Build wolfssl-new

```bash
cd ~/wolfssl-new
./autogen.sh
./configure.sh   # --enable-quic --enable-ech --enable-tls13 --enable-mtc --enable-all --quiet
make -j$(nproc)
```

This builds `libwolfssl` with TLS 1.3, ECH, MTC, ML-KEM hybrids, and
DTLS 1.3 support. The socket-level-wrapper (`libslc.a`) is built
automatically as part of the top-level make.

## 5. Build the C Server

```bash
make -C mtc-keymaster/server/c
```

Produces `mtc_server` binary. Builds with `-Werror` (warnings are errors).

## 6. Create ML-DSA-87 TLS Certificate for the Server

The MTC server itself needs a TLS certificate to accept connections.
We use ML-DSA-87 (CRYSTALS-Dilithium level 5) for post-quantum security.

```bash
mkdir -p ~/.mtc-ca-data

# Generate ML-DSA-87 private key
openssl35 genpkey -algorithm ML-DSA-87 \
    -out ~/.mtc-ca-data/server-key.pem

# Create self-signed certificate (365 days)
openssl35 req -x509 -new \
    -key ~/.mtc-ca-data/server-key.pem \
    -out ~/.mtc-ca-data/server-cert.pem \
    -days 365 \
    -subj "/CN=factsorlie.com"

# Verify
openssl35 x509 -in ~/.mtc-ca-data/server-cert.pem -noout -text | head -15

# Set permissions
chmod 600 ~/.mtc-ca-data/server-key.pem
```

For production, replace the self-signed cert with one from a trusted CA
or use the MTC system itself once bootstrapped.

## 7. First Server Start

On first startup the server auto-generates an Ed25519 CA key pair for
Merkle tree cosigning and creates all database tables.

```bash
cd ~/wolfssl-new/mtc-keymaster/server/c

./mtc_server \
    --port 8444 \
    --data-dir ~/.mtc-ca-data \
    --tokenpath ~/.env \
    --ca-name MTC-CA-C \
    --log-id 32473.2 \
    --tls-cert ~/.mtc-ca-data/server-cert.pem \
    --tls-key ~/.mtc-ca-data/server-key.pem \
    --ech-name factsorlie.com
```

Expected output:
```
[store] MERKLE_NEON found, using PostgreSQL (Neon) for persistence
[store] generating Ed25519 CA key ...
[http] listening on 0.0.0.0:8444 (TLS)
[http] ECH enabled for factsorlie.com
```

Verify (in another terminal):
```bash
curl -k https://localhost:8444/
# {"server":"MTC CA/Log Server","ca_name":"MTC-CA-C","log_id":"32473.2","tree_size":1}
```

Stop the server with Ctrl+C once verified.

## 8. Install Server Service (systemd)

```bash
sudo cp ~/wolfssl-new/mtc-keymaster/server/c/mtc-ca.service \
    /etc/systemd/system/mtc-ca.service

# Edit if your paths differ from the defaults
sudo vi /etc/systemd/system/mtc-ca.service

sudo systemctl daemon-reload
sudo systemctl enable mtc-ca
sudo systemctl start mtc-ca
sudo systemctl status mtc-ca

# View logs
journalctl -u mtc-ca -f
```

The service file is at `mtc-keymaster/server/c/mtc-ca.service`. It runs
the C server with TLS + ECH on port 8444.

## 9. Bootstrap the Client

Fetch the CA's Ed25519 public key and store it locally. This is a
one-time trust establishment step.

```bash
cd ~/wolfssl-new/mtc-keymaster/tools/python

python3 main.py --server https://localhost:8444 bootstrap
```

The CA public key is saved to `~/.trust_store.json`.

## 10. Register a CA Certificate (two-phase nonce enrollment)

If you have an intermediate CA certificate that needs to be registered
in the MTC log, the server requires a two-phase enrollment with a
server-issued nonce. This proves domain ownership via DNS.

**Phase 1 — Request a nonce and create the DNS TXT record:**

```bash
python3 main.py --server https://localhost:8444 enroll-ca ~/path/to/ca-cert.pem
```

The tool will:
1. Parse the CA certificate and compute the SPKI fingerprint
2. Request a 256-bit nonce from the server (`POST /enrollment/nonce`)
3. Print the exact DNS TXT record to create:

```
Phase 1: Requesting enrollment nonce for 'factsorlie.com'...
  Nonce:   a1b2c3d4...  (64 hex chars)
  Expires: 1782760800    (15 minutes from now)

  Add this DNS TXT record:
    _mtc-ca.factsorlie.com.  IN TXT  "v=mtc-ca2; fp=sha256:...; n=a1b2c3d4...; exp=1782760800"

  Press Enter after adding the DNS TXT record...
```

**Phase 2 — Add the DNS record, then press Enter:**

Add the TXT record to your DNS zone (Cloudflare, Route53, etc.), wait
a few seconds for propagation, then press Enter. The tool completes
the enrollment — the server verifies the nonce against its stored state,
queries DNS to confirm domain control, issues the certificate, and
burns the nonce (single-use).

**Security properties of the nonce:**
- 256-bit CSPRNG (unpredictable)
- Server-side state is the authority (not the DNS record)
- Single-use — consumed on success, never accepted again
- 15-minute TTL — limits the attack window
- Bound to domain + public key fingerprint

**Root CAs** skip DNS validation (no nonce needed):

```bash
# Root CAs are auto-detected (pathlen > 0) and bypass nonce requirement
python3 main.py --server https://localhost:8444 enroll-ca ~/path/to/root-ca.pem
```

## 11. Create ML-DSA-87 Leaf Key and Enroll

Leaf enrollment does not require a nonce — only CA enrollment does.

```bash
# Generate ML-DSA-87 leaf key pair
python3 create_leaf_cert.py --algorithm ML-DSA-87 factsorlie.com

# Enroll with the CA server
python3 main.py --server https://localhost:8444 enroll factsorlie.com
```

Keys and certificate are stored in `~/.TPM/factsorlie.com/`:
```
~/.TPM/factsorlie.com/
    private_key.pem       # ML-DSA-87 private key (mode 0600)
    public_key.pem        # ML-DSA-87 public key
    certificate.json      # MTC cert with Merkle proof + cosignature
    index                 # certificate log index number
```

## 12. Verify Enrollment

```bash
python3 main.py --server https://localhost:8444 verify 1
```

Expected output:
```
Verifying certificate #1 for 'factsorlie.com'...
  Inclusion proof:  PASS
  Cosignature:      PASS
  Not expired:      PASS
  Overall:          VALID
```

## 13. Install Renewal Service

The renewal tool scans `~/.TPM/` for expiring certificates and
re-enrolls them automatically. See `mtc-keymaster/renew-tool/README.md`
for full documentation.

**Option A: Cron (simple)**

```bash
cd ~/wolfssl-new/mtc-keymaster/renew-tool
./install_cron.sh
# Installs daily cron job at 3 AM
```

**Option B: Systemd timer (recommended for production)**

Create `/etc/systemd/system/mtc-renew.service`:
```ini
[Unit]
Description=MTC Certificate Renewal
After=network.target

[Service]
Type=oneshot
User=ubuntu
ExecStart=/usr/bin/python3 /home/ubuntu/wolfssl-new/mtc-keymaster/renew-tool/renew.py --neon
Environment=HOME=/home/ubuntu
WorkingDirectory=/home/ubuntu/wolfssl-new/mtc-keymaster/renew-tool
```

Create `/etc/systemd/system/mtc-renew.timer`:
```ini
[Unit]
Description=Run MTC renewal daily

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mtc-renew.timer
sudo systemctl start mtc-renew.timer

# Test manually
sudo systemctl start mtc-renew.service
journalctl -u mtc-renew -f
```

## 14. Reset for Testing

To wipe all state and cold-start:

```bash
bash ~/wolfssl-new/mtc-keymaster/tools/clearout.sh
```

This deletes `~/.TPM/`, `~/.mtc-ca-data/`, and truncates all Neon
tables. The server will generate a fresh CA key on next startup.

## Services Summary

| Service | Purpose | Config |
|---------|---------|--------|
| `mtc-ca.service` | MTC CA/Log server (TLS 1.3 + ECH) | `/etc/systemd/system/mtc-ca.service` |
| `mtc-renew.timer` | Daily certificate renewal | `/etc/systemd/system/mtc-renew.timer` |

## Quick Reference

| Command | Purpose |
|---------|---------|
| `openssl35 genpkey -algorithm ML-DSA-87` | Generate post-quantum key |
| `./mtc_server --port 8444 ...` | Start CA server |
| `python3 main.py bootstrap` | Trust the CA (one-time) |
| `python3 main.py enroll-ca <cert.pem>` | Register CA cert (two-phase nonce) |
| `python3 create_leaf_cert.py --algorithm ML-DSA-87 <domain>` | Generate leaf key |
| `python3 main.py enroll <domain>` | Enroll leaf with CA |
| `python3 main.py verify <index>` | Verify a certificate |
| `python3 renew.py --dry-run` | Preview renewals |
| `bash clearout.sh` | Wipe all state |
