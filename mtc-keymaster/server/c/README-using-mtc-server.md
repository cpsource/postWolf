# Using the MTC CA Server

## Quick Start

```bash
# Build
make

# Start (minimal, for testing)
./mtc_server --port 8444 --data-dir ~/.mtc-ca-data

# Start (production, with TLS + ECH)
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

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host HOST` | 0.0.0.0 | Bind address |
| `--port PORT` | 8443 | Bind port |
| `--data-dir DIR` | ./mtc-data | CA key + file-based storage directory |
| `--tokenpath FILE` | — | Path to .env file for `MERKLE_NEON` connection string |
| `--ca-name NAME` | MTC-CA-C | CA identifier (appears in cosignatures) |
| `--log-id ID` | 32473.2 | Log identifier (cosigner_id = log_id + ".ca") |
| `--tls-cert FILE` | — | PEM server certificate (enables TLS) |
| `--tls-key FILE` | — | PEM server private key |
| `--tls-ca FILE` | — | CA cert for client verification (optional) |
| `--ech-name NAME` | — | ECH public name (e.g., factsorlie.com) |
| `--abuse-threshold N` | 75 | AbuseIPDB score threshold for general access |
| `--log-level N` | 2 | Log verbosity (see below) |
| `--log-file PATH` | /var/log/mtc/mtc_server.log | Log file path |
| `-h` | — | Show help |

## Log Levels

| Level | Name | What You See |
|-------|------|-------------|
| 0 | ERROR | Errors only (DB failures, crypto errors) |
| 1 | WARN | Errors + warnings (rejected connections, TLS handshake failures, abuse blocks) |
| 2 | INFO | Connections, enrollments, nonce issuance, rejections **(default)** |
| 3 | DEBUG | Every request method + path, protocol-level trace |
| 4 | TRACE | Everything including internal details |

### Examples

```bash
# Production — see connections and failures
./mtc_server --log-level 2 ...

# Debugging — see every request
./mtc_server --log-level 3 ...

# Full trace — protocol details
./mtc_server --log-level 4 ...

# Quiet — errors only
./mtc_server --log-level 0 ...

# Custom log file
./mtc_server --log-file /tmp/mtc-debug.log --log-level 3 ...
```

### Log Output Format

```
2026-04-09 15:01:13 [INFO ] logging started (level=2, file=/var/log/mtc/mtc_server.log)
2026-04-09 15:01:14 [INFO ] connection from 203.0.113.42
2026-04-09 15:01:14 [DEBUG] GET /ca/public-key from 203.0.113.42
2026-04-09 15:01:15 [INFO ] nonce issued for factsorlie.com (fp=a1b2c3d4..., expires=1782760800)
2026-04-09 15:01:20 [WARN ] enrollment rejected for 198.51.100.7 (abuse score 35 >= 25)
2026-04-09 15:01:22 [WARN ] TLS accept/handshake failed
2026-04-09 15:01:25 [INFO ] rejected 192.0.2.99 (abuse score 80 >= 75)
```

Logs write to both the log file and stdout (for systemd journal capture).

### Log Directory

The server creates `/var/log/mtc/` on startup if it doesn't exist.
If it can't create the directory (e.g., no permissions), it falls back
to stderr.

```bash
# Create the directory manually if needed
sudo mkdir -p /var/log/mtc
sudo chown ubuntu:ubuntu /var/log/mtc
```

## AbuseIPDB Protection

Two-tier abuse checking:

| Tier | Threshold | Applies To |
|------|-----------|-----------|
| General access | 75% (configurable via `--abuse-threshold`) | All connections |
| Enrollment/revocation | 25% (hardcoded `ABUSEIPDB_ENROLL_THRESHOLD`) | `POST /certificate/request`, `POST /revoke` |

Requires `ABUSEIPDB_KEY` in environment or `~/.env`.

Cache records expire after 5 days and are refreshed from the API.

## Shell Scripts

Management scripts are in `mtc-keymaster/tools/`:

### mtc-server.sh — Server Management

```bash
bash mtc-keymaster/tools/mtc-server.sh start     # start the systemd service
bash mtc-keymaster/tools/mtc-server.sh stop      # stop the service
bash mtc-keymaster/tools/mtc-server.sh restart   # restart the service
bash mtc-keymaster/tools/mtc-server.sh status    # show service status
bash mtc-keymaster/tools/mtc-server.sh logs      # follow journal (Ctrl+C to stop)
bash mtc-keymaster/tools/mtc-server.sh rebuild   # stop → clean → build → start
```

### mtc-renew.sh — Renewal Service

```bash
bash mtc-keymaster/tools/mtc-renew.sh install    # install systemd timer
bash mtc-keymaster/tools/mtc-renew.sh start      # enable hourly timer
bash mtc-keymaster/tools/mtc-renew.sh stop       # stop and disable timer
bash mtc-keymaster/tools/mtc-renew.sh status     # show timer + last run
bash mtc-keymaster/tools/mtc-renew.sh run        # run renewal now (one-shot)
bash mtc-keymaster/tools/mtc-renew.sh dry-run    # preview what would renew
bash mtc-keymaster/tools/mtc-renew.sh logs       # follow renewal journal
```

### clearout.sh — Reset All State

```bash
bash mtc-keymaster/tools/clearout.sh
```

Deletes `~/.TPM/`, `~/.mtc-ca-data/`, and truncates all Neon tables.
Asks "Are you sure?" before proceeding.

## Systemd Service

### Install

```bash
sudo cp mtc-keymaster/server/c/mtc-ca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable mtc-ca
sudo systemctl start mtc-ca
```

### Service File

`mtc-ca.service` runs the server with TLS + ECH on port 8444.
Edit the file if your paths or settings differ.

To add logging options to the service, edit the `ExecStart` line:

```ini
ExecStart=/home/ubuntu/wolfssl-new/mtc-keymaster/server/c/mtc_server \
    --port 8444 \
    --data-dir /home/ubuntu/.mtc-ca-data \
    --tokenpath /home/ubuntu/.env \
    --ca-name MTC-CA-C \
    --log-id 32473.2 \
    --tls-cert /home/ubuntu/.mtc-ca-data/server-cert.pem \
    --tls-key /home/ubuntu/.mtc-ca-data/server-key.pem \
    --ech-name factsorlie.com \
    --log-level 2 \
    --log-file /var/log/mtc/mtc_server.log
```

## API Endpoints

### Read-Only (GET)

| Endpoint | Description |
|----------|-------------|
| `GET /` | Server info (name, log_id, tree_size) |
| `GET /log` | Log state (tree_size, root_hash, landmarks) |
| `GET /log/entry/<N>` | Log entry details |
| `GET /log/proof/<N>` | Merkle inclusion proof |
| `GET /log/checkpoint` | Latest checkpoint |
| `GET /log/consistency?old=N&new=M` | Consistency proof |
| `GET /certificate/<N>` | Retrieve certificate |
| `GET /certificate/search?q=<query>` | Search certificates |
| `GET /trust-anchors` | List trust anchors |
| `GET /revoked` | Revocation list |
| `GET /revoked/<N>` | Check if certificate is revoked |
| `GET /ca/public-key` | CA Ed25519 public key |
| `GET /ech/configs` | ECH configuration (base64) |

### Write (POST)

| Endpoint | Description |
|----------|-------------|
| `POST /enrollment/nonce` | Request a server-issued nonce for CA enrollment |
| `POST /certificate/request` | Request a certificate (leaf or CA with nonce) |
| `POST /revoke` | Revoke a certificate |

## First Startup Behavior

On first startup with an empty `--data-dir`:

1. Creates the data directory
2. Connects to Neon PostgreSQL (if `MERKLE_NEON` is set)
3. Creates all database tables (if they don't exist)
4. Generates a new Ed25519 CA key pair
5. Saves the key to `ca_key.der` and to the `mtc_ca_config` DB table
6. Creates the null entry (index 0) in the Merkle tree
7. Starts listening

## Python Client Tools

Client tools are in `mtc-keymaster/tools/python/`:

| Tool | Purpose |
|------|---------|
| `main.py bootstrap` | Fetch CA public key (one-time trust setup) |
| `main.py enroll <domain>` | Create leaf key + enroll |
| `main.py enroll-ca <cert.pem>` | Register CA cert (two-phase nonce) |
| `main.py verify <index>` | Verify a certificate |
| `create_leaf_cert.py <domain>` | Generate leaf key pair |
| `create_server_cert.py <domain>` | Generate ML-DSA-87 server TLS cert |
| `ca_dns_txt.py <cert.pem>` | Generate/verify DNS TXT for CA validation |

## See Also

- `mtc-keymaster/README-clean-install.md` — Full install guide (steps 1-14)
- `mtc-keymaster/README-bugsandtodo.md` — TODO items and design docs
- `mtc-keymaster/README-ml-dsa-87.md` — How MTC reduces PQ TLS overhead
- `mtc-keymaster/renew-tool/README.md` — Renewal tool documentation
