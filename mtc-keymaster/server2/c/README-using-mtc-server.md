# Using the MTC CA Server

## Building

All projects build from the postWolf root directory. A `Makefile.tools`
at the root orchestrates the sub-projects (SLC, MQC, QUIC, MTC). It is
separate from the autotools `Makefile` used for the postWolf library
itself, so it must be invoked explicitly with `-f`. On a fresh checkout
use the top-level driver instead — it runs the library build, installs
it (required so `pkg-config` can find `postWolf.pc`), then runs
`Makefile.tools`:

```bash
cd ~/postWolf
./make-all.sh
```

To rebuild only the tools when the library is already installed:

```bash
# Build everything: libslc.a, libmqc.a, libmqcp.a, mtc_server, show-tpm,
# bootstrap_ca, bootstrap_leaf, admin_recosign
make -f Makefile.tools

# Install tools to /usr/local/bin and run ldconfig
sudo make -f Makefile.tools install
```

After `make install`, all tools are on `$PATH` and the shared library
cache is refreshed — no `LD_LIBRARY_PATH` needed.

### Build targets

| Command | What it builds |
|---------|---------------|
| `make` | SLC (TLS wrapper), MQC (post-quantum), all MTC tools |
| `make slc` | `socket-level-wrapper/libslc.a` only |
| `make mqc` | `socket-level-wrapper-MQC/libmqc.a` only |
| `make mtc` | `mtc-keymaster/server/c/` tools (depends on slc + mqc) |
| `sudo make install` | Install binaries to `/usr/local/bin`, run `ldconfig` |
| `make clean` | Clean all sub-project build artifacts |

### Rebuilding the postWolf library

The postWolf shared library (libpostWolf.so) is built separately via
autotools and rarely needs rebuilding:

```bash
cd ~/postWolf
./configure.sh
make -f Makefile
sudo make -f Makefile install
sudo ldconfig
```

## Quick Start

```bash
# Start (minimal, for testing)
mtc_server --port 8444 --data-dir ~/.mtc-ca-data

# Start (production: TLS + ECH + DH bootstrap + MQC)
mtc_server \
    --port 8444 \
    --data-dir ~/.mtc-ca-data \
    --tokenpath ~/.env \
    --ca-name MTC-CA-C \
    --log-id 32473.2 \
    --tls-cert ~/.mtc-ca-data/server-cert.pem \
    --tls-key ~/.mtc-ca-data/server-key.pem \
    --ech-name factsorlie.com \
    --dh-port 8445 \
    --mqc-port 8446 \
    --tpm-path ~/.TPM/factsorlie.com-ca
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
| `--dh-port PORT` | — | Bootstrap DH port for pre-TLS enrollment (e.g., 8445) |
| `--mqc-port PORT` | — | MQC post-quantum listener port (e.g., 8446) |
| `--tpm-path PATH` | — | TPM identity for MQC (e.g., `~/.TPM/factsorlie.com-ca`). Required when `--mqc-port` is set |
| `--mtc-server URL` | auto | MTC server URL for MQC peer verification. Defaults to `https://HOST:PORT` |
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

**Important:** The server must accept direct connections — not behind an
untrusted reverse proxy. The client IP is obtained via `getpeername()`,
which returns the proxy's IP if one is present. If you must use a proxy,
ensure it is trusted and that additional rate limiting is in place.

## Rate Limiting (Redis)

Per-IP rate limiting uses Redis as a sliding window counter store.
The server connects to Redis on startup (non-fatal if unavailable —
rate limiting is simply disabled).

**Requires:** `redis-server` running on `127.0.0.1:6379` (default).

```bash
sudo apt install -y redis-server libhiredis-dev
redis-cli ping   # should return PONG
```

### Limits

| Category | Endpoint | Per-IP/Min | Per-IP/Hour |
|----------|----------|-----------|------------|
| Read | All `GET` endpoints | 60 | 600 |
| Leaf nonce | `POST /enrollment/nonce` (type=leaf) | 10 | 100 |
| CA nonce | `POST /enrollment/nonce` (type=ca) | 3 | 10 |
| Enroll | `POST /certificate/request` | 3 | 10 |
| Revoke | `POST /revoke` | 2 | 5 |
| **Global** | **Any endpoint (catch-all)** | **120** | **1200** |

Both the category-specific limit and the global limit are checked for
every request. The first one exceeded triggers a `429 Too Many Requests`
response.

### How It Works

- Redis keys: `rl:<ip>:<category>:m` (per-minute, TTL 60s) and
  `rl:<ip>:<category>:h` (per-hour, TTL 3600s)
- Uses `INCR` + `EXPIRE` — counters auto-expire when the window passes
- If Redis is down, all requests are allowed (fail-open)
- Rate limit hits are logged at INFO level

### Monitoring

```bash
# See all rate limit keys
redis-cli KEYS "rl:*"

# Check a specific IP's minute counter for reads
redis-cli GET "rl:203.0.113.42:0:m"

# Flush all rate limit state
redis-cli KEYS "rl:*" | xargs redis-cli DEL
```

## Listener Ports

The server can run up to three listeners simultaneously, all serving the
same REST API through a unified request dispatcher:

| Port | Protocol | Flag | Purpose |
|------|----------|------|---------|
| 8444 | TLS 1.3 (SLC) | `--port` | Primary HTTPS API |
| 8445 | DH bootstrap | `--dh-port` | Pre-TLS enrollment (X25519 + AES) |
| 8446 | MQC | `--mqc-port` | Post-quantum API (ML-KEM-768 + ML-DSA-87 + AES-256-GCM) |

The DH bootstrap and MQC listeners run on background threads. The TLS
listener runs on the main thread and blocks.

### MQC (Post-Quantum) Listener

The MQC port speaks the same HTTP API as the TLS port, but over the MQC
post-quantum protocol instead of TLS. Connections are authenticated via
Merkle tree certificates and ML-DSA-87 signatures.

The server's MQC identity comes from `--tpm-path` (e.g.,
`~/.TPM/factsorlie.com-ca`), which must contain `certificate.json` and
`private_key.pem` (ML-DSA-87).

The server auto-detects whether a client uses clear or encrypted identity
mode (no configuration needed).

### MQC Rate Limits

Separate from the HTTP rate limits, the MQC listener has its own
connection-level rate limiting:

| Counter | Per-IP/Min | Per-IP/Hour | Description |
|---------|-----------|------------|-------------|
| Connect | 10 | 60 | Total MQC connections |
| Fail | 3 | 10 | Failed handshakes only (incremented on actual failure) |

Redis keys: `mqc:<ip>:conn:m`, `mqc:<ip>:conn:h`, `mqc:<ip>:fail:m`,
`mqc:<ip>:fail:h`.

### Client Tools over MQC

`show-tpm` supports verification over the MQC protocol:

```bash
# Verify TPM entries via MQC (post-quantum)
show-tpm --mqc --verify

# With explicit TPM identity and server
show-tpm --mqc --verify --tpm-path ~/.TPM/factsorlie.com -s localhost:8446
```

## Input Validation

The server validates all request parameters:

| Parameter | Validation |
|-----------|-----------|
| `validity_days` | Must be 1–3650 (rejected otherwise) |
| `key_algorithm` | Whitelist: EC-P256, EC-P384, Ed25519, ML-DSA-44/65/87 |
| `public_key_fingerprint` | Must be exactly 64 hex chars after `sha256:` prefix |
| Path indices (`/log/entry/<N>`) | Parsed with bounds check (0–10M), rejects non-numeric |
| `Content-Length` | Rejects bodies larger than buffer (413 Payload Too Large) |

## HTTP Security Headers

All responses include:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
```

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

`mtc-ca.service` runs the server with TLS + ECH on port 8444, DH bootstrap
on port 8445, and MQC on port 8446. Edit the file if your paths differ.

```ini
ExecStart=/usr/local/bin/mtc_server \
    --port 8444 \
    --data-dir /home/ubuntu/.mtc-ca-data \
    --tokenpath /home/ubuntu/.env \
    --ca-name MTC-CA-C \
    --log-id 32473.2 \
    --tls-cert /home/ubuntu/.mtc-ca-data/server-cert.pem \
    --tls-key /home/ubuntu/.mtc-ca-data/server-key.pem \
    --ech-name factsorlie.com \
    --log-level 4 \
    --dh-port 8445 \
    --mqc-port 8446 \
    --tpm-path /home/ubuntu/.TPM/factsorlie.com-ca
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
| `POST /revoke` | Revoke a LEAF certificate (CA-signed; see below) |

### POST /revoke — CA-signed leaf revocation

Authentication model:
- Caller must be a **CA** (subject ends in `-ca`).
- Target must be a **leaf** (subject does not end in `-ca`).
- Target subject must be `<ca-domain>` or `*.<ca-domain>`.
- A CA may not revoke itself (`ca_cert_index != cert_index`).

Request body (all fields required):

```json
{
  "ca_cert_index":     42,
  "cert_index":        73,
  "reason":            "key compromise",
  "timestamp":         1776530000,
  "ca_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "signature":         "<hex>"
}
```

`signature` covers the UTF-8 string
`revoke:<ca_cert_index>:<cert_index>:<reason>:<timestamp>` using
whatever algorithm the CA's log entry recorded
(EC-P256/P-384, Ed25519, ML-DSA-44/65/87). `timestamp` must be within
±5 minutes of the server's clock.

Error responses: `400` malformed/stale, `403` for every authorization
violation (not a CA, target not a leaf, outside domain, self-revoke,
PEM hash mismatch, signature mismatch), `404` if either index is not
in the log.

On success: `200 {revoked:true, cert_index:N, ca_cert_index:M,
target_subject:"...", reason:"..."}` and the target is added to the
server's signed revocation list immediately.

Use `/usr/local/bin/revoke-key --target-index N` to build and sign
this request automatically from your CA's on-disk identity — see the
tool's `--help` for `--list`, `--refresh`, and `--dry-run` modes.

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
| `create_leaf_keypair.py <domain>` | Generate leaf key pair |
| `create_server_cert.py <domain>` | Generate ML-DSA-87 server TLS cert |
| `ca_dns_txt.py <cert.pem>` | Generate/verify DNS TXT for CA validation |

## C Tools

Installed to `/usr/local/bin` by `sudo make install`:

| Tool | Purpose |
|------|---------|
| `mtc_server` | MTC CA/Log server |
| `show-tpm` | List and verify `~/.TPM` credential store |
| `bootstrap_ca` | DH bootstrap CA enrollment client |
| `bootstrap_leaf` | DH bootstrap leaf enrollment client |

## See Also

- `mtc-keymaster/README-clean-install.md` — Full install guide (steps 1-14)
- `mtc-keymaster/README-bugsandtodo.md` — TODO items and design docs
- `mtc-keymaster/README-ml-dsa-87.md` — How MTC reduces PQ TLS overhead
- `mtc-keymaster/renew-tool/README.md` — Renewal tool documentation
