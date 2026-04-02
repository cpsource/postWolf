# MTC Certificate Renewal Tool

Automatic renewal for MTC (Merkle Tree Certificate) certificates. Scans
local `~/.TPM` storage and optionally the Neon PostgreSQL database for
certificates approaching expiry, then re-enrolls them through the MTC CA
server.

Revoked certificates are detected per-cert via the CA server's
`/revoked/<index>` endpoint and skipped automatically.

## Quick Start

```bash
# Dry run — see what would be renewed
python3 renew.py --dry-run

# Renew certificates expiring within 30 days (default)
python3 renew.py

# Also check Neon database for certs not in ~/.TPM
python3 renew.py --neon

# Install as daily cron job (3:00 AM)
./install_cron.sh
```

## How It Works

1. **Scan** `~/.TPM/*/certificate.json` for `not_after` timestamps
2. Optionally **scan** Neon `mtc_certificates` table for additional certs
3. For each cert within the renewal window, **check revocation** via
   `GET /revoked/<index>` — revoked certs are skipped
4. **Re-enroll** by POSTing to the CA server's `/certificate/request`
   endpoint (the server writes the new cert to Neon automatically)
5. **Update** `~/.TPM/<subject>/` with the new `certificate.json`,
   `index`, and optionally rotated keys
6. **Run hooks** (pre-renew, post-renew, on-error)

## CLI Options

```
usage: renew.py [-h] [-c CONFIG] [-n] [--server URL] [--days N]
                [--rotate-keys] [--neon] [-v]

  -c, --config PATH   Path to renew.conf
  -n, --dry-run       Check expiry without renewing
  --server URL        Override CA server URL
  --days N            Override renewal threshold (days before expiry)
  --rotate-keys       Generate fresh keys on renewal
  --neon              Also scan Neon database
  -v, --verbose       DEBUG-level logging
```

## Configuration

Edit `renew.conf` (INI format):

```ini
[renewal]
server = http://localhost:8443
tpm_dir = ~/.TPM
renew_days_before = 30
validity_days = 90
rotate_keys = false
key_algorithm = EC-P256
dry_run = false

[neon]
enabled = false
env_file = ~/.env
env_var = MERKLE_NEON

[hooks]
pre_renew =
post_renew = systemctl reload mtc-ca
on_error =

[logging]
level = INFO
file = /var/log/mtc-renew.log
```

### Hooks

Hook commands receive environment variables:
- `$MTC_SUBJECT` — certificate subject name
- `$MTC_INDEX` — certificate log index

## Cron Installation

```bash
# Daily at 3 AM (default)
./install_cron.sh

# Every 12 hours
./install_cron.sh --schedule "0 */12 * * *"

# Custom config path
./install_cron.sh --config /etc/mtc/renew.conf

# Remove
./install_cron.sh --remove
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | All certificates OK or renewed successfully |
| 1    | One or more renewals failed |
| 2    | Configuration or startup error |

## Key Rotation

By default, the existing public key is reused on renewal. To generate
fresh keys each time:

```bash
python3 renew.py --rotate-keys
```

Or set `rotate_keys = true` in `renew.conf`. The old private key is
overwritten in `~/.TPM/<subject>/private_key.pem`.

## Dependencies

- Python 3.10+
- `cryptography` (for key generation when rotating keys)
- `psycopg2` (only if `--neon` / `neon.enabled = true`)
