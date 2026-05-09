# postWolf MTC database backup

Plain-SQL `pg_dump`-based backups of the postWolf MTC Neon database,
synced to S3 with a tiered retention policy.

Adapted from the FrFlashCards `tools/neon_tools/` workflow; same
mechanism, postWolf-specific paths and bucket.

## Prerequisites

- `psql` (`sudo apt install postgresql-client`) — for restore.  Backup
  itself uses the bundled pg_dump 17 from `pg17/`; install via
  `./install-pg17.sh` (one-time, ~2.5 MB download from apt.postgresql.org;
  extracts into `pg17/` without touching system libpq).
- `aws` CLI configured with access to `s3://postwolf-neon-backups`
  (see `~/.aws/credentials`)
- `~/.env` contains `MERKLE_NEON=<connection string>` — the same env
  var `mtc_server` reads (see `mtc-keymaster/server2/c/mtc_db.c`)
- Python 3 (for the retention manager)

### Why a bundled pg_dump?

Neon currently runs PostgreSQL **17.x**, but Ubuntu 24.04 ships
`pg_dump 16`, which refuses with `server version mismatch`.  Adding
the pgdg apt repo would transitively upgrade `/usr/lib`'s `libpq5` to
18.x — that's already triggered an `mtc-ca` outage on this box once
(2026-05-09: apt postinstall restarted the service onto a fresh libpq
that exposed a latent search_path bug).  `install-pg17.sh` therefore
ships a self-contained pg_dump 17 + libpq under `pg17/`, used via
`LD_LIBRARY_PATH` so the system stays clean.

## First-time setup

```bash
./install-pg17.sh
aws sts get-caller-identity   # confirm AWS credentials work
./backup.sh                   # smoke test
```

## Quick reference

| Command | Effect |
|---|---|
| `./backup.sh` | Full pipeline: dump → S3 sync → prune → list |
| `./backup-development.sh` | One-shot pg_dump to `db/postwolf_backup_*.sql` |
| `./backup-schema-only.sh` | Schema-only dump to `schema-only.sql` |
| `./cp-to-s3.sh` | `aws s3 sync db/ → s3://postwolf-neon-backups` |
| `./age-backups.sh` | Apply retention (3d / 2w / 1m); pass `--dry-run` to preview |
| `python3 age-backups.py --help` | Full retention CLI |

## Retention policy

| Tier | Kept |
|---|---|
| Daily | 3 most recent days |
| Weekly | 2 most recent prior ISO weeks |
| Monthly | 1 most recent prior month |

`backup.sh` applies this policy to both local and S3 every run.

Useful flags:

```bash
# Preview without deleting
./age-backups.sh --dry-run

# Local-only / remote-only
./age-backups.sh --local
./age-backups.sh --remote

# Simulate a date (testing the policy)
./age-backups.sh --todays-date 2026-06-01 --dry-run
```

## Restoring

Stream from S3 directly into psql (no temp file):

```bash
set -a; . ~/.env; set +a
aws s3 cp s3://postwolf-neon-backups/postwolf_backup_YYYYMMDD_HHMMSS.sql - \
    | psql "$MERKLE_NEON"
```

Or from a local copy:

```bash
set -a; . ~/.env; set +a
psql "$MERKLE_NEON" < db/postwolf_backup_YYYYMMDD_HHMMSS.sql
```

## File layout

| Path | Purpose |
|---|---|
| `backup.sh` | Orchestrator (dump + sync + prune + list) |
| `backup-development.sh` | `pg_dump` wrapper |
| `backup-schema-only.sh` | Schema-only `pg_dump` |
| `cp-to-s3.sh` | One-line `aws s3 sync` |
| `age-backups.sh` | Retention wrapper (3 / 2 / 1 defaults) |
| `age-backups.py` | Retention engine (local + S3) |
| `db/` | Local backup directory (gitignored) |
| `schema-only.sql` | Schema dump output (gitignored) |

## Cron suggestion

```cron
# Nightly at 02:30 UTC
30 2 * * * cd $HOME/postWolf/backup && ./backup.sh >> $HOME/postWolf/backup/backup.log 2>&1
```
