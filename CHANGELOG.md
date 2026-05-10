# Changelog

All notable postWolf-specific changes are documented in this file.
postWolf is forked from wolfSSL but tracks its own release history;
upstream wolfSSL versions are referenced only at merge-from-upstream
points (e.g. via `wolfssl-merge-to-postWolf`).

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Tags follow semver-style `vMAJOR.MINOR.PATCH`.  The project is
intentionally in `0.x` — wire formats (MQC, FIPS canonical-leaf,
on-disk schemas) are still subject to flag-day changes; per SemVer
2.0 anything goes in `0.MINOR.PATCH`.  `1.0.0` will be cut when the
public surface is committed to.

postWolf is a fork of wolfSSL with three additional layers built on
top:
- **SLC** (`socket-level-wrapper/`) — TLS 1.3 + ECH + MTC socket wrapper
- **MQC** (`socket-level-wrapper-MQC/`) — Merkle Quantum Connect
  (ML-KEM-768 + ML-DSA-87 + AES-256-GCM, no TLS)
- **MTC** (`mtc-keymaster/`) — CA + transparency-log server + tooling
- **FIPS framework** (`fips-framework/`) — package-manifest pipeline
  anchored in the MTC log

See `CLAUDE.md` for the architectural overview, `README.md` for the
project's narrative, and `mtc-keymaster/README-bugsandtodo.md` for
the open issue list.

## [Unreleased]

### Added

- **`GET /log/diagnostics` server endpoint** + `show-tpm --verify`
  consumer.  Returns `{log_entries_count, log_entries_max_index,
  checkpoint_tree_size, tiles_max_leaf_coverage,
  last_tile_update_age_sec, last_tile_update_iso}` so operators can
  cross-check the SQL log against the on-disk Merkle tile store.
  Tile writes only fire on odd-indexed appends (when a sibling pair
  completes a parent), so `tiles_max_leaf_coverage = 2 * MAX(first_node
  + node_count)` over level-1 rows in `mtc_merkle_tiles`, and a lag
  of 1 (unpaired right-edge leaf) is the normal steady-state.
  `show-tpm --verify` flags `[TILES STALE]` only when `lag > 1` AND
  `last_tile_update_age_sec > 3600`.  Read-only endpoint, no schema
  changes.
- **`fips-manifest-submit` phase-2 wire submit** — the tool now POSTs
  the canonical leaf to `/fips/manifest` over MQC by default
  (`--dry-run` preserves the offline build-and-sign mode).  Reads
  `<source-dir>/MANIFEST.sha256` (produced by `sign-dir.sh`) instead
  of re-walking + re-hashing the source tree, so the file→hash table
  is whatever sign-dir.sh decided to include (with `-g`, gitignored
  artefacts are excluded).  `# publisher:`, `# publisher-cert-index:`,
  and `# git-commit:` headers from the manifest are cross-checked
  against `--domain` + on-disk cert + carried into the canonical
  leaf.  Server's JSON receipt persisted under
  `<tpm_dir>/fips-receipts/<package>-<version>-<log_index>.json`
  for later `fips-manifest-verify --receipt` use.  New flags:
  `--manifest PATH`, `--receipt-out FILE`, `-s/--server H[:P]`.
  `--label` is now optional (matches `sign-dir.sh`'s `~/.TPM/<DOMAIN>/`
  convention).  Inline `mqc_http_post` mirrors the same shape used
  by `fips-manifest-revoke`.  Closes the supported-submitter gap
  under TODO #7.

### Fixed

- **Concurrent fips submits silently corrupting state** — forked-after-
  accept workers inherited the parent's PGconn struct in
  `store->tree.conn` (set once at server-startup time before the fork).
  `mtc_db_after_fork` (TODO #25) cleared `store->db` so the next
  `mtc_db_ensure_connected` would lazily open a fresh per-child
  connection, but left `store->tree.conn` pointing at the parent's
  PGconn — every tile read/write in a child went through the
  inherited fd, multiple children sharing one TLS socket corrupted
  the GCM record stream (`SSL error: decryption failed or bad record
  mac`), and subsequent queries failed with `no connection to the
  server`.  In `mtc_store_add_entry`, after `mtc_db_ensure_connected`,
  re-point `store->tree.conn = store->db` so the freshly-opened
  per-child PGconn is used for tile-store I/O too.

- **Stale `store->tree.size` in forked workers** — a sibling worker
  committing a new leaf doesn't propagate to other children's
  in-memory tree.  Without sync, a stale worker assigns the now-
  occupied `idx_target = store->tree.size`, `mtc_db_save_entry`'s
  `ON CONFLICT (index) DO NOTHING` clause silently dropped the new
  payload, the rest of the pipeline (tile writes, search-index
  INSERT, receipt builder) ran on a corrupt picture and ultimately
  reported `inclusion_proof failed` even though the leaf was
  technically in the SQL log.  In `mtc_store_add_entry`, after
  taking the per-log advisory lock, resync `store->tree.size` from
  `mtc_tile_store_get_tree_size` (== `MAX(index)+1` over
  `mtc_log_entries`).  The lock guarantees no other worker advances
  the DB between the SELECT and the subsequent INSERT.

- **`mtc_db_save_entry` silent drop on conflict** — removed
  `ON CONFLICT (index) DO NOTHING` from the insert.  Callers
  (`mtc_store_add_entry`) hold the advisory lock AND resync
  `tree.size` before assigning, so a duplicate-key error means a
  real invariant violation that should surface, not be silently
  swallowed.

- **`mtc_tile_store_get_tile` on -2** — log the underlying
  `PQerrorMessage` text instead of returning -2 silently.  Without
  it, a query failure propagated upward as a generic "inclusion
  proof failed" with no operator-side breadcrumb.

- **`fips-manifest-submit`'s response reader** — `mqc_read` consumes a
  frame's length prefix BEFORE checking that the frame fits in the
  caller's buffer, so a frame larger than the buffer returns -1
  with the bytes already off the wire (`socket-level-wrapper-MQC/
  mqc_common.c:1860-1861`).  The server packs HTTP header + body
  into one AEAD frame (`mtc_http.c::http_send_json` comment), and a
  fips-manifest receipt with the full canonical leaf + inclusion
  proof + cosignatures easily exceeds the prior 16 KB initial
  buffer.  Pre-size to `MQC_MAX_MSG` (1 MiB, the single-frame
  ceiling) so the first read can always fit.  Same latent bug
  exists in the inlined `mqc_http_get`/`mqc_http_post` copies in
  `fips-manifest-revoke.c`, `fips-manifest-list.c`,
  `fips-manifest-verify.c`, and the mtc-keymaster client tools —
  not fixed here; they happen to work today only because their
  response payloads are small.

## [0.1.2] — 2026-05-09

### Added

- `backup/` directory with the postWolf MTC Neon database backup
  pipeline, modelled on FrFlashCards' `tools/neon_tools/`:
  - `backup.sh` orchestrator (pg_dump → S3 sync → 3d/2w/1m
    retention → cleanup → list)
  - `backup-development.sh` / `backup-schema-only.sh` /
    `cp-to-s3.sh` / `age-backups.{sh,py}`
  - `install-pg17.sh` — fetches PostgreSQL 17 client + libpq from
    apt.postgresql.org and extracts under `pg17/` (LD_LIBRARY_PATH
    used so the system libpq stays at v16; pgdg apt repo is
    intentionally not added — see CHANGELOG entry under "Fixed"
    for why).  S3 bucket: `postwolf-neon-backups` (us-east-1).
- TODO #78 in `mtc-keymaster/README-bugsandtodo.md` —
  external-review-derived hardening proposal for the `mqc`
  symmetric envelope (name the cipher, bind metadata as AEAD AAD,
  raise KDF cost or move to Argon2id, add `key_id` + monotonic
  version for rollback protection).  Severity Medium.  Original
  review captured verbatim in
  `socket-level-wrapper-MQC/README-mqc-tool-hardening-todo-78.md`.
- TODO #79 + `socket-level-wrapper-MQC/README-argon2.md` — switch
  the `mqc` KDF from scrypt to Argon2id (RFC 9106).  One slice of
  #78, carved out so it can land independently.  Reference doc
  covers what Argon2id is, why over scrypt, library options
  (wolfCrypt recommended), migration shape, and verification
  recipe.
- `server-configuration-data/` directory with two encrypted-at-rest
  artifacts and a `restore.sh` for fresh-machine setup:
  - `env.enc.json` — `mqc`-sealed copy of `~/.env`
  - `auth-bundle.tar.enc.json` — `mqc`-sealed tar of
    `.claude/.credentials.json`, `.config/gh/`, `.ssh/`, `.gnupg/`,
    `.aws/`
  Both blobs use AES-256-GCM with a scrypt-derived key from
  `MQC_MASTER_PASSWORD`.  `restore.sh` prompts (or takes `-p
  PASSWORD`), supports `--env-only` / `--auth-only` / `-n` dry-run /
  `-f` force, and shows the tar manifest before extracting.

### Fixed

- `mtc_db_connect()` now issues `SET search_path = public` after
  `PQconnectdb` so unqualified table references work regardless of
  Neon pooler state.  Neon's pgbouncer-style pooler reuses backends
  across clients and doesn't replay role/database SET defaults — so a
  fresh client could inherit a backend with empty `search_path` and
  every `CREATE TABLE IF NOT EXISTS mtc_log_entries (…)` would fail
  with "no schema has been selected".  Latent until something forced
  `mtc-ca` to reconnect; surfaced when an apt postinstall hook
  restarted the service after a transitive `libpq5` upgrade (which
  is why `backup/install-pg17.sh` does NOT add the pgdg apt repo).

## [0.1.1] — 2026-05-09

### Added

- `skills/` directory + `README-skills.md` at the repo root.
  Mirrors of the user-authored Claude Code skills
  (`cut-release`, `wolfssl-merge-to-postWolf`,
  `wolfssl-issue-review`, `auto-doc-cpsource`,
  `code-review-cpsource`) so the workflows are version-controlled
  alongside the code they operate on.  Install on a fresh machine
  with `cp -r ~/postWolf/skills/* ~/.claude/skills/`; full
  authoring + update guide in `README-skills.md`.

## [0.1.0] — 2026-05-09

First tagged release of the postWolf-specific stack on top of
upstream wolfSSL.  The MQC + MTC + FIPS-framework story is
end-to-end functional: identities can enrol, MQC handshakes run
post-quantum, FIPS manifests can be browsed/revoked over MQC, and
directory signatures verify cross-host with authoritative key
fetch from the log server.

### Added
- **FIPS-manifest revocation pipeline** — `POST /fips/revoke` endpoint
  + `GET /fips/revoked/<log_index>` read-side, mirrored
  `mtc_fips_manifest_revocations` table (DB-only, same shape as
  `mtc_revocations`).  Dual-arm authority: the publisher leaf may
  self-revoke or the publisher's CA may take down a release.  ML-DSA-87
  signature over `fips-revoke:<kind>:<revoker>:<log>:<reason>:<ts>`.
  In-handler revocation gate blocks revoked publishers; revoked CAs
  pass for emergency-recovery use.
- **`/fips/list` endpoint** — read-only browser over
  `mtc_fips_manifest_entries` joined with both revocation tables.
  Surfaces `manifest_revoked` + `publisher_cert_revoked` per row;
  detail mode embeds the full canonical manifest + nested revocation
  block.
- **`fips-manifest-revoke`** — MQC client that signs and POSTs
  revocation requests.  Auto-discovers identity under `~/.TPM`,
  reads `url-server` from `/etc/postWolf/config`, supports
  `--as publisher|ca`.
- **`fetch-publisher-key`** — small MQC helper that retrieves a
  publisher's PEM authoritatively from the server (`GET
  /public-key/<DOMAIN>`) and validates `sha256(pem) == cert.spk_hash`
  via `GET /certificate/<N>`.  Used as the cross-publisher fallback
  in `verify-dir.sh`.
- **`fips-manifest-verify --check-revocation`** — opt-in online check
  that queries both `/fips/revoked/<log>` and `/revoked/<cert>` between
  stages 5 and 6.  Default mode stays fully offline.
- **`fips-manifest-list`** — MQC client for browsing the FIPS log
  with table / detail / JSON renderers; no DB credentials needed.
- **`sign-dir.sh -g/--respect-gitignore`** — switches the file walk
  to `git ls-files --cached --others --exclude-standard`, so files
  matched by `.gitignore` (build artifacts, secrets) are excluded.
  Fixes the latent bug where built binaries inflated the file set
  on the signer's host but were absent on a fresh clone.
- **`verify-dir.sh -v/--verbose`** — surfaces per-file `OK` lines
  from `sha256sum` (default is quiet — only failures print).
- **`fips-framework/README-getting-started-guide.md`** — end-to-end
  walkthrough from "I have a leaf identity" to remote verification +
  revocation, plus a complete tools/ reference.
- **Tools install hook** — `make -f Makefile.tools install` now
  installs `sign-dir.sh`, `verify-dir.sh`, `fetch-publisher-key`,
  and the four `fips-manifest-*` C tools to `/usr/local/bin/`.
- **`fips-framework/tools/c/config.h`** — guarded fallback constants
  (`MQC_DEFAULT_SERVER_PORT`, `MQC_DEFAULT_SERVER_HOST`) so the FIPS
  tools have sane defaults if the wrapper's `config.h` isn't in the
  include path.

### Changed
- **`verify-dir.sh` pubkey resolution** — when the local identity dir
  isn't present, shells out to `fetch-publisher-key --cert-index <N>`
  for an authoritative server-fetched PEM (validated against the
  cert's `subject_public_key_hash`).  Previously fell back to a
  `~/.TPM/peers/<N>/` cache, which trusted potentially-stale local
  state; new behaviour matches `mqc_peer.c`'s trust model.  Output
  line annotates which path was taken (`key=local-identity ...` vs
  `key=server-fetch ...`).
- **`show-tpm --verify`** — adds a per-peer-cache pass that hashes
  every `~/.TPM/peers/<N>/public_key.pem` against the cached
  `certificate.json`'s `subject_public_key_hash`.  Closes the gap
  that masked a post-migration desync where the cached cert + cached
  PEM diverged silently while the rest of the verify reported clean.
- **`fips-manifest-list`** — table view's status column moved from
  `MANIF / CERT / BOTH` abbreviations to human-readable
  `Manifest Revoked / Cert Revoked / Manifest & Cert Revoked / OK`,
  with a footer hint pointing at detail view when any row is flagged.
- **`fips-framework/MANIFEST.{sha256,sig}`** — re-signed with
  `-g` to exclude built tool binaries.  Prior manifests would fail
  to verify on a fresh clone because the binaries weren't present.
- **`Makefile.tools`** — wires in a new `fips` target that builds
  + installs everything under `fips-framework/tools/c/`.

### Fixed
- **Stale peer-cache on factsorlie + frflashy** — `~/.TPM/peers/72/`
  carried the old cert-72 spk_hash from before the May-8 key
  migration, breaking every MQC handshake into / out of cert 72.
  Refreshed `certificate.json` and `leaf_hash.hex` from Neon's
  authoritative `mtc_certificates` + `mtc_log_entries.leaf_hash`.
- **Hardcoded fallback port literal in `fips-manifest-list.c`** —
  replaced `int port = 8446;` with `MQC_DEFAULT_SERVER_PORT` from
  the new `tools/c/config.h`, so the "no hardcoded ports" rule is
  observed in the source even on the never-triggered fallback path.

### Removed
- Stale top-level `fips-framework/Makefile` stub (predated the real
  `fips-framework/tools/c/Makefile` and never built the current
  sources).

## Earlier history

Pre-`[Unreleased]` history lives in the commit graph (`git log
master`) and is summarised feature-by-feature in
`mtc-keymaster/README-bugsandtodo.md`.
