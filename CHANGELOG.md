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

(no changes since 0.2.2)

## [0.2.2] — 2026-05-13

Small qsh / qshd quality-of-life pass: failure-handling fix on the
client, `$HOME` landing on the server, and a new top-level deployment
kit for shipping the qsh client to other hosts.

### Added

- **`kit-qsh/`** — top-level directory that builds a self-contained
  `deploy-qsh.tar.gz` for running `qsh` on a fresh host without
  checking out the postWolf tree.  Bundles the `qsh` binary, the
  `check-qsh-deps.py` runtime-library audit, an Augeas `Myconf` lens
  + minimal `postWolf.config` template, a `TPM/factsorlie.com/`
  identity dir, and a recipient-side `Makefile` with `check` /
  `install` / `install-bin` / `install-config` / `install-tpm` /
  `uninstall` / `run` targets.  See `kit-qsh/README.md` for build
  knobs and `deploy-qsh/README.md` (in the tarball) for recipient
  usage.
- **`qsh/check-qsh-deps.py`** — standalone Python script that reads
  a qsh binary's `DT_NEEDED` entries (or uses a baked-in list when
  no binary is on hand) and reports which runtime libraries are
  installed on the local box.  Suggests an `apt install` line for
  the gaps.
- **TODO #82** in `mtc-keymaster/README-bugsandtodo.md` — preventive
  hardening: tighten Redis `bind 0.0.0.0` -> `bind 127.0.0.1 -::1`
  and `protected-mode no` -> `protected-mode yes` on every host
  running `qshd`.  Severity Low (AWS SG already blocks `:6379`
  externally); defense in depth against SG-config churn.

### Changed

- **`qsh` no longer tight-loops when `qshd` refuses by ACL.**  The
  old retry budget reset the instant `mqc_connect` returned, before
  `qshd` had a chance to evaluate its `cert_index` ACL — so an
  ACL-denied caller looped forever until Ctrl-C.  `run_session` now
  reports whether the server ever sent a frame; if not, the client
  treats the disconnect as a hard refusal, prints `qsh: server
  closed connection before responding (qshd ACL refused
  cert_index=N?)`, and exits.  Mid-session disconnects (after at
  least one frame from the server) still retry up to 5x as before.
- **`qshd` lands the shell in the running user's `$HOME`.**  systemd
  starts the service with `cwd=/`, so a shell forked by `forkpty()`
  inherited `/` unless `--user` was set.  When `--user` is absent,
  `qshd` now looks up `getpwuid(getuid())->pw_dir` and chdirs there
  before `execl("bash")`.  The `--user` path is unchanged.

## [0.2.1] — 2026-05-13

Internal cleanup release: a small ergonomic fix on the new `qsh` /
`qshd` CLI plus an `libmqc.a` restructure that keeps server-only
dependencies (libcurl, libhiredis) off pure MQC client link lines.
No wire-format or API changes.

### Added

- **`mqc_abuseipdb.c`, `mqc_ratelimit.c`, `mqc_clear_accept.c`,
  `mqc_encrypted_accept.c`, `mqc_accept_dispatch.c`** as separate
  translation units inside `socket-level-wrapper-MQC/`.  Each holds
  one well-defined server-only concern (AbuseIPDB lookup, Redis
  rate-limit gates, accept-side handshake bodies, accept dispatcher).
  Static-archive symbol demand now confines libcurl + libhiredis to
  these object files; client-only consumers no longer drag them in.

### Changed

- **`--tpm-path=~/...` now expands `~/` to `$HOME/`** in both `qsh`
  and `qshd`.  Shells don't expand `~` in `--flag=~/...` because the
  `=` makes the tilde part of an assignment word, so the literal `~`
  reached the program and `mqc_ctx_new` failed to read the TPM dir.
- **`libmqc.a` translation-unit layout split along the client/server
  axis** (TODO #81 in `mtc-keymaster/README-bugsandtodo.md`).
  `mqc_common.c`, `mqc_clear.c`, `mqc_encrypted.c`, and `mqc.c` keep
  only client-needed code; accept-side handshake bodies and the
  rate-limit/AbuseIPDB chain moved into the new TUs listed above.
  `nm libmqc.a` now shows `curl_easy_*` only in `mqc_abuseipdb.o`,
  `redisCommand` only in `mqc_ratelimit.o`, and `ub_resolve*` only in
  `mqc_dnssec_pin.o`.
- **`qsh`, `fips-manifest-*`, `fetch-publisher-key`, `show-tpm`,
  `issue_leaf_nonce`, `revoke-key`, `renew-cert`,
  `check-renewal-cert`, `cancel-nonce`** drop `-lcurl -lhiredis` from
  their link lines.  `ldd` confirms no `libhiredis` is pulled.
  `qshd` continues to link both (it accepts connections).
- `libunbound` stays on every client link: `mqc_load_ca_pubkey`
  (a client API) invokes the cosigner DNSSEC pin in
  `mqc_dnssec_pin.c`.

### Removed

- ~470 lines of duplicated server-side code from `mqc_common.c` /
  `mqc_clear.c` / `mqc_encrypted.c` (moved into the new TUs above,
  not deleted from the binary).

## [0.2.0] — 2026-05-11

New post-quantum interactive-shell tool family (`qsh` / `qshd`) on top
of MQC, plus a small additive accessor (`mqc_get_peer_subject`) for
identifying the verified peer of any MQC connection.

### Added

- **`qsh` / `qshd` — interactive shell over MQC.**  Port of an
  earlier QUIC/ngtcp2 + X.509/CRL ssh-like tool onto the post-quantum
  MQC transport.  Authentication is a verified MTC `cert_index` plus
  Merkle inclusion proof + cosignature + revocation check (all
  handled inside `mqc_peer_verify` — no separate CRL).  Four-frame
  protocol on the bytestream: `OPEN_SHELL` / `DATA` / `RESIZE` /
  `SHELL_EXIT`.  Server forkpty()s a real `bash --login` per session.
  Source lives in `qsh/`; binaries install to `/usr/local/bin/qsh`
  and `/usr/local/bin/qshd`.
- **`qshd` cert_index ACL** at `/etc/qsh/qshd/config`.  Rules
  `allow N`, `allow N-M`, `deny N`, `deny N-M`, `default allow|deny`.
  Top-to-bottom, first match wins; fall-through default is `deny`;
  an absent or empty file denies every connection (fail-closed).
  Refused callers log `[qshd] DENIED by ACL: peer_index=N` before
  the daemon closes the conn.  Revocation continues to be handled
  by MQC itself; the ACL layers on top.
- **`qshd.service` systemd unit.**  Installed to
  `/etc/systemd/system/qshd.service` by `Makefile.tools install`;
  `User=ubuntu`, `LD_LIBRARY_PATH=/usr/local/lib`,
  `TimeoutStopSec=5`.  Disabled by default — operator runs
  `systemctl enable --now qshd` when ready.
- **`[qsh]` section in `/etc/postWolf/config`.**  New key
  `qshd-port` (default `1024`, the first non-privileged TCP port).
  Both `qsh` and `qshd` call `read_config_long("qsh/qshd-port",
  FALLBACK_PORT)`; `--port=N` on either CLI overrides.
- **`mqc_get_peer_subject(mqc_conn_t *)` accessor** in
  `libmqc.a`.  Returns the verified MTC subject string of the
  remote peer (e.g. `"factsorlie.com-ca"`) for any successful MQC
  connection.  Populated at handshake completion in all four sites
  (clear / encrypted × client / server); freed in `mqc_close`.
  `mtc_server`'s per-accept log line now reads
  `MQC connection from <ip> (peer_index=N, subject=<subject>)`.
- **`Makefile.tools qsh` target.**  Depends on `mqc`, added to
  `all` and `clean`.  `install` cmp-then-installs the binaries
  and the service unit (auto-restart-if-running, same pattern as
  `mtc-ca.service`) and ships the deny-all ACL template to
  `/etc/qsh/qshd/config` only if the file is absent — operator
  edits are preserved.
- **TODO #81** filed in `mtc-keymaster/README-bugsandtodo.md`:
  split `mqc_common.c` along the client-vs-server axis so
  client-only consumers of `libmqc.a` (qsh, fips-manifest-*,
  fetch-publisher-key) can drop the transitive `-lcurl`,
  `-lhiredis`, and `-lunbound` flags.  Severity: Low (cosmetic).

### Changed

- **qshd shutdown hardened.**  Signals installed via `sigaction()`
  without `SA_RESTART` so `SIGINT` / `SIGTERM` interrupt the
  blocking `accept()` inside `mqc_accept_auto`.  Previously
  `systemctl stop qshd` hung in `deactivating` until forcibly
  killed.

### Removed

- **QUIC-era archaeology from `qsh/`** (the directory carried over
  from `~/ngtcp2/ssh/` when the tool was tar-copied in).  Deleted:
  `README-QUIC.md`, `client-ext.cnf`, `make-certs.sh`, `rfc9000.txt`,
  `docs/`, `tools/`, plus the gitignored `certs/` and `crl/` trees.
  The new `qsh/README.md` describes only the MQC flow.

## [0.1.4] — 2026-05-11

### Changed

- **`mtc-ca` server log prefix `[wolfSSL]` → `[postWolf]`.**  The
  `wolfSSL_SetLoggingCb()` bridge in `mtc_server.c` previously stamped
  every forwarded library log line with `[wolfSSL]` in journalctl,
  which reads wrong now that the packaging layer is `libpostWolf`.
  The prefix is now `[postWolf]` and the postWolf-owned bridge
  function was renamed `wolfssl_log_bridge` → `postwolf_log_bridge`
  for internal consistency.  Upstream wolfSSL symbols (`wolfSSL_Init`,
  `wolfSSL_SetLoggingCb`, `ERROR_LOG`/`INFO_LOG`/`ENTER_LOG`/
  `LEAVE_LOG`) are untouched per the CLAUDE.md "do not rename wolfSSL
  upstream identifiers" guardrail.  Operator-only impact; no
  wire-format or API change.

## [0.1.3] — 2026-05-10

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
