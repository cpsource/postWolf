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

(no changes since 0.1.0)

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
