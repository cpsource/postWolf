# Getting started — FIPS-manifest workflow

End-to-end walk-through from "I have a leaf identity" to "I shipped a
package and someone else verified it offline."  Every step uses tools
that ship with `postWolf`; no extra dependencies.

## 0. Prerequisites — get a leaf identity

This guide assumes you already have a TPM identity directory at
`~/.TPM/<your-domain>[-<label>]/` containing `private_key.pem`,
`public_key.pem`, `certificate.json`, and `index`.  If you don't,
provision one first — see `mtc-keymaster/README.md` for the
end-to-end enrollment story (`register-leaf.sh` /
`bootstrap_leaf` / DH bootstrap on port 8445).

Sanity check that your identity is healthy before publishing:

```sh
show-tpm --verify
```

Look for `[+] <your-name>` with `Verify: server=OK revoked=no
proof=OK time=OK pubkey_db=OK` and `Local: pair=OK spkh=OK`, plus
the `Peer cache: ... all N cached peers consistent` block at the
end.  Any `MISMATCH` or `FAIL` line means stop and fix it before
continuing — a broken identity will only produce broken manifests.

## 1. Generate the canonical manifest

`fips-manifest-submit` builds the **spec-canonical-leaf v1**
representation of your package: alphabetically-sorted JSON with no
whitespace, no `\/` escapes, an ML-DSA-87 signature over the
canonical bytes (with the `signature` field set to `""` while
signing — restored after).  The resulting `leaf.bin` is exactly
the byte sequence that becomes log entry payload (`0x02 ||
canonical_json`).

```sh
fips-manifest-submit \
    --domain   <your-domain>          \
    --label    <your-label>           \
    --package  postWolf-test          \
    --version  v0.0.1                 \
    --source-dir ./dist               \
    --out      /tmp/leaf.bin          \
    --validity-days 30                \
    --pretty
```

What it does internally:

1. Walks `--source-dir`, computes SHA-256 of every regular file,
   sorts by path.
2. Reads `~/.TPM/<domain>-<label>/{private_key.pem, certificate.json}`
   to fetch your `publisher_cert_index` and signing key.
3. Builds the canonical JSON, signs it, self-verifies that the
   signature round-trips through canonicalisation, then writes the
   `0x02`-prefixed bytes to `--out`.

`--pretty` echoes a human-readable view of what was built; the
file on disk is always the canonical form.  This phase is offline
and read-only — no network, no DB.

## 2. Sign the manifest

Done.  Step 1 already produced an ML-DSA-87 signature over the
canonical bytes, embedded inside the leaf JSON itself.  There is
no separate signing step — the spec-canonical-leaf v1 envelope
*is* the signed object.

(If you were thinking of the old `MANIFEST.sha256 + MANIFEST.sig`
sidecar pair from `tools/sh/sign-dir.sh`, that's a different
workflow — see [Appendix B](#appendix-b--lightweight-directory-signing-shsign-dirsh).)

## 3. Register with the server

Submit the leaf bytes to `POST /fips/manifest` over MQC on port
8446.  The server runs the 9-step acceptance pipeline (strict JSON
parse → byte-equality re-canonicalisation → publisher cert lookup
+ revocation gate → ML-DSA-87 verify → time-bound check → log
append → cosignature → search-index INSERT) and returns a receipt.

> **Current gap (2026-05).**  The production wire submitter is not
> yet wrapped as a standalone tool.  `fips-manifest-submit` is
> phase-1 dry-run only — it builds and writes the canonical bytes
> but does not POST them.  Until the phase-2 upgrade lands, the
> submission is done via the test harness or an ad-hoc MQC POST
> using the same plumbing as `fips-manifest-revoke` (which is
> already a working MQC POST client and is the reference shape for
> the future submitter).
>
> The server endpoint is fully operational — you can confirm using
> `fips-manifest-list` (next step), which already shows manifests
> previously submitted by the test harness at log indices 81/82/83.

When the wire submitter ships, the contract will be:

```sh
fips-manifest-submit ... <as above> <minus --dry-run>
# -> receipt JSON written to --out
```

The receipt contains: `leaf_index`, `tree_size`, `tree_root` (hex),
`leaf_bytes_b64`, `inclusion_proof[]`, `cosignatures[]`,
`publisher_pubkey_pem`.  Save the receipt file alongside your
`./dist` tarball — it's what your downstream verifier needs.

## 4. Get status from the server

`fips-manifest-list` is the read-only browser over the FIPS log.
It opens MQC, calls `GET /fips/list` (or `/fips/list?log_index=N`
for detail), and renders.  Works on any host that holds a valid
TPM identity — no DB credentials required.

```sh
# Table view of recent manifests + revocation status
fips-manifest-list

# Detail view, including revocation block if revoked
fips-manifest-list <log_index>

# Filter by package / publisher / version
fips-manifest-list --package postWolf-test --version v0.0.1

# Raw JSON pass-through (good for scripts)
fips-manifest-list --json
fips-manifest-list <log_index> --json
```

The `status` column has four values: `OK`, `Cert Revoked`,
`Manifest Revoked`, `Manifest & Cert Revoked`.  When any row is
flagged the table footer prints a one-liner pointing you at the
detail view.

## 5. Verify your kit locally (offline)

`fips-manifest-verify` is the offline 6-stage verifier.  It needs
the receipt from step 3 and the on-disk `--source-dir` it claims to
describe.  No network — every byte it reads comes from the
filesystem.

```sh
fips-manifest-verify \
    --receipt    receipt.json \
    --source-dir ./dist
```

The 6 stages, in order:

1. **Strict-parse the receipt** + the embedded canonical leaf
   bytes.
2. **Cosignature verify** of `(tree_size, tree_root)` under the
   trusted cosigner pubkey at `~/.TPM/ca-cosigner.pem` (override
   with `--cosigner-pem`).  Signing-input layout matches the
   server's `mtc_store_cosign`: `"mtc-subtree/v1\n\x00" ||
   cosigner_id || log_id || start_be64 || end_be64 ||
   subtree_hash`.
3. **Inclusion-proof replay** from `leaf_hash` to `tree_root`
   using RFC 9162 §2.1 hashes.
4. **Manifest signature verify** under the receipt-embedded
   `publisher_pubkey_pem`.  The pubkey is sanity-checked against
   the canonical leaf's `spk_hash` first, defending against a
   malicious receipt forging a different pubkey.
5. **Time bounds**: `now ∈ [not_before − 300s, expires]`.
6. **File hashes**: walk `--source-dir`, recompute SHA-256 per
   file, match against `manifest.files[]` (sorted), reject extras.

Exit code: 0 on accept, non-zero on any failure.  The default mode
is **fully offline** — verifies receipts in air-gapped or
maintenance-window scenarios.

## 6. Verify your kit remotely (with revocation check)

Add `--check-revocation` to bring the verifier online for a single
extra step (between stages 5 and 6).  It opens MQC and queries:

- `GET /fips/revoked/<log_index>` — manifest-level revocation
- `GET /revoked/<publisher_cert_index>` — publisher cert revocation

Either reporting revoked aborts the verify with a clear message;
transport / parse failures fail-closed.

```sh
fips-manifest-verify \
    --receipt    receipt.json     \
    --source-dir ./dist           \
    --check-revocation            \
    --tpm-path ~/.TPM/<your-id>   \
    --server   factsorlie.com:8446
```

`--tpm-path` and `--server` default to the same auto-discovery as
`fips-manifest-list` (first identity under `~/.TPM`, `[global]
url-server` from `/etc/postWolf/config`).  Omit them in the common
case.

> **Why it's opt-in:** the receipt itself is a self-contained
> cryptographic proof that the manifest was in the log at submit
> time.  Bundling a cosigned revocation snapshot inside the receipt
> (so verification stays fully offline even when revocation matters)
> is `README-fips-todo.md` TODO 12.  Until that lands,
> `--check-revocation` is the online tradeoff: stronger safety, at
> the cost of a network round-trip.

## 7. Revoke a release

If you ship a buggy release, revoke the manifest leaf so verifiers
running `--check-revocation` reject it.

```sh
# Self-revoke (publisher pulling back their own release)
fips-manifest-revoke --log-index 83 \
                     --reason "found CVE-2026-XXXX in v0.1.1" \
                     --as publisher

# CA-revoke (compliance / takedown)
fips-manifest-revoke --log-index 83 \
                     --reason "compliance: not FIPS-validated" \
                     --as ca \
                     --tpm-path ~/.TPM/<your-domain>-ca
```

Both paths build the same wire envelope, signed with ML-DSA-87
over `fips-revoke:<kind>:<revoker_cert>:<log_index>:<reason>:<ts>`.
The server runs the 9-step revoke pipeline (strict JSON, freshness,
manifest exists, recover declared `publisher_cert_index`, load
revoker cert, authority branch, sha256(pem) == spk_hash, signature
verify, INSERT).

The new revocation row appears in the next `fips-manifest-list`
output as `Manifest Revoked` (or `Manifest & Cert Revoked` if the
publisher cert was also separately revoked).  Multiple revocation
rows per `log_index` are allowed — each idempotent: once revoked,
always revoked.  See `spec-canonical-leaf.md` "Manifest revocation"
for the full wire spec.

## Tools reference

All tools live under `fips-framework/tools/`.  Every tool listed
here is built by `make -f Makefile.tools` (or just `make` in
`fips-framework/tools/c/`) and installed to `/usr/local/bin/`
by `sudo make -f Makefile.tools install`.

### `fips-framework/tools/c/`

| Tool | Phase | Purpose |
|---|---|---|
| `fips-manifest-submit` | author | Build the canonical-leaf v1 representation of a package: walk source-dir, hash files, sort, sign with ML-DSA-87, emit `leaf.bin`.  Currently `--dry-run` only — phase-2 will add real POST. |
| `fips-manifest-list` | observer | Browse the FIPS log over MQC.  Read-only.  Table view shows `status` column (`OK`/`Cert Revoked`/`Manifest Revoked`/`Manifest & Cert Revoked`); detail view (`fips-manifest-list <log_index>`) shows the parsed manifest + nested revocation block.  No DB credentials required — works on any leaf host. |
| `fips-manifest-verify` | consumer | Offline 6-stage verifier of a receipt + on-disk source tree.  Stages: strict-parse, cosignature, inclusion-proof, manifest signature, time bounds, file hashes.  Add `--check-revocation` to bring step 5.5 online (manifest + cert revocation queries). |
| `fips-manifest-revoke` | author / CA | Sign + POST a revocation request for one log_index over MQC.  `--as publisher` is self-revoke (must hold the cert that submitted the manifest); `--as ca` is takedown (caller must hold a `-ca` cert in the publisher's domain). |

Common flags across the MQC-aware tools (`list`, `revoke`,
`verify --check-revocation`):

| Flag | Default |
|---|---|
| `--tpm-path PATH` | First identity under `$HOME/.TPM/` (skipping `peers`, `ech`, `default`, hidden). |
| `-s`, `--server H[:P]` | `[global] url-server` from `/etc/postWolf/config`, falling back to `MQC_DEFAULT_SERVER` from `tools/c/config.h` (host + port `#ifndef`-guarded — wrapper config wins when present). |
| `--json` (list) | Off — pretty table view is the default. |
| `-v`, `--verbose` | Off — minimal output. |

### `fips-framework/tools/sh/`

These are the *legacy lightweight* signing tools.  They produce a
detached `MANIFEST.sha256 + MANIFEST.sig` pair inside a directory,
verifiable by anyone with the publisher's public key.  They do
**not** anchor in the merkle log, do **not** participate in
revocation, and require no server.  Use when you want a quick
proof-of-authorship over an arbitrary tree without the full FIPS
pipeline.

| Tool | Purpose |
|---|---|
| `sign-dir.sh DOMAIN [DIR]` | Walk `DIR` (default `.`), recursively hash every regular file (symlinks followed; `.git`, `MANIFEST.*`, `private_key.pem` excluded; sorted via `LC_ALL=C`), prepend `# publisher:`, `# publisher-cert-index:`, optional `# git-commit:` header lines, write `MANIFEST.sha256`, then sign it with ML-DSA-87 from `~/.TPM/<DOMAIN>/private_key.pem` → `MANIFEST.sig`. |
| `verify-dir.sh DOMAIN [DIR]` | Three-stage check: (1) `MANIFEST.sig` is a valid ML-DSA-87 signature over `MANIFEST.sha256` under `~/.TPM/<DOMAIN>/public_key.pem`; (2) `sha256sum --strict --check MANIFEST.sha256` passes; (3) header cross-checks: `# publisher:` matches the `DOMAIN` argument (FAIL on mismatch), `# publisher-cert-index:` matches `~/.TPM/<DOMAIN>/index` (WARN on rotation), `# git-commit:` (if present) exists in the local repo (any branch). |

### `fips-framework/tools/python/`

Currently empty (placeholder for future Python helpers — see
`README-fips-todo.md` for what's planned).

## Appendix A — Where things live on disk

| Path | What it is |
|---|---|
| `~/.TPM/<domain>[-<label>]/` | Your identity: `private_key.pem`, `public_key.pem`, `certificate.json`, `index`.  Created by `register-leaf.sh` / `bootstrap_leaf`. |
| `~/.TPM/peers/<cert_index>/` | Per-peer cache populated by MQC handshakes: `certificate.json`, `public_key.pem`, `leaf_hash.hex`, `cosigner-fp.hex`, `revoked.json`.  `show-tpm --verify` flags any drift. |
| `~/.TPM/ca-cosigner.pem` | Trust anchor for offline `fips-manifest-verify` (the PEM the CA cosigns checkpoints with).  Bootstrapped on first `mqc_load_ca_pubkey` call. |
| `/etc/postWolf/config` | `url-server`, `url-bootstrap`, `url-local`, `mqc-revocation-policy`, etc.  Edit `mtc-keymaster/read-config/config.server` in the repo, then `sudo cp` to `/etc/`. |
| `/usr/local/bin/fips-manifest-*` | Installed binaries. |
| `/usr/local/include/postWolf/` | wolfSSL headers (postWolf-renamed). |
| `/usr/local/lib/libpostWolf.so*` | Crypto library the tools link against. |

## Appendix B — Lightweight directory signing (sh/sign-dir.sh)

The `tools/sh/` pair predates the canonical-leaf pipeline and
solves a smaller problem: **prove who signed an arbitrary directory
tree, without anchoring in the transparency log**.  Use it when
you don't want a server round-trip — e.g., to ship a release
tarball with a sidecar signature any consumer can verify offline
using just your public key.

```sh
# Sign
bash fips-framework/tools/sh/sign-dir.sh <your-domain> path/to/release/

# Verify
bash fips-framework/tools/sh/verify-dir.sh <your-domain> path/to/release/
```

This produces `path/to/release/MANIFEST.sha256` and `MANIFEST.sig`.
The MANIFEST file is human-readable; the `.sig` is the raw
ML-DSA-87 signature over those bytes.

The fips-framework directory itself is signed this way (commit
`29e2f7910` and onward) — see `fips-framework/MANIFEST.{sha256,sig}`.

## Appendix C — Spec + design references

- `fips-framework/spec-canonical-leaf.md` — the wire format,
  validation order, and "Manifest revocation" section that anchor
  every tool above.
- `fips-framework/README-implement.md` — the 4-step implementation
  roadmap (spec → submit → server endpoint → verify) with what's
  done vs. what's outstanding.
- `fips-framework/README-discussions.md` — three Q&A on the MitM
  threat model that motivated anchoring at the log layer rather
  than the directory layer.
- `mtc-keymaster/README.md` — the trust chain (cosigner / CA /
  leaf) underneath everything here.
- `socket-level-wrapper-MQC/README-MQC-specifications.md` — the
  MQC handshake + revocation policy that governs whether your
  request even reaches the server.
