# FIPS Integrity System — TODO

## Priority 0: Code TODOs (in-tree)

### 0a. MTC verification during TLS handshake
**File:** `socket-level-wrapper/slc.c:273`

`slc_connect` and `slc_accept` need to verify the peer's certificate against
the MTC Merkle tree when MTC is configured (`slc_ctx_set_mtc` was called).
Currently stubbed — TLS 1.3 cert chain validation works, but the Merkle proof
+ Ed25519 cosignature checks are not yet wired in.

**What's needed:**
1. Hash the peer cert's subject key ID after TLS handshake completes
2. Query MTC server: `GET /certificate/search?subject_key_hash=<hash>`
3. Retrieve inclusion proof for the leaf
4. Replay Merkle proof (hash chain from leaf to root)
5. Verify Ed25519 cosignature against `ctx->ca_pubkey` using `wc_ed25519_verify_msg()`
6. Check revocation: `GET /revoked/<index>`
7. Reject connection if any step fails

**Depends on:** FIPS framework tools being functional (same verification logic).

### 0b. Pin actual CA public key
**File:** `fips-framework/config/ca-pubkey.h:20`

The placeholder is 32 zero-bytes. Replace with the real CA Ed25519 public key
exported from `~/.mtc-ca-data/ca_key.der`.

**How:**
```bash
# Extract public key from the DER private key
openssl pkey -in ~/.mtc-ca-data/ca_key.der -inform DER -pubout -outform DER | \
    tail -c 32 | xxd -i
```

Then paste the bytes into `ca-pubkey.h`.

---

## Priority 1: Easy Wins (add now)

### 1. Manifest `expires` field
Add an `expires` timestamp to the FIPS build manifest. Verifiers reject
kits whose manifest has expired, preventing stale kits from being accepted
indefinitely.

**Changes:**
- `fips-manifest-submit.sh`: add `"expires": "<timestamp>"` to manifest JSON
  (default: 1 year from build time, configurable)
- `fips-manifest-verify.sh`: check `expires` against current time, fail if past
- `mtc_http.c` (`handle_fips_manifest_submit`): validate `expires` field if present
- `README-fips.md`: document the field and its default

### 2. Version rollback detection
Prevent an attacker from replaying an older (but valid) signed manifest for
the same package. The verifier should reject a manifest whose version is
older than one it has previously accepted.

**Changes:**
- `fips-manifest-verify.sh`: maintain a local state file
  (`~/.config/mtc-fips/last-verified.json`) recording the highest accepted
  version per package
- On verify, compare manifest `git_tag` / `version` against last-accepted;
  warn or fail if older
- `README-fips.md`: document rollback detection behavior and override flag
  (`--allow-rollback` for legitimate downgrades)

### 3. Self-contained kit bundle
Formalize what ships inside the release tarball so verification needs nothing
but the pinned root CA key. Currently `fips-manifest-receipt.json` is shipped
but the publisher's leaf cert and CA chain are not.

**Bundle layout:**
```
kit.tar.gz
  source files
  fips-manifest-receipt.json    (manifest + inclusion proof + cosignature)
  fips-publisher.crt            (leaf cert that signed this manifest)
  fips-chain.pem                (intermediate certs up to but not including root)
```

**Changes:**
- `fips-manifest-submit.sh`: copy `publisher.crt` and `chain.pem` into the
  build directory alongside the receipt
- `Makefile.am` / `EXTRA_DIST`: include `fips-publisher.crt` and `fips-chain.pem`
- `fips-manifest-verify.sh`: if `--offline`, verify cert chain from bundled
  certs + pinned root CA key (no server contact needed for cert lookup)
- `README-fips.md`: document the bundle layout and cert chain verification step

---

## Priority 2: TUF Roles (defer until core is deployed)

### 4. Timestamp role (freeze attack protection)
A short-lived signed token that says "as of time T, the latest manifest for
package X is index N." Prevents a compromised server from withholding newer
releases while serving stale-but-valid ones.

**Design:**
- New key pair: Timestamp key (short-lived, rotated frequently)
- New endpoint: `GET /fips/timestamp/<package>` returns signed
  `{package, latest_index, signed_at, expires}` with ~24h expiry
- Verifier (online mode): fetch timestamp, confirm the manifest index is
  not older than what the timestamp claims is current
- Verifier (offline mode): skip (timestamp is inherently online)

**Changes:**
- `mtc_store.h`: add timestamp key pair to `MtcStore`
- `mtc_http.c`: add `handle_fips_timestamp()` endpoint
- `mtc_store.c`: add timestamp key generation/rotation
- `fips-manifest-verify.sh` (online mode): fetch and check timestamp
- `README-fips.md`: document timestamp verification

### 5. Snapshot role (mix-and-match protection)
A signed snapshot listing all current package versions, preventing an attacker
from combining files from different valid releases into an inconsistent kit.

**Design:**
- New key pair: Snapshot key
- New endpoint: `GET /fips/snapshot` returns signed
  `{packages: [{name, latest_index, git_tag}, ...], signed_at}`
- Verifier: confirm the manifest index for this package matches the snapshot
- Useful when multiple packages or components are released together

**Changes:**
- `mtc_store.h`: add snapshot key pair to `MtcStore`
- `mtc_http.c`: add `handle_fips_snapshot()` endpoint
- `mtc_store.c`: add snapshot generation on each manifest submission
- `fips-manifest-verify.sh`: optionally fetch and verify snapshot
- `README-fips.md`: document snapshot verification

**Note:** Snapshot is most valuable when the system manages multiple packages
or multi-component releases. For a single-package system (wolfssl-new only),
the Timestamp role provides most of the freeze protection value. Implement
Snapshot if/when the system expands to multiple packages.

### 6. Scoped delegation (TUF-style)
Currently any valid leaf cert can sign a manifest for any package name. TUF's
delegation model allows scoping authority: "Key A may only sign packages
matching `wolfssl-*`." This prevents a compromised leaf from signing manifests
for packages outside its authority.

**Design:**
- Add a `scope` field to the leaf certificate's MTC log entry at enrollment
  time. The scope is a list of package name patterns (e.g., `["wolfssl-*"]`).
- At verification time, the verifier checks that the manifest's `package`
  field matches at least one pattern in the signing leaf's `scope`.
- If the leaf has no `scope` field, it is unrestricted (backward compatible).

**Changes:**
- `mtc_http.c` (`handle_certificate_request`): accept optional `scope` array
  in the leaf enrollment request; store in the log entry
- `fips-manifest-verify.sh`: after verifying the cert chain, fetch the leaf's
  log entry and check that `package` matches the leaf's `scope`
- `README-fips.md`: document scoped delegation

**Future extensions (defer further):**
- **Threshold signing**: require N-of-M leaf keys to co-sign a manifest
  (useful for high-value releases)
- **Chained delegation**: allow a leaf to sub-delegate authority to another
  key without going back to the CA (useful for build bots)

### 7. GPG keyserver cross-signing of CA public key
The CA Ed25519 public key is the single most important trust anchor. Currently
all channels that publish it (DNS TXT, server endpoint, source code) are
controlled by the same entity. An attacker who compromises that entity can
replace the CA key everywhere.

Publishing a GPG-signed statement of the CA key to an independent keyserver
adds a second trust path the attacker cannot control.

**Design:**
- Publish Cal Page's GPG key (`E9C059EC0D3264FAB35F94AD465BF9F6F8EB475A`)
  to `keys.openpgp.org`
- Create a signed cleartext statement binding the CA Ed25519 public key to
  the GPG identity:
  ```
  I, Cal Page (E9C059EC...), certify that the MTC CA Ed25519 public key
  for factsorlie.com is: <32 bytes hex>
  ```
- Publish the signed statement (e.g., in the git repo, project website, or
  as a keyserver notation)
- `fips-manifest-verify` (optional flag `--verify-gpg`): fetch GPG key from
  keyserver, verify the signed statement, compare CA key against what the
  server claims

**Trust channels after this change:**

| Channel | Controlled By | What It Pins |
|---------|--------------|--------------|
| DNS TXT | Domain registrar | CA public key |
| GPG keyserver | Third party (openpgp.org) | CA key, signed by GPG identity |
| Source code | Git repo | CA key in `ca-pubkey.h` |
| Git signed tag | Git + GPG keyserver | Commit hash + CA key |

Two independent channels agreeing on the same key is much harder to forge
than one.

**Prerequisites:**
- Upload GPG key: `gpg --keyserver keys.openpgp.org --send-keys E9C059EC0D3264FAB35F94AD465BF9F6F8EB475A`
- See `README-keyserver.md` for current keyserver status

---

## Reference

- Current design: `README-fips.md` and `README-fips.plan`
- Design rationale: `FIPS.md`
- Keyserver status: `README-keyserver.md`
- TUF spec: https://theupdateframework.github.io/specification/latest/
- TUF overview: https://theupdateframework.io/overview/
