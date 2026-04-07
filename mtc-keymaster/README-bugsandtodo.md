# MTC Keymaster — Bugs and TODO

## TODO

### 1. Client-side Merkle proof and cosignature verification

**Priority:** High — required before opening to third parties

The C client (`src/ssl_mtc.c` `MTC_Verify`) currently trusts the CA server's
response for inclusion proof validity and cosignature presence. It does not
independently verify either:

- **Inclusion proof:** Client accepts `"valid":true` from `GET /log/proof/<N>`
  without recomputing the Merkle hash chain.
- **Cosignature:** Client checks that a cosignature exists (`count > 0`) but
  does not verify the Ed25519 signature.

When third parties operate their own CAs (registered via DNS TXT validation),
a compromised CA server could return `"valid":true` for a forged certificate.
The client must independently verify:

1. Recompute the Merkle inclusion proof (SHA-256 hash chain from leaf to root)
2. Verify the Ed25519 cosignature over the subtree root using the bootstrapped
   CA public key
3. Verify the leaf belongs to a registered CA (chain validation)

The Python client (`mtc_client.py` `verify_standalone_certificate`) already
does real verification and can serve as reference. wolfSSL has SHA-256 and
Ed25519 verify APIs available.

**Files:**
- `src/ssl_mtc.c` — `MTC_Verify()` (lines ~453-540)
- `mtc-keymaster/tools/python/mtc_client.py` — reference implementation
- `examples/quic-mtc/quic_mtc_common.h` — `qmtc_verify()`

### 2. Server-side leaf-to-CA authorization check

**Priority:** High — required before opening to third parties

The server currently issues leaf certificates to anyone who POSTs to
`/certificate/request` without checking whether a registered CA exists for
that domain. A third party could enroll a leaf for any domain (e.g.
`candyorus.com`) without owning a CA for it.

The server should enforce:

1. Leaf request arrives for subject `example.com`
2. Server checks if a registered CA exists for this domain — look for
   `example.com-ca` in `mtc_certificates` (enrolled via `enroll-ca` with
   DNS TXT validation)
3. If a matching CA is found → issue the leaf
4. If no matching CA → reject with 403

This pairs with the existing DNS TXT validation for CA enrollment
(`_mtc-ca.<domain>` TXT record). Together they form a two-step authorization:

- **CA enrollment:** domain owner proves control via DNS TXT record
- **Leaf enrollment:** server verifies a CA for that domain was previously
  registered

The leaf request should also include `CA:FALSE` and the SAN DNS name in its
extensions so the server can match the domain and confirm it is not a CA.

**Files:**
- `mtc-keymaster/server/c/mtc_http.c` — `handle_certificate_request()`
- `mtc-keymaster/server/c/mtc_store.c` — needs a lookup by subject function
- `mtc-keymaster/server/python/server.py` — Python server equivalent

### 3. Enrollment authorization — anyone can enroll a leaf cert

**Priority:** High — open enrollment is a security gap

Currently, anyone can create a leaf cert (`create_leaf_cert.py`), send it to
the server, and get it enrolled without any proof of domain ownership. The
enrollment endpoint is an open door.

In the MTC model the CA doesn't sign individual leaf certs (it signs the
Merkle tree root). But the CA still needs to verify that the entity enrolling
a leaf actually controls the claimed domain — otherwise an attacker can
enroll a leaf for any domain.

**Recommended approach: DNS TXT validation** (similar to ACME/Let's Encrypt):

1. Client: `POST /enroll {subject: "example.com", pubkey: ...}`
2. Server: responds with a challenge token
3. Client: creates DNS TXT record `_mtc.example.com` containing the token
4. Server: verifies the TXT record, adds leaf to the tree
5. If TXT record is missing or wrong → reject enrollment

`ca_dns_txt.py` already exists in the tools directory and handles DNS TXT
lookups for CA enrollment. The same pattern should be extended to leaf
enrollment.

**Alternative approaches (lower priority):**

- **CA-signed enrollment token** — CA issues a one-time token out-of-band;
  `enroll` call must present the token
- **Mutual TLS** — enrollment endpoint requires a client cert the CA trusts
  (bootstrap problem, but works for device fleets)
- **Manual approval** — enrollment goes into a pending queue, CA operator
  reviews and approves before leaf is added to next tree batch

**Files:**
- `mtc-keymaster/server/c/mtc_http.c` — `handle_certificate_request()` needs
  a validation gate
- `mtc-keymaster/tools/python/ca_dns_txt.py` — reference for DNS TXT lookups
- `mtc-keymaster/tools/python/create_leaf_cert.py` — leaf creation tool
- `mtc-keymaster/tools/python/main.py` — `enroll` command

### 4. AbuseIPDB cache expiry — refresh stale records after 5 days

**Priority:** Medium — improves accuracy of IP reputation checks

The `mtc_checkendpoint` module caches AbuseIPDB lookup results in PostgreSQL
to avoid redundant API calls. However, cached records are never refreshed.
An IP that was clean 30 days ago may now be flagged as abusive, or an IP
that was temporarily flagged may have been cleared — the server keeps serving
stale data indefinitely.

**Current behavior:**
1. IP arrives in a request
2. Module checks PostgreSQL cache for a matching record
3. If found → return cached result (regardless of age)
4. If not found → query AbuseIPDB API, cache the result, return it

**Desired behavior:**
1. IP arrives in a request
2. Module checks PostgreSQL cache for a matching record
3. If found **and record is less than 5 days old** → return cached result
4. If found **but record is more than 5 days old** → query AbuseIPDB API,
   update the existing record with fresh data and a new timestamp, return it
5. If not found → query AbuseIPDB API, insert new record, return it

The staleness check should compare the record's `created_at` (or a new
`updated_at` column) against `now() - INTERVAL '5 days'`. The 5-day
threshold should be a configurable constant (e.g. `ABUSEIPDB_CACHE_TTL_DAYS`)
so it can be tuned without code changes.

**Implementation notes:**
- Add an `updated_at TIMESTAMPTZ DEFAULT now()` column to the cache table
  (or use the existing `created_at` if no schema change is desired)
- Modify the cache lookup query to return the timestamp alongside the result
- In the lookup function, compare the timestamp: if older than 5 days,
  treat it as a cache miss — query AbuseIPDB, then `UPDATE` the row
  instead of `INSERT`
- Use `INSERT ... ON CONFLICT (ip) DO UPDATE` (upsert) to handle both
  fresh inserts and stale refreshes in a single query

**Files:**
- `mtc-keymaster/server/c/mtc_checkendpoint.c` — cache lookup and API query logic
- `mtc-keymaster/server/c/mtc_checkendpoint.h` — add TTL constant
- `mtc-keymaster/server/c/mtc_db.c` — if the cache table schema is managed here

### 5. Server-verified FIPS source checksums via MTC transparency log

**Priority:** High — addresses a fundamental weakness in FIPS source integrity

**Problem:** FIPS source file checksums are stored in the same repository as
the source code. An attacker with write access can modify both a source file
and its checksum — nothing downstream detects the tampering. This weakness
exists in both OpenSSL (`fips-sources.checksums`) and wolfSSL (`fips-hash.sh`).

**Solution:** Anchor FIPS source checksums in the MTC Merkle tree transparency
log. At build time, a manifest of every FIPS source file's SHA256 hash is
submitted to the C MTC server, which logs it as a new entry type (`0x02`),
computes an inclusion proof, and signs the tree root with Ed25519. The manifest
cannot be altered after submission without detection.

**Design:** See `README-fips.plan` for the full implementation plan and
`README-fips.md` for admin/user documentation.

**Summary of work:**

1. **C server extensions** — Add entry type `0x02` (FIPS manifest) to the
   existing Merkle tree. Add four new HTTP endpoints:
   - `POST /fips/manifest` — submit a manifest
   - `GET /fips/manifest/<index>` — retrieve a manifest
   - `GET /fips/manifest/<index>/proof` — fresh inclusion proof
   - `GET /fips/manifest/search?package=X&tag=Y` — search manifests
   
2. **Database** — Add `mtc_fips_manifests` table with package/tag indexing.

3. **Client scripts** — Create `fips-manifest-submit.sh` (build-time: compute
   checksums, POST to server, save receipt) and `fips-manifest-verify.sh`
   (verification: compare local files against logged manifest, verify proof
   and cosignature). Supports online and offline modes.

4. **Build integration** — Call `fips-manifest-submit.sh` after `fips-hash.sh`
   in `debian/rules` and `Makefile.am`. Ship `fips-manifest-receipt.json` with
   the package for offline verification.

**Trust model:** The leaf (kit publisher) operates independently from the CA
after enrollment. The CA vouches for the leaf's identity at enrollment time
via DNS TXT validation. Downstream verifiers check the chain: CA public key
(obtained out-of-band) → CA enrollment → leaf certificate → FIPS manifest →
individual file hashes. Offline verification uses the receipt's cached proof
and cosignature — no server contact needed.

**Existing code reuse:** `mtc_merkle.c` (tree operations), `mtc_store.c`
(entry persistence, Ed25519 cosigning), `mtc_db.c` (DB patterns),
`mtc_http.c` (endpoint handler patterns). No changes needed to `mtc_merkle.c`.

**Files to create:**
- `fips-manifest-submit.sh` — build-time submission script
- `fips-manifest-verify.sh` — verification script (online + offline)

**Files to modify:**
- `mtc-keymaster/server/c/mtc_http.c` — add FIPS manifest endpoint handlers + routing
- `mtc-keymaster/server/c/mtc_db.c` — add `mtc_fips_manifests` table + CRUD
- `mtc-keymaster/server/c/mtc_store.c` — add type `0x02` detection + manifest persistence
- `mtc-keymaster/server/c/mtc_store.h` — add manifest fields to `MtcStore` struct
- `debian/rules` — call submit script in FIPS build path
- `Makefile.am` — add new targets

### 6. Compiler integrity — what if gcc has been corrupted?

**Priority:** Medium — defense-in-depth for the FIPS build pipeline

**Problem:** The FIPS source checksum system (item #4) verifies that source
files haven't been tampered with. But source integrity is meaningless if the
compiler itself has been compromised. A trojaned `gcc` could inject backdoors
into the binary while compiling pristine source — the source checksums would
all pass, the FIPS manifest would verify cleanly, and the resulting binary
would still be malicious.

This is Ken Thompson's classic "Reflections on Trusting Trust" (1984) attack:
a compiler can be modified to insert trojans into specific programs it
compiles, and even to propagate itself into new compiler builds.

**What we cannot solve:** Fully verifying compiler integrity from within the
compiled environment is a bootstrapping problem. If the compiler is the root
of trust and it's compromised, everything it produces is suspect — including
any tool you compile to check the compiler.

**What we can mitigate:**

1. **Reproducible builds** — Build the same source on two or more independent
   machines with independently obtained compilers. If the binaries are
   identical (bit-for-bit or after stripping timestamps/paths), the compiler
   on neither machine injected target-specific code. This is the strongest
   practical defense.
   
   - Requires deterministic build flags (`-frandom-seed`, fixed `SOURCE_DATE_EPOCH`, etc.)
   - Requires stripping or normalizing non-deterministic artifacts (timestamps,
     build paths, `__FILE__` macros)
   - The wolfssl-new build already stores `.build_params` — extend this to
     capture the full environment for reproducibility

2. **Compiler checksum in the FIPS manifest** — Record the SHA256 of the
   compiler binary (`gcc`, `cc1`, `as`, `ld`) in the FIPS manifest alongside
   the source file hashes. This doesn't prove the compiler is clean, but it
   lets a verifier confirm that the same compiler was used across builds and
   detect unexpected compiler changes.
   
   Add to the manifest JSON:
   ```json
   {
     "toolchain": {
       "cc": {"path": "/usr/bin/gcc-13", "sha256": "..."},
       "cc1": {"path": "/usr/lib/gcc/x86_64-linux-gnu/13/cc1", "sha256": "..."},
       "as": {"path": "/usr/bin/as", "sha256": "..."},
       "ld": {"path": "/usr/bin/ld", "sha256": "..."}
     }
   }
   ```

3. **Cross-compiler verification** — Compile with two different compilers
   (e.g. `gcc` and `clang`) and compare the test suite results. A trojaned
   `gcc` that injects a backdoor would need to also trojan `clang` — an
   independent codebase — to avoid detection. This doesn't produce identical
   binaries (different compilers generate different code) but functional
   equivalence via the test suite provides confidence.

4. **Diverse Double-Compiling (DDC)** — David A. Wheeler's technique (2009):
   compile a trusted compiler source with two different compilers, then use
   both resulting compilers to compile the target. If the outputs match,
   neither compiler injected a trojan. This is computationally expensive but
   provides strong guarantees.

5. **Package-signed compiler provenance** — Verify that `gcc` was installed
   from a signed distribution package (`apt`, `dnf`) with a valid GPG
   signature chain back to the distribution's archive key. This doesn't prove
   the distribution wasn't compromised, but it raises the bar from "attacker
   modified a file on disk" to "attacker compromised the distribution's
   signing infrastructure."
   
   ```bash
   # Verify gcc package signature
   dpkg -V gcc-13
   apt-cache policy gcc-13
   ```

**Recommended first step:** Add compiler checksums to the FIPS manifest
(option 2). This is low-effort, non-breaking, and provides an audit trail.
Reproducible builds (option 1) should be a longer-term goal.

**Files:**
- `fips-manifest-submit.sh` — add toolchain checksum collection
- `fips-manifest-verify.sh` — add optional toolchain hash comparison
- `README-fips.md` — document the compiler trust boundary

---

## Appendix: Server Directory Layout

Three directories are used on the server. The first two are active in the
codebase; the third (`masterKey`) is not currently referenced.

### `~/.TPM` — Client-side storage

Per-domain leaf keys, certificates, and ECH cache.

```
~/.TPM/
    {subject}/                  # one per enrolled domain
        private_key.pem         # EC-P256 private key (mode 0600)
        public_key.pem          # EC-P256 public key
        certificate.json        # MTC cert with Merkle proof + cosignatures
        index                   # certificate log index number
    ech/
        {host}.conf             # cached ECH config (base64)
```

**Created by:** `tools/python/main.py enroll`, `renew-tool/renew.py`
**Read by:** renewal tool (`scan_tpm()`), SLC library (`slc_ech_cache_load()`)

### `~/.mtc-ca-data` — Server-side CA/Log persistence

Merkle tree state, CA key, issued certificates, and revocations. Passed to
the C server via `--data-dir`.

```
~/.mtc-ca-data/
    ca_key.der                  # Ed25519 CA private key (DER)
    entries.json                # all Merkle tree log entries
    certificates.json           # issued certs with inclusion proofs
    landmarks.json              # cached Merkle landmark hashes (powers of 2)
    revocations.json            # revoked cert indices and reasons
    server-cert.pem             # TLS server certificate (if TLS enabled)
    server-key.pem              # TLS server private key (if TLS enabled)
```

**Created by:** C server (`mtc_store_init()`) at startup
**Configured in:** `mtc-ca.service` line 11 (`--data-dir`)

### `masterKey` — Not currently used

This directory is not referenced in the mtc-keymaster or socket-level-wrapper
code. It may be from a different project or manual experimentation.
