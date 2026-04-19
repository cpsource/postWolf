# MTC Keymaster — Bugs and TODO

## TODO

### 1. Client-side Merkle proof and cosignature verification — DONE

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

### 2. Server-side leaf-to-CA authorization check — DONE

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

### 3. Enrollment authorization — anyone can enroll a leaf cert — DONE

**Priority:** High — open enrollment is a security gap

**Resolution:** Implemented in item #4 — two-step enrollment protocol with
server-issued nonces, DNS TXT validation, single-use 15-minute TTL.

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
- **Provisional enrollment** — leaf is added to the Merkle tree immediately
  but marked `provisional: true`. The CA reviews asynchronously and either
  confirms (removes the provisional flag) or revokes. This is a default-allow
  model similar to Certificate Transparency — the entry is in the tree for
  transparency, but relying parties can treat provisional certs differently:

  1. Leaf enrolls → added to tree with `provisional: true`
  2. CA reviews (DNS TXT, manual check, whatever)
  3. If legitimate → CA confirms, cert becomes fully trusted
  4. If fraudulent → CA revokes (uses existing `revocations.json`)
  5. Timeout → if CA doesn't confirm within N hours, auto-revoke

  **Risk:** during the provisional window a fraudulent leaf is live in the
  tree. **Mitigation:** the inclusion proof carries the provisional flag, and
  the SLC library rejects or warns on provisional certs. The transparency log
  itself is the defense — anyone can audit what was enrolled and flag fraud.

**DNS token format (implemented in `ca_dns_txt.py`):**

The DNS TXT record uses a key-bound token (v=mtc-ca2) with a server-issued
nonce. The server stores the nonce + domain + fingerprint + expiry in its
pending state and verifies against that state — not against the DNS record
contents.

```
_mtc-ca.example.com.  IN TXT  "v=mtc-ca2; fp=sha256:<spki_hash>; n=<nonce>; exp=<unix_ts>"
```

| Field | Purpose |
|-------|---------|
| `fp`  | SHA-256 of public key SPKI — binds to this specific key |
| `n`   | Server-issued nonce — proves freshness, prevents replay |
| `exp` | Unix timestamp — limits the validation window (default 24h) |

**Why no integrity hash?** A plain hash (e.g. SHA-256 of the fields) does
NOT prevent tampering by an active attacker — anyone who can modify the DNS
record can recompute the hash with their own values. Integrity is enforced
server-side: the server verifies the nonce against its own stored state
(domain + fingerprint + expiry), not against anything in the DNS record.

**Files:**
- `mtc-keymaster/server/c/mtc_http.c` — `handle_certificate_request()` needs
  a validation gate
- `mtc-keymaster/tools/python/ca_dns_txt.py` — generates and verifies key-bound
  DNS TXT tokens (updated to v=mtc-ca2 format)
- `mtc-keymaster/tools/python/create_leaf_cert.py` — leaf creation tool
- `mtc-keymaster/tools/python/main.py` — `enroll` command

### 4. Two-step enrollment protocol with registration authority — DONE

**Priority:** High — required before public enrollment

The CA should not accept arbitrary leaf enrollment attempts directly.
Instead, it should only accept enrollments that carry a CA-issued, fresh,
unpredictable authorization nonce tied to a prior approval decision. This
is similar in spirit to how ACME (RFC 8555) separates account actions,
nonce-based anti-replay, and authorization before issuance.

**Protocol:**

1. An authorized domain admin or CA operator requests approval for a
   prospective leaf
2. CA generates a 256-bit CSPRNG nonce and stores a pending record
3. Leaf user later submits CSR + nonce
4. CA verifies nonce exists, is unused, unexpired, and matches the stored
   domain and key binding
5. CA converts request from pending to issued and burns the nonce

This gives three protections at once: **anti-spam**, **anti-replay**, and
**key binding**. Replay nonces are a standard pattern in certificate
automation (ACME `badNonce`).

**Server-side state per nonce:**

| Field | Purpose |
|-------|---------|
| `nonce` | Random opaque 256-bit value (indexes server-side state) |
| `domain` | Domain or subject/SAN scope |
| `key_fingerprint` | Expected SPKI hash or CSR fingerprint |
| `issuance_profile` | Policy/profile for this certificate |
| `requester_id` | Account or operator identity |
| `created_at` | When the nonce was issued |
| `expires_at` | Short-lived: minutes or hours, not days |
| `status` | pending / consumed / expired / revoked |

**Who may obtain a nonce (core policy question):**

- A logged-in domain administrator account
- An authenticated API client
- A prior domain-control check (DNS-based authorization)
- Manual CA-side approval

Without this gate, attackers can flood with nonce requests even if they
cannot complete issuance.

**Binding — the strongest simple rule:**

> A nonce should authorize exactly one certificate request, for one
> bounded subject/profile, for one key, within one short validity window.

At minimum bind to: one domain (or domain set), one leaf public key
fingerprint or CSR, one issuance profile, one expiration window. Otherwise
a valid nonce could be reused for a different key or a broader certificate
than intended.

**Expiry:**

Keep nonces short-lived (minutes, not days). The authoritative expiry is
enforced by the CA's own clock and database, not by trusting client input
or untrusted DNS data. Short validity sharply reduces replay and DoS
windows.

**Single-use:**

Once a nonce succeeds, mark it consumed immediately. If a request fails
halfway through, burn the nonce — burning on first serious use is safer.

**Proof of possession:**

The nonce authorizes the enrollment attempt, but does not replace proof of
possession. The leaf user must still prove they hold the private key
corresponding to the CSR public key. A CSR signature is the standard
proof-of-possession mechanism (RFC 7030 EST, ACME).

**Rate limiting:**

The nonce gate helps, but also rate-limit:
- Nonce issuance requests
- Registration attempts
- Failed validations
- Per-domain and per-account activity

This prevents shifting the flood from "leaf issuance" to "nonce request."

**Audit trail:**

Log: who requested the nonce, for which domain, from where, when it was
consumed, what key fingerprint it authorized, and whether issuance
succeeded. This matters for incident response.

**Public vs private PKI:**

- **Private PKI / own ecosystem** (our case): this nonce-gated registration
  model is directly workable
- **Public Web PKI CA**: would need to fit within CA/Browser Forum Baseline
  Requirements for domain control validation (CABF BR)

**Compact protocol sketch:**

```
POST /nonce-request   (by authorized admin)
  → CA returns random nonce, stores pending authorization

POST /certificate/request   (by leaf user)
  → CSR + nonce
  → CA checks: nonce validity, binding, expiry, proof-of-possession, policy
  → CA issues cert, marks nonce consumed
```

**Two biggest mistakes to avoid:**
1. Making the nonce predictable
2. Letting the nonce authorize "any key for this domain" instead of one
   exact key or CSR

**References:**
- RFC 8555 — ACME (nonce-based anti-replay, authorization before issuance)
- RFC 7030 — EST (proof-of-possession via CSR signature)
- CA/Browser Forum Baseline Requirements (public PKI validation rules)

**Files:**
- `server/c/mtc_http.c` — new `/nonce-request` endpoint, modified
  `/certificate/request` to require nonce
- `server/c/mtc_store.c` — nonce CRUD operations
- `server/c/mtc_db.c` — `mtc_enrollment_nonces` table (Neon)
- `tools/python/main.py` — two-phase enrollment flow
- `tools/python/mtc_client.py` — `request_enrollment_nonce()` method

### 5. AbuseIPDB gate on CA and leaf enrollment — DONE

**Priority:** High — blocks abusive IPs before they can enroll

The AbuseIPDB check currently only runs on general requests. It should also
gate CA enrollment (`/enroll-ca`) and leaf enrollment (`/certificate/request`)
at the service entrance — reject the connection before any enrollment logic
runs if the client IP has a high abuse confidence score.

**Threshold:** Lower the rejection threshold from 75% to **25%**. Enrollment
is a privileged operation and should be more restrictive than general access.
A 25% confidence score means "probably suspicious" which is enough to reject
an enrollment attempt. Legitimate users with flagged IPs can resolve their
AbuseIPDB listing or contact the CA operator.

**Implementation:**
1. In `mtc_http.c`, call `mtc_check_endpoint()` at the top of
   `handle_certificate_request()` and `handle_enroll_ca()` (or in the
   connection accept path before routing)
2. If abuse confidence score >= 25, return 403 and log the rejection
3. Define `ABUSEIPDB_ENROLL_THRESHOLD 25` in `mtc_checkendpoint.h`
   (separate from any general-access threshold)

**Files:**
- `mtc-keymaster/server/c/mtc_http.c` — add check at enrollment entry points
- `mtc-keymaster/server/c/mtc_checkendpoint.h` — add enrollment threshold constant
- `mtc-keymaster/server/c/mtc_checkendpoint.c` — ensure check function
  accepts a threshold parameter

### 6. AbuseIPDB cache expiry — refresh stale records after 5 days — DONE

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

### 7. Server-verified FIPS source checksums via MTC transparency log

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

### 8. Compiler integrity — what if gcc has been corrupted?

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
   - The postWolf build already stores `.build_params` — extend this to
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

### 9. MQC cosignature verification — follow-ups

**Priority:** Low–Medium — hygiene after task #2 (client-side Ed25519
cosignature verifier in `socket-level-wrapper-MQC/mqc_peer.c`) lands.
These were explicitly left out of task #2's scope to keep the change
focused.

**9a. `/ca/public-key` PEM header is mislabelled**

`mtc_store_get_public_key_pem()` currently produces
`-----BEGIN EDDSA PRIVATE KEY-----` around the Ed25519 *public* key
DER.  The DER body is correct; only the label is wrong.  Clients work
around it by base64-decoding the body and slicing the last 32 bytes.
Once the label is fixed to `-----BEGIN PUBLIC KEY-----`, clients can
use `wc_PubKeyPemToDer` + `wc_Ed25519PublicKeyDecode` cleanly.

**Files:** `mtc-keymaster/server/c/mtc_store.c` (`mtc_store_get_public_key_pem`)

**9b. Eliminate TOFU on first `/ca/public-key` fetch**

Currently `show-tpm --mqc` performs a trust-on-first-use fetch of the
CA cosigner pubkey from the MTC HTTP server and caches it at
`~/.TPM/ca-cosigner.pem`.  That first fetch is over TLS to the same
server whose signatures we're about to verify — not ideal.
Distribute the CA cosigner pubkey out-of-band (bundled with clients,
via signed DNS TXT, or similar) so no client ever trusts the MTC
server for initial bootstrap.

**9c. Load CA cosigner pubkey in every MQC client — DONE**

`mqc_load_ca_pubkey(mtc_server, out32)` is now a public API in
`socket-level-wrapper-MQC/mqc_peer.h`.  It reads (or TOFU-fetches)
`~/.TPM/ca-cosigner.pem`, decodes the PEM, and returns the raw
32-byte Ed25519 key.  `show-tpm`, `examples/echo_client`, and
`examples/echo_server` all call it.  Future `libmqc.a` consumers
should use it too.

**9d. Converge cosig message format with wolfSSL's `wc_MtcVerifyCosignature`**

The MTC server signs over:
```
"mtc-subtree/v1\n\x00" (16 bytes)
|| cosigner_id || log_id
|| start (8 BE) || end (8 BE)
|| subtree_hash (32 bytes)
```

but wolfSSL's reference `wc_MtcVerifyCosignature` expects:
```
"MTC SubtreeSign v1" (18 bytes)
|| start (8 BE) || end (8 BE)
|| subtree_hash (32 bytes)
```

The formats disagree on label and on whether `cosigner_id` / `log_id`
are part of the signed message.  Converging to the wolfSSL shape lets
us drop our hand-rolled verifier in `mqc_peer.c` and call the upstream
API directly.  Requires editing `mtc_store_cosign` in
`mtc-keymaster/server/c/mtc_store.c` and re-running `admin_recosign
--write` once the new format is active.

---

### 10. MQCP echo handshake never completes

**Priority:** Medium — MQCP is the QUIC-inspired transport under
`socket-level-wrapper-QUIC/`.  The MQC (TCP) and SLC (TLS 1.3 + MTC)
transports round-trip cleanly; MQCP does not.

**Symptoms** (observed during phase-5 end-to-end testing):

Running the bundled echo pair:

```
cd socket-level-wrapper-QUIC
./examples/echo_server ~/.TPM/factsorlie.com-ca 5443 &
./examples/echo_client ~/.TPM/factsorlie.com localhost 5443 "Hello QUIC!"
```

Client emits:
```
[MQCP mqcp_ctx_new] Context created: cert_index=72
[MQCP-HS mqcp_handshake_client_start] Client sent ClientHello (5 frags)
[MQCP-HS mqcp_handshake_check_timers] Retransmit handshake (attempt 1)
[MQCP-HS mqcp_handshake_check_timers] Retransmit handshake (attempt 2)
[MQCP-HS mqcp_handshake_check_timers] Retransmit handshake (attempt 3)
```
and then gives up.

Server emits only:
```
[MQCP mqcp_ctx_new] Context created: cert_index=73
[MQCP mqcp_listen] Listening on :::5443 (fd=3)
```
— never logs the `"New connection"` line from `mqcp_accept`.

**What that tells us:** the server's `poll()` loop either isn't
seeing incoming UDP datagrams, or `mqcp_accept()` receives them but
never completes ClientHello reassembly and so returns NULL.  Client
retransmission suggests the server is simply not ACKing or responding
at all.

**Suspected causes** (unverified, worth checking in this order):

1. UDP socket on the server is bound but not actually reading —
   check whether `mqcp_accept` calls `recvfrom` in its path and
   whether the poll-ready event is being consumed.
2. ClientHello arrives as multiple fragments but the reassembly
   logic can't correlate them to a pending pseudo-connection
   because no pseudo-connection exists before the first fragment
   arrives.
3. Address-family mismatch: `mqcp_listen` shows "Listening on
   :::5443" (IPv6 wildcard) while the client may be sending to
   127.0.0.1 (IPv4).  If the server's socket is pure IPv6 without
   `IPV6_V6ONLY=0`, IPv4 packets would be silently dropped.

**No dependency on phase-5 work:** MQCP (`libmqcp.a`) has its own
peer-verification path (`mqcp_peer.c`) — it does not call the new
`mqc_peer_verify` or `mqc_load_ca_pubkey` from libmqc.  The comment
in `mqcp_peer.c` ("matching MQC's mqc_peer_verify") is documentation
only.

**Files to investigate:**
- `socket-level-wrapper-QUIC/mqcp_conn.c`  — `mqcp_listen`, socket setup
- `socket-level-wrapper-QUIC/mqcp_handshake.c` — `mqcp_accept`,
  ClientHello reassembly
- `socket-level-wrapper-QUIC/examples/echo_server.c` — poll loop
  around `mqcp_accept` / `mqcp_process`

### 11. MQC peer verify uses libcurl (8444/TLS) instead of MQC (8446)

**Priority:** Medium — post-quantum consistency issue.  The handshake
and session are authenticated over ML-KEM-768 + ML-DSA-87 + AES-256-GCM,
but the lookups `mqc_peer_verify` performs to decide *whether to trust
the peer* all ride classical TLS on port 8444.

**Current behavior** (`socket-level-wrapper-MQC/mqc_peer.c`):

Every security-critical lookup is a libcurl `GET https://<mtc_server>/…`
call — resolving to port 8444 (the TLS 1.3 HTTP API):

| Endpoint | Site in `mqc_peer.c` |
|---|---|
| `/certificate/<n>` | `fetch_certificate` @ line 386 |
| `/revoked/<n>` | `check_revoked` @ line 475 |
| `/ca/public-key` | `mqc_load_ca_pubkey` @ line 921 |
| `/log/entry/<n>` | `mqc_peer_verify` @ line 1057 |
| `/public-key/<subject>` | `extract_pubkey_from_cert` @ line 772 |

**Why it matters:** the MQC listener at `mtc_http.c:1864` already serves
the same routes over the post-quantum channel on port 8446 (it routes
through the same `handle_request` dispatcher — see line 1908).  So the
server side is wired up; only the client bypasses it.

An attacker who can break TLS on 8444 — today via CA compromise / MITM,
or in a post-quantum future via harvested ECDHE / ECDSA keys — can:

- Suppress revocations by forging `{"revoked": false}` for a revoked
  cert (the 24-hour cache then masks the tampering for a full day).
- Poison first-contact TOFU of the CA key by returning an attacker key
  at `/ca/public-key`.
- Feed a forged cosignature/proof chain that passes local verification
  because the CA pubkey the client TOFU'd was the attacker's.

The whole point of MQC is to move the trust chain off classical crypto;
routing the decisions through TLS re-introduces the weakness MQC was
meant to eliminate.

**Fix sketch:**

Add a small PQ request helper to libmqc that opens an MQC connection,
sends an HTTP-shaped `GET <path> HTTP/1.1\r\n\r\n`, reads the response,
and returns the body + status.  Then replace each `http_get(...)` site
in `mqc_peer.c` with the new helper targeting `mtc_server:8446`.

Bootstrap subtlety: `mqc_load_ca_pubkey` runs *before* we have a
verified CA key (TOFU), so its first-contact fetch may have to stay on
a different channel (or be explicitly TOFU'd over MQC with a big
warning log).  All subsequent lookups — including `/revoked/<n>` —
have a CA key in hand and can authenticate the MQC peer.

**Files to change:**
- `socket-level-wrapper-MQC/mqc_peer.c` — replace five `http_get` call
  sites listed above
- `socket-level-wrapper-MQC/mqc.c` / `mqc.h` — add `mqc_http_get()`
  helper (or similar)
- `socket-level-wrapper-MQC/examples/echo_{client,server}.c` — update
  `DEFAULT_SERVER` to point at `:8446` when the switch is made

### 12. Consider vendoring cJSON to drop the `libjson-c` apt dependency

**Priority:** Low — nothing is broken.  Raised during phase-6 after a
scoping exercise against `DaveGamble/cJSON` (cloned to `~/postWolf/cJSON`
for reference, kept out of the build).

**Current state:** we rely on the Ubuntu-packaged `libjson-c-dev`
(0.17-1build1 as of 2026-04).  No rolled-our-own JSON code anywhere
in the tree — every call goes through `json_object_*` /
`json_tokener_*` and every Makefile links via
`pkg-config --cflags/--libs json-c` (or `-ljson-c` in
`examples/quic-mtc/Makefile` and upstream wolfSSL's own `Makefile`).

**Scope of a migration:** roughly 1,150 json-c API call sites across
15 files, ~12k LOC affected:

| Area | Files |
|---|---|
| MQC wrapper | `socket-level-wrapper-MQC/{mqc,mqc_peer}.c` |
| mtc-keymaster server | `mtc_http.c`, `mtc_db.c`, `mtc_store.c`, `mtc_ca_validate.c`, `mtc_bootstrap.c`, `mtc_checkendpoint.c` |
| mtc-keymaster tools | `show-tpm.c`, `bootstrap_ca.c`, `bootstrap_leaf.c`, `admin_recosign.c` |
| wolfSSL MTC glue | `src/ssl_mtc.c` (confirm this is ours, not upstream, before touching) |

**Not a sed-able migration.**  The two APIs are shaped differently
enough that every site needs to be read:

| Operation | json-c | cJSON |
|---|---|---|
| Get field | `json_object_object_get_ex(o,"k",&v)` (out-param + int return) | `v = cJSON_GetObjectItemCaseSensitive(o,"k")` (returns pointer, NULL on miss) |
| Lifetime | reference-counted (`json_object_put` on each ref) | tree-owned (`cJSON_Delete(root)` frees everything) |
| Parse | `json_tokener_parse(s)` | `cJSON_Parse(s)` |
| Serialize | `json_object_to_json_string_ext(o, flags)` | `cJSON_Print(o)` / `cJSON_PrintUnformatted(o)` |

The lifetime-model difference is the real risk.  json-c's
`json_object_put` calls are sprinkled through error-exit paths and
struct teardown.  With cJSON there's one `cJSON_Delete(root)` at the
end.  Each existing `json_object_put` has to be classified: drop it
(if the object is owned by a root that's still freed elsewhere) or
restructure (if we were leaning on ref-counting for shared ownership).
Get it wrong and you have either a leak or a double-free.

**Pros of switching:**
- Self-contained build; one less apt package on target systems.
- Source is in-tree, so we can audit / patch / add Doxygen to it.
- MIT-licensed, same as ours — no license friction.

**Cons of switching:**
- We inherit maintenance (including security patches) instead of
  riding the distro's updates.  json-c is a mature library that's
  seen many advisories over the years.
- ~1,150 call-site edits, all hand-reviewed, is a real-world
  regression risk.
- No functional benefit — the JSON we parse is not a bottleneck.

**Recommendation:** park it.  Revisit only if a concrete requirement
(e.g. a target platform without an easy apt path to `libjson-c-dev`,
or a security incident we can't get a timely upstream fix for) makes
self-containment necessary.  If we do pick it up, sequence the work
per file with a build + functional test between each file, not
big-bang.

**Files to touch (if we proceed):**  Makefiles first — add
`cJSON.c` / `cJSON.h` under a `third_party/cjson/` (or vendor into
each wrapper), swap `pkg-config --cflags/--libs json-c` for local
include paths, then migrate source files one at a time in the order
above.

### 13. Log and alert on nonce domain/fp mismatches during enrollment

**Priority:** Low–Medium — current behavior is safe but noisy.  The
binding check in `mtc_db_validate_and_consume_nonce` (`mtc_db.c:1222`)
already rejects a nonce submitted with the wrong `domain` or `fp` —
that discussion is captured in `README-nonce.md`.  We deliberately
chose *not* to invalidate the nonce on failure because that would
create a DoS primitive: anyone who learned the nonce (leaked log
line, chat paste, email) could burn a legitimate holder's enrollment
by posting one bogus request.

What we're missing is observability: right now the failure path in
`mtc_bootstrap.c:532` collapses four distinct outcomes into a single
`LOG_WARN("bootstrap: invalid, expired, or used nonce for '%s'")`:

1. Nonce never existed in the DB (likely probing / random guessing).
2. Nonce existed but expired (benign — clock skew or slow handoff).
3. Nonce existed and was already consumed (replay attempt).
4. Nonce existed, pending, unexpired — but the submitted `domain` or
   `fp` didn't match the bound values.  **This is the attacker
   signal** — possession of the nonce but not the keypair / not the
   intended subject.

**Fix sketch:**

1. Before the atomic `UPDATE`, run a diagnostic `SELECT … WHERE nonce
   = $1` to classify the failure.  Acceptable to do this only on the
   failure path (UPDATE returned 0 rows), so the hot path stays one
   round trip.  There is no TOCTOU concern for the log line itself
   because the UPDATE already decided the outcome.
2. For case (4), emit a distinct log tag (`MQC_SECURITY`-style or a
   new `LOG_SECURITY("NONCE_MISMATCH: ...")`) carrying:
   - `nonce` (redacted — first 16 hex + `...` matches the existing
     `LOG_INFO` style at `mtc_bootstrap.c:548`)
   - `expected_domain` (from the DB row)
   - `submitted_domain` (from the request)
   - `expected_fp` and `submitted_fp` (first 16 hex each)
   - Source IP (`ip_str` is already on `client_io`)
3. Bump a per-IP failed-enrollment counter (reuse or extend
   `mtc_ratelimit.c`) so an attacker sweeping `fp` or `domain` values
   against a known nonce hits a ceiling.  Existing `RL_ENROLL` bucket
   may already cover this — audit before adding a new one.
4. Optionally, report persistent mismatch floods to AbuseIPDB if the
   same IP crosses a threshold (see `README-abuseipdb.md`); reuse the
   existing reporting path rather than inventing a new one.

**What NOT to do:** do not mark the nonce `consumed` or otherwise
mutate its row on a mismatch.  That is the DoS primitive discussed
above.  The nonce's natural 15-minute TTL is the correct bound.

**Files to change:**
- `mtc-keymaster/server/c/mtc_bootstrap.c` — expand the failure branch
  at line 529-545 to call the new classifier before sending the
  error response.
- `mtc-keymaster/server/c/mtc_db.c` / `mtc_db.h` — add a
  `mtc_db_classify_nonce_failure()` helper (or inline the SELECT) so
  the HTTP handler and the bootstrap handler can both call it.
- `mtc-keymaster/server/c/mtc_ratelimit.{c,h}` — confirm `RL_ENROLL`
  already covers failed attempts, or add `RL_ENROLL_FAILED`.
- `mtc-keymaster/README-nonce.md` — add a "Observability" section
  once implemented, so the doc matches the shipped behavior.

### 14. Purge main.py references from the docs

**Priority:** Low — cosmetic doc cleanup after a deletion.

`mtc-keymaster/tools/python/main.py` was removed in phase-6 because
its functionality (`bootstrap`, `enroll`, `enroll-ca`, `verify`,
`monitor`) is now covered by the C binaries (`bootstrap_ca`,
`bootstrap_leaf`, `show-tpm`) plus `issue_leaf_nonce.py`.  The
script also had a stale `--server http://localhost:8443` default
that no listener matches anymore.

The delete commit did *not* update the six docs that still reference
`main.py`:

| File | Flavor of reference |
|---|---|
| `README.md` | CLI description + example invocations on 8443 |
| `README-postWolf.md` | Project overview bullet (tools/python list) |
| `README-clean-install.md` | Step-by-step bootstrap / CA enroll / leaf enroll / verify walkthrough (heaviest) |
| `README-ml-dsa-87.md` | Example enrollment flow |
| `server/c/README-using-mtc-server.md` | Command-reference table (`main.py bootstrap`, `main.py enroll`, etc.) |
| `README-bugsandtodo.md` | Historical notes in #3, #4, and the DNS-cache section (safer to leave alone — they document past state) |

**Cleanup sketch:**

Replace each active-instruction `main.py` example with the current
C-tooling equivalent, preserving intent:

| Old | New |
|---|---|
| `python3 main.py --server https://localhost:8444 bootstrap` | Fetch CA pubkey once via `show-tpm -s localhost:8444` (or `mqc_load_ca_pubkey` for API users) |
| `python3 main.py --server ... enroll-ca <cert.pem>` | `bootstrap_ca --server HOST:8445 ...` |
| `python3 main.py --server ... enroll <domain> --nonce ...` | `bootstrap_leaf --server HOST:8445 --domain <d> --nonce ...` |
| `python3 main.py --server ... verify <index>` | `show-tpm --verify --index <index> -s HOST:8444` |
| "monitor" command | No direct replacement — drop from docs unless we add a C monitor |

Historical `main.py` references in `README-bugsandtodo.md` (items #3,
#4, and the DNS-cache note) should be left intact — they document
past decisions, and rewriting them distorts the record.

**Files to change:**
- `mtc-keymaster/README.md`
- `README-postWolf.md`
- `mtc-keymaster/README-clean-install.md`
- `mtc-keymaster/README-ml-dsa-87.md`
- `mtc-keymaster/server/c/README-using-mtc-server.md`

### 15. Gate leaf-nonce issuance by cryptographic caller identity (MQC-only)

**Priority:** Medium — follow-up enabled by moving `issue_leaf_nonce` to
MQC on port 8446.

**Why this is only possible now:** the Python `issue_leaf_nonce.py` hits
`POST /enrollment/nonce` over classical TLS on 8444.  The server sees
a source IP and a `(domain, fingerprint)` pair but has no
cryptographic evidence of *who* is making the request.  Today the
policy check is: "does a registered CA exist for `<domain>`?"
(`mtc_http.c:584-596`, via `mtc_db_find_ca_for_domain`).  Anyone who
can reach port 8444 and knows the request format can issue a pending
nonce for any domain whose CA is registered — the binding check at
consumption time is what actually keeps it safe.

With the new C `issue_leaf_nonce` using MQC on 8446, the server's MQC
layer authenticates the caller's cert_index (the CA operator's
enrolled ML-DSA-87 identity) before `handle_request` ever sees the
body.  That gives us a stronger server-side policy:

> **Only the CA that holds the registered CA cert for `<domain>` may
> issue a leaf nonce for that domain.**

**Fix sketch:**

1. In `handle_enrollment_nonce` (`mtc_http.c:510`), when the transport
   is MQC (`io->mqc != NULL` — confirm the existing flag), extract the
   caller's cert_index via `mqc_get_peer_index(io->mqc)`.
2. Look up the cert for that index in `mtc_certificates` and read its
   subject.
3. For `type=leaf` nonces, reject (`403`) unless the caller's subject
   is `<domain>-ca` (or, more generally, matches the CA registered for
   `<domain>` in `mtc_db_find_ca_for_domain`).
4. Keep the existing "a registered CA exists for this domain" check
   as a cheap first-pass filter; the identity check is a stricter
   second pass that only applies to MQC-authenticated requests.
5. Log (structured) both success and rejections, in line with TODO
   #13.

**Migration concern:** the Python `issue_leaf_nonce.py` on port 8444
would keep working under the old looser policy (no caller-identity
check) until we sunset it.  That's fine — enforce the stricter rule
only for MQC-authenticated requests so we don't break the lax path
before the C tool has distribution.  Eventually: return 410 on
`POST /enrollment/nonce` at 8444 (mirroring what we did with
`/certificate/request`).

**Files to change:**
- `mtc-keymaster/server/c/mtc_http.c` — extend
  `handle_enrollment_nonce` with an MQC-identity check before the
  `mtc_db_create_nonce` call.
- `mtc-keymaster/server/c/mtc_db.c` / `mtc_db.h` — add
  `mtc_db_get_cert_subject(conn, cert_index, out, outsz)` (or reuse
  any existing helper).
- `mtc-keymaster/server/c/mtc_http.h` — ensure `client_io` exposes the
  MQC connection pointer so we can reach `mqc_get_peer_index`.

### 16. Tighten TODO #13 observability once MQC-authenticated issuance lands

**Priority:** Low — refinement of TODO #13.

Once TODO #15 ships, failed enrollment attempts carry a cryptographic
caller identity (the peer's cert_index) instead of just a source IP.
That makes the log-and-alert work from TODO #13 considerably sharper:

- **Current TODO #13 log record:** `source IP`, `submitted_domain`,
  `submitted_fp`, classification of the failure.
- **After TODO #15:** same fields plus `caller_cert_index` and
  `caller_subject` from the MQC peer.  Logging the caller's subject
  changes a mismatch alert from "an IP is probing nonce binding" to
  "principal X attempted to mint a nonce for domain Y they don't
  control" — a much stronger signal, and something worth escalating
  directly (not just AbuseIPDB).

**Fix sketch:**
- Wire the caller's cert_index / subject into the log record added by
  TODO #13.
- Consider a distinct log tag (`NONCE_CROSS_CA_ATTEMPT`) for the case
  where the caller is a valid CA but for a *different* domain — that's
  the clearest sign of an insider / compromised-CA scenario.
- Rate-limiting by caller_cert_index becomes an option in addition to
  rate-limiting by IP; a single CA operator flooding the endpoint can
  now be throttled without affecting other operators sharing NAT.

**No files to change yet** — this TODO stays a pointer until TODOs
#13 and #15 are both in progress.

### 17. MQC client connect retry subsystem

**Priority:** Medium — observed during phase-7 smoke testing of
`issue_leaf_nonce` against a live `mtc-ca.service` on port 8446.

**Observed symptom:** the *first* `mqc_connect` call from a cold
client tool failed with `"Error: mqc_connect to localhost:8446
failed"`, printing no protocol-level trace (no context setup lines,
no handshake frames).  An immediate retry in the same process —
triggered by passing `--trace`, which only changes verbosity — fully
succeeded, and every subsequent run completed normally (either 200
with a fresh nonce or 409 duplicate-pending, both valid outcomes).

Service state was confirmed good before and after: `systemctl
is-active mtc-ca.service` = active, all three listeners (8444, 8445,
8446) open.  This means the failure was not server-down, not
cert_index-mismatch, not a pubkey issue — the three things a real
handshake failure would surface.  The most likely cause is a
transient cold-start: an accept-side socket buffer not yet drained,
an internal MQC context state that settles on second contact, or
packet loss on the local loopback at handshake time.

**Why it warrants more than a shrug:** every new MQC-over-8446 tool
(`show-tpm`, `issue_leaf_nonce`, and the helpers TODO #11 will add
to replace libcurl in `mqc_peer.c`) will hit this same cold-start
path.  A one-off transient failure that a human can retry is a
one-off *visible* transient failure for programmatic callers too —
that's going to show up as flaky CI, flaky monitoring probes, and
mid-operation aborts in tools that expect a single attempt to work.

**Fix sketch:**

1. **Put the retry in libmqc, not in each tool.**  Add a thin
   wrapper, e.g. `mqc_connect_retry(ctx, host, port, opts)`, that
   encapsulates the policy so every client gets the same behavior:

   ```c
   typedef struct {
       int max_attempts;     /* default 3 */
       int initial_delay_ms; /* default 200 */
       double backoff;       /* default 2.0  — 200ms, 400ms, 800ms */
       int timeout_ms;       /* per-attempt connect timeout */
   } mqc_retry_opts_t;
   ```

   Tools should keep calling the primitive `mqc_connect` only when
   they have a specific reason (e.g. test harnesses that want to
   observe a single attempt).  `mqc_connect_retry` becomes the default
   for end-user tooling.

2. **Classify which failures are retryable.**  A connect-level error
   (TCP/UDP refused, handshake never completed, timeout) is retryable.
   A cryptographic failure (CA pubkey mismatch, peer not in log,
   cosignature invalid, subtree hash mismatch) is *not* — retrying
   it will just repeat the same deterministic rejection.  The
   classifier lives where `mqc_connect` currently returns its NULL:
   the internal error path already knows which kind of failure
   occurred; expose it to callers (e.g. via `mqc_last_error()` or a
   small `mqc_status_t` return from `mqc_connect_retry`) so retryable
   vs. fatal is a first-class distinction.

3. **Honor `mqc_set_verbose(1)` on each retry** so the cold-start
   case produces a comparable trace to a successful attempt.  Right
   now `--trace` accidentally *is* the workaround because the second
   MQC context initialization after the verbose flag flips is what
   actually succeeds — but that's coincidence, not design.

4. **Narrow the scope of the retry to connect + handshake.**  Once
   a connection is established and a request is in flight, retrying
   a POST has different semantics (could mint a second nonce row).
   `mqc_connect_retry` should only run the connect loop; anything
   built on top is the caller's responsibility.

**Call-site audit (will need updating after the helper lands):**

- `mtc-keymaster/server/c/show-tpm.c` — `mqc_http_get` @ line 57
- `mtc-keymaster/server/c/issue_leaf_nonce.c` — `mqc_http_post` @ its
  single `mqc_connect` call
- `socket-level-wrapper-MQC/mqc_peer.c` — once TODO #11 replaces
  libcurl with MQC, every lookup path gains a connect site

**Files to change:**
- `socket-level-wrapper-MQC/mqc.h` — add `mqc_connect_retry` +
  `mqc_retry_opts_t` + error classification enum.
- `socket-level-wrapper-MQC/mqc.c` — implement the retry/backoff
  policy and failure classification.
- Tools above — switch from `mqc_connect` to `mqc_connect_retry`.

---

### 18. Server-side: don't drop the handshake after revocation cache refresh

**Priority:** Medium — functionality is correct today (client tools
paper over it with a 100 ms retry, commit 90b4fb6e8), but the
root cause lives on the server and every new MQC-over-8446 consumer
inherits the workaround.

**Observed symptom:** the *first* MQC handshake for a given
`cert_index` after a server restart (or after the 24 h revocation
cache TTL expires) fails.  The client sees
`"Error: cannot reach server at mqc://localhost:8446"` even though
the server is fully healthy.  Any second attempt succeeds.

**Root cause:** in `socket-level-wrapper-MQC/mqc_peer.c` the helper
`check_revoked` is documented to return `-1` on cache-miss-then-fresh-fetch:

```
/* check_revoked return codes:
 *   0  = not revoked (fresh cached status allows connection)
 *   1  = revoked (cached status says so, or fresh fetch confirmed)
 *  -1  = cache miss or stale; fresh single-cert status was fetched
 *        and persisted, but caller must drop this connection as a
 *        safety measure.  The peer will find the cache fresh on retry.
 */
```

The callers (both client-verifies-server and server-verifies-client)
honor that `-1` and drop the otherwise-usable connection.  The fresh
revocation status is *already known* at that point — the drop is
belt-and-suspenders, not a correctness requirement.

**Current workaround:** `tools/c/show-tpm.c` and
`tools/c/issue_leaf_nonce.c` each do a one-shot 100 ms retry around
`mqc_connect` (see commit 90b4fb6e8).  Works, but it:
- hides a known-benign failure from callers instead of fixing it,
- makes every new MQC tool re-implement the retry,
- doubles cold-start latency by a hardcoded 100 ms, and
- interacts poorly with TODO #17's more principled retry/backoff
  policy (both will be trying to paper over the same server quirk).

**Fix sketch:**

1. **Investigate the "safety measure" comment.** `git log -p` on
   `mqc_peer.c` around the `check_revoked` function and find the commit
   that introduced the `-1` drop.  Understand what threat or race the
   author had in mind.  This is the 30-second due-diligence that
   distinguishes "the drop was defensive against a real risk" from
   "the drop was habit, not design."

2. **Assuming no load-bearing reason, stop dropping.** When the fresh
   fetch successfully returns a revocation status, use it.  Collapse
   the return codes to just `{not revoked, revoked, transport error}`
   — there is no longer a "fresh fetch means drop" case.

3. **If there *is* a load-bearing reason,** write it into the comment
   so future readers don't second-guess it, and leave the workaround in
   place.  At minimum distinguish "this drop is deliberate" from "this
   drop is a TODO."

4. **Remove the client-side retry** in `tools/c/show-tpm.c` and
   `tools/c/issue_leaf_nonce.c` once the server no longer drops.
   Anything TODO #17 builds can focus on real transient failures, not
   this synthetic one.

**Files to change:**
- `socket-level-wrapper-MQC/mqc_peer.c` — adjust `check_revoked`
  return codes and the caller(s) that interpret the `-1` drop.
- `mtc-keymaster/server2/c/mtc_http.c` — if any server-side callers
  of the handshake path depend on the drop.
- `mtc-keymaster/tools/c/show-tpm.c`,
  `mtc-keymaster/tools/c/issue_leaf_nonce.c` — remove the 100 ms
  retry shim once the root cause is fixed.

---

### 19. End-to-end test coverage for `/revoke` and `revoke-key`

**Priority:** High — authentication-gated revocation landed in phase-7
but only the two read-only subcommands (`--list`, `--refresh`) have
been exercised against the live server.  The signing path was built,
compiled, and dry-run'd, but never actually POSTed to `/revoke`
because every test would mutate the production Merkle log.

**What's verified today (2026-04-18):**

- `revoke-key --list factsorlie.com` round-trips via the bootstrap
  port; filters `/revoked` by subject suffix correctly.
- `revoke-key --refresh` re-pulls `/revoked` and rewrites every
  `~/.TPM/peers/<n>/revoked.json` with fresh mtime + correct
  `{"revoked": true|false}` state.
- `handle_revoke` builds, links, and passes `-Wall -Wextra -Werror`.

**What still needs a test rig:**

Stand up a scratch log (`tools/clearout.sh` → restart `mtc-ca.service`),
enrol a disposable CA + two disposable leaves, and run the full
positive + negative matrix.  Expected results:

| Scenario | Expect | Current verification |
|---|---|---|
| CA revokes a leaf in its own domain | `200 {revoked:true}`, `/revoked/<n>` returns `true` on next call | NOT TESTED |
| CA revokes itself (`ca_cert_index == cert_index`) | `403 "CA may not revoke itself"` | NOT TESTED |
| CA revokes a leaf **outside** its domain | `403 "target leaf is not within the CA's domain"` | NOT TESTED |
| CA revokes another CA (`-ca` target) | `403 "target is not a leaf"` | NOT TESTED |
| Caller is a leaf, not a CA | `403 "caller is not a CA"` | NOT TESTED |
| Signature valid but `ca_public_key_pem` hash ≠ logged hash | `403 "ca_public_key_pem does not match logged CA certificate"` | NOT TESTED |
| Signature invalid for otherwise-valid payload | `403 "signature verification failed"` | NOT TESTED |
| Timestamp > 5 min old | `400 "timestamp outside ±5 min freshness window"` | NOT TESTED |
| Timestamp > 5 min in the future | `400` same message | NOT TESTED |
| Every key algorithm: EC-P256, EC-P384, Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87 | `200` on the matching CA, `403` if algorithm mismatched against log | NOT TESTED |

**Cross-reference:** `tools/c/revoke-key.c` dry-run mode prints the
exact body that would be POSTed, which is the easiest way to seed
malformed inputs for the negative cases — e.g. hand-edit the
dry-run output, `printf` it through `nc` or `curl -k
https://localhost:8444/revoke` with `Content-Type: application/json`.

**Files involved:**
- `mtc-keymaster/server2/c/mtc_http.c` — `handle_revoke` (auth logic).
- `mtc-keymaster/tools/c/revoke-key.c` — signing client.
- `mtc-keymaster/tools/clearout.sh` — scratch-log reset.

---

### 20. Kit leaf — one-shot packaging / setup tool for a new leaf identity.

### 21. Kit CA — one-shot packaging / setup tool for a new CA identity.

### 22. Update factsorlie.com website to reflect the current postWolf architecture.

### 23. Cert renewal — review and harden the existing `/certificate/renew` + `renew-tool/` flow.

### 24. Leaf-side "cert about to expire" tooling + docs — ship a tool in the leaf kit (and instructions in README-leaf.md) that scans `~/.TPM/`, detects certs within N days of `not_after`, and kicks off a renewal against the CA.  `install-leaf-kit.sh` should also install a cron (or systemd-timer) entry that runs the expiration check on a schedule so the leaf user doesn't have to wire it up themselves.

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

---

## Appendix: Post-Quantum Readiness

### Diffie-Hellman is not post-quantum safe

Classical key exchange (DH, ECDH) and signatures (RSA, DSA, ECDSA) are all
broken by Shor's algorithm on a sufficiently large quantum computer.

**Vulnerable algorithms:**
- DH (finite field) — discrete log
- ECDH (elliptic curve) — elliptic curve discrete log
- RSA — integer factorization
- DSA, ECDSA — discrete log variants

### NIST post-quantum standards

| Algorithm | Replaces | Type |
|-----------|----------|------|
| **ML-KEM** (CRYSTALS-Kyber) | DH/ECDH | Key encapsulation |
| **ML-DSA** (CRYSTALS-Dilithium) | RSA/ECDSA | Digital signatures |
| **SLH-DSA** (SPHINCS+) | RSA/ECDSA | Hash-based signatures (conservative fallback) |

### Current wolfSSL build status

This build has post-quantum support enabled:
- `WOLFSSL_HAVE_MLKEM` — ML-KEM key encapsulation
- `WOLFSSL_PQC_HYBRIDS` — hybrid key exchange (ML-KEM + ECDH in a single
  TLS 1.3 handshake)

The hybrid approach provides post-quantum security from ML-KEM while keeping
classical security from ECDH as a safety net in case ML-KEM has an
undiscovered weakness.

### "Harvest now, decrypt later"

The near-term threat is an adversary recording TLS traffic today and
decrypting it once quantum computers are available. This is why migrating
key exchange to ML-KEM (or hybrids) matters now, even though large quantum
computers don't yet exist. Signatures are less urgent since they only need
to be valid at verification time.

### MTC implications

The MTC transparency log uses Ed25519 for CA cosignatures. Ed25519 is
**not** post-quantum safe (elliptic curve discrete log). A future migration
path would be:

1. **Key exchange** — already addressed by `WOLFSSL_PQC_HYBRIDS` in TLS 1.3
2. **MTC cosignatures** — migrate from Ed25519 to ML-DSA or SLH-DSA when
   wolfSSL adds support and the draft-ietf-plants spec is updated
3. **Leaf certificates** — currently EC-P256; would need ML-DSA equivalent

The Merkle tree structure itself (SHA-256 hashes) is quantum-resistant —
Grover's algorithm only halves the effective hash length (256→128 bits),
which remains secure.

---

## Appendix: Server-Issued Nonce Plan for CA Enrollment

### Problem

The current CA enrollment has a chicken-and-egg problem: `ca_dns_txt.py`
generates nonces client-side, but the server never sees or validates them.
The C server's `validate_ca_dns_txt()` only checks `v=mtc-ca1; fp=sha256:<hex>`
— it ignores nonces entirely. The v=mtc-ca2 token fields are client-side
theater that the server never verifies.

### Security Principles

1. **Server-side state is the authority.** The server stores
   `(domain, fp, nonce, expiry)` when it issues the nonce and verifies
   against that state — not against anything in the DNS record.
2. **A plain hash in the DNS record does NOT provide integrity.** An attacker
   who can modify the record can recompute any hash. No `tok` field.
3. **`exp` in the DNS record is informational for humans only.** The server
   checks expiry from its own stored state, not from the record.
4. **`fp` = SHA-256(SubjectPublicKeyInfo)** — the standard SPKI fingerprint.

### Policy

1. Reject concurrent duplicate requests (same domain+fp)
2. Require a fresh server-issued nonce (256-bit CSPRNG)
3. Server stores `(domain, fp, nonce, expiry)` — this is the binding
4. **Single-use** — mark nonce as consumed on success, never accept again (prevents replay)
5. **Short lifetime** — 15 minutes default (limits attack window; DNS TXT records via API propagate fast enough)

### DNS TXT Record Format

```
_mtc-ca.example.com. IN TXT "v=mtc-ca2; fp=sha256:<hex>; n=<nonce>; exp=<ts>"
```

| Field | Purpose |
|-------|---------|
| `fp`  | Binds to this specific key (server verifies against stored state) |
| `n`   | Server-issued nonce (server verifies against stored state) |
| `exp` | Informational for humans (server uses its own stored expiry) |

No integrity hash. No signature. DNS placement proves domain control.
Server-side state proves everything else.

### Two-Phase Flow

```
Phase 1: Request Nonce
  Client → POST /enrollment/nonce { domain, public_key_fingerprint }
  Server → generates nonce, stores (domain, fp, nonce, expiry)
  Server → returns { nonce, expires, dns_record_name, dns_record_value }
  Server → rejects 409 if pending request already exists for domain+fp

Phase 2: Complete Enrollment
  Client → creates DNS TXT record with server-issued nonce
  Client → POST /certificate/request { ...existing fields, enrollment_nonce }
  Server → looks up nonce in pending state
  Server → verifies domain + fp match stored state, not expired, not consumed
  Server → queries DNS TXT to confirm record exists (proves domain control)
  Server → issues certificate, marks nonce consumed
```

### C Server Changes

**`mtc_store.h`** — Add pending nonce storage:

```c
#define MTC_MAX_PENDING_NONCES 256
#define MTC_NONCE_TTL_SECS     900    /* 15 minutes */
#define MTC_NONCE_HEX_LEN     64     /* 32 bytes = 64 hex chars (256-bit) */

typedef struct {
    char     domain[256];
    char     fp_hex[65];           /* sha256 of public key SPKI */
    char     nonce_hex[MTC_NONCE_HEX_LEN + 1];
    time_t   created;
    time_t   expires;
    int      consumed;             /* 1 = already used */
} MtcPendingNonce;
```

Functions:
- `mtc_store_create_nonce()` → 0 ok, -1 duplicate, -2 full
- `mtc_store_validate_nonce()` → 1 valid, 0 invalid
- `mtc_store_consume_nonce()` → marks nonce consumed
- `mtc_store_expire_nonces()` → compacts out expired/consumed entries

Persisted in PostgreSQL (Neon) — survives server restarts:

```sql
CREATE TABLE mtc_enrollment_nonces (
    nonce       TEXT PRIMARY KEY,          -- 64 hex chars (256-bit)
    domain      TEXT NOT NULL,
    fp          TEXT NOT NULL,             -- sha256 of SPKI
    expires_at  TIMESTAMPTZ NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | consumed | expired
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_nonce_domain_fp ON mtc_enrollment_nonces (domain, fp)
    WHERE status = 'pending';
```

- `create_nonce`: INSERT, reject if pending row exists for same domain+fp
- `validate_nonce`: SELECT WHERE nonce=? AND status='pending' AND expires_at > now(), verify domain+fp match
- `consume_nonce`: UPDATE SET status='consumed' WHERE nonce=?
- `expire_nonces`: UPDATE SET status='expired' WHERE expires_at <= now() AND status='pending' (run periodically or on each create)

**`mtc_http.c`** — New endpoint + modified validation:

- `POST /enrollment/nonce` → `handle_enrollment_nonce()` — issues nonce,
  returns exact DNS TXT record to create, rejects 409 on duplicate
- `validate_ca_dns_txt()` — add `expected_nonce` param; if non-NULL require
  v=mtc-ca2 format, verify nonce is present in record (actual validation is
  against server-side state — DNS query just proves domain control)
- `handle_certificate_request()` — extract `enrollment_nonce` from body,
  validate via store, consume on successful issuance

### Python Tool Changes

**`ca_dns_txt.py`** — Add `--nonce`, `--expiry`, `--server` args:
- `--server`: auto-fetch nonce from `/enrollment/nonce`
- `--nonce`+`--expiry`: use server-issued values directly
- Neither: generate locally (standalone/testing mode)

**`mtc_client.py`** — Add `request_enrollment_nonce(domain, fingerprint)` method.

**`main.py`** — Two-phase `cmd_enroll_ca()` for intermediate CAs:
1. Compute fingerprint
2. Call `client.request_enrollment_nonce(domain, fp)`
3. Print DNS TXT record to create
4. Prompt: "Add this DNS TXT record, then press Enter..."
5. Call `client.request_certificate()` with `enrollment_nonce`

Root CAs: skip nonce (no DNS validation, unchanged).

### File Summary

| File | Change |
|------|--------|
| `server/c/mtc_store.h` | `MtcPendingNonce` struct, 4 function decls |
| `server/c/mtc_store.c` | Implement 4 nonce functions via `mtc_db.c` |
| `server/c/mtc_db.c` | `mtc_enrollment_nonces` table DDL + CRUD queries |
| `server/c/mtc_http.c` | New `/enrollment/nonce` handler, modify DNS validation |
| `tools/python/ca_dns_txt.py` | Accept server-issued nonce via `--nonce`/`--server` |
| `tools/python/mtc_client.py` | Add `request_enrollment_nonce()` method |
| `tools/python/main.py` | Two-phase flow in `cmd_enroll_ca()` |

### Verification

1. `make -C mtc-keymaster/server/c` — builds clean with `-Werror`
2. Phase 1: `POST /enrollment/nonce` → returns nonce + DNS record
3. Duplicate rejection: same request → 409
4. Phase 2: `POST /certificate/request` with nonce → cert issued, nonce consumed
5. Replay: same nonce again → rejected (consumed)
6. `python3 ca_dns_txt.py --server localhost:8443 test-ca.crt` → fetches nonce, prints TXT record

---

## Appendix: Security Audit Findings

Results of a security review of the MTC keymaster protocol, server, and
client code. Findings are prioritized by severity.

### Critical — fix before any deployment

**S1. TOCTOU race in nonce consume — FIXED**
- **Location:** `mtc_http.c` (handle_certificate_request)
- **Issue:** `mtc_db_validate_nonce()` and `mtc_db_consume_nonce()` are
  separate DB calls. A concurrent request can reuse the same nonce between
  check and consume.
- **Fix:** Atomic `UPDATE mtc_enrollment_nonces SET status='consumed'
  WHERE nonce=$1 AND status='pending' AND expires_at > now() RETURNING nonce`
  in a single query. If zero rows updated, the nonce was invalid or already
  consumed.

**S2. Nonce fingerprint binding bypassed — FIXED**
- **Location:** `mtc_http.c:654` — passes `""` for `fp_hex`
- **Issue:** Leaf enrollment validates nonce by domain only, not the key
  fingerprint it was bound to at creation. An attacker with a nonce for
  key A can enroll key B for the same domain.
- **Fix:** Compute the leaf's SPKI fingerprint from `public_key_pem` and
  pass it to `mtc_db_validate_nonce()`. Require all three fields to match:
  nonce + domain + fingerprint.

**S3. Root CA bypass is client-controlled — FIXED**
- **Location:** `mtc_http.c:350-358`
- **Issue:** Any request with `"root_ca": true` in extensions skips DNS
  validation. The flag is client-controlled JSON — an attacker can enroll
  a CA for any domain without proving ownership.
- **Fix:** Remove the client-controlled `root_ca` flag. Determine root
  status server-side from the certificate's Basic Constraints pathlen
  (pathlen > 0 or pathlen absent = root; pathlen == 0 = intermediate).

**S4. DNS TXT parsing uses substring matching — FIXED**
- **Location:** `mtc_http.c:291-297` — `strstr()` for v=mtc-ca2 check
- **Issue:** Substring matching allows crafted TXT records to pass.
  An attacker can embed all three substrings in a single record in the
  wrong structure and still pass validation.
- **Fix:** Parse the TXT record by splitting on `;`, extract exact
  key=value pairs, and match fields individually.

### High — fix before production

**S5. `sprintf()` buffer overflow in nonce generation — FIXED**
- **Location:** `mtc_db.c:639`
- **Issue:** Unbounded `sprintf()` writes hex bytes. If `nonce_out` is
  smaller than 65 bytes, stack overflow occurs.
- **Fix:** Use `snprintf(nonce_out + i * 2, 3, "%02x", rand_bytes[i])`.

**S6. No `validity_days` validation — FIXED**
- **Location:** `mtc_http.c:607-609`
- **Issue:** Attacker can request certificates valid for 999999 days,
  negative days, or zero days.
- **Fix:** Clamp to 1–3650 (1 day to 10 years).

**S7. No fingerprint format validation — FIXED**
- **Location:** `mtc_http.c:492-495`
- **Issue:** `"sha256:abc"`, `"sha256:"`, or non-hex characters accepted.
- **Fix:** Require exactly 64 hex characters after the `sha256:` prefix.

**S8. No `key_algorithm` whitelist — FIXED**
- **Location:** `mtc_http.c:603-605`
- **Issue:** Any string accepted as `key_algorithm`, embedded in cert.
- **Fix:** Whitelist: EC-P256, Ed25519, ML-DSA-87, EC-P384.

**S9. Debug `printf()` leaking sensitive data — FIXED**
- **Location:** Multiple locations in `mtc_http.c`
- **Issue:** Fingerprints, DNS record contents, PEM lengths visible in
  stdout. Should use `LOG_DEBUG` with appropriate log levels.
- **Fix:** Replace `printf("[ca-validate]...")` with `LOG_DEBUG(...)`.

**S10. `sscanf()` hex parsing without error check — FIXED**
- **Location:** `ssl_mtc.c:589-599` (`mtc_hex_to_bytes`)
- **Issue:** `sscanf("%2x")` returns 0 on non-hex input, leaving the
  byte uninitialized. Invalid proofs or signatures silently accepted.
- **Fix:** Check `sscanf()` return value == 1, return -1 on failure.

**S11. Subject not matched to nonce domain — FIXED**
- **Location:** `mtc_http.c` (handle_certificate_request)
- **Issue:** Leaf can claim any `subject` with a valid nonce. The nonce
  is bound to a domain at creation, but the enrollment doesn't verify
  that `subject` matches that domain.
- **Fix:** Extract domain from subject, match against the nonce's stored
  domain.

### Medium

**S12. Inclusion proof missing bounds check — FIXED**
- **Location:** `ssl_mtc.c:500-527` (`mtc_verify_inclusion`)
- **Issue:** No check that `index >= start` and `index < end`.
- **Fix:** Add bounds validation before proof computation.

**S13. CA private key stored unencrypted in Neon — MITIGATED**
- **Location:** `mtc_store.c` — `ca_private_key_hex` in `mtc_ca_config`
- **Issue:** The Ed25519 CA private key is stored as plaintext hex in
  PostgreSQL. Database compromise exposes the key.
- **Fix:** Consider key management service, or at minimum encrypt the
  key at rest with a passphrase.

**S14. Python urllib TLS — no cert pinning — FIXED**
- **Location:** `mtc_client.py:43-55`
- **Issue:** Relies on system CA store. No pinning to the MTC server's
  specific certificate.
- **Fix:** Add explicit SSL context with cert pinning for the MTC server.

**S15. No HTTP security headers — FIXED**
- **Location:** `mtc_http.c` (http_send_json)
- **Issue:** Missing CORS, X-Content-Type-Options, X-Frame-Options.
- **Fix:** Add security headers to all responses.

**S16. AbuseIPDB IP spoofing behind proxy — MITIGATED**
- **Location:** `mtc_http.c:1380-1400`
- **Issue:** `getpeername()` returns proxy IP, not client IP, when behind
  a reverse proxy.
- **Fix:** Document direct-connection requirement, or support trusted
  proxy headers (`X-Real-IP`) from a configured trusted proxy.

### Low

**S17. `atoi()` without overflow check — FIXED** on path parameters.

**S18. Content-Length truncation — FIXED** — large bodies silently truncated.

**S19. Nonce TTL 15 min** — could be reduced to 5 min for tighter window.

**S20. No rate limiting on API endpoints — FIXED** — `/enrollment/nonce` and
`/certificate/request` can be flooded. (Noted — deferred per design.)

### TODO: ECH support in MTC mode

**Priority:** Medium

ECH (Encrypted Client Hello) is currently disabled when using MTC certificates
(`slc.c` skips ECH auto-fetch in MTC mode). The ECH auto-fetch connects to the
peer's port to `GET /ech/configs`, which steals the server's `accept()` call.

**Fix:** Fetch ECH configs from the MTC server's HTTP port (8444) which serves
`/ech/configs`, or use a cached config from `~/.TPM/ech/<host>.conf`, instead
of connecting to the peer's TLS port. This avoids the stale connection issue
while still providing SNI encryption.

### TODO: Reduce Certificate message size — send proof, not full key

**Priority:** High — key benefit of MTC for post-quantum

Currently `ssl_mtc.c` builds a synthetic X.509 cert containing the full
public key SPKI (~2.6KB for ML-DSA-87) plus the MTC proof. The entire thing
is sent in the TLS Certificate message. This defeats a key advantage of MTC:
the ability to avoid sending large post-quantum public keys on every handshake.

**Ideal flow:**
1. Sender includes only cert\_index + Merkle proof in the Certificate message
2. Receiver looks up the public key hash from the transparency log by index
3. Receiver verifies the Merkle inclusion proof against the log's root hash
4. Receiver fetches the actual public key from the MTC server (or local cache)
   to verify the CertificateVerify signature

**Approaches:**
- **On-demand fetch:** Peer fetches public key from MTC server during handshake.
  Adds latency but dramatically reduces wire size.
- **Pre-cached keys:** Peers cache public keys of known peers in `~/.TPM/peers/`.
  Zero latency for repeat connections.
- **Trust anchor pre-distribution:** MTC draft Section 7 — relying parties
  pre-cache landmark subtree hashes and frequently-used public keys.

This requires changes to `ssl_mtc.c` (build a smaller cert DER with just the
proof) and `internal.c` (fetch public key during ProcessPeerCerts if not
present in the cert).

**How Merkle solves this:**
1. Peer sends only cert\_index + Merkle proof in the Certificate message
2. Receiver verifies the proof against the log's root hash — now trusts
   that cert\_index is legitimate and the `subject_public_key_hash` is authentic
3. Receiver fetches the full public key from the MTC server:
   `GET /certificate/<index>` (one HTTP call)
4. Receiver hashes the fetched key, confirms it matches the hash in the
   verified proof
5. Receiver uses the key to verify CertificateVerify

For repeat connections, cache the peer's public key in `~/.TPM/peers/<index>/`
and skip step 3. First connection costs one HTTP fetch; every subsequent
connection is zero extra round trips and zero extra bytes on the wire.

This is the core MTC advantage for post-quantum — 2.6KB ML-DSA-87 keys
don't bloat every TLS handshake.

**Key insight:** If both peers are enrolled in the same MTC log, no public
key ever needs to go over the wire. Each side sends only a cert\_index
(an integer). The receiver looks up the peer's public key from the
transparency log. The current implementation only sends the full key
because we're shoehorning MTC into TLS's X.509 Certificate message
format, which expects an embedded public key. Removing that constraint
is the fix.

### TODO: Pure MTC Protocol — Replace TLS with ML-KEM + Merkle (Phase 2)

**Priority:** High — this is the target architecture

Replace the wolfSSL TLS 1.3 handshake in MTC mode with a pure
post-quantum protocol. No TLS. No X.509. No public keys on the wire.

**Connection overview:**

```
Step  Direction         Content                        Encryption
----  ---------         -------                        ----------
1.    Client → Server   ML-KEM encaps key +            plaintext
                        X25519 public key
2.    Server → Client   ML-KEM ciphertext +            plaintext
                        X25519 public key + salt
      [Both derive shared secret:
       ML-KEM decapsulation + X25519 agreement
       combined via HKDF(mlkem_ss || x25519_ss, salt, "mtc-slc-connect")]
3.    Client → Server   {"cert_index": 72}          encrypted
4.    Server → Client   {"cert_index": 73}          encrypted
      [Both verify peer: cache or fetch from MTC server,
       verify Merkle proof + cosignature, check revocation]
5.    Client → Server   {"status": "verified"}      encrypted
6.    Server → Client   {"status": "verified"}      encrypted
      [Authenticated encrypted channel established]
7.    Application data  slc_read / slc_write        encrypted
```

**What goes over the wire:**
- ML-KEM + X25519 keys: ~2KB (key exchange)
- Cert indices: ~100 bytes (two integers, encrypted)
- Status: ~60 bytes (encrypted)
- **No public keys. No certificates. No X.509. No TLS.**
- Compare to current: ~6KB (ML-DSA-87 key + X.509 + TLS handshake)

**Key exchange:** Hybrid ML-KEM + X25519 (post-quantum resistant).
ML-KEM provides quantum resistance; X25519 is belt-and-suspenders.

**Authentication:** Each side looks up the peer's cert\_index in the
Merkle transparency log, verifies the inclusion proof + Ed25519
cosignature, checks revocation and validity. Public key fetched from
the MTC server on first contact, cached in `~/.TPM/peers/<index>/`
for subsequent connections.

**Encryption:** All post-handshake traffic encrypted with the ML-KEM
derived shared secret using AES-256-GCM.

**SLC API unchanged:** `slc_connect` / `slc_accept` / `slc_read` /
`slc_write` / `slc_close` — callers don't know the underlying protocol.
`mtc_store` in `slc_cfg_t` selects MTC mode vs traditional TLS.

**Building blocks already exist:**
- ML-KEM: `WOLFSSL_HAVE_MLKEM` + `WOLFSSL_PQC_HYBRIDS` compiled in
- X25519: `wolfssl/wolfcrypt/curve25519.h`
- HKDF: `wolfssl/wolfcrypt/hmac.h`
- AES-GCM: `wolfssl/wolfcrypt/aes.h`
- Merkle verification: `wc_MtcVerifyInclusionProof()`, `wc_MtcVerifyCosignature()`
- Length-prefixed I/O: from bootstrap code
- MTC server fetch: `GET /certificate/<n>`, `GET /log/checkpoint`, `GET /revoked/<n>`

#### Implementation Plan

**Files to modify:**

1. **`socket-level-wrapper/slc.c`** — Major rewrite for MTC mode:
   - New: `slc_mtc_handshake_client(ctx, fd)` — ML-KEM+X25519 exchange,
     send cert\_index, receive peer index, verify peer, key confirmation
   - New: `slc_mtc_handshake_server(ctx, fd)` — same, reversed
   - New: `slc_mtc_verify_peer(ctx, cert_index)` — fetch/cache peer cert,
     verify Merkle proof + cosignature + revocation + validity
   - New: `slc_mtc_fetch_cert(ctx, cert_index)` — HTTP GET from MTC server,
     cache in `~/.TPM/peers/<index>/`
   - New: `slc_mtc_fetch_checkpoint(ctx)` — HTTP GET checkpoint, cache with TTL
   - Modified: `slc_connect()` — if MTC: TCP connect + `slc_mtc_handshake_client()`
   - Modified: `slc_accept()` — if MTC: TCP accept + `slc_mtc_handshake_server()`
   - Modified: `slc_read()` — if MTC: `recv` + AES-GCM decrypt
   - Modified: `slc_write()` — if MTC: AES-GCM encrypt + `send`
   - Modified: `slc_close()` — if MTC: close socket + free crypto (no wolfSSL)
   - Remove: `wolfSSL_CTX_use_MTC_certificate()` call, `wolfSSL_MTC_AddCosigner()`,
     all X.509 MTC shim code

2. **`socket-level-wrapper/slc.h`** — No public API changes.
   Same `slc_connect/accept/read/write/close`. `mtc_store` in `slc_cfg_t`
   selects MTC mode vs traditional TLS.

3. **`socket-level-wrapper/Makefile`** — Add `mtc_crypt.c` dependency,
   keep wolfSSL for ML-KEM, X25519, HKDF, AES-GCM, Merkle verification.

4. **`socket-level-wrapper/examples/echo_server.c`** and **`echo_client.c`** —
   Update to use pure MTC mode. Should work with just `--mtc ~/.TPM/<domain>`.

**struct slc_conn changes:**
```c
struct slc_conn {
    WOLFSSL *ssl;           /* NULL in MTC mode */
    int      fd;
    int      mtc_mode;      /* 1 = pure MTC protocol */
    MtcCryptCtx *crypt_ctx; /* AES encrypt/decrypt context */
    int      peer_index;    /* peer's cert_index after handshake */
};
```

**Peer cache layout:**
```
~/.TPM/peers/<cert_index>/
    certificate.json     # full standalone cert from MTC server
    checkpoint.json      # tree state at time of verification
```

**Verification steps:**
1. `wc_MtcVerifyInclusionProof()` — leaf is in the tree
2. `wc_MtcVerifyCosignature()` — Ed25519 cosignature valid
3. `GET /revoked/<index>` — not revoked
4. `not_before <= now <= not_after` — not expired

---

## Appendix: Signed Key Exchange Protocol (Final Design)

### Problem

ML-DSA-87 is a signature algorithm — it proves identity but can't
encrypt or exchange keys. Two MTC-enrolled nodes need both
authentication AND a shared secret for encryption.

### Solution: Signed Ephemeral Key Exchange

Combine key exchange and authentication in a single round trip.
Each side signs its ephemeral key exchange material with its
ML-DSA-87 private key. The other side verifies using the peer's
public key from the Merkle transparency log.

### Protocol (1 round trip)

```
NodeA → NodeB:
  {
    "cert_index": 72,
    "mlkem_encaps_key": "<hex>",     # ephemeral ML-KEM public key
    "signature": "<hex>"             # ML-DSA-87 signature over mlkem_encaps_key
  }

NodeB → NodeA:
  {
    "cert_index": 73,
    "mlkem_ciphertext": "<hex>",     # ML-KEM encapsulation result
    "signature": "<hex>"             # ML-DSA-87 signature over mlkem_ciphertext
  }
```

### What Each Side Does

**NodeA (initiator):**
1. Generate ephemeral ML-KEM keypair
2. Sign the ML-KEM encaps key with own ML-DSA-87 private key
3. Send cert\_index + encaps key + signature
4. Receive NodeB's cert\_index + ciphertext + signature
5. Look up NodeB's public key (cache or MTC server fetch + Merkle verify)
6. Verify NodeB's signature over the ciphertext
7. ML-KEM decapsulate → shared secret
8. Derive AES-256-GCM key from shared secret

**NodeB (responder):**
1. Receive NodeA's cert\_index + encaps key + signature
2. Look up NodeA's public key (cache or MTC server fetch + Merkle verify)
3. Verify NodeA's signature over the encaps key
4. ML-KEM encapsulate with NodeA's encaps key → ciphertext + shared secret
5. Sign the ciphertext with own ML-DSA-87 private key
6. Send cert\_index + ciphertext + signature
7. Derive AES-256-GCM key from shared secret

### Security Properties

- **Authentication:** Both sides prove identity by signing with their
  ML-DSA-87 private key. Signatures verified against Merkle-authenticated
  public keys from the transparency log.
- **Confidentiality:** ML-KEM shared secret → AES-256-GCM for all traffic.
  Post-quantum resistant.
- **No replay:** Ephemeral ML-KEM keys are fresh per connection.
- **No MITM:** Attacker can't forge ML-DSA-87 signatures without the
  private keys. Can't substitute their own ML-KEM keys because the
  signatures wouldn't verify.
- **No public keys on the wire:** Only cert\_index integers. Public keys
  resolved from the Merkle tree.
- **1 round trip:** Authentication + key exchange in a single message
  each direction. Compare to TLS 1.3: 1-2 round trips with full cert.

### Peer Key Resolution

When you receive a cert\_index you haven't seen before:
1. Check `~/.TPM/peers/<index>/certificate.json` (local cache)
2. If miss: `GET /certificate/<index>` from MTC server (factsorlie.com:8444)
3. Verify Merkle inclusion proof: `wc_MtcVerifyInclusionProof()`
4. Verify cosignature: `wc_MtcVerifyCosignature()`
5. Check `GET /revoked/<index>` — reject if revoked
6. Check `not_before <= now <= not_after` — reject if expired
7. Extract `subject_public_key_hash` from the verified proof
8. Fetch full public key, hash it, confirm matches
9. Cache in `~/.TPM/peers/<index>/` for next time
10. Use the public key to verify the peer's signature

Subsequent connections to the same peer: step 1 hits cache, skip 2-9.

### Security Analysis

**MITM (Man in the Middle): SAFE.**
Attacker intercepts NodeA's message and substitutes their own ML-KEM key.
But they can't sign it with NodeA's ML-DSA-87 private key — NodeB rejects
the forged signature. The attacker would need to compromise the private
key, which never leaves the node.

**Replay attack: SAFE.**
ML-KEM encaps key is ephemeral — fresh every connection. Replaying an
old message gives an old encaps key, but the attacker can't derive the
shared secret without the corresponding ephemeral private key (destroyed
after use).

**Impersonation: SAFE.**
Requires the victim's ML-DSA-87 private key to sign. The Merkle tree
binds the public key to the cert\_index — can't substitute a different
key because the hash wouldn't match the logged entry.

**Compromised MTC server: PARTIALLY SAFE.**
The server could return a fake certificate for a cert\_index, but the
Merkle inclusion proof and cosignature would fail verification. The
server can't forge the Ed25519 cosignature without the CA's private key.
However, if BOTH the MTC server AND the CA cosigning key are compromised,
a fake cert could be injected.

**Denial of service: VULNERABLE.**
An attacker could flood connection attempts, forcing the responder to do
expensive ML-KEM + ML-DSA operations. Rate limiting helps but PQ
operations are inherently slower than classical ones.

**Downgrade attack: NOT APPLICABLE.**
Only one protocol version. No TLS version negotiation to downgrade.

**Cache poisoning: LOW RISK.**
Possible if an attacker can write to `~/.TPM/peers/`. But that requires
local filesystem access, which is game over regardless.

**Harvest now, decrypt later: SAFE.**
ML-KEM is post-quantum — recorded traffic can't be decrypted later by
a quantum computer.

### Protocol Name: MQC (Merkle Quantum Connect)

The signed key exchange protocol described above is named **MQC** —
Merkle Quantum Connect. Merkle-based authentication + quantum-resistant
encryption. Distinct from TLS. Enabled via `--enable-mqc` or
`cfg.mtc_store` in the SLC API.

Usage: "Should we enable MQC when we rebuild postWolf?"

**Metadata leakage: PARTIAL WEAKNESS.**
The initial messages (step 1-2) are plaintext. An eavesdropper sees the
cert\_index values, revealing who is connecting to whom (traffic analysis).
**Fix:** Send cert\_index in an encrypted follow-up message after the
ML-KEM shared secret is established. Costs an extra half round trip but
hides peer identities from passive observers. Consider for high-security
deployments.
