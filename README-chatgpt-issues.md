I reviewed the uploaded `s2.tar.gz`. Priority fixes:

## P0 — fix before exposing this server

1. **Replace `mtc_crypt.c` entirely** — **DONE 2026-05-06 (commit `265178701`)**

   * `mtc_crypt.{c,h}` rewritten as AES-256-GCM AEAD with
     random 96-bit nonces, per-direction keys (c2s/s2c), and
     28-byte AAD binding label + direction + plaintext length.
   * Byte-rotation, find-last-`}` padding strip, and zero-IV
     all gone.  Flag-day cutover; both factsorlie and
     frflashy deployed.
   * See appendix below for the cross-host verification trace.

2. **Add authentication to the DH bootstrap handshake** — **DONE 2026-05-06 (TODO #63)**

   * Step 2 now carries `transcript_sig` (ML-DSA-87 over both DH pubkeys || salt || pop_nonce || version) under the cosigner key, plus `ca_cosigner_pem` so the client can verify without a prior fetch.
   * Client aborts BEFORE deriving AEAD keys on any signature/fingerprint mismatch.
   * See appendix below + TODO #63 in `mtc-keymaster/README-bugsandtodo.md`.

3. **Stop issuing leaf nonces to anyone who merely names an existing CA domain** — **DONE 2026-05-06 (commit `6ec344bf1`)**

   * `POST /enrollment/nonce` for leaf now requires MQC peer-cert auth AND the peer's subject == `<domain>-ca` for the requested domain.
   * See appendix below + TODO #64 in `mtc-keymaster/README-bugsandtodo.md`.
   * Original "any internet client" framing was wrong on this deployment (8444 is localhost-only, 8446 needs MQC handshake); the real exploitable path was cross-CA leaf hopping by in-log peers — also blocked.

4. **Remove late-bind reservation nonces or strongly constrain them** — **BY DESIGN, filed as TODO #73**

   * Real concern: a leaked reservation nonce is a bearer token (any holder can bind their own fp to the slot at consume time).
   * Both proposed fixes (require fp at issue / require CA-signed consume approval) break the team-onboarding workflow the feature exists to support.
   * Documented as BY-DESIGN with mitigations in place: TTL ≤ 30 days, unique `(domain, label)` slot, MQC-authenticated cancel-nonce, post-#64 cross-CA hopping blocked.  See TODO #73 in `mtc-keymaster/README-bugsandtodo.md` for full rationale + future-fix sketch.

## P1 — high priority

5. **Bootstrap fork loop lacks child backpressure/reaping** — **DONE 2026-05-06 (TODO #65)**

   * `mtc_bootstrap.c::bootstrap_thread` now calls
     `mtc_wait_for_child_slot("bootstrap")` before `accept()`
     and `mtc_register_active_child()` after `fork()`.
   * Verified live with 25 parallel real bootstraps hitting
     the 20-child cap.

6. **HTTP parser can slow-loris** — **DONE 2026-05-06 (TODO #66)**

   * `handle_request` now sets `SO_RCVTIMEO =
     MTC_HTTP_READ_STALL_SEC` (default 10 s) on the accepted
     socket BEFORE entering the read loop, gated to non-MQC
     transports.  Idle connections drop at t≈10 s; healthy
     requests are unchanged.
   * Knob: `mtc-keymaster/server2/c/config.h`.

7. **Plain HTTP mode can expose write endpoints** — **DONE 2026-05-06**

   * Combination of TODO #64 (MQC-gate the cross-CA leaf-nonce
     path; the only real gap once the rest were already
     MQC-only or payload-signed) and the new
     `url-local-port-disabled = Yes` knob (default Yes —
     port 8444 stays closed entirely on this deployment).
   * See appendix item 7 below for verification trace.

8. **`http_get` proxy on bootstrap exposes arbitrary GET dispatcher over plaintext** — **DONE 2026-05-06** (TODO #67)

   * Static allowlist in `bootstrap_path_allowed`; mirrors
     `dispatch_get` exactly (read-only public endpoints only).
     Anything else dropped.
   * See appendix item 8 below for the verification trace.

## P2 — correctness / hardening

9. **Label is stored "verbatim"** — **DONE 2026-05-06** (TODO #68)

   * `mtc_canonicalize_label` in `mtc_domain.{c,h}` (charset
     `[A-Za-z0-9._-]`, length 1..64, rejects `.` / `..` /
     leading `-` / leading `.`); `handle_enrollment_nonce`
     calls it before `mtc_db_create_nonce`.
   * See appendix item 9 below for the verification trace.

10. **Persistence failures after in-memory success are not fatal everywhere** — **DONE 2026-05-06** (TODO #69)

* `mtc_db_save_certificate` / `mtc_db_save_public_key`
  failures now LOG_ERROR + drop the in-memory cert at
  `store->certificates[index]` + free local state +
  `goto cleanup` (connection drop).  Client retry hits the
  TODO #57 idempotency path.
* See appendix item 10 below for the full trace.

11. **Custom canonical JSON signing is fragile** — **DONE 2026-05-06** (TODO #70)

* Replaced canonical-JSON signing with a fixed binary
  transcript (option B from the design discussion: matches
  the MQC handshake / DH bootstrap idiom).  ctx label bumped
  v1 → v2 for domain separation.
* See appendix item 11 below for the wire format + live
  bootstrap_leaf round-trip trace.

12. **CA X.509 `NO_VERIFY` is deliberate, but document it loudly**

* Your DNSSEC SPKI pin + PoP signature mostly compensates. Still, this is nonstandard and future maintainers may misuse the cert as a real X.509 trust object.
* File: `mtc_ca_validate.c:37-75`.

## Best first patch sequence

1. Replace `mtc_crypt` with AEAD.
2. Sign the bootstrap DH transcript.
3. Require CA-authenticated leaf nonce issuance.
4. Disable late-bind nonce consumption.
5. Add bootstrap child backpressure.
6. Add HTTP read timeouts and reject sensitive POSTs on plain transport.


---

# Appendix: Triage 2026-05-06 (phase-25, HEAD `8d1808c60`)

Each finding cross-checked against current source.  Verdicts use
this scale:

- **OPEN** — finding matches current code; warrants a TODO.
- **PARTIAL** — partially mitigated since the review; residual
  risk warrants follow-up.
- **CLOSED** — already fixed by post-review work.
- **BY DESIGN / DOC** — current behavior is the documented
  trade-off; risk is acknowledged.

Every commit reference points to the postWolf repo; line numbers
reflect HEAD.

## P0

### 1. Replace `mtc_crypt.c` (AES-CBC zero-IV no-MAC) — **DONE 2026-05-06** (commit `265178701`)

Closed.  `mtc_crypt.{c,h}` rewritten as AES-256-GCM AEAD.

Wire format per AEAD frame:
`[12-byte nonce][N-byte ciphertext][16-byte GCM tag]`.
AAD binds `"mtc-bootstrap-aead/v1\n"` + direction byte +
plaintext_length BE — so a MitM cannot replay a request frame
as a response (different direction → different AAD → tag fails).

HKDF call extended to produce 64 bytes (c2s_key || s2c_key).
Per-direction keys eliminate any GCM nonce-reuse risk across
directions.  Random 96-bit nonces per message; collision
probability negligible within a single short DH session.

Removed dead code:
- byte-rotation layer (pure obfuscation)
- "find last `}`" padding strip (GCM doesn't pad)
- bit-7 noise padding (same)

Verified: localhost AEAD round-trip on factsorlie + cross-host
register-leaf from frflashy after deploying the new code.

### 2. Sign the bootstrap DH transcript — **DONE 2026-05-06** (TODO #63)

Closed.  Step 2 of the DH-bootstrap flow now carries three
new fields: `protocol_version`, `ca_cosigner_pem`, and
`transcript_sig`.

`transcript_sig` is ML-DSA-87 over the 113-byte transcript:

```
client_dh_pub_raw (32) || server_dh_pub_raw (32) ||
salt              (16) || pop_nonce         (32) ||
version_byte       (1)
```

Bidirectional binding means a MitM substituting EITHER DH key
invalidates the signature.  The client verifies the embedded
PEM's fingerprint against its known cosigner pin (DNSSEC for
CA branch, operator-paste for leaf branch) BEFORE running
ML-DSA verify under that PEM, then verifies the transcript_sig
BEFORE deriving any AEAD keys.  Failure aborts step 2 with
`step-2 COSIGNER_FP_MISMATCH` or `BOOTSTRAP_DH_TRANSCRIPT_INVALID`
— enrollment-request bytes never leak.

Verified live with three tests on factsorlie:
  T1 `--no-pin`: SKIPPED (localhost only)
  T2 correct fp: VERIFIED, enrollment OK
  T3 wrong fp: COSIGNER_FP_MISMATCH at step 2

### 3. Stop issuing leaf nonces to anyone — **DONE 2026-05-06** (TODO #64)

Originally filed as HIGH, re-scoped to Medium after operator
clarified that port 8444 is localhost-only and port 8446
requires an MQC peer-cert handshake — the attacker had to
already be in the log as some leaf or CA, exploitable path was
**cross-CA leaf hopping** (a legitimate leaf of `domain-A.com`
MQC-connects, requests a leaf nonce for `domain-B.com`, gets
one because the server checked only "does a CA exist for B?",
ends up holding a valid leaf cert for B in addition to A).

**Resolution:** `mtc_http.c::handle_enrollment_nonce` now
requires for any `type=leaf` request: (a) MQC transport AND
(b) the peer's subject == `<domain>-ca` exactly.  CA-type
nonces stay open (auth at consume time via DNSSEC TXT).
Plain HTTP returns `403 leaf nonce issuance requires MQC
peer-cert auth`; an MQC peer that's not the CA for the
requested domain returns `403 only the CA for this domain
may mint leaf nonces`.

Spec (§§3.2 + 5.1 of
`mtc-keymaster/server2/README-detail-design-spec.md`) updated
— the previous "the nonce IS the auth token" rationale is
gone.

Verified live with six tests on factsorlie + frflashy:

  T1: HTTP curl from localhost (no MQC) → 403 ✓
  T2: factsorlie-ca → factsorlie leaf → OK ✓
  T3: factsorlie LEAF → factsorlie leaf → 403 ✓
  T4: factsorlie-ca → frflashy leaf → 403 ✓
  T5: frflashy-ca → frflashy leaf → OK ✓
  T6: frflashy-ca → factsorlie leaf → 403 ✓

Cross-CA hopping is blocked from both directions; the
legitimate `issue_leaf_nonce` workflow on each box is
unchanged.

Implementation: commit `6ec344bf1`, mirror of the same
`io->mqc` + `mqc_get_peer_index` gate `/cancel-nonce` already
uses.  ~30 lines added to handle_enrollment_nonce.

### 4. Late-bind reservation nonces — **PARTIAL / BY DESIGN**

Reservation nonces (fp=NULL, label-bound) are deliberate — they
support the team-onboarding flow ("CA pre-provisions Alice
without knowing her fingerprint", see deleted
`README-leaf-registration.md` content now in
`README-detail-design-spec.md` §3.2).  ChatGPT's point: a leaked
reservation nonce is a bearer token; whoever has it can bind
their own fp at consume time.

Today's mitigations:

- Operator-tunable TTL (`MTC_NONCE_MAX_TTL_DAYS` clamps at 30 days).
- Unique `(domain, label)` partial index — only one pending
  reservation per slot.
- `cancel-nonce` MQC tool retracts a reservation early.
- Documented as a "high-value secret transmit via secure OOB
  channel".

ChatGPT's threat model is a leaked nonce + ahead-of-Alice
attacker.  Mitigation gap: the CA has no real-time visibility
into consumption; an attacker who consumes before Alice gets to
her box wins (Alice's later attempt fails with `409 Conflict` or
"already consumed", at which point the CA cancels and re-issues).

**Recommendation:** combined fix with TODO #64.  If
`/enrollment/nonce` is MQC-gated by the CA, add a parallel
"leaf bootstrap consumed your reservation" notification path so
the CA learns at consume-time and can compare against the
expected Alice IP / time window.  Lower priority than #64
itself; reservation mode is a real feature, not a bug.

## P1

### 5. Bootstrap fork lacks backpressure — **DONE 2026-05-06** (TODO #65)

`mtc_bootstrap.c::bootstrap_thread` now calls
`mtc_wait_for_child_slot("bootstrap")` before `accept()` and
`mtc_register_active_child()` in the parent after `fork()`.
The same global `g_active_children` counter the HTTP/MQC
listeners share now covers the bootstrap path too.

Helpers exposed in `mtc_http.h` (previously file-static).  The
SIGCHLD reaper was already decrementing on exit; the missing
piece was the matching increment for the bootstrap path.

Verified: 25 parallel `bootstrap_ca --no-pin` calls hit the
20-child cap and the listener logged `bootstrap backpressure:
20/20 active children, sleeping before accept` repeatedly
until earlier children drained.

### 6. HTTP slow-loris — **DONE 2026-05-06** (TODO #66)

`handle_request` now sets `SO_RCVTIMEO =
MTC_HTTP_READ_STALL_SEC` (default 10 s) on `io->fd` before
entering the read loop, gated to `!io->mqc` so MQC's own
handshake-deadline machinery isn't clobbered.  The knob lives
next to `MTC_BOOTSTRAP_READ_STALL_SEC` in
`mtc-keymaster/server2/c/config.h`.

After 10 s of silence `recv` returns `-1/EAGAIN`, the read
loop exits, and the forked worker terminates — freeing the
active-child slot that `mqc-max-children` accounts.

Verified live on factsorlie: idle TLS connect dies at t≈10.6 s;
partial headers cause a clean dispatch at t≈10.7 s; healthy
sub-second requests are unchanged.

### 7. Plain HTTP exposes write endpoints — **DONE 2026-05-06**

Two layers of closure:

1. **TODO #64** (cross-CA leaf-nonce gate) shrank the residual
   surface to: `/cancel-nonce` and `/renew-cert` already
   MQC-only; `/revoke` payload-signed under the CA key
   (transport-agnostic auth).
2. **`url-local-port-disabled = Yes`** (new config knob,
   default Yes) — the local TLS HTTP listener (port 8444)
   now stays closed entirely on this deployment.  Nothing on
   factsorlie talks to 8444 over the network: every C client
   speaks MQC on 8446, the bootstrap port serves its own
   traffic on 8445, and the bootstrap port's `http_get`
   proxy hits `dispatch_get` in-process (no socket).
   Operators with Python tooling that hits the TLS API can
   flip the knob to `No`.

Verified live: `ss -tlnp` shows only 8445 + 8446 bound; TCP
connect to 8444 returns "Connection refused".  MQC end-to-end
smoke (`issue_leaf_nonce`) still succeeds.

### 8. `http_get` proxy on bootstrap exposes GET dispatcher — **DONE 2026-05-06** (TODO #67)

`mtc_bootstrap.c::send_http_get_proxy` now consults a static
allowlist (`bootstrap_path_allowed`) before invoking
`mtc_http_dispatch_get_capture`.  Mirrors `dispatch_get`
exactly:

```
exact:  /log  /log/checkpoint  /trust-anchors  /revoked
        /ca/public-key  /ech/configs
prefix: /log/entry/  /log/proof/  /log/consistency
        /certificate/search  /certificate/
        /revoked/  /public-key/
```

Anything else logs `bootstrap: http_get rejected (path='X',
not in allowlist)` and drops.  Verified live: `/log/checkpoint`
and `/certificate/0` proxied normally; `/enrollment/nonce`,
`/../../etc/passwd`, `/admin` all rejected with no body
returned; `show-tpm --verify` (which legitimately uses the
proxy for `/revoked` + `/public-key/<name>`) still passes
end-to-end.

## P2

### 9. Server-side label canonicalization — **DONE 2026-05-06** (TODO #68)

`mtc_canonicalize_label` lives in `mtc_domain.{c,h}` next to
the existing `mtc_canonicalize_domain`.  Enforces charset
`[A-Za-z0-9._-]`, length 1..`MTC_LABEL_MAX` (=64), rejects
bare `.` or `..` and leading `-` / `.`.  Case is preserved
(labels are case-sensitive directory names client-side).

`handle_enrollment_nonce` calls it before passing the label
into `mtc_db_create_nonce`; rejection produces HTTP 400 with
a diagnostic.  19/19 unit tests pass on the helper; live MQC
smoke (`issue_leaf_nonce` / `cancel-nonce` with
`valid.label_9-mix`) still succeeds end-to-end.

### 10. Persistence-fail-after-success warnings — **DONE 2026-05-06** (TODO #69)

The post-enrollment persistence block in `mtc_bootstrap.c` now
fails closed.  On `mtc_db_save_certificate` or
`mtc_db_save_public_key` non-zero return:

- `LOG_ERROR` with full context.
- `json_object_put(store->certificates[index])` + NULL out the
  slot.
- Free local enrollment state (`result`, `tbs`, `checkpoint`,
  `proof`, `entry_buf`) and `goto cleanup` — the connection
  drops, client sees EOF, retry hits the TODO #57 idempotency
  path.

The committed Merkle log entry is left in place — un-appending
cross-fork isn't possible — so a save_certificate failure
costs one wasted log slot.  Same trade-off TODO #57 item 4
made for log-entry-write failures.  Operator can run
`backfill-pubkey` if `save_public_key` repeatedly fails after
`save_certificate` succeeded.

### 11. Custom canonical JSON signing fragile — **DONE 2026-05-06** (TODO #70)

`add_cosigner_sig_to_response` (and its leaf+CA verifiers) now
sign a fixed binary transcript, not a json-c canonical
serialization.  New module
`mtc-keymaster/server2/c/mtc_bootstrap_transcript.{c,h}` is
linked into both `mtc_server` and the operator tools
(`bootstrap_ca`, `bootstrap_leaf`) so signer and verifier walk
the parsed JSON identically.

Wire format (all multi-byte ints big-endian):
```
[u8:  version = 0x02]
[u32: cosigner_pem_len][cosigner_pem_bytes]
[u32: index]
[u32: subject_len][subject_bytes]
[u32: spk_hash_len][spk_hash_bytes]
[u32: spk_algo_len][spk_algo_bytes]
[u64: not_before_unix]
[u64: not_after_unix]
[u32: label_len][label_bytes]
```

ctx label bumped from `mtc-bootstrap/v1\n\x00` to
`mtc-bootstrap/v2\n\x00` so a v1 signature can never be
confused with a v2 signature.  Per CLAUDE.md "MQC wire-format
invariants are NOT operator-tunable" + project memory
`project_mqc_no_backwards_compat`: server + clients rebuilt
and redeployed together, no fallback path.

Same idiom as the MQC handshake transcript and the DH
bootstrap transcript (TODO #63): no canonical-JSON contract,
no float-format dependency, no Unicode quirks, no library
version coupling.

Verified live on factsorlie: real `bootstrap_leaf` round-trip
(fresh ML-DSA-87 keypair, reservation nonce, cert issued at
index 80) — DH transcript signature verified, response
signature verified under cosigner PEM.

### 12. CA X.509 NO_VERIFY — **DOC**

ChatGPT acknowledges this is deliberate (the X.509 wrapper is
parser-bait, not a real trust object — postWolf trusts the
DNSSEC-pinned SPKI fingerprint + PoP signature).  Comment in
`mtc_ca_validate.c:37-75` already documents it; a clearer
warning header would help future readers avoid mis-using the
cert.

**Recommendation:** open as TODO #71, LOW.  Three-line
"DO NOT TRUST THIS CERT AS X.509" banner at the top of
`mtc_ca_validate.c` and in §4.3 of the design spec.  Done.

## Recommended attack queue

Prioritized by impact-per-effort against the current code.
TODOs closed 2026-05-06: #62, #63, #64, #65.  Remaining:

1. **TODO #69** — fail-closed on persistence errors during
   enrollment.  Local-only change in `mtc_bootstrap.c`.
2. **TODO #68** — server-side label canonicalization.
   Local-only.
3. **TODO #66** — HTTP read timeout (`SO_RCVTIMEO`).
   Local-only.
4. **TODO #67, #70, #71** — defense-in-depth / hygiene.
