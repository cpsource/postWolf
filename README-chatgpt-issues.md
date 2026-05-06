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

2. **Add authentication to the DH bootstrap handshake**

   * Server DH public key is plaintext and unsigned. A MITM can substitute DH keys, even if later response signing limits some damage.
   * Fix: sign the server’s ephemeral DH public key, salt, nonce, protocol version, and transcript with the cosigner key, or run bootstrap over MQC/TLS.

3. **Stop issuing leaf nonces to anyone who merely names an existing CA domain** — **DONE 2026-05-06 (commit `6ec344bf1`)**

   * `POST /enrollment/nonce` for leaf now requires MQC peer-cert auth AND the peer's subject == `<domain>-ca` for the requested domain.
   * See appendix below + TODO #64 in `mtc-keymaster/README-bugsandtodo.md`.
   * Original "any internet client" framing was wrong on this deployment (8444 is localhost-only, 8446 needs MQC handshake); the real exploitable path was cross-CA leaf hopping by in-log peers — also blocked.

4. **Remove late-bind reservation nonces or strongly constrain them**

   * If `fp` is NULL, consume accepts any key and binds it at first use.
   * A stolen/leaked reservation nonce becomes a bearer token for arbitrary key enrollment.
   * Fix: require fingerprint at nonce creation, or require CA-signed authorization at consumption.
   * File: `mtc_db.c:1350-1361`.

## P1 — high priority

5. **Bootstrap fork loop lacks child backpressure/reaping** — **DONE 2026-05-06 (TODO #65)**

   * `mtc_bootstrap.c::bootstrap_thread` now calls
     `mtc_wait_for_child_slot("bootstrap")` before `accept()`
     and `mtc_register_active_child()` after `fork()`.
   * Verified live with 25 parallel real bootstraps hitting
     the 20-child cap.

6. **HTTP parser can slow-loris**

   * Main HTTP read loop has no socket read timeout before parsing headers.
   * Bootstrap has timeouts; HTTP/MQC path should too.
   * File: `mtc_http.c:2078-2140`.

7. **Plain HTTP mode can expose write endpoints**

   * `handle_request()` permits `/enrollment/nonce`, `/renew-cert`, `/revoke`, etc. based on path checks; only some handlers enforce MQC.
   * Fix: reject sensitive POSTs unless `io->mqc` or trusted TLS-client-auth is present.
   * File: `mtc_http.c:2165-2192`.

8. **`http_get` proxy on bootstrap exposes arbitrary GET dispatcher over plaintext**

   * It rejects non-`/` paths, but otherwise proxies all GETs.
   * Fix: allowlist only harmless endpoints needed by bootstrap clients.
   * File: `mtc_bootstrap.c:324-339`.

## P2 — correctness / hardening

9. **Label is stored “verbatim”**

   * Comment says sanitization is client-side. Server should enforce `[A-Za-z0-9._-]`, length, and no path-ish values.
   * File: `mtc_http.c:620-626`.

10. **Persistence failures after in-memory success are not fatal everywhere**

* I saw warnings after `save_certificate` / `save_public_key`. These should fail closed or queue retry before returning success.
* File: `mtc_bootstrap.c:1560-1584`.

11. **Custom canonical JSON signing is fragile**

* Signing relies on json-c insertion order / serialization matching.
* Fix: use a real canonicalization scheme: RFC 8785 JCS or sign fixed binary fields.

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

### 2. Sign the bootstrap DH transcript — **PARTIAL**

ChatGPT's concern is that a MitM can substitute the server's
ephemeral DH pubkey in the plaintext message-2 reply
(`mtc_bootstrap.c:705-723`).  Currently the response signature
(P0 #9b, `add_cosigner_sig_to_response`) covers the cert JSON
but NOT the DH-exchange transcript (server_dh_pub, salt,
pop_nonce).

What the cosigner-signed response DOES defeat:
- Substitution of the cert content (cosigner-fp pin verifies).
- Substitution of `ca_cosigner_pem` itself.

What it does NOT defeat:
- Confidentiality of enrollment-request bytes (MitM with
  substituted DH key sees the leaf's pub_key_pem + nonce
  before re-encrypting to the real server).

The leaf's pub_key_pem is going to be public anyway (it lands in
the log).  The nonce is more sensitive — leakage to a passive
attacker means the attacker learns the (domain, fp) binding and
COULD attempt to consume it... but consumption requires the
matching private key, which the attacker does not have.

**Recommendation:** open as TODO #63 alongside #62.  Sign
`H(server_dh_pub || salt || pop_nonce || protocol_version)` under
the cosigner key in message 2 — gives the client a way to
constant-time-verify the DH transcript before deriving any
secrets.  Lower priority than #62; the layered defenses contain
the actual exploitable paths.

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

### 6. HTTP slow-loris — **PARTIAL**

`mtc_http.c::handle_request` at lines 2070-2143 reads headers
via `cio_read` in a loop.  No `setsockopt(SO_RCVTIMEO)` is set
on the socket beforehand.  `cio_read` itself doesn't time out
(blocking read).  An attacker can dribble bytes to keep one
worker tied up.

Mitigation: each connection runs in a forked child, so a
single slow-loris attacker tying up workers eventually hits the
fork-rate-limit / max-children cap and stops escalating.  But
the worker is still a live process consuming a slot.

**Recommendation:** open as TODO #66, LOW.  Set
`SO_RCVTIMEO` on the accepted socket BEFORE entering the read
loop in handle_request.  10s is plenty for a healthy peer; a
slow-loris drops at 10s.  One block of code, no protocol impact.

### 7. Plain HTTP exposes write endpoints — **PARTIAL**

Inventory:

- `/enrollment/nonce` — open on both ports (covered by #3 above).
- `/cancel-nonce` — already MQC-only (`mtc_http.c:814`).
- `/renew-cert` — already MQC-only (`mtc_http.c:969`).
- `/revoke` — accepts on both, but the request body carries a
  CA-key signature that the server verifies — auth is in the
  payload, not the transport.

So #3 (the leaf-nonce open path) is the only real gap.  /revoke
is acceptably authenticated.  Marking this finding as
**SUPERSEDED-BY-#3**.

### 8. `http_get` proxy on bootstrap exposes GET dispatcher — **BY DESIGN / LOW**

`mtc_bootstrap.c::send_http_get_proxy` runs any incoming
`{"op":"http_get","path":...}` through `dispatch_get`.  All of
those endpoints ARE public-readable on port 8444 anyway
(everything in `dispatch_get` is read-only and intended for
public consumption — log entries, certs, revocation list, etc.).
The proxy exists to give clients without a TLS trust anchor
access to the same data.

ChatGPT suggests an explicit allowlist.  Marginal value: an
attacker who compromises the bootstrap port and can speak the
op format already has full read access.  The allowlist would
catch a hypothetical future POST endpoint accidentally added to
`dispatch_get`.

**Recommendation:** open as TODO #67, LOW.  Defense-in-depth
allowlist of `/log/*`, `/certificate/*`, `/public-key/*`,
`/revoked/*`, `/ca/public-key`, `/ech/configs`, `/log/checkpoint`,
`/trust-anchors`, `/log/consistency`, `/certificate/search`.

## P2

### 9. Server-side label canonicalization — **OPEN**

`mtc_db_create_nonce` (mtc_db.c:1088) accepts the label string
verbatim and inserts it into the `mtc_enrollment_nonces.label`
column.  No charset / length / path-traversal validation.  The
client-side `sanitize_label` in `bootstrap_leaf` rejects labels
containing `/`, `..`, etc., but a malicious /enrollment/nonce
caller can plant a label that a future tool might use as a
directory name.

**Recommendation:** open as TODO #68, MEDIUM.  Add
`mtc_canonicalize_label(in, out, outsz)` (alongside the existing
`mtc_canonicalize_domain` in `mtc_domain.c`) enforcing
`[A-Za-z0-9._-]`, length 1..MTC_LABEL_MAX (=64).  Apply at the
top of `handle_enrollment_nonce` before passing to
`mtc_db_create_nonce`.

### 10. Persistence-fail-after-success warnings — **PARTIAL**

`mtc_bootstrap.c:1564` and `:1580` log warnings on
`mtc_db_save_certificate` / `mtc_db_save_public_key` failures
but proceed to send the (already-mutated-in-memory) successful
response to the client.  TODO #57 item 4 already converted the
mtc_log_entries write path to fail-closed (DB-first persistence;
see commit `0c4a8a7e1`).  The cert + pubkey writes weren't
covered.

**Recommendation:** open as TODO #69, MEDIUM.  Same fail-closed
pattern: if either save returns non-zero, roll back the
in-memory append (or refuse to send the response) and log
LOG_ERROR rather than LOG_WARN.

### 11. Custom canonical JSON signing fragile — **DOC / LOW**

The P0 #9b `add_cosigner_sig_to_response` relies on json-c's
`JSON_C_TO_STRING_PLAIN` producing identical bytes across the
sender's serialize → wire-encode → decode → mutate (delete sig
field) → re-serialize cycle.  Currently true for json-c 0.16+
but a future version upgrade could subtly change ordering and
break verification deployment-wide.

This is documented in `README-detail-design-spec.md` §8.4 with
the matching note in `mtc_bootstrap.c::add_cosigner_sig_to_response`
about "both sides use json-c's PLAIN flag".  Acceptable for a
single-deployment protocol with flag-day cutovers, but worth a
note in the spec about which json-c version is the verified
floor.

**Recommendation:** open as TODO #70, LOW.  Either pin a json-c
version in postWolf.pc requires (CI-friendly), or migrate to
RFC 8785 JCS canonicalization on both sides (more work, removes
the json-c version coupling entirely).  No live exploit; a
hygiene item.

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
TODOs closed 2026-05-06: #64, #62, #65.  Remaining:

1. **TODO #69** — fail-closed on persistence errors during
   enrollment.  Local-only change in `mtc_bootstrap.c`.
2. **TODO #68** — server-side label canonicalization.
   Local-only.
3. **TODO #66** — HTTP read timeout (`SO_RCVTIMEO`).
   Local-only.
4. **TODO #63** — DH-transcript signature.  Defense-in-depth
   on top of the now-shipped AEAD.
5. **TODO #67, #70, #71** — defense-in-depth / hygiene.
3. **TODO #65** — bootstrap fork backpressure.  One-line fix,
   contains the fork-storm DoS vector.
4. **TODO #69** — fail-closed on persistence errors during
   enrollment.  Local-only change.
5. **TODO #68** — server-side label canonicalization.  Local-only.
6. **TODO #66** — HTTP read timeout.  Local-only.
7. **TODO #63** — DH-transcript signature.  Defense-in-depth on
   top of #62.
8. **TODO #67, #70, #71** — defense-in-depth / hygiene.

Items 1–3 cover the genuine attack surface ChatGPT identified
that current postWolf code does not already mitigate.  Items 4+
are good practice but lower urgency.
