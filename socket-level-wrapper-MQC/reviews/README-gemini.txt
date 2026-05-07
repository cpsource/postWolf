================================================================
TRIAGE 2026-05-06 (phase-23, HEAD post-TODO-#58 fix)
================================================================

Reading order: this file is the per-finding Gemini triage.  For
the current "what is still open?" scoreboard, see
../README-mqc-issues-summary.md (its Gemini scorecard rows are
the live status; this triage is the source it cites).

Each Gemini finding triaged against the current MQC implementation
in socket-level-wrapper-MQC/.  Verdicts use this scale:

  CLOSED       — finding does not match current code; no action
  PARTIAL      — defenses cover most of the threat; defense-in-depth
                 still possible
  BY DESIGN    — current behavior is the intended trade-off; document
  OPEN         — gap exists, follow-up TODO recommended

----------------------------------------------------------------
MQC-01  Server identity leak via mqc_accept_auto      BY DESIGN +
        (clear-mode probe)                            small guard
                                                      recommended
----------------------------------------------------------------

Current state:
- Encrypted mode (mqc_encrypted.c): server's cert_index is sent
  ONLY in phase-2, AEAD-sealed under early_secret derived from
  the phase-1 ML-KEM exchange.  An anonymous attacker cannot
  decrypt phase 2.  Encrypted-mode privacy is intact.
- Clear mode (mqc_clear.c:181): ServerHello carries cert_index
  in plaintext.  Any peer who opens a TCP connection and sends
  a clear-mode ClientHello learns cert_index.  This IS the
  documented clear-mode behavior — clear mode does not promise
  identity privacy.
- Dispatcher mqc_accept_auto (mqc.c:81) reads the FIRST frame's
  parsed `mode` field and dispatches.  It does NOT consult
  ctx->encrypt_identity.

Verdict: clear-mode "leak" is by design — `mqc_accept_auto`
serves both populations.  The operator who needs server-identity
privacy must call `mqc_accept` (with cfg.encrypt_identity=1),
not `mqc_accept_auto`.  Spec README-MQC-specifications.md §
"Server Auto-Detection" documents the dispatch but does not
spell out the privacy trade-off.

Small guard worth shipping (low cost, high signal): in
mqc_accept_auto, if ctx->encrypt_identity == 1 and the parsed
client mode is "clear", refuse with MQC_SECURITY("REQUIRE_
ENCRYPTED_REJECT") and close.  Current behavior would silently
serve the clear handshake even though the operator opted in to
encrypted-only — the guard converts a quiet config foot-gun
into a fail-loud abort.

Doc clarification also worth adding to README-MQC-specifications.md
§ "Server Auto-Detection": "mqc_accept_auto serves both modes by
client choice.  Operators who require server-identity privacy MUST
use mqc_accept with encrypt_identity=1; mqc_accept_auto will be
guarded against accidental clear-mode dispatch when encrypt_identity
is set."

----------------------------------------------------------------
MQC-02  DoS via asymmetric work (ML-KEM/ML-DSA on        PARTIAL
        unauthenticated frames; 5-second budget)
----------------------------------------------------------------

Current state — defenses already in place:
- mqc-handshake-total-sec (default 5, config-tunable; not a
  hardcoded 5 in C).  Slow-loris deadline (HANDSHAKE_DEADLINE_
  ACTIVE + mqc_read_all check) wall-bounds an active handshake.
- mqc-max-children (default 20) caps concurrent forked accepts;
  bursts queue/stretch instead of fan-out.
- Pre-crypto length filter (mqc_json_get_hex_strict) rejects
  malformed hex BEFORE invoking ML-KEM / ML-DSA — gating the
  expensive primitives behind cheap byte checks.
- Per-IP connect/fail rate limits + per-IP distinct-cert_index
  SET (Redis-backed); fail-policy `mqc-rl-redis-fail-policy`
  with fail-closed-after-sec backstop landed in phase-22.
- Strict JSON parse on the unauthenticated first frame (length-
  prefixed, no trailing bytes, no unknown fields, no duplicate
  keys, strict UTF-8) — closes the heavy-parser-attack surface
  too.

Gap (defense-in-depth):
- No proof-of-work / token gate BEFORE the ML-KEM decap.  Even
  with all the above, one TCP connection per IP-bucket budget
  buys exactly one ML-KEM decap — a coordinated source could
  still trade IPs for crypto cycles.  The 5-second budget puts
  a wall-clock cap on each individual abuser slot but doesn't
  reduce the per-connection crypto cost.

Recommendation: TODO #59 (pre-auth client puzzle).  Lightweight
HMAC-cookie or hashcash-style PoW client-side that the server
verifies before invoking wc_KyberKey_Decapsulate.  Not urgent
— layered defenses already make a successful flood expensive
to mount — but a sensible defense-in-depth item to file.

----------------------------------------------------------------
MQC-03  ERANGE desync in JSON integer parsing               CLOSED
----------------------------------------------------------------

Current state:
- mqc_json_get_int_strict (mqc_common.c:463) explicitly checks
  errno == ERANGE after json_object_get_int64 and rejects with
  MQC_SECURITY("...overflows int64").  Then bounds-checks against
  the caller-supplied [min, max].  No silent saturation.
- All transcript-bound integer fields (cert_index, version, …)
  go through this helper.

Verdict: closed.  No code change needed.

----------------------------------------------------------------
Side observations (not numbered findings)
----------------------------------------------------------------

* Duplicate-Key Smuggling: mqc_json_no_duplicates +
  mqc_json_count_field (mqc_common.c:390-441) implement the
  custom check Gemini calls out as critical.  Logic walks the
  buffer with proper string-literal / escape tracking, which is
  what makes it correct against payloads like
  {"cert_index":1,"x":"\"cert_index\":2"}.  No bypass found.
  Worth keeping this code in scope on every audit pass — if
  the field-list check ever drifts out of sync with the
  signed-fields list, transcript divergence becomes possible.

* Entropy Exhaustion (wc_InitRng in fork-per-connection):
  Linux post-boot uses getrandom(2) / /dev/urandom which does
  NOT block once the kernel has seeded its CSPRNG (early-boot
  systems are out of scope for postWolf, which assumes
  systemd-managed services).  No fallback to deterministic
  state on Linux.  Verdict: not a Linux-deployment issue;
  could matter on niche embedded platforms not in scope here.
  Consider RNG init at process startup (parent pre-fork) so
  per-handshake cost is bounded — current code paths look
  fine but worth a check on the next pass.

* "Hardened JSON" (replace json-c with custom parser):
  significant scope.  The strict-mode + UTF-8 + duplicate-key
  + unknown-key + length-prefix + trailing-byte stack already
  rejects every malformed payload class Gemini's report
  references.  Defer.

================================================================
End triage 2026-05-06.
================================================================

Gemini security report is attached.

I have conducted a security review of the Merkle Quantum Connect (MQC) protocol and its implementation in mqc_encrypted.c, specifically focusing on its role as a Post-Quantum (PQ) replacement for TLS 1.3.

Security Review Summary
The MQC protocol is a robust, "zero-ASN.1" approach to authenticated encryption using ML-KEM-768 and ML-DSA-87. It successfully addresses several legacy TLS weaknesses by mandating a strict JSON handshake and binding every byte of the exchange into a transcript hash.  
+2

However, the "Encrypted-Identity" mode and the socket-level wrapper introduce specific risks—particularly regarding identity leaks, resource exhaustion, and state desynchronization.

High-Priority Findings
1. Identity Leak in Encrypted-Identity Mode
While Section 7 aims to hide identities , the mqc_accept_auto dispatcher must read the first frame to determine the mode.  
+2

Risk: An attacker can probe the server by sending a "clear" mode ClientHello. If the server responds with its identity before the client is authenticated, it defeats the privacy goal for the server.

Mitigation: Ensure the server never reveals its cert_index in any mode until it has verified the client's KEM contribution.

2. JSON "Duplicate-Key Smuggling"
The protocol correctly identifies that most JSON parsers (like json-c) are vulnerable to duplicate-key attacks.  
+1


Observation: In mqc_encrypted.c, the code calls mqc_json_no_duplicates. This is a critical custom check. If this check is bypassed or has a logic error, an attacker could sign one cert_index while the verifier processes another.  
+2

3. Denial of Service (DoS) via Asymmetric Work
The implementation performs ML-KEM decapsulation and ML-DSA signature verification  during the handshake.  
+2

Risk: These are CPU-intensive. An attacker can flood the mqc-max-children limit (default 20) with "half-open" handshakes.  
+1


Mitigation: The "fail-closed" rate limiting on cert_index is a good start, but the 5-second total budget  may still be too long under a heavy SYN flood.  
+1

4. Entropy Exhaustion
The code relies on wc_InitRng for all key generation and encapsulation.  
+1


Risk: In a high-concurrency "fork-per-connection" model, if the OS entropy pool is depleted, wc_InitRng could block or fail, leading to handshake failures or, worse, weak keys if the library falls back to a deterministic state.  

Implementation Observations: mqc_encrypted.c

Secure Zeroization: The use of mqc_secure_zero on sensitive material (shared secrets, keys, IVs) at the end of the function and in the fail block is excellent practice.  
+3


Transcript Binding: The protocol binds the MODE_ID and SUITE_ID into the transcript. This prevents "Cross-Mode" attacks where an attacker tries to trick a peer into treating an encrypted-mode frame as a clear-mode frame.  
+3

===

# MQC Security Audit Report (v0.0.1)
**Project:** Merkle Quantum Connect (MQC)
**Date:** May 4, 2026
**Status:** High-Priority Review

## Vulnerability Registry

| ID | Severity | Component | Description |
|---|---|---|---|
| MQC-01 | High | Handshake | Potential Server Identity leak during Mode-Negotiation. |
| MQC-02 | Medium | Resource | DoS via ML-DSA verification on unauthenticated frames. |
| MQC-03 | Low | Parsing | Potential for ERANGE desynchronization in JSON integer parsing. |

## Critical Logic Checks
1. [cite_start]**Transcript Consistency:** The "Finished" frame (Sequence 0) is mandatory[cite: 421, 460]. [cite_start]It prevents an attacker from tampering with the unencrypted portions of the handshake[cite: 638].
2. [cite_start]**Name Constraints:** The `NAME_CHECK_FAILED` logic [cite: 100, 563] is vital. [cite_start]Without it, the protocol only proves *authority*, not *intent*[cite: 650, 651].

## Recommendations
- **Pre-Authentication Filter:** Implement a small proof-of-work or a token-based rate limiter before triggering ML-KEM/ML-DSA.
- **Hardened JSON:** Replace general-purpose JSON parsers with a hard-coded, non-recursive "Handshake Parser" to eliminate the attack surface of the parser library itself.

===

# MQC Technical Audit (mqc_common.c)
**Reviewer:** Gemini (AI Collaborator)
**Context:** Phase 7 Hardening Pass

## Critical Parser Mitigations
* **Duplicate Key Smuggling:** Blocked by `mqc_json_count_field`.
* **Transcript Divergence:** Prevented by binding `SUITE_ID` into the KDF salt.
* **Slow-Loris:** Blocked by `s_handshake_deadline` in `mqc_read_all`.

## Cryptographic State
* **Nonce Construction:** TLS 1.3 XOR mask used correctly (Line 473).
* **Zeroization:** `mqc_secure_zero` is volatile-qualified to prevent compiler optimization removals.

