I reviewed the tarball.

**Bottom line:** the implementation addresses many earlier design issues, but it **does not fully meet `draft-page-mqc-protocol-00.md` yet**, and I would **not treat it as TLS-replacement safe**.

Major findings:

1. **Spec mismatch: handshake frames are not length-prefixed.**
   Spec §5.1 says *every unit before and after handshake* is a 4-byte length-prefixed frame. Code sends raw JSON and reads by brace-counting with `mqc_read_json_block()`. This is the biggest compliance failure.

2. **Brace-count JSON reader is fragile.**
   It does not understand JSON strings/escapes, so braces inside strings can desynchronize framing. Strict JSON parsing happens only after this ad-hoc frame extraction.

3. **Trust anchor bootstrap is TOFU/plaintext.**
   `mqc_load_ca_pubkey()` fetches the CA cosigner key over a plaintext bootstrap port and caches it. A first-contact MITM can pin their own CA key.

4. **Peer public key binding looks weak/incomplete.**
   The cert contains a `subject_public_key_hash`, but `extract_pubkey_from_cert()` fetches/loads a public key from local paths or `/public-key/<subject>` and I did not see a clear check that the fetched key hashes to the certificate’s `subject_public_key_hash`. That is a serious identity-substitution risk.

5. **Revocation “mandatory” deliberately drops first contact.**
   On cache miss it fetches revocation status, writes cache, then returns failure so the peer retries. That is fail-closed, but operationally brittle and easy to DoS.

6. **Handshake transcript is field-based, not raw-frame based.**
   It binds version/mode/suite hash/KEM/ciphertext/cert indices/role, which is good, but it does not bind the exact JSON bytes or length prefix. That is acceptable only if the spec clearly defines canonical transcript fields; it currently mixes “frame” language with field hashing.

7. **AEAD receive increments sequence before auth succeeds.**
   `mqc_enc_recv()` and `mqc_read()` increment `recv_seq` before GCM verification. Since failures should terminate the connection this is probably not exploitable, but it violates the spec wording “increments on success” and is unsafe if callers ever continue after failure.

8. **Encrypted-identity mode is present, not a stub.**
   The comments in `mqc.c` / `mqc_internal.h` still say it is stubbed, but `mqc_encrypted.c` has real code. Documentation is stale.

9. **Auto-detect mode peeks plaintext JSON instead of using a framed parser.**
   `mqc_accept_auto()` uses `MSG_PEEK` and `strstr()` for `"mode":"encrypted"`. This is brittle and not spec-grade.

10. **No build/test verification completed here.**
    I inspected source, but did not compile or run tests because the tree depends on wolfSSL PQC/MTC headers, json-c, hiredis, curl, and local postWolf config/runtime services.

**Priority fixes:**

1. Replace all handshake raw JSON send/read with the same 4-byte length-prefixed frame format in §5.1.
2. Delete brace-count framing. Read length, cap it, then parse exactly that buffer.
3. Make CA cosigner key pinned/configured out-of-band; do not TOFU it silently.
4. Verify fetched peer public key against the certificate’s `subject_public_key_hash`.
5. Increment receive sequence only after AEAD verification succeeds.
6. Make `mqc_accept_auto()` parse a real length-prefixed ClientHello and dispatch from the parsed `mode`.

Once those are fixed, the core crypto shape is much closer: transcript-bound signatures, HKDF salt, Finished MACs, AEAD AAD, revocation policy, and name checks are all substantially improved.


---

## Appendix A — Triage and plan response (Claude Code, 2026-05-03)

This appendix records the read of the 10 reviewer findings above
that produced [`mqc-2-master.plan`](./mqc-2-master.plan).  It
captures both the per-finding verification (was the claim true
on the actual codebase?) and the structured plan response.

### Per-finding verification

Each finding was verified by reading the cited code path before
agreeing or disagreeing.

| # | Reviewer claim | Verified | Verdict |
|---|---|---|---|
| 1 | Handshake not length-prefixed | YES — `mqc_read_json_block` reads byte-by-byte, counts braces, no length prefix.  Spec §5.1 explicitly requires length-prefixed framing for "every unit before and after handshake." | **Agree.** Real spec/code mismatch. |
| 2 | Brace-count reader is fragile | YES — line 533–534 of `mqc_common.c`: counts `{` and `}` without string-literal awareness.  `{"k":"}"}` desynchronises framing. | **Agree.** |
| 3 | Cosigner TOFU at first contact | YES — already tracked as TODO #9b in `mtc-keymaster/README-bugsandtodo.md` with two design branches at `~/.claude/plans/lets-plan-to-implement-snoopy-rivest.md`. | **Agree.**  Not new; pick up the existing design. |
| 4 | Peer pubkey not verified against `subject_public_key_hash` | YES — `extract_pubkey_from_cert` reads PEM from local files, never SHA-256s it and compares to the cert's hash field. | **Agree, and this is the most serious one.**  Anyone with write access to `~/.TPM/peers/<n>/public_key.pem` can substitute the verifier pubkey while keeping the cert hash unchanged → identity-substitution. |
| 5 | Revocation drop-and-retry is brittle | YES, real behavior — but the per-(IP, cert_index) throttle from #12 already mitigates the DoS amplification path.  The drop happens once per (peer, cert_index) lifetime, not per connection. | **Partial disagree.**  Worth revisiting but not security-critical. |
| 6 | Transcript binds fields, not raw bytes | YES, by design.  Spec §6.0 explicitly defines a structured byte sequence (LABEL ‖ version ‖ mode ‖ SUITE_ID ‖ KEM ‖ cert_index ‖ role). | **Disagree on severity** — the field-based transcript is a TLS-1.3-style design choice, not a bug.  The reviewer's actual concern is doc clarity around the word "frame," which fix #1 will resolve. |
| 7 | AEAD recv increments seq before auth | YES — `mqc_enc_recv` line 1420 does `(*seq)++` BEFORE `wc_AesGcmDecrypt` at line 1425.  Same pattern at line 1591 in `mqc_read`. | **Agree.**  Trivial fix (move one line).  Spec wording matters even though the connection terminates on auth failure today. |
| 8 | Docs say encrypted is stub but code is real | YES — three stale comments in `mqc_internal.h:7`, `mqc.c:15`, `mqc.c:27`. | **Agree.**  Trivial cleanup. |
| 9 | Auto-detect uses MSG_PEEK + strstr | YES, current behavior. | **Partial agree.**  Architecturally inelegant but the strict-parser fallback catches false positives.  Fix #1 (length-prefixed frames) lets us replace MSG_PEEK with "read full frame, parse strict, dispatch from parsed `mode`" — much cleaner. |
| 10 | Reviewer didn't compile/test | (meta) | n/a |

**Bottom line:** 7 of 10 findings are actionable.  Findings #1,
#2, #6, and #9 are coupled — one underlying design fix
(length-prefix the handshake frames) closes all four.  Finding
#4 is the highest severity.  Findings #7 and #8 are trivial.

### Agreement summary

Agree with: #1, #2, #3, #4, #7, #8 — all real, all worth fixing.

Partial agree:

- **#5:** real behavior, but the per-cert throttle from #12
  already mitigates the DoS path.
- **#9:** workable today (strict-parser fallback catches false
  positives) but ugly; fix #1 enables a clean replacement.

Disagree:

- **#6:** the field-based transcript is by design (spec §6.0,
  TLS-1.3-aligned), not a bug.  The reviewer's actual concern is
  doc clarity around the word "frame," which fix #1 resolves.

### Plan structure ([`mqc-2-master.plan`](./mqc-2-master.plan))

| Phase | Closes findings | Cutover | Effort |
|---|---|---|---|
| **1** — length-prefixed handshake frames | #1, #2, #6, #9 | flag-day | substantial — touches all 4 .c files + tests + spec |
| **2** — pubkey-hash binding | #4 (highest severity) | wire-quiet | medium — single function + regression test + spec §10.2/§12.11 |
| **3** — AEAD seq after verify | #7 | wire-quiet | trivial — one line, two locations |
| **4** — stale-doc cleanup | #8 | doc only | trivial |
| **5** — cosigner TOFU hardening | #3 | substantial | triggers existing snoopy-rivest plan branches |
| **6** — revocation first-contact UX (deferred) | #5 | wire-quiet | may never land |

**Key insight:** findings #1/#2/#6/#9 cluster into ONE underlying
fix (length-prefix the handshake).  Once Phase 1 lands, four
reviewer items close together.
