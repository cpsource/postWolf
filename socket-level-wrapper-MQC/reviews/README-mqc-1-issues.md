> **Reading order.** This file is the original 12-finding
> external review.  For the current "what is still open?"
> scoreboard, see
> [`../README-mqc-issues-summary.md`](../README-mqc-issues-summary.md);
> the per-issue commit map at the bottom of this file is the
> closure record.

It is a solid experimental start, but I would **not yet trust this as TLS replacement strength**. The biggest problem is that the handshake signatures do **not bind the full transcript**; they only sign the sender’s `kem_pub` / ciphertext. That leaves room for identity substitution, mode confusion, cross-protocol, replay, and unknown-key-share style attacks. 

Top fixes:

1. **Sign the full transcript**
   Sign: protocol version, mode, both identities, both KEM values, log ID, cert index, cipher suite, transcript hash, and role label `"client"` / `"server"`. Signing only `EK_c` or `CT_s` is too weak. 

2. **Add a real protocol version and suite ID**
   Right now there is no explicit version field. Add `version: 0`, `suite: "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256"`, and bind both into signatures and HKDF.

3. **Use transcript-bound HKDF**
   Current HKDF uses empty salt and simple info strings. Better:
   `handshake_secret = HKDF-Extract(transcript_hash, SS)`
   then derive `c2s_key`, `s2c_key`, IVs, and finished keys with labeled info strings. 

4. **Add Finished messages**
   After authentication, each side should send a MAC over the full transcript using a derived finished key. TLS does this for a reason: it catches transcript tampering and implementation mismatch.

5. **AEAD must authenticate frame headers**
   Your AES-GCM AAD is empty. Include at least: frame type, protocol version, sequence number, payload length, direction, and maybe connection ID. Otherwise length/type metadata is unauthenticated. 

6. **Encrypted-identity mode has authentication gaps**
   The encrypted server identity blob contains only `cert_index` and `signature`, and the signature appears to be over only `CT_s`. It should sign the full encrypted-identity transcript, including `EK_c`, `CT_s`, mode, and server role. 

7. **Revocation should be mandatory, not MAY**
   The spec says revocation MAY be queried, with 24-hour negative caching. For an authenticated transport, online revocation should be mandatory by policy unless explicitly disabled. 

8. **Certificate retrieval over “out of band HTTP” is dangerous**
   If retrieval is unauthenticated, the cert object must be fully self-verifying: signed checkpoint, inclusion proof, log identity, expiry, name constraints, revocation state. Do not rely on plain HTTP integrity.

9. **No server-name / expected identity check is specified**
   The client must verify not only “this cert is valid,” but “this cert is authorized for the service I intended to reach.” Add expected service name / DNS name / application name matching.

10. **No downgrade protection**
    Clear vs encrypted identity mode is selected by the shape of JSON. Bind selected mode into transcript and signatures, or an active attacker may be able to force clear mode or create confusion.

11. **JSON parsing is attack surface**
    You removed ASN.1, but JSON has its own hazards: duplicate keys, huge integers, alternate encodings, whitespace differences, Unicode, and inconsistent canonicalization. Specify strict JSON parsing and duplicate-key rejection.

12. **DoS risk is high**
    128 KiB handshake frames plus ML-DSA verification can be expensive. Add cheap prefilters: exact byte-length checks for KEM/signature fields before crypto, puzzles/tokens optionally, per-IP and per-cert throttling, and memory caps. 

How well will it stand up? Against passive quantum-era eavesdropping, the primitive choices are strong. Against active network attackers, I’d rate the current draft **not yet safe**, mainly because the handshake lacks full transcript binding, finished messages, strict identity matching, and mandatory revocation policy.

The design can become strong, but I’d fix the handshake before anything else.


## Status — what addressed each issue

The 12 reviewer items above drove the Phase 1–3 hardening pass
recorded in [`mqc-master.plan`](./mqc-master.plan).  Every item
either has its own per-issue plan (the design discussion) or
was subsumed by another issue's binding.  Status as of phase-20:

| Issue | Commit | Notes |
|---|---|---|
| #1 — sign full transcript | `6b4c380b6` | Bind transcript + HKDF Extract + Finished + AAD (one flag-day cutover, Phase 1) |
| #2 — version + suite ID | `6b4c380b6` (subsumed by #1) | Both fields added to handshake JSON and bound into the transcript hash |
| #3 — transcript-bound HKDF | `6b4c380b6` (subsumed by #1) | HKDF-Extract salt is `transcript_hash_full`; full Extract+Expand schedule |
| #4 — Finished messages | `6b4c380b6` (subsumed by #1) | New §8.1; HMAC-SHA256 over the transcript, sent as the first AEAD frame each direction |
| #5 — AEAD authenticates frame headers | `6b4c380b6` (subsumed by #1) | New §9.1.1; 31-byte AAD covers label, version, direction, frame_type, sequence, plaintext_length |
| #6 — encrypted-mode auth gaps | `6b4c380b6`, `a287aa8d0` | Full-transcript binding from #1 also binds encrypted-mode signatures over the right inputs.  Encrypted-mode handshake bodies were stubs through Phase 6 and shipped end-to-end in Phase 7 commit 2 (`a287aa8d0`); both peers sign / verify the FULL transcript including `EK_c`, `CT_s`, `MODE_ID=0x01`, and both `cert_index` values.  Auto-detect dispatcher in `mqc.c` lets one listener serve both modes |
| #7 — mandatory revocation | `04ad93f5f` | `mqc-revocation-policy` knob; default `mandatory` fail-closed; `cache-only` and `disabled` opt-outs |
| #8 — cert self-verification audit | `089a3966a` | Tightened cert-validity window enforcement + cosigner-fingerprint cache invariant |
| #9 — server-name / expected identity | `890e27137` | New §10.7; client-side check against verified subject; dial-by-IP fails closed |
| #10 — downgrade protection | `6b4c380b6` (subsumed by #1) | `mode` field is bound into the transcript via `MODE_ID` byte in §6.0 |
| #11 — strict JSON parsing | `ee9977b71` | New §5.2 / §12.10; rejects parser extensions, duplicates, trailing bytes, unknown fields, integer overflow |
| #12 — DoS pre-crypto filters | `615d0e9ba` | Per-(IP, distinct-`cert_index`) throttle (#12) + pre-crypto length filter (already shipped via #11) |

Three cross-cutting changes extended the operational surface but
weren't on the reviewer list:

| Change | Commit | Notes |
|---|---|---|
| Operational tunables in `/etc/postWolf/config` | `292c07bcc` | The foundation Phases 1–3 build on; per-knob docs in `config.server` and spec §11 |
| Server fork backpressure | `86e924fb3` | `mqc-max-children` (default 20) — defends against fork-storm OOM observed during Phase-4 stress testing.  Spec §11.6 |
| Phase 7 — encrypted-identity mode | `de0ff9d60`, `a287aa8d0` | Two-commit rewrite (file-split refactor + 4-frame handshake bodies + auto-detect dispatcher).  `show-tpm --verify --encrypted` exercises the new code path end-to-end against the live server |

The per-issue `mqc-issue-N.plan` files that originally accompanied
each row have been removed from the tree now that the work has
shipped (commit `git log --diff-filter=D --name-only -- 'socket-level-wrapper-MQC/mqc-issue-*.plan'`
shows when).  The narrative orchestration across all 7 phases lives
in [`mqc-master.plan`](./mqc-master.plan); the design rationale for
each change lives in the corresponding commit message + the spec
edits.

System-level testing for the cumulative pass landed under
[`mqc-master.plan`](./mqc-master.plan) Phase 4 — see
`make -f Makefile.tools test-mqc-all` for the aggregate suite.

Encrypted-identity mode shipped in Phase 7 (commits `de0ff9d60`
and `a287aa8d0`) and is opt-in for callers that want
traffic-analysis resistance.  Set `cfg.encrypt_identity = 1`
before `mqc_ctx_new` (or pass `--encrypted` to `show-tpm`) to
exercise the 4-frame path; the server listener auto-detects per
connection so a single port serves both kinds of peer.
