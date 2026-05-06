# MQC issue-plan analyses

This file collects the analyses that accompany each `mqc-issue-N.plan`
in this directory.  Plans themselves are step-by-step implementation
documents; this file is the reasoning that produced them.

## Deployment model — read this first

postWolf is the **only** MQC deployment.  The four MQC client
tools (`show-tpm`, `bootstrap_ca`, `bootstrap_leaf`,
`admin_recosign`) and the CA server itself are all built from this
tree, and the operator (factsorlie.com) upgrades server and
clients together.  No external clients exist.  No `-01` of
`draft-page-mqc-protocol-00.md` has been published.

**Therefore:** plans never need dual-stack support, capability
negotiation, fall-back paths, version-flag opt-ins, or compat
shims.  Every cutover is a flag day: bump the version string in
the spec, change the wire/derivation/etc., restart
`mtc-ca.service`, redeploy the four client tools, done.

The plans below mention "wire-format breaking" or "behavior-
breaking" or "flag-day cutover" only to flag *which kind* of
break a change is (so the operator knows what failure mode to
expect during the brief mid-cutover window — JSON parse error vs.
AEAD AUTH_FAIL).  They are never gating the change itself; that's
already accepted.

---

## Issue #1 — Sign the full transcript

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #1.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 1.

### Verdict

**Agree with the assessment.**  The reviewer's analysis is correct in
substance, and the implementation is in fact slightly worse than the
spec the reviewer was reading.

### What the spec says (`draft-page-mqc-protocol-00.md` §10.2)

> The verifier extracts the ML-DSA-87 public key from the retrieved
> certificate and verifies that `signature` in the handshake frame is
> a valid ML-DSA-87 signature, under that public key, over:
>
> - the sender's `kem_pub` field value (the ML-KEM-768 encapsulation
>   key for the client; the ML-KEM-768 ciphertext for the server).

So per the spec:

- Client signs only `EK_c` (its own ML-KEM public key).
- Server signs only `CT_s` (its own ML-KEM ciphertext).

What the signature does **not** commit to:

- **Protocol version** — there's no `version` field on the wire at
  all; "version 0" is a property of the spec, not the bytes.
- **Mode** — clear-identity vs encrypted-identity is decided by JSON-
  shape inspection (§7.1), so the mode itself is unauthenticated.
- **The peer's identity** — neither side's `cert_index` is in the
  other's signed bytes.
- **The peer's KEM contribution** — the server signs `CT_s` but not
  `EK_c`; the client signs `EK_c` but not `CT_s`.  Each half of the
  KEM exchange is signed in isolation.
- **Role label** — nothing distinguishes a "client signed this"
  blob from a "server signed this" blob.
- **Domain separation** — the implementation calls
  `wc_dilithium_sign_ctx_msg(NULL, 0, …)` (`mqc.c:753` and seven
  other sites), so the ML-DSA `ctx` is empty.  An MQC handshake
  signature is bytewise indistinguishable from any other empty-ctx
  ML-DSA signature the same identity key might ever produce.  By
  contrast, the cosigner uses an explicit context label
  `"mtc-subtree/v1\n\x00"` (16 bytes — see §10.4); identity keys
  should follow the same convention.

That gap is the textbook transcript-binding hole.  It enables
identity-substitution / Unknown Key Share / cross-protocol replay
against any other use of the same identity key.

### What the *implementation* does on top of all that

While reading `mqc.c` for the plan, I noticed the encrypted-identity
mode is **strictly worse** than what §7.3 describes.

`mqc.c:1573-1588` — the server-side encrypted-identity signature is
computed over the literal C string:

```c
char peer_challenge[32];
int pc_len = snprintf(peer_challenge, sizeof(peer_challenge),
                      "mqc-id:%d", ctx->our_cert_index);
...
ret = wc_dilithium_sign_ctx_msg(NULL, 0,
    (const byte *)peer_challenge, (word32)pc_len,
    our_sig, &our_sig_sz, &dil, &rng);
```

That is a **constant per identity**.  Every successful encrypted-
identity ServerHello blob from cert_index N is the same signature.
A passive attacker who observes one such handshake can replay the
server-identity blob in any future encrypted-identity handshake
claiming to be cert_index N — without ever having access to the
server's ML-DSA private key.  The encrypted-identity mode currently
provides effectively zero handshake binding on the server→client
direction.

The corresponding client-side verify (`mqc.c:1370-1373`) accepts
the constant blob.

So the plan must fix two distinct holes, not one:

1. The transcript-binding gap that the reviewer flagged for clear
   mode (and that also affects the encrypted-mode *client* side,
   which signs only `EK_c`).
2. The constant-per-identity replay hole on the encrypted-mode
   *server* side.

A single transcript construction (defined in the plan) closes both
in the same change.

### Caveats on the reviewer's wording

The reviewer's recommendation lists "log ID, cert index, cipher
suite" as fields to bind.  Those are TLS-1.3-isms.  The MQC
equivalents are:

- `log_id` — currently implicit (the cosigner's known pubkey is the
  trust anchor).  Including a `log_id` byte string in the transcript
  would prevent cross-log substitution if MQC ever supports more
  than one log.  Not addressed in this plan since postWolf is
  single-log; can be added later without a wire-format break by
  defining `log_id = "" (empty)` for v0.
- `cert_index` — already on the wire, just not signed.  This plan
  signs both peers' `cert_index`.
- `cipher suite` — does not exist as a wire field today.  This plan
  introduces a `suite` field (`MQC_MLKEM768_MLDSA87_AES256GCM_SHA256`)
  and binds it.

### Why this is wire-format breaking (and we don't care)

The plan adds three new top-level handshake JSON fields (`version`,
`suite`, `mode`), renames `mlkem_encaps_key` / `mlkem_ciphertext` →
`kem_pub` to align with the spec, restructures encrypted-identity
mode from 3 frames to 4 frames, and changes the byte-string that
every signature covers.

Old clients cannot interoperate with new servers and vice-versa.
That's fine: the spec is at draft-00, the protocol is in continuous
deployment only on factsorlie.com (one MTC log, four client tools
all built from this tree), and there are no external 8446 clients
in the wild.  The plan's runbook is a single-host flag-day cutover.

---

## Issue #2 — Add a real protocol version and suite ID

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #2.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 2.

### Verdict

**Agree with the assessment, but most of it is already covered by
issue-1's plan.**  The reviewer's three asks were:

1. Add a `version` field on the wire.
2. Add a `suite` ID on the wire.
3. Bind both into signatures *and* HKDF.

Items 1, 2, and the signature-binding portion of 3 are all in
issue #1 because transcript binding is meaningless without
something to bind.  The HKDF-binding portion of item 3 is the only
non-trivial residual, and it splits further into:

- The cheap version (this plan, issue #2): tag `version`
  and `suite` into the existing HKDF *info* strings.
- The real version (issue #3, when written): full
  transcript-bound `HKDF-Extract(transcript_hash, SS)` per the
  reviewer's item #3.

### The cheap-vs-real tradeoff

Today's HKDF info strings (`mqc.c:51-52`) are
`"mqc-session-c2s"` / `"mqc-session-s2c"` — 15 bytes, no version, no
suite.  Two ways to fix:

- **Cheap (this plan)** — change the info strings to literals like
  `"mqc/v0/MQC_MLKEM768_MLDSA87_AES256GCM_SHA256/c2s-session-key"`.
  Two `#define` edits, six call sites unchanged because they go
  through `derive_session_keys` → `wc_HKDF`.  Defends against a
  buggy peer that mis-binds the signature transcript or against
  cross-version/cross-suite collisions, but does not bind the
  *handshake transcript* (which is what TLS 1.3 actually does).
- **Real (issue-3)** — replace the current `HKDF(IKM=SS, salt=NULL,
  info=…)` with `HKDF-Extract(salt=transcript_hash, IKM=SS)`
  followed by labeled `HKDF-Expand` for c2s, s2c, IV, and finished
  keys.  This is a bigger restructuring and deserves its own plan.

These are not mutually exclusive — the cheap version is
strictly subsumed by the real version, but the cheap version is a
two-line change that lands cleanly with issue-1 in the same
flag-day cutover.  When issue-3 lands later, the info-string change
goes away (the suite/version end up bound through the transcript
hash instead of through the info string).

### Why bother with the cheap version if issue-3 supersedes it?

Defense in depth, and the cost is essentially zero.  A peer that
mis-implements issue-1's signature transcript could still derive
matching session keys with a correct peer if the info strings are
identical.  Tagging `version` and `suite` into the info string
breaks that: keys differ, AEAD rejects the first frame, the bug
surfaces immediately.

The reviewer's framing ("bind both into signatures and HKDF")
captures exactly this: belt-and-braces is the design intent.

### Caveats

- The plan uses literal `"v0"` in the info string rather than
  stringifying `MQC_PROTOCOL_VERSION`.  Bumping to v1 should be a
  deliberate flag-day cutover, not something that happens silently
  when an integer constant is bumped.
- The plan does not introduce a wire-level "negotiated" suite —
  there's still exactly one suite in v0.  When MQC ever supports
  multiple suites, the binding mechanism is in place; the
  *negotiation* mechanism would be a separate spec change.

### Why combine #1 and #2 in one cutover

Both are wire-format breaking, both touch the handshake JSON, both
modify the same `mqc.c` functions.  Splitting them into two flag
days serves no one.  The plans stay in separate files for trail
clarity, but the implementation is one commit.

---

## Issue #3 — Use transcript-bound HKDF

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #3.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 3.

### Verdict

**Agree with the assessment.**  The reviewer's recipe is essentially
a port of TLS 1.3's `Derive-Secret` construction (RFC 8446 §7.1):
take the handshake transcript, hash it, and feed it into HKDF as the
salt of `Extract`.  Then `Expand` per-direction key + IV from the
resulting PRK.  This makes the session keys depend on every byte the
peers exchanged, not just the ML-KEM shared secret.

### Why this matters beyond what issues #1 and #2 buy us

Issue-1 binds the transcript into the *signature* the peer verifies.
Issue-2 (info-string tag) binds version+suite into the *KDF*.
Neither prevents the keys themselves from being computed correctly
when an attacker tampers with bytes the signature doesn't cover —
e.g., JSON whitespace, a `version` field stripped before signature
verification, a malformed but-still-parseable suite string that a
buggy verifier accepts.

Issue-3 closes that gap: any divergence in what the two peers think
the transcript was produces a different `data_secret`, different
session keys, and AEAD failure on the first data frame.  It is the
defense-in-depth complement to signature-binding.

### The two-stage problem in encrypted-identity mode

The naive single-stage derivation
`HKDF-Extract(transcript_hash_full, SS)` works fine for clear-mode
(both peers know the full transcript before any encrypted byte goes
out).  Encrypted-identity mode breaks that property: the phase-2
identity blobs need to be *encrypted* before the receiver can know
the sender's `cert_index`, but the full transcript depends on both
`cert_index` values.

Fix: two HKDF-Extract operations, both with `IKM = SS`.  The first
uses `transcript_hash_phase1` (everything except the `cert_index`
fields) as salt and produces `early_secret`; the phase-2 identity
blobs are sealed with keys expanded from this secret.  The second
uses `transcript_hash_full` (the same construction with both
`cert_index` fields populated) as salt and produces `data_secret`;
data-plane traffic is sealed with keys expanded from this secret.

This is structurally close to TLS 1.3's
`handshake_secret` → `master_secret` split, but simpler: MQC has
only one input secret (no PSK, no early-data), so neither secret
needs to chain into the other.  Two independent Extract operations
on the same `SS` with different salts.

### Per-direction IVs (TLS 1.3 style)

The reviewer's recipe also calls out IVs ("derive `c2s_key`,
`s2c_key`, IVs, and finished keys").  Today MQC's nonce is purely
counter-derived (`mqc.c:269` `make_nonce`): `4 zero bytes ||
htobe64(seq)`.  TLS 1.3 (RFC 8446 §5.3) instead derives a 12-byte
per-direction `iv` and uses
`per_record_nonce = iv XOR (4 zero bytes || htobe64(seq))`.

Both constructions are AEAD-safe — the `(key, nonce)` uniqueness
property is preserved by the per-direction key, and per-direction
key is what actually matters for AES-GCM.  The TLS-1.3-style
derived-IV is a defense-in-depth bonus: it makes nonces
unpredictable across connections (the IV byte-prefix is per-
connection secret material) and prevents a nonce-prediction
analysis surface.  It costs four `wc_HKDF_Expand` calls per
handshake — negligible.

The plan adopts this construction.  No wire-format change is
implied; the per-direction IV is derived locally on each peer.

### Why this supersedes issue-2

Once the transcript hash carries `version` and `suite` (which
issue-1 puts there) and the transcript hash is the HKDF-Extract
salt (which issue-3 makes happen), the version/suite tag in the
HKDF info string is redundant.  Issue-2's info-string format is no
longer load-bearing for security; removing the tag would not
weaken anything.  The plan keeps the new info-string names anyway
because they're more readable in debugging output, but the
`"v0"` / `MQC_SUITE_STRING` substrings could be dropped without
affecting the cryptographic argument.

### Bytes-on-wire vs derived-keys

This is the rare wire-quiet protocol break: the same JSON bytes go
out, but the keys derived from them are different.  An old peer
(pre-issue-3) talking to a new peer (post-issue-3) would complete
the handshake successfully and then fail on the first data-plane
frame with a GCM tag mismatch.  Worth calling out because
"upgraded one end first" produces a more confusing failure mode
than the issue-1 wire-format break (which fails at JSON parse).

### Land it together with #1 and #2 or stage?

Both options work.  The plan recommends one combined cutover
because they all touch adjacent code, all break interop, and the
factsorlie.com deployment can absorb a single flag day more
cheaply than three.  If staging is preferred (easier bisect on
any post-cutover bug), land #1+#2 first and #3 second.

---

## Issue #4 — Add Finished messages

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #4.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 4.

### Verdict

**Agree.**  Finished is one of those constructions that looks
redundant on paper after issues #1 and #3 are in place — the
transcript is signature-bound, and the keys are transcript-bound,
so what does an additional MAC over the transcript buy?  The
answer is: it makes implementation divergence loud at the moment
it is detectable, instead of leaving it to manifest as opaque
AEAD failures three frames into application traffic.

This is exactly what TLS 1.3 cites as the rationale for Finished
(RFC 8446 §4.4.4) and the reviewer's "TLS does this for a reason"
is the right framing.

### What Finished catches that issues #1+#3 don't

Issues #1 and #3 cover the *cryptographic* failure modes — an
attacker who tampers with bytes the protocol accounts for.  They
do not cover *implementation* failure modes.  Concrete examples:

1. **Transcript-construction disagreement**.  One peer hashes the
   `cert_index` fields as 4-byte big-endian; the other hashes
   them as 4-byte little-endian.  Both signatures verify (each
   peer signs over its own construction; an attacker isn't
   involved).  Both AEAD frames go out cleanly.  But every
   subsequent frame fails to decrypt, because the keys were
   derived from divergent transcript hashes.  Without Finished,
   the failure surfaces as "first data frame: GCM tag mismatch"
   — opaque.  With Finished, the failure surfaces as "Finished
   MAC: mismatch" — pointing at the transcript-construction
   layer specifically.
2. **Verifier control-flow bug**.  An implementation refactor
   accidentally returns success from
   `wc_dilithium_verify_ctx_msg` without actually calling it
   (e.g., a wrapper that short-circuits on a cached lookup).
   Issue-1 thinks the signature was checked; it wasn't.  Issue-3
   doesn't help because both sides did agree on the transcript
   bytes.  Finished still works because the bug was in
   *signature verify*, not in transcript or key derivation.
   Wait — actually Finished doesn't catch this either, because
   the signing peer is honest and the keys derive correctly.
   Finished catches case (1), not case (2).  The reviewer's
   "implementation mismatch" framing primarily captures case (1).
3. **Field one peer didn't bother to bind**.  An on-path
   attacker flips a byte in a JSON field that's *parsed but not
   signed* — e.g., a future MQC extension field that the
   verifier ignores when computing the transcript hash.  The
   signature verifies (the attacker didn't touch signed bytes).
   The keys derive correctly on the *signing* side but not on
   the *receiving* side, because the receiver hashes the
   tampered byte into its `transcript_hash_full`.  AEAD fails on
   first data frame.  With Finished, the divergence shows up at
   handshake completion before any application byte goes out.

So Finished primarily defends against **construction
disagreements** between honest peers, and against **on-path
tampering of bytes outside the signature transcript**.  Both are
defense-in-depth properties; both are cheap (one HMAC + one AEAD
frame each direction).

### Why piggyback on the data-plane frame format

The plan reuses the data-plane AEAD frame format for Finished
rather than inventing a new "control frame" type.  Two reasons:

- **Structural symmetry**: Finished is the only post-handshake
  message that needs encryption.  Inventing a typed frame for
  one message in the protocol's lifetime is overkill.
- **Free key-mismatch detection**: AEAD-sealing the MAC means
  the receiver gets `wrong key` (AEAD-tag failure) and `wrong
  transcript` (HMAC mismatch) as distinct error states.  TLS
  1.3 makes the same choice for the same reason.

The "Finished is the first frame in each direction" rule is
sufficient to disambiguate it from data-plane traffic — no frame
type byte needed.

### Sequence-number bookkeeping

The plan uses Finished to absorb a small inconsistency that's
been accumulating across the issue plans.  Issue-1 had encrypted
mode start the data plane at `seq=1` (because the phase-2
identity blobs each consumed `seq=0`).  Issue-3 carved out
separate `early_*` keys for the phase-2 blobs, freeing the data
plane to start at `seq=0`.  Issue-4 makes the data plane start at
`seq=1` again, this time because Finished consumed `seq=0`.

The net result: across all four issues, the data plane begins at
`seq=1` in both modes.  This contract is documented in spec §9.2
once and stays true for the life of v0.

### Where Finished doesn't help

The plan calls out that Finished does not help with verifier
*control-flow* bugs (case 2 above).  It commits to the transcript
the signing peer used; if the verifying peer skips signature
verify entirely, Finished still verifies (both peers compute the
same transcript hash, both compute the same MAC).  The defense
against control-flow bugs is unit testing, not protocol design.

### Scope kept tight

The plan deliberately defers exporter keys, PSK resumption, and
re-keying — none of which exist in MQC v0.  The Finished MAC
itself is one HMAC + one AEAD frame per direction, gated by a
flag on the connection struct, with two new HKDF-Expand outputs
threaded through the issue-3 derivation tree.  The whole change
is roughly 100–150 lines of new C plus 8 tests.

### Land it together with #1, #2, #3 or stage?

Same recommendation as before: one combined cutover for #1+#2+#3+#4
on `phase-20` is the easiest path on factsorlie.com.  Each issue
adds wire- or behavior-affecting changes that no external client
needs to coordinate against.  If staging is preferred, #4 is the
smallest of the four and a fine "second cutover" after #1+#2+#3.

---

## Issue #5 — AEAD must authenticate frame headers

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #5.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 5.

### Verdict

**Agree, but the win is narrower than the reviewer's framing
suggests.**  The reviewer listed six fields to bind into AAD
(frame type, protocol version, sequence number, payload length,
direction, connection ID).  After issues #1, #3, and #4 land,
most of those are *already* bound by other means — sequence by
the per-frame nonce, direction by the per-direction key, version
and suite by the transcript-bound HKDF salt.  Connection ID
doesn't exist in MQC.  The two genuine gaps are **payload
length** (currently a plaintext wire prefix that nothing
authenticates) and **frame type** (currently a positional
distinction between Finished and data-plane application frames).

### Why this is "narrower" than TLS-style AAD binding

TLS doesn't have transcript-bound traffic keys in the same way
MQC does after issue-3.  In TLS, AAD is the primary mechanism
binding frame metadata to the ciphertext; in MQC after issue-3,
much of that binding already lives in the keys themselves.  AAD
in MQC is therefore mostly belt-and-braces for fields that are
already cryptographically separated, with two real wins:

1. **Length-prefix tampering becomes immediate AEAD failure** —
   today an attacker who flips a bit in the 4-byte length prefix
   either causes the receiver to truncate the read (AEAD fails
   on tag) or to over-read into the next frame's bytes (AEAD
   fails *and* framing desyncs).  With length in AAD, the
   diagnostic is clean ("this frame failed AEAD") rather than
   spilled across two frames.
2. **Frame type becomes a cryptographic distinction** — issue-4
   distinguishes Finished from application data purely
   positionally (Finished is the first frame after handshake).
   Adding a one-byte frame type into AAD pre-empts any future
   ambiguity if MQC ever adds key-update / alert / heartbeat
   frame types.  Cost: one byte.  Pre-emptive but free.

### What the plan does NOT add

- **Connection ID** — would require multipath / migration /
  session-resumption semantics that MQC v0 doesn't have.
- **Per-frame version negotiation** — a single version byte
  goes into AAD for forward compat, but actual cross-version
  negotiation is a separate spec change.
- **Variable-length AAD** — fixed 31 bytes per frame.  If
  future control-frame types need richer headers, bump the AAD
  label to v2 and re-cut.

### Frame type taxonomy

The plan defines three frame types that map cleanly onto MQC's
existing AEAD-sealed wire contexts:

| Type | Value | Keys used | Sequence | Sender |
|---|---|---|---|---|
| `PHASE2_IDENTITY` | 0x01 | `early_*_key` | 0 | encrypted-mode handshake |
| `FINISHED` | 0x02 | `data_*_key` | 0 | both sides, after handshake |
| `APP_DATA` | 0x03 | `data_*_key` | ≥ 1 | application traffic |

Phase-2 blobs are already cryptographically separated from
Finished and data by the `early_*` vs `data_*` key split
(issue-3); the type byte is belt-and-braces there.  Finished and
APP_DATA share keys, so the type byte is the only AEAD-level
distinction between them — meaningful even today, load-bearing if
new control types are added later.

### Wire-quiet, behavior-breaking

This is the second wire-quiet issue (issue-3 was the first):
bytes-on-wire don't change, AAD bytes are local to each peer,
but a peer running pre-issue-5 sees AEAD AUTH_FAIL against a
peer running post-issue-5 from the very first frame.  Same
flag-day cutover semantics; same one-deployment factsorlie.com
runbook.

### Land it together with #1–#4 or stage?

Same recommendation as before.  Issue-5 is the smallest of all
five plans (~50 LoC, four call sites) and bundles cleanly with
the others.  If staging is preferred for bisect-friendliness on
post-cutover bugs, #5 is also a fine standalone second-cutover
after #1–#4 land.

---

## Issue #6 — Encrypted-identity authentication gaps

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #6.
subsumed by issue #1).
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 6.

### Verdict

**Agree, but no separate work.**  Every binding the reviewer asked
for — `EK_c`, `CT_s`, mode, server role — is in the transcript
construction defined by issue #1.  All four code sites
that need editing are in issue-1's code-edit list.  The
`neg-mqc-id-replay` test that proves the constant-blob hole is
closed is in issue-1's test coverage.  When issue-1 lands, issue
#6 closes automatically.

### What the implementation actually did vs. what the spec said

This was the most striking finding of the issue-1 analysis: the
reviewer described the *spec* gap (signature covers only `CT_s`),
but the *implementation* at `mqc.c:1573-1588` was strictly worse
— it signs the literal C string `"mqc-id:<cert_index>"`, a
constant per identity.  Any past server-identity blob from
cert_index N is replayable forever as a valid server-identity blob
for cert_index N in any future encrypted-identity handshake,
without the attacker ever needing the server's private key.  The
encrypted-identity ServerHello today provides effectively zero
handshake binding on the server→client direction.

Issue-1's transcript-binding closes both the spec gap (signature
covers the full transcript including `EK_c`, `CT_s`, mode, role,
both `cert_index` values, version, suite) and the implementation
gap (the `"mqc-id:N"` constant is replaced with a real
transcript signature) in the same change.

### Why the stub plan exists

Trail completeness.  The `mqc-issue-N.plan` series has files for
issues #1–#5; skipping #6 because "it's subsumed" would leave a
gap that future readers might mistake for an unfinished item.  A
short stub explaining the subsumption is cheaper than the
ambiguity of a missing file.

---

## Issue #6a — Expose operational tunables in /etc/postWolf/config

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #6a.
Source: side-track raised during issue #6 review (not in
[`README-mqc-1-issues.md`](./README-mqc-1-issues.md)).

### Verdict

**No security finding; pure operability hygiene.**  Several
constants that an operator might legitimately want to tune (per-
deployment threat model, slow-network handshake budgets,
revocation-cache TTL) are presently either compiled-in via
`config.h` `#ifndef` (overridable only at build time) or
hardcoded in `mqc.c` (not overridable at all).  The existing
`/etc/postWolf/config` file already carries URL knobs through an
Augeas-parsed INI file (`mtc-keymaster/read-config/`); the plan
adds an integer accessor parallel to the existing `read_config_url`
and routes ten knobs through it.

### What is and isn't a knob

The dividing line: **operational** constants (timeouts, rate
limits, cache TTLs, frame-size ceilings) become runtime
overrides; **protocol invariants** (suite IDs, label strings,
HKDF info strings, AAD format, transcript construction, frame
types, version number) stay compiled-in.  The reasoning is the
"Deployment model" rule at the top of this file: protocol
invariants change only via flag-day cutovers; if they're not
runtime-tunable they can't be tuned wrong.

The knob list:

- **Promote from `config.h` to runtime** (4 keys): handshake
  stall + total seconds, revoked-cache TTL, signature
  freshness window.
- **Promote from `mqc.c` hardcoded to runtime** (6 keys): four
  rate-limit buckets (connect-per-min/hour, fail-per-min/hour),
  two frame-size ceilings (handshake, data).

Spec §11.3 says implementations MAY lower the frame-size
ceilings but MUST NOT raise them.  The plan enforces this
automatically: a config-file value above the compiled-in cap is
silently clamped at parse time.  Right failure mode (no peer
speaks frames larger than the cap; raising would just fail at
the peer) and zero extra plumbing.

### Resolution precedence

For each knob:
1. Runtime — value in `[global]` section of
   `/etc/postWolf/config`, parsed via Augeas.
2. Build-time — `-DMQC_…=…` at compile, picked up by the
   `config.h` `#ifndef`.
3. Compiled default — the value baked into `config.h` /
   `mqc.c`.

The compiled default is always the floor for sanity-check
failures (negative, zero, or unparseable runtime values fall
back to the compiled default with a stderr warning).

### Why this is safe to deploy without coordination

Unlike issues #1–#5, this plan is wire-quiet *and* behavior-
conservative.  An MQC binary upgraded with the issue-6a code but
running against an unmodified `/etc/postWolf/config` behaves
**exactly** like a pre-issue-6a binary: every knob falls back to
its compiled default, which is the same default that's been
hardcoded since the original code.  No client-side coordination
required, no flag-day, no incompatibility window.

This makes 6a a fine "ship-anytime" change — it can land before,
between, or after any of issues #1–#5 without affecting the
others.

### Why this isn't issue #7

Issue #7 (mandatory revocation policy) is a separate concern in
the reviewer's list.  6a only touches the cache TTL of revocation
queries, not the policy of whether to make them.  Issue #7's
plan, when written, layers on top of 6a's TTL knob (the cache
becomes mandatory; the TTL controls how aggressively it refreshes).

### Scope kept tight

The plan deliberately does NOT add: live SIGHUP-based reloading,
per-tool client-only overrides, dynamic suite negotiation,
exposure of any cryptographic constant, equivalent runtime
overrides for SLC or MQCP (those would be separate plans
following the same pattern).  The minimum viable change is the
ten operational knobs and the read-config accessor.

---

## Issue #7 — Revocation should be mandatory

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #7.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 7.

### Verdict

**Agree.**  Today the spec says "MAY query" and the
implementation has the asymmetry exactly backwards: server checks
revocation on incoming clients, client does NOT check revocation
on the server it's about to disclose data to.  And on either
side, a query failure (network error, log down) silently
degrades to "skip" — fail-open by default.  Both gaps close
together by making revocation mandatory on both sides and
fail-closed on query failure, with a single `mqc-revocation-policy`
opt-out (`mandatory` / `cache-only` / `disabled`) for emergency
recovery.

### Why "mandatory" is the right default

The MTC trust model puts revocation on the same trust-axis as
the cosigner-signed checkpoint: both are how the log endpoint
communicates "this identity is or isn't trustworthy."  Treating
the cosignature as MUST and the revocation as MAY would be
asymmetric in a way the threat model doesn't justify — a
revoked-but-not-yet-removed identity is exactly the case
revocation is for, and skipping the check defeats the purpose.

### Why an explicit `disabled` opt-out exists

There is one legitimate scenario for skipping revocation: the
log endpoint has been catastrophically lost (DNS hijack,
permanent compromise, regulator takedown) and an emergency
operator needs to bring up replacement infrastructure before
restoring the log.  In that scenario, every handshake would
otherwise abort.  The `disabled` policy lets the operator opt
in to "trust whatever's cached, and don't query," with a loud
warning at handshake time so the dangerous mode is visible in
`journalctl`.

The `cache-only` middle ground covers the milder case where the
log endpoint is temporarily unreachable but caches are still
valid.

### How this layers on issue 6a

Issue 6a exposes `mqc-revoked-cache-ttl-sec` (how long a
"not-revoked" answer stays cached).  Issue #7 adds
`mqc-revocation-policy` (whether the cache is allowed to be a
fallback at all).  Operators tune them together: tight TTL +
mandatory policy = aggressive checking; long TTL + cache-only
policy = lower-load mode for stable steady state.

---

## Issue #8 — Cert retrieval is self-verifying, not transport-trusted

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #8.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 8.

### Verdict

**Agree, but with a smaller delta than the reviewer's framing
suggests.**  MTC certs are already self-verifying by design —
spec §10 walks through the four mandatory checks (inclusion
proof, cosignature on the checkpoint, revocation, and the
already-existing cosigner-pubkey trust anchor).  The plan does
three things on top:

1. **Make the spec's strict reading explicit.**  Today §10.1
   reads "retrieval MAY be performed via HTTP" as permissive;
   the strict reading is "the transport MUST NOT be trusted;
   §10.2-§10.5 MUST run on whatever bytes the transport
   returns."  Rewrite §10.1 to say so.
2. **Add a missing check: cert validity window** (`not_before` /
   `not_after` per a new §10.6).  Today the implementation
   accepts an expired cached cert.
3. **Add cosigner-pubkey-fingerprint cache invalidation** so a
   stored "verified once" cert under cosigner A is not silently
   trusted when the operator rotates to cosigner B.

The cryptographic content was largely correct; the spec wording
and the fingerprint-rotation handling are the real gaps.

### Why a cosigner-rotation invariant matters

`admin_recosign` (the cosigner-rotation tool, per
`mtc-keymaster/README.md`) replaces the cosigner pubkey.
Without an invariant tying each cached cert to the cosigner
that signed its checkpoint, a verifier could accept a cert
verified under the old cosigner long after rotation — defeating
the rotation's whole purpose.  Storing
`~/.TPM/peers/<index>/cosigner-fingerprint.txt` alongside the
cached cert closes this with one extra file per cache entry.

### What's still cosigner-bootstrap territory

The first-contact "how do I know this cosigner pubkey is real?"
problem is tracked in
`mtc-keymaster/README-bugsandtodo.md` TODO #9b and addressed by
the leaf-bootstrap and CA-bootstrap branches in
`/home/ubuntu/.claude/plans/lets-plan-to-implement-snoopy-rivest.md`.
This plan assumes the cosigner pubkey is already trusted.

### Negative tests as the load-bearing piece

The biggest delta this plan ships is the **8 negative tests**
proving each spec-required check actually triggers under
adversarial input (HTTP MITM substitute, HTTP MITM corrupt,
expired cert, not-yet-valid cert, cosigner rotation with stale
cache, empty body, content-type spoof).  Without these, the
"cert is self-verifying" property is asserted in spec but not
demonstrated; with them, every check becomes regression-tested.

---

## Issue #9 — Server-name / expected-identity check

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #9.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 9.

### Verdict

**Agree.**  This is the MQC equivalent of TLS hostname
verification, and it's the gap that the most-paranoid design
review usually notices: "you authenticated *some* identity from
the log; you didn't authenticate the *intended* identity for
the URL the user typed."

### The substituted-server attack

The plan's key motivating attack: two real servers in the same
log, certs A and B.  Client dials A's hostname.  Active attacker
redirects TCP to B's address.  B is honest — it returns its own
cert_index Y, signs the transcript correctly under issue-1's
binding, the cert verifies via inclusion proof and cosignature
under issue-8's checks, the cert is not revoked under issue-7's
policy.  Everything passes, and the client now believes it's
talking to A while actually talking to B.

The fix isn't cryptographic — it's a one-line semantic check:
"does the cert at index Y list A's hostname in its subject DNS
names?"  If not, abort.  This is §10.7 in the spec, plus the
`mqc_cert_name_matches` helper in `mqc_peer.c`.

### Why "fail closed for IP literals"

An operator who dials `192.0.2.1:8446` directly has bypassed the
DNS-binding loop that makes the name check meaningful.  Two
options: silently skip the check (risky — operator might not
know they have no name protection), or fail closed and demand
explicit `--expected-name <hostname>` or `--no-name-check`.

The plan picks fail-closed.  The operator who dials an IP
intentionally is also the operator who can supply
`--expected-name` intentionally; the operator who dials an IP
by accident gets a clear error instead of a silent
loss-of-protection.

### Wildcards explicitly out

MTC subject schema doesn't currently define wildcards.
Implementing wildcard semantics on the verifier without a
spec-defined wildcard format would be a unilateral extension,
and wildcard-matching is its own design rabbit hole (label-only?
IDNA?).  V0 is exact-match only; if a cert needs to vouch for
multiple hostnames, list them all.

### Pre-deploy operator audit

The one wrinkle: this plan's enforcement breaks any cert that
*doesn't* list its public hostname in the subject.  Pre-deploy
audit of the live log (`show-tpm --list-peers`) confirms each
deployed peer's cert lists its dial hostname.  For
factsorlie.com specifically, a known-good audit pass before the
cutover is part of the runbook.

---

## Issue #10 — Downgrade protection on identity-mode selection

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #10.
subsumed by issue #1).
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 10.

### Verdict

**Agree, but no separate work.**  The reviewer's two specific
requirements — explicit mode field on the wire and mode bound
into signatures — are both already in issue #1.

Issue-1 adds `mode` as a top-level handshake JSON field and
includes its `mode_id` byte (0x00 for clear, 0x01 for encrypted)
in the transcript hash that every signature covers.  Issue-1
also adds a shape-vs-value consistency check in
`auto_accept_detect`: reject as malformed if `mode="clear"` but
no `cert_index`, or if `mode="encrypted"` with `cert_index`
present.  Together these defeat both attacker substitution and
implementation bugs.

When issue-1 lands, issue #10 closes automatically.  The stub
plan exists for trail completeness — same reasoning as the
issue-6 stub.

---

## Issue #11 — Strict JSON parsing on the handshake

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #11.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 11.

### Verdict

**Agree.**  The reviewer's framing ("you removed ASN.1, but JSON
has its own hazards") is exactly right.  Default-flag json-c
silently accepts: duplicate keys (last-wins), trailing garbage
after `}`, json-c-specific extensions (C-style comments, leading
zeros, single quotes, trailing commas), and integer overflow
(silent saturation at INT_MAX).  Each of these is a potential
desync between the bytes the signer hashed and the values the
verifier extracted.

### What's actually exploitable today

The most concerning case is **duplicate-key smuggling**: a
modified-in-flight handshake with two `"cert_index":` keys,
where the parser uses the second value (last-wins) but the
signature verifier might hash the first value's string
representation.  Whether this is exploitable depends on the
parser and the signer agreeing on which duplicate wins; the
fact that *which* wins is implementation-defined is itself the
attack surface.

**Trailing garbage** is less directly exploitable for MQC but
matters for downstream tools (audit log pipelines that re-parse
the same JSON with different libraries).

**Integer overflow** matters once issue-1 binds `cert_index`
into the transcript hash: signer hashes "9999999999" as a
string, verifier parses to INT_MAX, divergence.

### Why field-set validation matters

After all expected fields are read, the plan walks the object
and rejects any **unknown** top-level field.  This is the
opposite of TLS's "ignore unknown extensions" principle, and
it's the right call for v0: there is no extension registry, so
any field outside the defined set is suspicious.  When an
extension registry exists later, this rule relaxes for
registered prefixes (e.g., `x-`).

### Intersection with issue 12

The hex-length validators (`mqc_json_get_hex_strict(…,
expected_byte_len, …)`) are the implementation of issue-11's
strict reading; issue-12 makes them the canonical pre-crypto
guard.  The two plans depend on each other in opposite
directions: issue-11 introduces the helper, issue-12 calls it
load-bearingly.

### What's NOT in this plan

**Canonical JSON serialization** (RFC 8785) is deferred.
Issue-1's transcript hash binds field values, not the raw JSON
bytes — so canonical serialization isn't load-bearing for
security.  If a future feature hashes raw JSON (audit log
signing), revisit.

**JSON Schema** validation is deferred — overkill for ~6
fields; the per-field strict readers are the lightweight
equivalent.

---

## Issue #12 — Cheap pre-crypto filters and tighter DoS budgets

Status: see [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) row #12.
Source review: [`README-mqc-1-issues.md`](./README-mqc-1-issues.md), item 12.

### Verdict

**Agree, with a smaller delta than the reviewer suggests.**  A
substantial DoS surface is already addressed: per-IP rate
limits (Redis-backed, per-minute and per-hour, both for connect
attempts and handshake failures), AbuseIPDB integration,
handshake timeouts (3s per-read, 5s total), maximum handshake
frame (128 KiB).  What's left is four targeted improvements:

1. **Pre-crypto byte-length validation** (`kem_pub` exact
   1184 bytes client→server / 1088 bytes server→client;
   `signature` exact 4627 bytes).  Today an attacker who sends
   garbage of the right *shape* (parseable JSON, parseable hex,
   wrong byte count) burns ML-DSA verification budget before
   the wrong-size mismatch surfaces.  One length comparison per
   field eliminates the whole class.
2. **Per-(IP, cert_index) throttling** to defeat
   index-rotation attacks within the per-IP envelope.  Same
   Redis pattern, two new runtime knobs (`mqc-rl-cert-per-min`,
   `mqc-rl-cert-per-hour`).
3. **Total handshake-bytes-in-flight cap** with an atomic
   counter, defending against memory-exhaustion via many
   concurrent half-open handshakes.
4. **Bounded LRU cache** on the per-cert verify cache —
   already exists in spirit per spec §10.1 SHOULD, but
   verify the cache size is capped (`mqc-cert-cache-max-entries`,
   default 1024 ≈ 4 MiB).

### What's NOT in the plan

- **Client puzzles / proof-of-work**.  The reviewer suggests
  these as optional.  V0 with a single deployment behind a
  cloud-provider WAF doesn't justify the wire-format addition
  (would require a server-issued token before the first
  ClientHello — extra round trip) or the operator burden (PoW
  difficulty tuning).
- **TCP-level rate limits** (iptables, fail2ban) — already
  RECOMMENDED in spec §12.6, orthogonal to MQC code.
- **Adaptive thresholds** that tighten under CPU pressure —
  feedback-loop complexity not justified at current scale.

### Intersection with issue 11 (the symmetric pair)

The pre-crypto length guards (item 1) live in
`mqc_json_get_hex_strict(…, expected_byte_len, …)` — the helper
issue-11 introduces.  Issue-11 owns the **parser strictness**;
issue-12 owns the **rate-limiting wiring** of length-failure
into `mqc_ratelimit_fail_record(client_ip)`.  Both plans
together close the "burn ML-DSA cycles on malformed input"
attack surface.

### Why "wire-quiet, behavior-conservative"

A legitimate peer producing correctly-sized fields and
rotating `cert_index` at human rates (i.e., never) sees no
behavior change.  The new rejections only fire on
non-conformant or malicious clients, which by definition
aren't the operator's friends.

---

<!-- All 12 reviewer-issue plans are written.  Issue 6a (operational
     tunables in /etc/postWolf/config) is the only side-track plan.
     If new issues are filed, add an analysis section above this
     line and create the corresponding mqc-issue-N.plan file. -->
