# MQC reviewer findings — outstanding items, prioritized

**Branch:** `phase-23` &nbsp;·&nbsp; **HEAD:** `c22e045fe` &nbsp;·&nbsp;
**Compiled:** 2026-05-06

This file rolls up the open items across the four reviewer
documents in this directory:

- [`README-mqc-1-issues.md`](./README-mqc-1-issues.md) — the
  earliest external review (12 items) that drove the Phase 1–3
  hardening pass.  All 12 closed; carried here for completeness
  and for the per-row commit map.
- [`README-mqc-2-issues.md`](./README-mqc-2-issues.md) — second
  10-finding review and the Phase 1/2/3/4/5/6 master plan
- [`README-mqc-3-issues.md`](./README-mqc-3-issues.md) — DNSSEC
  bootstrap proposal + drop-in `mqc_dnssec_pin.c`
- [`README-mqc-4-issues.md`](./README-mqc-4-issues.md) — TLS 1.3
  security-property map and the six highest-priority fixes

It does **not** re-derive the analysis — the source documents are
canonical.  This file is a checkpoint that says *what is still open
right now* so the next session can pick up the highest-impact item
without re-reading 1,170 lines of review traffic.

---

## At-a-glance scorecard

| Source | ID | Title | Status |
|---|---|---|---|
| mqc-1 | #1 | Sign full transcript | **DONE** (`6b4c380b6`) |
| mqc-1 | #2 | Protocol version + suite ID | **DONE** (`6b4c380b6`) |
| mqc-1 | #3 | Transcript-bound HKDF | **DONE** (`6b4c380b6`) |
| mqc-1 | #4 | Finished MAC frames | **DONE** (`6b4c380b6`) |
| mqc-1 | #5 | AEAD authenticates frame headers (AAD) | **DONE** (`6b4c380b6`) |
| mqc-1 | #6 | Encrypted-mode auth gaps | **DONE** (`6b4c380b6`, `a287aa8d0`) |
| mqc-1 | #7 | Mandatory revocation policy | **DONE** (`04ad93f5f`) |
| mqc-1 | #8 | Cert self-verification audit | **DONE** (`089a3966a`) |
| mqc-1 | #9 | Server-name / expected-identity check | **DONE** (`890e27137`) |
| mqc-1 | #10 | Downgrade protection | **DONE** (`6b4c380b6`) |
| mqc-1 | #11 | Strict JSON parsing | **DONE** (`ee9977b71`) |
| mqc-1 | #12 | DoS pre-crypto filters + per-(IP,cert) RL | **DONE** (`615d0e9ba`) |
| mqc-2 | #1 | Length-prefixed handshake frames | **DONE** (P1, `45e8390d4`) |
| mqc-2 | #2 | Brace-count JSON reader | **DONE** (P1, `45e8390d4`) |
| mqc-2 | #3 | Cosigner TOFU on first contact | **LEAF BRANCH DONE** 2026-05-06; CA branch + show-tpm surface still TODO #9b |
| mqc-2 | #4 | Pubkey-hash binding to cert | **DONE** (P2, `dfd06d187`) |
| mqc-2 | #5 | Revocation drop-and-retry first-contact | **DONE** (TODO #58 fix, `0c573bffb`, 2026-05-06) |
| mqc-2 | #6 | Field-based vs raw-frame transcript | **DEFERRED** — TODO #54 (LOW) |
| mqc-2 | #7 | AEAD recv seq before verify | **DONE** (P3, `88b7fadbe`) |
| mqc-2 | #8 | Stale "encrypted is stub" docs | **DONE** (P4, `627d28bab`) |
| mqc-2 | #9 | Auto-detect MSG_PEEK + strstr | **DONE** (P1, `45e8390d4`) |
| mqc-3 | DNSSEC TXT pinning for 8445 (server) | CA enrollment DNSSEC validation | **DONE** (`bf21e4fc9`, `bdbf08309`) |
| mqc-3 | §1.4 | Pre-auth proof-of-work | **OPEN** — TODO #59 (defense-in-depth) |
| mqc-3 | §1.5 | CA key continuity (new key signed by old) | **OPEN** — *not yet tracked*; recommend opening TODO |
| mqc-4 | #1–#3, #5, #6 | (length-prefix / pubkey-hash / DNSSEC / inclusion-proof / AEAD seq) | **DONE** |
| mqc-4 | #4 | Exact canonical handshake-frame bytes in transcript | **DEFERRED** — TODO #54 (LOW) |

Plus, from the Gemini security review (separate file, just triaged):

| Gemini ID | Status |
|---|---|
| MQC-01 (server-identity leak in `mqc_accept_auto`) | **DONE** + guard shipped 2026-05-06 (`c22e045fe`) |
| MQC-02 (DoS via asymmetric work) | **OPEN** — same TODO #59 as mqc-3 §1.4 |
| MQC-03 (ERANGE desync) | **CLOSED** (already mitigated by `mqc_json_get_int_strict`) |

---

## Outstanding work, prioritized

**mqc-1 contributes nothing to the open list — every one of its
12 reviewer items shipped during the Phase 1–3 hardening pass
(per the status table at the bottom of `README-mqc-1-issues.md`).
Its inclusion in this summary is a closure record, not a backlog.**

### P0 — load-bearing security gap

#### Cosigner TOFU on first contact (mqc-2 #3 / TODO #9b)

The cosigner pubkey is the root of trust for every Merkle proof
the MQC handshake verifies.  Today, a first-contact client
(`show-tpm`, `bootstrap_leaf`, `bootstrap_ca`, MQC peer that has
no `~/.TPM/ca-cosigner.pem` yet) fetches it over the
unauthenticated 8445 bootstrap port and TOFUs the result.  An
on-path attacker on that first fetch can substitute their own
cosigner key and every subsequent MQC handshake — no matter how
hardened — verifies against the attacker's forged log.

**Status of the snoopy-rivest plan**
([`~/.claude/plans/lets-plan-to-implement-snoopy-rivest.md`](../%7E/.claude/plans/lets-plan-to-implement-snoopy-rivest.md)):

- **Leaf branch** (operator-pasted `--cosigner-fp` alongside the
  enrollment nonce; bootstrap response signed with the cosigner
  key; client verifies the signature before trusting the cosigner
  PEM): **NOT SHIPPED.**
- **CA branch** (bootstrap response also signed with the parent
  CA's already-trusted X.509 TLS private key; client validates
  the chain against the system CA store + SAN match): **NOT
  SHIPPED.**
- **DNSSEC server-side check that an enrolling CA controls its
  domain** (`_mqc-ca.<domain>` TXT record validation in
  `mtc_http.c` / `mtc_dnssec_pin.c`): SHIPPED.  But this is a
  *different* trust direction — the SERVER authenticates the
  ENROLLING CA, not the CLIENT authenticating the SERVER.

**Recommended next move:** ship the leaf branch first (smaller,
operator-paste already exists for the nonce, so the cosigner-fp
delivery channel is free).  The CA branch + the `show-tpm`
first-contact surface follow as separate cutovers.  Each branch
is a wire-format addition that requires a flag-day rebuild per
CLAUDE.md "MQC wire-format invariants are NOT operator-tunable",
so plan the rollout accordingly.

### P1 — medium-priority gap that has no TODO yet

#### CA key continuity (mqc-3 §1.5)

> "If a CA already exists: new_key must be signed by old_key.
> Prevents silent key takeover."

A fresh CA enrollment with the same subject as an existing CA
should not be able to silently overwrite the existing CA key.
The reviewer's recommendation: require the new public key to
arrive in an enrollment payload signed by the previous CA key,
unless an explicit operator-flagged emergency-recovery mode is
used.

**Current state:** TODO #57 item 1 (idempotency by
`(subject, spk_hash)`) returns the *same* cert when the same key
re-enrolls.  But it does not handle a *different* key for the
*same* subject — that path has no continuity check today.

**Recommended next move:** open a new TODO entry capturing the
threat model and the policy ("new spk_hash for an existing
subject requires either a sig under the prior CA key or an
operator-acked emergency-recovery flag") so future Claude
sessions can pick it up.

### P2 — defense-in-depth, already filed

#### Pre-auth client puzzle (Gemini MQC-02 / mqc-3 §1.4 / TODO #59)

OPEN as TODO #59 in
[`mtc-keymaster/README-bugsandtodo.md`](../mtc-keymaster/README-bugsandtodo.md).
Layered defenses already make a flood expensive (per-IP +
per-cert RL, mqc-max-children, handshake total deadline,
pre-crypto length filter).  A pre-auth HMAC-cookie or hashcash
gate would close the residual "one TCP connection per IP-bucket
budget = one ML-KEM decap" amplification but is not urgent.

### P3 — explicitly deferred / LOW

#### Raw-frame canonical transcript binding (mqc-2 #6 / mqc-4 #4 / TODO #54)

The reviewer prefers binding the exact handshake-frame bytes
into the transcript hash; postWolf binds a structured field
sequence (LABEL ‖ version ‖ mode ‖ SUITE_ID ‖ KEM ‖ cert_index ‖
role) per spec §6.0, the TLS-1.3-aligned design choice.
Tracked as TODO #54 LOW; no security gap on the current code,
purely a parser-canonicalization cleanup.

---

## Cross-check against the TLS-1.3 property map (mqc-4)

The mqc-4 table includes property rows that aren't part of the
six numbered fixes.  Quick state check:

- **Forward secrecy** ("ensure KEM key material is ephemeral per
  session"): the MQC handshake calls `wc_KyberKey_MakeKey` per
  accept and discards keys after use; the per-direction AEAD keys
  are derived per session via HKDF — no static key reuse on the
  wire.  Verdict: matches the property; no follow-up needed.
- **Replay resistance** ("add explicit anti-replay policy for
  registration and handshake"): nonces are 128 bits,
  one-time-use, expire (operator-tunable); the handshake
  transcript binding + Finished MAC defeat replay of the
  handshake.  Registration replay is gated by nonce consumption
  in `mtc_db`.  Verdict: covered; no follow-up needed.
- **Identity privacy** ("document and test it fully"):
  encrypted-mode is documented in spec §7 + README.md; the new
  `mqc_accept_auto` guard (Gemini MQC-01) prevents accidental
  cleartext-identity dispatch when `encrypt_identity=1`.
  Verdict: covered.
- **Parser robustness** ("weakest implementation area"):
  strict-mode + UTF-8 + duplicate-key + unknown-key + length-
  prefix + trailing-byte stack rejects every malformed-payload
  class the reviewer flagged.  Replacing json-c entirely is
  scope-creep; deferred indefinitely.

---

## Recommended attack queue for the next session

1. **TODO #9b leaf branch** (operator-paste cosigner-fp on
   `bootstrap_leaf`): biggest impact-per-effort.  Closes the
   leaf-side MitM completely; reuses the existing nonce delivery
   channel; about a day of work + a flag-day cutover.
2. **CA key continuity** (open the TODO; small implementation
   afterward): protects against silent CA-key takeover; tightly
   scoped to the enrollment dedup path that already exists from
   TODO #57.
3. **TODO #9b CA branch** (X.509-chain authenticated bootstrap
   response): closes the CA-side MitM.  Larger scope (loads TLS
   cert + key into the bootstrap thread, adds chain validation in
   `bootstrap_ca`); plan calls for it to follow the leaf branch.
4. TODO #59 (pre-auth puzzle): defense-in-depth; only after the
   above three.

Everything else is either DONE, deferred-LOW, or out of scope.
