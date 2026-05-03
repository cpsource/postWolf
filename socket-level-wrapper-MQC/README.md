# socket-level-wrapper-MQC — Merkle Quantum Connect

This directory holds the reference implementation, specification,
and design documentation for **MQC** (Merkle Quantum Connect), a
post-quantum authenticated transport that postWolf uses for
machine-to-machine APIs in place of TLS 1.3.

## What MQC is, in two paragraphs

MQC is a TCP-based authenticated bidirectional byte stream that
uses **ML-KEM-768** for ephemeral key establishment, **ML-DSA-87**
for long-term peer identity and handshake binding, **HKDF-SHA256**
for session-key derivation, and **AES-256-GCM** for bulk
confidentiality and integrity.  Every primitive on the wire
targets at least NIST Category 3 against a quantum adversary, and
the same ML-DSA-87 key signs the **transparency-log checkpoint**
(via the cosigner) so the chain of trust has no pre-quantum
hedge.  No X.509, no ASN.1, no certificate chains: peers identify
each other by `cert_index` — an integer referencing their entry
in a public **Merkle Tree Certificate** ([MTC]) log — and the
cert itself is fetched out of band and verified against the
log's signed checkpoint.

The handshake is a 2-frame JSON exchange in **clear-identity
mode** (the default; both `cert_index` values appear in the wire
JSON) or a 4-frame exchange in **encrypted-identity mode** (the
identity frames are AEAD-sealed under an "early secret" derived
from an anonymous KEM phase, so a passive observer learns
neither endpoint's identity).  Encrypted mode is currently a
stub in the reference implementation; clear mode is the
production path.  The full key schedule (per-direction keys,
per-direction IVs, per-direction Finished MAC keys) is HKDF-
Expand'd from a single Extract whose salt is the SHA-256
**transcript hash** that covers every byte both peers exchanged,
so any divergence (signer vs verifier view of the bytes,
on-path tampering of metadata) surfaces as a clean Finished MAC
failure rather than as an opaque AEAD failure deep into
application traffic.

## Where to look

| File | What it is |
|---|---|
| [`draft-page-mqc-protocol-00.md`](./draft-page-mqc-protocol-00.md) | **The spec** — normative wire format, key schedule, peer-verification chain, security considerations.  Renderable to plain text via `python3 render-draft.py draft-page-mqc-protocol-00.md > draft-page-mqc-protocol-00.txt`. |
| [`mqc-master.plan`](./mqc-master.plan) | **What changed and when** — the master plan for the Phase 0–7 hardening pass, including the dependency graph between issues and the cumulative spec deltas. |
| [`mqc-issue-{1,2,3,4,5,6,6a,7,8,9,11,12}.plan`](./) | **Why each design decision was made** — per-issue plans that document the threat the change addresses, the alternative designs considered, and the migration runbook. |
| [`README-mqc-issues.md`](./README-mqc-issues.md) | The original external security-review issue list (12 items) that drove the Phase 1–3 hardening. |
| [`README-plans.md`](./README-plans.md) | Per-issue analyses: deployment model, wire-format-break categorization, the "this is a single-deployment protocol so flag days are fine" rule. |
| [`mqc.h`](./mqc.h), [`mqc.c`](./mqc.c) | Public API + clear-mode handshake implementation.  See `mqc_connect`, `mqc_accept`, `mqc_ctx_set_expected_name`. |
| [`mqc_peer.h`](./mqc_peer.h), [`mqc_peer.c`](./mqc_peer.c) | Peer-verification chain: cert fetch, Merkle inclusion proof, ML-DSA cosignature verify, revocation check, validity-window check.  See `mqc_peer_verify`. |
| [`tests/test_name_check.c`](./tests/) | Issue-#9 expected-identity-check regression test. |

## Spec sections at a glance

The 14-section spec (post-Phase-5 cumulative edit) is organized:

1. **Introduction** — context, goals, non-goals.
2. **Conventions and Terminology** — RFC 2119 + MQC-specific terms.
3. **Protocol Overview** — sequence diagram + identity-mode summary.
4. **Cryptographic Primitives** — algorithm table + suite identifier.
5. **Wire Format** — common framing, handshake JSON shape, strict-parsing rules.
6. **Handshake (clear-identity mode)** — transcript construction, frame definitions, signature inputs.
7. **Handshake (encrypted-identity mode)** — 4-frame variant; impl-status note.
8. **Key Derivation** — HKDF-Extract+Expand schedule, Finished frame.
9. **Data Plane** — frame structure, AEAD AAD, nonce construction.
10. **Peer Verification** — cert retrieval, signature verify, Merkle proof, cosignature, revocation, validity, expected-identity.
11. **Operational Parameters** — knob registry table, timeouts, rate limits, message sizes, default port, revocation policy, server concurrency cap.
12. **Security Considerations** — quantum resistance, nonce management, identity exposure, revocation-cache staleness, cosigner compromise, DoS, transcript binding, AAD, identity vs authority, JSON parsing.
13. **IANA Considerations** — TCP port 8446 registration request.
14. **References** — normative + informative.

Plus three informative appendices: A (worked example from a live
handshake), B (reference implementation pointer), C (changes from
prior text — section-by-section changelog of the Phase 1–5 edits).

## Quick start (operator)

```sh
# Build + install (from postWolf root):
./make-all.sh

# Confirm the service is up + the default knobs are picked up:
sudo systemctl restart mtc-ca.service
sudo journalctl -u mtc-ca.service -n 10 | grep -E "max-children|MQC listener"

# End-to-end roundtrip:
echo hi | mqc --encode --env --no-cache | mqc --decode --env --no-cache

# Aggregate regression suite:
make -f Makefile.tools test-mqc-all

# Performance snapshot:
make -f Makefile.tools test-mqc-perf
```

For tuning the operational knobs in `/etc/postWolf/config`, see
`mtc-keymaster/read-config/config.server` and spec §11.
