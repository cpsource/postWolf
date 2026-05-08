# fips-framework discussions

A running log of design / threat-model questions raised while building
out the framework, with the answers reasoned through at the time.
Captured here so future Claude sessions (and humans) don't have to
re-derive the same conclusions.

---

## 2026-05-08 — three threat-model questions about the signed MANIFEST

Context: just after dropping `tools/sh/{sign-dir.sh,verify-dir.sh}`
(commit `7f34fe636`), which produces a `MANIFEST.sha256` of every
regular file under `fips-framework/` and an ML-DSA-87 detached
signature `MANIFEST.sig` over it.  Symlinks are followed (so
`fips-keys/` is traversed); `private_key.pem` and the `MANIFEST.*`
files themselves are excluded from the manifest.

### Q1 — MitM on `git clone` swapping the MANIFEST files

> If I had a MitM on `git clone` and they replaced the MANIFEST files,
> wouldn't I be compromised?

**Only if the attacker also substitutes `public_key.pem`.**

Without the ML-DSA-87 private key, every clone-time tamper attempt fails
under `verify-dir.sh`:

- **Replace MANIFEST.sha256 + MANIFEST.sig (signed by attacker key)** —
  signature invalid under the legitimate `public_key.pem`.
- **Replace just MANIFEST.sha256 to match malicious files** — sig is
  over the *old* manifest bytes, so signature verifies but the new sums
  don't match what's on disk.  Actually, it's the other way: sig
  verification checks `sig` against the *current* MANIFEST.sha256, so a
  swapped-out manifest with a legitimate `sig` from an older manifest
  fails at signature verification.
- **Modify source files but leave MANIFEST.* alone** — `sha256sum -c`
  catches the tampered files.

If the attacker also swaps `public_key.pem`, **yes, you are
compromised**: they sign with their key, ship their public key, and
everything verifies cleanly — against the wrong key.  ML-DSA-87 is just
a primitive; it can't tell you whether the public key it's using is the
right one.

**Current posture (partial mitigation by accident):**
`fips-keys/` is in `fips-framework/.gitignore`, so the public key is
**not** shipped via git at all.  It lives at `/home/ubuntu/fips-keys/`
(symlinked into the tree) and is provisioned out-of-band on each
developer's machine.  A MitM on `git clone` therefore can't substitute
the public key — they only see the repo channel.  This is the actual
defense.

**For shipping to a fresh machine** the trust anchor must come from a
channel separate from the repo.  Options:
- DNSSEC TXT pin of `sha256(public_key.pem)` — same pattern the MTC
  side already implements for the cosigner key
  (`mqc_dnssec_pin.c`, `mtc_dnssec_pin.c`).
- Distribution through a separately-authenticated channel (signed
  distro package chained to a root the recipient already trusts).
- TOFU with explicit re-pin on rotation (weakest fallback).

### Q2 — does including the public-key hash in MANIFEST help?

> Right now the public-key hash is in the signed MANIFEST.* (because
> sign-dir.sh follows symlinks and `fips-keys/public_key.pem` is a
> regular file under DIR).  Wouldn't that protect me?

**No — that's a self-referential bind, not a trust anchor.**

Walk through what an attacker who substitutes the public key does:

1. Generate their own ML-DSA-87 keypair: `attacker_priv`, `attacker_pub`.
2. Tamper with whatever source files they want.
3. Build a *new* `MANIFEST.sha256` whose `fips-keys/public_key.pem`
   line is `sha256(attacker_pub) fips-keys/public_key.pem`, plus the
   new file hashes.
4. Sign that manifest with `attacker_priv` → new `MANIFEST.sig`.
5. Serve all three: `fips-keys/public_key.pem` = `attacker_pub`, new
   MANIFEST.sha256, new MANIFEST.sig.

User runs `verify-dir.sh`:
- `pkeyutl -verify` checks MANIFEST.sig against `public_key.pem`
  (= attacker_pub) → **valid**, attacker signed with `attacker_priv`.
- `sha256sum -c MANIFEST.sha256` checks each entry, including
  `fips-keys/public_key.pem` against `sha256(attacker_pub)` →
  **matches**, attacker computed the hash over their own key.

Clean verification.  Compromised.

**General principle:** a signature over data that *includes the
verification-key hash* doesn't bootstrap trust — the attacker controls
every variable in the equation and can make them mutually consistent.
Same reason a self-signed X.509 cert proves nothing about identity:
the attacker can mint one for any name.

**What the in-manifest hash actually gives you (usefully but limited):**
- **Tamper detection if you already know the legitimate hash.**
  If you've memorised or pinned the expected value separately, you can
  spot a mismatch by `grep public_key.pem MANIFEST.sha256` before even
  running verify-dir.sh.
- **A historical record of which key was active at sign time.**
  Useful for forensics — proving e.g. that a cosigner key rotated
  between two manifests.

The actual MitM defense remains out-of-band trust on `public_key.pem`.

### Q3 — how does the MQC protocol protect against MitM?

MQC stacks four independent defenses, each rooted in a different
mechanism.  An attacker has to break all four to substitute themselves;
breaking any one alone gets caught.

#### 1. Trust anchor — DNSSEC pin on the cosigner key

The Merkle-log cosigner's ML-DSA-87 public-key hash is published in a
DNSSEC TXT record (`mqc_dnssec_pin.c`, `mtc_dnssec_pin.c`).  DNSSEC
chains to IANA's offline-distributed root key, so a MitM at the IP
layer can't substitute the cosigner pubkey without also breaking
DNSSEC.  This is the root — every other check chains back to it.

#### 2. Identity — cosigned leaf cert in the transparency log

Each peer's identity is an ML-DSA-87 leaf cert, issued by a domain CA
(also ML-DSA-87), entered into the Merkle log, and the log root is
cosigned by the DNSSEC-pinned cosigner.  To impersonate
`factsorlie.com` an attacker needs one of:
- the leaf's ML-DSA-87 private key,
- the CA's private key + cosigner's blessing of a forged leaf, or
- the cosigner's private key.

None of those are on the wire.

The **expected-identity check** (`mqc_ctx_set_expected_name`,
spec §10.7) requires the verified subject to match the dialed
hostname; dial-by-IP without an explicit name fails closed.  So an
attacker with *any* validly cosigned cert can't redirect a connection
meant for `factsorlie.com` to themselves under a different subject.

#### 3. Handshake binding — ML-DSA-87 transcript signature

Both peers sign a SHA-256 hash of the full transcript: ML-KEM-768 KEM
bytes, role tags, protocol version, both peers' identities, both peers'
contributions (spec §6, `MQC_HANDSHAKE_LABEL`).  Each signature commits
the signer to "I, subject X, participated in *exactly this* handshake."
A MitM running two separate handshakes (one per side) gets two
different transcripts, so they can't relay legitimate signatures
between sides.

#### 4. Joint-view commitment — Finished MAC + per-direction keys + AAD

- **Finished MAC** (`HMAC-SHA256(data_<role>_finished, transcript_hash_full)`,
  spec §8.1) is the first AEAD frame each direction.  Both peers
  commit to their *joint* transcript view; any byte differing between
  views breaks the MAC.
- **Per-direction keys/IVs** (`data_c2s_*` and `data_s2c_*`, independent
  HKDF-Expand outputs) make AES-GCM `(key, nonce)` collisions
  impossible across directions.
- **31-byte AAD per frame** (label + version + direction + frame_type +
  sequence + plaintext_length, spec §9.1.1, `MQC_AAD_LABEL`) binds
  frame metadata into every GCM tag.  A MitM reordering, splicing, or
  replaying frames hits AEAD failures.

#### Belt-and-suspenders

- **Cosigner-fingerprint cache invariant** (spec §10.1) — cached peer
  cert is invalidated when the cosigner key rotates; next handshake
  re-fetches and re-verifies under the current cosigner.  Historical
  cosigner-key compromise doesn't grant forever-MitM after rotation.
- **Mandatory revocation, fail-closed** (spec §10.5) — both peers
  query the log on cache miss; query failure aborts the handshake.
  A MitM blackholing the revocation channel can't paper over a
  compromised leaf.
- **Cert validity window** (spec §10.6, `mqc-sig-freshness-sec` =
  300s) — replay of an old signed handshake outside its window fails
  closed.

#### Concrete MitM attempt walk-through

| Attempt | Why it fails |
|---|---|
| Passive sniff | ML-KEM-768 ephemeral KEM + AEAD frames |
| Substitute server cert with one for `attacker.com` | Expected-identity check: dialed `factsorlie.com` ≠ verified `attacker.com` |
| Substitute cosigner pubkey | DNSSEC TXT mismatch; cache-fingerprint mismatch |
| Forge a leaf under the legit CA | CA's ML-DSA-87 private key not on the wire |
| Mint a parallel cosigner + new log | DNSSEC TXT under the legit domain doesn't authorize the new cosigner key |
| Splice frames between two real handshakes | Per-direction keys + AAD sequence numbers + Finished MAC all reject |
| Downgrade protocol version | `MQC_PROTOCOL_VERSION` byte is in the signed transcript |
| Replay an old handshake | Cert validity window + per-session ML-KEM freshness + nonce uniqueness |

#### The single point of failure

Break DNSSEC for the target domain *and* compromise the cosigner
private key (or coerce the legitimate cosigner to bless a fake leaf),
and you win.  Every other layer assumes the cosigner pubkey delivered
via DNSSEC is authentic; the transparency log + Merkle proofs + cert
chain all chain back to that single anchor.  Same trust posture as
Let's Encrypt's CAA record, with PQ primitives and explicit
transparency-log requirement instead of TOFU.

#### Tie-back to the fips-framework manifest

The MQC protocol's cosigner-pin via DNSSEC is the same pattern
fips-framework needs for trust-anchoring `public_key.pem` (see Q1).
When fips-framework starts being shipped beyond a single dev box, the
right move is to publish `sha256(public_key.pem)` in a DNSSEC TXT
record under a stable domain — not to invent a new mechanism, and
definitely not to rely on the in-manifest self-reference (Q2).
