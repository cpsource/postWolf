```
Internet Engineering Task Force                           C. Page, Ed.
Internet-Draft                                              factsorlie
Intended status: Experimental                          21 April 2026
Expires: 23 October 2026
```

# Merkle Quantum Connect (MQC) Transport Protocol

**draft-page-mqc-protocol-00**

## Abstract

This document specifies **Merkle Quantum Connect (MQC)**, a
post-quantum authenticated encryption protocol for bidirectional
byte streams over TCP.  Unlike TLS, MQC does not carry X.509
certificates on the wire; peer identity is referenced by index
into a public transparency log of Merkle Tree Certificates ([MTC])
and the cert itself is retrieved out of band.  The protocol uses
**ML-KEM-768** [FIPS203] for ephemeral key establishment,
**ML-DSA-87** [FIPS204] for long-term peer identity and handshake
binding, **HKDF-SHA256** [RFC5869] for session-key derivation, and
**AES-256-GCM** [FIPS197] for bulk confidentiality and integrity.
Peer certificates are verified against a log checkpoint signed with
**ML-DSA-87** as well.  Every primitive on the wire targets NIST
Category 3 or higher against a quantum adversary.

MQC is designed as a drop-in replacement for the authenticated-
channel role that TLS currently plays in machine-to-machine APIs,
without the mandatory X.509 chain-walking surface.  A reference
implementation in C is available in the `postWolf` source tree.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering
Task Force (IETF).  Note that other groups may also distribute
working documents as Internet-Drafts.  The list of current
Internet-Drafts is at <https://datatracker.ietf.org/drafts/>.

Internet-Drafts are draft documents valid for a maximum of six
months and may be updated, replaced, or obsoleted by other
documents at any time.  It is inappropriate to use Internet-Drafts
as reference material or to cite them other than as "work in
progress."

This Internet-Draft will expire on 23 October 2026.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the
document authors.  All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents
(<https://trustee.ietf.org/license-info>) in effect on the date of
publication of this document.

---

## Table of Contents

1. Introduction
2. Conventions and Terminology
3. Protocol Overview
4. Cryptographic Primitives
5. Wire Format
6. Handshake (clear-identity mode)
7. Handshake (encrypted-identity mode)
8. Key Derivation
9. Data Plane
10. Peer Verification
11. Operational Parameters
12. Security Considerations
13. IANA Considerations
14. References
15. Author's Address

---

## 1. Introduction

### 1.1. Context

The migration of public-key cryptography to post-quantum algorithms
is underway ([NIST-PQC], [GOOGLE-2029]).  While **TLS 1.3**
[RFC8446] can be extended with post-quantum key-exchange groups, it
retains the X.509 certificate path — a substantial attack surface
(ASN.1 parsers, revocation lists, name-constraint semantics) that
is largely orthogonal to the handshake's confidentiality goals.

**Merkle Tree Certificates** [MTC] replace the X.509 chain with a
single index into a public transparency log.  Given an index, any
peer can fetch the certificate, verify its Merkle inclusion proof
against a cosigned log head, and confirm the binding of name to
public key without walking a chain of issuing authorities.

MQC is the transport that delivers this model for machine-to-
machine APIs: a post-quantum authenticated channel with
MTC-referenced peer identity and no X.509 on the wire.

### 1.2. Goals

- Mutual post-quantum peer authentication using ML-DSA-87 signatures
  bound to identities anchored in an MTC log.
- Post-quantum key establishment using ML-KEM-768.
- Authenticated confidentiality using AES-256-GCM.
- No ASN.1, no X.509, no CRL/OCSP machinery in the handshake path.
- An optional **encrypted-identity** mode in which the peer's MTC
  log index is never sent in the clear.
- Implementability in ~2000 lines of C on top of a post-quantum
  crypto library such as wolfSSL.

### 1.3. Non-Goals

- MQC does not attempt to carry arbitrary application-layer data
  formats.  It is a byte-stream transport with the same semantic
  contract as TLS record layer.
- MQC does not specify a congestion-control layer; it runs over
  TCP and relies on the OS TCP stack.
- MQC is not intended as a replacement for QUIC-based transports.
  A QUIC-style sibling protocol that reuses MQC's crypto is
  described informally in [MQCP] but is out of scope here.

---

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in
this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

### 2.1. Definitions

**MQC connection.**  A full-duplex byte stream running between two
endpoints, established by one MQC handshake, carrying an arbitrary
number of encrypted data frames until closed.

**MQC endpoint.**  One of the two parties to an MQC connection.
Each endpoint holds an MQC identity (an MTC certificate and the
corresponding ML-DSA-87 private key).

**MTC certificate.**  A certificate in the format defined by
[MTC], identified by an integer `cert_index` within a named log.

**Log.**  The Merkle transparency log that witnesses MTC
certificates.  Log identity consists of a `log_id` string and an
ML-DSA-87 public key (the log's **cosigner**).

**Handshake.**  The initial bidirectional exchange that performs
peer authentication and establishes the session key.

**Session key schedule.**  The set of per-direction symmetric
secrets produced from the ML-KEM-768 shared secret and the
handshake transcript via HKDF-Extract+Expand (Section 8): two
32-byte AES-256-GCM keys (`data_c2s_key`, `data_s2c_key`), two
12-byte IVs (`data_c2s_iv`, `data_s2c_iv`), and two 32-byte
HMAC-SHA256 keys for the Finished frame (`data_c2s_finished`,
`data_s2c_finished`).

**Frame.**  A single length-prefixed, AEAD-sealed unit on the wire
after the handshake completes.  The same wire shape applies to
the Finished frame and to all subsequent application-data frames;
they are distinguished cryptographically by the `frame_type` byte
in their AEAD AAD (Section 9.1.1).

---

## 3. Protocol Overview

```
        +----------+                           +----------+
        |  client  |                           |  server  |
        +----------+                           +----------+
             |                                      |
             |  TCP connect to :mqc-port             |
             |------------------------------------->|
             |                                      |
             |  ClientHello  (JSON, plaintext)       |
             |  ─ version / suite / mode             |
             |  ─ ML-KEM-768 encapsulation key       |
             |  ─ MTC cert_index                     |
             |  ─ ML-DSA-87 sig over transcript hash |
             |------------------------------------->|
             |                                      |
             |            ServerHello (JSON, plaintext)
             |            ─ version / suite / mode   |
             |            ─ ML-KEM-768 ciphertext   |
             |            ─ MTC cert_index          |
             |            ─ ML-DSA-87 sig over txn hash
             |<-------------------------------------|
             |                                      |
        Both peers compute transcript_hash_full and derive a
        per-direction key schedule via HKDF-Extract+Expand
        (Section 8): data_c2s_key, data_s2c_key, data_c2s_iv,
        data_s2c_iv, data_c2s_finished, data_s2c_finished.
             |                                      |
             |   Finished frame (AEAD, both ways)   |
             |<====== HMAC-SHA256(finished_key,    |
             |        transcript_hash_full) =======>|
             |                                      |
             |  application data frames (both ways) |
             |<====== AES-256-GCM frames =========>|
             |                                      |
```

### 3.1. Layered Architecture

MQC runs over TCP.  It does not multiplex independent streams; an
application needing multiplexing MUST layer that above MQC (for
example, via HTTP/1.1 with `Connection: close` or a length-
prefixed RPC framing).

### 3.2. Identity Modes

MQC defines two handshake modes:

- **Clear-identity mode** (Section 6).  The `cert_index` of each
  endpoint is visible in the handshake JSON as it crosses the
  wire.  A passive observer can learn which logged identity is
  using the connection.  This is the default.

- **Encrypted-identity mode** (Section 7).  The server's identity
  is revealed only after the first ML-KEM shared secret is
  established; the client's identity is revealed only after the
  server is authenticated.  This costs one additional round trip
  but denies an observer both endpoints' identities.

---

## 4. Cryptographic Primitives

MQC uses the following primitives.  Implementations MUST NOT
negotiate alternatives; the only negotiable knob in version 0 of
this protocol is the identity mode (Section 3.2), which is
declared explicitly by the `mode` field (Section 5.2).

| Role | Algorithm | Spec |
|---|---|---|
| KEM (ephemeral key establishment) | ML-KEM-768 | [FIPS203] |
| Signature (peer identity, handshake binding) | ML-DSA-87 | [FIPS204] |
| Key derivation | HKDF-SHA256 (Extract + Expand) | [RFC5869] |
| Hash for HKDF salt and transcript | SHA-256 | [FIPS180] |
| Bulk cipher | AES-256-GCM | [FIPS197] |
| Handshake-MAC + Finished MAC | HMAC-SHA256 | [FIPS180] + [RFC2104] |
| Log cosigner | ML-DSA-87 | [FIPS204] |

The version-0 suite is identified by the literal ASCII string
`MQC_MLKEM768_MLDSA87_AES256GCM_SHA256` (referred to as `SUITE`
below).  This identifier appears verbatim in the handshake `suite`
field and a SHA-256 hash of it is mixed into the transcript hash
as `SUITE_ID` (Section 6).

Implementations MUST use a cryptographically secure RNG for all
randomness (ML-KEM key generation, ML-KEM encapsulation
randomness, handshake randomness).

---

## 5. Wire Format

All multi-byte integers on the wire are transmitted in big-endian
(network) byte order unless stated otherwise.

### 5.1. Common Frame

Every unit sent on an MQC connection, before and after the
handshake, is a **length-prefixed frame**:

```
     0               1               2               3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       payload length                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       payload  (variable)                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `payload length` is a 32-bit unsigned integer.  It counts only
  the payload bytes, not the length field itself.
- For handshake frames, the payload is a UTF-8 JSON object
  (Section 5.2).
- For data-plane frames, the payload is `ct || tag` where `ct` is
  the AES-256-GCM ciphertext and `tag` is the 16-byte GCM
  authentication tag.  `payload length` equals
  `len(plaintext) + 16`.

Receivers MUST reject a frame whose payload length exceeds the
implementation limit for its phase:

| Phase | Max payload (bytes) |
|---|---|
| Handshake | 131072  (128 KiB) |
| Data | 1048576 (1 MiB) |

A peer sending an oversized frame SHOULD be disconnected and MAY
be counted against a rate-limit bucket for failed handshakes.

### 5.2. Handshake JSON

All handshake frames are JSON objects.  Byte-valued fields are
hex-encoded (lowercase, no separators) with the exact byte length
given in the table.  The following fields are defined:

| Field | Type | Description |
|---|---|---|
| `version` | integer | Protocol version.  v0 of this spec uses `0`.  A receiver MUST reject any other value. |
| `suite` | string | Suite identifier (Section 4).  v0 uses the literal `"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256"`.  A receiver MUST reject any other value. |
| `mode` | string | Identity mode: `"clear"` or `"encrypted"`.  Bound into the transcript hash. |
| `kem_pub` | hex string | ML-KEM-768 encapsulation key (1184 B, client→server) or ciphertext (1088 B, server→client). |
| `signature` | hex string | ML-DSA-87 signature (4627 B), Section 6 / Section 10.2. |
| `cert_index` | integer | MTC log index of the signing identity. |

Implementations MUST parse handshake JSON in strict mode and
enforce the following rules; failing any one MUST abort the
handshake before any cryptographic primitive is invoked on the
field's contents:

- **No parser extensions.** Reject comments, leading zeros on
  numbers, single-quoted strings, unquoted keys, and trailing
  commas (these are common parser extensions but not JSON).
- **No trailing bytes.** Reject any bytes past the first complete
  top-level object — even whitespace.  The parsed length MUST
  equal the consumed length.
- **Valid UTF-8.** Reject malformed UTF-8 in any string value.
- **Each defined field exactly once.** Reject any object in
  which a defined field appears zero times or more than once.
  The receiver MUST detect duplication on the raw JSON bytes,
  not on the parsed object — most JSON parsers silently keep the
  last value when a key repeats, so a parser-only check would
  miss the smuggling case where a signer serialised the FIRST
  occurrence and a verifier parses the LAST.
- **No unknown top-level fields.** v0 has no extension registry;
  any key not listed in the table above MUST cause the handshake
  to be rejected.
- **Hex fields: lowercase, no separators, exact length.** The
  hex string for `kem_pub` and `signature` MUST contain only
  characters `[0-9a-f]`, MUST contain no separators, and MUST
  decode to exactly the byte length defined for the field by
  the chosen suite (1184 bytes for the ML-KEM-768 public key,
  1088 bytes for the ML-KEM-768 ciphertext, 4627 bytes for the
  ML-DSA-87 signature).
- **Integer fields: bounded.** `version` MUST equal the protocol
  version; `cert_index` MUST be a non-negative integer that fits
  in `int32`.  Implementations MUST reject overflow rather than
  saturating to `INT_MAX` (some JSON libraries silently saturate;
  see Section 12.10).

An implementation SHOULD serialize the JSON compactly (no
whitespace) to keep the `payload length` predictable, but MUST NOT
reject a peer's JSON solely for containing whitespace between
tokens.

---

## 6. Handshake (clear-identity mode)

### 6.0. Transcript Construction

Both ML-DSA signatures and the HKDF-Extract salt (Section 8) are
computed over a **transcript hash**, never directly over a single
field.  Two SHA-256 inputs are defined; they share a common prefix
and differ only by an optional 6-byte role tag.

`LABEL`     = `"mqc-hndshk/v1\n\x00"` (16 bytes; the 16th byte is
              the explicit `\x00`, NOT the terminating C-string
              NUL).

`SUITE_ID`  = SHA-256 of the literal ASCII suite string from
              Section 4 (32 bytes).

`MODE_ID`   = `0x00` for clear-identity, `0x01` for encrypted-
              identity.

`ROLE`      = `"client"` (6 bytes) or `"server"` (6 bytes).

For the **transcript hash for signatures** (one peer per role):

```
   transcript_hash_sig(role) = SHA-256(
       LABEL                                      (16 bytes)
    || u8(version)                                (1 byte; v0 = 0)
    || u8(MODE_ID)                                (1 byte)
    || SUITE_ID                                   (32 bytes)
    || u32be(len(EK_c)) || EK_c                   (variable)
    || u32be(len(CT_s)) || CT_s                   (variable;
                                                   len=0 if not yet
                                                   known by signer)
    || s32be(C_c)                                 (4 bytes; 0 if
                                                   not yet known)
    || s32be(C_s)                                 (4 bytes; 0 if
                                                   not yet known)
    || ROLE                                       (6 bytes))
```

For the **transcript hash for HKDF-Extract salt** (Section 8): the
same input MINUS the final 6-byte `ROLE` tag.  Both peers compute
the identical input.

ML-DSA-87 signatures cover `transcript_hash_sig(role)` with the
context label set to `LABEL` (16 bytes) — i.e., the call is
`wc_dilithium_sign_ctx_msg(LABEL, 16, transcript_hash_sig(role),
32, ...)`.  Verification uses the matching
`wc_dilithium_verify_ctx_msg`.  The context label provides
domain separation between MQC handshake signatures and any other
ML-DSA signature the same identity key might ever produce.

### 6.1. Client → Server

Upon establishing the TCP connection, the client:

1. Generates an ephemeral ML-KEM-768 keypair.  Let `EK_c` be the
   encoded public (encapsulation) key and `DK_c` the decoded
   secret (decapsulation) key.
2. Computes `transcript_hash_sig(role="client")` per Section 6.0
   with `(EK_c, len=1184; CT_s, len=0; C_s=0)` — the client does
   not yet know the server's `cert_index` or the ML-KEM ciphertext.
3. Signs that hash under its long-term ML-DSA-87 private key with
   the `LABEL` context, yielding signature `Sig_c`.
4. Sends one handshake frame containing the JSON:

```json
   {
     "version":    0,
     "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
     "mode":       "clear",
     "kem_pub":    "<hex(EK_c)>",
     "cert_index": <int C_c>,
     "signature":  "<hex(Sig_c)>"
   }
```

### 6.2. Server → Client

The server, upon receiving the client's handshake frame:

1. Strict-parses the JSON (Section 5.2); rejects on any field
   mismatch (`version != 0`, `suite != SUITE`, `mode != "clear"`,
   wrong hex length on `kem_pub` / `signature`).
2. Retrieves the MTC certificate at index `C_c` (see Section 10)
   and extracts its ML-DSA-87 public key `PK_c`.
3. Recomputes `transcript_hash_sig(role="client")` with the
   server's just-parsed view of the client fields and `(CT_s,
   len=0; C_s=0)`.  Verifies `Sig_c` against this hash with
   ctx=`LABEL`.  Failure → disconnect.
4. Performs ML-KEM-768 encapsulation against `EK_c`, producing
   ciphertext `CT_s` and shared secret `SS`.
5. Computes `transcript_hash_sig(role="server")` per Section 6.0
   with `(EK_c, len=1184; CT_s, len=1088; C_c, C_s)` — both
   `cert_index` values now populated.
6. Signs that hash with ctx=`LABEL`, yielding `Sig_s`.
7. Sends a handshake frame:

```json
   {
     "version":    0,
     "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
     "mode":       "clear",
     "kem_pub":    "<hex(CT_s)>",
     "cert_index": <int C_s>,
     "signature":  "<hex(Sig_s)>"
   }
```

### 6.3. Client Key Derivation

The client, upon receiving the server's handshake frame:

1. Strict-parses the JSON; rejects on field mismatch.
2. Retrieves the MTC certificate at index `C_s` and extracts its
   ML-DSA-87 public key `PK_s`.
3. Recomputes `transcript_hash_sig(role="server")` with both
   `cert_index` values populated.  Verifies `Sig_s` against this
   hash with ctx=`LABEL`.  Failure → disconnect.
4. Decapsulates `SS = MLKEM-Decap(DK_c, CT_s)`.
5. Derives the session key set (Section 8).
6. Sends its Finished frame and verifies the peer's Finished
   frame (Section 8.1) before the handshake is considered
   complete.

After a successful Finished exchange both parties share
identical `data_c2s_key` / `data_s2c_key` / `data_c2s_iv` /
`data_s2c_iv` and the connection is ready for application data.

Upon handshake completion each endpoint MUST zeroize its
ephemeral ML-KEM private key material and any intermediate
shared-secret buffers that are not required post-handshake,
including the Finished MAC keys (which are consumed exactly once
each).

---

## 7. Handshake (encrypted-identity mode)

Encrypted-identity mode hides both `cert_index` values from a
passive observer at the cost of one additional round trip.

> **Implementation status note (informative).** The reference
> implementation in `socket-level-wrapper-MQC/mqc_encrypted.c`
> ships the full encrypted-mode handshake as of Phase 7 (commits
> `de0ff9d60` and `a287aa8d0` on the postWolf tree).  Both
> `mqc_connect_encrypted` and `mqc_accept_encrypted` route
> through the post-Phase-1 transcript / HKDF-Extract+Expand /
> Finished / AAD architecture defined elsewhere in this
> document.  Callers opt in by setting
> `cfg.encrypt_identity = 1` on the `mqc_ctx_t` (or via
> `--encrypted` on CLI tools that surface it, e.g.
> `show-tpm`).  The `mqc_accept_auto` listener-side dispatcher
> peeks the first JSON frame's `mode` field and routes to the
> clear or encrypted continuation per connection, so a single
> server port handles both modes.  Earlier drafts of this
> document described the entry points as stubs; that text is
> obsolete.  The wire-format and cryptographic requirements
> below are normative; implementations MUST follow them if they
> offer encrypted mode at all.

### 7.1. Distinguishing the Mode

The client selects the mode and declares it explicitly via the
`mode` JSON field (Section 5.2).  Receivers MUST use this field
rather than infer mode from the presence or absence of other
fields, and MUST reject a frame whose `mode` value contradicts
its JSON shape (e.g., `mode="clear"` with no `cert_index`, or
`mode="encrypted"` with `cert_index` present).

### 7.2. Encrypted-Identity ClientHello

The client sends a first plaintext frame containing only the
mode markers and its ML-KEM public key — no identity, no
signature:

```json
   {
     "version":  0,
     "suite":    "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
     "mode":     "encrypted",
     "kem_pub":  "<hex(EK_c)>"
   }
```

### 7.3. Encrypted-Identity ServerHello

The server replies with a parallel plaintext frame carrying
`CT_s`.  No signature accompanies this frame; the server cannot
yet sign the full transcript because it does not know `C_c`.

```json
   {
     "version":  0,
     "suite":    "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
     "mode":     "encrypted",
     "kem_pub":  "<hex(CT_s)>"
   }
```

After this exchange both peers compute the **phase-1 transcript
hash** (per Section 6.0 with `C_c=C_s=0`) and derive
`early_secret = HKDF-Extract(salt=transcript_hash_phase1,
IKM=SS)`.  HKDF-Expand on `early_secret` produces
`early_c2s_key`, `early_s2c_key`, `early_c2s_iv`, `early_s2c_iv`
— used to seal the phase-2 identity frames only.

### 7.4. Encrypted-Identity Phase 2 (Client → Server)

The client signs the **full** transcript hash
(`transcript_hash_sig(role="client")` per Section 6.0) with its
own `cert_index` populated and `C_s=0` (still unknown), then
seals the resulting `{cert_index, signature}` JSON object with
`early_c2s_key` / `early_c2s_iv` at sequence 0:

```
   AEAD-Seal(early_c2s_key, nonce(early_c2s_iv, 0),
             aad(C2S, PHASE2_IDENTITY, 0, plaintext_len),
             {"cert_index": C_c, "signature": Sig_c})
```

### 7.5. Encrypted-Identity Phase 2 (Server → Client)

After receiving and verifying the client's phase-2 frame, the
server now knows `C_c`.  It computes
`transcript_hash_sig(role="server")` with both `cert_index`
values populated, signs it, and seals the
`{cert_index, signature}` blob with `early_s2c_key` /
`early_s2c_iv` at sequence 0.

This 4-frame total (CH plaintext + SH plaintext + client
encrypted-identity + server encrypted-identity) is one round
trip more than clear mode.  After phase 2 both peers compute
the **full** transcript hash, derive `data_secret =
HKDF-Extract(salt=transcript_hash_full, IKM=SS)`, and proceed
to the Finished exchange (Section 8.1) and data plane.

### 7.6. Sequence Numbering

Across both modes the data-plane sequence counter starts at
**1** in each direction, because the Finished frame (Section
8.1) consumed sequence 0.  This contract is uniform regardless
of mode.

---

## 8. Key Derivation

Key derivation in v0 uses HKDF-SHA256 in its full **Extract +
Expand** form (RFC 5869).  The salt for `HKDF-Extract` is the
**transcript hash** (Section 6.0, KDF variant — no role tag), so
all derived material is bound to every byte both peers
exchanged.  This goes beyond TLS-1.3-style transcript binding by
including the `cert_index` of both peers and the suite identifier
in the salt.

Two derivation contexts exist; they share `IKM = SS` (the 32-byte
ML-KEM-768 shared secret) and differ by salt:

```
    data_secret  = HKDF-Extract(SHA-256,
                       salt = transcript_hash_full,
                       IKM  = SS)

    early_secret = HKDF-Extract(SHA-256,
                       salt = transcript_hash_phase1,
                       IKM  = SS)             [encrypted mode only]
```

`transcript_hash_full` is the KDF-variant transcript with both
`cert_index` values populated — known to both peers after
clear-mode ServerHello or after encrypted-mode phase 2.
`transcript_hash_phase1` is the KDF-variant transcript with
`C_c=C_s=0` — known after encrypted-mode plaintext exchange,
needed to seal the phase-2 identity frames.

Per-direction keys, IVs, and Finished MAC keys are produced by
HKDF-Expand off the appropriate PRK.  All info strings are
deployment-stable ASCII literals containing the version and
suite identifier so a peer cannot accidentally agree on key
material across protocol versions:

```
    /* Convention: "mqc/v0/<SUITE>/<purpose>" where SUITE is the full
       suite identifier from Section 4.  Abbreviated as "..." below
       after the first occurrence. */
    data_c2s_key      = HKDF-Expand(SHA-256, data_secret,
        info = "mqc/v0/MQC_MLKEM768_MLDSA87_AES256GCM_SHA256"
               "/data-c2s-key",                              L = 32)
    data_s2c_key      = HKDF-Expand(SHA-256, data_secret,
        info = "mqc/v0/.../data-s2c-key",                L = 32)
    data_c2s_iv       = HKDF-Expand(SHA-256, data_secret,
        info = "mqc/v0/.../data-c2s-iv",                 L = 12)
    data_s2c_iv       = HKDF-Expand(SHA-256, data_secret,
        info = "mqc/v0/.../data-s2c-iv",                 L = 12)
    data_c2s_finished = HKDF-Expand(SHA-256, data_secret,
        info = "mqc/v0/.../data-c2s-finished",           L = 32)
    data_s2c_finished = HKDF-Expand(SHA-256, data_secret,
        info = "mqc/v0/.../data-s2c-finished",           L = 32)
```

In encrypted-identity mode an additional four outputs come from
`early_secret` (info strings `early-c2s-key`, `early-s2c-key`,
`early-c2s-iv`, `early-s2c-iv`).  These are used only to seal
the two phase-2 identity frames and MUST NOT appear in any other
frame.

`data_c2s_key` encrypts every client→server data-plane frame
(Section 9.1); `data_s2c_key` every server→client frame.
Per-direction keys eliminate `(key, nonce)` pair reuse across
directions — a property AES-256-GCM requires for confidentiality
and tag unforgeability.

Implementations MUST zeroize the PRK (`data_secret`,
`early_secret`) after expansion completes.

### 8.1. Finished Frame

After each peer derives the data-plane key set above (and
verifies the peer's handshake signature), it sends a **Finished
frame** as the first AEAD-sealed frame in its sending direction
and verifies the peer's Finished frame before allowing any
application data to flow.

The Finished frame uses the same wire format as a data-plane
frame (Section 9.1).  It is sealed with `data_<role>_key` and
`data_<role>_iv` at sequence number 0; its 31-byte AAD
(Section 9.1.1) carries `frame_type = 0x02` (Finished) and
`plaintext_length = 32`.  The plaintext is exactly **32 bytes**:

```
    finished_mac = HMAC-SHA256(
                       key = data_<role>_finished,
                       msg = transcript_hash_full)
```

A receiver MUST:

1. AEAD-decrypt the first frame in each direction at sequence 0.
   Failure → terminate (this surfaces as "wrong key" — distinct
   from MAC failure).
2. Assert plaintext length is exactly `MQC_FINISHED_MAC_SZ`
   (32 bytes).  Mismatch → terminate.
3. Recompute the expected MAC using its local copy of
   `data_<sender_role>_finished` and `transcript_hash_full`.
4. Constant-time compare received vs expected.  Mismatch →
   terminate.
5. Mark the connection as Finished-verified.  The next frame on
   the same key/IV is the first application frame at sequence 1.

Each Finished MAC key is consumed exactly once (one MAC
computation) and MUST be zeroized after use.

The Finished MAC defends against transcript-construction
divergence between honest peers and against on-path tampering of
bytes outside the signature transcript that the receiver
nevertheless hashes into its own `transcript_hash_full`.  See
Section 12.7.

---

## 9. Data Plane

### 9.1. Frame Structure

After handshake completion, every frame carries:

- The 32-bit big-endian length prefix (Section 5.1).
- `payload length` bytes of AEAD output: `ct || tag`, where
  `ct` is the AES-256-GCM ciphertext of the application
  plaintext and `tag` is the 16-byte authentication tag.

No additional headers are inserted on the wire between the length
prefix and the AEAD output.  Frame metadata (direction, type,
sequence, plaintext length, version) is bound into the AEAD AAD
(Section 9.1.1) rather than emitted as a separate header.

### 9.1.1. AEAD AAD

Every AEAD-sealed frame on an MQC connection (phase-2 identity
blobs in encrypted mode, the Finished frame, every application
data frame) is sealed with a fixed 31-byte AAD:

```
   AAD = LABEL                       (16 bytes "mqc-frame/v01\n\x00")
      || u8(version)                 (1 byte; v0 = 0)
      || u8(direction)               (1 byte; 0 = c2s, 1 = s2c)
      || u8(frame_type)              (1 byte; see below)
      || u64be(sequence)             (8 bytes)
      || u32be(plaintext_length)     (4 bytes)
```

`LABEL` is `"mqc-frame/v01\n\x00"` — 16 bytes including the
implicit terminating NUL appended by C's string-literal storage.
The `/v01` is the AAD-format version, NOT the protocol version;
it would be bumped only if the AAD bytes themselves changed.

`direction` is the direction of the frame on the wire from the
sender's point of view: client→server frames carry `0x00` in AAD
on both peers; server→client frames carry `0x01`.

`frame_type` distinguishes the three AEAD-sealed wire contexts:

| Value | Meaning | Keys used | Sequence |
|---|---|---|---|
| `0x01` | Phase-2 identity frame (encrypted mode) | `early_*_key` | 0 |
| `0x02` | Finished frame | `data_*_key` | 0 |
| `0x03` | Application data frame | `data_*_key` | ≥ 1 |

`plaintext_length` is the byte length of the plaintext that
will be sealed (i.e., the on-wire `payload length` minus the
16-byte GCM tag).  Length-prefix tampering becomes immediate
AEAD failure: a receiver that read a tampered prefix builds AAD
with the on-wire length, which differs from what the honest
sender computed; the GCM tag verification fails on the next
byte.

### 9.2. Nonce Construction

Per-direction IVs derived in Section 8 (`data_<role>_iv`,
`early_<role>_iv`) drive the per-frame nonce via TLS-1.3 §5.3
construction:

```
   nonce = iv  XOR  (0x00 0x00 0x00 0x00 || htobe64(seq))
```

The 4-byte zero prefix and 8-byte big-endian sequence form a
12-byte mask; the 12-byte IV is XOR'd with the mask to produce
the GCM nonce.  Per-direction IVs make the on-wire nonce
unpredictable across connections (the IV byte-prefix is per-
connection secret material), eliminating any nonce-prediction
analysis surface.

Each endpoint maintains two 64-bit unsigned sequence counters,
`send_seq` and `recv_seq`.  Both initialize to 0 immediately
after key derivation, are consumed (set to 1) by the Finished
frame in each direction (Section 8.1), and proceed to 2, 3, ...
for application data.  Application data therefore begins at
sequence 1 in both directions and in both modes.

A send operation forms the nonce, AEAD-seals
`(plaintext, AAD = mqc_build_aad(direction, frame_type,
send_seq, len(plaintext)))`, increments `send_seq`, and writes
the frame.  A receive operation reads the frame, forms the
nonce from `recv_iv` and `recv_seq`, AEAD-decrypts with the
matching AAD, increments `recv_seq` on success.

A decryption failure (AEAD tag mismatch, AAD mismatch, length
ceiling exceeded) MUST cause the connection to be terminated;
the endpoint SHOULD record the failure for rate-limiting
(Section 11.2).

Direction separation is enforced by the **per-direction key**;
the per-direction IV is a defense-in-depth bonus that makes
nonces unguessable.  AES-GCM collision requires the same
`(key, nonce)` pair, and per-direction keys ensure the keys
always differ.

### 9.3. No Reordering or Omission

MQC runs over TCP and does not tolerate reordering or omission of
frames.  An endpoint receiving a frame whose tag does not verify
against the expected `recv_seq` MUST NOT attempt to recover by
trying other sequence numbers.

---

## 10. Peer Verification

The `cert_index` fields identify MTC certificates in a named log.
Before accepting a peer's identity, an endpoint MUST perform all
four of the following checks; failure of any one MUST cause the
handshake to be aborted.

### 10.1. MTC Certificate Retrieval

Given `cert_index`, the verifier retrieves the full MTC
certificate.  The retrieval transport (HTTP, MQC, or a local
filesystem cache) MUST NOT be relied on for trust.  The verifier
MUST perform every check in §10.2 through §10.6 on the bytes the
transport returns, regardless of source; a cert that fails any
of those checks MUST be rejected even if the transport reported
success.

Implementations SHOULD cache verified certificates locally to
avoid repeated log queries; a typical cache structure stores one
file per `cert_index` under a path such as
`~/.TPM/peers/<index>/certificate.json`.  Cache entries MUST be
invalidated when the cosigner key rotates: a cached cert was
verified under the cosigner key in effect at cache-write time,
and a key rotation (e.g., via `admin_recosign` in the postWolf
reference implementation) means subsequent cosignature checks
against the new key would fail.  The reference implementation
stores `~/.TPM/peers/<index>/cosigner-fp.hex` alongside each
cached cert (lowercase hex SHA-256 of the cosigner pubkey at
verification time) and treats a fingerprint mismatch as a cache
miss, triggering a re-fetch + re-verify under the current
cosigner.

Retrieval MAY be performed over the same MQC connection if the
peer is the log itself, or out of band via HTTP against a known
log-service URL.

### 10.2. ML-DSA-87 Signature on the Handshake

The verifier extracts the ML-DSA-87 public key from the retrieved
certificate and verifies that `signature` in the handshake frame
is a valid ML-DSA-87 signature under that public key, with the
context label `LABEL = "mqc-hndshk/v1\n\x00"` (16 bytes), over
the **transcript hash** for the appropriate role (Section 6.0):

```
   verified = MLDSA-Verify-CtxMsg(
                  pk      = peer_PK,
                  ctx     = LABEL,                  /* 16 bytes */
                  ctx_len = 16,
                  msg     = transcript_hash_sig(role),
                  msg_len = 32,                     /* SHA-256 */
                  sig     = signature)
```

The transcript hash binds:

- the protocol version (`u8(version)`);
- the suite identifier (`SUITE_ID = SHA-256(SUITE)`);
- the identity mode (`u8(MODE_ID)`);
- both peers' ML-KEM contributions (`EK_c`, `CT_s`, with explicit
  byte-length prefixes — `len=0` if not yet known by the signer);
- both peers' `cert_index` values (`s32be(C_c)`, `s32be(C_s)` —
  `0` if not yet known by the signer);
- the role tag (`"client"` or `"server"`, 6 bytes).

Together with the ML-DSA `ctx` label, this provides cryptographic
domain separation against any other use of the same identity key
and prevents:

- identity-substitution attacks (the peer's `cert_index` is
  signed);
- KEM-share substitution (both ML-KEM values are signed);
- cross-protocol replay (the `LABEL` ctx and `LABEL` prefix in
  the message guarantee a different signed bytestring);
- mode confusion (the `mode_id` byte is signed);
- role confusion (the role tag distinguishes a client signature
  from a server signature on otherwise-identical data).

The asymmetry in the "knowledge available at signing time" —
client signs with `C_s = 0` and `len(CT_s) = 0` because the
client doesn't yet know those — is intentional.  The server
signs with everything populated, which closes Unknown Key Share
in the client→server direction.  A "Finished" MAC over the full
transcript (Section 8.1) closes the residual asymmetry by
committing both peers to their view of the same transcript at
handshake completion.

### 10.3. Merkle Inclusion Proof

MTC certificates carry an inclusion proof of the form defined in
[MTC].  The verifier reconstructs the expected subtree root from
the leaf hash, the claimed `cert_index`, and the inclusion path,
then compares that root to the value carried in the checkpoint
(Section 10.4).

The tree-walk algorithm differs from a balanced binary Merkle-
tree walk when subtree sizes are not powers of two: at each
recursion step, split at `k = largest power of 2 < n`.  Full
pseudocode is given in [MTC] Section 2.1.3.

### 10.4. ML-DSA-87 Cosignature on the Checkpoint

The log cosigner issues an ML-DSA-87 signature over a structured
checkpoint message of the form:

```
     label       = "mtc-subtree/v1\n\x00"             (16 bytes)
     cosigner_id = <UTF-8>
     log_id      = <UTF-8>
     start       = htobe64(subtree_start)              (8 bytes)
     end         = htobe64(subtree_end)                (8 bytes)
     subtree_hash = <32 bytes, SHA-256>                (32 bytes)
```

The verifier recomputes this message in exactly the bytes above,
reconstructs the `subtree_hash` it expects from Section 10.3, and
verifies the ML-DSA-87 signature against the log's known ML-DSA-87
public key (2592 bytes, raw encoding).  The signature is 4627 bytes.
The verification uses `wc_dilithium_verify_ctx_msg` with an empty
context (`ctx = NULL, ctxLen = 0`).  Note that this differs from
the handshake-signature call in Section 6 / Section 10.2, which
uses the 16-byte `LABEL` as the ctx — the in-message label
`"mtc-subtree/v1\n\x00"` provides the cosignature's domain
separation, so a separate ctx is unnecessary.

### 10.5. Revocation

For each verified peer, the verifier **MUST** query a log endpoint
for the revocation status of `cert_index` unless a non-expired
cache entry covers that index.  A positive revocation answer MUST
cause the handshake to be aborted.  Implementations MAY cache
negative ("not revoked") answers for a bounded TTL (default 24
hours; tunable via the `mqc-revoked-cache-ttl-sec` operational
parameter, Section 11).

Implementations MUST treat a query failure (network error, HTTP
error, malformed response, invalid signature on the response) as
equivalent to an unknown revocation status: the handshake MUST
be aborted.  This is the **fail-closed** default.

Both peers — the initiator and the acceptor — MUST apply this
check to the other party's `cert_index`.  Earlier revisions of
this protocol applied the check only on the acceptor side; that
asymmetry is removed in v0 because a client connecting to a
revoked server is the case that warrants the most caution (the
client is about to disclose application data to whatever
identity the server presents).

An operator MAY opt out of the strict policy by setting the
operational parameter `mqc-revocation-policy` (Section 11) to one
of:

- `mandatory` (the default behavior described above);
- `cache-only` — trust the cache, abort on cache miss; never
  touches the network.  Useful during planned log-endpoint
  maintenance windows where caches are still valid;
- `disabled` — skip revocation entirely.  Implementations
  selecting this MUST log a warning at process startup
  indicating that revocation enforcement is disabled.  This
  setting is intended only for emergency recovery (catastrophic
  log loss) and MUST NOT be the steady-state operational mode.

### 10.6. Validity Window

Each MTC certificate carries `not_before` and `not_after`
Unix-epoch timestamps in its `tbs_entry`.  The verifier MUST
require both fields and MUST reject the cert if:

- either field is missing or zero (a malformed cert that the
  verifier cannot bound), or
- the verifier's clock indicates `now < not_before - skew`
  (the cert is not yet valid), or
- the verifier's clock indicates `now > not_after + skew`
  (the cert has expired).

`skew` is the operational parameter `mqc-sig-freshness-sec`
(Section 11; default 300 s).  This tolerance accommodates
peers with modest NTP drift without indefinitely accepting
expired certs.  Implementations SHOULD log distinct
`CERT_NOT_YET_VALID` and `CERT_EXPIRED` lines (rather than a
generic "validity failed") so an operator can tell which
clock is wrong.

### 10.7. Expected-Identity Check

The cryptographic checks in 10.1–10.6 prove that the peer
holds the private key bound to a verified, in-log,
unrevoked, and currently-valid certificate.  They do NOT
prove that the verified certificate names the identity the
caller intended to talk to.  Without an expected-identity
check, a hostile name resolver (DNS, hosts file,
configuration error, or a `cert_index` supplied by an
attacker-controlled lookup) can route the connection to a
DIFFERENT in-log identity that satisfies every cryptographic
check while not being the party the caller meant to reach.

A client implementation MUST perform an expected-identity
check after 10.1–10.6 succeed, on the verified subject
string from the cert's `tbs_entry.subject` field.  The
expected name SHOULD be derived from the hostname the caller
dialed; the API MUST also expose a way to set it explicitly
(for callers that dial by IP or use a non-DNS routing
indirection) and a way to disable the check (for callers
with an out-of-band reason to trust the peer index, e.g. a
log-replication or admin tool).

The match rule is case-insensitive throughout, and accepts:

- exact match (`subject == expected`); or
- prefix match where `subject` begins with `<expected> + "-"`.

The prefix rule covers the postWolf naming convention in
which a single domain owner runs an unbounded set of
identities sharing a common DNS prefix (`<dns>`, `<dns>-ca`,
`<dns>-<label>`).  No wildcards are accepted.  The rule
operates on the verified-from-the-log subject only; it MUST
NOT consult DNS, system resolvers, or any source other than
the cert itself.

If the caller dialed an IP address literal and has not
supplied an explicit expected name, the implementation MUST
fail the connection with a clear `NAME_CHECK_FAILED`
diagnostic — an IP names a location, not an MTC subject, so
no meaningful expected identity can be derived from the dial
target.  Implementations SHOULD log a distinct
`NAME_CHECK_FAILED` line so an operator can distinguish this
case from cryptographic failures in 10.1–10.6.

The server side performs no symmetric expected-identity
check on the client cert: clients are not constrained to a
particular hostname-derived identity in this protocol.
Server-side authorisation against `peer_index` or the cert
subject is the application's responsibility.

---

## 11. Operational Parameters

The parameters below are runtime-tunable in the reference
implementation via `/etc/postWolf/config` under the `[global]`
section, read once at process startup.  An implementation MAY
substitute any equivalent configuration mechanism; the parameter
*names* below are normative for cross-implementation
interoperability, the *transport* is not.

| Parameter | Default | Section | What it controls |
|---|---|---|---|
| `mqc-handshake-stall-sec` | 3 | 11.1 | Per-read timeout during the handshake |
| `mqc-handshake-total-sec` | 5 | 11.1 | Total wall-clock budget for one handshake |
| `mqc-max-handshake-bytes` | 131072 | 11.3 | Cap on a single handshake JSON frame |
| `mqc-max-msg-bytes` | 1048576 | 11.3 | Cap on a single data-plane payload |
| `mqc-rl-connect-per-min` | 100 | 11.2 | Per-IP connection-attempt cap (per minute) |
| `mqc-rl-connect-per-hour` | 1000 | 11.2 | Per-IP connection-attempt cap (per hour) |
| `mqc-rl-fail-per-min` | 10 | 11.2 | Per-IP handshake-failure cap (per minute) |
| `mqc-rl-fail-per-hour` | 100 | 11.2 | Per-IP handshake-failure cap (per hour) |
| `mqc-rl-cert-per-min` | 10 | 11.2 | Per-IP distinct-cert_index cap (per minute) |
| `mqc-rl-cert-per-hour` | 100 | 11.2 | Per-IP distinct-cert_index cap (per hour) |
| `mqc-max-children` | 20 | 11.6 | Per-listener fork backpressure cap |
| `mqc-revoked-cache-ttl-sec` | 86400 | 10.5 | Revocation-cache TTL |
| `mqc-sig-freshness-sec` | 300 | 10.6 | Cert-validity skew tolerance |
| `mqc-revocation-policy` | `mandatory` | 11.5 | One of `mandatory` / `cache-only` / `disabled` |

The defaults above are suitable for a single-host deployment
serving on the order of 10² distinct identities.  See the cited
sections for tuning guidance.

### 11.1. Timeouts

An implementation SHOULD impose a per-read deadline
(`mqc-handshake-stall-sec`, RECOMMENDED 3 seconds) and a total
wall-clock deadline (`mqc-handshake-total-sec`, RECOMMENDED 5
seconds) on the handshake from TCP accept to handshake completion.
A separate per-read deadline of approximately 60 seconds applies
to the data plane.  Exceeding any deadline MUST cause the
connection to be terminated.

The handshake budgets are deliberately tight: a legitimate
post-quantum handshake completes in under 200 ms on commodity
hardware (median ~195 ms on a single-core 4 GHz x86 against a
local server, per the reference implementation's perf snapshot).
The 5-second total budget allows ample slack for slow links and
modest server-side queue depth while denying an attacker the
multi-minute stall windows that pre-Phase-1 drafts permitted.

### 11.2. Rate Limiting

Servers SHOULD enforce per-source-IP rate limits on:

- **connection attempts**, to limit opportunistic scanning;
- **handshake failures**, to limit brute-force attempts on peer
  identity;
- **per-endpoint request counters** (after connection, at the
  application-protocol layer above MQC) using at least a
  per-minute and a per-hour bucket.

Servers SHOULD additionally enforce **per-(source-IP,
`cert_index`)** rate limits.  A peer that rotates `cert_index`
on every connect, even within the per-IP connection budget,
forces a fresh certificate fetch (Section 10.1), inclusion-
proof verification (Section 10.3), and ML-DSA-87 cosignature
verification (Section 10.4) per attempt — millisecond-scale
work per cheap client byte.  Cap distinct `cert_index` values
per source IP; RECOMMENDED defaults are 10 fresh indices per
minute and 100 per hour, exposed via the operational
parameters `mqc-rl-cert-per-min` and `mqc-rl-cert-per-hour`.
Rejections under this cap SHOULD count against the per-IP
failure bucket (so a single attacker IP rotating `cert_index`
also burns its handshake-failure budget).

A typical bucket structure keys on `<operation>:<ip>:<window>`
and is persisted in a local key-value store (e.g., Redis) for
cross-process aggregation within a single host.

### 11.3. Maximum Message Sizes

- Handshake frame payload: 128 KiB.
- Data-plane frame payload: 1 MiB.

Implementations MAY lower these limits but MUST NOT raise them
without advertising a new protocol version.

### 11.4. Default Port

The suggested default TCP port for MQC services is **8446** (see
Section 13).

### 11.5. Revocation Policy

Implementations MUST honor the operational parameter
`mqc-revocation-policy` with one of three values: `mandatory`
(default, fail-closed; see Section 10.5), `cache-only`, or
`disabled`.  On Linux deployments using the postWolf reference
implementation this parameter is read from `/etc/postWolf/config`
under the `[global]` section at process startup.

### 11.6. Server Concurrency Cap

A fork-per-connection server SHOULD cap the number of concurrent
per-connection child processes via `mqc-max-children` (RECOMMENDED
default: 20).  Before each `accept()`, the listener checks the
active-child counter; if it is at or above the cap, the listener
sleeps briefly (RECOMMENDED 1 second) and re-checks.  Children
continue to run once spawned — only the *accept rate* is
throttled, so bursts stretch out instead of fanning into hundreds
of concurrent forks.

This is a process-level resource cap distinct from the per-IP
rate limits in Section 11.2: a single legitimate IP can drive
many parallel connections, and the cap prevents that traffic
pattern from exhausting host memory or process-table limits even
when each individual connection is well-behaved.

A thread-pool implementation SHOULD impose an equivalent cap on
in-flight handshake worker threads.  An implementation that
admits multiple concurrent handshakes per process (whether via
threads or async I/O) MAY additionally cap total in-flight
handshake-buffer memory directly (per Section 12.6).

---

## 12. Security Considerations

### 12.1. Quantum Resistance of Components

- **ML-KEM-768** targets NIST post-quantum security category 3
  against adversaries with a quantum computer.
- **ML-DSA-87** targets NIST post-quantum security category 5 and
  is paired with ML-KEM-768 to keep the aggregate handshake at
  Category 3 or above.  [FIPS204]
- **AES-256-GCM** at Category 5 is selected to match ML-DSA-87's
  pre-quantum and post-quantum margins.  Using AES-128-GCM or a
  smaller key would weaken the aggregate.
- **SHA-256** provides 128 bits of post-quantum collision
  resistance (Grover gives a quadratic speedup on preimage search
  but not on collision search in the birthday-attack regime).
- **Every wire primitive targets at least NIST Category 3 against a quantum adversary.**
  The log cosigner (Section 10.4) uses ML-DSA-87 — identical to
  peer identity — so there is no pre-quantum hedge remaining in
  the chain of trust.  An operator migrating from an earlier
  draft that used Ed25519 for the cosigner should refer to the
  `migrate-cosigner` tool in the reference implementation for
  the one-shot rotation procedure.

### 12.2. Nonce Management

The all-zero reserved prefix in the nonce construction (Section
9.2) MUST NOT be interpreted as slack for key-reuse across
connections.  Each MQC connection derives fresh per-direction
keys (`c2s_key`, `s2c_key`) from a fresh ML-KEM shared secret;
each direction's nonce counter starts at 0 (or 1 in
encrypted-identity mode) and never wraps within a single
connection before the 2^64 limit — effectively, never.

Direction separation is enforced cryptographically by the
per-direction keys derived in Section 8.  AES-GCM is catastrophic
under `(key, nonce)` reuse: encrypting two distinct plaintexts
under the same `(K, N)` lets a passive observer XOR the
ciphertexts to recover plaintext XOR and additionally lets them
recover the GHASH authentication subkey, enabling forgery.
Earlier MQC drafts derived a single session key shared by both
directions and relied on the TCP stream to separate them; that
construction is incorrect because TCP delivers both halves of the
stream to a passive observer, and is replaced in this revision
by the per-direction-key construction.

### 12.3. Identity Exposure

In clear-identity mode, a passive observer learns both endpoints'
`cert_index` values.  An observer who can query the same MTC log
can therefore learn both identities by name.  If hiding the
identities from passive observers is a requirement, implementations
MUST use encrypted-identity mode (Section 7).

### 12.4. Revocation-Cache Staleness

A revoked peer whose revocation has not yet been published to the
log, or whose published revocation has not yet been pulled into
the verifier's cache, will continue to be accepted.  Operators
SHOULD set revocation-cache TTLs commensurate with their
threat model; an emergency-revocation pipeline that forcibly
invalidates peer caches is out of scope here.

### 12.5. Compromise of the Log Cosigner

If the log cosigner's ML-DSA-87 private key is compromised, an
adversary can forge checkpoints and thereby inject fraudulent
certificates into the verification chain.  Defence-in-depth
measures — HSM-backed cosigner key storage, multiple independent
cosigners, public append-only witnesses of the cosigner's
signatures — are addressed in [MTC] and not duplicated here.

### 12.6. Denial of Service

ML-KEM and ML-DSA verification are more expensive than their
pre-quantum analogues.  An attacker sending many half-open
connections can exhaust a server's CPU budget before the
handshake completes.  The rate-limiting guidance in Section 11.2
mitigates but does not eliminate this.  Placing MQC behind an
L4 rate limiter (e.g., `iptables --hitcount` or a cloud-provider
WAF) is RECOMMENDED for production deployments.

The strict-parsing rules in Section 5.2 are also load-bearing
for DoS resistance: implementations MUST validate the byte
length of every hex-encoded field (`kem_pub`, `signature`)
against the exact size defined for that field by the chosen
suite (Section 4) BEFORE invoking any cryptographic primitive
on the field's contents.  Without this
guard, a 1-byte attacker payload of the right shape would still
trigger a ~400 µs ML-DSA-87 verification — many orders of
magnitude of asymmetric work per attack byte.  Rejections at
the length-check stage SHOULD count against the per-IP
handshake-failure bucket (Section 11.2) so that a peer that
repeatedly sends malformed input also exhausts its connection
budget.

The accept loop in the reference implementation runs the entire
handshake in the listener process before forking off the
connection-handling child, so handshakes are serialised and
only one handshake-sized JSON buffer is ever in flight per
listener.  An implementation that uses a thread pool (or
otherwise admits multiple in-flight handshakes per process)
SHOULD additionally cap total in-flight handshake-buffer
memory and reject new accepts when the cap is exceeded.

### 12.7. Transcript Binding and Cross-Protocol Domain Separation

Every byte both peers exchange in the handshake is bound into
the transcript hash that the ML-DSA signatures cover (Section
6.0) and that becomes the HKDF-Extract salt for all derived
session material (Section 8).  Specifically:

- `version`, `suite_id`, and `mode` defeat version, suite, and
  mode rollback / confusion.
- Both peers' `cert_index` values defeat identity substitution
  (an attacker presenting cert A's signature for a connection
  the client believed was with cert B fails verification because
  the `cert_index` value the client expected differs from what
  the signing peer hashed).
- Both peers' KEM contributions (`EK_c` and `CT_s`, with
  byte-length prefixes) defeat KEM-share substitution and
  classic Unknown Key Share attacks where an attacker forwards
  one peer's KEM value to a different peer.
- The 6-byte role tag (`"client"` vs `"server"`) prevents a
  client signature from being mistaken for a server signature
  on otherwise-identical data.

The ML-DSA `ctx` label `"mqc-hndshk/v1\n\x00"` and its
in-message `LABEL` prefix together provide cross-protocol
domain separation: an MQC handshake signature is not a valid
signature for any other use of the same ML-DSA-87 identity
key, including the cosigner's checkpoint signature (which uses
a different label `"mtc-subtree/v1\n\x00"`).

The Finished MAC (Section 8.1) closes the residual gap left by
the asymmetric "knowledge available at signing time" in §6.0
(client signs without knowing `C_s`; server signs knowing
both).  By committing both peers via HMAC-SHA256 to their view
of the full transcript at handshake completion, transcript-
construction divergence between honest implementations and
on-path tampering of bytes outside the signature transcript
both surface as a clean Finished failure rather than as opaque
AEAD failures three frames into application traffic.

### 12.8. Frame-Header Authentication

Every AEAD-sealed frame past the unauthenticated handshake
fields binds the same 31-byte AAD (Section 9.1.1) into its GCM
authentication tag.  This:

- Turns length-prefix tampering into immediate AEAD failure on
  the affected frame, rather than letting a tampered prefix
  spill into the next frame's bytes and desynchronize framing.
- Distinguishes Finished frames (`frame_type = 0x02`) from
  application data frames (`frame_type = 0x03`) cryptographically,
  even though they share the same `data_*_key` / `data_*_iv`.
  A peer that swapped one for the other in flight (impossible
  without breaking AES-256-GCM, but defense in depth) hits AEAD
  failure on the type-byte mismatch.
- Provides defense in depth on fields already bound by other
  means: `direction` is also separated by per-direction keys;
  `sequence` is also bound by the per-frame nonce; `version`
  is also bound by the transcript-hash HKDF salt.  The AAD
  doesn't add cryptographic guarantees here but does make
  divergence loud at the moment of detection.

The 16-byte `LABEL` `"mqc-frame/v01\n\x00"` is the AAD-format
version, NOT the protocol version.  It would be bumped only if
the AAD bytes themselves changed; a protocol-version bump (v0 →
v1) does not by itself require a new AAD label.

### 12.9. Identity vs Authority

The cryptographic verification chain in 10.1–10.6 establishes
*authority* — the peer holds a private key bound to a
verified, in-log, currently-valid, unrevoked certificate.
That is necessary but NOT sufficient for a client.  The
client also needs *identity*: confirmation that the
authoritative peer is the specific identity the client
intended to talk to.

Without the Section 10.7 expected-identity check, an
attacker who can influence the connection's routing
indicator (DNS, hosts file, mis-typed configuration, a
hostile `cert_index` lookup) can route the client to a
different but cryptographically-valid identity in the same
log.  All four checks in 10.3–10.6 will pass.  No bytes go
to a malicious party — but they go to the wrong honest
party.  For an application that conditions sensitive actions
on *who* the peer is (CA-side recording of leaf actions,
client-side selection of an oracle), this is a confused-
deputy vulnerability with the protocol acting as the
deputy.

Section 10.7 closes that gap by making the comparison
explicit and surfacing a `NAME_CHECK_FAILED` error before
any session keys are derived.  The check operates exclusively
on the verified subject from the log entry; it never queries
DNS or any other external system, so it cannot be subverted
by the same attacker who supplied the routing indicator.

The cost is operational rigidity: dialing by IP requires the
caller to set an explicit expected name, and renaming an
identity (changing `tbs_entry.subject`) breaks every client
configured for the old name.  Both are intentional: an
implicit "trust whatever the log says" mode would re-open
the gap this section closes.

### 12.10. JSON Parsing Hardening

The handshake JSON parser is a security-sensitive component
because the bytes on the wire are bound into the transcript
hash by both parties; any divergence between what the signer
serialised and what the verifier parsed lets an attacker
force one side to authenticate to a different message than
the other side believes it received.  Section 5.2's strict-
parsing rules close four concrete classes of attack:

- **Duplicate-key smuggling.**  Most JSON parsers (json-c
  among them) accept duplicate keys in an object and keep one
  of them — typically the last.  A signer that serialises the
  FIRST occurrence and a verifier that reads the LAST will
  hash different `cert_index` values: the signature still
  validates (it was generated over the signer's view of the
  bytes) but the verifier proceeds with a different identity.
  Section 5.2's "exactly once" rule, enforced on the raw JSON
  bytes (not on the parsed object — by which time the
  duplicate is already collapsed), closes this.

- **Trailing-garbage smuggling.**  A streaming parser stops
  at the first complete object; any bytes that follow are
  ignored by the handshake but may be consumed by some other
  tool (logger, audit pipeline, application-layer demuxer)
  and interpreted differently.  The "no trailing bytes" rule
  forces a length match between the input buffer and the
  parser's consumed-bytes count, so the same bytes are seen
  by every consumer or none.

- **Integer-overflow desynchronisation.**  Several JSON
  libraries silently clamp out-of-range integers to
  `INT_MAX` / `INT_MIN`.  A signer that serialises a string
  representation of a 64-bit value and a verifier that parses
  it into a saturated 32-bit integer hash different transcript
  bytes.  Section 5.2's "fit in int32" rule, enforced via an
  explicit `errno=ERANGE` check rather than a silent
  saturation, closes this.

- **Parser-extension fingerprinting.**  Comments, leading
  zeros, and single-quoted strings are accepted by some
  parsers and rejected by others.  An attacker probing a
  service can fingerprint the parser implementation by sending
  inputs in the grey zone — useful for pivoting to a parser-
  specific exploit.  Strict mode removes the grey zone.

The rules also defend in depth against future code changes:
hex-length and integer-range checks happen BEFORE any
cryptographic primitive runs (Section 11.2 calls these out as
cheap pre-crypto filters), so a malformed `kem_pub` cannot
exercise the ML-KEM decoder and a malformed `cert_index`
cannot exercise the certificate-fetch path.

---

## 13. IANA Considerations

This document requests IANA to register TCP port **8446** in the
"Service Name and Transport Protocol Port Number Registry" for
the service name `mqc`.  The assignment category is "User" (not
"System"); the contact is the author of this document.

No other IANA actions are requested.  Future revisions introducing
negotiable parameters (alternate KEMs, alternate AEADs, version
identifiers) will require registries; those are deferred until
such negotiation is actually introduced.

---

## 14. References

### 14.1. Normative References

- **[FIPS197]**  NIST, *Advanced Encryption Standard (AES)*,
  FIPS 197, November 2001.
- **[FIPS180]**  NIST, *Secure Hash Standard (SHS)*, FIPS 180-4,
  August 2015.
- **[FIPS203]**  NIST, *Module-Lattice-Based Key-Encapsulation
  Mechanism Standard*, FIPS 203, August 2024.
- **[FIPS204]**  NIST, *Module-Lattice-Based Digital Signature
  Standard*, FIPS 204, August 2024.
- **[MTC]**      Birgisson, Messeri, et al., *Merkle Tree
  Certificates*, draft-ietf-plants-merkle-tree-certs, work in
  progress.
- **[RFC2104]**  Krawczyk, Bellare, and Canetti, *HMAC: Keyed-
  Hashing for Message Authentication*, RFC 2104, February 1997.
- **[RFC2119]**  Bradner, *Key words for use in RFCs to Indicate
  Requirement Levels*, BCP 14, RFC 2119, March 1997.
- **[RFC5869]**  Krawczyk and Eronen, *HMAC-based Extract-and-
  Expand Key Derivation Function (HKDF)*, RFC 5869, May 2010.
- **[RFC8174]**  Leiba, *Ambiguity of Uppercase vs Lowercase in
  RFC 2119 Key Words*, BCP 14, RFC 8174, May 2017.

### 14.2. Informative References

- **[RFC8446]**     Rescorla, *The Transport Layer Security (TLS)
  Protocol Version 1.3*, RFC 8446, August 2018.
- **[NIST-PQC]**    NIST Post-Quantum Cryptography Project,
  <https://csrc.nist.gov/projects/post-quantum-cryptography>.
- **[GOOGLE-2029]** Google, *Our pledge to migrate to post-
  quantum cryptography by 2029*, blog post, March 2026,
  <https://blog.google/innovation-and-ai/technology/safety-security/cryptography-migration-timeline/>.
- **[MQCP]**        Merkle Quantum Connect Protocol over UDP.  A
  sibling transport that reuses MQC's crypto over a QUIC-style
  reliable UDP substrate.  See the `postWolf` source tree,
  `socket-level-wrapper-QUIC/`.

---

## 15. Author's Address

    Cal Page (editor)
    factsorlie.com
    Email: cal@factsorlie.com
    URI:   https://factsorlie.com/

---

## Appendix A. Worked Example (informative)

The following is a single clear-identity-mode handshake captured
live from the reference implementation against
`factsorlie.com:8446` on 2026-05-03.  Both peers in this trace
share the same `cert_index` (the client and server happen to be
the same MTC-CA identity at index 73); this is unusual in
deployment but is what factsorlie's loopback test produces and
exercises the byte layout fully.

All hex strings on the wire are 1184-byte (`EK_c`), 1088-byte
(`CT_s`), or 4627-byte (signatures) blobs; the worked example
shows the first 16 bytes of each as 32 hex chars followed by
`…`.  Where the spec text below shows a 32-byte value (transcript
hash, MAC tag), the full value is given.

**TCP SYN → SYN/ACK → ACK** complete.

ClientHello frame on the wire (after the 4-byte length prefix):

```json
   {
     "version":    0,
     "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
     "mode":       "clear",
     "kem_pub":    "63146e9dbba2f4897c6c2ac0e46801f3…",
     "cert_index": 73,
     "signature":  "6bda001d26890c898bbf53beab9b228f…"
   }
```

The signature is over `transcript_hash_sig(role="client")` per
Section 6.0, with `(EK_c, len=1184; CT_s, len=0; C_s=0)`:

```
   transcript_hash_sig(client)[0:16] = 5b5cf695a45f881bcca7ea80ca217737
```

The signature itself is generated via
`MLDSA-Sign-CtxMsg(SK_c, ctx=LABEL, msg=that 32-byte hash)`.

ServerHello frame on the wire:

```json
   {
     "version":    0,
     "suite":      "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256",
     "mode":       "clear",
     "kem_pub":    "b47d82e1e7a29f97288ee05b9902a63e…",
     "cert_index": 73,
     "signature":  "e687babbe0a6b37e626accf82798d101…"
   }
```

Now both peers know `(EK_c, CT_s, C_c, C_s)` and derive the
session key schedule.

ML-KEM shared secret (32 bytes; client decapsulates, server
already holds it from encapsulation):

```
   SS[0:16] = c5b38efc9430a398befe96549732ca82…
```

Full 32-byte transcript hash for KDF salt
(`transcript_hash_full`, Section 6.0 KDF variant — same input
as the signature transcript MINUS the 6-byte ROLE tag):

```
   transcript_hash_full =
       17c5ff609e48f85604a87e2e4657a024
       024209861dffddb6b2c5f29411d93546
```

HKDF-Extract (Section 8):

```
   data_secret = HKDF-Extract(SHA-256,
                              salt = transcript_hash_full,
                              IKM  = SS)
```

HKDF-Expand off `data_secret` produces the per-direction key set
(info strings abbreviated; the full prefix is
`"mqc/v0/MQC_MLKEM768_MLDSA87_AES256GCM_SHA256/"`):

```
   data_c2s_key       = HKDF-Expand(.../data-c2s-key,       L=32)
                      = 6a3113cb4cda8decf34c9789f933d63b…
   data_s2c_key       = HKDF-Expand(.../data-s2c-key,       L=32)
                      = 3898947d60028fe295f1ca3a219b0d11…
   data_c2s_iv        = HKDF-Expand(.../data-c2s-iv,        L=12)
                      = e035254d24c497c7aa05c0d6
   data_s2c_iv        = HKDF-Expand(.../data-s2c-iv,        L=12)
                      = af9e82995e5a28fa1b468fa9
   data_c2s_finished  = HKDF-Expand(.../data-c2s-finished,  L=32)
                      = e7b904a3ed1709df5e314e0a18ff0e76…
   data_s2c_finished  = HKDF-Expand(.../data-s2c-finished,  L=32)
                      = 527ace3e7da04cd6492cb7e6fa815b4c…
```

The client computes its Finished MAC (Section 8.1) over the same
`transcript_hash_full` shown above, keyed by
`data_c2s_finished`:

```
   finished_mac_c2s =
       HMAC-SHA256(data_c2s_finished, transcript_hash_full)
                 [0:16]
     = 1d25a23644649c060a89f31c7cece15a…
```

The Finished frame is sealed with `data_c2s_key`, IV constructed
per Section 9.2 from `data_c2s_iv` XOR `(0x00 × 4 || u64be(0))`
(sequence 0), and the 31-byte AAD (Section 9.1.1):

```
   AAD[0:16]  = "mqc-frame/v01\n\x00"
   AAD[16]    = 0x00              (version)
   AAD[17]    = 0x00              (direction = c2s)
   AAD[18]    = 0x02              (frame_type = Finished)
   AAD[19:27] = 0x00 × 8          (sequence = 0)
   AAD[27:31] = 0x00 0x00 0x00 0x20  (plaintext_length = 32)
```

The plaintext sealed under those parameters is exactly the
32-byte `finished_mac_c2s` value shown above.  After the seal,
`client.send_seq` advances to 1.  The first application data
frame uses `data_c2s_key` / `data_c2s_iv` at sequence 1 with
`frame_type = 0x03` in the AAD.

The server's Finished frame (sealed with `data_s2c_key`,
sequence 0, `frame_type = 0x02`, `direction = 0x01`) carries:

```
   finished_mac_s2c =
       HMAC-SHA256(data_s2c_finished, transcript_hash_full)
```

Each peer constant-time-compares the received MAC against its
locally recomputed copy.  Match → connection ready for
application data.  Mismatch → terminate with a Finished MAC
failure (distinct from any earlier handshake-signature or AEAD
failure).

## Appendix B. Reference Implementation (informative)

A reference implementation in C, built against the postWolf fork
of wolfSSL, is available at
<https://github.com/cpsource/postWolf> in `socket-level-wrapper-
MQC/`.  A packaged kit suitable for operator install on Ubuntu
24.04 is provided in the same repository as `kit-mqc/`.

The reference implementation has been in continuous deployment on
`factsorlie.com` (ports 8444/TLS, 8445/DH bootstrap, 8446/MQC)
since February 2026.  All CA enrollments, leaf enrollments, cert
renewals, and revocations at that deployment transit MQC in
production.

## Appendix C. Changes from Prior Text (informative)

This revision of `draft-page-mqc-protocol-00` differs from the
text published initially as follows.  The changes were
accumulated during the postWolf reference implementation's Phase
1-3 hardening pass against an external security review of the
codebase.  No formal `-01` was issued; the cumulative edits land
in `-00` because no draft consumer exists outside the reference
deployment.

### Section 4 — Cryptographic Primitives

- Added the `SUITE_ID = SHA-256(SUITE)` mixing rule (the suite
  identifier is now bound into the transcript hash, not just
  echoed in the wire JSON).

### Section 5.2 — Handshake JSON

- Added required fields: `version`, `suite`, `mode`.
- Added the strict-parsing requirements: no parser extensions,
  no trailing bytes, valid UTF-8, each defined field exactly
  once, no unknown top-level fields, lowercase-hex with exact
  byte length per field, integer fields bounded with explicit
  overflow rejection.

### Section 6 — Handshake (clear-identity mode)

- Added §6.0 "Transcript Construction": both ML-DSA signatures
  and the HKDF-Extract salt are now computed over a structured
  transcript hash with the explicit `LABEL`, version,
  `MODE_ID`, `SUITE_ID`, both KEM contributions (with
  byte-length prefixes), both `cert_index` values, and a 6-byte
  ROLE tag.  Previously each signature was over a single field.
- §6.3 client-side flow now requires sending and verifying the
  Finished frame before the connection is considered complete.

### Section 7 — Handshake (encrypted-identity mode)

- Resequenced from 3 frames to 4 frames: phase 1 carries only
  ML-KEM material (plaintext), phase 2 carries the AEAD-sealed
  identity frames keyed by an early secret derived from the
  phase-1 transcript.
- Reference-implementation status note: encrypted-mode entry
  points are stubs in the post-Phase-1 codebase; restoration is
  tracked under `mqc-master.plan` Phase 7.

### Section 8 — Key Derivation

- HKDF in its full Extract+Expand form (RFC 5869), not a single
  Expand off an empty salt.  The Extract salt is the transcript
  hash, so all derived material is bound to every byte both
  peers exchanged.
- Six derived secrets per direction set: `data_<role>_key`
  (32 B), `data_<role>_iv` (12 B), `data_<role>_finished`
  (32 B).  Previously a single 32-byte session key without
  explicit IV or Finished material.
- New §8.1 "Finished Frame": HMAC-SHA256 over the full
  transcript hash, sealed as the first AEAD frame in each
  direction at sequence 0.

### Section 9 — Data Plane

- New §9.1.1 "AEAD AAD": every AEAD-sealed frame binds a
  31-byte AAD (`LABEL || version || direction || frame_type ||
  u64be(sequence) || u32be(plaintext_length)`) into its GCM
  tag.  Previously the AAD was empty.
- §9.2 Nonce construction now uses TLS-1.3-style `iv XOR
  (zero4 || u64be(seq))` on the per-direction IV.  Previously
  the nonce was the raw sequence counter padded with zeros,
  predictable across connections.
- §9.2 application-data sequence numbering starts at **1** in
  both directions because the Finished frame consumes
  sequence 0.

### Section 10 — Peer Verification

- §10.1 rewritten to make the "transport is untrusted"
  assumption explicit: every check in §10.2-§10.6 runs on
  whatever the transport returned, regardless of source.  Added
  the cosigner-fingerprint cache invariant
  (`~/.TPM/peers/<index>/cosigner-fp.hex`) that triggers a
  re-fetch + re-verify when the operator rotates the cosigner.
- §10.2 signature is over the transcript hash (per §6.0), not
  over a single field; the ML-DSA `ctx` is the 16-byte `LABEL`.
- §10.5 revocation upgraded from MAY to MUST, fail-closed by
  default; new operational parameter `mqc-revocation-policy`
  with three values (`mandatory`, `cache-only`, `disabled`).
- New §10.6 "Validity Window": both `not_before` and
  `not_after` MUST be present and within ±`mqc-sig-freshness-sec`
  of the verifier's clock.
- New §10.7 "Expected-Identity Check": after the cryptographic
  chain succeeds, the client MUST compare the verified subject
  string to a caller-supplied expected name (case-insensitive
  exact match OR `<expected>-` prefix); dial-by-IP without an
  explicit expected name fails closed.

### Section 11 — Operational Parameters

- Added a unified knob registry table at the top of §11
  listing 14 tunables and which section governs each.
- §11.1 RECOMMENDED handshake-stall and handshake-total
  timeouts tightened to 3 s / 5 s (from a hand-wave 30 s).
- §11.2 added per-(IP, `cert_index`) rate-limit recommendation
  with two new tunables (`mqc-rl-cert-per-min`,
  `mqc-rl-cert-per-hour`) defending against `cert_index`
  rotation attacks.
- §11.5 documents `mqc-revocation-policy`.
- New §11.6 "Server Concurrency Cap": fork-per-connection
  servers SHOULD cap concurrent children via
  `mqc-max-children` (RECOMMENDED 20).

### Section 12 — Security Considerations

- New §12.7 "Transcript Binding and Cross-Protocol Domain
  Separation": describes which attack classes each transcript
  field defeats.
- New §12.8 "Frame-Header Authentication": describes how the
  AAD turns frame-header tampering into immediate AEAD failure.
- New §12.9 "Identity vs Authority": explains the
  confused-deputy attack that §10.7 closes.
- New §12.10 "JSON Parsing Hardening": describes the four
  attack classes the §5.2 strict-parsing rules close.
- §12.6 strengthened: pre-crypto byte-length validation is
  load-bearing for DoS resistance.

### Appendix A — Worked Example

- Rewritten end-to-end against the post-Phase-1 wire format
  using bytes captured live from the reference implementation
  on 2026-05-03.  Previous version showed the pre-Phase-1
  3-field JSON, the single-key HKDF derivation, and a
  zero-padded nonce — all wrong relative to current text.

### Cumulative scope

The numerical impact is: the .md source grew from ~810 lines
(initial draft) to ~1700 lines (post-edit), with the bulk in
the new transcript-construction text (§6.0), the four new
§12.x security-considerations subsections, the AAD definition
(§9.1.1), the Finished frame (§8.1), and the §10.6/§10.7 peer-
verification additions.
