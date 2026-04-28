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

**Session key.**  A 32-byte AES-256-GCM key derived from the
ML-KEM-768 shared secret via HKDF-SHA256.

**Frame.**  A single length-prefixed, AEAD-sealed unit on the wire
after the handshake completes.

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
             |  ClientHello  (JSON)                  |
             |  ─ ML-KEM-768 public key             |
             |  ─ ML-DSA-87 signature over same     |
             |  ─ MTC cert_index                    |
             |------------------------------------->|
             |                                      |
             |            ServerHello  (JSON)        |
             |            ─ ML-KEM-768 ciphertext   |
             |            ─ ML-DSA-87 signature     |
             |            ─ MTC cert_index          |
             |<-------------------------------------|
             |                                      |
        HKDF-SHA256(shared_secret, "mqc-session-c2s") → 32-byte c2s_key
        HKDF-SHA256(shared_secret, "mqc-session-s2c") → 32-byte s2c_key
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
distinguished by inspection (Section 7.1).

| Role | Algorithm | Spec |
|---|---|---|
| KEM (ephemeral key establishment) | ML-KEM-768 | [FIPS203] |
| Signature (peer identity, handshake binding) | ML-DSA-87 | [FIPS204] |
| Key derivation | HKDF-SHA256 | [RFC5869] |
| Hash for HKDF and transcript | SHA-256 | [FIPS180] |
| Bulk cipher | AES-256-GCM | [FIPS197] |
| Log cosigner | ML-DSA-87 | [FIPS204] |

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
hex-encoded (lowercase, no separators).  The following fields are
defined:

| Field | Type | Description |
|---|---|---|
| `kem_pub` | hex string | ML-KEM-768 encapsulation key (client→server) or ciphertext (server→client) |
| `signature` | hex string | ML-DSA-87 signature, see Section 10 |
| `cert_index` | integer | MTC log index of the signing identity |
| `encrypted` | hex string | AEAD-sealed identity blob (encrypted-identity mode only) |

An implementation SHOULD serialize the JSON compactly (no
whitespace) to keep the `payload length` predictable, but MUST NOT
reject a peer's JSON solely for containing whitespace.

---

## 6. Handshake (clear-identity mode)

### 6.1. Client → Server

Upon establishing the TCP connection, the client:

1. Generates an ephemeral ML-KEM-768 keypair.  Let `EK_c` be the
   encoded public (encapsulation) key and `DK_c` the decoded
   secret (decapsulation) key.
2. Signs `EK_c` under its long-term ML-DSA-87 private key, yielding
   signature `Sig_c`.
3. Sends one handshake frame containing the JSON:

```json
   {
     "kem_pub":    "<hex(EK_c)>",
     "signature":  "<hex(Sig_c)>",
     "cert_index": <int C_c>
   }
```

### 6.2. Server → Client

The server, upon receiving the client's handshake frame:

1. Hex-decodes `EK_c` and `Sig_c`; parses `C_c`.
2. Retrieves the MTC certificate at index `C_c` (see Section 10)
   and extracts its ML-DSA-87 public key `PK_c`.
3. Verifies `Sig_c = MLDSA-Verify(PK_c, EK_c)`.  If verification
   fails, the server MUST disconnect and SHOULD record the
   failure.
4. Performs ML-KEM-768 encapsulation against `EK_c`, producing
   ciphertext `CT_s` and shared secret `SS`.
5. Signs `CT_s` under its long-term ML-DSA-87 private key,
   yielding signature `Sig_s`.
6. Sends a handshake frame containing:

```json
   {
     "kem_pub":    "<hex(CT_s)>",
     "signature":  "<hex(Sig_s)>",
     "cert_index": <int C_s>
   }
```

### 6.3. Client Key Derivation

The client, upon receiving the server's handshake frame:

1. Hex-decodes `CT_s` and `Sig_s`; parses `C_s`.
2. Retrieves the MTC certificate at index `C_s` and extracts its
   ML-DSA-87 public key `PK_s`.
3. Verifies `Sig_s = MLDSA-Verify(PK_s, CT_s)`.
4. Decapsulates `SS = MLKEM-Decap(DK_c, CT_s)`.
5. Derives the session key (Section 8).

At this point both parties share `SS` and derive the same 32-byte
AES-256-GCM session key.  The handshake is complete.

Upon handshake completion each endpoint MUST zeroize its
ephemeral ML-KEM private key material and any intermediate shared-
secret buffers that are not required post-handshake.

---

## 7. Handshake (encrypted-identity mode)

Encrypted-identity mode hides both `cert_index` values from a
passive observer at the cost of one additional round trip.

### 7.1. Distinguishing the Mode

The client selects the mode.  The server distinguishes the two
modes by inspecting the first handshake frame: if the JSON
contains a `cert_index` field, the mode is clear-identity; if not,
the mode is encrypted-identity.

### 7.2. Encrypted-Identity ClientHello

The client sends a first frame containing only:

```json
   {
     "kem_pub": "<hex(EK_c)>"
   }
```

Note the absence of `cert_index` and `signature`.

### 7.3. Encrypted-Identity ServerHello

The server derives a preliminary AEAD key from `SS` (Section 8)
and sends a frame whose JSON contains:

```json
   {
     "kem_pub":   "<hex(CT_s)>",
     "encrypted": "<hex(AEAD-Seal(k, nonce=0, identity_s))>"
   }
```

where `identity_s` is a nested JSON object `{"cert_index": C_s,
"signature": Sig_s}` serialized to UTF-8.  The AEAD key for this
server→client frame is `s2c_key`, derived from `SS` via HKDF as
in Section 8.  The nonce is eight bytes of zero in the counter
region (Section 9.2) and is consumed exactly once on `s2c_key`.

### 7.4. Encrypted-Identity Client Identity

After completing key establishment and verifying the server's
signature (as in Section 6.3), the client sends a second,
AEAD-sealed frame:

```json
   {
     "encrypted": "<hex(AEAD-Seal(c2s_key, nonce=0, identity_c))>"
   }
```

where `identity_c = {"cert_index": C_c, "signature":
MLDSA-Sign(EK_c)}`.  This frame is sealed with `c2s_key`, an
independent key from §7.3's `s2c_key`; both directions may use
nonce counter 0 because the keys differ.

### 7.5. Sequence Starts After Identity Frames

Each direction's nonce counter advances independently because
each direction has its own key.  In encrypted-identity mode each
side has consumed nonce 0 on its respective key (one frame), so
the first data-plane frame in either direction MUST use nonce
counter 1 (Section 9.2).  In clear-identity mode no AEAD frames
were exchanged during handshake, so each direction's data-plane
counter begins at 0.

---

## 8. Key Derivation

Both modes derive **two** 32-byte AES-256-GCM session keys from
the ML-KEM-768 shared secret — one per direction:

```
    c2s_key = HKDF-SHA256(
                IKM      = SS,                       // 32 bytes
                salt     = <empty>,                  // zero-length
                info     = "mqc-session-c2s",        // ASCII, 15 bytes
                L        = 32)

    s2c_key = HKDF-SHA256(
                IKM      = SS,
                salt     = <empty>,
                info     = "mqc-session-s2c",        // ASCII, 15 bytes
                L        = 32)
```

`c2s_key` encrypts every client→server frame; `s2c_key` encrypts
every server→client frame.  Each direction maintains its own
nonce counter (Section 9.2).  Per-direction keys eliminate the
possibility of `(key, nonce)` pair reuse across directions, which
under AES-256-GCM would leak both plaintexts and the GHASH
authentication key.

---

## 9. Data Plane

### 9.1. Frame Structure

After handshake completion, every frame carries:

- The 32-bit big-endian length prefix (Section 5.1).
- `payload length` bytes of AEAD output: `ct || tag`, where
  `ct` is the AES-256-GCM ciphertext of the application
  plaintext and `tag` is the 16-byte authentication tag.

No additional headers are inserted between the length prefix and
the AEAD output.

### 9.2. Nonce Construction

Each endpoint maintains two 64-bit unsigned counters:

- `send_seq`, initialized at 0 (clear-identity mode) or 1
  (encrypted-identity mode, Section 7.5).
- `recv_seq`, initialized at the same value as `send_seq`.

To send a frame, an endpoint forms a 12-byte GCM nonce:

```
      nonce[0..4]   = 0x00 0x00 0x00 0x00    (reserved zeros)
      nonce[4..12]  = htobe64(send_seq)       (8-byte big-endian)
```

and encrypts with:

```
      (ct, tag) = AES-256-GCM-Seal(
                      key = K_send,
                      nonce = nonce,
                      aad = <empty>,
                      plaintext = application_payload)
```

where `K_send` is `c2s_key` on the client and `s2c_key` on the
server (Section 8).  It then increments `send_seq` by one.

To receive a frame, an endpoint uses `recv_seq` to form the
nonce in the same way and decrypts with `K_recv` — `s2c_key` on
the client, `c2s_key` on the server — then increments `recv_seq`
on success.  A decryption failure MUST cause the connection to
be terminated; the endpoint SHOULD record the failure for
rate-limiting (Section 11.2).

Direction separation is enforced by the **per-direction key**,
not by the nonce.  Endpoint counters may collide (both sides at
`send_seq = N` simultaneously) without consequence: an AES-GCM
collision requires the same `(key, nonce)` pair, and the keys
differ.

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
certificate.  Implementations SHOULD cache verified certificates
locally to avoid repeated log queries; a typical cache structure
stores one file per `cert_index` under a path such as
`~/.TPM/peers/<index>/certificate.json`.

Retrieval MAY be performed over the same MQC connection if the
peer is the log itself, or out of band via HTTP against a known
log-service URL.

### 10.2. ML-DSA-87 Signature on the Handshake

The verifier extracts the ML-DSA-87 public key from the retrieved
certificate and verifies that `signature` in the handshake frame
is a valid ML-DSA-87 signature, under that public key, over:

- the sender's `kem_pub` field value (the ML-KEM-768 encapsulation
  key for the client; the ML-KEM-768 ciphertext for the server).

This binds the ephemeral KEM exchange to the long-term identity.

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
context (`ctx = NULL, ctxLen = 0`), matching the handshake-signature
call in Section 6.

### 10.5. Revocation

For each verified peer, the verifier MAY query a log endpoint for
the revocation status of `cert_index`.  A positive revocation
answer MUST cause the handshake to be aborted.  Implementations
SHOULD cache negative ("not revoked") answers for a bounded TTL
(a default of 24 hours is RECOMMENDED); see Section 12 for the
implications of caching.

---

## 11. Operational Parameters

### 11.1. Timeouts

An implementation SHOULD impose a total wall-clock deadline on the
handshake (RECOMMENDED default: 30 seconds from TCP accept to
handshake completion), and a per-read deadline on the data plane
(RECOMMENDED default: 60 seconds).  Exceeding either deadline MUST
cause the connection to be terminated.

### 11.2. Rate Limiting

Servers SHOULD enforce per-source-IP rate limits on:

- **connection attempts**, to limit opportunistic scanning;
- **handshake failures**, to limit brute-force attempts on peer
  identity;
- **per-endpoint request counters** (after connection, at the
  application-protocol layer above MQC) using at least a
  per-minute and a per-hour bucket.

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
- **Every wire primitive targets at least NIST Category 3 against
  a quantum adversary.**  The log cosigner (Section 10.4) uses
  ML-DSA-87 — identical to peer identity — so there is no
  pre-quantum hedge remaining in the chain of trust.  An operator
  migrating from an earlier draft that used Ed25519 for the
  cosigner should refer to the `migrate-cosigner` tool in the
  reference implementation for the one-shot rotation procedure.

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

The following is a single clear-identity mode handshake, captured
from the reference implementation.  All values are truncated for
brevity; hex strings have been shortened to 32 characters and
followed by `...`.

**TCP SYN → ACK** complete.

ClientHello frame:
```
     0x00 0x00 0x04 0x92        ; payload length = 1170 bytes
     {                          ; JSON payload
       "kem_pub":
         "b3f07a1cde23... (1184 hex chars total)",
       "signature":
         "5a90...  (9256 hex chars total)",
       "cert_index": 74
     }
```

ServerHello frame:
```
     0x00 0x00 0x04 0x8e        ; payload length = 1166 bytes
     {
       "kem_pub":
         "2e5471cc... (2176 hex chars total, ML-KEM CT)",
       "signature":
         "91b2...  (9256 hex chars total)",
       "cert_index": 12
     }
```

Both sides now derive:

```
    shared_secret = MLKEM-Decap(DK_c, CT_s)     // on client
                  = MLKEM-Encap-Result(EK_c)     // on server (already held)
    c2s_key       = HKDF-SHA256(shared_secret,
                                salt="",
                                info="mqc-session-c2s",
                                L=32)
    s2c_key       = HKDF-SHA256(shared_secret,
                                salt="",
                                info="mqc-session-s2c",
                                L=32)
```

The first data-plane frame from client to server uses `c2s_key`
with GCM nonce:

```
     00 00 00 00  00 00 00 00 00 00 00 00
```

and increments `client.send_seq` to 1 after encryption.  The
first server→client frame uses `s2c_key` with the same nonce —
safe, because the keys differ.

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
