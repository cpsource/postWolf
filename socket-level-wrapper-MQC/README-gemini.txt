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

