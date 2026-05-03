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

