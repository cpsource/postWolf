Excellent. Item 3:

## MQC vs TLS 1.3 security-property map

| Security property        | TLS 1.3                              | MQC current state                                       | MQC recommendation                                                   |
| ------------------------ | ------------------------------------ | ------------------------------------------------------- | -------------------------------------------------------------------- |
| Server authentication    | X.509 cert chain to trusted CA       | Merkle/MQC cert + CA cosigner                           | Good direction, but enforce key-hash binding                         |
| Bootstrap trust          | WebPKI / root store                  | Previously TOFU on 8445                                 | Replace TOFU with DNSSEC TXT `kh=` pinning                           |
| Key exchange             | ECDHE / hybrid PQ optional           | PQ KEM                                                  | Good, assuming KEM ciphertext and shared secret are transcript-bound |
| Forward secrecy          | Yes, via ephemeral ECDHE             | Depends on ephemeral KEM use                            | Ensure KEM key material is ephemeral per session                     |
| Handshake transcript     | Hash of exact handshake messages     | Field-based transcript                                  | Prefer exact framed bytes or strict canonical encoding               |
| Finished MAC             | Required                             | Present                                                 | Good; ensure both sides verify before application data               |
| Application encryption   | AEAD                                 | AES-GCM style AEAD                                      | Good; fix receive sequence increment after auth success              |
| Framing                  | Strict TLS records                   | Spec says length-prefixed, code uses JSON brace parsing | Must fix: 4-byte length-prefixed frames                              |
| Replay resistance        | Nonces, transcript, sequence numbers | Partial                                                 | Add explicit anti-replay policy for registration and handshake       |
| Certificate transparency | CT optional/public ecosystem         | Merkle tree is central                                  | Strong idea; require inclusion proof before trusting cert            |
| Revocation               | OCSP/CRL/status mechanisms           | Revocation cache/fetch                                  | Good, but avoid “first contact must fail” behavior if possible       |
| Identity privacy         | SNI exposed unless ECH               | Encrypted identity mode exists                          | Promising, but document and test it fully                            |
| Downgrade protection     | Built into transcript                | Suite hash/version included                             | Good; reject unknown downgrade paths                                 |
| Parser robustness        | Binary, strict structures            | JSON + ad-hoc framing                                   | Weakest implementation area                                          |

## Main conclusion

MQC’s **conceptual model can match several TLS 1.3 properties**, especially once DNSSEC replaces TOFU:

```text
DNSSEC → domain CA key hash → Merkle CA cert → leaf cert → MQC session
```

That gives you a clean trust chain.

But the **implementation is still weaker than TLS 1.3 mainly because of parsing/framing and canonicalization**, not because the crypto idea is bad.

## Highest-priority MQC fixes

1. **Replace brace-count JSON reads with length-prefixed frames.**
2. **Bind public keys to certs by checking `hash(pubkey) == subject_public_key_hash`.**
3. **Make DNSSEC TXT pinning mandatory for 8445 bootstrap.**
4. **Hash exact canonical handshake frames into the transcript.**
5. **Require Merkle inclusion proof before accepting CA/leaf certs.**
6. **Increment AEAD receive sequence only after successful decrypt/auth.**

After those, MQC becomes much closer to a real TLS-like authenticated key exchange.

