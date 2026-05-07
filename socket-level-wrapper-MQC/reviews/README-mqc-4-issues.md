> **Reading order.** This file is the TLS-1.3 vs MQC
> security-property map (six highest-priority fixes).  For the
> current "what is still open?" scoreboard, see
> [`../README-mqc-issues-summary.md`](../README-mqc-issues-summary.md);
> the cross-check against this property map lives in that
> file's "Cross-check against the TLS-1.3 property map"
> section.

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

1. **Replace brace-count JSON reads with length-prefixed frames.** — DONE (mqc-2 P1, commit `45e8390d4`)
2. **Bind public keys to certs by checking `hash(pubkey) == subject_public_key_hash`.** — DONE (mqc-2 P2, commit `dfd06d187`)
3. **Make DNSSEC TXT pinning mandatory for 8445 bootstrap.** — DONE (mqc-3 server, commit `bf21e4fc9`; tightened in `bdbf08309`)
4. **Hash exact canonical handshake frames into the transcript.** — DEFERRED as TODO #54 in `mtc-keymaster/README-bugsandtodo.md`; field-based transcript stays for now (see commit `705ccbc21` for the rationale).
5. **Require Merkle inclusion proof before accepting CA/leaf certs.** — DONE (already in tree at `socket-level-wrapper-MQC/mqc_peer.c::mqc_peer_verify` step 3 + cosignature verify at step 4; both client and server reject with `MQC_SECURITY("PROOF_INVALID: cert N")` on failure).
6. **Increment AEAD receive sequence only after successful decrypt/auth.** — DONE 2026-05-04 (commit `88b7fadbe`).  `mqc_common.c::mqc_enc_recv` and `mqc_read` now advance `*seq` / `conn->recv_seq` only on `wc_AesGcmDecrypt` success; failure logs name the actually-failing sequence number.  Verified: 79/79 `attack-port-8446` probes still pass and the happy path is unchanged.

After those, MQC becomes much closer to a real TLS-like authenticated key exchange.

