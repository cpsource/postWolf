# TODO #78 — `mqc` symmetric envelope hardening (external review)

Verbatim external review of the JSON envelope produced by
`mqc --encode` (the format used for
`server-configuration-data/{env,auth-bundle.tar}.enc.json`).

Captured 2026-05-09.  Cross-reference: `mtc-keymaster/README-bugsandtodo.md`
TODO #78 (the proposed fix list) and `socket-level-wrapper-MQC/examples/mqc.c`
(the implementation).

---

Yes. It’s **mostly good shape**, but I see some security concerns.

The file uses `scrypt` with `N=32768,r=8,p=1`, a random-looking salt, a 12-byte IV, ciphertext, and a 16-byte tag, which strongly suggests an AEAD mode like AES-GCM or ChaCha20-Poly1305. That part is reasonable.

Weak spots:

1. **No algorithm field**

   * It says `"kdf":"scrypt"` but not the encryption algorithm.
   * Add:

   ```json
   "cipher": "AES-256-GCM"
   ```

   or:

   ```json
   "cipher": "XChaCha20-Poly1305"
   ```

2. **Header may not be authenticated**

   * Fields like `domain`, `tool`, `created`, `N`, `r`, `p`, `salt`, and `iv` should be included as AEAD associated data.
   * Otherwise an attacker may tamper with metadata even if they cannot decrypt.

3. **scrypt parameters are okay but not very high**

   * `N=32768,r=8,p=1` is decent, but for protecting server secrets I’d prefer stronger defaults if latency is acceptable:

   ```text
   N=1048576, r=8, p=1
   ```

   or switch to **Argon2id**.

4. **No key identifier / recipient**

   * Add a `key_id` or `recipient` so the decryptor knows what key/password is expected.

5. **No rollback protection**

   * Someone could replace this with an older valid `env.enc.json`.
   * Add a monotonic version, log it in MTC, or store the expected file hash elsewhere.

6. **Domain binding is useful, but only if authenticated**

   * `"domain":"factsorlie.com-ca"` helps prevent cross-use, but only if that field is in the AEAD associated data.

So: **not obviously broken**, but strengthen it by authenticating all metadata, naming the cipher, increasing KDF cost if possible, and adding rollback protection.
