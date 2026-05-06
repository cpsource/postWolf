I reviewed the uploaded `s2.tar.gz`. Priority fixes:

## P0 — fix before exposing this server

1. **Replace `mtc_crypt.c` entirely**

   * Current bootstrap encryption uses AES-CBC, **zero IV**, no MAC/AEAD, custom byte rotation, and “find last `}`” padding removal.
   * This is malleable and not authenticated. Use `XChaCha20-Poly1305`, `AES-GCM`, or wolfSSL’s AEAD with fresh nonce per message.
   * Files: `mtc_crypt.c:370-483`, `mtc_bootstrap.c:725-735`.

2. **Add authentication to the DH bootstrap handshake**

   * Server DH public key is plaintext and unsigned. A MITM can substitute DH keys, even if later response signing limits some damage.
   * Fix: sign the server’s ephemeral DH public key, salt, nonce, protocol version, and transcript with the cosigner key, or run bootstrap over MQC/TLS.

3. **Stop issuing leaf nonces to anyone who merely names an existing CA domain**

   * `POST /enrollment/nonce` for leaf checks only that a CA exists for the domain, then issues a nonce.
   * That means any internet client can request a leaf nonce for `factsorlie.com` if the CA exists.
   * Fix: make leaf nonce issuance MQC-authenticated by the CA, or require a CA signature over `(domain, label, fp, ttl)`.
   * File: `mtc_http.c:661-680`.

4. **Remove late-bind reservation nonces or strongly constrain them**

   * If `fp` is NULL, consume accepts any key and binds it at first use.
   * A stolen/leaked reservation nonce becomes a bearer token for arbitrary key enrollment.
   * Fix: require fingerprint at nonce creation, or require CA-signed authorization at consumption.
   * File: `mtc_db.c:1350-1361`.

## P1 — high priority

5. **Bootstrap fork loop lacks child backpressure/reaping**

   * HTTP/MQC have active-child backpressure; bootstrap forks without the same guard.
   * A connection flood can fork-storm the host.
   * Fix: reuse `mtc_wait_for_child_slot()` / SIGCHLD accounting for bootstrap.
   * File: `mtc_bootstrap.c:1716-1736`.

6. **HTTP parser can slow-loris**

   * Main HTTP read loop has no socket read timeout before parsing headers.
   * Bootstrap has timeouts; HTTP/MQC path should too.
   * File: `mtc_http.c:2078-2140`.

7. **Plain HTTP mode can expose write endpoints**

   * `handle_request()` permits `/enrollment/nonce`, `/renew-cert`, `/revoke`, etc. based on path checks; only some handlers enforce MQC.
   * Fix: reject sensitive POSTs unless `io->mqc` or trusted TLS-client-auth is present.
   * File: `mtc_http.c:2165-2192`.

8. **`http_get` proxy on bootstrap exposes arbitrary GET dispatcher over plaintext**

   * It rejects non-`/` paths, but otherwise proxies all GETs.
   * Fix: allowlist only harmless endpoints needed by bootstrap clients.
   * File: `mtc_bootstrap.c:324-339`.

## P2 — correctness / hardening

9. **Label is stored “verbatim”**

   * Comment says sanitization is client-side. Server should enforce `[A-Za-z0-9._-]`, length, and no path-ish values.
   * File: `mtc_http.c:620-626`.

10. **Persistence failures after in-memory success are not fatal everywhere**

* I saw warnings after `save_certificate` / `save_public_key`. These should fail closed or queue retry before returning success.
* File: `mtc_bootstrap.c:1560-1584`.

11. **Custom canonical JSON signing is fragile**

* Signing relies on json-c insertion order / serialization matching.
* Fix: use a real canonicalization scheme: RFC 8785 JCS or sign fixed binary fields.

12. **CA X.509 `NO_VERIFY` is deliberate, but document it loudly**

* Your DNSSEC SPKI pin + PoP signature mostly compensates. Still, this is nonstandard and future maintainers may misuse the cert as a real X.509 trust object.
* File: `mtc_ca_validate.c:37-75`.

## Best first patch sequence

1. Replace `mtc_crypt` with AEAD.
2. Sign the bootstrap DH transcript.
3. Require CA-authenticated leaf nonce issuance.
4. Disable late-bind nonce consumption.
5. Add bootstrap child backpressure.
6. Add HTTP read timeouts and reject sensitive POSTs on plain transport.

