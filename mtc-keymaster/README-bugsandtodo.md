# MTC Keymaster — Bugs and TODO

## TODO

### 1. Client-side Merkle proof and cosignature verification

**Priority:** High — required before opening to third parties

The C client (`src/ssl_mtc.c` `MTC_Verify`) currently trusts the CA server's
response for inclusion proof validity and cosignature presence. It does not
independently verify either:

- **Inclusion proof:** Client accepts `"valid":true` from `GET /log/proof/<N>`
  without recomputing the Merkle hash chain.
- **Cosignature:** Client checks that a cosignature exists (`count > 0`) but
  does not verify the Ed25519 signature.

When third parties operate their own CAs (registered via DNS TXT validation),
a compromised CA server could return `"valid":true` for a forged certificate.
The client must independently verify:

1. Recompute the Merkle inclusion proof (SHA-256 hash chain from leaf to root)
2. Verify the Ed25519 cosignature over the subtree root using the bootstrapped
   CA public key
3. Verify the leaf belongs to a registered CA (chain validation)

The Python client (`mtc_client.py` `verify_standalone_certificate`) already
does real verification and can serve as reference. wolfSSL has SHA-256 and
Ed25519 verify APIs available.

**Files:**
- `src/ssl_mtc.c` — `MTC_Verify()` (lines ~453-540)
- `mtc-keymaster/tools/python/mtc_client.py` — reference implementation
- `examples/quic-mtc/quic_mtc_common.h` — `qmtc_verify()`

### 2. Server-side leaf-to-CA authorization check

**Priority:** High — required before opening to third parties

The server currently issues leaf certificates to anyone who POSTs to
`/certificate/request` without checking whether a registered CA exists for
that domain. A third party could enroll a leaf for any domain (e.g.
`candyorus.com`) without owning a CA for it.

The server should enforce:

1. Leaf request arrives for subject `example.com`
2. Server checks if a registered CA exists for this domain — look for
   `example.com-ca` in `mtc_certificates` (enrolled via `enroll-ca` with
   DNS TXT validation)
3. If a matching CA is found → issue the leaf
4. If no matching CA → reject with 403

This pairs with the existing DNS TXT validation for CA enrollment
(`_mtc-ca.<domain>` TXT record). Together they form a two-step authorization:

- **CA enrollment:** domain owner proves control via DNS TXT record
- **Leaf enrollment:** server verifies a CA for that domain was previously
  registered

The leaf request should also include `CA:FALSE` and the SAN DNS name in its
extensions so the server can match the domain and confirm it is not a CA.

**Files:**
- `mtc-keymaster/server/c/mtc_http.c` — `handle_certificate_request()`
- `mtc-keymaster/server/c/mtc_store.c` — needs a lookup by subject function
- `mtc-keymaster/server/python/server.py` — Python server equivalent
