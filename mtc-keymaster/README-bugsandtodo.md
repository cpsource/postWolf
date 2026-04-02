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
