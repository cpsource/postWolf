# Unsure / Open Questions

## Leaf Enrollment: Public Key Fingerprint Binding

The leaf enrollment flow assumes the following:

1. The leaf generates a keypair locally
2. The leaf gives its public key fingerprint to the CA operator (out of band)
3. The CA operator calls `POST /enrollment/nonce` with the leaf's domain + the leaf's public key fingerprint
4. The CA operator gives the nonce back to the leaf (out of band)
5. The leaf calls `POST /certificate/request` with its public key PEM + the nonce
6. The server hashes the submitted public key, confirms it matches the fingerprint the nonce was bound to

This ensures only the holder of that specific keypair can use the nonce. If someone steals the nonce, they can't use it with a different key.

**Question:** Is this the correct understanding of how the public key fingerprint binding works in the enrollment flow?

## Design Proposal: Client-Side Certificate Renewal Without Nonces

### Problem

The current renewal tool (`renew.py`) is designed to run on the server machine.
Remote clients cannot renew autonomously because enrollment requires a nonce
issued by the CA operator. This creates two bad options:

1. The CA operator manually issues nonces every time a client cert approaches expiry.
2. The CA operator holds the client's private keys and renews on their behalf —
   which breaks the trust model (private key should never leave the client).

### Proposed Solution: `POST /certificate/renew`

If a client already has a valid certificate with a private key, it can prove
its identity by signing with that key. No nonce or CA operator involvement needed.

**Flow:**

1. Client detects its cert is approaching expiry (via local cron)
2. Client optionally generates a new keypair (key rotation)
3. Client calls `POST /certificate/renew` with:
   - `cert_index` — the current certificate's log index
   - `new_public_key_pem` — the new public key (or same key if not rotating)
   - `signature` — a signature over the request payload, made with the **old** private key
4. Server looks up the existing certificate in the log by index
5. Server verifies the signature against the public key hash in the logged entry
6. Server issues a new certificate — no nonce, no CA operator involvement
7. Client updates `~/.TPM/<subject>/` with the new certificate

**Why this works:** The old private key is the proof of identity. Only the
legitimate key holder can produce a valid signature. The transparency log
provides the server with the public key to verify against.

**Edge cases to consider:**

- What if the old cert has already expired? Grace period?
- What if the old cert was revoked? Reject renewal.
- Rate limiting to prevent abuse.
- Should the server require the old cert to be within N days of expiry
  before allowing renewal?
