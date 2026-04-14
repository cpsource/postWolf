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
