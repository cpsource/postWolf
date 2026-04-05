/* ca-pubkey.h — Pinned CA Ed25519 public key for offline verification
 *
 * This key is obtained out-of-band from one of:
 *   - DNS TXT record: _mtc-ca-key.factsorlie.com
 *   - MTC server:     GET factsorlie.com/ca/public-key
 *   - Project website or signed git tag
 *
 * Replace the placeholder bytes below with your CA's actual 32-byte
 * Ed25519 public key.
 */

#ifndef FIPS_CA_PUBKEY_H
#define FIPS_CA_PUBKEY_H

static const unsigned char fips_ca_pubkey[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    /* TODO: replace with actual CA public key */
};

#endif /* FIPS_CA_PUBKEY_H */
