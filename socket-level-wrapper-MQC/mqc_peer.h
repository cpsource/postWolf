/* mqc_peer.h — MQC Peer Verification
 *
 * Fetch, cache, and verify peer certificates from the MTC
 * transparency log. Returns the peer's public key for
 * signature verification during the MQC handshake.
 */

#ifndef MQC_PEER_H
#define MQC_PEER_H

#include <stdint.h>

/* is_server: 1 = acceptor side (performs revocation check; has vested
 * interest in rejecting revoked incoming peers); 0 = initiator side
 * (skips revocation check, saving a round trip).  This reflects the
 * asymmetry of "who's at risk when the peer is revoked": the acceptor
 * is the party that would forward traffic to a revoked identity. */

/* Verify a peer by cert_index against the Merkle transparency log.
 *
 * Steps:
 *   1. Check ~/.TPM/peers/<index>/certificate.json (cache)
 *   2. If miss: fetch from MTC server
 *   3. Verify Merkle inclusion proof + cosignature
 *   4. Check revocation (server-side only) + validity
 *   5. Return peer's public key DER
 *
 * mtc_server:     MTC server URL (e.g., "localhost:8444")
 * ca_pubkey:      CA Ed25519 cosigner public key
 * ca_pubkey_sz:   Size of ca_pubkey
 * cert_index:     Peer's certificate log index
 * is_server:      1 = acceptor, 0 = initiator (see above)
 * pubkey_out:     Output: malloc'd DER public key (caller frees)
 * pubkey_sz_out:  Output: size of pubkey_out
 *
 * Returns 0 on success, -1 on failure. */
int mqc_peer_verify(const char *mtc_server,
                    const unsigned char *ca_pubkey, int ca_pubkey_sz,
                    int cert_index, int is_server,
                    unsigned char **pubkey_out, int *pubkey_sz_out);

/* Get a cached peer's public key without re-verifying.
 * Returns 0 if found in cache, -1 if not cached. */
int mqc_peer_get_cached_pubkey(int cert_index,
                               unsigned char **pubkey_out, int *pubkey_sz_out);

#endif /* MQC_PEER_H */
