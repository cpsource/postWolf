/* mqcp_peer.h — Peer verification (cache-only, no curl)
 *
 * Resolves a peer's ML-DSA-87 public key from the local TPM cache.
 * No network calls — peers must be pre-cached in ~/.TPM/peers/<index>/.
 */

#ifndef MQCP_PEER_H
#define MQCP_PEER_H

#include <stdint.h>

/* Verify a peer by cert_index using local cache only.
 *
 * Looks up ~/.TPM/peers/<cert_index>/public_key.pem and converts to DER.
 * No HTTP, no curl.
 *
 * cert_index:     Peer's certificate log index
 * pubkey_out:     Output: malloc'd DER public key (caller frees)
 * pubkey_sz_out:  Output: size of pubkey_out
 *
 * Returns 0 on success, -1 if peer not found in cache. */
int mqcp_peer_get_pubkey(int cert_index,
                         unsigned char **pubkey_out, int *pubkey_sz_out);

#endif /* MQCP_PEER_H */
