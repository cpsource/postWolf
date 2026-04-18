/**
 * @file mtc_pubkey_db.h
 * @brief Store public keys in the Neon mtc_public_keys table.
 */

#ifndef MTC_PUBKEY_DB_H
#define MTC_PUBKEY_DB_H

/**
 * @brief  Store a public key in the mtc_public_keys table.
 *
 * Connects to Neon via MERKLE_NEON in ~/.env, upserts the key.
 * Non-fatal: logs a warning on failure but does not abort.
 *
 * @param[in] key_name  Unique key identifier (domain name).
 * @param[in] key_value Public key PEM text.
 */
void mtc_store_public_key(const char *key_name, const char *key_value);

#endif /* MTC_PUBKEY_DB_H */
