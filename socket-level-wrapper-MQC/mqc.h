/* mqc.h — Merkle Quantum Connect API
 *
 * Post-quantum authenticated encrypted connections using:
 *   - ML-KEM-768 key exchange (FIPS 203)
 *   - ML-DSA-87 signed authentication (FIPS 204)
 *   - Merkle tree proof verification (RFC 9162)
 *   - AES-256-GCM session encryption (FIPS 197 + SP 800-38D)
 *
 * No TLS. No X.509. Peers identify by cert_index — an integer
 * referencing their entry in the Merkle transparency log. Public
 * keys are resolved from the log on demand and cached locally.
 *
 * See README-MQC-specifications.md for the full protocol spec.
 *
 * Copyright (C) 2026 Cal Page. All rights reserved.
 */

#ifndef MQC_H
#define MQC_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef struct mqc_ctx  mqc_ctx_t;
typedef struct mqc_conn mqc_conn_t;

/* Connection role */
typedef enum {
    MQC_CLIENT,
    MQC_SERVER
} mqc_role_t;

/* Context configuration */
typedef struct {
    mqc_role_t  role;            /* MQC_CLIENT or MQC_SERVER */
    const char *tpm_path;        /* ~/.TPM/<domain> — our identity.
                                  * Must contain certificate.json and
                                  * private_key.pem (ML-DSA-87). */
    const char *mtc_server;      /* MTC CA server for peer key resolution
                                  * (e.g., "localhost:8444"). */
    const unsigned char *ca_pubkey;  /* CA Ed25519 cosigner public key
                                      * (32 bytes) for Merkle proof
                                      * verification. */
    int ca_pubkey_sz;            /* Size of ca_pubkey (typically 32). */
    int encrypt_identity;        /* 1 = encrypt cert_index during handshake
                                  * (hides who is connecting from eavesdroppers).
                                  * Adds half a round trip. Default: 0 (off). */
} mqc_cfg_t;

/* --- Context management --- */

/* Create an MQC context from configuration.
 * Loads our identity (cert_index + ML-DSA-87 private key) from tpm_path.
 * Returns NULL on failure. */
mqc_ctx_t *mqc_ctx_new(const mqc_cfg_t *cfg);

/* Free a context and zero all key material. */
void mqc_ctx_free(mqc_ctx_t *ctx);

/* --- Connection lifecycle --- */

/* Connect to an MQC server. Performs TCP connect + signed ML-KEM key
 * exchange + Merkle proof verification of the peer.
 * Returns NULL if connection or any verification step fails. */
mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port);

/* Create a listening socket. Pure POSIX — no crypto.
 * Returns listen fd on success, -1 on failure. */
int mqc_listen(const char *host, int port);

/* Accept a client connection and perform MQC handshake.
 * Returns NULL if accept or any verification step fails. */
mqc_conn_t *mqc_accept(mqc_ctx_t *ctx, int listen_fd);

/* Connect/accept with encrypted identity (hides cert_index from eavesdroppers).
 * Two-phase handshake: ML-KEM key exchange first (plaintext), then
 * cert_index + signatures encrypted with the derived key.
 * Adds half a round trip compared to mqc_connect/mqc_accept. */
mqc_conn_t *mqc_connect_encrypted(mqc_ctx_t *ctx, const char *host, int port);
mqc_conn_t *mqc_accept_encrypted(mqc_ctx_t *ctx, int listen_fd);

/* Auto-detecting accept: peeks at the first byte to determine if the
 * client is using clear or encrypted identity mode.
 * 0x7B ('{') = clear JSON → mqc_accept
 * Otherwise  = encrypted  → mqc_accept_encrypted */
mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd);

/* --- I/O --- */

/* Read and decrypt data. Returns bytes read, 0 on close, -1 on error. */
int mqc_read(mqc_conn_t *conn, void *buf, int sz);

/* Alias for mqc_read. */
int mqc_recv(mqc_conn_t *conn, void *buf, int sz);

/* Encrypt and send data. Returns bytes written, -1 on error. */
int mqc_write(mqc_conn_t *conn, const void *buf, int sz);

/* Alias for mqc_write. */
int mqc_send(mqc_conn_t *conn, const void *buf, int sz);

/* --- Cleanup and utility --- */

/* Close connection, zero session keys, free resources. */
void mqc_close(mqc_conn_t *conn);

/* Get the raw file descriptor for use with select/poll. */
int mqc_get_fd(mqc_conn_t *conn);

/* Get peer's cert_index (valid after successful connect/accept). */
int mqc_get_peer_index(mqc_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* MQC_H */
