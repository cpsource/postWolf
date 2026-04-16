/* slc.h — Socket Level Connection API
 *
 * Simplified TLS 1.3 + ECH + MTC wrapper over wolfSSL.
 * One call to connect, one call to accept. All authentication,
 * certificate validation, Merkle proof verification, and ECH
 * negotiation happen inside the API. The caller gets back a
 * fully authenticated connection or NULL.
 *
 * NOTE: Applications that include wolfSSL headers directly must
 * include <wolfssl/options.h> before any other wolfSSL headers.
 * The SLC API handles this internally — callers only need slc.h.
 * If you include wolfSSL headers alongside slc.h, either include
 * <wolfssl/options.h> first or compile with -DWOLFSSL_USE_OPTIONS_H.
 *
 * Copyright (C) 2026 Cal Page. All rights reserved.
 */

#ifndef SLC_H
#define SLC_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef struct slc_ctx  slc_ctx_t;
typedef struct slc_conn slc_conn_t;

/* Connection role */
typedef enum {
    SLC_CLIENT,
    SLC_SERVER
} slc_role_t;

/* Context configuration */
typedef struct {
    slc_role_t  role;            /* SLC_CLIENT or SLC_SERVER */
    const char *cert_file;       /* PEM certificate (traditional X.509) */
    const char *key_file;        /* PEM private key (traditional) */
    const char *ca_file;         /* CA cert for peer verification (traditional) */
    const char *mtc_store;       /* MTC identity: ~/.TPM/<domain> path.
                                  * If set, uses MTC cert instead of cert_file/key_file.
                                  * Contains certificate.json + private_key.pem */
    const char *ech_configs_b64; /* base64 ECH configs (client: set to server's
                                  * ECH config; server: NULL, auto-generated) */
    const char *ech_public_name; /* server only: public-facing SNI for ECH
                                  * (e.g., "factsorlie.com"). NULL to skip ECH. */
} slc_cfg_t;

/* --- Context management --- */

/* Create a TLS 1.3 context from configuration.
 * Returns NULL on failure. */
slc_ctx_t *slc_ctx_new(const slc_cfg_t *cfg);

/* Configure MTC (Merkle Tree Certificate) verification.
 * Registers the CA cosigner key for peer proof verification and
 * the MTC server URL for on-demand checkpoint fetching.
 * Returns 0 on success, -1 on failure. */
int slc_ctx_set_mtc(slc_ctx_t *ctx, const char *mtc_server,
                    const unsigned char *ca_pubkey, int ca_pubkey_sz);

/* Load MTC identity from a ~/.TPM/<domain> directory.
 * Reads certificate.json + private_key.pem and loads them as an MTC
 * certificate into the TLS context.  Can be called after slc_ctx_new()
 * as an alternative to setting mtc_store in slc_cfg_t.
 * Returns 0 on success, -1 on failure. */
int slc_ctx_load_mtc(slc_ctx_t *ctx, const char *tpm_path);

/* Free a context. */
void slc_ctx_free(slc_ctx_t *ctx);

/* --- Connection lifecycle --- */

/* Connect to a TLS 1.3 server. Performs TCP connect + full TLS handshake
 * including certificate validation, ECH, and MTC verification.
 * Returns NULL if connection or any verification step fails. */
slc_conn_t *slc_connect(slc_ctx_t *ctx, const char *host, int port);

/* Create a listening socket. Pure POSIX — no TLS.
 * Returns listen fd on success, -1 on failure. */
int slc_listen(const char *host, int port);

/* Accept a client connection and perform TLS handshake.
 * Returns NULL if accept or any verification step fails. */
slc_conn_t *slc_accept(slc_ctx_t *ctx, int listen_fd);

/* --- I/O --- */

/* Read decrypted data. Returns bytes read, 0 on close, -1 on error. */
int slc_read(slc_conn_t *conn, void *buf, int sz);

/* Receive decrypted data. Alias for slc_read. */
int slc_recv(slc_conn_t *conn, void *buf, int sz);

/* Write data (encrypted by TLS). Returns bytes written, -1 on error. */
int slc_write(slc_conn_t *conn, const void *buf, int sz);

/* Send data (encrypted by TLS). Alias for slc_write. */
int slc_send(slc_conn_t *conn, const void *buf, int sz);

/* --- Cleanup --- */

/* Shutdown TLS, close socket, free resources. */
void slc_close(slc_conn_t *conn);

/* --- Utility --- */

/* Export the server's ECH config (for distribution to clients).
 * Call after slc_ctx_new with SLC_SERVER + ech_public_name set.
 * If buf is NULL, writes required size to *sz and returns 0.
 * Returns 0 on success, -1 on failure or if ECH not configured. */
int slc_ctx_get_ech_configs(slc_ctx_t *ctx, unsigned char *buf, int *sz);

/* Get the raw file descriptor for use with select/poll. */
int slc_get_fd(slc_conn_t *conn);

/* Set/get log verbosity.  0 = errors only (default), 1 = trace. */
void slc_set_verbose(int level);
int  slc_get_verbose(void);

#ifdef __cplusplus
}
#endif

#endif /* SLC_H */
