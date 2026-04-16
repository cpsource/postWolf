/**
 * @file mtc_http.h
 * @brief Minimal HTTP-over-TLS server for the MTC CA/Log.
 *
 * @details
 * Provides a single-threaded, blocking HTTP server that exposes the MTC
 * CA REST API (matching the Python server's endpoints).  Supports
 * optional TLS 1.3 via the slc (socket-level-crypto) wrapper, with
 * optional ECH (Encrypted Client Hello).
 *
 * Thread safety: the server is single-threaded and NOT thread-safe.
 *
 * @date 2026-04-13
 */

#ifndef MTC_HTTP_H
#define MTC_HTTP_H

#include "mtc_store.h"
#include "slc.h"
#include "mqc.h"

/**
 * @brief TLS configuration for the server.
 *
 * @details
 * Pass to mtc_http_serve() to enable TLS 1.3.  If the pointer is NULL
 * or cert_file is NULL, the server runs in plain HTTP mode (testing only).
 */
typedef struct {
    const char *cert_file;       /**< PEM server certificate path         */
    const char *key_file;        /**< PEM server private key path         */
    const char *ca_file;         /**< CA cert for client verification
                                      (optional, NULL to skip)            */
    const char *ech_public_name; /**< ECH public name (e.g. "example.com"),
                                      NULL to disable ECH                 */
} mtc_tls_cfg_t;

/**
 * @brief    Start the HTTP(-over-TLS) server.  Blocks until shutdown.
 *
 * @details
 * Binds to @p host:@p port, optionally negotiates TLS 1.3, and enters
 * an accept loop dispatching requests to the MTC CA REST API handlers.
 * Each connection is handled synchronously (single-threaded).
 *
 * If @p tls_cfg is NULL or tls_cfg->cert_file is NULL, the server runs
 * in plain HTTP mode (intended for local testing only).
 *
 * @param[in] host     Bind address (e.g. "0.0.0.0").  NULL defaults to
 *                      all interfaces.
 * @param[in] port     TCP port to listen on.
 * @param[in] store    Initialised MtcStore containing the Merkle tree,
 *                      certificates, and DB connection.  Must outlive
 *                      the server.
 * @param[in] tls_cfg  TLS configuration, or NULL for plain HTTP.
 *
 * @return
 *   0   on clean exit (unreachable in current implementation — loops
 *       forever).
 *  -1   on fatal startup error (TLS context or listen failure).
 */
int mtc_http_serve(const char *host, int port, MtcStore *store,
                   const mtc_tls_cfg_t *tls_cfg);

/**
 * @brief  Start MQC listener on a background thread.
 *
 * @param[in] host      Bind address (NULL = "0.0.0.0").
 * @param[in] port      MQC port (e.g., 8446).
 * @param[in] store     Initialised MTC store.
 * @param[in] tpm_path  Path to server's TPM identity (e.g., ~/.TPM/factsorlie.com-ca).
 * @param[in] mtc_server MTC server URL for peer verification.
 * @param[in] ca_pubkey  CA Ed25519 cosigner public key.
 * @param[in] ca_pubkey_sz Size of ca_pubkey.
 *
 * @return  0 on success, -1 on failure.
 */
int mtc_mqc_start(const char *host, int port, MtcStore *store,
                  const char *tpm_path, const char *mtc_server,
                  const unsigned char *ca_pubkey, int ca_pubkey_sz);

#endif
