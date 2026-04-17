/* mqcp.h — MQCP (Merkle Quantum Connect Protocol) public API
 *
 * QUIC-inspired reliable transport over UDP with MQC post-quantum crypto:
 *   - ML-KEM-768 key exchange (FIPS 203)
 *   - ML-DSA-87 signed authentication (FIPS 204)
 *   - AES-256-GCM session encryption (FIPS 197 + SP 800-38D)
 *   - Merkle tree peer verification (RFC 9162)
 *   - RENO congestion control
 *   - Single reliable ordered byte stream per connection
 *
 * No TLS. No X.509. Built on libudp + MQC crypto.
 *
 * Copyright (C) 2026 Cal Page. All rights reserved.
 */

#ifndef MQCP_H
#define MQCP_H

#include "mqcp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef struct mqcp_ctx  mqcp_ctx_t;
typedef struct mqcp_conn mqcp_conn_t;

/* Context configuration */
typedef struct {
    mqcp_role_t  role;            /* MQCP_CLIENT or MQCP_SERVER */
    const char  *tpm_path;        /* ~/.TPM/<domain> — our identity.
                                   * Must contain certificate.json and
                                   * private_key.pem (ML-DSA-87). */
    const char  *mtc_server;      /* MTC CA server for peer key resolution
                                   * (e.g., "localhost:8444"). */
    const unsigned char *ca_pubkey;  /* CA Ed25519 cosigner public key (32B) */
    int          ca_pubkey_sz;
    int          encrypt_identity;   /* 1 = hide cert_index from eavesdroppers */
    uint64_t     idle_timeout_ms;    /* 0 = default 30s */
    size_t       max_recv_window;    /* 0 = default 1MB */
} mqcp_cfg_t;

/* --- Context lifecycle --- */

/* Create an MQCP context. Loads identity from tpm_path.
 * Returns NULL on failure. */
mqcp_ctx_t *mqcp_ctx_new(const mqcp_cfg_t *cfg);

/* Free context and zero all key material. */
void mqcp_ctx_free(mqcp_ctx_t *ctx);

/* --- Connection lifecycle --- */

/* Client: initiate connection. Non-blocking — returns immediately.
 * Call mqcp_process() in event loop until mqcp_is_established().
 * Returns NULL on immediate failure (bad address, etc). */
mqcp_conn_t *mqcp_connect(mqcp_ctx_t *ctx, const char *host, int port);

/* Server: create a listening UDP socket on host:port.
 * Returns listen fd on success, -1 on failure. */
int mqcp_listen(mqcp_ctx_t *ctx, const char *host, int port);

/* Server: process incoming datagrams on listen_fd.
 * Returns new connection (handshake may still be in progress),
 * or existing connection that received data, or NULL if nothing ready.
 * Call mqcp_process() on returned connection to advance state. */
mqcp_conn_t *mqcp_accept(mqcp_ctx_t *ctx, int listen_fd);

/* --- Event processing --- */

/* Drive the state machine: process incoming packets, send ACKs,
 * retransmit lost packets, advance handshake. Call when socket is
 * readable or a timer fires. Returns MQCP_OK or error code. */
int mqcp_process(mqcp_conn_t *conn);

/* Returns 1 if handshake is complete and data can flow. */
int mqcp_is_established(mqcp_conn_t *conn);

/* Get connection state. */
mqcp_state_t mqcp_get_state(mqcp_conn_t *conn);

/* Get the UDP socket fd for use with poll/epoll/select. */
int mqcp_get_fd(mqcp_conn_t *conn);

/* Get next timer deadline (absolute, clock_gettime CLOCK_MONOTONIC,
 * microseconds). Returns 0 if no timer pending. */
uint64_t mqcp_next_timer(mqcp_conn_t *conn);

/* --- I/O --- */

/* Write data to the stream. Returns bytes buffered (may be < len if
 * flow-control limited). Returns MQCP_ERR_AGAIN if send buffer full. */
int mqcp_write(mqcp_conn_t *conn, const void *buf, size_t len);

/* Read data from the stream. Returns bytes read, 0 if no data yet,
 * MQCP_ERR_CLOSED if peer closed the stream. */
int mqcp_read(mqcp_conn_t *conn, void *buf, size_t len);

/* Flush buffered data: build and send packets for any pending stream
 * data, respecting congestion and flow control. Called automatically
 * by mqcp_process(), but can be called explicitly after mqcp_write(). */
int mqcp_flush(mqcp_conn_t *conn);

/* --- Connection close --- */

/* Initiate graceful close. Sends CLOSE frame. */
int mqcp_close(mqcp_conn_t *conn);

/* Free connection resources. Call after state reaches CLOSED. */
void mqcp_conn_free(mqcp_conn_t *conn);

/* --- Info --- */

/* Get peer's cert_index (valid after handshake). Returns -1 if unknown. */
int mqcp_get_peer_index(mqcp_conn_t *conn);

/* Logging: 0 = errors only (default), 1 = trace. */
void mqcp_set_verbose(int level);
int  mqcp_get_verbose(void);

#ifdef __cplusplus
}
#endif

#endif /* MQCP_H */
