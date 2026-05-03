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
    const char *mtc_server;      /* MTC CA server for peer key resolution.
                                  * Typically the MQC endpoint the caller
                                  * already knows (e.g.,
                                  * "factsorlie.com:8446").  Only the host
                                  * portion is used here — bootstrap-port
                                  * lookups always hit :8445 on the same
                                  * host. */
    const unsigned char *ca_pubkey;  /* CA ML-DSA-87 cosigner public key
                                      * (DILITHIUM_LEVEL5_PUB_KEY_SIZE =
                                      * 2592 bytes, raw encoding) used for
                                      * Merkle-proof verification. */
    int ca_pubkey_sz;            /* Size of ca_pubkey
                                  * (DILITHIUM_LEVEL5_PUB_KEY_SIZE). */
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

/* After mqc_accept_auto (or the other accept variants) returns NULL,
 * the fd has already been closed so getpeername() is useless.  This
 * returns the peer IP captured at the raw-accept() moment, letting
 * callers log which client triggered the failure.  Valid until the
 * next call to any mqc_accept* in the same process. */
const char *mqc_last_accept_peer_ip(void);

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

/* Set/get log verbosity.  0 = errors only (default), 1 = trace. */
void mqc_set_verbose(int level);
int  mqc_get_verbose(void);

/* Enable per-handshake millisecond-precision stage timing in the
 * server-side mqc_accept path.  Off by default; toggled on with
 * --mqc-time on the mtc_server CLI.  Lines appear in journalctl as
 *   [MQC-TIME] <stage> = <N> ms
 * Useful for hunting cold-start regressions.  Production cost when
 * disabled: zero (the macros expand to no-ops). */
void mqc_set_time_enabled(int on);
int  mqc_get_time_enabled(void);

/* --- Issue #9: client-side expected-identity (server-name) check --
 *
 * After successfully verifying a peer cert (signature, inclusion
 * proof, cosignature, revocation, validity window), mqc_connect
 * additionally checks that the cert's subject matches the hostname
 * the caller intended to reach.  By default the expected hostname
 * is the `host` argument passed to mqc_connect.  An MTC subject
 * matches if subject == expected (case-insensitive) OR subject
 * starts with "expected-" (case-insensitive) — covering the
 * postWolf naming convention where `<dns>-ca`, `<dns>-<label>`
 * etc. all serve `<dns>`.  IP-literal hostnames cannot bind to
 * any DNS subject and fail closed unless the check is explicitly
 * disabled.
 *
 * Set BEFORE calling mqc_connect.  hostname is strdup'd. */
void mqc_ctx_set_expected_name(mqc_ctx_t *ctx, const char *hostname);

/* Disable the expected-identity check entirely.  Logs a
 * NAME_CHECK_DISABLED warning at handshake time so the dangerous
 * mode is visible in journalctl.  Use only when the caller has
 * out-of-band assurance about which identity it's reaching (e.g.,
 * a cert_index pin, IP-only deployment). */
void mqc_ctx_disable_name_check(mqc_ctx_t *ctx);

/* --- Runtime configuration (issue 6a) ------------------------------
 * Operational tunables resolved once per process from
 * /etc/postWolf/config (Augeas-parsed) with compiled-in defaults from
 * config.h and mqc.c.  Read-only view — modify only by editing the
 * config file and restarting the process. */
struct mqc_runtime_cfg {
    long handshake_stall_sec;
    long handshake_total_sec;
    long max_msg_bytes;
    long max_handshake_bytes;
    long rl_connect_per_min;
    long rl_connect_per_hour;
    long rl_fail_per_min;
    long rl_fail_per_hour;
    long revoked_cache_ttl_sec;
    long sig_freshness_sec;
    int  revocation_policy;       /* MQC_REVOCATION_POLICY_* (issue #7) */
};
const struct mqc_runtime_cfg *mqc_rt_cfg(void);

/* --- Phase 1 protocol constants (issues 1+2+3+4+5) ----------------
 * Wire-format invariants for MQC v0.  Changing any of these requires
 * a coordinated flag-day cutover (server + all clients rebuilt and
 * redeployed together).  See README-plans.md "Deployment model" and
 * mqc-master.plan. */
#define MQC_PROTOCOL_VERSION    0
#define MQC_SUITE_STRING        "MQC_MLKEM768_MLDSA87_AES256GCM_SHA256"

/* 16-byte ML-DSA `ctx` label for handshake signatures, also embedded
 * in the transcript hash for in-message belt-and-braces.  Style
 * matches the cosigner label "mtc-subtree/v1\n\x00". */
#define MQC_HANDSHAKE_LABEL     "mqc-hndshk/v1\n\x00"
#define MQC_HANDSHAKE_LABEL_LEN 16

/* 16-byte AAD label prefix on every AEAD frame past handshake.  The
 * "/v01" here is the AAD-format version, NOT the protocol version —
 * bumped only if the AAD bytes themselves change.  Two-digit version
 * keeps the literal at exactly 16 bytes (15 explicit chars + implicit
 * NUL terminator), matching MQC_HANDSHAKE_LABEL's "mqc-hndshk/v1\n\x00"
 * which is naturally 16 due to its longer prefix. */
#define MQC_AAD_LABEL           "mqc-frame/v01\n\x00"
#define MQC_AAD_LABEL_LEN       16
#define MQC_AAD_LEN             31

/* 6-byte role tags hashed into the signature transcript so a client
 * sig is bytewise distinguishable from a server sig over the same
 * fields. */
#define MQC_ROLE_CLIENT         "client"
#define MQC_ROLE_SERVER         "server"
#define MQC_ROLE_LEN            6

/* Mode markers — appear in the JSON `mode` field AND as the
 * mode_id byte hashed into the transcript. */
#define MQC_MODE_CLEAR          0x00
#define MQC_MODE_ENCRYPTED      0x01

/* Direction byte in AAD. */
#define MQC_DIR_C2S             0x00
#define MQC_DIR_S2C             0x01

/* Frame types in AAD.  Type 0x01 (early keys) is structurally
 * separated from 0x02/0x03 (data keys) by key choice; 0x02 vs 0x03
 * distinguishes Finished from application data over the same key. */
#define MQC_FRAME_TYPE_PHASE2_IDENTITY 0x01
#define MQC_FRAME_TYPE_FINISHED        0x02
#define MQC_FRAME_TYPE_APP_DATA        0x03

/* HMAC-SHA256 output length used for Finished MAC. */
#define MQC_FINISHED_MAC_SZ     32

/* --- Revocation policy enum (issue #7) ----------------------------
 * MANDATORY: query log on cache miss; abort handshake on query failure.
 * CACHE_ONLY: use cache; abort on cache miss.  Useful during planned
 *             log-endpoint maintenance windows.
 * DISABLED:   skip revocation entirely.  Emergency-recovery only;
 *             selecting this in /etc/postWolf/config logs a loud
 *             MQC_SECURITY warning at process startup. */
#define MQC_REVOCATION_POLICY_MANDATORY  0
#define MQC_REVOCATION_POLICY_CACHE_ONLY 1
#define MQC_REVOCATION_POLICY_DISABLED   2

/* Exact byte sizes of the cryptographic field blobs.  Used as
 * pre-crypto length filters per spec §11.3 and issue #12. */
#define MQC_MLKEM768_PUB_SZ     1184
#define MQC_MLKEM768_CT_SZ      1088
#define MQC_MLDSA87_SIG_SZ      4627

/* HKDF info strings.  Produced by HKDF-Expand off the data_secret
 * (PRK = HKDF-Extract(transcript_hash_full, SS)) and early_secret
 * (PRK = HKDF-Extract(transcript_hash_phase1, SS)) per issue #3. */
#define MQC_HKDF_INFO_DATA_C2S_KEY \
    "mqc/v0/" MQC_SUITE_STRING "/data-c2s-key"
#define MQC_HKDF_INFO_DATA_S2C_KEY \
    "mqc/v0/" MQC_SUITE_STRING "/data-s2c-key"
#define MQC_HKDF_INFO_DATA_C2S_IV \
    "mqc/v0/" MQC_SUITE_STRING "/data-c2s-iv"
#define MQC_HKDF_INFO_DATA_S2C_IV \
    "mqc/v0/" MQC_SUITE_STRING "/data-s2c-iv"
#define MQC_HKDF_INFO_DATA_C2S_FINISHED \
    "mqc/v0/" MQC_SUITE_STRING "/data-c2s-finished"
#define MQC_HKDF_INFO_DATA_S2C_FINISHED \
    "mqc/v0/" MQC_SUITE_STRING "/data-s2c-finished"
#define MQC_HKDF_INFO_EARLY_C2S_KEY \
    "mqc/v0/" MQC_SUITE_STRING "/early-c2s-key"
#define MQC_HKDF_INFO_EARLY_S2C_KEY \
    "mqc/v0/" MQC_SUITE_STRING "/early-s2c-key"
#define MQC_HKDF_INFO_EARLY_C2S_IV \
    "mqc/v0/" MQC_SUITE_STRING "/early-c2s-iv"
#define MQC_HKDF_INFO_EARLY_S2C_IV \
    "mqc/v0/" MQC_SUITE_STRING "/early-s2c-iv"

#ifdef __cplusplus
}
#endif

#endif /* MQC_H */
