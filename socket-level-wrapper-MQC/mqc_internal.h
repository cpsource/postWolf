/* mqc_internal.h — private cross-file API for the MQC reference impl
 *
 * Shared between mqc.c (the dispatcher), mqc_common.c (the shared
 * machinery: rate limits, JSON parsers, transcript hash, key
 * schedule, AEAD frames, runtime cfg), mqc_clear.c (the clear-mode
 * handshake bodies), and mqc_encrypted.c (the encrypted-mode bodies
 * — currently stubs; bodies arrive in Phase 7 commit 2).
 *
 * Nothing in this file is part of the public API contract.  The
 * public API is defined in mqc.h; opaque-handle types declared
 * there are given full struct definitions here so the four .c files
 * can manipulate them.  Public callers continue to see only the
 * opaque pointers.
 *
 * Copyright (C) 2026 Cal Page. All rights reserved.
 */

#ifndef MQC_INTERNAL_H
#define MQC_INTERNAL_H

#include "mqc.h"
#include "config.h"
#include "mqc_peer.h"

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <hiredis/hiredis.h>
#include <json-c/json.h>

/* ----------------------------------------------------------------------
 * Internal-only constants (not part of the public ABI in mqc.h).
 * Defined first so the struct mqc_conn definition below can use them.
 * -------------------------------------------------------------------- */

#define MQC_AES_KEY_SZ      32
#define MQC_GCM_IV_SZ       12
#define MQC_GCM_TAG_SZ      16
#define MQC_MAX_MSG          (1024 * 1024)  /* 1 MiB max message */
#define MQC_MAX_HANDSHAKE    (128 * 1024)   /* 128 KiB max handshake JSON */

/* MQC_FRAME_TYPE_*, MQC_DIR_*, MQC_MODE_*, MQC_ROLE_* are public
 * constants defined in mqc.h (transitively included above). */

/* ----------------------------------------------------------------------
 * Opaque handles — full struct definitions
 *
 * `struct mqc_ctx` and `struct mqc_conn` are forward-declared in
 * mqc.h as opaque typedefs; their actual layout is defined here so
 * the four implementation files can access fields directly.
 * -------------------------------------------------------------------- */

struct mqc_ctx {
    mqc_role_t   role;
    char        *tpm_path;
    int          our_cert_index;
    char        *mtc_server;
    uint8_t     *ca_pubkey;
    int          ca_pubkey_sz;
    uint8_t     *privkey_der;      /* ML-DSA-87 private key DER */
    int          privkey_der_sz;
    int          encrypt_identity; /* 1 = encrypt cert_index in handshake;
                                    * read by mqc.c dispatcher */
    /* Issue #9: client-side expected-identity check.
     *   NULL  → derive from the host argument to mqc_connect (default).
     *   ""    → name check explicitly disabled (operator opt-out).
     *   other → match cert subject against this string. */
    char        *expected_name;
};

struct mqc_conn {
    int          fd;
    /* Per-direction AES-256-GCM keys + IVs derived via HKDF Extract
     * (issue #3).  Per-direction keys eliminate (key, nonce) collision
     * across directions; per-direction IVs make the per-frame nonce
     * unpredictable across connections via iv XOR (zeros||seq). */
    uint8_t      send_key[MQC_AES_KEY_SZ];
    uint8_t      recv_key[MQC_AES_KEY_SZ];
    uint8_t      send_iv [MQC_GCM_IV_SZ];
    uint8_t      recv_iv [MQC_GCM_IV_SZ];
    uint64_t     send_seq;
    uint64_t     recv_seq;
    int          peer_index;
    /* Phase-1 issues #4 + #5 connection-state additions. */
    uint8_t      is_client;                       /* 1 = client, 0 = server */
    uint8_t      finished_verified;               /* 0 until Finished MAC ok */
    uint8_t      send_finished_key[MQC_FINISHED_MAC_SZ];
    uint8_t      recv_finished_key[MQC_FINISHED_MAC_SZ];
    uint8_t      transcript_hash_full[WC_SHA256_DIGEST_SIZE];
};

/* ----------------------------------------------------------------------
 * Logging macros (use public mqc_get_verbose accessor so they work
 * across files without an extern of the static)
 * -------------------------------------------------------------------- */

#define MQC_LOG(fmt, ...) do { if (mqc_get_verbose()) \
    fprintf(stderr, "[MQC %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); } while(0)

#define MQC_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQC-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MQC_TRACE(fmt, ...) do { if (mqc_get_verbose()) \
    fprintf(stderr, fmt, ##__VA_ARGS__); } while(0)

/* ----------------------------------------------------------------------
 * Timing probes (opt-in via --mqc-time on the server CLI).  The
 * macros call the public accessor mqc_get_time_enabled() rather than
 * reading the static directly so they work across files.
 * -------------------------------------------------------------------- */

long mqc_now_ms(void);

#define MQC_TIME_BEGIN(name) \
    long _t_##name = mqc_get_time_enabled() ? mqc_now_ms() : 0
#define MQC_TIME_END(name) do { \
    if (mqc_get_time_enabled()) \
        fprintf(stderr, "[MQC-TIME] %s = %ld ms\n", \
                #name, mqc_now_ms() - _t_##name); \
    } while (0)

/* ----------------------------------------------------------------------
 * Slow-loris / handshake-deadline helpers + RAII-style macro
 * -------------------------------------------------------------------- */

int  mqc_handshake_deadline_exceeded(void);
void mqc_handshake_deadline_set(void);
void mqc_handshake_deadline_clear(void);
void mqc_handshake_deadline_cleanup(int *unused);

#define HANDSHAKE_DEADLINE_ACTIVE()                                       \
    int _hs_dl __attribute__((cleanup(mqc_handshake_deadline_cleanup))) = \
        (mqc_handshake_deadline_set(), 0);                                \
    (void)_hs_dl

/* ----------------------------------------------------------------------
 * Generic byte helpers
 * -------------------------------------------------------------------- */

void mqc_secure_zero(void *buf, unsigned int len);
void mqc_to_hex(const uint8_t *data, int sz, char *out);
/* mqc_hex_digit_lower is private to mqc_common.c (used only by
 * mqc_json_get_hex_strict).  No prototype here. */
int  mqc_const_eq(const uint8_t *a, const uint8_t *b, size_t n);
void mqc_put_u32be(uint8_t out[4], uint32_t v);

/* ----------------------------------------------------------------------
 * Socket I/O + timeouts
 * -------------------------------------------------------------------- */

int  mqc_write_all(int fd, const unsigned char *buf, unsigned int len);
int  mqc_read_all(int fd, unsigned char *buf, unsigned int len);
int  mqc_read_json_block(int fd, char *buf, int bufsz);
void mqc_set_socket_timeout(int fd, int seconds);
void mqc_clear_socket_timeout(int fd);

/* ----------------------------------------------------------------------
 * Strict-JSON parsing helpers (issue #11)
 * -------------------------------------------------------------------- */

struct json_object *mqc_json_parse_strict(const char *what,
                                          const char *buf, int len);

/* mqc_json_count_field is private to mqc_common.c (only used by
 * mqc_json_no_duplicates).  No prototype here. */

int mqc_json_no_duplicates(const char *what,
                           const char *buf, int len,
                           const char *const *fields, int n_fields);

int mqc_json_no_unknown_keys(const char *what,
                             struct json_object *obj,
                             const char *const *allowed,
                             int n_allowed);

int mqc_json_get_int_strict(const char *what,
                            struct json_object *obj, const char *field,
                            int min, int max, int *out);

int mqc_json_get_hex_strict(const char *what,
                            struct json_object *obj, const char *field,
                            int expected_byte_len, uint8_t *out_buf);

int mqc_json_get_string_exact(const char *what,
                              struct json_object *obj,
                              const char *field,
                              const char *expected_value);

/* ----------------------------------------------------------------------
 * Transcript hash + AEAD AAD construction (issues #1, #5)
 * -------------------------------------------------------------------- */

int mqc_compute_transcript_hash(uint8_t out[WC_SHA256_DIGEST_SIZE],
                                int mode_id,
                                const uint8_t *ek, size_t ek_len,
                                const uint8_t *ct, size_t ct_len,
                                int32_t cert_index_c, int32_t cert_index_s,
                                const char *role);

int mqc_transcript_hash_kdf(uint8_t out[WC_SHA256_DIGEST_SIZE],
                            int mode_id,
                            const uint8_t *ek, size_t ek_len,
                            const uint8_t *ct, size_t ct_len,
                            int32_t cert_index_c, int32_t cert_index_s);

void mqc_build_aad(uint8_t out[MQC_AAD_LEN],
                   uint8_t direction,
                   uint8_t frame_type,
                   uint64_t sequence,
                   uint32_t plaintext_len);

void mqc_make_nonce(const uint8_t iv[MQC_GCM_IV_SZ],
                    uint64_t seq,
                    uint8_t out[MQC_GCM_IV_SZ]);

/* ----------------------------------------------------------------------
 * HKDF key schedule + Finished MAC (issues #3, #4)
 * -------------------------------------------------------------------- */

int mqc_derive_data_keys(const uint8_t *shared_secret,
                         const uint8_t  transcript_hash[WC_SHA256_DIGEST_SIZE],
                         uint8_t c2s_key     [MQC_AES_KEY_SZ],
                         uint8_t s2c_key     [MQC_AES_KEY_SZ],
                         uint8_t c2s_iv      [MQC_GCM_IV_SZ],
                         uint8_t s2c_iv      [MQC_GCM_IV_SZ],
                         uint8_t c2s_finished[MQC_FINISHED_MAC_SZ],
                         uint8_t s2c_finished[MQC_FINISHED_MAC_SZ]);

int mqc_compute_finished_mac(const uint8_t finished_key[MQC_FINISHED_MAC_SZ],
                             const uint8_t transcript_hash[WC_SHA256_DIGEST_SIZE],
                             uint8_t out_mac[MQC_FINISHED_MAC_SZ]);

/* Encrypted-mode early-key schedule (spec §7.3 / §8).  Salted with
 * the phase-1 transcript hash (C_c=C_s=0) so the early keys are
 * independent of the full-transcript data keys.  Used to AEAD-seal
 * the two phase-2 identity frames only. */
int mqc_derive_early_keys(const uint8_t *shared_secret,
                          const uint8_t  transcript_hash_phase1[WC_SHA256_DIGEST_SIZE],
                          uint8_t early_c2s_key[MQC_AES_KEY_SZ],
                          uint8_t early_s2c_key[MQC_AES_KEY_SZ],
                          uint8_t early_c2s_iv [MQC_GCM_IV_SZ],
                          uint8_t early_s2c_iv [MQC_GCM_IV_SZ]);

/* ----------------------------------------------------------------------
 * AEAD seal/unseal + Finished frame send/recv (data-plane primitives;
 * shared between handshake completion and post-handshake traffic)
 * -------------------------------------------------------------------- */

int mqc_enc_send(int fd,
                 const uint8_t *key, const uint8_t *iv,
                 uint64_t *seq,
                 uint8_t direction, uint8_t frame_type,
                 const void *plaintext, int plaintext_len);

int mqc_enc_recv(int fd,
                 const uint8_t *key, const uint8_t *iv,
                 uint64_t *seq,
                 uint8_t direction, uint8_t frame_type,
                 void *plaintext_out, int plaintext_max);

int mqc_send_finished(struct mqc_conn *conn);
int mqc_recv_finished(struct mqc_conn *conn);

/* ----------------------------------------------------------------------
 * Redis-backed rate limiting (issues #6a, #12)
 * -------------------------------------------------------------------- */

void mqc_redis_init(void);
int  mqc_redis_incr(const char *key, int ttl_secs);
int  mqc_redis_sadd_count(const char *key, int cert_index, int ttl_secs);

int  mqc_ratelimit_check(const char *ip);
int  mqc_ratelimit_fail_check(const char *ip);
void mqc_ratelimit_fail_record(const char *ip);
int  mqc_ratelimit_cert_check(const char *ip, int cert_index);

/* ----------------------------------------------------------------------
 * AbuseIPDB integration (issue #6a)
 * -------------------------------------------------------------------- */

int mqc_abuse_check(const char *ip);

/* ----------------------------------------------------------------------
 * Mode-specific handshake bodies (the actual Phase 7 split)
 *
 * Public mqc_connect / mqc_accept in mqc.c dispatch to one of these
 * pairs based on ctx->encrypt_identity.
 * -------------------------------------------------------------------- */

mqc_conn_t *mqc_connect_clear(mqc_ctx_t *ctx, const char *host, int port);
mqc_conn_t *mqc_accept_clear (mqc_ctx_t *ctx, int listen_fd);

/* Post-accept continuations.  Take an already-accepted, connected fd
 * plus the client_ip string the caller already extracted via
 * inet_ntop on the accept's cli_addr.  Used by mqc_accept_auto in
 * mqc.c so it can peek the wire to choose mode without re-doing the
 * accept (which would be impossible — it's already happened). */
mqc_conn_t *mqc_accept_clear_post    (mqc_ctx_t *ctx, int fd,
                                      const char *client_ip);
mqc_conn_t *mqc_accept_encrypted_post(mqc_ctx_t *ctx, int fd,
                                      const char *client_ip);

/* mqc_connect_encrypted / mqc_accept_encrypted are public (declared in
 * mqc.h); their bodies live in mqc_encrypted.c. */

#endif /* MQC_INTERNAL_H */
