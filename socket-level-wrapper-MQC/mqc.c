/******************************************************************************
 * File:        mqc.c
 * Purpose:     MQC (Merkle Quantum Connect) protocol implementation.
 *
 * Description:
 *   Post-quantum authenticated encrypted connections using ML-KEM-768
 *   key exchange, ML-DSA-87 signed authentication, and AES-256-GCM
 *   session encryption. Peer identity verified via Merkle transparency log.
 *
 *   Protocol: 1 round trip.
 *     Client -> Server: {cert_index, mlkem_encaps_key, signature}
 *     Server -> Client: {cert_index, mlkem_ciphertext, signature}
 *     Both derive AES-256-GCM key from ML-KEM shared secret.
 *
 * Dependencies:
 *   wolfSSL crypto (ML-KEM, ML-DSA, AES-GCM, HKDF, SHA-256)
 *   json-c          (JSON serialization)
 *   POSIX sockets   (TCP)
 *
 * Created:     2026-04-15
 ******************************************************************************/

#include "mqc.h"
#include "mqc_peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <hiredis/hiredis.h>
#include <pthread.h>

#include "read-config.h"

/* Forward declarations of Phase 1 helpers defined later in this TU.
 * mqc_connect / mqc_accept (defined first) need them; their actual
 * bodies sit alongside the encrypted-mode handshake further down. */
struct mqc_conn;
static int mqc_send_finished(struct mqc_conn *conn);
static int mqc_recv_finished(struct mqc_conn *conn);

#define MQC_AES_KEY_SZ      32
#define MQC_GCM_IV_SZ       12
#define MQC_GCM_TAG_SZ      16
#define MQC_MAX_MSG          (1024 * 1024)  /* 1MB max message */
#define MQC_MAX_HANDSHAKE    (128 * 1024)   /* 128KB max handshake JSON */
#include "config.h"
/* MQC_HANDSHAKE_STALL_SEC and MQC_HANDSHAKE_TOTAL_SEC live in config.h. */
/* Kept as a back-compat alias for existing call sites. */
#define MQC_HANDSHAKE_TIMEOUT  MQC_HANDSHAKE_STALL_SEC

/* Wall-clock deadline for the current accept-side handshake.  Set by
 * each mqc_accept* function at entry, consulted inside read_all /
 * read_json_block to kill slow-loris drip attacks that stay under
 * SO_RCVTIMEO per read.  0 means "no deadline" (client side / any
 * path that isn't the accept handshake).  Safe as a file-static
 * because mqc.c is used in single-connection-per-process contexts
 * — server forks per accept, clients run one mqc_connect at a time. */
static time_t s_handshake_deadline = 0;

/* Stashed peer IP from the most recent accept-side handshake.  Lets
 * callers log meaningful diagnostics when mqc_accept* returns NULL
 * (the fd has already been closed by then, so getpeername is too late). */
static char s_last_accept_peer_ip[64] = "";

const char *mqc_last_accept_peer_ip(void)
{
    return s_last_accept_peer_ip;
}

static int handshake_deadline_exceeded(void)
{
    return s_handshake_deadline != 0 && time(NULL) > s_handshake_deadline;
}

static void handshake_deadline_set(void)
{
    s_handshake_deadline = time(NULL) + mqc_rt_cfg()->handshake_total_sec;
}

static void handshake_deadline_clear(void)
{
    s_handshake_deadline = 0;
}

/* Scope-based cleanup: drop an HANDSHAKE_DEADLINE_ACTIVE(); at the
 * top of each accept-side function and the deadline is automatically
 * set-on-entry and cleared on every return path.  Keeps us from
 * leaking the deadline into post-handshake data-plane reads. */
static void handshake_deadline_cleanup(int *unused)
{
    (void)unused;
    handshake_deadline_clear();
}

#define HANDSHAKE_DEADLINE_ACTIVE()                                      \
    int _hs_dl __attribute__((cleanup(handshake_deadline_cleanup))) =    \
        (handshake_deadline_set(), 0);                                   \
    (void)_hs_dl

#define MQC_ABUSE_THRESHOLD  25  /* reject if abuse score >= 25% */

/* Compiled-in defaults for the operational tunables.  Each can be
 * overridden at runtime via [global]/<key> in /etc/postWolf/config
 * (issue 6a).  See README-plans.md and the per-key documentation in
 * mtc-keymaster/read-config/config.server. */
#define MQC_RL_CONNECT_MIN   100   /* max connections per minute per IP */
#define MQC_RL_CONNECT_HOUR  1000  /* max connections per hour per IP */
#define MQC_RL_FAIL_MIN       10   /* max failed handshakes per minute per IP */
#define MQC_RL_FAIL_HOUR     100   /* max failed handshakes per hour per IP */

/* --- Runtime configuration cache (issue 6a) ----------------------------
 * struct mqc_runtime_cfg is defined in mqc.h so mqc_peer.c can also read
 * it.  Resolved once per process from /etc/postWolf/config; falls back
 * to the compiled-in defaults above and in config.h for keys that
 * aren't set.  Caches the result in s_rt_cfg under pthread_once so the
 * per-key Augeas init/get/close cycles happen exactly once.  See
 * socket-level-wrapper-MQC/mqc-issue-6a.plan for the design. */
static struct mqc_runtime_cfg s_rt_cfg;
static pthread_once_t          s_rt_cfg_once = PTHREAD_ONCE_INIT;

static void mqc_rt_cfg_init_once(void)
{
    s_rt_cfg.handshake_stall_sec =
        read_config_long("global/mqc-handshake-stall-sec",
                         MQC_HANDSHAKE_STALL_SEC);
    s_rt_cfg.handshake_total_sec =
        read_config_long("global/mqc-handshake-total-sec",
                         MQC_HANDSHAKE_TOTAL_SEC);
    s_rt_cfg.max_msg_bytes =
        read_config_long("global/mqc-max-msg-bytes",
                         MQC_MAX_MSG);
    s_rt_cfg.max_handshake_bytes =
        read_config_long("global/mqc-max-handshake-bytes",
                         MQC_MAX_HANDSHAKE);
    s_rt_cfg.rl_connect_per_min =
        read_config_long("global/mqc-rl-connect-per-min",
                         MQC_RL_CONNECT_MIN);
    s_rt_cfg.rl_connect_per_hour =
        read_config_long("global/mqc-rl-connect-per-hour",
                         MQC_RL_CONNECT_HOUR);
    s_rt_cfg.rl_fail_per_min =
        read_config_long("global/mqc-rl-fail-per-min",
                         MQC_RL_FAIL_MIN);
    s_rt_cfg.rl_fail_per_hour =
        read_config_long("global/mqc-rl-fail-per-hour",
                         MQC_RL_FAIL_HOUR);
    s_rt_cfg.revoked_cache_ttl_sec =
        read_config_long("global/mqc-revoked-cache-ttl-sec",
                         MQC_REVOKED_CACHE_TTL_SEC);
    s_rt_cfg.sig_freshness_sec =
        read_config_long("global/mqc-sig-freshness-sec",
                         MQC_SIG_FRESHNESS_SEC);

    /* Spec §11.3: implementations MAY lower frame ceilings, MUST NOT
     * raise them.  Clamp config-file values that exceed the compiled
     * cap; raising would just produce frames the peer rejects. */
    if (s_rt_cfg.max_msg_bytes > MQC_MAX_MSG)
        s_rt_cfg.max_msg_bytes = MQC_MAX_MSG;
    if (s_rt_cfg.max_handshake_bytes > MQC_MAX_HANDSHAKE)
        s_rt_cfg.max_handshake_bytes = MQC_MAX_HANDSHAKE;
}

const struct mqc_runtime_cfg *mqc_rt_cfg(void)
{
    pthread_once(&s_rt_cfg_once, mqc_rt_cfg_init_once);
    return &s_rt_cfg;
}

/* --- Logging --- */

static int s_mqc_verbose = 0;

void mqc_set_verbose(int level) { s_mqc_verbose = level; }
int  mqc_get_verbose(void) { return s_mqc_verbose; }

#define MQC_LOG(fmt, ...) do { if (s_mqc_verbose) \
    fprintf(stderr, "[MQC %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); } while(0)

#define MQC_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQC-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MQC_TRACE(fmt, ...) do { if (s_mqc_verbose) \
    fprintf(stderr, fmt, ##__VA_ARGS__); } while(0)

/* --- Internal structures --- */

struct mqc_ctx {
    mqc_role_t   role;
    char        *tpm_path;
    int          our_cert_index;
    char        *mtc_server;
    uint8_t     *ca_pubkey;
    int          ca_pubkey_sz;
    uint8_t     *privkey_der;      /* ML-DSA-87 private key DER */
    int          privkey_der_sz;
    int          encrypt_identity; /* 1 = encrypt cert_index in handshake */
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

/* --- Helpers --- */

static void secure_zero(void *buf, unsigned int len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    unsigned int i;
    for (i = 0; i < len; i++)
        p[i] = 0;
}

static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

static int hex_to_bytes(const char *hex, uint8_t *out, int out_sz)
{
    int len = (int)strlen(hex);
    int i;
    if (len % 2 != 0 || len / 2 > out_sz)
        return -1;
    for (i = 0; i < len / 2; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1)
            return -1;
        out[i] = (uint8_t)b;
    }
    return len / 2;
}

static int write_all(int fd, const unsigned char *buf, unsigned int len)
{
    unsigned int sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += (unsigned int)n;
    }
    return 0;
}

static int read_all(int fd, unsigned char *buf, unsigned int len)
{
    unsigned int got = 0;
    while (got < len) {
        ssize_t n;
        if (handshake_deadline_exceeded()) {
            MQC_LOG("read_all: handshake deadline exceeded "
                    "(got=%u/%u) — slow-loris?", got, len);
            return -1;
        }
        n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += (unsigned int)n;
    }
    return 0;
}

static int read_json_block(int fd, char *buf, int bufsz)
{
    int pos = 0, depth = 0, started = 0;
    while (pos < bufsz - 1) {
        ssize_t n;
        if (handshake_deadline_exceeded()) {
            MQC_LOG("read_json_block: handshake deadline exceeded "
                    "(pos=%d depth=%d) — slow-loris?", pos, depth);
            return -1;
        }
        n = read(fd, buf + pos, 1);
        if (n <= 0) return -1;
        if (buf[pos] == '{') { depth++; started = 1; }
        else if (buf[pos] == '}') { depth--; }
        pos++;
        if (started && depth == 0) {
            buf[pos] = '\0';
            return pos;
        }
    }
    return -1;
}

static int read_file_bytes(const char *path, uint8_t **out, int *out_sz)
{
    FILE *f;
    long sz;
    uint8_t *buf;

    f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf;
    *out_sz = (int)sz;
    return 0;
}

/* --- Phase 1 transcript hashing (issues #1, #3) -------------------
 * Two variants:
 *   mqc_compute_transcript_hash  — for ML-DSA signatures.  Includes
 *     the 6-byte role tag so a client signature is bytewise distinct
 *     from a server signature over the same transcript.
 *   mqc_transcript_hash_kdf      — for HKDF-Extract salt.  Same input
 *     MINUS the role tag (both peers compute the same byte string). */

static uint8_t s_suite_id[WC_SHA256_DIGEST_SIZE];
static pthread_once_t s_suite_id_once = PTHREAD_ONCE_INIT;

static void mqc_init_suite_id(void)
{
    wc_Sha256Hash((const byte *)MQC_SUITE_STRING,
                  (word32)strlen(MQC_SUITE_STRING),
                  s_suite_id);
}

static void mqc_put_u32be(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

static int mqc_transcript_update_common(wc_Sha256 *sha,
    int mode_id,
    const uint8_t *ek, size_t ek_len,
    const uint8_t *ct, size_t ct_len,
    int32_t cert_index_c, int32_t cert_index_s)
{
    uint8_t hdr[16 + 1 + 1 + WC_SHA256_DIGEST_SIZE];
    uint8_t lenbuf[4];
    int ret;

    pthread_once(&s_suite_id_once, mqc_init_suite_id);

    memcpy(hdr, MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN);
    hdr[16] = (uint8_t)MQC_PROTOCOL_VERSION;
    hdr[17] = (uint8_t)mode_id;
    memcpy(hdr + 18, s_suite_id, WC_SHA256_DIGEST_SIZE);
    if ((ret = wc_Sha256Update(sha, hdr, sizeof(hdr))) != 0) return ret;

    mqc_put_u32be(lenbuf, (uint32_t)ek_len);
    if ((ret = wc_Sha256Update(sha, lenbuf, 4)) != 0) return ret;
    if (ek_len && (ret = wc_Sha256Update(sha, ek, (word32)ek_len)) != 0) return ret;

    mqc_put_u32be(lenbuf, (uint32_t)ct_len);
    if ((ret = wc_Sha256Update(sha, lenbuf, 4)) != 0) return ret;
    if (ct_len && (ret = wc_Sha256Update(sha, ct, (word32)ct_len)) != 0) return ret;

    mqc_put_u32be(lenbuf, (uint32_t)cert_index_c);
    if ((ret = wc_Sha256Update(sha, lenbuf, 4)) != 0) return ret;
    mqc_put_u32be(lenbuf, (uint32_t)cert_index_s);
    if ((ret = wc_Sha256Update(sha, lenbuf, 4)) != 0) return ret;

    return 0;
}

static int mqc_compute_transcript_hash(
    uint8_t out[WC_SHA256_DIGEST_SIZE],
    int mode_id,
    const uint8_t *ek, size_t ek_len,
    const uint8_t *ct, size_t ct_len,
    int32_t cert_index_c, int32_t cert_index_s,
    const char *role)
{
    wc_Sha256 sha;
    int ret;
    if ((ret = wc_InitSha256(&sha)) != 0) return ret;
    ret = mqc_transcript_update_common(&sha, mode_id, ek, ek_len,
                                       ct, ct_len, cert_index_c, cert_index_s);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, (const byte *)role, MQC_ROLE_LEN);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return ret;
}

static int mqc_transcript_hash_kdf(
    uint8_t out[WC_SHA256_DIGEST_SIZE],
    int mode_id,
    const uint8_t *ek, size_t ek_len,
    const uint8_t *ct, size_t ct_len,
    int32_t cert_index_c, int32_t cert_index_s)
{
    wc_Sha256 sha;
    int ret;
    if ((ret = wc_InitSha256(&sha)) != 0) return ret;
    ret = mqc_transcript_update_common(&sha, mode_id, ek, ek_len,
                                       ct, ct_len, cert_index_c, cert_index_s);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return ret;
}

/* --- Phase 1 AAD builder (issue #5) -------------------------------
 * 31-byte AAD on every AEAD call past the unauthenticated handshake
 * fields:
 *   LABEL                       (16 bytes "mqc-frame/v01\n\x00")
 * || u8(version) || u8(direction) || u8(frame_type)
 * || u64be(sequence) || u32be(plaintext_length) */
static void mqc_build_aad(uint8_t out[MQC_AAD_LEN],
                          uint8_t direction,
                          uint8_t frame_type,
                          uint64_t sequence,
                          uint32_t plaintext_length)
{
    int i = 0;
    memcpy(out + i, MQC_AAD_LABEL, MQC_AAD_LABEL_LEN);
    i += MQC_AAD_LABEL_LEN;
    out[i++] = (uint8_t)MQC_PROTOCOL_VERSION;
    out[i++] = direction;
    out[i++] = frame_type;
    out[i++] = (uint8_t)(sequence >> 56);
    out[i++] = (uint8_t)(sequence >> 48);
    out[i++] = (uint8_t)(sequence >> 40);
    out[i++] = (uint8_t)(sequence >> 32);
    out[i++] = (uint8_t)(sequence >> 24);
    out[i++] = (uint8_t)(sequence >> 16);
    out[i++] = (uint8_t)(sequence >> 8);
    out[i++] = (uint8_t)(sequence);
    out[i++] = (uint8_t)(plaintext_length >> 24);
    out[i++] = (uint8_t)(plaintext_length >> 16);
    out[i++] = (uint8_t)(plaintext_length >> 8);
    out[i++] = (uint8_t)(plaintext_length);
    (void)i;
}

/* TLS-1.3 §5.3 nonce construction: nonce = iv XOR (4 zeros ||
 * htobe64(seq)).  Per-direction IV makes the on-wire nonce
 * unpredictable across connections (issue #3). */
static void make_nonce(const uint8_t iv[MQC_GCM_IV_SZ],
                       uint64_t seq, uint8_t nonce[MQC_GCM_IV_SZ])
{
    int i;
    uint8_t mask[MQC_GCM_IV_SZ];
    memset(mask, 0, 4);
    mask[4]  = (uint8_t)(seq >> 56);
    mask[5]  = (uint8_t)(seq >> 48);
    mask[6]  = (uint8_t)(seq >> 40);
    mask[7]  = (uint8_t)(seq >> 32);
    mask[8]  = (uint8_t)(seq >> 24);
    mask[9]  = (uint8_t)(seq >> 16);
    mask[10] = (uint8_t)(seq >> 8);
    mask[11] = (uint8_t)(seq);
    for (i = 0; i < MQC_GCM_IV_SZ; i++)
        nonce[i] = iv[i] ^ mask[i];
}

/* --- Phase 1 derivation tree (issue #3) ---------------------------
 * data_secret  = HKDF-Extract(salt=transcript_hash_full, IKM=SS)
 * early_secret = HKDF-Extract(salt=transcript_hash_phase1, IKM=SS)
 * Then HKDF-Expand for per-direction keys, IVs, finished MAC keys. */

static int derive_data_keys(
    const uint8_t *shared_secret,
    const uint8_t  transcript_hash[WC_SHA256_DIGEST_SIZE],
    uint8_t c2s_key     [MQC_AES_KEY_SZ],
    uint8_t s2c_key     [MQC_AES_KEY_SZ],
    uint8_t c2s_iv      [MQC_GCM_IV_SZ],
    uint8_t s2c_iv      [MQC_GCM_IV_SZ],
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ],
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ])
{
    uint8_t prk[WC_SHA256_DIGEST_SIZE];
    int ret;

    ret = wc_HKDF_Extract(WC_SHA256,
        transcript_hash, WC_SHA256_DIGEST_SIZE,
        shared_secret,   WC_ML_KEM_SS_SZ,
        prk);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_DATA_C2S_KEY,
        (word32)strlen(MQC_HKDF_INFO_DATA_C2S_KEY),
        c2s_key, MQC_AES_KEY_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_DATA_S2C_KEY,
        (word32)strlen(MQC_HKDF_INFO_DATA_S2C_KEY),
        s2c_key, MQC_AES_KEY_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_DATA_C2S_IV,
        (word32)strlen(MQC_HKDF_INFO_DATA_C2S_IV),
        c2s_iv, MQC_GCM_IV_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_DATA_S2C_IV,
        (word32)strlen(MQC_HKDF_INFO_DATA_S2C_IV),
        s2c_iv, MQC_GCM_IV_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_DATA_C2S_FINISHED,
        (word32)strlen(MQC_HKDF_INFO_DATA_C2S_FINISHED),
        c2s_finished, MQC_FINISHED_MAC_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_DATA_S2C_FINISHED,
        (word32)strlen(MQC_HKDF_INFO_DATA_S2C_FINISHED),
        s2c_finished, MQC_FINISHED_MAC_SZ);

out:
    secure_zero(prk, sizeof(prk));
    return ret;
}

/* derive_early_keys (encrypted-identity early_secret expand) was
 * removed after the encrypted-mode stubs went in.  Restore in Phase
 * 5 alongside the encrypted-mode rewrite — see mqc-master.plan. */


/* --- Phase 1 Finished MAC (issue #4) ------------------------------ */

static int mqc_compute_finished_mac(
    const uint8_t finished_key[MQC_FINISHED_MAC_SZ],
    const uint8_t transcript_hash[WC_SHA256_DIGEST_SIZE],
    uint8_t out_mac[MQC_FINISHED_MAC_SZ])
{
    Hmac hmac;
    int ret;
    if ((ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID)) != 0) return ret;
    if ((ret = wc_HmacSetKey(&hmac, WC_SHA256, finished_key,
                             MQC_FINISHED_MAC_SZ)) != 0) goto out;
    if ((ret = wc_HmacUpdate(&hmac, transcript_hash,
                             WC_SHA256_DIGEST_SIZE)) != 0) goto out;
    ret = wc_HmacFinal(&hmac, out_mac);
out:
    wc_HmacFree(&hmac);
    return ret;
}

static int mqc_const_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t r = 0;
    while (n--) r |= *a++ ^ *b++;
    return r == 0;
}

/* --- Socket timeout --- */

static void set_socket_timeout(int fd, int seconds)
{
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void clear_socket_timeout(int fd)
{
    struct timeval tv = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* --- Redis rate limiting --- */

static redisContext *s_redis = NULL;

static void mqc_redis_init(void)
{
    struct timeval timeout = { 1, 0 };
    if (s_redis) return;  /* already connected */

    s_redis = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (!s_redis || s_redis->err) {
        MQC_LOG("Redis connect failed: %s — rate limiting disabled",
                s_redis ? s_redis->errstr : "NULL context");
        if (s_redis) { redisFree(s_redis); s_redis = NULL; }
    } else {
        MQC_LOG("Redis connected for rate limiting");
    }
}

static int redis_incr(const char *key, int ttl_secs)
{
    redisReply *reply;
    int count;

    if (!s_redis) return 0;

    reply = redisCommand(s_redis, "INCR %s", key);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        MQC_LOG("Redis INCR failed for %s — fail-open", key);
        if (reply) freeReplyObject(reply);
        return 0;
    }
    count = (int)reply->integer;
    freeReplyObject(reply);

    if (count == 1) {
        reply = redisCommand(s_redis, "EXPIRE %s %d", key, ttl_secs);
        if (reply) freeReplyObject(reply);
    }
    return count;
}

/* Check rate limit for a connection attempt. Returns 0 = OK, -1 = reject. */
static int mqc_ratelimit_check(const char *ip)
{
    char key[128];
    int count_m, count_h;

    mqc_redis_init();
    if (!s_redis) return 0;  /* no Redis = allow */

    /* Per-minute */
    snprintf(key, sizeof(key), "mqc:%s:conn:m", ip);
    count_m = redis_incr(key, 60);

    /* Per-hour */
    snprintf(key, sizeof(key), "mqc:%s:conn:h", ip);
    count_h = redis_incr(key, 3600);

    if (count_m > mqc_rt_cfg()->rl_connect_per_min) {
        MQC_SECURITY("RATE_LIMITED: %s connect %d/min (max %ld)",
                     ip, count_m, mqc_rt_cfg()->rl_connect_per_min);
        return -1;
    }
    if (count_h > mqc_rt_cfg()->rl_connect_per_hour) {
        MQC_SECURITY("RATE_LIMITED: %s connect %d/hr (max %ld)",
                     ip, count_h, mqc_rt_cfg()->rl_connect_per_hour);
        return -1;
    }
    return 0;
}

/* Check if IP has too many recent failures (does NOT increment).
 * Returns 0 = OK, -1 = too many failures. */
static int mqc_ratelimit_fail_check(const char *ip)
{
    char key[128];
    redisReply *reply;
    int count_m = 0, count_h = 0;

    if (!s_redis) return 0;

    snprintf(key, sizeof(key), "mqc:%s:fail:m", ip);
    reply = redisCommand(s_redis, "GET %s", key);
    if (reply) { if (reply->str) count_m = atoi(reply->str); freeReplyObject(reply); }

    snprintf(key, sizeof(key), "mqc:%s:fail:h", ip);
    reply = redisCommand(s_redis, "GET %s", key);
    if (reply) { if (reply->str) count_h = atoi(reply->str); freeReplyObject(reply); }

    if (count_m >= mqc_rt_cfg()->rl_fail_per_min ||
        count_h >= mqc_rt_cfg()->rl_fail_per_hour) {
        MQC_SECURITY("FAIL_RATE_LIMITED: %s failures %d/min %d/hr",
                     ip, count_m, count_h);
        return -1;
    }
    return 0;
}

/* Record a failed handshake (increment counters). */
static void mqc_ratelimit_fail_record(const char *ip)
{
    char key[128];

    if (!s_redis) return;

    snprintf(key, sizeof(key), "mqc:%s:fail:m", ip);
    redis_incr(key, 60);

    snprintf(key, sizeof(key), "mqc:%s:fail:h", ip);
    redis_incr(key, 3600);

    MQC_SECURITY("handshake failure recorded for %s", ip);
}

/* --- AbuseIPDB check --- */

struct abuse_buf { char *data; size_t sz; };

static size_t abuse_write_cb(void *ptr, size_t size, size_t nmemb, void *ud)
{
    struct abuse_buf *b = (struct abuse_buf *)ud;
    size_t total = size * nmemb;
    char *tmp = realloc(b->data, b->sz + total + 1);
    if (!tmp) return 0;
    b->data = tmp;
    memcpy(b->data + b->sz, ptr, total);
    b->sz += total;
    b->data[b->sz] = '\0';
    return total;
}

/* Read ABUSEIPDB_TOKEN from environment or ~/.env. Returns NULL if not found. */
static const char *get_abuseipdb_token(void)
{
    static char token[512] = {0};
    const char *env;
    FILE *f;
    char line[512];
    char path[512];
    const char *home;

    if (token[0]) return token;

    env = getenv("ABUSEIPDB_TOKEN");
    if (env && *env) {
        snprintf(token, sizeof(token), "%s", env);
        return token;
    }

    home = getenv("HOME");
    if (!home) return NULL;
    snprintf(path, sizeof(path), "%s/.env", home);

    f = fopen(path, "r");
    if (!f) return NULL;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ABUSEIPDB_TOKEN=", 16) == 0) {
            char *val = line + 16;
            char *nl = strchr(val, '\n');
            if (nl) *nl = '\0';
            if (strlen(val) >= 2 && val[0] == '"' && val[strlen(val)-1] == '"') {
                val[strlen(val)-1] = '\0';
                val++;
            }
            snprintf(token, sizeof(token), "%s", val);
            fclose(f);
            return token;
        }
    }
    fclose(f);
    return NULL;
}

/* Check an IP against AbuseIPDB. Returns abuse confidence score (0-100),
 * or -1 if the check is unavailable (no token, network error). */
static int abuseipdb_check(const char *ip)
{
    const char *api_token = get_abuseipdb_token();
    CURL *curl;
    CURLcode cres;
    char url[512];
    char auth_header[600];
    struct curl_slist *headers = NULL;
    struct abuse_buf buf = {NULL, 0};
    int score = -1;

    if (!api_token || !ip || !*ip)
        return -1;  /* no token = skip check */

    curl = curl_easy_init();
    if (!curl) return -1;

    snprintf(url, sizeof(url),
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90",
        ip);
    snprintf(auth_header, sizeof(auth_header), "Key: %s", api_token);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, abuse_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    cres = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (cres != CURLE_OK || !buf.data) {
        free(buf.data);
        return -1;
    }

    /* Parse: {"data":{"abuseConfidenceScore":N}} */
    {
        struct json_object *obj = json_tokener_parse(buf.data);
        struct json_object *data_obj, *score_obj;
        if (obj &&
            json_object_object_get_ex(obj, "data", &data_obj) &&
            json_object_object_get_ex(data_obj, "abuseConfidenceScore", &score_obj)) {
            score = json_object_get_int(score_obj);
        }
        if (obj) json_object_put(obj);
    }

    free(buf.data);
    return score;
}

/* Check IP and reject if abuse score >= threshold. Returns 0 = OK, -1 = reject. */
static int mqc_abuse_check(const char *ip)
{
    int score = abuseipdb_check(ip);
    if (score < 0) return 0;  /* no token or error = allow (fail-open) */
    if (score >= MQC_ABUSE_THRESHOLD) {
        MQC_SECURITY("ABUSEIPDB_REJECTED: %s score=%d (threshold=%d)",
                     ip, score, MQC_ABUSE_THRESHOLD);
        return -1;
    }
    MQC_LOG("AbuseIPDB: %s score=%d (OK)", ip, score);
    return 0;
}

/* --- Context --- */

mqc_ctx_t *mqc_ctx_new(const mqc_cfg_t *cfg)
{
    mqc_ctx_t *ctx;
    char path[512];

    if (!cfg || !cfg->tpm_path || !cfg->mtc_server ||
        !cfg->ca_pubkey || cfg->ca_pubkey_sz <= 0)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->role = cfg->role;
    ctx->tpm_path = strdup(cfg->tpm_path);
    ctx->mtc_server = strdup(cfg->mtc_server);
    ctx->ca_pubkey = malloc((size_t)cfg->ca_pubkey_sz);
    if (!ctx->tpm_path || !ctx->mtc_server || !ctx->ca_pubkey) {
        mqc_ctx_free(ctx);
        return NULL;
    }
    memcpy(ctx->ca_pubkey, cfg->ca_pubkey, (size_t)cfg->ca_pubkey_sz);
    ctx->ca_pubkey_sz = cfg->ca_pubkey_sz;
    ctx->encrypt_identity = cfg->encrypt_identity;

    /* Load our cert_index from certificate.json */
    snprintf(path, sizeof(path), "%s/certificate.json", cfg->tpm_path);
    {
        uint8_t *json_buf;
        int json_sz;
        if (read_file_bytes(path, &json_buf, &json_sz) != 0) {
            fprintf(stderr, "[mqc] cannot read %s\n", path);
            mqc_ctx_free(ctx);
            return NULL;
        }
        {
            struct json_object *obj = json_tokener_parse((char *)json_buf);
            struct json_object *val;
            free(json_buf);
            if (!obj) {
                fprintf(stderr, "[mqc] invalid JSON in %s\n", path);
                mqc_ctx_free(ctx);
                return NULL;
            }
            if (json_object_object_get_ex(obj, "index", &val))
                ctx->our_cert_index = json_object_get_int(val);
            else {
                struct json_object *sc;
                if (json_object_object_get_ex(obj, "standalone_certificate", &sc) &&
                    json_object_object_get_ex(sc, "index", &val))
                    ctx->our_cert_index = json_object_get_int(val);
            }
            json_object_put(obj);
        }
    }

    /* Load our ML-DSA-87 private key PEM -> DER */
    snprintf(path, sizeof(path), "%s/private_key.pem", cfg->tpm_path);
    {
        uint8_t *pem;
        int pem_sz;
        uint8_t der[8192];
        int der_sz;

        if (read_file_bytes(path, &pem, &pem_sz) != 0) {
            fprintf(stderr, "[mqc] cannot read %s\n", path);
            mqc_ctx_free(ctx);
            return NULL;
        }

        der_sz = wc_KeyPemToDer(pem, pem_sz, der, (int)sizeof(der), NULL);
        free(pem);
        if (der_sz <= 0) {
            fprintf(stderr, "[mqc] PEM to DER failed: %d\n", der_sz);
            mqc_ctx_free(ctx);
            return NULL;
        }

        /* Store the full DER. We'll try multiple import strategies. */
        ctx->privkey_der = malloc((size_t)der_sz);
        if (!ctx->privkey_der) {
            mqc_ctx_free(ctx);
            return NULL;
        }
        memcpy(ctx->privkey_der, der, (size_t)der_sz);
        ctx->privkey_der_sz = der_sz;
        secure_zero(der, (unsigned int)der_sz);
    }

    MQC_TRACE("[mqc] context ready: cert_index=%d role=%s\n",
            ctx->our_cert_index,
            ctx->role == MQC_CLIENT ? "client" : "server");

    return ctx;
}

void mqc_ctx_free(mqc_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->tpm_path);
    free(ctx->mtc_server);
    free(ctx->ca_pubkey);
    if (ctx->privkey_der) {
        secure_zero(ctx->privkey_der, (unsigned int)ctx->privkey_der_sz);
        free(ctx->privkey_der);
    }
    free(ctx);
}

/* --- Handshake --- */

mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port)
{
    int fd = -1;
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t encaps_key[MQC_MLKEM768_PUB_SZ];
    word32 encaps_key_sz;
    uint8_t sig[MQC_MLDSA87_SIG_SZ];
    word32 sig_sz = sizeof(sig);
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t c2s_key[MQC_AES_KEY_SZ], s2c_key[MQC_AES_KEY_SZ];
    uint8_t c2s_iv[MQC_GCM_IV_SZ],   s2c_iv[MQC_GCM_IV_SZ];
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ];
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ];
    uint8_t th_sign[WC_SHA256_DIGEST_SIZE];
    uint8_t th_kdf [WC_SHA256_DIGEST_SIZE];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

    {
        struct addrinfo hints, *res, *rp;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;
        for (rp = res; rp; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(fd); fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0) {
            MQC_TRACE("[mqc] TCP connect to %s:%d failed\n", host, port);
            return NULL;
        }
    }

    MQC_TRACE("[mqc] connected to %s:%d\n", host, port);

    if (wc_InitRng(&rng) != 0) goto fail;
    rng_ok = 1;

    ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM init: %d\n", ret); goto fail; }
    mlkem_ok = 1;
    ret = wc_MlKemKey_MakeKey(&mlkem, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM keygen: %d\n", ret); goto fail; }
    wc_MlKemKey_PublicKeySize(&mlkem, &encaps_key_sz);
    if (encaps_key_sz != MQC_MLKEM768_PUB_SZ) {
        fprintf(stderr, "[mqc] ML-KEM pub size %u != %u\n",
                encaps_key_sz, MQC_MLKEM768_PUB_SZ);
        goto fail;
    }
    ret = wc_MlKemKey_EncodePublicKey(&mlkem, encaps_key, encaps_key_sz);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM encode pub: %d\n", ret); goto fail; }

    /* Sign client transcript (C_s=0; client doesn't yet know server's index). */
    ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
        encaps_key, encaps_key_sz, NULL, 0,
        ctx->our_cert_index, 0, MQC_ROLE_CLIENT);
    if (ret != 0) goto fail;

    wc_dilithium_init(&dil);
    dil_ok = 1;
    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
    {
        word32 dil_idx = 0;
        ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx,
            &dil, (word32)ctx->privkey_der_sz);
    }
    if (ret != 0) { fprintf(stderr, "[mqc] DSA import: %d\n", ret); goto fail; }

    ret = wc_dilithium_sign_ctx_msg(
        (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
        th_sign, WC_SHA256_DIGEST_SIZE,
        sig, &sig_sz, &dil, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc] DSA sign: %d\n", ret); goto fail; }

    {
        char *ek_hex  = malloc(encaps_key_sz * 2 + 1);
        char *sig_hex = malloc(sig_sz * 2 + 1);
        int json_len;
        if (!ek_hex || !sig_hex) { free(ek_hex); free(sig_hex); goto fail; }
        to_hex(encaps_key, (int)encaps_key_sz, ek_hex);
        to_hex(sig,        (int)sig_sz,        sig_hex);
        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"version\":%d,\"suite\":\"%s\",\"mode\":\"clear\","
            "\"kem_pub\":\"%s\",\"cert_index\":%d,\"signature\":\"%s\"}",
            MQC_PROTOCOL_VERSION, MQC_SUITE_STRING,
            ek_hex, ctx->our_cert_index, sig_hex);
        free(ek_hex); free(sig_hex);
        if (write_all(fd, (unsigned char *)json_buf, (unsigned int)json_len) != 0)
            goto fail;
    }

    MQC_TRACE("[mqc] sent ClientHello (cert_index=%d)\n", ctx->our_cert_index);

    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;

    {
        struct json_tokener *tok;
        struct json_object *resp = NULL;
        struct json_object *val;
        const char *ct_hex = NULL, *resp_sig_hex = NULL;
        const char *suite_str = NULL, *mode_str = NULL;
        uint8_t ciphertext[MQC_MLKEM768_CT_SZ];
        int ct_sz;
        uint8_t resp_sig[MQC_MLDSA87_SIG_SZ];
        int resp_sig_sz;
        int peer_index;
        int peer_version = -1;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;

        tok = json_tokener_new();
        if (!tok) goto fail;
        json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
        resp = json_tokener_parse_ex(tok, json_buf, ret);
        if (!resp || json_tokener_get_error(tok) != json_tokener_success) {
            json_tokener_free(tok);
            if (resp) json_object_put(resp);
            MQC_SECURITY("ServerHello: strict JSON parse failed");
            goto fail;
        }
        json_tokener_free(tok);

        if (!json_object_object_get_ex(resp, "version", &val) ||
            (peer_version = json_object_get_int(val)) != MQC_PROTOCOL_VERSION) {
            MQC_SECURITY("ServerHello: version mismatch (got %d)", peer_version);
            json_object_put(resp); goto fail;
        }
        if (!json_object_object_get_ex(resp, "suite", &val) ||
            (suite_str = json_object_get_string(val)) == NULL ||
            strcmp(suite_str, MQC_SUITE_STRING) != 0) {
            MQC_SECURITY("ServerHello: suite mismatch");
            json_object_put(resp); goto fail;
        }
        if (!json_object_object_get_ex(resp, "mode", &val) ||
            (mode_str = json_object_get_string(val)) == NULL ||
            strcmp(mode_str, "clear") != 0) {
            MQC_SECURITY("ServerHello: mode mismatch");
            json_object_put(resp); goto fail;
        }
        if (!json_object_object_get_ex(resp, "cert_index", &val)) {
            json_object_put(resp); goto fail;
        }
        peer_index = json_object_get_int(val);
        if (!json_object_object_get_ex(resp, "kem_pub", &val) ||
            (ct_hex = json_object_get_string(val)) == NULL) {
            json_object_put(resp); goto fail;
        }
        ct_sz = hex_to_bytes(ct_hex, ciphertext, sizeof(ciphertext));
        if (ct_sz != MQC_MLKEM768_CT_SZ) {
            MQC_SECURITY("ServerHello: kem_pub length %d != %d",
                         ct_sz, MQC_MLKEM768_CT_SZ);
            json_object_put(resp); goto fail;
        }
        if (!json_object_object_get_ex(resp, "signature", &val) ||
            (resp_sig_hex = json_object_get_string(val)) == NULL) {
            json_object_put(resp); goto fail;
        }
        resp_sig_sz = hex_to_bytes(resp_sig_hex, resp_sig, sizeof(resp_sig));
        if (resp_sig_sz != MQC_MLDSA87_SIG_SZ) {
            MQC_SECURITY("ServerHello: signature length %d != %d",
                         resp_sig_sz, MQC_MLDSA87_SIG_SZ);
            json_object_put(resp); goto fail;
        }
        json_object_put(resp);

        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, 0, &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) {
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d", peer_index);
            goto fail;
        }

        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
            encaps_key, encaps_key_sz, ciphertext, (size_t)ct_sz,
            ctx->our_cert_index, peer_index, MQC_ROLE_SERVER);
        if (ret != 0) { free(peer_pubkey); goto fail; }

        {
            dilithium_key peer_dil;
            int verified = 0;
            wc_dilithium_init(&peer_dil);
            wc_dilithium_set_level(&peer_dil, WC_ML_DSA_87);
            {
                word32 peer_idx = 0;
                ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &peer_idx,
                    &peer_dil, (word32)peer_pubkey_sz);
            }
            if (ret == 0) {
                ret = wc_dilithium_verify_ctx_msg(
                    resp_sig, (word32)resp_sig_sz,
                    (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
                    th_sign, WC_SHA256_DIGEST_SIZE,
                    &verified, &peer_dil);
            }
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);
            if (ret != 0 || !verified) {
                MQC_SECURITY("SIG_VERIFY_FAILED: server signature invalid");
                goto fail;
            }
        }

        MQC_TRACE("[mqc] peer %d verified + signature OK\n", peer_index);

        ret = wc_MlKemKey_Decapsulate(&mlkem, shared_secret,
            ciphertext, (word32)ct_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM decapsulate: %d\n", ret);
            goto fail;
        }

        ret = mqc_transcript_hash_kdf(th_kdf, MQC_MODE_CLEAR,
            encaps_key, encaps_key_sz, ciphertext, (size_t)ct_sz,
            ctx->our_cert_index, peer_index);
        if (ret != 0) goto fail;
        ret = derive_data_keys(shared_secret, th_kdf,
            c2s_key, s2c_key, c2s_iv, s2c_iv,
            c2s_finished, s2c_finished);
        if (ret != 0) goto fail;

        conn = calloc(1, sizeof(*conn));
        if (!conn) goto fail;
        conn->fd = fd;
        memcpy(conn->send_key, c2s_key, MQC_AES_KEY_SZ);
        memcpy(conn->recv_key, s2c_key, MQC_AES_KEY_SZ);
        memcpy(conn->send_iv,  c2s_iv,  MQC_GCM_IV_SZ);
        memcpy(conn->recv_iv,  s2c_iv,  MQC_GCM_IV_SZ);
        memcpy(conn->send_finished_key, c2s_finished, MQC_FINISHED_MAC_SZ);
        memcpy(conn->recv_finished_key, s2c_finished, MQC_FINISHED_MAC_SZ);
        memcpy(conn->transcript_hash_full, th_kdf, WC_SHA256_DIGEST_SIZE);
        conn->peer_index = peer_index;
        conn->is_client = 1;
        conn->send_seq = 0;
        conn->recv_seq = 0;
        conn->finished_verified = 0;

        if (mqc_send_finished(conn) != 0) goto fail;
        if (mqc_recv_finished(conn) != 0) goto fail;

        MQC_TRACE("[mqc] session established with peer %d (Finished verified)\n",
                  peer_index);
    }

    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(c2s_key, sizeof(c2s_key));
    secure_zero(s2c_key, sizeof(s2c_key));
    secure_zero(c2s_iv,  sizeof(c2s_iv));
    secure_zero(s2c_iv,  sizeof(s2c_iv));
    secure_zero(c2s_finished, sizeof(c2s_finished));
    secure_zero(s2c_finished, sizeof(s2c_finished));
    secure_zero(th_sign, sizeof(th_sign));
    secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    MQC_TRACE("[mqc] connect to %s:%d failed (handshake)\n", host, port);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(c2s_key, sizeof(c2s_key));
    secure_zero(s2c_key, sizeof(s2c_key));
    secure_zero(c2s_iv,  sizeof(c2s_iv));
    secure_zero(s2c_iv,  sizeof(s2c_iv));
    secure_zero(c2s_finished, sizeof(c2s_finished));
    secure_zero(s2c_finished, sizeof(s2c_finished));
    secure_zero(th_sign, sizeof(th_sign));
    secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (conn) { free(conn); conn = NULL; }
    if (fd >= 0) close(fd);
    return NULL;
}

mqc_conn_t *mqc_accept(mqc_ctx_t *ctx, int listen_fd)
{
    int fd;
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t ciphertext[MQC_MLKEM768_CT_SZ];
    word32 ct_sz;
    uint8_t sig[MQC_MLDSA87_SIG_SZ];
    word32 sig_sz = sizeof(sig);
    uint8_t c2s_key[MQC_AES_KEY_SZ], s2c_key[MQC_AES_KEY_SZ];
    uint8_t c2s_iv[MQC_GCM_IV_SZ],   s2c_iv[MQC_GCM_IV_SZ];
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ];
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ];
    uint8_t th_sign[WC_SHA256_DIGEST_SIZE];
    uint8_t th_kdf [WC_SHA256_DIGEST_SIZE];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;
    char client_ip[64] = "unknown";

    fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;

    /* Arm the slow-loris deadline AFTER accept() returns.  Setting it
     * before accept() is wrong: accept() can block for arbitrarily
     * long waiting for the next connection, and the 5-second budget
     * would already be expired before the handshake even begins.
     * Bug surfaced during P1.11 attack-port-8446 testing where the
     * first attack after a quiet period reproducibly hit the
     * deadline at pos=0 in read_json_block.  Same fix applies to
     * mqc_accept_encrypted (currently stubbed). */
    HANDSHAKE_DEADLINE_ACTIVE();

    inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
    MQC_LOG("accepted connection from %s:%d", client_ip, ntohs(cli_addr.sin_port));

    if (mqc_abuse_check(client_ip) != 0) { close(fd); return NULL; }
    if (mqc_ratelimit_check(client_ip) != 0) { close(fd); return NULL; }
    if (mqc_ratelimit_fail_check(client_ip) != 0) { close(fd); return NULL; }

    set_socket_timeout(fd, mqc_rt_cfg()->handshake_stall_sec);

    if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
    rng_ok = 1;

    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) {
        MQC_SECURITY("handshake read failed (empty or malformed, fd=%d)", fd);
        goto fail;
    }
    if (ret > mqc_rt_cfg()->max_handshake_bytes) {
        MQC_SECURITY("handshake too large: %d bytes (max %ld)",
                     ret, mqc_rt_cfg()->max_handshake_bytes);
        goto fail;
    }

    {
        struct json_tokener *tok;
        struct json_object *req = NULL;
        struct json_object *val;
        const char *ek_hex = NULL, *req_sig_hex = NULL;
        const char *suite_str = NULL, *mode_str = NULL;
        uint8_t encaps_key[MQC_MLKEM768_PUB_SZ];
        int ek_sz;
        uint8_t req_sig[MQC_MLDSA87_SIG_SZ];
        int req_sig_sz;
        int peer_index;
        int peer_version = -1;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;

        tok = json_tokener_new();
        if (!tok) goto fail;
        json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
        req = json_tokener_parse_ex(tok, json_buf, ret);
        if (!req || json_tokener_get_error(tok) != json_tokener_success) {
            json_tokener_free(tok);
            if (req) json_object_put(req);
            MQC_SECURITY("ClientHello: strict JSON parse failed");
            goto fail;
        }
        json_tokener_free(tok);

        if (!json_object_object_get_ex(req, "version", &val) ||
            (peer_version = json_object_get_int(val)) != MQC_PROTOCOL_VERSION) {
            MQC_SECURITY("ClientHello: version mismatch (got %d)", peer_version);
            json_object_put(req); goto fail;
        }
        if (!json_object_object_get_ex(req, "suite", &val) ||
            (suite_str = json_object_get_string(val)) == NULL ||
            strcmp(suite_str, MQC_SUITE_STRING) != 0) {
            MQC_SECURITY("ClientHello: suite mismatch");
            json_object_put(req); goto fail;
        }
        if (!json_object_object_get_ex(req, "mode", &val) ||
            (mode_str = json_object_get_string(val)) == NULL ||
            strcmp(mode_str, "clear") != 0) {
            MQC_SECURITY("ClientHello: mode mismatch (expected clear)");
            json_object_put(req); goto fail;
        }
        if (!json_object_object_get_ex(req, "cert_index", &val)) {
            json_object_put(req); goto fail;
        }
        peer_index = json_object_get_int(val);
        if (!json_object_object_get_ex(req, "kem_pub", &val) ||
            (ek_hex = json_object_get_string(val)) == NULL) {
            json_object_put(req); goto fail;
        }
        ek_sz = hex_to_bytes(ek_hex, encaps_key, sizeof(encaps_key));
        if (ek_sz != MQC_MLKEM768_PUB_SZ) {
            MQC_SECURITY("ClientHello: kem_pub length %d != %d",
                         ek_sz, MQC_MLKEM768_PUB_SZ);
            json_object_put(req); goto fail;
        }
        if (!json_object_object_get_ex(req, "signature", &val) ||
            (req_sig_hex = json_object_get_string(val)) == NULL) {
            json_object_put(req); goto fail;
        }
        req_sig_sz = hex_to_bytes(req_sig_hex, req_sig, sizeof(req_sig));
        if (req_sig_sz != MQC_MLDSA87_SIG_SZ) {
            MQC_SECURITY("ClientHello: signature length %d != %d",
                         req_sig_sz, MQC_MLDSA87_SIG_SZ);
            json_object_put(req); goto fail;
        }
        json_object_put(req);

        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, 1, &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) {
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d", peer_index);
            goto fail;
        }

        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
            encaps_key, (size_t)ek_sz, NULL, 0,
            peer_index, 0, MQC_ROLE_CLIENT);
        if (ret != 0) { free(peer_pubkey); goto fail; }

        {
            dilithium_key peer_dil;
            int verified = 0;
            wc_dilithium_init(&peer_dil);
            wc_dilithium_set_level(&peer_dil, WC_ML_DSA_87);
            {
                word32 peer_idx = 0;
                ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &peer_idx,
                    &peer_dil, (word32)peer_pubkey_sz);
            }
            if (ret == 0) {
                ret = wc_dilithium_verify_ctx_msg(
                    req_sig, (word32)req_sig_sz,
                    (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
                    th_sign, WC_SHA256_DIGEST_SIZE,
                    &verified, &peer_dil);
            }
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);
            if (ret != 0 || !verified) {
                MQC_SECURITY("SIG_VERIFY_FAILED: client signature invalid");
                goto fail;
            }
        }

        MQC_TRACE("[mqc] peer %d verified + signature OK\n", peer_index);

        ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
        if (ret != 0) goto fail;
        mlkem_ok = 1;
        ret = wc_MlKemKey_DecodePublicKey(&mlkem, encaps_key, (word32)ek_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM decode pub: %d\n", ret);
            goto fail;
        }
        ct_sz = sizeof(ciphertext);
        wc_MlKemKey_CipherTextSize(&mlkem, &ct_sz);
        if (ct_sz != MQC_MLKEM768_CT_SZ) {
            fprintf(stderr, "[mqc] ML-KEM ct size %u != %u\n",
                    ct_sz, MQC_MLKEM768_CT_SZ);
            goto fail;
        }
        ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM encapsulate: %d\n", ret);
            goto fail;
        }

        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
            encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
            peer_index, ctx->our_cert_index, MQC_ROLE_SERVER);
        if (ret != 0) goto fail;

        wc_dilithium_init(&dil);
        dil_ok = 1;
        wc_dilithium_set_level(&dil, WC_ML_DSA_87);
        {
            word32 dil_idx2 = 0;
            ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx2,
                &dil, (word32)ctx->privkey_der_sz);
        }
        if (ret != 0) { fprintf(stderr, "[mqc] server DSA import: %d\n", ret); goto fail; }

        ret = wc_dilithium_sign_ctx_msg(
            (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
            th_sign, WC_SHA256_DIGEST_SIZE,
            sig, &sig_sz, &dil, &rng);
        if (ret != 0) goto fail;

        {
            char *ct_hex_str  = malloc(ct_sz * 2 + 1);
            char *sig_hex_str = malloc(sig_sz * 2 + 1);
            int json_len;
            if (!ct_hex_str || !sig_hex_str) {
                free(ct_hex_str); free(sig_hex_str); goto fail;
            }
            to_hex(ciphertext, (int)ct_sz, ct_hex_str);
            to_hex(sig,        (int)sig_sz, sig_hex_str);
            json_len = snprintf(json_buf, sizeof(json_buf),
                "{\"version\":%d,\"suite\":\"%s\",\"mode\":\"clear\","
                "\"kem_pub\":\"%s\",\"cert_index\":%d,\"signature\":\"%s\"}",
                MQC_PROTOCOL_VERSION, MQC_SUITE_STRING,
                ct_hex_str, ctx->our_cert_index, sig_hex_str);
            free(ct_hex_str); free(sig_hex_str);
            if (write_all(fd, (unsigned char *)json_buf, (unsigned int)json_len) != 0)
                goto fail;
        }

        ret = mqc_transcript_hash_kdf(th_kdf, MQC_MODE_CLEAR,
            encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
            peer_index, ctx->our_cert_index);
        if (ret != 0) goto fail;
        ret = derive_data_keys(shared_secret, th_kdf,
            c2s_key, s2c_key, c2s_iv, s2c_iv,
            c2s_finished, s2c_finished);
        if (ret != 0) goto fail;

        conn = calloc(1, sizeof(*conn));
        if (!conn) goto fail;
        conn->fd = fd;
        memcpy(conn->send_key, s2c_key, MQC_AES_KEY_SZ);
        memcpy(conn->recv_key, c2s_key, MQC_AES_KEY_SZ);
        memcpy(conn->send_iv,  s2c_iv,  MQC_GCM_IV_SZ);
        memcpy(conn->recv_iv,  c2s_iv,  MQC_GCM_IV_SZ);
        memcpy(conn->send_finished_key, s2c_finished, MQC_FINISHED_MAC_SZ);
        memcpy(conn->recv_finished_key, c2s_finished, MQC_FINISHED_MAC_SZ);
        memcpy(conn->transcript_hash_full, th_kdf, WC_SHA256_DIGEST_SIZE);
        conn->peer_index = peer_index;
        conn->is_client = 0;
        conn->send_seq = 0;
        conn->recv_seq = 0;
        conn->finished_verified = 0;

        if (mqc_recv_finished(conn) != 0) goto fail;
        if (mqc_send_finished(conn) != 0) goto fail;

        clear_socket_timeout(fd);
        MQC_TRACE("[mqc] session established with peer %d (Finished verified)\n",
                  peer_index);
    }

    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(c2s_key, sizeof(c2s_key));
    secure_zero(s2c_key, sizeof(s2c_key));
    secure_zero(c2s_iv,  sizeof(c2s_iv));
    secure_zero(s2c_iv,  sizeof(s2c_iv));
    secure_zero(c2s_finished, sizeof(c2s_finished));
    secure_zero(s2c_finished, sizeof(s2c_finished));
    secure_zero(th_sign, sizeof(th_sign));
    secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    mqc_ratelimit_fail_record(client_ip);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(c2s_key, sizeof(c2s_key));
    secure_zero(s2c_key, sizeof(s2c_key));
    secure_zero(c2s_iv,  sizeof(c2s_iv));
    secure_zero(s2c_iv,  sizeof(s2c_iv));
    secure_zero(c2s_finished, sizeof(c2s_finished));
    secure_zero(s2c_finished, sizeof(s2c_finished));
    secure_zero(th_sign, sizeof(th_sign));
    secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (conn) { free(conn); conn = NULL; }
    if (fd >= 0) close(fd);
    return NULL;
}

/* --- Encrypted-identity handshake helpers --- */

static int enc_send(int fd,
                    const uint8_t *key, const uint8_t *iv,
                    uint64_t *seq,
                    uint8_t direction, uint8_t frame_type,
                    const void *data, int data_sz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t aad[MQC_AAD_LEN];
    uint8_t *ct;
    uint32_t net_len;
    int ret;

    ct = malloc((size_t)data_sz);
    if (!ct) return -1;
    make_nonce(iv, *seq, nonce);
    mqc_build_aad(aad, direction, frame_type, *seq, (uint32_t)data_sz);
    (*seq)++;
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }
    ret = wc_AesGcmSetKey(&aes, key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }
    ret = wc_AesGcmEncrypt(&aes, ct, (const byte *)data, (word32)data_sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, aad, MQC_AAD_LEN);
    wc_AesFree(&aes);
    if (ret != 0) { free(ct); return -1; }

    net_len = htonl((uint32_t)(data_sz + MQC_GCM_TAG_SZ));
    if (write_all(fd, (unsigned char *)&net_len, 4) != 0 ||
        write_all(fd, ct, (unsigned int)data_sz) != 0 ||
        write_all(fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct); return -1;
    }
    free(ct);
    return 0;
}

static int enc_recv(int fd,
                    const uint8_t *key, const uint8_t *iv,
                    uint64_t *seq,
                    uint8_t direction, uint8_t frame_type,
                    void *buf, int bufsz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t aad[MQC_AAD_LEN];
    uint32_t net_len, total_len;
    int ct_sz;
    uint8_t *ct;
    int ret;

    if (read_all(fd, (unsigned char *)&net_len, 4) != 0) return -1;
    total_len = ntohl(net_len);
    if (total_len < MQC_GCM_TAG_SZ ||
        total_len > (uint32_t)mqc_rt_cfg()->max_msg_bytes) return -1;
    ct_sz = (int)(total_len - MQC_GCM_TAG_SZ);
    if (ct_sz > bufsz) return -1;

    ct = malloc((size_t)ct_sz);
    if (!ct) return -1;
    if (read_all(fd, ct, (unsigned int)ct_sz) != 0 ||
        read_all(fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct); return -1;
    }
    make_nonce(iv, *seq, nonce);
    mqc_build_aad(aad, direction, frame_type, *seq, (uint32_t)ct_sz);
    (*seq)++;
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }
    ret = wc_AesGcmSetKey(&aes, key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }
    ret = wc_AesGcmDecrypt(&aes, (byte *)buf, ct, (word32)ct_sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, aad, MQC_AAD_LEN);
    wc_AesFree(&aes);
    free(ct);
    if (ret != 0) {
        MQC_SECURITY("GCM_AUTH_FAILED: decryption failed (tampered data or wrong key, seq=%lu)",
                     (unsigned long)(*seq - 1));
        return -1;
    }
    return ct_sz;
}

/* Finished helpers — defined here so they can use enc_send/enc_recv. */
static int mqc_send_finished(struct mqc_conn *conn);
static int mqc_recv_finished(struct mqc_conn *conn);
static int mqc_send_finished(struct mqc_conn *conn)
{
    uint8_t mac[MQC_FINISHED_MAC_SZ];
    uint8_t direction;
    int ret;
    if (!conn) return -1;
    ret = mqc_compute_finished_mac(conn->send_finished_key,
                                   conn->transcript_hash_full, mac);
    if (ret != 0) return ret;
    direction = conn->is_client ? MQC_DIR_C2S : MQC_DIR_S2C;
    ret = enc_send(conn->fd, conn->send_key, conn->send_iv,
                   &conn->send_seq,
                   direction, MQC_FRAME_TYPE_FINISHED,
                   mac, MQC_FINISHED_MAC_SZ);
    secure_zero(mac, sizeof(mac));
    secure_zero(conn->send_finished_key, sizeof(conn->send_finished_key));
    return ret;
}
static int mqc_recv_finished(struct mqc_conn *conn)
{
    uint8_t got_mac[MQC_FINISHED_MAC_SZ];
    uint8_t expected_mac[MQC_FINISHED_MAC_SZ];
    uint8_t direction;
    int n, ret;
    if (!conn) return -1;
    direction = conn->is_client ? MQC_DIR_S2C : MQC_DIR_C2S;
    n = enc_recv(conn->fd, conn->recv_key, conn->recv_iv,
                 &conn->recv_seq,
                 direction, MQC_FRAME_TYPE_FINISHED,
                 got_mac, sizeof(got_mac));
    if (n != MQC_FINISHED_MAC_SZ) {
        MQC_SECURITY("FINISHED_LENGTH_INVALID got %d expected %d",
                     n, MQC_FINISHED_MAC_SZ);
        return -1;
    }
    ret = mqc_compute_finished_mac(conn->recv_finished_key,
                                   conn->transcript_hash_full,
                                   expected_mac);
    if (ret != 0) return ret;
    if (!mqc_const_eq(got_mac, expected_mac, MQC_FINISHED_MAC_SZ)) {
        MQC_SECURITY("FINISHED_MAC_MISMATCH peer=%d", conn->peer_index);
        secure_zero(got_mac, sizeof(got_mac));
        secure_zero(expected_mac, sizeof(expected_mac));
        return -1;
    }
    conn->finished_verified = 1;
    secure_zero(got_mac, sizeof(got_mac));
    secure_zero(expected_mac, sizeof(expected_mac));
    secure_zero(conn->recv_finished_key, sizeof(conn->recv_finished_key));
    return 0;
}

/* --- Encrypted-identity connect / accept (Phase 1: stubbed) -----
 *
 * The encrypted-identity mode (issue #1's 4-frame variant + issue #4
 * Finished + issue #5 AAD) requires substantial new code that no
 * production caller currently exercises — every postWolf MQC client
 * (show-tpm, bootstrap_ca/leaf, admin_recosign, renew/revoke/issue
 * tools) uses clear-mode mqc_connect.  Rather than carry hundreds
 * of lines of unused (and untested-in-anger) encrypted-mode logic
 * through Phase 1, the two entry points are stubbed: any call
 * returns NULL with a clear MQC_SECURITY log line.
 *
 * To re-enable encrypted mode, restore the pre-Phase-1 bodies and
 * port them to the new transcript / HKDF Extract+Expand / IV /
 * Finished / AAD architecture (the same patterns mqc_connect and
 * mqc_accept now use, plus the early_secret split for the two
 * pre-identity phase-1 frames).  Tracked under the master plan's
 * Phase 5 (spec consolidation) cleanup. */

mqc_conn_t *mqc_connect_encrypted(mqc_ctx_t *ctx, const char *host, int port)
{
    (void)ctx; (void)host; (void)port;
    MQC_SECURITY("mqc_connect_encrypted is not implemented in Phase 1; "
                 "use mqc_connect (clear mode)");
    return NULL;
}

mqc_conn_t *mqc_accept_encrypted(mqc_ctx_t *ctx, int listen_fd)
{
    (void)ctx; (void)listen_fd;
    MQC_SECURITY("mqc_accept_encrypted is not implemented in Phase 1; "
                 "use mqc_accept (clear mode)");
    return NULL;
}

/* --- Auto-detecting accept (Phase 1: clear-mode only) -----------
 *
 * Pre-Phase-1 mqc_accept_auto inlined both the clear and encrypted
 * handshake bodies because it had to detect mode after accept().
 * Issue #1's wire-format change broke the inlined logic, and every
 * production MQC caller uses clear-mode mqc_connect, so this is a
 * thin alias for mqc_accept.  An operator who needs encrypted mode
 * on the server should call mqc_accept_encrypted directly (currently
 * stubbed; see above).  Restoring true auto-detection would require
 * extracting do_clear_post_read and do_encrypted_post_read helpers
 * from mqc_accept and mqc_accept_encrypted respectively — deferred
 * to Phase 5 (spec consolidation) cleanup.  No silent compat loss:
 * a peer sending encrypted-mode bytes hits mqc_accept's strict-parse
 * "mode" check and is rejected with a clear diagnostic. */

mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd)
{
    return mqc_accept(ctx, listen_fd);
}

/* --- I/O --- */

int mqc_write(mqc_conn_t *conn, const void *buf, int sz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t aad[MQC_AAD_LEN];
    uint8_t direction;
    uint8_t *ct;
    uint32_t net_len;
    int ret;

    if (!conn || !buf || sz <= 0) return -1;
    /* Issue #4: gate application data on Finished verification. */
    if (!conn->finished_verified) {
        MQC_SECURITY("mqc_write called before Finished verified");
        return -1;
    }

    ct = malloc((size_t)sz);
    if (!ct) return -1;

    make_nonce(conn->send_iv, conn->send_seq, nonce);
    direction = conn->is_client ? MQC_DIR_C2S : MQC_DIR_S2C;
    mqc_build_aad(aad, direction, MQC_FRAME_TYPE_APP_DATA,
                  conn->send_seq, (uint32_t)sz);
    conn->send_seq++;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }

    ret = wc_AesGcmSetKey(&aes, conn->send_key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }

    ret = wc_AesGcmEncrypt(&aes, ct, (const byte *)buf, (word32)sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, aad, MQC_AAD_LEN);
    wc_AesFree(&aes);

    if (ret != 0) { free(ct); return -1; }

    /* Send: [4-byte len] [ciphertext] [tag] */
    net_len = htonl((uint32_t)(sz + MQC_GCM_TAG_SZ));
    if (write_all(conn->fd, (unsigned char *)&net_len, 4) != 0 ||
        write_all(conn->fd, ct, (unsigned int)sz) != 0 ||
        write_all(conn->fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct);
        return -1;
    }

    free(ct);
    return sz;
}

int mqc_read(mqc_conn_t *conn, void *buf, int sz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t aad[MQC_AAD_LEN];
    uint8_t direction;
    uint32_t net_len;
    uint32_t total_len;
    int ct_sz;
    uint8_t *ct;
    int ret;

    if (!conn || !buf || sz <= 0) return -1;
    if (!conn->finished_verified) {
        MQC_SECURITY("mqc_read called before Finished verified");
        return -1;
    }

    /* Read length prefix */
    if (read_all(conn->fd, (unsigned char *)&net_len, 4) != 0)
        return 0;  /* connection closed */

    total_len = ntohl(net_len);
    if (total_len < MQC_GCM_TAG_SZ ||
        total_len > (uint32_t)mqc_rt_cfg()->max_msg_bytes)
        return -1;

    ct_sz = (int)(total_len - MQC_GCM_TAG_SZ);
    if (ct_sz > sz) return -1;  /* buffer too small */

    ct = malloc((size_t)ct_sz);
    if (!ct) return -1;

    /* Read ciphertext + tag */
    if (read_all(conn->fd, ct, (unsigned int)ct_sz) != 0 ||
        read_all(conn->fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct);
        return -1;
    }

    make_nonce(conn->recv_iv, conn->recv_seq, nonce);
    /* Receiver's AAD direction is the *peer's* direction. */
    direction = conn->is_client ? MQC_DIR_S2C : MQC_DIR_C2S;
    mqc_build_aad(aad, direction, MQC_FRAME_TYPE_APP_DATA,
                  conn->recv_seq, (uint32_t)ct_sz);
    conn->recv_seq++;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }

    ret = wc_AesGcmSetKey(&aes, conn->recv_key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }

    ret = wc_AesGcmDecrypt(&aes, (byte *)buf, ct, (word32)ct_sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, aad, MQC_AAD_LEN);
    wc_AesFree(&aes);
    free(ct);

    if (ret != 0) {
        MQC_SECURITY("GCM_AUTH_FAILED: data decryption failed "
                     "(tampered data or wrong key, peer=%d seq=%lu)",
                     conn->peer_index, (unsigned long)(conn->recv_seq - 1));
        return -1;
    }

    return ct_sz;
}

int mqc_recv(mqc_conn_t *conn, void *buf, int sz)
{
    return mqc_read(conn, buf, sz);
}

int mqc_send(mqc_conn_t *conn, const void *buf, int sz)
{
    return mqc_write(conn, buf, sz);
}

/* --- Listen / Close / Utility --- */

int mqc_listen(const char *host, int port)
{
    struct sockaddr_in addr;
    int fd, opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (host && strcmp(host, "0.0.0.0") != 0) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        if (getaddrinfo(host, NULL, &hints, &res) == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
            addr.sin_addr = sin->sin_addr;
            freeaddrinfo(res);
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    if (listen(fd, 5) < 0) {
        close(fd); return -1;
    }
    return fd;
}

void mqc_close(mqc_conn_t *conn)
{
    if (!conn) return;
    if (conn->fd >= 0) close(conn->fd);
    secure_zero(conn->send_key, MQC_AES_KEY_SZ);
    secure_zero(conn->recv_key, MQC_AES_KEY_SZ);
    free(conn);
}

int mqc_get_fd(mqc_conn_t *conn)
{
    return conn ? conn->fd : -1;
}

int mqc_get_peer_index(mqc_conn_t *conn)
{
    return conn ? conn->peer_index : -1;
}
