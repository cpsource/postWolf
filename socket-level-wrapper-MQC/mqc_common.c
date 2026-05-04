/******************************************************************************
 * File:        mqc_common.c
 * Purpose:     MQC shared machinery (rate limits, JSON parsers, transcript
 *              hash, key schedule, AEAD frames, runtime cfg, etc.).
 *
 * Description:
 *   Mode-agnostic core of the MQC reference implementation.  The two
 *   handshake-mode-specific files (mqc_clear.c, mqc_encrypted.c) call
 *   into this file via the prototypes in mqc_internal.h, and the
 *   public dispatcher in mqc.c routes mqc_connect / mqc_accept to the
 *   right mode based on cfg.encrypt_identity.
 *
 * Dependencies:
 *   wolfSSL crypto (ML-KEM, ML-DSA, AES-GCM, HKDF, SHA-256)
 *   json-c          (JSON serialization)
 *   hiredis         (Redis-backed rate-limit buckets)
 *   POSIX sockets   (TCP)
 *
 * Created:     2026-04-15  (split out of mqc.c during Phase 7 commit 1)
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>     /* INT_MAX (issue #11 strict-int range) */
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

/* MQC_AES_KEY_SZ / MQC_GCM_IV_SZ / MQC_GCM_TAG_SZ / MQC_MAX_MSG /
 * MQC_MAX_HANDSHAKE come from mqc.h (via mqc_internal.h).
 * MQC_HANDSHAKE_STALL_SEC and MQC_HANDSHAKE_TOTAL_SEC live in config.h. */
#define MQC_HANDSHAKE_TIMEOUT  MQC_HANDSHAKE_STALL_SEC

/* Wall-clock deadline for the current accept-side handshake.  Set by
 * each mqc_accept* function at entry, consulted inside mqc_read_all
 * to kill slow-loris drip attacks that stay under SO_RCVTIMEO per
 * read.  0 means "no deadline" (client side / any path that isn't
 * the accept handshake).  Safe as a file-static because mqc_common.c
 * is used in single-connection-per-process contexts — the server
 * forks per accept, clients run one mqc_connect at a time. */
static time_t s_handshake_deadline = 0;

/* Stashed peer IP from the most recent accept-side handshake.  Lets
 * callers log meaningful diagnostics when mqc_accept* returns NULL
 * (the fd has already been closed by then, so getpeername is too late). */
static char s_last_accept_peer_ip[64] = "";

const char *mqc_last_accept_peer_ip(void)
{
    return s_last_accept_peer_ip;
}

int mqc_handshake_deadline_exceeded(void)
{
    return s_handshake_deadline != 0 && time(NULL) > s_handshake_deadline;
}

void mqc_handshake_deadline_set(void)
{
    s_handshake_deadline = time(NULL) + mqc_rt_cfg()->handshake_total_sec;
}

void mqc_handshake_deadline_clear(void)
{
    s_handshake_deadline = 0;
}

/* Scope-based cleanup hook: HANDSHAKE_DEADLINE_ACTIVE() (in
 * mqc_internal.h) attaches this to a stack int via __attribute__
 * cleanup, so the deadline auto-clears on every return path. */
void mqc_handshake_deadline_cleanup(int *unused)
{
    (void)unused;
    mqc_handshake_deadline_clear();
}

#define MQC_ABUSE_THRESHOLD  25  /* reject if abuse score >= 25% */

/* --- Timing probes (opt-in via --mqc-time on the server CLI) -------
 * Once enabled, every accept() handshake logs millisecond-precision
 * stage breakdowns to stderr (so they show up in journalctl).  Useful
 * for hunting cold-start regressions like the rt_cfg/augeas pause
 * that surfaced during P2a smoke testing.  Default is OFF; the
 * macros (in mqc_internal.h) expand to no-ops in the common case so
 * the production hot path pays nothing. */
static int s_mqc_time_enabled = 0;
void mqc_set_time_enabled(int on) { s_mqc_time_enabled = !!on; }
int  mqc_get_time_enabled(void)   { return s_mqc_time_enabled; }

long mqc_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

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
 * spec §11 for the knob registry; commit `292c07bcc` introduced this
 * runtime-cfg layer (originally tracked as issue #6a). */
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
    s_rt_cfg.rl_cert_per_min =
        read_config_long("global/mqc-rl-cert-per-min",
                         MQC_RL_CERT_MIN);
    s_rt_cfg.rl_cert_per_hour =
        read_config_long("global/mqc-rl-cert-per-hour",
                         MQC_RL_CERT_HOUR);
    s_rt_cfg.revoked_cache_ttl_sec =
        read_config_long("global/mqc-revoked-cache-ttl-sec",
                         MQC_REVOKED_CACHE_TTL_SEC);
    s_rt_cfg.sig_freshness_sec =
        read_config_long("global/mqc-sig-freshness-sec",
                         MQC_SIG_FRESHNESS_SEC);

    /* Revocation policy (issue #7).  String-typed config key with
     * three accepted values.  Anything else (or empty) falls back to
     * mandatory and warns. */
    {
        char *raw = read_config_str("global/mqc-revocation-policy",
                                    MQC_REVOCATION_POLICY_DEFAULT);
        if (raw && strcmp(raw, "mandatory") == 0) {
            s_rt_cfg.revocation_policy = MQC_REVOCATION_POLICY_MANDATORY;
        } else if (raw && strcmp(raw, "cache-only") == 0) {
            s_rt_cfg.revocation_policy = MQC_REVOCATION_POLICY_CACHE_ONLY;
        } else if (raw && strcmp(raw, "disabled") == 0) {
            s_rt_cfg.revocation_policy = MQC_REVOCATION_POLICY_DISABLED;
            fprintf(stderr,
                "[MQC-SECURITY] REVOCATION_DISABLED policy=disabled "
                "(operator opt-out at /etc/postWolf/config; revoked "
                "peers will be ACCEPTED until policy is restored)\n");
        } else {
            if (raw)
                fprintf(stderr,
                    "[MQC-SECURITY] REVOCATION_POLICY_INVALID value=%s, "
                    "falling back to mandatory\n", raw);
            s_rt_cfg.revocation_policy = MQC_REVOCATION_POLICY_MANDATORY;
        }
        free(raw);
    }

    /* Spec §11.3: implementations MAY lower frame ceilings, MUST NOT
     * raise them.  Clamp config-file values that exceed the compiled
     * cap; raising would just produce frames the peer rejects. */
    if (s_rt_cfg.max_msg_bytes > MQC_MAX_MSG)
        s_rt_cfg.max_msg_bytes = MQC_MAX_MSG;
    if (s_rt_cfg.max_handshake_bytes > MQC_MAX_HANDSHAKE)
        s_rt_cfg.max_handshake_bytes = MQC_MAX_HANDSHAKE;

    /* Redis-down failure policy.  See config.h header for the
     * three accepted values + defaults.  Same shape as the
     * revocation-policy block above: string-typed key, fall back
     * to the recommended default with a warning if the operator
     * supplied something we don't recognise. */
    s_rt_cfg.redis_fail_closed_after_sec =
        read_config_long("global/mqc-rl-redis-fail-closed-after-sec",
                         MQC_REDIS_FAIL_CLOSED_AFTER_SEC_DEFAULT);
    if (s_rt_cfg.redis_fail_closed_after_sec < 0)
        s_rt_cfg.redis_fail_closed_after_sec = 0;
    {
        char *raw = read_config_str("global/mqc-rl-redis-fail-policy",
                                    MQC_REDIS_FAIL_POLICY_DEFAULT);
        if (raw && strcmp(raw, "open") == 0) {
            s_rt_cfg.redis_fail_policy = MQC_REDIS_FAIL_POLICY_OPEN;
        } else if (raw && strcmp(raw, "closed") == 0) {
            s_rt_cfg.redis_fail_policy = MQC_REDIS_FAIL_POLICY_CLOSED;
        } else if (raw && strcmp(raw, "closed-after") == 0) {
            s_rt_cfg.redis_fail_policy = MQC_REDIS_FAIL_POLICY_CLOSED_AFTER;
        } else {
            if (raw && raw[0])
                fprintf(stderr,
                    "[MQC-SECURITY] REDIS_FAIL_POLICY_INVALID value=%s, "
                    "falling back to %s\n",
                    raw, MQC_REDIS_FAIL_POLICY_DEFAULT);
            /* Match the default-string */
            if (strcmp(MQC_REDIS_FAIL_POLICY_DEFAULT, "open") == 0)
                s_rt_cfg.redis_fail_policy = MQC_REDIS_FAIL_POLICY_OPEN;
            else if (strcmp(MQC_REDIS_FAIL_POLICY_DEFAULT, "closed") == 0)
                s_rt_cfg.redis_fail_policy = MQC_REDIS_FAIL_POLICY_CLOSED;
            else
                s_rt_cfg.redis_fail_policy = MQC_REDIS_FAIL_POLICY_CLOSED_AFTER;
        }
        free(raw);
    }
    {
        char *raw = read_config_str("global/mqc-rl-redis-state-path",
                                    MQC_REDIS_STATE_PATH_DEFAULT);
        snprintf(s_rt_cfg.redis_state_path,
                 sizeof(s_rt_cfg.redis_state_path),
                 "%s",
                 (raw && raw[0]) ? raw : MQC_REDIS_STATE_PATH_DEFAULT);
        free(raw);
    }
}

const struct mqc_runtime_cfg *mqc_rt_cfg(void)
{
    pthread_once(&s_rt_cfg_once, mqc_rt_cfg_init_once);
    return &s_rt_cfg;
}

/* --- Verbose flag (the MQC_LOG / MQC_TRACE macros in
 *     mqc_internal.h reach this via the public mqc_get_verbose()
 *     accessor below, so the static stays file-local). */

static int s_mqc_verbose = 0;

void mqc_set_verbose(int level) { s_mqc_verbose = level; }
int  mqc_get_verbose(void) { return s_mqc_verbose; }

/* struct mqc_ctx and struct mqc_conn are defined in mqc_internal.h
 * so all four .c files (mqc.c dispatcher, mqc_common.c, mqc_clear.c,
 * mqc_encrypted.c) can manipulate them.  Public callers continue to
 * see them as opaque pointers per mqc.h. */

/* --- Helpers --- */

void mqc_secure_zero(void *buf, unsigned int len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    unsigned int i;
    for (i = 0; i < len; i++)
        p[i] = 0;
}

void mqc_to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

int mqc_write_all(int fd, const unsigned char *buf, unsigned int len)
{
    unsigned int sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += (unsigned int)n;
    }
    return 0;
}

int mqc_read_all(int fd, unsigned char *buf, unsigned int len)
{
    unsigned int got = 0;
    while (got < len) {
        ssize_t n;
        if (mqc_handshake_deadline_exceeded()) {
            MQC_LOG("mqc_read_all: handshake deadline exceeded "
                    "(got=%u/%u) — slow-loris?", got, len);
            return -1;
        }
        n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += (unsigned int)n;
    }
    return 0;
}

/* ====================================================================
 * Strict JSON parsing helpers (issue #11)
 *
 * MQC handshake JSON is generated by trusted peers (postWolf controls
 * all clients) but flows over the network where bytes can be tampered
 * or fabricated.  Default json-c parsing accepts duplicate keys
 * (silently keeping the last value), trailing garbage past the
 * closing brace, comments, leading zeros, and integer overflow
 * (saturates to INT_MAX).  Each of those has been used in real
 * protocols to desynchronize a signer (which hashes one value) from
 * a verifier (which parses a different value).  These helpers route
 * every handshake parse through a strict tokener with explicit
 * per-field validators, duplicate-key rejection, and unknown-field
 * rejection.
 *
 * Spec: draft-page-mqc-protocol-00.md Sections 5.2 and 12.10.
 * ==================================================================*/

struct json_object *mqc_json_parse_strict(const char *what,
                                          const char *buf, int len)
{
    struct json_tokener *tok;
    struct json_object  *obj;

    if (len <= 0 || len > MQC_MAX_HANDSHAKE) {
        MQC_SECURITY("%s: JSON_LEN_INVALID len=%d", what, len);
        return NULL;
    }
    tok = json_tokener_new();
    if (!tok) return NULL;
    json_tokener_set_flags(tok,
        JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    obj = json_tokener_parse_ex(tok, buf, len);
    if (!obj || json_tokener_get_error(tok) != json_tokener_success) {
        MQC_SECURITY("%s: strict JSON parse failed (%s)", what,
            json_tokener_error_desc(json_tokener_get_error(tok)));
        if (obj) json_object_put(obj);
        json_tokener_free(tok);
        return NULL;
    }
    if ((size_t)json_tokener_get_parse_end(tok) != (size_t)len) {
        MQC_SECURITY("%s: trailing bytes past JSON (len=%d parsed=%zu)",
                     what, len,
                     (size_t)json_tokener_get_parse_end(tok));
        json_object_put(obj);
        json_tokener_free(tok);
        return NULL;
    }
    if (!json_object_is_type(obj, json_type_object)) {
        MQC_SECURITY("%s: top-level JSON value is not an object", what);
        json_object_put(obj);
        json_tokener_free(tok);
        return NULL;
    }
    json_tokener_free(tok);
    return obj;
}

/* Count occurrences of `"<field>":` in buf, ignoring text inside
 * string literals (so a key whose VALUE happens to be a JSON-shaped
 * string doesn't inflate the count).  Used to detect duplicate keys
 * because json-c silently keeps the LAST value when a key repeats —
 * a signer that serialized the FIRST creates a transcript-vs-parsed
 * divergence.  Returns the count, or -1 on a malformed run that
 * leaves a string unterminated. */
static int mqc_json_count_field(const char *buf, int len, const char *field)
{
    int n = 0;
    int in_str = 0;
    int esc = 0;
    int field_len = (int)strlen(field);
    int i;

    for (i = 0; i < len; i++) {
        char c = buf[i];
        if (in_str) {
            if (esc)            { esc = 0; continue; }
            if (c == '\\')      { esc = 1; continue; }
            if (c == '"')       { in_str = 0; continue; }
            continue;
        }
        if (c != '"') continue;

        if (i + 1 + field_len + 1 < len &&
            memcmp(buf + i + 1, field, (size_t)field_len) == 0 &&
            buf[i + 1 + field_len] == '"') {
            int j = i + 2 + field_len;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t' ||
                               buf[j] == '\n' || buf[j] == '\r'))
                j++;
            if (j < len && buf[j] == ':') {
                n++;
                i = j;
                continue;
            }
        }
        in_str = 1;
    }
    if (in_str) return -1;
    return n;
}

int mqc_json_no_duplicates(const char *what,
                                  const char *buf, int len,
                                  const char *const *fields, int n_fields)
{
    int i;
    for (i = 0; i < n_fields; i++) {
        int n = mqc_json_count_field(buf, len, fields[i]);
        if (n != 1) {
            MQC_SECURITY("%s: field '%s' appears %d times (require 1)",
                         what, fields[i], n);
            return -1;
        }
    }
    return 0;
}

int mqc_json_no_unknown_keys(const char *what,
                                    struct json_object *obj,
                                    const char *const *allowed,
                                    int n_allowed)
{
    struct json_object_iter it;

    json_object_object_foreachC(obj, it) {
        int i, ok = 0;
        for (i = 0; i < n_allowed; i++) {
            if (strcmp(it.key, allowed[i]) == 0) { ok = 1; break; }
        }
        if (!ok) {
            MQC_SECURITY("%s: unknown field '%s'", what, it.key);
            return -1;
        }
    }
    return 0;
}

int mqc_json_get_int_strict(const char *what,
                                   struct json_object *obj, const char *field,
                                   int min, int max, int *out)
{
    struct json_object *val;
    int64_t v;

    if (!json_object_object_get_ex(obj, field, &val)) {
        MQC_SECURITY("%s: missing field '%s'", what, field);
        return -1;
    }
    if (!json_object_is_type(val, json_type_int)) {
        MQC_SECURITY("%s: field '%s' is not an integer", what, field);
        return -1;
    }
    errno = 0;
    v = json_object_get_int64(val);
    if (errno == ERANGE) {
        MQC_SECURITY("%s: field '%s' overflows int64", what, field);
        return -1;
    }
    if (v < min || v > max) {
        MQC_SECURITY("%s: field '%s' value %lld out of [%d,%d]",
                     what, field, (long long)v, min, max);
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int mqc_hex_digit_lower(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0');      return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(10 + c - 'a'); return 0; }
    return -1;
}

/* Hex blob of EXACTLY expected_byte_len bytes.  Lowercase only;
 * uppercase, separators, or wrong length are rejected before any
 * crypto runs (issue #12 also calls this out as a cheap pre-crypto
 * filter).  out_buf must hold expected_byte_len bytes. */
int mqc_json_get_hex_strict(const char *what,
                                   struct json_object *obj, const char *field,
                                   int expected_byte_len, uint8_t *out_buf)
{
    struct json_object *val;
    const char *s;
    int slen, i;

    if (!json_object_object_get_ex(obj, field, &val)) {
        MQC_SECURITY("%s: missing field '%s'", what, field);
        return -1;
    }
    if (!json_object_is_type(val, json_type_string)) {
        MQC_SECURITY("%s: field '%s' is not a string", what, field);
        return -1;
    }
    s = json_object_get_string(val);
    slen = (int)strlen(s);
    if (slen != expected_byte_len * 2) {
        MQC_SECURITY("%s: field '%s' hex length %d != %d", what, field,
                     slen, expected_byte_len * 2);
        return -1;
    }
    for (i = 0; i < expected_byte_len; i++) {
        uint8_t hi, lo;
        if (mqc_hex_digit_lower(s[i*2], &hi) != 0 ||
            mqc_hex_digit_lower(s[i*2 + 1], &lo) != 0) {
            MQC_SECURITY("%s: field '%s' invalid hex (lowercase 0-9 a-f only)",
                         what, field);
            return -1;
        }
        out_buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int mqc_json_get_string_exact(const char *what,
                                     struct json_object *obj,
                                     const char *field,
                                     const char *expected_value)
{
    struct json_object *val;
    const char *s;

    if (!json_object_object_get_ex(obj, field, &val)) {
        MQC_SECURITY("%s: missing field '%s'", what, field);
        return -1;
    }
    if (!json_object_is_type(val, json_type_string)) {
        MQC_SECURITY("%s: field '%s' is not a string", what, field);
        return -1;
    }
    s = json_object_get_string(val);
    if (strcmp(s, expected_value) != 0) {
        MQC_SECURITY("%s: field '%s' = '%s' != expected '%s'",
                     what, field, s, expected_value);
        return -1;
    }
    return 0;
}

/* ----------------------------------------------------------------------
 * Length-prefixed handshake framing (mqc-2 Phase 1, issue #1 + #2)
 *
 * Spec §5.1 mandates that EVERY unit on the wire — handshake and
 * data-plane alike — is a length-prefixed frame: 4-byte big-endian
 * payload length, followed by exactly that many payload bytes.
 *
 * Pre-mqc-2 Phase-1, the handshake JSON was sent as raw bytes and
 * read by a brace-counting parser (mqc_read_json_block, removed in
 * P1.5) that (a) wasn't string-literal aware — a `}` inside a JSON
 * string value would desynchronise framing — and (b) violated §5.1.
 * These two helpers replace that path:
 *
 *   - mqc_write_handshake_frame: prepend htonl(len), then body.
 *   - mqc_read_handshake_frame:  read 4 bytes, decode length,
 *     validate against mqc-max-handshake-bytes ceiling, then read
 *     EXACTLY that many body bytes.  Returns the body length on
 *     success, -1 on any error.  NUL-terminates the body in-place
 *     so callers can still hand the buffer to JSON parsers that
 *     want a C string.
 *
 * The slow-loris deadline (HANDSHAKE_DEADLINE_ACTIVE) propagates
 * naturally because both helpers go through mqc_read_all /
 * mqc_write_all, which already check the deadline.
 * ==================================================================*/

int mqc_write_handshake_frame(int fd, const void *body, unsigned int len)
{
    uint32_t net_len;
    if (len > (unsigned int)mqc_rt_cfg()->max_handshake_bytes) {
        MQC_SECURITY("write_handshake_frame: body %u > max_handshake_bytes %ld",
                     len, mqc_rt_cfg()->max_handshake_bytes);
        return -1;
    }
    net_len = htonl((uint32_t)len);
    if (mqc_write_all(fd, (const unsigned char *)&net_len, 4) != 0)
        return -1;
    if (len > 0 &&
        mqc_write_all(fd, (const unsigned char *)body, len) != 0)
        return -1;
    return 0;
}

int mqc_read_handshake_frame(int fd, char *buf, int bufsz)
{
    uint32_t net_len, body_len;
    long max;

    if (bufsz <= 1) return -1;

    if (mqc_read_all(fd, (unsigned char *)&net_len, 4) != 0) {
        MQC_LOG("read_handshake_frame: short read on length prefix");
        return -1;
    }
    body_len = ntohl(net_len);
    max = mqc_rt_cfg()->max_handshake_bytes;
    if (body_len == 0) {
        MQC_SECURITY("read_handshake_frame: zero-length frame");
        return -1;
    }
    if (body_len > (uint32_t)max) {
        MQC_SECURITY("read_handshake_frame: frame_len=%u > max=%ld",
                     body_len, max);
        return -1;
    }
    if ((int)body_len > bufsz - 1) {
        MQC_SECURITY("read_handshake_frame: frame_len=%u > buf=%d",
                     body_len, bufsz);
        return -1;
    }
    if (mqc_read_all(fd, (unsigned char *)buf, body_len) != 0) {
        MQC_LOG("read_handshake_frame: short read on body (claimed %u)",
                body_len);
        return -1;
    }
    buf[body_len] = '\0';
    return (int)body_len;
}

/* Shared prologue for an accepted MQC connection (mqc-2 P1.3).
 *
 * Both the per-mode direct entry points (mqc_accept_clear /
 * mqc_accept_encrypted) and the auto-detect dispatcher
 * (mqc_accept_auto) need to do the same pre-handshake work BEFORE
 * any byte of the wire is read: AbuseIPDB check, per-IP rate limit,
 * per-IP fail-rate limit, and the per-syscall socket timeout that
 * caps single-call stalls.  Centralising it here means the auto-
 * detect path can run the prologue, do its own length-prefixed read
 * + parse to learn the mode, and dispatch into the mode-specific
 * continuation without that continuation re-doing the checks.
 *
 * Returns 0 on success — caller continues with the handshake.
 * Returns -1 if the connection should be dropped — caller is
 * responsible for close(fd) and returning NULL.
 *
 * The slow-loris HANDSHAKE_DEADLINE_ACTIVE() macro stays the
 * caller's responsibility because it relies on cleanup-attribute
 * scope: arm it in the function whose lifetime should bound the
 * deadline. */
int mqc_accept_prologue(int fd, const char *client_ip)
{
    long _t_total = mqc_now_ms();

    MQC_TIME_BEGIN(abuse);
    if (mqc_abuse_check(client_ip) != 0) return -1;
    MQC_TIME_END(abuse);

    MQC_TIME_BEGIN(rl_check);
    if (mqc_ratelimit_check(client_ip) != 0) return -1;
    MQC_TIME_END(rl_check);

    MQC_TIME_BEGIN(rl_fail);
    if (mqc_ratelimit_fail_check(client_ip) != 0) return -1;
    MQC_TIME_END(rl_fail);

    mqc_set_socket_timeout(fd, mqc_rt_cfg()->handshake_stall_sec);

    if (mqc_get_time_enabled())
        fprintf(stderr, "[MQC-TIME] setup_total = %ld ms\n",
                mqc_now_ms() - _t_total);
    return 0;
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

void mqc_put_u32be(uint8_t out[4], uint32_t v)
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

int mqc_compute_transcript_hash(
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

int mqc_transcript_hash_kdf(
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
void mqc_build_aad(uint8_t out[MQC_AAD_LEN],
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
void mqc_make_nonce(const uint8_t iv[MQC_GCM_IV_SZ],
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

int mqc_derive_data_keys(
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
    mqc_secure_zero(prk, sizeof(prk));
    return ret;
}

/* Encrypted-identity early-key schedule (spec §7.3 / §8).  Used to
 * AEAD-seal the two phase-2 identity frames.  Derived from the
 * SAME shared_secret as data_secret but salted with the phase-1
 * transcript hash (C_c=C_s=0) so the early keys are independent of
 * the full-transcript data keys.  Six outputs are NOT produced
 * here (no early Finished MAC keys) -- the early keys only seal
 * the two phase-2 frames; the Finished frame after phase 2 uses
 * the full data_*_finished keys. */
int mqc_derive_early_keys(
    const uint8_t *shared_secret,
    const uint8_t  transcript_hash_phase1[WC_SHA256_DIGEST_SIZE],
    uint8_t early_c2s_key[MQC_AES_KEY_SZ],
    uint8_t early_s2c_key[MQC_AES_KEY_SZ],
    uint8_t early_c2s_iv [MQC_GCM_IV_SZ],
    uint8_t early_s2c_iv [MQC_GCM_IV_SZ])
{
    uint8_t prk[WC_SHA256_DIGEST_SIZE];
    int ret;

    ret = wc_HKDF_Extract(WC_SHA256,
        transcript_hash_phase1, WC_SHA256_DIGEST_SIZE,
        shared_secret,          WC_ML_KEM_SS_SZ,
        prk);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_EARLY_C2S_KEY,
        (word32)strlen(MQC_HKDF_INFO_EARLY_C2S_KEY),
        early_c2s_key, MQC_AES_KEY_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_EARLY_S2C_KEY,
        (word32)strlen(MQC_HKDF_INFO_EARLY_S2C_KEY),
        early_s2c_key, MQC_AES_KEY_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_EARLY_C2S_IV,
        (word32)strlen(MQC_HKDF_INFO_EARLY_C2S_IV),
        early_c2s_iv, MQC_GCM_IV_SZ);
    if (ret != 0) goto out;

    ret = wc_HKDF_Expand(WC_SHA256, prk, sizeof(prk),
        (const byte *)MQC_HKDF_INFO_EARLY_S2C_IV,
        (word32)strlen(MQC_HKDF_INFO_EARLY_S2C_IV),
        early_s2c_iv, MQC_GCM_IV_SZ);

out:
    mqc_secure_zero(prk, sizeof(prk));
    return ret;
}


/* --- Phase 1 Finished MAC (issue #4) ------------------------------ */

int mqc_compute_finished_mac(
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

int mqc_const_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t r = 0;
    while (n--) r |= *a++ ^ *b++;
    return r == 0;
}

/* --- Socket timeout --- */

void mqc_set_socket_timeout(int fd, int seconds)
{
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void mqc_clear_socket_timeout(int fd)
{
    struct timeval tv = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* --- Redis rate limiting --- */

static redisContext *s_redis = NULL;

/* Cross-fork "Redis-down since when" state.
 *
 * The MQC server forks per-accept, so process-local state can't tell
 * a child "Redis has been down for K seconds across the last M
 * connections" — each child only sees its own one connect attempt.
 * A tiny tmpfile (default /tmp/postWolf-mqc-redis-down, override via
 * config knob mqc-rl-redis-state-path) gives us shared state with
 * zero fork-time setup: each child reads on Redis-down, the first
 * child writes "now", siblings read it; whichever child sees Redis
 * back up unlinks it.  Writes race benignly — values converge within
 * a few seconds and the policy decision tolerates jitter on that
 * scale.  Used by mqc_redis_down_decide() below. */

typedef enum {
    MQC_REDIS_DECISION_OPEN,
    MQC_REDIS_DECISION_CLOSED
} mqc_redis_decision_t;

static time_t mqc_redis_get_down_since(void)
{
    FILE *f = fopen(mqc_rt_cfg()->redis_state_path, "r");
    long ts = 0;
    if (!f) return 0;
    if (fscanf(f, "%ld", &ts) != 1) ts = 0;
    fclose(f);
    return (time_t)ts;
}

static void mqc_redis_mark_down(void)
{
    FILE *f;
    if (mqc_redis_get_down_since() != 0) return;  /* already marked */
    f = fopen(mqc_rt_cfg()->redis_state_path, "w");
    if (!f) return;                                /* best effort */
    fprintf(f, "%ld\n", (long)time(NULL));
    fclose(f);
}

static void mqc_redis_mark_up(void)
{
    /* Idempotent and racy on purpose: an unlink of a missing path
     * is a cheap ENOENT, and concurrent unlinks all converge. */
    unlink(mqc_rt_cfg()->redis_state_path);
}

/* Caller has already determined Redis is unreachable for this
 * request.  Returns the policy decision and (if @p out_dt is non-
 * NULL) the seconds-since-first-down value the caller can include
 * in its log line. */
static mqc_redis_decision_t mqc_redis_down_decide(time_t *out_dt)
{
    int p = mqc_rt_cfg()->redis_fail_policy;
    time_t down_since;
    time_t dt;

    mqc_redis_mark_down();
    down_since = mqc_redis_get_down_since();
    dt = down_since ? (time(NULL) - down_since) : 0;
    if (dt < 0) dt = 0;                            /* clock jump */
    if (out_dt) *out_dt = dt;

    if (p == MQC_REDIS_FAIL_POLICY_OPEN)
        return MQC_REDIS_DECISION_OPEN;
    if (p == MQC_REDIS_FAIL_POLICY_CLOSED)
        return MQC_REDIS_DECISION_CLOSED;
    /* CLOSED_AFTER */
    return (dt < mqc_rt_cfg()->redis_fail_closed_after_sec)
        ? MQC_REDIS_DECISION_OPEN
        : MQC_REDIS_DECISION_CLOSED;
}

void mqc_redis_init(void)
{
    struct timeval timeout = { 1, 0 };
    if (s_redis) return;  /* already connected */

    s_redis = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (!s_redis || s_redis->err) {
        /* Promoted from MQC_LOG to MQC_SECURITY: every gate that
         * relies on Redis (per-IP RL, per-IP fail RL, per-(IP,
         * cert) RL, fail-recording) silently fails OPEN when
         * Redis is unreachable.  Operators need to see this in
         * the journal — without it, an attacker who DoSes Redis
         * disables rate limiting invisibly. */
        MQC_SECURITY("REDIS_DOWN: connect failed: %s — every "
                     "rate-limit gate is now FAIL-OPEN until Redis "
                     "comes back",
                     s_redis ? s_redis->errstr : "NULL context");
        if (s_redis) { redisFree(s_redis); s_redis = NULL; }
    } else {
        MQC_LOG("Redis connected for rate limiting");
    }
}

int mqc_redis_incr(const char *key, int ttl_secs)
{
    redisReply *reply;
    int count;

    if (!s_redis) return 0;

    reply = redisCommand(s_redis, "INCR %s", key);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        /* Promoted from MQC_LOG: an in-flight INCR failure is
         * a Redis-side problem (server crash mid-pipeline,
         * connection reset).  Caller treats the 0 return as
         * "no count" → its rate-limit comparison can never
         * exceed the threshold → fail-open.  Operators need
         * the loud line. */
        MQC_SECURITY("RL_FAIL_OPEN: Redis INCR failed for key=%s "
                     "— gate is fail-open for this request", key);
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
int mqc_ratelimit_check(const char *ip)
{
    char key[128];
    int count_m, count_h;

    {
        long _t = mqc_now_ms();
        mqc_redis_init();
        if (s_mqc_time_enabled)
            fprintf(stderr, "[MQC-TIME]   redis_init = %ld ms\n",
                    mqc_now_ms() - _t);
    }
    if (!s_redis) {
        time_t dt;
        if (mqc_redis_down_decide(&dt) == MQC_REDIS_DECISION_CLOSED) {
            MQC_SECURITY("RL_FAIL_CLOSED: per-IP connect-rate gate "
                         "enforced, Redis down %lds (ip=%s) — "
                         "rejecting connection per "
                         "mqc-rl-redis-fail-policy",
                         (long)dt, ip);
            return -1;
        }
        MQC_SECURITY("RL_FAIL_OPEN: per-IP connect-rate gate disabled, "
                     "Redis down %lds (ip=%s)", (long)dt, ip);
        return 0;
    }
    mqc_redis_mark_up();

    /* Per-minute */
    snprintf(key, sizeof(key), "mqc:%s:conn:m", ip);
    {
        long _t = mqc_now_ms();
        count_m = mqc_redis_incr(key, 60);
        if (s_mqc_time_enabled)
            fprintf(stderr, "[MQC-TIME]   redis_incr_m = %ld ms\n",
                    mqc_now_ms() - _t);
    }

    /* Per-hour */
    snprintf(key, sizeof(key), "mqc:%s:conn:h", ip);
    {
        long _t = mqc_now_ms();
        count_h = mqc_redis_incr(key, 3600);
        if (s_mqc_time_enabled)
            fprintf(stderr, "[MQC-TIME]   redis_incr_h = %ld ms\n",
                    mqc_now_ms() - _t);
    }

    {
        long _t = mqc_now_ms();
        const struct mqc_runtime_cfg *cfg = mqc_rt_cfg();
        if (s_mqc_time_enabled)
            fprintf(stderr, "[MQC-TIME]   rt_cfg = %ld ms\n",
                    mqc_now_ms() - _t);
        (void)cfg;
    }

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
int mqc_ratelimit_fail_check(const char *ip)
{
    char key[128];
    redisReply *reply;
    int count_m = 0, count_h = 0;

    if (!s_redis) {
        time_t dt;
        if (mqc_redis_down_decide(&dt) == MQC_REDIS_DECISION_CLOSED) {
            MQC_SECURITY("RL_FAIL_CLOSED: per-IP fail-rate gate "
                         "enforced, Redis down %lds (ip=%s) — "
                         "rejecting connection",
                         (long)dt, ip);
            return -1;
        }
        MQC_SECURITY("RL_FAIL_OPEN: per-IP fail-rate gate disabled, "
                     "Redis down %lds (ip=%s)", (long)dt, ip);
        return 0;
    }

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
void mqc_ratelimit_fail_record(const char *ip)
{
    char key[128];

    if (!s_redis) {
        /* Recording side has nothing to fail-closed against — the
         * connection is already failing, we just can't record it.
         * One MQC_SECURITY line is enough; no decide() call. */
        MQC_SECURITY("RL_FAIL_OPEN: failure-recording disabled, "
                     "Redis unreachable (ip=%s) — this handshake "
                     "failure will NOT count toward future fail-rate "
                     "checks, even after Redis comes back", ip);
        return;
    }

    snprintf(key, sizeof(key), "mqc:%s:fail:m", ip);
    mqc_redis_incr(key, 60);

    snprintf(key, sizeof(key), "mqc:%s:fail:h", ip);
    mqc_redis_incr(key, 3600);

    MQC_SECURITY("handshake failure recorded for %s", ip);
}

/* --- Per-IP distinct-cert_index rate limit (issue #12) ----------------
 * Inside the per-IP connection budget, an attacker that rotates
 * cert_index every connect forces a fresh certificate fetch + Merkle
 * inclusion + cosignature verify per attempt -- ~ms of asymmetric
 * work per cheap client byte.  This pair of buckets caps how many
 * DISTINCT cert_index values a single source IP can present per
 * minute / per hour.
 *
 * Implementation note: a SET keyed by IP with cert_index values as
 * members lets SCARD give us the exact distinct-count.  Per-(IP,
 * cert_index) counters would only catch repeated hits on the SAME
 * index -- not what we want here. */
int mqc_redis_sadd_count(const char *key, int cert_index, int ttl_secs)
{
    redisReply *reply;
    int count = 0;

    if (!s_redis) return 0;

    reply = redisCommand(s_redis, "SADD %s %d", key, cert_index);
    if (!reply) return 0;
    freeReplyObject(reply);

    reply = redisCommand(s_redis, "EXPIRE %s %d", key, ttl_secs);
    if (reply) freeReplyObject(reply);

    reply = redisCommand(s_redis, "SCARD %s", key);
    if (!reply) return 0;
    if (reply->type == REDIS_REPLY_INTEGER)
        count = (int)reply->integer;
    freeReplyObject(reply);
    return count;
}

int mqc_ratelimit_cert_check(const char *ip, int cert_index)
{
    char key[160];
    int count_m, count_h;

    if (!s_redis) {
        time_t dt;
        if (mqc_redis_down_decide(&dt) == MQC_REDIS_DECISION_CLOSED) {
            MQC_SECURITY("RL_FAIL_CLOSED: per-(IP, cert) gate "
                         "enforced, Redis down %lds (ip=%s cert=%d) "
                         "— rejecting connection",
                         (long)dt, ip, cert_index);
            return -1;
        }
        MQC_SECURITY("RL_FAIL_OPEN: per-(IP, cert) gate disabled, "
                     "Redis down %lds (ip=%s cert=%d)",
                     (long)dt, ip, cert_index);
        return 0;
    }

    snprintf(key, sizeof(key), "mqc:%s:cert:m", ip);
    count_m = mqc_redis_sadd_count(key, cert_index, 60);
    snprintf(key, sizeof(key), "mqc:%s:cert:h", ip);
    count_h = mqc_redis_sadd_count(key, cert_index, 3600);

    if (count_m > mqc_rt_cfg()->rl_cert_per_min) {
        MQC_SECURITY("CERT_RATE_LIMITED: %s distinct cert_index "
                     "%d/min (max %ld); last cert_index=%d",
                     ip, count_m, mqc_rt_cfg()->rl_cert_per_min,
                     cert_index);
        return -1;
    }
    if (count_h > mqc_rt_cfg()->rl_cert_per_hour) {
        MQC_SECURITY("CERT_RATE_LIMITED: %s distinct cert_index "
                     "%d/hr (max %ld); last cert_index=%d",
                     ip, count_h, mqc_rt_cfg()->rl_cert_per_hour,
                     cert_index);
        return -1;
    }
    return 0;
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
int mqc_abuse_check(const char *ip)
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
        mqc_secure_zero(der, (unsigned int)der_sz);
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
    free(ctx->expected_name);
    if (ctx->privkey_der) {
        mqc_secure_zero(ctx->privkey_der, (unsigned int)ctx->privkey_der_sz);
        free(ctx->privkey_der);
    }
    free(ctx);
}

void mqc_ctx_set_expected_name(mqc_ctx_t *ctx, const char *hostname)
{
    if (!ctx) return;
    free(ctx->expected_name);
    ctx->expected_name = hostname ? strdup(hostname) : NULL;
}

void mqc_ctx_disable_name_check(mqc_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->expected_name);
    ctx->expected_name = strdup("");  /* sentinel: explicitly disabled */
}

/* --- Handshake --- */


/* --- Encrypted-identity handshake helpers --- */

int mqc_enc_send(int fd,
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
    mqc_make_nonce(iv, *seq, nonce);
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
    if (mqc_write_all(fd, (unsigned char *)&net_len, 4) != 0 ||
        mqc_write_all(fd, ct, (unsigned int)data_sz) != 0 ||
        mqc_write_all(fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct); return -1;
    }
    free(ct);
    return 0;
}

int mqc_enc_recv(int fd,
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

    if (mqc_read_all(fd, (unsigned char *)&net_len, 4) != 0) return -1;
    total_len = ntohl(net_len);
    if (total_len < MQC_GCM_TAG_SZ ||
        total_len > (uint32_t)mqc_rt_cfg()->max_msg_bytes) return -1;
    ct_sz = (int)(total_len - MQC_GCM_TAG_SZ);
    if (ct_sz > bufsz) return -1;

    ct = malloc((size_t)ct_sz);
    if (!ct) return -1;
    if (mqc_read_all(fd, ct, (unsigned int)ct_sz) != 0 ||
        mqc_read_all(fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct); return -1;
    }
    /* Spec §9.2: increment recv_seq ONLY on successful AEAD verify
     * (mqc-2 master plan Phase 3 / second-review issue #7 /
     * mqc-4 highest-priority fix #6).  Today the connection is
     * torn down on any verify failure so the off-by-one nonce
     * never gets reused, but spec wording matters and a future
     * refactor that tries to keep the connection alive across an
     * auth failure would otherwise reopen this as a real
     * (key, nonce) collision.  Failure logs now name the actually-
     * failing sequence number, not the post-increment value. */
    mqc_make_nonce(iv, *seq, nonce);
    mqc_build_aad(aad, direction, frame_type, *seq, (uint32_t)ct_sz);
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
                     (unsigned long)(*seq));
        return -1;
    }
    (*seq)++;
    return ct_sz;
}

/* Finished helpers — prototyped in mqc_internal.h so the handshake
 * bodies in mqc_clear.c / mqc_encrypted.c can call them. */
int mqc_send_finished(struct mqc_conn *conn)
{
    uint8_t mac[MQC_FINISHED_MAC_SZ];
    uint8_t direction;
    int ret;
    if (!conn) return -1;
    ret = mqc_compute_finished_mac(conn->send_finished_key,
                                   conn->transcript_hash_full, mac);
    if (ret != 0) return ret;
    direction = conn->is_client ? MQC_DIR_C2S : MQC_DIR_S2C;
    ret = mqc_enc_send(conn->fd, conn->send_key, conn->send_iv,
                   &conn->send_seq,
                   direction, MQC_FRAME_TYPE_FINISHED,
                   mac, MQC_FINISHED_MAC_SZ);
    mqc_secure_zero(mac, sizeof(mac));
    mqc_secure_zero(conn->send_finished_key, sizeof(conn->send_finished_key));
    return ret;
}
int mqc_recv_finished(struct mqc_conn *conn)
{
    uint8_t got_mac[MQC_FINISHED_MAC_SZ];
    uint8_t expected_mac[MQC_FINISHED_MAC_SZ];
    uint8_t direction;
    int n, ret;
    if (!conn) return -1;
    direction = conn->is_client ? MQC_DIR_S2C : MQC_DIR_C2S;
    n = mqc_enc_recv(conn->fd, conn->recv_key, conn->recv_iv,
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
        mqc_secure_zero(got_mac, sizeof(got_mac));
        mqc_secure_zero(expected_mac, sizeof(expected_mac));
        return -1;
    }
    conn->finished_verified = 1;
    mqc_secure_zero(got_mac, sizeof(got_mac));
    mqc_secure_zero(expected_mac, sizeof(expected_mac));
    mqc_secure_zero(conn->recv_finished_key, sizeof(conn->recv_finished_key));
    return 0;
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

    mqc_make_nonce(conn->send_iv, conn->send_seq, nonce);
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
    if (mqc_write_all(conn->fd, (unsigned char *)&net_len, 4) != 0 ||
        mqc_write_all(conn->fd, ct, (unsigned int)sz) != 0 ||
        mqc_write_all(conn->fd, tag, MQC_GCM_TAG_SZ) != 0) {
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
    if (mqc_read_all(conn->fd, (unsigned char *)&net_len, 4) != 0)
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
    if (mqc_read_all(conn->fd, ct, (unsigned int)ct_sz) != 0 ||
        mqc_read_all(conn->fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct);
        return -1;
    }

    /* See the matching comment in mqc_enc_recv: spec §9.2 says
     * recv_seq increments only on successful AEAD verify
     * (mqc-2 P3 / second-review #7 / mqc-4 fix #6). */
    mqc_make_nonce(conn->recv_iv, conn->recv_seq, nonce);
    /* Receiver's AAD direction is the *peer's* direction. */
    direction = conn->is_client ? MQC_DIR_S2C : MQC_DIR_C2S;
    mqc_build_aad(aad, direction, MQC_FRAME_TYPE_APP_DATA,
                  conn->recv_seq, (uint32_t)ct_sz);

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
                     conn->peer_index, (unsigned long)conn->recv_seq);
        return -1;
    }

    conn->recv_seq++;
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
    mqc_secure_zero(conn->send_key, MQC_AES_KEY_SZ);
    mqc_secure_zero(conn->recv_key, MQC_AES_KEY_SZ);
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
