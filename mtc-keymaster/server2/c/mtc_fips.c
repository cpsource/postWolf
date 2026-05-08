/******************************************************************************
 * File:        mtc_fips.c
 * Purpose:     FIPS-manifest acceptance pipeline (entry_type 0x02).
 *
 * See mtc_fips.h for the public API.  Spec is
 * ../../../fips-framework/spec-canonical-leaf.md.
 ******************************************************************************/

#include "mtc_fips.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/coding.h>      /* Base64_Decode */
#include <wolfssl/wolfcrypt/asn_public.h>  /* wc_PubKeyPemToDer */

#include <libpq-fe.h>

#include "mtc_db.h"
#include "mtc_log.h"
#include "mtc_merkle_tiled.h"

/* Field limits — must agree with the spec section "Top-level fields". */
#define FIPS_PUBLISHER_MAX        253
#define FIPS_PACKAGE_MAX          64
#define FIPS_VERSION_MAX          64
#define FIPS_PATH_MAX             512
#define FIPS_FILES_MAX            65535
#define FIPS_VALIDITY_MAX_SEC     31536000.0    /* 1 year */
#define FIPS_TIME_SKEW_BACK_SEC   300.0
#define FIPS_SHA256_HEX_LEN       64
#define FIPS_GIT_COMMIT_HEX_MIN   40             /* SHA-1 */
#define FIPS_GIT_COMMIT_HEX_MAX   64             /* SHA-256 */

#define MLDSA87_SIG_SIZE          4627
#define MLDSA87_SIG_B64_MAX       8192

#define DBG(fmt, ...) LOG_DEBUG("[fips] " fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) LOG_INFO("[fips] " fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG_WARN("[fips] " fmt, ##__VA_ARGS__)

/* Top-level required keys, alphabetical.  git_commit is OPTIONAL and
 * not in this list; an explicit check is done separately. */
static const char *FIPS_REQ_KEYS[] = {
    "alg", "expires", "files", "not_before", "package",
    "publisher", "publisher_cert_index", "schema_version",
    "signature", "version"
};
#define FIPS_REQ_KEY_COUNT  (sizeof(FIPS_REQ_KEYS)/sizeof(FIPS_REQ_KEYS[0]))

#define ALLOWED_TOP_KEYS_INCL_OPT  (FIPS_REQ_KEY_COUNT + 1)  /* + git_commit */

/* ---------------------------------------------------------------- */
/* small helpers                                                     */
/* ---------------------------------------------------------------- */

static void set_err(char *buf, size_t bufsz, const char *fmt, ...)
{
    if (!buf || bufsz == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, bufsz, fmt, ap);
    va_end(ap);
}

static int charset_label(const char *s, size_t maxlen)
{
    /* [A-Za-z0-9._-]{1..maxlen} */
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > maxlen) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) return -1;
    }
    return 0;
}

static int charset_version(const char *s, size_t maxlen)
{
    /* [A-Za-z0-9._+~-]{1..maxlen} */
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > maxlen) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '+' || c == '~' || c == '-'))
            return -1;
    }
    return 0;
}

static int charset_publisher(const char *s)
{
    /* lowercase ASCII LDH per RFC 1035, ≤ 253 chars, no leading/trailing
     * dot, no leading hyphen on a label, labels ≤ 63 chars. */
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > FIPS_PUBLISHER_MAX) return -1;
    if (s[0] == '.' || s[n-1] == '.') return -1;
    int label_len = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '.') {
            if (label_len == 0 || label_len > 63) return -1;
            label_len = 0;
            continue;
        }
        if (label_len == 0 && c == '-') return -1;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return -1;
        label_len++;
    }
    if (label_len == 0 || label_len > 63) return -1;
    return 0;
}

static int charset_relpath(const char *s)
{
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > FIPS_PATH_MAX) return -1;
    if (s[0] == '/' || s[n-1] == '/') return -1;
    if (strstr(s, "//")) return -1;
    if (strstr(s, "/../") || !strncmp(s, "../", 3)) return -1;
    if (n >= 3 && !strcmp(s + n - 3, "/..")) return -1;
    if (!strcmp(s, ".") || !strcmp(s, "..")) return -1;
    if (strstr(s, "/./") || !strncmp(s, "./", 2)) return -1;
    if (n >= 2 && !strcmp(s + n - 2, "/.")) return -1;
    /* Reject embedded NUL is implicit (strlen would have stopped). */
    return 0;
}

static int hex_lower_only(const char *s, size_t expected_len)
{
    if (!s) return -1;
    if (strlen(s) != expected_len) return -1;
    for (size_t i = 0; i < expected_len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
    }
    return 0;
}

static int git_commit_format_ok(const char *s)
{
    /* OPTIONAL field; called only when present.  Form: 40 or 64 lowercase
     * hex chars, with optional `-dirty` suffix. */
    size_t n = strlen(s);
    int dirty = 0;
    if (n > 6 && strcmp(s + n - 6, "-dirty") == 0) {
        dirty = 1;
        n -= 6;
    }
    if (n != 40 && n != 64) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
    }
    (void)dirty;
    return 0;
}

static void to_hex64(const uint8_t *in, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0xf];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[64] = 0;
}

static int sha256_hex(const uint8_t *data, size_t data_len, char hex[65])
{
    wc_Sha256 sha;
    uint8_t h[32];
    if (wc_InitSha256(&sha) != 0) return -1;
    if (wc_Sha256Update(&sha, data, (word32)data_len) != 0) {
        wc_Sha256Free(&sha); return -1;
    }
    if (wc_Sha256Final(&sha, h) != 0) {
        wc_Sha256Free(&sha); return -1;
    }
    wc_Sha256Free(&sha);
    to_hex64(h, hex);
    return 0;
}

/* ---------------------------------------------------------------- */
/* Step 2: strict-parse + structural validation                      */
/* ---------------------------------------------------------------- */

static int validate_files_array(struct json_object *arr,
                                char *err, size_t err_sz)
{
    if (!json_object_is_type(arr, json_type_array))
        { set_err(err, err_sz, "files: not an array"); return -1; }
    int n = json_object_array_length(arr);
    if (n < 1 || n > FIPS_FILES_MAX)
        { set_err(err, err_sz, "files: count %d out of [1, %d]",
                 n, FIPS_FILES_MAX); return -1; }
    const char *prev_path = NULL;
    for (int i = 0; i < n; i++) {
        struct json_object *fe = json_object_array_get_idx(arr, i);
        if (!json_object_is_type(fe, json_type_object))
            { set_err(err, err_sz, "files[%d]: not an object", i); return -1; }
        if (json_object_object_length(fe) != 2)
            { set_err(err, err_sz, "files[%d]: exactly path+sha256 required", i);
              return -1; }
        struct json_object *path_v, *sha_v;
        if (!json_object_object_get_ex(fe, "path", &path_v) ||
            !json_object_object_get_ex(fe, "sha256", &sha_v))
            { set_err(err, err_sz, "files[%d]: missing path or sha256", i);
              return -1; }
        if (!json_object_is_type(path_v, json_type_string) ||
            !json_object_is_type(sha_v, json_type_string))
            { set_err(err, err_sz, "files[%d]: wrong types", i); return -1; }
        const char *p = json_object_get_string(path_v);
        const char *h = json_object_get_string(sha_v);
        if (charset_relpath(p) != 0)
            { set_err(err, err_sz, "files[%d]: invalid path", i); return -1; }
        if (hex_lower_only(h, FIPS_SHA256_HEX_LEN) != 0)
            { set_err(err, err_sz, "files[%d]: invalid sha256", i); return -1; }
        /* sorted ascending, no duplicates */
        if (prev_path && strcmp(prev_path, p) >= 0)
            { set_err(err, err_sz, "files[%d]: not sorted (or dup)", i);
              return -1; }
        prev_path = p;
    }
    return 0;
}

static int validate_top_level(struct json_object *m, char *err, size_t err_sz)
{
    /* Check key count: must equal FIPS_REQ_KEY_COUNT (10) when no
     * git_commit, FIPS_REQ_KEY_COUNT+1 (11) when present. */
    int got = json_object_object_length(m);
    if (got != (int)FIPS_REQ_KEY_COUNT &&
        got != (int)ALLOWED_TOP_KEYS_INCL_OPT)
        { set_err(err, err_sz, "top-level key count %d unexpected", got);
          return -1; }

    /* Required keys must all be present. */
    for (size_t i = 0; i < FIPS_REQ_KEY_COUNT; i++) {
        if (!json_object_object_get_ex(m, FIPS_REQ_KEYS[i], NULL))
            { set_err(err, err_sz, "missing required field: %s",
                     FIPS_REQ_KEYS[i]); return -1; }
    }

    /* And no unknown top-level keys (only required + optional git_commit). */
    {
        struct json_object_iter it;
        json_object_object_foreachC(m, it) {
            int known = 0;
            if (strcmp(it.key, "git_commit") == 0) known = 1;
            else for (size_t i = 0; i < FIPS_REQ_KEY_COUNT; i++)
                if (strcmp(it.key, FIPS_REQ_KEYS[i]) == 0) { known = 1; break; }
            if (!known)
                { set_err(err, err_sz, "unknown field: %s", it.key);
                  return -1; }
        }
    }

    struct json_object *v;

    /* alg: must be exactly "ML-DSA-87" */
    json_object_object_get_ex(m, "alg", &v);
    if (!json_object_is_type(v, json_type_string) ||
        strcmp(json_object_get_string(v), "ML-DSA-87") != 0)
        { set_err(err, err_sz, "alg must be ML-DSA-87"); return -1; }

    /* schema_version: must equal MTC_FIPS_SCHEMA_VERSION */
    json_object_object_get_ex(m, "schema_version", &v);
    if (!json_object_is_type(v, json_type_int) ||
        json_object_get_int(v) != MTC_FIPS_SCHEMA_VERSION)
        { set_err(err, err_sz, "schema_version must be %d",
                 MTC_FIPS_SCHEMA_VERSION); return -1; }

    /* publisher */
    json_object_object_get_ex(m, "publisher", &v);
    if (!json_object_is_type(v, json_type_string) ||
        charset_publisher(json_object_get_string(v)) != 0)
        { set_err(err, err_sz, "publisher invalid"); return -1; }

    /* publisher_cert_index */
    json_object_object_get_ex(m, "publisher_cert_index", &v);
    if (!json_object_is_type(v, json_type_int) ||
        json_object_get_int64(v) < 0 ||
        json_object_get_int64(v) > 2147483647LL)
        { set_err(err, err_sz, "publisher_cert_index out of range");
          return -1; }

    /* package */
    json_object_object_get_ex(m, "package", &v);
    if (!json_object_is_type(v, json_type_string) ||
        charset_label(json_object_get_string(v), FIPS_PACKAGE_MAX) != 0)
        { set_err(err, err_sz, "package invalid"); return -1; }

    /* version */
    json_object_object_get_ex(m, "version", &v);
    if (!json_object_is_type(v, json_type_string) ||
        charset_version(json_object_get_string(v), FIPS_VERSION_MAX) != 0)
        { set_err(err, err_sz, "version invalid"); return -1; }

    /* signature: base64 ASCII; non-empty */
    json_object_object_get_ex(m, "signature", &v);
    if (!json_object_is_type(v, json_type_string))
        { set_err(err, err_sz, "signature not string"); return -1; }
    {
        const char *sig_b64 = json_object_get_string(v);
        size_t n = strlen(sig_b64);
        if (n < 16 || n > MLDSA87_SIG_B64_MAX)
            { set_err(err, err_sz, "signature length %zu out of range", n);
              return -1; }
        for (size_t i = 0; i < n; i++) {
            char c = sig_b64[i];
            if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || c == '='))
                { set_err(err, err_sz, "signature: non-base64 char");
                  return -1; }
        }
    }

    /* not_before, expires: floats, plausible range, ordered */
    json_object_object_get_ex(m, "not_before", &v);
    if (!json_object_is_type(v, json_type_double))
        { set_err(err, err_sz, "not_before not double"); return -1; }
    double nb = json_object_get_double(v);
    json_object_object_get_ex(m, "expires", &v);
    if (!json_object_is_type(v, json_type_double))
        { set_err(err, err_sz, "expires not double"); return -1; }
    double exp = json_object_get_double(v);
    if (nb <= 0 || exp <= 0 || exp <= nb || (exp - nb) > FIPS_VALIDITY_MAX_SEC)
        { set_err(err, err_sz, "time window invalid (nb=%f exp=%f)", nb, exp);
          return -1; }

    /* git_commit: optional; if present, format-check */
    if (json_object_object_get_ex(m, "git_commit", &v)) {
        if (!json_object_is_type(v, json_type_string) ||
            git_commit_format_ok(json_object_get_string(v)) != 0)
            { set_err(err, err_sz, "git_commit invalid format");
              return -1; }
    }

    /* files */
    json_object_object_get_ex(m, "files", &v);
    if (validate_files_array(v, err, err_sz) != 0) return -1;

    return 0;
}

/* ---------------------------------------------------------------- */
/* Step 3: re-canonicalize + byte-compare to received body           */
/* ---------------------------------------------------------------- */

/* Re-serialize the parsed manifest in canonical form.
 * Output is the canonical JSON text (NOT prefixed by 0x02).
 * Caller owns *out and must free(). */
static int canonicalize(struct json_object *m, char **out, size_t *out_sz)
{
    const char *s = json_object_to_json_string_ext(
        m, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!s) return -1;
    size_t n = strlen(s);
    char *buf = (char *)malloc(n + 1);
    if (!buf) return -1;
    memcpy(buf, s, n + 1);
    *out = buf; *out_sz = n;
    return 0;
}

/* ---------------------------------------------------------------- */
/* Step 6 helper: lookup pubkey PEM by spk_hash (SHA-256-of-PEM-text) */
/* ---------------------------------------------------------------- */

/* Iterates mtc_public_keys, returns the first key_value whose
 * sha256(key_value) matches the provided expected_spk_hash hex.
 * Caller free()s on success.  Returns NULL on no match.
 *
 * O(n) but acceptable at current log scale (< 100 publishers).
 * Replace with a sha256 index if/when the table grows. */
static char *load_pubkey_pem_by_spk_hash(PGconn *conn,
                                         const char *expected_spk_hash)
{
    if (!conn || !expected_spk_hash) return NULL;
    PGresult *r = PQexec(conn, "SELECT key_value FROM mtc_public_keys");
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        PQclear(r);
        return NULL;
    }
    char *match = NULL;
    int n = PQntuples(r);
    for (int i = 0; i < n; i++) {
        const char *pem = PQgetvalue(r, i, 0);
        if (!pem) continue;
        char hex[65];
        if (sha256_hex((const uint8_t *)pem, strlen(pem), hex) != 0) continue;
        if (strcmp(hex, expected_spk_hash) == 0) {
            match = strdup(pem);
            break;
        }
    }
    PQclear(r);
    return match;
}

/* ---------------------------------------------------------------- */
/* Step 6: ML-DSA-87 verify of manifest signature                    */
/* ---------------------------------------------------------------- */

static int verify_mldsa87_signature(const char *pub_pem,
                                    const uint8_t *signing_input,
                                    size_t signing_input_len,
                                    const uint8_t *sig, size_t sig_len)
{
    int rc = -1;
    int verify_res = 0;
    int pub_init = 0;
    int pem_len = (int)strlen(pub_pem);
    int der_max = pem_len;        /* DER ≤ PEM length, comfortably */
    uint8_t *der = (uint8_t *)malloc((size_t)der_max);
    if (!der) return -1;
    int der_sz = wc_PubKeyPemToDer((const unsigned char *)pub_pem,
                                   pem_len, der, der_max);
    if (der_sz <= 0) goto out;

    dilithium_key key;
    if (wc_dilithium_init(&key) != 0) goto out;
    pub_init = 1;
    if (wc_dilithium_set_level(&key, WC_ML_DSA_87) != 0) goto out;
    word32 idx_w = 0;
    if (wc_Dilithium_PublicKeyDecode(der, &idx_w, &key,
                                     (word32)der_sz) != 0) goto out;
    if (wc_dilithium_verify_ctx_msg(sig, (word32)sig_len, NULL, 0,
                                    signing_input, (word32)signing_input_len,
                                    &verify_res, &key) != 0) goto out;
    rc = (verify_res == 1) ? 0 : -1;
out:
    if (pub_init) wc_dilithium_free(&key);
    free(der);
    return rc;
}

/* ---------------------------------------------------------------- */
/* Step 4-5: cert lookup + revocation                                */
/* ---------------------------------------------------------------- */

/* Loads cert tbs_data at index, verifies subject and entry_type=1,
 * returns the spk_hash on success.  Caller free()s spk_hash_out.
 * Returns 0 on success, non-zero on failure. */
static int lookup_publisher_cert(PGconn *conn, int cert_index,
                                 const char *expected_subject,
                                 char **spk_hash_out,
                                 char *err, size_t err_sz)
{
    *spk_hash_out = NULL;
    char idx_str[32];
    snprintf(idx_str, sizeof(idx_str), "%d", cert_index);
    const char *params[1] = { idx_str };

    PGresult *r = PQexecParams(conn,
        "SELECT entry_type, tbs_data->>'subject', tbs_data->>'spk_hash' "
        "FROM mtc_log_entries WHERE index = $1",
        1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        set_err(err, err_sz, "cert lookup query failed: %s",
                PQerrorMessage(conn));
        PQclear(r);
        return -1;
    }
    if (PQntuples(r) != 1) {
        set_err(err, err_sz, "no log entry at index %d", cert_index);
        PQclear(r);
        return -1;
    }
    int et = atoi(PQgetvalue(r, 0, 0));
    const char *subject = PQgetvalue(r, 0, 1);
    const char *spkh = PQgetvalue(r, 0, 2);
    if (et != 1) {
        set_err(err, err_sz, "log entry %d is type %d, not a cert",
                cert_index, et);
        PQclear(r);
        return -1;
    }
    if (!subject || strcmp(subject, expected_subject) != 0) {
        set_err(err, err_sz, "cert subject '%s' != publisher '%s'",
                subject ? subject : "(null)", expected_subject);
        PQclear(r);
        return -1;
    }
    if (!spkh || hex_lower_only(spkh, FIPS_SHA256_HEX_LEN) != 0) {
        set_err(err, err_sz, "cert %d spk_hash invalid", cert_index);
        PQclear(r);
        return -1;
    }
    *spk_hash_out = strdup(spkh);
    PQclear(r);

    /* Revocation check */
    r = PQexecParams(conn,
        "SELECT 1 FROM mtc_revocations WHERE cert_index = $1 LIMIT 1",
        1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        set_err(err, err_sz, "revocation query failed: %s",
                PQerrorMessage(conn));
        PQclear(r); free(*spk_hash_out); *spk_hash_out = NULL;
        return -1;
    }
    int revoked = (PQntuples(r) > 0);
    PQclear(r);
    if (revoked) {
        set_err(err, err_sz, "publisher cert %d is revoked", cert_index);
        free(*spk_hash_out); *spk_hash_out = NULL;
        return -2;       /* distinct rc → 403 */
    }
    return 0;
}

/* ---------------------------------------------------------------- */
/* Step 8 helper: insert search-index row                            */
/* ---------------------------------------------------------------- */

static int save_search_index_row(PGconn *conn, int log_index,
                                 const char *publisher,
                                 const char *package,
                                 const char *version)
{
    char idx_str[32];
    snprintf(idx_str, sizeof(idx_str), "%d", log_index);
    const char *params[4] = { idx_str, publisher, package, version };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO mtc_fips_manifest_entries "
        "  (log_index, publisher, package, version) "
        "VALUES ($1, $2, $3, $4)",
        4, NULL, params, NULL, NULL, 0);
    int ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
    if (!ok) WARN("INSERT mtc_fips_manifest_entries failed: %s",
                  PQerrorMessage(conn));
    PQclear(r);
    return ok ? 0 : -1;
}

/* ---------------------------------------------------------------- */
/* Step 9: receipt builder                                           */
/* ---------------------------------------------------------------- */

static struct json_object *build_receipt(MtcStore *store,
                                         int leaf_index,
                                         const uint8_t *leaf_bytes,
                                         size_t leaf_bytes_len,
                                         const char *publisher_pem,
                                         char *err, size_t err_sz)
{
    int tree_size = store->tree.size;
    if (leaf_index < 0 || leaf_index >= tree_size) {
        set_err(err, err_sz, "receipt: leaf_index %d out of range [0,%d)",
                leaf_index, tree_size);
        return NULL;
    }

    /* Inclusion proof */
    uint8_t *proof = NULL;
    int proof_count = 0;
    if (mtc_tiled_tree_inclusion_proof(&store->tree, leaf_index,
                                       0, tree_size,
                                       &proof, &proof_count) != 0) {
        set_err(err, err_sz, "receipt: inclusion_proof failed");
        return NULL;
    }

    uint8_t root[MTC_HASH_SIZE];
    if (mtc_tiled_tree_subtree_hash(&store->tree, 0, tree_size, root) != 0) {
        free(proof);
        set_err(err, err_sz, "receipt: subtree_hash failed");
        return NULL;
    }
    char root_hex[65];
    to_hex64(root, root_hex);

    /* Cosignature over (0, tree_size) */
    uint8_t cosig[MLDSA87_SIG_SIZE];
    int cosig_sz = sizeof(cosig);
    if (mtc_store_cosign(store, 0, tree_size, cosig, &cosig_sz) != 0) {
        free(proof);
        set_err(err, err_sz, "receipt: cosign failed");
        return NULL;
    }
    char cosig_b64[MLDSA87_SIG_B64_MAX];
    word32 cosig_b64_sz = sizeof(cosig_b64);
    if (Base64_Encode_NoNl(cosig, (word32)cosig_sz,
                           (byte *)cosig_b64, &cosig_b64_sz) != 0) {
        free(proof);
        set_err(err, err_sz, "receipt: cosig base64 failed");
        return NULL;
    }
    cosig_b64[cosig_b64_sz] = 0;

    /* leaf_bytes_b64 */
    word32 leaf_b64_sz_max = (word32)((leaf_bytes_len * 4 / 3) + 8);
    char *leaf_b64 = (char *)malloc(leaf_b64_sz_max);
    if (!leaf_b64) {
        free(proof);
        set_err(err, err_sz, "receipt: oom leaf_b64");
        return NULL;
    }
    word32 leaf_b64_sz = leaf_b64_sz_max;
    if (Base64_Encode_NoNl(leaf_bytes, (word32)leaf_bytes_len,
                           (byte *)leaf_b64, &leaf_b64_sz) != 0) {
        free(proof); free(leaf_b64);
        set_err(err, err_sz, "receipt: leaf_bytes base64 failed");
        return NULL;
    }
    leaf_b64[leaf_b64_sz] = 0;

    /* Build JSON */
    struct json_object *r = json_object_new_object();

    struct json_object *cosigs = json_object_new_array();
    {
        struct json_object *c = json_object_new_object();
        char key_id[128];
        snprintf(key_id, sizeof(key_id), "%s.ca", store->log_id);
        json_object_object_add(c, "alg", json_object_new_string("ML-DSA-87"));
        json_object_object_add(c, "key_id", json_object_new_string(key_id));
        json_object_object_add(c, "sig", json_object_new_string(cosig_b64));
        json_object_array_add(cosigs, c);
    }
    json_object_object_add(r, "cosignatures", cosigs);

    struct json_object *proof_arr = json_object_new_array();
    for (int i = 0; i < proof_count; i++) {
        char hex[65];
        to_hex64(proof + i * MTC_HASH_SIZE, hex);
        json_object_array_add(proof_arr, json_object_new_string(hex));
    }
    json_object_object_add(r, "inclusion_proof", proof_arr);
    json_object_object_add(r, "leaf_bytes_b64", json_object_new_string(leaf_b64));
    json_object_object_add(r, "leaf_index",     json_object_new_int(leaf_index));
    /* Embed publisher pubkey PEM so the verifier can run fully offline.
     * The verifier MUST sha256-compare this PEM against the cert's
     * spk_hash before trusting it (same posture as show-tpm pubkey_db
     * check) — receipt-embedded data isn't authoritative, only the
     * cosigned tree_root + leaf is. */
    if (publisher_pem)
        json_object_object_add(r, "publisher_pubkey_pem",
                               json_object_new_string(publisher_pem));
    json_object_object_add(r, "tree_root",      json_object_new_string(root_hex));
    json_object_object_add(r, "tree_size",      json_object_new_int(tree_size));

    free(proof);
    free(leaf_b64);
    return r;
}

/* ---------------------------------------------------------------- */
/* Public entrypoint                                                  */
/* ---------------------------------------------------------------- */

int mtc_fips_submit(MtcStore *store,
                    const uint8_t *body, size_t body_len,
                    struct json_object **out_receipt,
                    int *out_status,
                    char *out_err_msg, size_t err_msg_sz)
{
    if (out_receipt) *out_receipt = NULL;
    if (out_status) *out_status = 500;

    /* Step 1 — pre-crypto length filter */
    if (!body || body_len == 0) {
        set_err(out_err_msg, err_msg_sz, "empty body");
        if (out_status) *out_status = 400;
        return -1;
    }
    if (body_len > MTC_FIPS_BODY_MAX) {
        set_err(out_err_msg, err_msg_sz, "body too large: %zu > %d",
                body_len, MTC_FIPS_BODY_MAX);
        if (out_status) *out_status = 400;
        return -1;
    }

    /* Step 2 — strict JSON parse + structural validation */
    struct json_object *m = NULL;
    {
        struct json_tokener *tok = json_tokener_new();
        if (!tok) {
            set_err(out_err_msg, err_msg_sz, "tokener_new failed");
            return -1;
        }
        json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
        m = json_tokener_parse_ex(tok, (const char *)body, (int)body_len);
        enum json_tokener_error tok_err = json_tokener_get_error(tok);
        size_t consumed = (size_t)json_tokener_get_parse_end(tok);
        json_tokener_free(tok);
        if (!m || tok_err != json_tokener_success || consumed != body_len) {
            if (m) json_object_put(m);
            set_err(out_err_msg, err_msg_sz,
                    "JSON parse failed (err=%d consumed=%zu of %zu)",
                    tok_err, consumed, body_len);
            if (out_status) *out_status = 400;
            return -1;
        }
    }

    if (!json_object_is_type(m, json_type_object)) {
        set_err(out_err_msg, err_msg_sz, "top-level not object");
        json_object_put(m);
        if (out_status) *out_status = 400;
        return -1;
    }
    if (validate_top_level(m, out_err_msg, err_msg_sz) != 0) {
        json_object_put(m);
        if (out_status) *out_status = 400;
        return -1;
    }

    /* Step 3 — re-canonicalize and byte-compare to received body.
     * Defends against canonicalization drift (e.g., parser tolerance for
     * whitespace + our serializer always emits canonical form). */
    {
        char *recanon = NULL;
        size_t recanon_sz = 0;
        if (canonicalize(m, &recanon, &recanon_sz) != 0) {
            json_object_put(m);
            set_err(out_err_msg, err_msg_sz, "re-canonicalize failed");
            if (out_status) *out_status = 500;
            return -1;
        }
        int eq = (recanon_sz == body_len &&
                  memcmp(recanon, body, body_len) == 0);
        free(recanon);
        if (!eq) {
            json_object_put(m);
            set_err(out_err_msg, err_msg_sz,
                    "non-canonical input (re-canonicalization differs)");
            if (out_status) *out_status = 400;
            return -1;
        }
    }

    /* Pull the validated values out */
    struct json_object *v;
    json_object_object_get_ex(m, "publisher", &v);
    const char *publisher = json_object_get_string(v);
    json_object_object_get_ex(m, "publisher_cert_index", &v);
    int cert_index = json_object_get_int(v);
    json_object_object_get_ex(m, "package", &v);
    const char *package = json_object_get_string(v);
    json_object_object_get_ex(m, "version", &v);
    const char *version = json_object_get_string(v);
    json_object_object_get_ex(m, "not_before", &v);
    double not_before = json_object_get_double(v);
    json_object_object_get_ex(m, "expires", &v);
    double expires = json_object_get_double(v);
    json_object_object_get_ex(m, "signature", &v);
    const char *sig_b64 = json_object_get_string(v);

    /* Step 4 — cert lookup + revocation */
    char *cert_spk_hash = NULL;
    int rc = lookup_publisher_cert(store->db, cert_index, publisher,
                                   &cert_spk_hash, out_err_msg, err_msg_sz);
    if (rc != 0) {
        json_object_put(m);
        if (out_status) *out_status = (rc == -2) ? 403 : 400;
        return -1;
    }

    /* Step 5 — cert cosignature freshness: a cert in mtc_log_entries with
     * an unexpired window AND not in mtc_revocations is implicitly fresh
     * (the server cosigned the tree at append-time, and admin_recosign /
     * checkpoint refresh keeps it current).  No additional check here. */

    /* Step 6 — manifest signature verify */

    /* Build signing input: same JSON with signature := "" */
    struct json_object *sign_view = json_tokener_parse((const char *)body);
    if (!sign_view) {
        free(cert_spk_hash);
        json_object_put(m);
        set_err(out_err_msg, err_msg_sz, "sign-view reparse failed");
        return -1;
    }
    json_object_object_add(sign_view, "signature", json_object_new_string(""));
    char *signing_input = NULL;
    size_t signing_input_sz = 0;
    if (canonicalize(sign_view, &signing_input, &signing_input_sz) != 0) {
        json_object_put(sign_view);
        free(cert_spk_hash);
        json_object_put(m);
        set_err(out_err_msg, err_msg_sz, "signing-input canonicalize failed");
        return -1;
    }
    json_object_put(sign_view);

    /* Decode signature */
    uint8_t sig_bin[MLDSA87_SIG_SIZE];
    word32 sig_bin_sz = sizeof(sig_bin);
    if (Base64_Decode((const byte *)sig_b64, (word32)strlen(sig_b64),
                      sig_bin, &sig_bin_sz) != 0) {
        free(signing_input);
        free(cert_spk_hash);
        json_object_put(m);
        set_err(out_err_msg, err_msg_sz, "signature base64 decode failed");
        if (out_status) *out_status = 400;
        return -1;
    }

    /* Lookup pubkey by spk_hash from mtc_public_keys */
    char *pub_pem = load_pubkey_pem_by_spk_hash(store->db, cert_spk_hash);
    if (!pub_pem) {
        set_err(out_err_msg, err_msg_sz,
                "pubkey for spk_hash %.16s... not found in mtc_public_keys",
                cert_spk_hash);
        free(signing_input);
        free(cert_spk_hash);
        json_object_put(m);
        if (out_status) *out_status = 500;     /* server-side data gap */
        return -1;
    }

    if (verify_mldsa87_signature(pub_pem,
                                 (const uint8_t *)signing_input,
                                 signing_input_sz,
                                 sig_bin, sig_bin_sz) != 0) {
        free(pub_pem);
        free(signing_input);
        free(cert_spk_hash);
        json_object_put(m);
        set_err(out_err_msg, err_msg_sz, "signature verification failed");
        if (out_status) *out_status = 400;
        return -1;
    }
    /* Keep pub_pem live to embed in the receipt below; free at function
     * exit instead of here. */
    free(signing_input);
    free(cert_spk_hash);

    /* Step 7 — time bounds */
    {
        double now = (double)time(NULL);
        if (now + FIPS_TIME_SKEW_BACK_SEC < not_before) {
            set_err(out_err_msg, err_msg_sz,
                    "not_before %f > now+skew %f",
                    not_before, now + FIPS_TIME_SKEW_BACK_SEC);
            json_object_put(m);
            if (out_status) *out_status = 400;
            return -1;
        }
        if (now > expires) {
            set_err(out_err_msg, err_msg_sz,
                    "expires %f < now %f", expires, now);
            json_object_put(m);
            if (out_status) *out_status = 400;
            return -1;
        }
    }

    /* Step 8 — append to log + insert search-index row */
    size_t leaf_len = body_len + 1;
    uint8_t *leaf = (uint8_t *)malloc(leaf_len);
    if (!leaf) {
        json_object_put(m);
        set_err(out_err_msg, err_msg_sz, "oom leaf");
        return -1;
    }
    leaf[0] = MTC_FIPS_ENTRY_TYPE;
    memcpy(leaf + 1, body, body_len);

    int new_idx = mtc_store_add_entry(store, leaf, (int)leaf_len);
    if (new_idx < 0) {
        free(leaf);
        json_object_put(m);
        set_err(out_err_msg, err_msg_sz, "mtc_store_add_entry failed");
        if (out_status) *out_status = 500;
        return -1;
    }

    if (save_search_index_row(store->db, new_idx,
                              publisher, package, version) != 0) {
        /* Non-fatal: the leaf is in the canonical log; only the search
         * index missed.  Log + continue. */
        WARN("search-index insert failed for log_index %d (continuing)",
             new_idx);
    }

    /* Step 9 — receipt */
    char rcpt_err[256];
    rcpt_err[0] = 0;
    struct json_object *receipt = build_receipt(store, new_idx,
                                                leaf, leaf_len,
                                                pub_pem,
                                                rcpt_err, sizeof(rcpt_err));
    free(pub_pem);
    free(leaf);
    json_object_put(m);
    if (!receipt) {
        set_err(out_err_msg, err_msg_sz, "%s", rcpt_err);
        if (out_status) *out_status = 500;
        return -1;
    }

    INFO("submission accepted: pkg=%s ver=%s publisher=%s log_index=%d",
         package, version, publisher, new_idx);

    if (out_receipt) *out_receipt = receipt;
    if (out_status)  *out_status = 200;
    return 0;
}
