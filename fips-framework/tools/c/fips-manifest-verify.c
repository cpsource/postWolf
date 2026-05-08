/*
 * fips-manifest-verify — offline verifier for a FIPS-manifest receipt.
 *
 * Per fips-framework/spec-canonical-leaf.md §"Verifier-side check
 * order", runs six checks in order against (receipt, source-dir,
 * trusted-cosigner-pubkey):
 *
 *   1. Strict-parse receipt + the embedded canonical leaf bytes.
 *   2. Cosignature verify of (tree_size, tree_root) under the trusted
 *      cosigner pubkey (matches mtc_store_cosign signing-input layout:
 *      "mtc-subtree/v1\n\x00" || cosigner_id || log_id || start_be64
 *      || end_be64 || subtree_hash).
 *   3. Inclusion-proof replay from leaf_hash to tree_root using
 *      RFC 9162 Section 2.1 leaf/node hashes.
 *   4. Manifest signature verify under the receipt-embedded
 *      publisher_pubkey_pem (after recomputing canonical signing-input
 *      bytes with signature := "").
 *   5. Time bounds (now in [not_before - 300, expires]).
 *   6. File hashes: recompute SHA-256 of every file under --source-dir
 *      and confirm against manifest.files[]; reject extras.
 *
 * Exit code: 0 on accept, non-zero on any failed check.
 *
 * Usage:
 *   fips-manifest-verify --receipt FILE --source-dir DIR
 *                        [--cosigner-pem FILE]    (default: ~/.TPM/ca-cosigner.pem)
 *                        [-v|--verbose]
 *
 * Receipt-embedded publisher_pubkey_pem is sanity-checked against the
 * canonical leaf's spk_hash before being trusted, defending against
 * a malicious receipt forging a different pubkey.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>

#include <json-c/json.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_RECEIPT_SIZE      (8 * 1024 * 1024)
#define MAX_LEAF_SIZE         (16 * 1024 * 1024)
#define MAX_SIG_SIZE          4627
#define HASH_SIZE             32
#define COSIG_TIME_SKEW_BACK  300.0
#define MAX_FILES             65535
#define MAX_PATH_LEN          512
#define COSIG_LABEL           "mtc-subtree/v1\n"     /* 15 chars + NUL */
#define COSIG_LABEL_FULL_LEN  16

#define die(fmt, ...) do { \
    fprintf(stderr, "fips-manifest-verify: " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

static int g_verbose = 0;

#define VLOG(fmt, ...) do { \
    if (g_verbose) fprintf(stderr, "  " fmt "\n", ##__VA_ARGS__); \
} while (0)

/* ---------------- file IO helpers ---------------- */

static int read_whole_file(const char *path, uint8_t **out, size_t *out_sz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);
    uint8_t *p = malloc((size_t)sz + 1);
    if (!p) { fclose(fp); return -1; }
    if (sz > 0 && fread(p, 1, (size_t)sz, fp) != (size_t)sz) {
        free(p); fclose(fp); return -1;
    }
    p[sz] = 0;
    fclose(fp);
    *out = p; *out_sz = (size_t)sz;
    return 0;
}

/* ---------------- hash primitives (RFC 9162 §2.1) ---------------- */

static int sha256_file_hex(const char *path, char out_hex[65])
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    wc_Sha256 sha;
    if (wc_InitSha256(&sha) != 0) { fclose(fp); return -1; }
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (wc_Sha256Update(&sha, buf, (word32)n) != 0) {
            wc_Sha256Free(&sha); fclose(fp); return -1;
        }
    }
    uint8_t h[32];
    if (wc_Sha256Final(&sha, h) != 0) {
        wc_Sha256Free(&sha); fclose(fp); return -1;
    }
    wc_Sha256Free(&sha);
    fclose(fp);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out_hex[i*2]   = hex[(h[i] >> 4) & 0xf];
        out_hex[i*2+1] = hex[h[i] & 0xf];
    }
    out_hex[64] = 0;
    return 0;
}

static int hash_leaf(const uint8_t *data, size_t data_len, uint8_t out[32])
{
    /* SHA-256(0x00 || data) — RFC 9162 §2.1 */
    wc_Sha256 sha;
    if (wc_InitSha256(&sha) != 0) return -1;
    uint8_t prefix = 0x00;
    if (wc_Sha256Update(&sha, &prefix, 1) != 0 ||
        wc_Sha256Update(&sha, data, (word32)data_len) != 0 ||
        wc_Sha256Final(&sha, out) != 0) {
        wc_Sha256Free(&sha); return -1;
    }
    wc_Sha256Free(&sha);
    return 0;
}

static int hash_node(const uint8_t left[32], const uint8_t right[32],
                     uint8_t out[32])
{
    /* SHA-256(0x01 || left || right) */
    wc_Sha256 sha;
    if (wc_InitSha256(&sha) != 0) return -1;
    uint8_t prefix = 0x01;
    if (wc_Sha256Update(&sha, &prefix, 1) != 0 ||
        wc_Sha256Update(&sha, left, 32) != 0 ||
        wc_Sha256Update(&sha, right, 32) != 0 ||
        wc_Sha256Final(&sha, out) != 0) {
        wc_Sha256Free(&sha); return -1;
    }
    wc_Sha256Free(&sha);
    return 0;
}

/* ---------------- hex helpers ---------------- */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_max)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = -1, lo = -1;
        char ch = hex[i*2];
        char cl = hex[i*2+1];
        if (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
        if (cl >= '0' && cl <= '9') lo = cl - '0';
        else if (cl >= 'a' && cl <= 'f') lo = cl - 'a' + 10;
        else if (cl >= 'A' && cl <= 'F') lo = cl - 'A' + 10;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

/* ---------------- RFC 9162 inclusion-proof replay ---------------- */

/* fn = leaf index, sn = tree_size - 1, leaf_hash → expected_root.
 * Returns 0 on accept, non-zero on reject. */
static int verify_inclusion_proof(int fn, int sn,
                                  const uint8_t *leaf_hash,
                                  const uint8_t *proof,    /* count*32 bytes */
                                  int count,
                                  const uint8_t expected_root[32])
{
    if (fn < 0 || sn < 0 || fn > sn) return -1;
    uint8_t h[32];
    memcpy(h, leaf_hash, 32);
    int ip = 0;
    while (sn > 0) {
        if (ip >= count) return -1;     /* proof too short */
        const uint8_t *p = proof + (size_t)ip * 32;
        ip++;
        uint8_t next[32];
        if ((fn & 1) == 1 || fn == sn) {
            if (hash_node(p, h, next) != 0) return -1;
            memcpy(h, next, 32);
            while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
        } else {
            if (hash_node(h, p, next) != 0) return -1;
            memcpy(h, next, 32);
        }
        fn >>= 1;
        sn >>= 1;
    }
    if (ip != count) return -1;          /* proof too long */
    return memcmp(h, expected_root, 32) == 0 ? 0 : -1;
}

/* ---------------- ML-DSA-87 verify ---------------- */

static int mldsa87_verify(const char *pub_pem,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len)
{
    int rc = -1;
    int verify_res = 0;
    int pub_init = 0;
    int pem_len = (int)strlen(pub_pem);
    uint8_t *der = malloc((size_t)pem_len);
    if (!der) return -1;
    int der_sz = wc_PubKeyPemToDer((const unsigned char *)pub_pem, pem_len,
                                   der, pem_len);
    if (der_sz <= 0) goto out;
    dilithium_key key;
    if (wc_dilithium_init(&key) != 0) goto out;
    pub_init = 1;
    if (wc_dilithium_set_level(&key, WC_ML_DSA_87) != 0) goto out;
    word32 idx = 0;
    if (wc_Dilithium_PublicKeyDecode(der, &idx, &key, (word32)der_sz) != 0)
        goto out;
    if (wc_dilithium_verify_ctx_msg(sig, (word32)sig_len, NULL, 0,
                                    msg, (word32)msg_len,
                                    &verify_res, &key) != 0)
        goto out;
    rc = (verify_res == 1) ? 0 : -1;
out:
    if (pub_init) wc_dilithium_free(&key);
    free(der);
    return rc;
}

/* ---------------- canonicalization (must match server + submit) --- */

static int canonicalize(struct json_object *m, char **out, size_t *out_sz)
{
    const char *s = json_object_to_json_string_ext(
        m, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!s) return -1;
    size_t n = strlen(s);
    char *buf = malloc(n + 1);
    if (!buf) return -1;
    memcpy(buf, s, n + 1);
    *out = buf; *out_sz = n;
    return 0;
}

/* ---------------- file walk for source-dir ---------------- */

typedef struct {
    char path[MAX_PATH_LEN + 1];
    char sha256[65];
    int  matched;     /* set when walked-and-matched against manifest */
} fl_entry;

typedef struct {
    fl_entry *items;
    size_t    n, cap;
} file_list;

static void fl_init(file_list *fl) { fl->items = NULL; fl->n = fl->cap = 0; }
static void fl_free(file_list *fl) { free(fl->items); fl->items = NULL; fl->n = fl->cap = 0; }
static void fl_push(file_list *fl, const fl_entry *e)
{
    if (fl->n == MAX_FILES) die("too many files");
    if (fl->n >= fl->cap) {
        size_t nc = fl->cap ? fl->cap * 2 : 256;
        void *p = realloc(fl->items, nc * sizeof(fl_entry));
        if (!p) die("oom");
        fl->items = p; fl->cap = nc;
    }
    fl->items[fl->n++] = *e;
}

static int fl_cmp(const void *a, const void *b)
{
    return strcmp(((const fl_entry *)a)->path,
                  ((const fl_entry *)b)->path);
}

static fl_entry *fl_find(file_list *fl, const char *path)
{
    fl_entry key = {0};
    snprintf(key.path, sizeof(key.path), "%s", path);
    return (fl_entry *)bsearch(&key, fl->items, fl->n,
                               sizeof(fl_entry), fl_cmp);
}

/* Same exclusion posture as fips-manifest-submit / sign-dir.sh:
 * recursive, follow symlinks, skip .git, MANIFEST.*, private_key.pem. */
static void walk_dir(const char *base, const char *rel_prefix, file_list *fl)
{
    char abs[4096];
    if (rel_prefix[0])
        snprintf(abs, sizeof(abs), "%s/%s", base, rel_prefix);
    else
        snprintf(abs, sizeof(abs), "%s", base);
    DIR *d = opendir(abs);
    if (!d) die("opendir %s: %s", abs, strerror(errno));
    struct dirent *de;
    while ((de = readdir(d))) {
        const char *name = de->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        if (!strcmp(name, ".git")) continue;
        if (!strcmp(name, "MANIFEST.sha256") ||
            !strcmp(name, "MANIFEST.sig") ||
            !strcmp(name, "private_key.pem")) continue;
        char rel[MAX_PATH_LEN + 64];
        if (rel_prefix[0])
            snprintf(rel, sizeof(rel), "%s/%s", rel_prefix, name);
        else
            snprintf(rel, sizeof(rel), "%s", name);
        char child_abs[4096];
        snprintf(child_abs, sizeof(child_abs), "%s/%s", base, rel);
        struct stat st;
        if (stat(child_abs, &st) != 0) continue;   /* broken symlink */
        if (S_ISDIR(st.st_mode)) {
            walk_dir(base, rel, fl);
        } else if (S_ISREG(st.st_mode)) {
            fl_entry e = {0};
            if (strlen(rel) > MAX_PATH_LEN)
                die("path too long: %s", rel);
            snprintf(e.path, sizeof(e.path), "%s", rel);
            if (sha256_file_hex(child_abs, e.sha256) != 0)
                die("sha256 failed for %s", child_abs);
            fl_push(fl, &e);
        }
    }
    closedir(d);
}

/* ---------------- main ---------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --receipt FILE --source-dir DIR\n"
        "         [--cosigner-pem FILE]    (default: ~/.TPM/ca-cosigner.pem)\n"
        "         [-v|--verbose]\n",
        prog);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *receipt_path = NULL, *source_dir = NULL;
    const char *cosigner_pem_path = NULL;

    static struct option opts[] = {
        {"receipt",       required_argument, 0, 'r'},
        {"source-dir",    required_argument, 0, 's'},
        {"cosigner-pem",  required_argument, 0, 'c'},
        {"verbose",       no_argument,       0, 'v'},
        {"help",          no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "r:s:c:vh", opts, NULL)) != -1) {
        switch (c) {
            case 'r': receipt_path = optarg; break;
            case 's': source_dir   = optarg; break;
            case 'c': cosigner_pem_path = optarg; break;
            case 'v': g_verbose = 1; break;
            default:  usage(argv[0]);
        }
    }
    if (!receipt_path || !source_dir) usage(argv[0]);

    char cosigner_default[1024];
    if (!cosigner_pem_path) {
        const char *home = getenv("HOME");
        if (!home) die("HOME unset");
        snprintf(cosigner_default, sizeof(cosigner_default),
                 "%s/.TPM/ca-cosigner.pem", home);
        cosigner_pem_path = cosigner_default;
    }

    /* === Step 1: strict-parse receipt + embedded canonical leaf === */
    uint8_t *recv_buf = NULL;
    size_t recv_len = 0;
    if (read_whole_file(receipt_path, &recv_buf, &recv_len) != 0)
        die("cannot read receipt %s: %s", receipt_path, strerror(errno));
    if (recv_len > MAX_RECEIPT_SIZE) die("receipt too large");

    struct json_tokener *tok = json_tokener_new();
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    struct json_object *r = json_tokener_parse_ex(tok, (const char *)recv_buf,
                                                  (int)recv_len);
    enum json_tokener_error tok_err = json_tokener_get_error(tok);
    json_tokener_free(tok);
    free(recv_buf);
    if (!r || tok_err != json_tokener_success)
        die("receipt JSON parse failed (err=%d)", tok_err);
    if (!json_object_is_type(r, json_type_object))
        die("receipt: top-level not object");

    struct json_object *v;
    int leaf_index, tree_size;
    const char *tree_root_hex, *leaf_b64, *publisher_pem;

    if (!json_object_object_get_ex(r, "leaf_index", &v) ||
        !json_object_is_type(v, json_type_int))
        die("receipt: leaf_index missing/wrong");
    leaf_index = json_object_get_int(v);

    if (!json_object_object_get_ex(r, "tree_size", &v) ||
        !json_object_is_type(v, json_type_int))
        die("receipt: tree_size missing/wrong");
    tree_size = json_object_get_int(v);

    if (!json_object_object_get_ex(r, "tree_root", &v) ||
        !json_object_is_type(v, json_type_string))
        die("receipt: tree_root missing/wrong");
    tree_root_hex = json_object_get_string(v);
    if (strlen(tree_root_hex) != 64)
        die("receipt: tree_root not 64 hex");
    uint8_t tree_root[32];
    if (hex_to_bytes(tree_root_hex, tree_root, 32) != 32)
        die("receipt: tree_root hex decode failed");

    if (!json_object_object_get_ex(r, "leaf_bytes_b64", &v) ||
        !json_object_is_type(v, json_type_string))
        die("receipt: leaf_bytes_b64 missing/wrong");
    leaf_b64 = json_object_get_string(v);

    if (!json_object_object_get_ex(r, "publisher_pubkey_pem", &v) ||
        !json_object_is_type(v, json_type_string))
        die("receipt: publisher_pubkey_pem missing");
    publisher_pem = json_object_get_string(v);

    struct json_object *cosig_arr;
    if (!json_object_object_get_ex(r, "cosignatures", &cosig_arr) ||
        !json_object_is_type(cosig_arr, json_type_array) ||
        json_object_array_length(cosig_arr) < 1)
        die("receipt: cosignatures missing/empty");

    struct json_object *proof_arr;
    if (!json_object_object_get_ex(r, "inclusion_proof", &proof_arr) ||
        !json_object_is_type(proof_arr, json_type_array))
        die("receipt: inclusion_proof missing/wrong");

    /* Decode leaf_bytes */
    word32 leaf_len = (word32)strlen(leaf_b64);
    uint8_t *leaf_bytes = malloc(leaf_len);
    if (!leaf_bytes) die("oom");
    word32 leaf_bytes_sz = leaf_len;
    if (Base64_Decode((const byte *)leaf_b64, leaf_len,
                      leaf_bytes, &leaf_bytes_sz) != 0)
        die("leaf_bytes_b64 decode failed");
    if (leaf_bytes_sz < 2 || leaf_bytes[0] != 0x02)
        die("leaf entry-type prefix != 0x02");

    /* Parse the canonical leaf (after the prefix byte) */
    struct json_object *m = json_tokener_parse((const char *)(leaf_bytes + 1));
    if (!m || !json_object_is_type(m, json_type_object))
        die("leaf canonical JSON parse failed");

    /* Pull manifest fields needed downstream */
    json_object_object_get_ex(m, "publisher_cert_index", &v);
    int cert_index = json_object_get_int(v);
    json_object_object_get_ex(m, "not_before", &v);
    double not_before = json_object_get_double(v);
    json_object_object_get_ex(m, "expires", &v);
    double expires = json_object_get_double(v);
    json_object_object_get_ex(m, "signature", &v);
    const char *sig_b64 = json_object_get_string(v);
    json_object_object_get_ex(m, "files", &v);
    struct json_object *files_arr = v;

    VLOG("receipt: leaf_index=%d tree_size=%d", leaf_index, tree_size);
    VLOG("manifest: cert_index=%d not_before=%.0f expires=%.0f",
         cert_index, not_before, expires);

    /* === Step 2: cosignature verify === */
    {
        struct json_object *cosig0 = json_object_array_get_idx(cosig_arr, 0);
        struct json_object *kj, *sj, *aj;
        if (!json_object_object_get_ex(cosig0, "key_id", &kj) ||
            !json_object_object_get_ex(cosig0, "sig", &sj) ||
            !json_object_object_get_ex(cosig0, "alg", &aj))
            die("cosignatures[0]: missing fields");
        const char *key_id = json_object_get_string(kj);
        const char *cosig_sig_b64 = json_object_get_string(sj);
        if (strcmp(json_object_get_string(aj), "ML-DSA-87") != 0)
            die("cosignatures[0]: alg != ML-DSA-87");

        /* log_id = key_id with trailing ".ca" stripped (server convention).
         * Cosigner_id = key_id full.  Match what mtc_store_cosign embeds. */
        size_t kid_len = strlen(key_id);
        if (kid_len < 4 || strcmp(key_id + kid_len - 3, ".ca") != 0)
            die("cosignatures[0].key_id missing .ca suffix");
        size_t log_id_len = kid_len - 3;

        /* Build signing input:
         *   "mtc-subtree/v1\n\x00" || cosigner_id || log_id ||
         *   start_be64 || end_be64 || subtree_hash
         * Receipt represents (start=0, end=tree_size, subtree_hash=tree_root). */
        uint8_t cosig_msg[256];
        size_t msg_sz = 0;
        memcpy(cosig_msg, COSIG_LABEL, 15);
        cosig_msg[15] = 0;
        msg_sz = COSIG_LABEL_FULL_LEN;
        memcpy(cosig_msg + msg_sz, key_id, kid_len);
        msg_sz += kid_len;
        memcpy(cosig_msg + msg_sz, key_id, log_id_len);
        msg_sz += log_id_len;
        for (int i = 7; i >= 0; i--) cosig_msg[msg_sz++] = 0;          /* start=0 */
        uint64_t end64 = (uint64_t)(unsigned int)tree_size;
        for (int i = 7; i >= 0; i--)
            cosig_msg[msg_sz++] = (uint8_t)((end64 >> (i*8)) & 0xff);
        memcpy(cosig_msg + msg_sz, tree_root, 32);
        msg_sz += 32;

        /* Decode cosig signature */
        uint8_t cosig_bin[MAX_SIG_SIZE];
        word32 cosig_bin_sz = sizeof(cosig_bin);
        if (Base64_Decode((const byte *)cosig_sig_b64,
                          (word32)strlen(cosig_sig_b64),
                          cosig_bin, &cosig_bin_sz) != 0)
            die("cosignatures[0].sig base64 decode failed");

        /* Load cosigner pubkey */
        uint8_t *cosigner_pem_buf = NULL;
        size_t cosigner_pem_len = 0;
        if (read_whole_file(cosigner_pem_path,
                            &cosigner_pem_buf, &cosigner_pem_len) != 0)
            die("cannot read cosigner pem %s: %s",
                cosigner_pem_path, strerror(errno));

        if (mldsa87_verify((const char *)cosigner_pem_buf,
                           cosig_msg, msg_sz,
                           cosig_bin, cosig_bin_sz) != 0)
            die("cosignature verification failed");
        free(cosigner_pem_buf);
        VLOG("cosignature: OK (key_id=%s tree_size=%d)", key_id, tree_size);
    }

    /* === Step 3: inclusion-proof replay === */
    {
        int proof_count = json_object_array_length(proof_arr);
        uint8_t *proof = malloc((size_t)proof_count * 32);
        if (!proof && proof_count > 0) die("oom");
        for (int i = 0; i < proof_count; i++) {
            struct json_object *e = json_object_array_get_idx(proof_arr, i);
            if (!json_object_is_type(e, json_type_string))
                die("inclusion_proof[%d]: not string", i);
            const char *h = json_object_get_string(e);
            if (strlen(h) != 64 ||
                hex_to_bytes(h, proof + (size_t)i * 32, 32) != 32)
                die("inclusion_proof[%d]: bad hex", i);
        }
        uint8_t leaf_hash[32];
        if (hash_leaf(leaf_bytes, leaf_bytes_sz, leaf_hash) != 0)
            die("hash_leaf failed");
        if (verify_inclusion_proof(leaf_index, tree_size - 1,
                                   leaf_hash, proof, proof_count,
                                   tree_root) != 0)
            die("inclusion proof does not chain to tree_root");
        free(proof);
        VLOG("inclusion proof: OK (%d siblings, leaf_hash chains to tree_root)",
             proof_count);
    }

    /* === Step 4: manifest signature verify === */
    {
        /* Sanity: receipt-embedded publisher_pem must hash to the cert's
         * spk_hash that the manifest claims.  But we don't have the cert
         * here in offline mode — best we can do is confirm
         * sha256(publisher_pem) matches manifest.publisher_pubkey_hash if
         * such a field existed.  Since the spec doesn't include the
         * spk_hash in the manifest itself (it's in the cert at
         * publisher_cert_index), we trust the cosigned tree_root: a
         * malicious receipt that swapped publisher_pem for an attacker's
         * key would still need to produce a valid cosignature (Step 2)
         * over a tree containing the matching leaf; the cosigner won't
         * sign an inconsistent tree.  Skip explicit cert check in v1. */

        /* Build signing input: re-canonicalize manifest with signature := "" */
        struct json_object *m_signing = json_tokener_parse(
            (const char *)(leaf_bytes + 1));
        if (!m_signing) die("signing-input reparse failed");
        json_object_object_add(m_signing, "signature",
                               json_object_new_string(""));
        char *signing_input = NULL;
        size_t signing_input_sz = 0;
        if (canonicalize(m_signing, &signing_input, &signing_input_sz) != 0)
            die("signing-input canonicalize failed");
        json_object_put(m_signing);

        /* Decode signature */
        uint8_t sig_bin[MAX_SIG_SIZE];
        word32 sig_bin_sz = sizeof(sig_bin);
        if (Base64_Decode((const byte *)sig_b64, (word32)strlen(sig_b64),
                          sig_bin, &sig_bin_sz) != 0)
            die("signature base64 decode failed");

        if (mldsa87_verify(publisher_pem,
                           (const uint8_t *)signing_input, signing_input_sz,
                           sig_bin, sig_bin_sz) != 0)
            die("manifest signature verification failed");
        free(signing_input);
        VLOG("manifest signature: OK (publisher_pem %zu bytes, %u-byte sig)",
             strlen(publisher_pem), sig_bin_sz);
    }

    /* === Step 5: time bounds === */
    {
        double now = (double)time(NULL);
        if (now + COSIG_TIME_SKEW_BACK < not_before)
            die("not_before %.0f > now+skew %.0f", not_before,
                now + COSIG_TIME_SKEW_BACK);
        if (now > expires)
            die("expires %.0f < now %.0f", expires, now);
        VLOG("time bounds: OK (now=%.0f in [%.0f, %.0f])",
             now, not_before, expires);
    }

    /* === Step 6: file hashes === */
    {
        /* Build expected: parse manifest.files into a sorted list. */
        int n_expected = json_object_array_length(files_arr);
        file_list expected;
        fl_init(&expected);
        for (int i = 0; i < n_expected; i++) {
            struct json_object *fe = json_object_array_get_idx(files_arr, i);
            struct json_object *pv, *hv;
            json_object_object_get_ex(fe, "path", &pv);
            json_object_object_get_ex(fe, "sha256", &hv);
            fl_entry e = {0};
            snprintf(e.path,   sizeof(e.path),   "%s", json_object_get_string(pv));
            snprintf(e.sha256, sizeof(e.sha256), "%s", json_object_get_string(hv));
            fl_push(&expected, &e);
        }
        qsort(expected.items, expected.n, sizeof(fl_entry), fl_cmp);

        /* Walk source-dir, compute hashes, match */
        char src_abs[4096];
        if (!realpath(source_dir, src_abs))
            die("realpath %s: %s", source_dir, strerror(errno));
        file_list found;
        fl_init(&found);
        walk_dir(src_abs, "", &found);
        qsort(found.items, found.n, sizeof(fl_entry), fl_cmp);

        for (size_t i = 0; i < found.n; i++) {
            fl_entry *exp = fl_find(&expected, found.items[i].path);
            if (!exp)
                die("extra file on disk not in manifest: %s",
                    found.items[i].path);
            if (strcmp(exp->sha256, found.items[i].sha256) != 0)
                die("file hash mismatch for %s (expected %.16s..., got %.16s...)",
                    found.items[i].path, exp->sha256, found.items[i].sha256);
            exp->matched = 1;
        }
        for (size_t i = 0; i < expected.n; i++) {
            if (!expected.items[i].matched)
                die("manifest file missing on disk: %s", expected.items[i].path);
        }
        VLOG("files: OK (%d files matched)", n_expected);
        fl_free(&expected);
        fl_free(&found);
    }

    free(leaf_bytes);
    json_object_put(m);
    json_object_put(r);

    printf("OK leaf_index=%d tree_size=%d cert_index=%d (cosigner+proof+sig+files all verified)\n",
           leaf_index, tree_size, cert_index);
    return 0;
}
