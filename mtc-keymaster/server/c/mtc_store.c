/* mtc_store.c — Persistence and CA operations.
 *
 * Uses PostgreSQL (Neon) when MERKLE_NEON is set, otherwise falls
 * back to file-based JSON storage in data_dir. */

#include "mtc_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/* ------------------------------------------------------------------ */
/* File helpers                                                        */
/* ------------------------------------------------------------------ */

static void mkdirp(const char *path)
{
    char tmp[512];
    char *p;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
}

static int write_file(const char *path, const void *data, int sz)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

static int read_file(const char *path, void *buf, int maxSz)
{
    FILE *f = fopen(path, "rb");
    long sz;
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz > maxSz) { fclose(f); return -1; }
    sz = (long)fread(buf, 1, (size_t)sz, f);
    fclose(f);
    return (int)sz;
}

/* ------------------------------------------------------------------ */
/* Key management                                                      */
/* ------------------------------------------------------------------ */

static int init_ca_key(MtcStore *store)
{
    char path[512];
    ed25519_key key;
    WC_RNG rng;
    int ret;

    /* Try to load from DB first */
    if (store->use_db && store->db) {
        char *hex = mtc_db_load_config(store->db, "ca_private_key_hex");
        if (hex) {
            int i, len = (int)strlen(hex) / 2;
            if (len <= (int)sizeof(store->ca_priv_key)) {
                for (i = 0; i < len; i++) {
                    unsigned int bv;
                    sscanf(hex + i * 2, "%02x", &bv);
                    store->ca_priv_key[i] = (uint8_t)bv;
                }
                store->ca_priv_key_sz = len;
            }
            free(hex);
        }
    }

    snprintf(path, sizeof(path), "%s/ca_key.der", store->data_dir);

    /* Try to load from file if not from DB */
    if (store->ca_priv_key_sz <= 0)
        store->ca_priv_key_sz = read_file(path, store->ca_priv_key,
            (int)sizeof(store->ca_priv_key));

    if (store->ca_priv_key_sz > 0) {
        /* Extract public key from private */
        word32 idx = 0;
        ret = wc_ed25519_init(&key);
        if (ret != 0) return ret;
        ret = wc_Ed25519PrivateKeyDecode(store->ca_priv_key, &idx, &key,
            (word32)store->ca_priv_key_sz);
        if (ret == 0) {
            word32 pubSz = sizeof(store->ca_pub_key);
            ret = wc_ed25519_export_public(&key, store->ca_pub_key, &pubSz);
            store->ca_pub_key_sz = (int)pubSz;
        }
        wc_ed25519_free(&key);
        return ret;
    }

    /* Generate new Ed25519 key */
    printf("[store] generating Ed25519 CA key ...\n");
    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    ret = wc_ed25519_init(&key);
    if (ret == 0)
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
    wc_FreeRng(&rng);
    if (ret != 0) { wc_ed25519_free(&key); return ret; }

    /* Export private key DER */
    {
        word32 privSz = sizeof(store->ca_priv_key);
        ret = wc_Ed25519KeyToDer(&key, store->ca_priv_key, privSz);
        if (ret > 0) {
            store->ca_priv_key_sz = ret;
            write_file(path, store->ca_priv_key, store->ca_priv_key_sz);
            chmod(path, 0600);

            /* Also save to DB */
            if (store->use_db && store->db) {
                char hex[256];
                int j;
                for (j = 0; j < store->ca_priv_key_sz; j++)
                    snprintf(hex + j * 2, 3, "%02x", store->ca_priv_key[j]);
                mtc_db_save_config(store->db, "ca_private_key_hex", hex);
            }
            ret = 0;
        }
    }

    /* Export public key */
    {
        word32 pubSz = sizeof(store->ca_pub_key);
        wc_ed25519_export_public(&key, store->ca_pub_key, &pubSz);
        store->ca_pub_key_sz = (int)pubSz;
    }

    wc_ed25519_free(&key);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Store init/free                                                     */
/* ------------------------------------------------------------------ */

int mtc_store_init(MtcStore *store, const char *data_dir,
                   const char *ca_name, const char *log_id)
{
    memset(store, 0, sizeof(*store));
    snprintf(store->data_dir, sizeof(store->data_dir), "%s", data_dir);
    snprintf(store->ca_name, sizeof(store->ca_name), "%s", ca_name);
    snprintf(store->log_id, sizeof(store->log_id), "%s", log_id);
    snprintf(store->cosigner_id, sizeof(store->cosigner_id), "%s.ca", log_id);

    mkdirp(data_dir);

    /* Try to connect to PostgreSQL (Neon) */
    if (mtc_db_get_connstr() != NULL) {
        store->db = mtc_db_connect();
        if (store->db) {
            store->use_db = 1;
            mtc_db_init_schema(store->db);
            printf("[store] using PostgreSQL (Neon) for persistence\n");
        }
        else {
            printf("[store] PostgreSQL unavailable, falling back to files\n");
        }
    }
    else {
        printf("[store] MERKLE_NEON not set, using file-based storage\n");
    }

    mtc_tree_init(&store->tree);

    store->cert_capacity = 256;
    store->certificates = (struct json_object**)calloc(
        (size_t)store->cert_capacity, sizeof(struct json_object*));

    store->checkpoints = (struct json_object**)calloc(256,
        sizeof(struct json_object*));

    /* Load or generate CA key */
    if (init_ca_key(store) != 0) {
        fprintf(stderr, "failed to initialize CA key\n");
        return -1;
    }

    /* Try to load existing state */
    mtc_store_load(store);

    /* If empty, add null entry (index 0) */
    if (store->tree.size == 0) {
        uint8_t null_entry = 0x00;
        mtc_tree_append(&store->tree, &null_entry, 1);
    }

    return 0;
}

void mtc_store_free(MtcStore *store)
{
    int i;
    mtc_tree_free(&store->tree);
    for (i = 0; i < store->cert_count; i++) {
        if (store->certificates[i])
            json_object_put(store->certificates[i]);
    }
    free(store->certificates);
    for (i = 0; i < store->checkpoint_count; i++) {
        if (store->checkpoints[i])
            json_object_put(store->checkpoints[i]);
    }
    free(store->checkpoints);
}

/* ------------------------------------------------------------------ */
/* Persistence (JSON files)                                            */
/* ------------------------------------------------------------------ */

int mtc_store_save(MtcStore *store)
{
    char path[512];
    int i;

    /* Save entries as a JSON array */
    {
        struct json_object *arr = json_object_new_array();
        for (i = 0; i < store->tree.size; i++) {
            struct json_object *entry = json_object_new_object();
            char hex[1024];
            int j;
            for (j = 0; j < store->tree.entry_sizes[i] && j < 512; j++)
                snprintf(hex + j * 2, 3, "%02x", store->tree.entries[i][j]);
            json_object_object_add(entry, "hex", json_object_new_string(hex));
            json_object_object_add(entry, "size",
                json_object_new_int(store->tree.entry_sizes[i]));
            json_object_array_add(arr, entry);
        }
        snprintf(path, sizeof(path), "%s/entries.json", store->data_dir);
        {
            const char *s = json_object_to_json_string_ext(arr,
                JSON_C_TO_STRING_PRETTY);
            write_file(path, s, (int)strlen(s));
        }
        json_object_put(arr);
    }

    /* Save certificates */
    {
        struct json_object *arr = json_object_new_array();
        for (i = 0; i < store->cert_count; i++) {
            if (store->certificates[i])
                json_object_array_add(arr, json_object_get(store->certificates[i]));
        }
        snprintf(path, sizeof(path), "%s/certificates.json", store->data_dir);
        {
            const char *s = json_object_to_json_string_ext(arr,
                JSON_C_TO_STRING_PRETTY);
            write_file(path, s, (int)strlen(s));
        }
        json_object_put(arr);
    }

    /* Save landmarks */
    {
        struct json_object *arr = json_object_new_array();
        for (i = 0; i < store->landmark_count; i++)
            json_object_array_add(arr,
                json_object_new_int(store->landmarks[i]));
        snprintf(path, sizeof(path), "%s/landmarks.json", store->data_dir);
        {
            const char *s = json_object_to_json_string(arr);
            write_file(path, s, (int)strlen(s));
        }
        json_object_put(arr);
    }

    return 0;
}

int mtc_store_load(MtcStore *store)
{
    char path[512], buf[1024 * 1024];
    int sz;
    struct json_object *arr, *entry;
    int i, count;

    /* Load from PostgreSQL if available */
    if (store->use_db && store->db) {
        struct json_object *db_entries = NULL;
        int n;

        /* Entries */
        n = mtc_db_load_entries(store->db, &db_entries);
        if (n > 0 && db_entries) {
            count = (int)json_object_array_length(db_entries);
            for (i = 0; i < count; i++) {
                struct json_object *e = json_object_array_get_idx(db_entries, (size_t)i);
                struct json_object *val;
                if (json_object_object_get_ex(e, "serialized_hex", &val)) {
                    const char *hex = json_object_get_string(val);
                    int entry_sz = 0;
                    uint8_t entry_bytes[4096];
                    int j;

                    if (json_object_object_get_ex(e, "serialized_len", &val))
                        entry_sz = json_object_get_int(val);

                    for (j = 0; j < entry_sz && hex[j*2] && hex[j*2+1]; j++) {
                        unsigned int bv;
                        sscanf(hex + j * 2, "%02x", &bv);
                        entry_bytes[j] = (uint8_t)bv;
                    }
                    mtc_tree_append(&store->tree, entry_bytes, entry_sz);
                }
            }
            json_object_put(db_entries);
        }

        /* Landmarks */
        store->landmark_count = mtc_db_load_landmarks(store->db,
            store->landmarks, MTC_MAX_LANDMARKS);

        /* Certificates */
        {
            struct json_object **certs = NULL;
            int cert_count = 0;
            mtc_db_load_all_certificates(store->db, &certs, &cert_count);
            if (certs && cert_count > 0) {
                if (cert_count > store->cert_capacity) {
                    store->cert_capacity = cert_count * 2;
                    store->certificates = (struct json_object**)realloc(
                        store->certificates,
                        (size_t)store->cert_capacity * sizeof(struct json_object*));
                }
                for (i = 0; i < cert_count; i++)
                    store->certificates[i] = certs[i];
                store->cert_count = cert_count;
                free(certs);
            }
        }

        printf("[store] loaded %d entries, %d certs, %d landmarks from DB\n",
               store->tree.size, store->cert_count, store->landmark_count);
        return 0;
    }

    /* Load entries */
    snprintf(path, sizeof(path), "%s/entries.json", store->data_dir);
    sz = read_file(path, buf, (int)sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = 0;
        arr = json_tokener_parse(buf);
        if (arr) {
            count = (int)json_object_array_length(arr);
            for (i = 0; i < count; i++) {
                struct json_object *val;
                entry = json_object_array_get_idx(arr, (size_t)i);
                if (json_object_object_get_ex(entry, "hex", &val)) {
                    const char *hex = json_object_get_string(val);
                    int entry_sz = 0;
                    uint8_t entry_bytes[512];
                    int j;

                    if (json_object_object_get_ex(entry, "size", &val))
                        entry_sz = json_object_get_int(val);

                    for (j = 0; j < entry_sz && hex[j*2] && hex[j*2+1]; j++) {
                        unsigned int bv;
                        sscanf(hex + j * 2, "%02x", &bv);
                        entry_bytes[j] = (uint8_t)bv;
                    }
                    mtc_tree_append(&store->tree, entry_bytes, entry_sz);
                }
            }
            json_object_put(arr);
        }
    }

    /* Load certificates */
    snprintf(path, sizeof(path), "%s/certificates.json", store->data_dir);
    sz = read_file(path, buf, (int)sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = 0;
        arr = json_tokener_parse(buf);
        if (arr) {
            count = (int)json_object_array_length(arr);
            for (i = 0; i < count; i++) {
                struct json_object *cert = json_object_array_get_idx(arr, (size_t)i);
                if (store->cert_count >= store->cert_capacity) {
                    store->cert_capacity *= 2;
                    store->certificates = (struct json_object**)realloc(
                        store->certificates,
                        (size_t)store->cert_capacity * sizeof(struct json_object*));
                }
                store->certificates[store->cert_count++] = json_object_get(cert);
            }
            json_object_put(arr);
        }
    }

    /* Load landmarks */
    snprintf(path, sizeof(path), "%s/landmarks.json", store->data_dir);
    sz = read_file(path, buf, (int)sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = 0;
        arr = json_tokener_parse(buf);
        if (arr) {
            count = (int)json_object_array_length(arr);
            for (i = 0; i < count && i < MTC_MAX_LANDMARKS; i++)
                store->landmarks[store->landmark_count++] =
                    json_object_get_int(json_object_array_get_idx(arr, (size_t)i));
            json_object_put(arr);
        }
    }

    printf("[store] loaded %d entries, %d certs, %d landmarks\n",
           store->tree.size, store->cert_count, store->landmark_count);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

int mtc_store_add_entry(MtcStore *store, const uint8_t *entry, int entrySz)
{
    int idx = mtc_tree_append(&store->tree, entry, entrySz);

    /* Persist entry to DB */
    if (store->use_db && store->db) {
        uint8_t lh[MTC_HASH_SIZE];
        int entry_type = (entrySz > 0 && entry[0] == 0x01) ? 1 : 0;
        const char *tbs_json = NULL;
        char *tbs_str = NULL;

        mtc_hash_leaf(entry, entrySz, lh);

        if (entry_type == 1 && entrySz > 1) {
            tbs_str = (char*)malloc((size_t)entrySz);
            memcpy(tbs_str, entry + 1, (size_t)(entrySz - 1));
            tbs_str[entrySz - 1] = 0;
            tbs_json = tbs_str;
        }

        mtc_db_save_entry(store->db, idx, entry_type, tbs_json,
            entry, entrySz, lh);
        free(tbs_str);
    }

    /* Check for landmark */
    if (store->tree.size % MTC_LANDMARK_INTERVAL == 0 &&
        store->landmark_count < MTC_MAX_LANDMARKS) {
        store->landmarks[store->landmark_count++] = store->tree.size;
        if (store->use_db && store->db)
            mtc_db_save_landmark(store->db, store->tree.size);
    }

    return idx;
}

struct json_object *mtc_store_checkpoint(MtcStore *store)
{
    uint8_t root[MTC_HASH_SIZE];
    char root_hex[MTC_HASH_SIZE * 2 + 1];
    struct json_object *cp;
    int i;

    mtc_tree_root_hash(&store->tree, store->tree.size, root);
    for (i = 0; i < MTC_HASH_SIZE; i++)
        snprintf(root_hex + i * 2, 3, "%02x", root[i]);

    cp = json_object_new_object();
    json_object_object_add(cp, "log_id",
        json_object_new_string(store->log_id));
    json_object_object_add(cp, "tree_size",
        json_object_new_int(store->tree.size));
    json_object_object_add(cp, "root_hash",
        json_object_new_string(root_hex));
    json_object_object_add(cp, "timestamp",
        json_object_new_double(time(NULL)));

    if (store->checkpoint_count < 256) {
        store->checkpoints[store->checkpoint_count++] = json_object_get(cp);
    }

    /* Persist to DB */
    if (store->use_db && store->db) {
        mtc_db_save_checkpoint(store->db, store->log_id,
            store->tree.size, root_hex, (double)time(NULL));
    }

    return cp;
}

int mtc_store_cosign(MtcStore *store, int start, int end,
                     uint8_t *sig_out, int *sig_sz)
{
    ed25519_key key;
    uint8_t subtree_hash[MTC_HASH_SIZE];
    uint8_t msg[256];
    int msg_sz = 0;
    word32 idx_w = 0;
    word32 outSz;
    int ret, i;

    mtc_tree_subtree_hash(&store->tree, start, end, subtree_hash);

    /* Build signature input per MTC draft:
     * "mtc-subtree/v1\n\0" + cosigner_id + log_id + start(8) + end(8) + hash */
    memcpy(msg, "mtc-subtree/v1\n\x00", 16);
    msg_sz = 16;
    memcpy(msg + msg_sz, store->cosigner_id, strlen(store->cosigner_id));
    msg_sz += (int)strlen(store->cosigner_id);
    memcpy(msg + msg_sz, store->log_id, strlen(store->log_id));
    msg_sz += (int)strlen(store->log_id);

    for (i = 7; i >= 0; i--)
        msg[msg_sz++] = (uint8_t)((start >> (i * 8)) & 0xff);
    for (i = 7; i >= 0; i--)
        msg[msg_sz++] = (uint8_t)((end >> (i * 8)) & 0xff);

    memcpy(msg + msg_sz, subtree_hash, MTC_HASH_SIZE);
    msg_sz += MTC_HASH_SIZE;

    /* Sign with Ed25519 */
    ret = wc_ed25519_init(&key);
    if (ret != 0) return ret;

    ret = wc_Ed25519PrivateKeyDecode(store->ca_priv_key, &idx_w, &key,
        (word32)store->ca_priv_key_sz);
    if (ret != 0) { wc_ed25519_free(&key); return ret; }

    outSz = ED25519_SIG_SIZE;
    ret = wc_ed25519_sign_msg(msg, (word32)msg_sz, sig_out, &outSz, &key);
    *sig_sz = (int)outSz;

    wc_ed25519_free(&key);
    return ret;
}

int mtc_store_get_public_key_pem(MtcStore *store, char *out, int maxSz)
{
    uint8_t der[128];
    int derSz;
    ed25519_key key;
    word32 idx = 0;
    int ret;

    ret = wc_ed25519_init(&key);
    if (ret != 0) return ret;

    ret = wc_Ed25519PrivateKeyDecode(store->ca_priv_key, &idx, &key,
        (word32)store->ca_priv_key_sz);
    if (ret != 0) { wc_ed25519_free(&key); return ret; }

    derSz = wc_Ed25519PublicKeyToDer(&key, der, sizeof(der), 1);
    wc_ed25519_free(&key);

    if (derSz < 0) return derSz;

    ret = wc_DerToPem(der, (word32)derSz, (byte*)out, (word32)maxSz,
        ED25519_TYPE);
    return ret;
}
