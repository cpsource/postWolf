/******************************************************************************
 * File:        mtc_store.c
 * Purpose:     Persistence and CA operations for the MTC CA server.
 *
 * Description:
 *   Manages all server-side state: the Merkle tree, Ed25519 CA key,
 *   certificates, checkpoints, landmarks, and revocations.  Supports two
 *   storage backends:
 *     - PostgreSQL (Neon) when MERKLE_NEON is available
 *     - File-based JSON (entries.json, certificates.json, landmarks.json,
 *       revocations.json) in data_dir as fallback
 *
 *   The CA Ed25519 key is loaded from DB, file (ca_key.der), or
 *   generated fresh on first run.
 *
 * Dependencies:
 *   mtc_store.h, mtc_log.h
 *   stdio.h, stdlib.h, string.h, time.h
 *   sys/stat.h              (mkdir, chmod)
 *   wolfssl/options.h
 *   wolfssl/wolfcrypt/ed25519.h     (CA key operations)
 *   wolfssl/wolfcrypt/random.h      (key generation)
 *   wolfssl/wolfcrypt/asn_public.h  (DER/PEM conversion)
 *
 * Notes:
 *   - NOT thread-safe.  All operations must be serialised.
 *   - The store owns all json_object refs in certificates/checkpoints.
 *   - CA private key is stored as DER in ca_key.der (chmod 0600) and
 *     optionally mirrored to DB as hex (unencrypted — see warning in
 *     init_ca_key).
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include "mtc_store.h"
#include "mtc_log.h"
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

/******************************************************************************
 * Function:    mkdirp
 *
 * Description:
 *   Recursively creates directories for the given path, similar to
 *   "mkdir -p".  Walks the path string, creating each component.
 *
 * Input Arguments:
 *   path  - Directory path to create (may already exist).
 ******************************************************************************/
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

/******************************************************************************
 * Function:    write_file
 *
 * Description:
 *   Writes raw bytes to a file, overwriting any existing content.
 *
 * Input Arguments:
 *   path  - File path.
 *   data  - Data to write.
 *   sz    - Number of bytes to write.
 *
 * Returns:
 *    0  on success.
 *   -1  if the file could not be opened.
 ******************************************************************************/
static int write_file(const char *path, const void *data, int sz)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

/******************************************************************************
 * Function:    read_file
 *
 * Description:
 *   Reads an entire file into a caller-owned buffer.
 *
 * Input Arguments:
 *   path   - File path.
 *   buf    - Caller-owned destination buffer.
 *   maxSz  - Maximum bytes to read (rejects files larger than this).
 *
 * Returns:
 *   Number of bytes read (>= 0) on success.
 *  -1  if the file could not be opened or exceeds maxSz.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    init_ca_key
 *
 * Description:
 *   Loads or generates the CA Ed25519 signing key.  Sources are tried in
 *   order:
 *     1. Database (ca_private_key_hex in mtc_ca_config)
 *     2. File (data_dir/ca_key.der)
 *     3. Generate new key, save to file (chmod 0600) and DB
 *
 * Input Arguments:
 *   store  - Store with data_dir and DB connection already set.
 *
 * Returns:
 *   0 on success, non-zero wolfCrypt error code on failure.
 *
 * Side Effects:
 *   Populates store->ca_priv_key, ca_priv_key_sz, ca_pub_key, ca_pub_key_sz.
 *   May write ca_key.der and/or DB config row.
 ******************************************************************************/
static int init_ca_key(MtcStore *store)
{
    char path[1024];
    ed25519_key key;
    WC_RNG rng;
    int ret;

    snprintf(path, sizeof(path), "%s/ca_key.der", store->data_dir);

    /* Load from file only — private keys are never stored in the DB */
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

/******************************************************************************
 * Function:    mtc_store_init
 *
 * Description:
 *   Initialises the store: creates the data directory, connects to
 *   PostgreSQL (if available), initialises the Merkle tree, allocates
 *   certificate/checkpoint arrays, loads or generates the CA key, and
 *   restores persisted state.  If the tree is empty after loading, a
 *   null entry (0x00) is inserted at index 0.
 *
 * Input Arguments:
 *   store     - Store to initialise.
 *   data_dir  - Directory for file-based storage.
 *   ca_name   - CA display name.
 *   log_id    - Log identifier string.
 *
 * Returns:
 *    0  on success.
 *   -1  if the CA key could not be initialised.
 *
 * Side Effects:
 *   Creates data_dir, connects to DB, allocates arrays, may generate
 *   and persist a new CA key.
 ******************************************************************************/
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
            fflush(stdout);
        }
        else {
            printf("[store] PostgreSQL unavailable, falling back to files\n");
            fflush(stdout);
        }
    }
    else {
        printf("[store] MERKLE_NEON not set, using file-based storage\n");
        fflush(stdout);
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

/******************************************************************************
 * Function:    mtc_store_free
 *
 * Description:
 *   Frees all memory owned by the store: the Merkle tree, all certificate
 *   and checkpoint json_objects, and the top-level arrays.  Does NOT close
 *   the DB connection.
 *
 * Input Arguments:
 *   store  - Store to free.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_store_save
 *
 * Description:
 *   Persists the current store state to JSON files in data_dir:
 *     entries.json      — hex-encoded tree entries
 *     certificates.json — issued certificate objects
 *     landmarks.json    — landmark tree sizes
 *
 * Input Arguments:
 *   store  - Store to save.
 *
 * Returns:
 *   0 always.
 ******************************************************************************/
int mtc_store_save(MtcStore *store)
{
    char path[1024];
    int i;

    /* Save entries as a JSON array */
    {
        struct json_object *arr = json_object_new_array();
        for (i = 0; i < store->tree.size; i++) {
            struct json_object *entry = json_object_new_object();
            int esz = store->tree.entry_sizes[i];
            int hexsz = esz * 2 + 1;
            char *hex = (char*)malloc(hexsz);
            int j;
            for (j = 0; j < esz; j++)
                snprintf(hex + j * 2, 3, "%02x", store->tree.entries[i][j]);
            json_object_object_add(entry, "hex", json_object_new_string(hex));
            json_object_object_add(entry, "size",
                json_object_new_int(esz));
            json_object_array_add(arr, entry);
            free(hex);
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

/******************************************************************************
 * Function:    mtc_store_load
 *
 * Description:
 *   Loads persisted state into the store.  If use_db is set, loads from
 *   PostgreSQL (entries, landmarks, certificates, revocations).  Otherwise
 *   loads from JSON files in data_dir (entries.json, certificates.json,
 *   landmarks.json).
 *
 * Input Arguments:
 *   store  - Store to populate (tree and arrays are appended to).
 *
 * Returns:
 *   0 always (an empty result is not an error).
 *
 * Side Effects:
 *   Appends entries to store->tree, populates certificates, landmarks,
 *   and revocations arrays.
 ******************************************************************************/
int mtc_store_load(MtcStore *store)
{
    char path[1024], buf[1024 * 1024];
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
                    int j;

                    if (json_object_object_get_ex(e, "serialized_len", &val))
                        entry_sz = json_object_get_int(val);

                    if (entry_sz > 0) {
                        uint8_t *entry_bytes = (uint8_t*)malloc(entry_sz);
                        for (j = 0; j < entry_sz && hex[j*2] && hex[j*2+1]; j++) {
                            unsigned int bv;
                            sscanf(hex + j * 2, "%02x", &bv);
                            entry_bytes[j] = (uint8_t)bv;
                        }
                        mtc_tree_append(&store->tree, entry_bytes, entry_sz);
                        free(entry_bytes);
                    }
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

        /* Revocations */
        {
            int rev_buf[MTC_MAX_CERTS];
            int rev_count = mtc_db_load_revocations(store->db, rev_buf,
                MTC_MAX_CERTS);
            if (rev_count > 0) {
                store->revocation_capacity = rev_count * 2;
                store->revoked_indices = (int*)malloc(
                    (size_t)store->revocation_capacity * sizeof(int));
                memcpy(store->revoked_indices, rev_buf,
                    (size_t)rev_count * sizeof(int));
                store->revocation_count = rev_count;
            }
        }

        printf("[store] loaded %d entries, %d certs, %d landmarks, "
               "%d revocations from DB\n",
               store->tree.size, store->cert_count, store->landmark_count,
               store->revocation_count);
        fflush(stdout);
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
                    int j;

                    if (json_object_object_get_ex(entry, "size", &val))
                        entry_sz = json_object_get_int(val);

                    if (entry_sz > 0) {
                        uint8_t *entry_bytes = (uint8_t*)malloc(entry_sz);
                        for (j = 0; j < entry_sz && hex[j*2] && hex[j*2+1]; j++) {
                            unsigned int bv;
                            sscanf(hex + j * 2, "%02x", &bv);
                            entry_bytes[j] = (uint8_t)bv;
                        }
                        mtc_tree_append(&store->tree, entry_bytes, entry_sz);
                        free(entry_bytes);
                    }
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
    fflush(stdout);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    mtc_store_add_entry
 *
 * Description:
 *   Appends a serialised entry to the Merkle tree and persists it to DB
 *   (if connected).  Automatically records a landmark if the new tree
 *   size is a multiple of MTC_LANDMARK_INTERVAL.
 *
 * Input Arguments:
 *   store    - Target store.
 *   entry    - Serialised entry bytes (0x01 prefix = TBS, 0x00 = null).
 *   entrySz  - Size in bytes.
 *
 * Returns:
 *   0-based log index of the new entry.
 *
 * Side Effects:
 *   Appends to tree, may write to DB, may add a landmark.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_store_checkpoint
 *
 * Description:
 *   Creates a checkpoint for the current tree state: computes the root
 *   hash, builds a JSON object with log_id/tree_size/root_hash/timestamp,
 *   stores it in the checkpoints array, and persists to DB.
 *
 * Input Arguments:
 *   store  - Store.
 *
 * Returns:
 *   New json_object checkpoint.  Caller owns the reference and must
 *   call json_object_put() when done.  The store also keeps a ref
 *   in its checkpoints array.
 *
 * Side Effects:
 *   Appends to store->checkpoints (up to 256).  Writes to DB.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_store_cosign
 *
 * Description:
 *   Cosigns a subtree range [start, end) with the CA's Ed25519 key.
 *   Builds the signature input per the MTC draft specification:
 *     "mtc-subtree/v1\n\0" + cosigner_id + log_id + start(8BE) +
 *     end(8BE) + subtree_hash
 *
 * Input Arguments:
 *   store    - Store (provides CA key and tree).
 *   start    - Subtree start (inclusive).
 *   end      - Subtree end (exclusive).
 *   sig_out  - Caller-owned buffer (>= 64 bytes).
 *   sig_sz   - Receives the signature size.
 *
 * Returns:
 *   0 on success, non-zero wolfCrypt error code on failure.
 ******************************************************************************/
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

    /* Build signature input per MTC draft specification:
     * 16-byte context prefix (includes NUL) + cosigner_id + log_id +
     * start as 8-byte big-endian + end as 8-byte big-endian + subtree hash */
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

/******************************************************************************
 * Function:    mtc_store_get_public_key_pem
 *
 * Description:
 *   Exports the CA Ed25519 public key as a PEM string by decoding the
 *   stored private key DER, extracting the public key DER, and
 *   converting to PEM.
 *
 * Input Arguments:
 *   store  - Store (provides CA key).
 *   out    - Caller-owned buffer for the PEM string.
 *   maxSz  - Size of out in bytes.
 *
 * Returns:
 *   Number of PEM bytes written (> 0) on success.
 *   Negative wolfCrypt error code on failure.
 ******************************************************************************/
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

/* ------------------------------------------------------------------ */
/* Revocation                                                          */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    mtc_store_revoke
 *
 * Description:
 *   Revokes a certificate by log index.  The index is inserted into the
 *   sorted revoked_indices array (growing it if needed).  The revocation
 *   is persisted to both DB and a local revocations.json file.
 *   If already revoked, returns 0 immediately (idempotent).
 *
 * Input Arguments:
 *   store       - Store.
 *   cert_index  - Log index of the certificate to revoke.
 *   reason      - Human-readable reason (may be NULL).
 *
 * Returns:
 *    0  on success (including already-revoked).
 *   -1  on memory allocation failure.
 *
 * Side Effects:
 *   Inserts into revoked_indices (sorted), writes to DB and file.
 ******************************************************************************/
int mtc_store_revoke(MtcStore *store, int cert_index, const char *reason)
{
    /* Check not already revoked */
    if (mtc_store_is_revoked(store, cert_index))
        return 0; /* Already revoked */

    /* Grow array if needed */
    if (store->revocation_count >= store->revocation_capacity) {
        int newcap = store->revocation_capacity == 0 ? 64
                     : store->revocation_capacity * 2;
        int *tmp = (int*)realloc(store->revoked_indices,
            (size_t)newcap * sizeof(int));
        if (!tmp) return -1;
        store->revoked_indices = tmp;
        store->revocation_capacity = newcap;
    }

    /* Insert into sorted position via insertion sort — maintains the
     * invariant that revoked_indices is always sorted ascending for
     * binary search in mtc_store_is_revoked(). */
    {
        int i = store->revocation_count;
        while (i > 0 && store->revoked_indices[i - 1] > cert_index) {
            store->revoked_indices[i] = store->revoked_indices[i - 1];
            i--;
        }
        store->revoked_indices[i] = cert_index;
        store->revocation_count++;
    }

    /* Persist to DB */
    if (store->use_db && store->db)
        mtc_db_save_revocation(store->db, cert_index, reason);

    /* Persist to file */
    {
        char path[1024];
        struct json_object *arr = json_object_new_array();
        int i;
        const char *s;
        for (i = 0; i < store->revocation_count; i++)
            json_object_array_add(arr,
                json_object_new_int(store->revoked_indices[i]));
        snprintf(path, sizeof(path), "%s/revocations.json", store->data_dir);
        s = json_object_to_json_string(arr);
        {
            FILE *f = fopen(path, "w");
            if (f) { fputs(s, f); fclose(f); }
        }
        json_object_put(arr);
    }

    printf("[store] revoked cert index %d (reason: %s)\n",
           cert_index, reason ? reason : "unspecified");
    return 0;
}

/******************************************************************************
 * Function:    mtc_store_is_revoked
 *
 * Description:
 *   Checks whether a certificate is revoked via binary search on the
 *   sorted revoked_indices array.
 *
 * Input Arguments:
 *   store       - Store.
 *   cert_index  - Log index to check.
 *
 * Returns:
 *   1  if revoked.
 *   0  if not revoked.
 ******************************************************************************/
int mtc_store_is_revoked(MtcStore *store, int cert_index)
{
    int lo = 0, hi = store->revocation_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (store->revoked_indices[mid] == cert_index)
            return 1;
        else if (store->revoked_indices[mid] < cert_index)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return 0;
}

/******************************************************************************
 * Function:    mtc_store_get_revocation_list
 *
 * Description:
 *   Builds a signed revocation list as a JSON object containing:
 *   log_id, revoked (array of cert indices), count, updated_at
 *   timestamp, and an Ed25519 signature over the revoked array JSON.
 *
 * Input Arguments:
 *   store  - Store.
 *
 * Returns:
 *   New json_object.  Caller owns and must free with json_object_put().
 ******************************************************************************/
struct json_object *mtc_store_get_revocation_list(MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int i;
    uint8_t sig[64];
    int sig_sz = 0;

    json_object_object_add(obj, "log_id",
        json_object_new_string(store->log_id));

    for (i = 0; i < store->revocation_count; i++)
        json_object_array_add(arr,
            json_object_new_int(store->revoked_indices[i]));
    json_object_object_add(obj, "revoked", arr);

    json_object_object_add(obj, "count",
        json_object_new_int(store->revocation_count));
    json_object_object_add(obj, "updated_at",
        json_object_new_double((double)time(NULL)));

    /* Sign the revocation list with the CA key */
    {
        const char *payload = json_object_to_json_string(arr);
        ed25519_key key;
        word32 idx = 0;
        word32 outSz = sizeof(sig);

        if (wc_ed25519_init(&key) == 0 &&
            wc_Ed25519PrivateKeyDecode(store->ca_priv_key, &idx, &key,
                (word32)store->ca_priv_key_sz) == 0) {
            if (wc_ed25519_sign_msg((const byte*)payload,
                    (word32)strlen(payload), sig, &outSz, &key) == 0) {
                char sig_hex[129];
                sig_sz = (int)outSz;
                for (i = 0; i < sig_sz; i++)
                    snprintf(sig_hex + i * 2, 3, "%02x", sig[i]);
                json_object_object_add(obj, "signature",
                    json_object_new_string(sig_hex));
            }
            wc_ed25519_free(&key);
        }
    }

    return obj;
}
