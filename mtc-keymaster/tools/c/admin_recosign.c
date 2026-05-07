/******************************************************************************
 * File:        admin_recosign.c
 * Purpose:     Administrative tool — rewrite stale cosignatures (and the
 *              tree-state fields they cover) on every stored certificate so
 *              they match what the current CA key + current tree state would
 *              produce.
 *
 * Description:
 *   During implementation of client-side Merkle inclusion-proof verification
 *   we discovered that some stored cosignatures do not verify under the
 *   current CA ML-DSA-87 key using the message format produced by
 *   mtc_store_cosign().  This tool brings stored state back in sync — also
 *   used as the second phase of the Ed25519 -> ML-DSA-87 cosigner migration
 *   to rewrite every existing entry's cosig under the new key.
 *
 *   Default mode is --dry-run: the tool prints what it would change but
 *   does not touch certificates.json or the Neon mtc_certificates table.
 *   Pass --write to apply.
 *
 * Build:  make admin_recosign
 * Usage:  admin_recosign [--data-dir DIR] [--tokenpath FILE] [--write]
 *                        [--ca-name NAME] [--log-id ID] [-v] [-h]
 *
 * Created: 2026-04-16
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include "mtc_store.h"
#include "mtc_db.h"
#include "mtc_merkle.h"
#include "mtc_log.h"

/* Hex helper — duplicated from the other tools rather than refactoring a
 * shared utility out.  Scope creep for this task otherwise. */
static void to_hex(const uint8_t *data, int sz, char *out)
{
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 0; i < sz; i++) {
        out[i * 2]     = h[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = h[data[i] & 0xf];
    }
    out[sz * 2] = '\0';
}

static void usage(const char *prog)
{
    printf("admin_recosign — repair stale cosignatures in the MTC cert store.\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --data-dir DIR     Data directory (default: /home/ubuntu/.mtc-ca-data)\n");
    printf("  --tokenpath FILE   .env file for MERKLE_NEON (optional)\n");
    printf("  --ca-name NAME     CA name (default: MTC-CA-C)\n");
    printf("  --log-id ID        Log identifier (default: 32473.2)\n");
    printf("  --dry-run          Print per-cert diff; write nothing (default)\n");
    printf("  --write            Apply changes to certificates.json + Neon\n");
    printf("  --repair-tbs       Also detect+rewrite cert.tbs_entry when it\n");
    printf("                     doesn't match the canonical leaf bytes in\n");
    printf("                     the tree (recovers from the fork-after-accept\n");
    printf("                     duplicate-enrollment corruption — TODO #57).\n");
    printf("  -v, --verbose      Print full sig hex on each STALE entry\n");
    printf("  -h, --help         Show this help\n\n");
    printf("Exit codes: 0 = success, 2 = stale entries found in dry-run,\n");
    printf("            1 = fatal error.\n");
}

/* Build a cosignature JSON object in the same shape as
 * mtc_http.c:1068-1090 and mtc_bootstrap.c:666-688. */
static struct json_object *build_cosig(const char *cosigner_id,
                                       const char *log_id,
                                       int start, int end,
                                       const char *subtree_hash_hex,
                                       const char *sig_hex)
{
    struct json_object *co = json_object_new_object();
    json_object_object_add(co, "cosigner_id",  json_object_new_string(cosigner_id));
    json_object_object_add(co, "log_id",       json_object_new_string(log_id));
    json_object_object_add(co, "start",        json_object_new_int(start));
    json_object_object_add(co, "end",          json_object_new_int(end));
    json_object_object_add(co, "subtree_hash", json_object_new_string(subtree_hash_hex));
    json_object_object_add(co, "signature",    json_object_new_string(sig_hex));
    json_object_object_add(co, "algorithm",    json_object_new_string("ML-DSA-87"));
    return co;
}

/* Rebuild a tbs_entry-shaped JSON object from the canonical leaf bytes
 * stored in the tree.  The leaf payload format produced by
 * mtc_bootstrap.c is `0x01 || alphabetical-keyed JSON` with the keys
 * renamed (`spk_algorithm`, `spk_hash`).  This reverses the renaming
 * to produce the cert.standalone_certificate.tbs_entry shape.  Returns
 * NULL on any failure; caller owns the result. */
static struct json_object *tbs_from_entry_bytes(const uint8_t *entry, int entry_sz)
{
    if (!entry || entry_sz < 2 || entry[0] != 0x01) return NULL;

    char *buf = (char *)malloc((size_t)entry_sz);
    if (!buf) return NULL;
    memcpy(buf, entry + 1, (size_t)(entry_sz - 1));
    buf[entry_sz - 1] = '\0';

    struct json_object *src = json_tokener_parse(buf);
    free(buf);
    if (!src) return NULL;

    struct json_object *tbs = json_object_new_object();
    struct json_object *v;

    if (json_object_object_get_ex(src, "subject", &v))
        json_object_object_add(tbs, "subject", json_object_get(v));
    if (json_object_object_get_ex(src, "spk_algorithm", &v))
        json_object_object_add(tbs, "subject_public_key_algorithm",
                               json_object_get(v));
    if (json_object_object_get_ex(src, "spk_hash", &v))
        json_object_object_add(tbs, "subject_public_key_hash",
                               json_object_get(v));
    if (json_object_object_get_ex(src, "not_before", &v))
        json_object_object_add(tbs, "not_before", json_object_get(v));
    if (json_object_object_get_ex(src, "not_after", &v))
        json_object_object_add(tbs, "not_after", json_object_get(v));
    if (json_object_object_get_ex(src, "extensions", &v))
        json_object_object_add(tbs, "extensions", json_object_get(v));

    json_object_put(src);
    return tbs;
}

int main(int argc, char *argv[])
{
    const char *data_dir  = "/home/ubuntu/.mtc-ca-data";
    const char *tokenpath = NULL;
    const char *ca_name   = "MTC-CA-C";
    const char *log_id    = "32473.2";
    int  write_mode = 0;  /* 0 = dry-run (default), 1 = apply */
    int  verbose    = 0;
    int  repair_tbs = 0;  /* If set, also rewrite cert.tbs_entry from the
                           * canonical leaf bytes when they diverge.
                           * Targets the corruption pattern documented in
                           * TODO #57 (fork-after-accept duplicate
                           * enrollment writes mismatched cert/leaf
                           * pairs).                                       */
    int  i;

    MtcStore store;
    int scanned = 0, stale = 0, applied = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc)
            data_dir = argv[++i];
        else if (strcmp(argv[i], "--tokenpath") == 0 && i + 1 < argc)
            tokenpath = argv[++i];
        else if (strcmp(argv[i], "--ca-name") == 0 && i + 1 < argc)
            ca_name = argv[++i];
        else if (strcmp(argv[i], "--log-id") == 0 && i + 1 < argc)
            log_id = argv[++i];
        else if (strcmp(argv[i], "--dry-run") == 0)
            write_mode = 0;
        else if (strcmp(argv[i], "--write") == 0 || strcmp(argv[i], "--apply") == 0)
            write_mode = 1;
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "--repair-tbs") == 0)
            repair_tbs = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    mtc_log_init(NULL, MTC_LOG_WARN);
    wolfSSL_Init();

    if (tokenpath) mtc_db_set_tokenpath(tokenpath);

    if (mtc_store_init(&store, data_dir, ca_name, log_id) != 0) {
        fprintf(stderr, "fatal: mtc_store_init failed\n");
        return 1;
    }

    printf("Mode:       %s\n", write_mode ? "WRITE (applying)" : "DRY-RUN");
    printf("Data dir:   %s\n", data_dir);
    printf("Tree size:  %d\n", store.tree.size);
    /* Phase 3: certs are no longer mirrored in RAM; the count comes
     * from the DB.  Use a single COUNT(*) for the header line. */
    {
        int n = -1;
        PGresult *r = PQexec(store.db,
            "SELECT COUNT(*) FROM mtc_certificates");
        if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
            n = atoi(PQgetvalue(r, 0, 0));
        PQclear(r);
        printf("Cert count: %d\n", n);
    }
    /* Public key is ML-DSA-87 raw (2592 B); show a 16-byte prefix so
     * the line stays readable.  Full pubkey is available over /ca/public-key. */
    printf("CA key:     loaded (pub=");
    { char h[33]; to_hex(store.ca_pub_key, 16, h); printf("%s…  %dB raw)\n", h, store.ca_pub_key_sz); }
    printf("Neon:       %s\n\n", store.use_db ? "connected" : "file-only");

    /* Iterate every stored cert; recompute tree-state fields + cosig.
     * Phase 3: walk the DB instead of an in-memory cert array.  The
     * helper indices[] holds every (sorted) cert index from
     * mtc_certificates, and mtc_store_get_cert pages each through
     * cert_cache + Neon. */
    int *indices = NULL;
    int n_indices = 0;
    {
        PGresult *r = PQexec(store.db,
            "SELECT index FROM mtc_certificates ORDER BY index");
        if (PQresultStatus(r) != PGRES_TUPLES_OK) {
            fprintf(stderr, "fatal: SELECT mtc_certificates failed: %s\n",
                    PQerrorMessage(store.db));
            PQclear(r);
            mtc_store_free(&store);
            return 1;
        }
        n_indices = PQntuples(r);
        indices = (int *)malloc((size_t)n_indices * sizeof(int));
        for (int k = 0; k < n_indices; k++)
            indices[k] = atoi(PQgetvalue(r, k, 0));
        PQclear(r);
    }
    for (int row = 0; row < n_indices; row++) {
        i = indices[row];           /* log index */
        struct json_object *cert = mtc_store_get_cert(&store, i);
        struct json_object *sc;
        struct json_object *old_proof_arr, *old_cosig_arr, *val;
        const char *old_cosig_sig = NULL;
        const char *old_subtree_hash = NULL;
        int old_subtree_start = -1, old_subtree_end = -1;
        int old_proof_count = -1;

        int start = 0;
        int end   = store.tree.size;
        uint8_t subtree_hash_new[MTC_HASH_SIZE];
        char    subtree_hash_hex[MTC_HASH_SIZE * 2 + 1];
        uint8_t *proof_new = NULL;
        int     proof_count_new = 0;
        uint8_t sig_new[DILITHIUM_LEVEL5_SIG_SIZE];
        int     sig_sz_new = 0;
        char    sig_hex_new[DILITHIUM_LEVEL5_SIG_SIZE * 2 + 1];
        int     changed = 0;

        if (!cert) continue;
        scanned++;

        if (!json_object_object_get_ex(cert, "standalone_certificate", &sc)) {
            printf("cert %d: SKIP (no standalone_certificate)\n", i);
            json_object_put(cert);
            continue;
        }

        /* TBS-vs-leaf consistency check (TODO #57 recovery path).
         *
         * Compare the scalar fields in cert.tbs_entry against the same
         * fields in the canonical leaf payload at the cert's
         * stated log index (sc.index).  The cert *array* may or may
         * not be flat-packed — DB load is sparse (NULLs in gaps),
         * file load is compact — so always re-derive the real log
         * index from sc.index.  store.tree.entries[] is always
         * indexed by log index, so once we have the right log index
         * the rest is straightforward.
         *
         * We deliberately don't byte-compare the full re-serialised
         * forms, because nested objects (notably `extensions`) can
         * have keys in different orders between entries.json and
         * certificates.json — same data, but
         * `JSON_C_TO_STRING_PLAIN` honours insertion order, so
         * round-tripped objects can serialise differently.  The
         * fork-after-accept corruption we're targeting (TODO #57)
         * always changes a SCALAR field (not_before, not_after,
         * subject, spk_*), so scalar-only comparison catches it
         * without flagging the spurious extensions-reorder cases. */
        int cert_log_idx = -1;
        {
            struct json_object *idx_val;
            if (json_object_object_get_ex(sc, "index", &idx_val))
                cert_log_idx = json_object_get_int(idx_val);
        }
        if (cert_log_idx >= 0 && cert_log_idx < store.tree.size) {
            struct json_object *cur_tbs = NULL;
            int tbs_divergent = 0;
            uint8_t *ser = NULL;
            int ser_sz = 0;

            if (json_object_object_get_ex(sc, "tbs_entry", &cur_tbs) &&
                mtc_db_load_entry_serialized(store.db, cert_log_idx,
                                              &ser, &ser_sz) == 0) {
                struct json_object *canonical =
                    tbs_from_entry_bytes(ser, ser_sz);
                free(ser);
                ser = NULL;
                if (canonical) {
                    /* Compare scalar fields by their JSON string form. */
                    static const char *scalar_keys[] = {
                        "subject",
                        "subject_public_key_algorithm",
                        "subject_public_key_hash",
                        "not_before",
                        "not_after",
                        NULL
                    };
                    int k;
                    for (k = 0; scalar_keys[k]; k++) {
                        struct json_object *a = NULL, *b = NULL;
                        json_object_object_get_ex(cur_tbs,
                            scalar_keys[k], &a);
                        json_object_object_get_ex(canonical,
                            scalar_keys[k], &b);
                        const char *as = a
                            ? json_object_to_json_string_ext(a,
                                JSON_C_TO_STRING_PLAIN)
                            : "";
                        const char *bs = b
                            ? json_object_to_json_string_ext(b,
                                JSON_C_TO_STRING_PLAIN)
                            : "";
                        if (strcmp(as, bs) != 0) {
                            tbs_divergent = 1;
                            if (!verbose) break;
                            printf("cert %d: TBS DIVERGENT field '%s': "
                                   "cert=%s leaf=%s\n", i,
                                   scalar_keys[k], as, bs);
                        }
                    }

                    if (tbs_divergent) {
                        printf("cert %d: TBS DIVERGENT (scalar fields "
                               "differ from canonical leaf at log "
                               "index %d)\n", cert_log_idx, cert_log_idx);

                        if (repair_tbs && write_mode) {
                            json_object_object_add(sc, "tbs_entry",
                                json_object_get(canonical));
                            printf("        TBS REPAIRED from canonical "
                                   "leaf bytes\n");
                            changed = 1; /* force the recosign path */
                        } else if (!repair_tbs) {
                            printf("        (pass --repair-tbs --write "
                                   "to fix)\n");
                        }
                    }
                    json_object_put(canonical);
                }
            }
        }

        /* Snapshot the old values we care about (still present in memory). */
        if (json_object_object_get_ex(sc, "subtree_start", &val))
            old_subtree_start = json_object_get_int(val);
        if (json_object_object_get_ex(sc, "subtree_end", &val))
            old_subtree_end = json_object_get_int(val);
        if (json_object_object_get_ex(sc, "subtree_hash", &val))
            old_subtree_hash = json_object_get_string(val);
        if (json_object_object_get_ex(sc, "inclusion_proof", &old_proof_arr) &&
            json_object_is_type(old_proof_arr, json_type_array))
            old_proof_count = (int)json_object_array_length(old_proof_arr);
        if (json_object_object_get_ex(sc, "cosignatures", &old_cosig_arr) &&
            json_object_is_type(old_cosig_arr, json_type_array) &&
            json_object_array_length(old_cosig_arr) > 0) {
            struct json_object *first = json_object_array_get_idx(old_cosig_arr, 0);
            if (first && json_object_object_get_ex(first, "signature", &val))
                old_cosig_sig = json_object_get_string(val);
        }

        /* Compute current tree-state values. */
        if (mtc_tiled_tree_subtree_hash(&store.tree, start, end, subtree_hash_new) != 0) {
            printf("cert %d: SKIP (subtree_hash failed)\n", i);
            json_object_put(cert);
            continue;
        }
        to_hex(subtree_hash_new, MTC_HASH_SIZE, subtree_hash_hex);

        if (mtc_tiled_tree_inclusion_proof(&store.tree, i, start, end,
                                     &proof_new, &proof_count_new) != 0) {
            printf("cert %d: SKIP (inclusion_proof failed)\n", i);
            json_object_put(cert);
            continue;
        }

        if (mtc_store_cosign(&store, start, end, sig_new, &sig_sz_new) != 0) {
            printf("cert %d: SKIP (cosign failed)\n", i);
            free(proof_new);
            json_object_put(cert);
            continue;
        }
        to_hex(sig_new, sig_sz_new, sig_hex_new);

        /* Detect whether anything differs. */
        if (old_subtree_start != start) changed = 1;
        if (old_subtree_end   != end)   changed = 1;
        if (!old_subtree_hash || strcmp(old_subtree_hash, subtree_hash_hex) != 0) changed = 1;
        if (old_proof_count != proof_count_new) changed = 1;
        if (!old_cosig_sig || strcmp(old_cosig_sig, sig_hex_new) != 0) changed = 1;
        /* We don't byte-compare every proof hash here — a length change or a
         * subtree_hash change already implies the whole tree-state snapshot
         * needs refreshing.  For matching lengths with identical subtree_hash,
         * the tree structure from [0,end) is the same, so RFC 9162 PATH(i,n)
         * is deterministic and proof bytes will match. */

        if (!changed) {
            printf("cert %d: up-to-date\n", i);
            free(proof_new);
            json_object_put(cert);
            continue;
        }

        stale++;

        printf("cert %d: STALE  ", i);
        if (old_cosig_sig) {
            printf("sig %.16s… → %.16s…  ", old_cosig_sig, sig_hex_new);
        } else {
            printf("sig (missing) → %.16s…  ", sig_hex_new);
        }
        printf("end %d→%d  proof %d→%d\n",
               old_subtree_end, end, old_proof_count, proof_count_new);

        if (verbose) {
            printf("        old sig: %s\n", old_cosig_sig ? old_cosig_sig : "(missing)");
            printf("        new sig: %s\n", sig_hex_new);
            printf("        old subtree_hash: %s\n",
                   old_subtree_hash ? old_subtree_hash : "(missing)");
            printf("        new subtree_hash: %s\n", subtree_hash_hex);
        }

        if (write_mode) {
            struct json_object *new_proof_arr;
            struct json_object *new_cosig_arr;
            struct json_object *new_cosig;
            int j;

            /* Build new inclusion_proof array */
            new_proof_arr = json_object_new_array();
            for (j = 0; j < proof_count_new; j++) {
                char hh[MTC_HASH_SIZE * 2 + 1];
                to_hex(proof_new + j * MTC_HASH_SIZE, MTC_HASH_SIZE, hh);
                json_object_array_add(new_proof_arr, json_object_new_string(hh));
            }

            /* Build new cosignatures array */
            new_cosig = build_cosig(store.cosigner_id, store.log_id,
                                    start, end, subtree_hash_hex,
                                    sig_hex_new);
            new_cosig_arr = json_object_new_array();
            json_object_array_add(new_cosig_arr, new_cosig);

            /* Overwrite fields inside sc (json_object_object_add replaces) */
            json_object_object_add(sc, "subtree_start",
                json_object_new_int(start));
            json_object_object_add(sc, "subtree_end",
                json_object_new_int(end));
            json_object_object_add(sc, "subtree_hash",
                json_object_new_string(subtree_hash_hex));
            json_object_object_add(sc, "inclusion_proof", new_proof_arr);
            json_object_object_add(sc, "cosignatures", new_cosig_arr);

            /* Persist to DB if connected. */
            if (store.use_db && store.db) {
                const char *cert_str =
                    json_object_to_json_string_ext(cert, JSON_C_TO_STRING_PLAIN);
                if (mtc_db_save_certificate(store.db, i, cert_str) != 0) {
                    fprintf(stderr, "  WARN: DB save_certificate failed for %d\n", i);
                }
            }

            applied++;
            printf("        APPLIED\n");
        }

        free(proof_new);
        json_object_put(cert);
    }
    free(indices);

    /* Phase 3: file persistence retired.  Per-cert DB writes happened
     * inline above; nothing else to flush. */

    printf("\nSummary: scanned=%d  stale=%d  applied=%d  (%s)\n",
           scanned, stale, applied,
           write_mode ? "write mode" : "dry-run");
    if (write_mode && applied > 0) {
        printf("Recommend: sudo systemctl restart mtc-ca (to reload repaired state).\n");
    }

    mtc_store_free(&store);
    wolfSSL_Cleanup();
    mtc_log_close();

    if (!write_mode && stale > 0) return 2;
    return 0;
}
