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

int main(int argc, char *argv[])
{
    const char *data_dir  = "/home/ubuntu/.mtc-ca-data";
    const char *tokenpath = NULL;
    const char *ca_name   = "MTC-CA-C";
    const char *log_id    = "32473.2";
    int  write_mode = 0;  /* 0 = dry-run (default), 1 = apply */
    int  verbose    = 0;
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
    printf("Cert count: %d\n", store.cert_count);
    /* Public key is ML-DSA-87 raw (2592 B); show a 16-byte prefix so
     * the line stays readable.  Full pubkey is available over /ca/public-key. */
    printf("CA key:     loaded (pub=");
    { char h[33]; to_hex(store.ca_pub_key, 16, h); printf("%s…  %dB raw)\n", h, store.ca_pub_key_sz); }
    printf("Neon:       %s\n\n", store.use_db ? "connected" : "file-only");

    /* Iterate every stored cert; recompute tree-state fields + cosig. */
    for (i = 0; i < store.cert_count; i++) {
        struct json_object *cert = store.certificates[i];
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
            continue;
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
        if (mtc_tree_subtree_hash(&store.tree, start, end, subtree_hash_new) != 0) {
            printf("cert %d: SKIP (subtree_hash failed)\n", i);
            continue;
        }
        to_hex(subtree_hash_new, MTC_HASH_SIZE, subtree_hash_hex);

        if (mtc_tree_inclusion_proof(&store.tree, i, start, end,
                                     &proof_new, &proof_count_new) != 0) {
            printf("cert %d: SKIP (inclusion_proof failed)\n", i);
            continue;
        }

        if (mtc_store_cosign(&store, start, end, sig_new, &sig_sz_new) != 0) {
            printf("cert %d: SKIP (cosign failed)\n", i);
            free(proof_new);
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
    }

    /* File persistence: one write for the whole updated certificates.json. */
    if (write_mode && applied > 0) {
        if (mtc_store_save(&store) != 0) {
            fprintf(stderr, "WARN: mtc_store_save failed\n");
        } else {
            printf("\ncertificates.json rewritten.\n");
        }
    }

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
