/******************************************************************************
 * File:        migrate-cosigner.c
 * Purpose:     One-shot migration tool — rotate the transparency-log cosigner
 *              from Ed25519 to ML-DSA-87 and re-cosign every stored entry
 *              under the new key.
 *
 * Description:
 *   Run this on the CA server after deploying the post-quantum cosigner build.
 *   The tool:
 *
 *     1. Renames any legacy Ed25519 `ca_key.der` to
 *        `ca_key.der.ed25519.bak` so it can't be accidentally re-read.
 *     2. Triggers the server store's normal init path, which generates a
 *        fresh ML-DSA-87 private key at `ca_key_mldsa.der` when missing.
 *     3. Iterates every stored certificate and re-cosigns it under the
 *        new ML-DSA-87 key, writing the replacement cosignature back
 *        into store->certificates[i] and (in write mode) into the
 *        certificates.json file and the Neon DB.
 *     4. Prints the first 16 bytes of the NEW cosigner pubkey in hex so
 *        the operator can notify existing peers to re-TOFU.
 *
 *   Default mode is --dry-run: it reports per-cert action without
 *   touching persistent state.  Pass --write to actually apply.
 *
 *   Flag-day migration: after this completes, every peer that had the
 *   old Ed25519 cosigner pinned under ~/.TPM/ca-cosigner.pem must delete
 *   that file and re-fetch from the bootstrap port (:8445).  See the
 *   runbook in mtc-keymaster/README-bugsandtodo.md §47.
 *
 * Build:  make migrate-cosigner
 * Usage:  migrate-cosigner [--data-dir DIR] [--tokenpath FILE]
 *                          [--ca-name NAME] [--log-id ID]
 *                          [--dry-run] [--write] [-v] [-h]
 *
 * Created: 2026-04-21
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include "mtc_store.h"
#include "mtc_db.h"
#include "mtc_merkle.h"
#include "mtc_log.h"

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
    printf("migrate-cosigner — rotate the MTC log cosigner from Ed25519 to\n");
    printf("                   ML-DSA-87 and re-cosign every stored entry.\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --data-dir DIR     Data directory (default: /home/ubuntu/.mtc-ca-data)\n");
    printf("  --tokenpath FILE   .env file for MERKLE_NEON (optional)\n");
    printf("  --ca-name NAME     CA name (default: MTC-CA-C)\n");
    printf("  --log-id ID        Log identifier (default: 32473.2)\n");
    printf("  --dry-run          Show what would change, write nothing (default)\n");
    printf("  --write            Apply: rename legacy Ed25519 key, generate new\n");
    printf("                     ML-DSA-87 key, re-cosign every entry in Neon\n");
    printf("  -v, --verbose      Print full sig hex on each re-cosigned entry\n");
    printf("  -h, --help         Show this help\n\n");
    printf("Post-run action: every peer that had the old Ed25519 cosigner pinned\n");
    printf("under ~/.TPM/ca-cosigner.pem must delete that file and re-run\n");
    printf("`show-tpm --verify` to TOFU-pin the new ML-DSA-87 cosigner.\n");
}

static int rename_legacy_ed25519(const char *data_dir, int write_mode)
{
    char old_path[1024];
    char bak_path[1024];
    struct stat st;

    snprintf(old_path, sizeof(old_path), "%s/ca_key.der", data_dir);
    snprintf(bak_path, sizeof(bak_path), "%s/ca_key.der.ed25519.bak", data_dir);

    if (stat(old_path, &st) != 0) {
        printf("Legacy Ed25519 key: not present (no rename needed).\n");
        return 0;
    }
    /* Size heuristic — Ed25519 DER private keys are ~48–60 bytes.
     * ML-DSA-87 DER private keys are ~4900 bytes, so anything <= 128
     * here is certainly the old Ed25519. */
    if ((long)st.st_size > 128) {
        fprintf(stderr,
            "warn: %s exists but is %ld bytes (> 128) — not Ed25519; leaving alone\n",
            old_path, (long)st.st_size);
        return 0;
    }

    printf("Legacy Ed25519 key: %s (%ld B)\n", old_path, (long)st.st_size);
    if (!write_mode) {
        printf("  (dry-run: would rename → %s)\n", bak_path);
        return 0;
    }

    if (rename(old_path, bak_path) != 0) {
        fprintf(stderr, "error: rename %s → %s: %s\n",
                old_path, bak_path, strerror(errno));
        return -1;
    }
    printf("  renamed → %s\n", bak_path);
    return 0;
}

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
    int  write_mode = 0;
    int  verbose    = 0;
    int  i;

    MtcStore store;
    int scanned = 0, rewritten = 0;

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
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    mtc_log_init(NULL, MTC_LOG_WARN);
    wolfSSL_Init();

    if (tokenpath) mtc_db_set_tokenpath(tokenpath);

    printf("Mode:       %s\n", write_mode ? "WRITE (applying)" : "DRY-RUN");
    printf("Data dir:   %s\n\n", data_dir);

    /* --- Phase 1: retire the legacy Ed25519 cosigner key on disk --- */
    if (rename_legacy_ed25519(data_dir, write_mode) != 0)
        return 1;

    /* --- Phase 2: open store (generates ca_key_mldsa.der if missing) --- */
    if (mtc_store_init(&store, data_dir, ca_name, log_id) != 0) {
        fprintf(stderr, "fatal: mtc_store_init failed\n");
        return 1;
    }

    printf("\nNew cosigner key: loaded (pub=");
    { char h[33]; to_hex(store.ca_pub_key, 16, h); printf("%s… %dB ML-DSA-87)\n",
                                                          h, store.ca_pub_key_sz); }
    printf("Tree size:   %d\n", store.tree.size);
    printf("Cert count:  %d\n", store.cert_count);
    printf("Neon:        %s\n\n", store.use_db ? "connected" : "file-only");

    /* --- Phase 3: re-cosign every stored entry under the new key --- */
    for (i = 0; i < store.cert_count; i++) {
        struct json_object *cert = store.certificates[i];
        struct json_object *sc;

        int start = 0;
        int end   = store.tree.size;
        uint8_t subtree_hash_new[MTC_HASH_SIZE];
        char    subtree_hash_hex[MTC_HASH_SIZE * 2 + 1];
        uint8_t *proof_new = NULL;
        int     proof_count_new = 0;
        uint8_t sig_new[DILITHIUM_LEVEL5_SIG_SIZE];
        int     sig_sz_new = 0;
        char    sig_hex_new[DILITHIUM_LEVEL5_SIG_SIZE * 2 + 1];

        if (!cert) continue;
        scanned++;

        if (!json_object_object_get_ex(cert, "standalone_certificate", &sc)) {
            printf("cert %d: SKIP (no standalone_certificate)\n", i);
            continue;
        }

        /* Recompute tree-state fields for the current tree size. */
        mtc_tree_inclusion_proof(&store.tree, i, start, end,
                                 &proof_new, &proof_count_new);
        mtc_tree_subtree_hash(&store.tree, start, end, subtree_hash_new);
        to_hex(subtree_hash_new, MTC_HASH_SIZE, subtree_hash_hex);

        if (mtc_store_cosign(&store, start, end, sig_new, &sig_sz_new) != 0) {
            fprintf(stderr, "cert %d: cosign failed\n", i);
            if (proof_new) free(proof_new);
            continue;
        }
        to_hex(sig_new, sig_sz_new, sig_hex_new);

        printf("cert %d: re-cosigned (sig=%.16s…  %dB)\n",
               i, sig_hex_new, sig_sz_new);
        if (verbose) {
            printf("        full sig: %s\n", sig_hex_new);
        }

        if (write_mode) {
            /* Overwrite inclusion_proof, subtree_*, cosignatures in-place. */
            struct json_object *proof_arr = json_object_new_array();
            int k;
            for (k = 0; k < proof_count_new; k++) {
                char hex[MTC_HASH_SIZE * 2 + 1];
                to_hex(proof_new + k * MTC_HASH_SIZE, MTC_HASH_SIZE, hex);
                json_object_array_add(proof_arr, json_object_new_string(hex));
            }
            json_object_object_add(sc, "inclusion_proof", proof_arr);
            json_object_object_add(sc, "subtree_start",
                json_object_new_int(start));
            json_object_object_add(sc, "subtree_end",
                json_object_new_int(end));
            json_object_object_add(sc, "subtree_hash",
                json_object_new_string(subtree_hash_hex));

            {
                struct json_object *cosig_arr = json_object_new_array();
                json_object_array_add(cosig_arr,
                    build_cosig(store.cosigner_id, store.log_id,
                                start, end, subtree_hash_hex, sig_hex_new));
                json_object_object_add(sc, "cosignatures", cosig_arr);
            }

            /* mtc_store_save() only persists to files; the running server
             * loads from Postgres on restart.  Push each rewritten cert
             * directly into the DB so the next startup sees ML-DSA-87. */
            if (store.use_db && store.db) {
                const char *cert_json_str =
                    json_object_to_json_string(cert);
                if (mtc_db_save_certificate(store.db, i, cert_json_str) != 0) {
                    fprintf(stderr,
                        "cert %d: mtc_db_save_certificate failed\n", i);
                }
            }
            rewritten++;
        }

        if (proof_new) free(proof_new);
    }

    if (write_mode) {
        if (mtc_store_save(&store) != 0) {
            fprintf(stderr, "warn: mtc_store_save returned non-zero — disk "
                    "state may be stale\n");
        } else {
            printf("\nPersisted certificates.json (+ Neon if connected).\n");
        }
    }

    printf("\n%d scanned, %d rewritten (%s).\n",
           scanned, rewritten, write_mode ? "WRITE" : "DRY-RUN");

    printf("\nNext steps:\n");
    printf("  1. systemctl restart mtc-ca.service\n");
    printf("  2. On every peer: rm ~/.TPM/ca-cosigner.pem ; show-tpm --verify\n");
    printf("     (re-TOFUs the ML-DSA-87 cosigner pubkey over port 8445)\n");

    mtc_store_free(&store);
    wolfSSL_Cleanup();
    return 0;
}
