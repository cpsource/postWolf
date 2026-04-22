/******************************************************************************
 * File:        backfill-pubkey.c
 * Purpose:     Administrative tool — upsert a leaf's or CA's public key into
 *              mtc_public_keys.
 *
 * Description:
 *   The bootstrap enrollment path now auto-persists a peer's public key
 *   to `mtc_public_keys` under the directory-naming convention
 *     `<subject>` or `<subject>-<label>`.
 *   For older identities enrolled before that server change, the pubkey
 *   may be missing or keyed under a stale name — `show-tpm --verify`
 *   reports `pubkey_db=FAIL: public key not in Neon` in that case.
 *
 *   This tool backfills the DB.  It can look the cert up by log index and
 *   auto-derive the key_name + PEM source, or be driven entirely by
 *   explicit flags.
 *
 * Build:  make backfill-pubkey
 *
 * Usage:
 *   backfill-pubkey --index N [--label L] [--pem-file PATH]
 *   backfill-pubkey --key-name NAME --pem-file PATH
 *
 *   --index N        Log index of the cert to backfill.  Used to derive
 *                    the cert's subject.  Requires --data-dir access to
 *                    the mtc store (Postgres via --tokenpath or files).
 *   --label L        Append as `-<label>` suffix to the derived key_name
 *                    (matches bootstrap_leaf's label semantics).
 *   --key-name NAME  Explicit key_name; bypasses log lookup.
 *   --pem-file PATH  Explicit PEM path; default: ~/.TPM/<key_name>/public_key.pem
 *
 *   Supporting options (same defaults as admin_recosign):
 *     --data-dir DIR     (default: /home/ubuntu/.mtc-ca-data)
 *     --tokenpath FILE   (default: /home/ubuntu/.env)
 *     --ca-name NAME     (default: MTC-CA-C)
 *     --log-id ID        (default: 32473.2)
 *     --dry-run          Print what would change; write nothing
 *     -v, --verbose      Echo the PEM bytes being uploaded
 *     -h, --help         Show this help
 *
 * Exit codes:
 *   0  - success
 *   1  - DB or filesystem error
 *   2  - invocation error
 *
 * Created: 2026-04-22
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

#include "mtc_store.h"
#include "mtc_db.h"
#include "mtc_log.h"

static char *read_text(const char *path)
{
    FILE *f = fopen(path, "r");
    long sz;
    char *buf;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static void usage(const char *prog)
{
    printf("backfill-pubkey — upsert a peer's public key into mtc_public_keys.\n\n");
    printf("Usage: %s --index N [--label L] [--pem-file PATH] [options]\n", prog);
    printf("       %s --key-name NAME --pem-file PATH [options]\n\n", prog);
    printf("  --index N          Log index; derives key_name from the cert's subject\n");
    printf("  --label L          Append `-<label>` to the derived key_name\n");
    printf("  --key-name NAME    Explicit key_name (bypasses --index lookup)\n");
    printf("  --pem-file PATH    Explicit PEM path\n");
    printf("                      (default: ~/.TPM/<key_name>/public_key.pem)\n\n");
    printf("  --data-dir DIR     Data directory (default: /home/ubuntu/.mtc-ca-data)\n");
    printf("  --tokenpath FILE   .env for MERKLE_NEON (default: /home/ubuntu/.env)\n");
    printf("  --ca-name NAME     CA name (default: MTC-CA-C)\n");
    printf("  --log-id ID        Log identifier (default: 32473.2)\n");
    printf("  --dry-run          Print, don't write\n");
    printf("  -v, --verbose      Echo the PEM bytes being uploaded\n");
    printf("  -h, --help         Show this help\n");
}

static int derive_key_name_from_index(MtcStore *store, int idx,
                                      const char *label,
                                      char *out, size_t sz)
{
    struct json_object *cert, *sc, *tbs, *val;
    const char *subject = NULL;

    if (idx < 0 || idx >= store->cert_count) {
        fprintf(stderr, "error: index %d outside log range [0, %d)\n",
                idx, store->cert_count);
        return -1;
    }
    cert = store->certificates[idx];
    if (!cert) {
        fprintf(stderr, "error: cert at index %d is NULL\n", idx);
        return -1;
    }
    if (!json_object_object_get_ex(cert, "standalone_certificate", &sc) ||
        !json_object_object_get_ex(sc,   "tbs_entry",               &tbs) ||
        !json_object_object_get_ex(tbs,  "subject",                 &val)) {
        fprintf(stderr, "error: cert %d missing subject in tbs_entry\n", idx);
        return -1;
    }
    subject = json_object_get_string(val);
    if (!subject) return -1;

    if (label && label[0])
        snprintf(out, sz, "%s-%s", subject, label);
    else
        snprintf(out, sz, "%s", subject);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *data_dir  = "/home/ubuntu/.mtc-ca-data";
    const char *tokenpath = "/home/ubuntu/.env";
    const char *ca_name   = "MTC-CA-C";
    const char *log_id    = "32473.2";
    const char *label     = NULL;
    const char *pem_file_arg = NULL;
    const char *key_name_arg = NULL;
    int index_arg = -1;
    int dry_run   = 0;
    int verbose   = 0;
    int rc;
    int i;

    char key_name[256];
    char pem_path[1024];
    char *pem = NULL;
    MtcStore store;
    int store_initialised = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--index") == 0      && i + 1 < argc)
            index_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--label") == 0      && i + 1 < argc)
            label = argv[++i];
        else if (strcmp(argv[i], "--key-name") == 0   && i + 1 < argc)
            key_name_arg = argv[++i];
        else if (strcmp(argv[i], "--pem-file") == 0   && i + 1 < argc)
            pem_file_arg = argv[++i];
        else if (strcmp(argv[i], "--data-dir") == 0   && i + 1 < argc)
            data_dir = argv[++i];
        else if (strcmp(argv[i], "--tokenpath") == 0  && i + 1 < argc)
            tokenpath = argv[++i];
        else if (strcmp(argv[i], "--ca-name") == 0    && i + 1 < argc)
            ca_name = argv[++i];
        else if (strcmp(argv[i], "--log-id") == 0     && i + 1 < argc)
            log_id = argv[++i];
        else if (strcmp(argv[i], "--dry-run") == 0)   dry_run = 1;
        else if (strcmp(argv[i], "-v") == 0 ||
                 strcmp(argv[i], "--verbose") == 0)   verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        }
        else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]); return 2;
        }
    }

    if (index_arg < 0 && !key_name_arg) {
        fprintf(stderr, "error: pass --index N or --key-name NAME\n");
        usage(argv[0]); return 2;
    }
    if (index_arg >= 0 && key_name_arg) {
        fprintf(stderr, "error: --index and --key-name are mutually exclusive\n");
        return 2;
    }

    mtc_log_init(NULL, MTC_LOG_WARN);
    wolfSSL_Init();
    if (tokenpath) mtc_db_set_tokenpath(tokenpath);

    /* --- Resolve key_name --------------------------------------------- */
    if (key_name_arg) {
        snprintf(key_name, sizeof(key_name), "%s", key_name_arg);
    } else {
        if (mtc_store_init(&store, data_dir, ca_name, log_id) != 0) {
            fprintf(stderr, "error: mtc_store_init failed\n");
            return 1;
        }
        store_initialised = 1;
        if (derive_key_name_from_index(&store, index_arg, label,
                                       key_name, sizeof(key_name)) != 0) {
            rc = 1; goto done;
        }
    }

    /* --- Resolve PEM path --------------------------------------------- */
    if (pem_file_arg) {
        snprintf(pem_path, sizeof(pem_path), "%s", pem_file_arg);
    } else {
        const char *home = getenv("HOME");
        if (!home) home = "/home/ubuntu";
        snprintf(pem_path, sizeof(pem_path),
                 "%s/.TPM/%s/public_key.pem", home, key_name);
    }

    pem = read_text(pem_path);
    if (!pem) {
        fprintf(stderr, "error: cannot read PEM from %s: %s\n",
                pem_path, strerror(errno));
        rc = 1; goto done;
    }

    printf("key_name:   %s\n", key_name);
    printf("pem_file:   %s (%zu bytes)\n", pem_path, strlen(pem));
    if (verbose) {
        printf("----- PEM -----\n%s----- end -----\n", pem);
    }
    printf("mode:       %s\n", dry_run ? "DRY-RUN" : "WRITE");

    if (dry_run) {
        printf("\n(dry-run: no changes.)\n");
        rc = 0; goto done;
    }

    /* --- Upsert into Neon --------------------------------------------- */
    {
        PGconn *conn = mtc_db_connect();
        if (!conn) {
            fprintf(stderr, "error: cannot connect to Neon via MERKLE_NEON\n");
            rc = 1; goto done;
        }
        if (mtc_db_save_public_key(conn, key_name, pem) != 0) {
            fprintf(stderr, "error: save_public_key failed\n");
            PQfinish(conn);
            rc = 1; goto done;
        }
        {
            char *back = mtc_db_get_public_key(conn, key_name);
            if (back) {
                printf("readback:   %zu bytes (OK)\n", strlen(back));
                free(back);
            } else {
                fprintf(stderr, "warn: readback returned NULL\n");
            }
        }
        PQfinish(conn);
    }
    printf("\nDone.  /public-key/%s should now resolve from the MTC server.\n",
           key_name);
    rc = 0;

done:
    if (pem) free(pem);
    if (store_initialised) mtc_store_free(&store);
    wolfSSL_Cleanup();
    return rc;
}
