/******************************************************************************
 * File:        cleanup-tpm.c
 * Purpose:     Surgically remove a single log index from postWolf state.
 *
 * Description:
 *   The test rig leaves sacrificial bob-revoke-test-<timestamp> leaves in
 *   the production log every time the matrix runs.  This tool cleans up
 *   one such index by removing all of:
 *
 *     - mtc_log_entries        WHERE index      = N
 *     - mtc_certificates       WHERE index      = N
 *     - mtc_revocations        WHERE cert_index = N
 *     - mtc_enrollment_nonces  WHERE ca_index   = N
 *     - mtc_public_keys        rows whose name == any matching ~/.TPM/<dir>
 *     - any ~/.TPM/<dir>/      whose `index` file contains N
 *     - ~/.TPM/peers/<N>/      if present
 *
 *   The mtc-ca.service is stopped before mutation and restarted after,
 *   so the parent's in-memory tree gets rebuilt from the post-deletion
 *   DB state.
 *
 * WARNING — Merkle integrity:
 *   Removing a log entry invalidates every cosigned proof a verifier
 *   may have cached for that entry, AND if the deleted index is not
 *   the current tail it leaves a hole that the rebuild loop will paper
 *   over silently (mtc_store_load appends entries in ORDER BY index, so
 *   subsequent indices end up at the wrong tree position).  This tool
 *   is a development / test cleanup aid; do NOT run it on a production
 *   log against an index any real verifier has touched.
 *
 * Build:  make cleanup-tpm
 *
 * Usage:
 *   cleanup-tpm --index N [options]
 *
 *   --index N            Log index to remove (must be >= 1; genesis is
 *                        permanent).
 *   --tpm-dir DIR        Client TPM root (default: $HOME/.TPM).
 *   --tokenpath FILE     .env file to read MERKLE_NEON from (default:
 *                        $HOME/.env).
 *   --dry-run            Print the plan; mutate nothing.
 *   --yes                Skip the interactive "type yes" confirmation.
 *   --no-restart         Skip systemctl stop/start (caller manages
 *                        service lifecycle separately).
 *   -h, --help           Show this help.
 *
 * Exit codes:
 *   0 — success
 *   1 — DB / filesystem / systemctl failure during execution
 *   2 — invocation / argument error
 *
 * Created: 2026-05-07
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <json-c/json.h>
#include <libpq-fe.h>

#include "mtc_db.h"

static int g_dry_run   = 0;
static int g_yes       = 0;
static int g_no_restart = 0;

typedef struct {
    char name[256];   /* basename of ~/.TPM/<X>/                       */
    char path[1024];  /* full path                                     */
} tpm_match_t;

static void usage(const char *prog)
{
    printf("Surgically remove a log index from postWolf state.\n\n");
    printf("Usage: %s --index N [options]\n\n", prog);
    printf("  --index N            Log index to remove (>= 1).\n");
    printf("  --tpm-dir DIR        Client TPM root (default: $HOME/.TPM).\n");
    printf("  --tokenpath FILE     .env with MERKLE_NEON "
                                  "(default: $HOME/.env).\n");
    printf("  --dry-run            Print the plan; mutate nothing.\n");
    printf("  --yes                Skip the interactive confirmation.\n");
    printf("  --no-restart         Skip systemctl stop/start.\n");
    printf("  -h, --help           Show this help.\n\n");
    printf("WARNING: removing a log entry invalidates every cosigned proof\n");
    printf("a verifier may have cached, and a non-tail removal leaves a\n");
    printf("Merkle-tree position hole.  Use only on test/junk indices.\n");
}

static int read_index_file(const char *path)
{
    FILE *f = fopen(path, "r");
    int idx = -1;
    if (!f) return -1;
    if (fscanf(f, "%d", &idx) != 1) idx = -1;
    fclose(f);
    return idx;
}

static int rm_rf(const char *path)
{
    if (g_dry_run) {
        printf("  [dry-run] rm -rf -- '%s'\n", path);
        return 0;
    }
    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", path);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        fprintf(stderr, "cleanup-tpm: path too long: %s\n", path);
        return -1;
    }
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "cleanup-tpm: rm -rf '%s' failed (rc=%d)\n",
                path, rc);
        return -1;
    }
    printf("  rm -rf -- %s\n", path);
    return 0;
}

static int run_systemctl(const char *verb)
{
    if (g_no_restart) {
        printf("  [skip --no-restart] sudo systemctl %s mtc-ca.service\n",
               verb);
        return 0;
    }
    if (g_dry_run) {
        printf("  [dry-run] sudo systemctl %s mtc-ca.service\n", verb);
        return 0;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo systemctl %s mtc-ca.service", verb);
    printf("  exec: %s\n", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr,
                "cleanup-tpm: systemctl %s failed (rc=%d)\n", verb, rc);
        return -1;
    }
    return 0;
}

static int neon_delete(PGconn *conn, const char *label,
                       const char *sql, const char *param)
{
    if (g_dry_run) {
        printf("  [dry-run] [neon] %s param='%s'\n", label, param);
        return 0;
    }
    const char *params[1] = {param};
    PGresult *res = PQexecParams(conn, sql, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "cleanup-tpm: %s failed: %s",
                label, PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    int affected = atoi(PQcmdTuples(res));
    PQclear(res);
    printf("  [neon] %s param='%s' -> %d row(s)\n", label, param, affected);
    return 0;
}

static int walk_tpm_for_index(const char *tpm_dir, int target_idx,
                              tpm_match_t **out, int *out_count)
{
    DIR *d = opendir(tpm_dir);
    struct dirent *de;
    int cap = 16, n = 0;
    tpm_match_t *arr;

    *out = NULL;
    *out_count = 0;

    if (!d) {
        fprintf(stderr, "cleanup-tpm: cannot open %s: %s\n",
                tpm_dir, strerror(errno));
        return -1;
    }

    arr = (tpm_match_t *)malloc(sizeof(*arr) * cap);
    if (!arr) { closedir(d); return -1; }

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;        /* . .. hidden */
        if (strcmp(de->d_name, "peers") == 0) continue;

        char idx_path[1024];
        snprintf(idx_path, sizeof(idx_path), "%s/%s/index",
                 tpm_dir, de->d_name);

        int idx = read_index_file(idx_path);
        if (idx == target_idx) {
            if (n >= cap) {
                cap *= 2;
                tpm_match_t *tmp =
                    (tpm_match_t *)realloc(arr, sizeof(*arr) * cap);
                if (!tmp) { free(arr); closedir(d); return -1; }
                arr = tmp;
            }
            snprintf(arr[n].name, sizeof(arr[n].name), "%s", de->d_name);
            snprintf(arr[n].path, sizeof(arr[n].path), "%s/%s",
                     tpm_dir, de->d_name);
            n++;
        }
    }
    closedir(d);

    *out = arr;
    *out_count = n;
    return 0;
}

int main(int argc, char *argv[])
{
    int target_idx = -1;
    const char *tpm_dir_arg = NULL;
    const char *tokenpath  = NULL;
    char tpm_dir[512];
    char default_tokenpath[512];
    int i, k;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--index") == 0 && i + 1 < argc) {
            target_idx = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--tpm-dir") == 0 && i + 1 < argc) {
            tpm_dir_arg = argv[++i];
        }
        else if (strcmp(argv[i], "--tokenpath") == 0 && i + 1 < argc) {
            tokenpath = argv[++i];
        }
        else if (strcmp(argv[i], "--dry-run") == 0) {
            g_dry_run = 1;
        }
        else if (strcmp(argv[i], "--yes") == 0) {
            g_yes = 1;
        }
        else if (strcmp(argv[i], "--no-restart") == 0) {
            g_no_restart = 1;
        }
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "cleanup-tpm: unknown argument '%s'\n",
                    argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (target_idx <= 0) {
        fprintf(stderr,
            "cleanup-tpm: --index N is required and must be >= 1 "
            "(refusing to touch the genesis entry at index 0).\n");
        return 2;
    }

    /* Resolve TPM dir */
    if (tpm_dir_arg) {
        snprintf(tpm_dir, sizeof(tpm_dir), "%s", tpm_dir_arg);
    } else {
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr,
                    "cleanup-tpm: HOME not set; pass --tpm-dir DIR.\n");
            return 2;
        }
        snprintf(tpm_dir, sizeof(tpm_dir), "%s/.TPM", home);
    }

    /* Resolve tokenpath */
    if (!tokenpath) {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(default_tokenpath, sizeof(default_tokenpath),
                     "%s/.env", home);
            tokenpath = default_tokenpath;
        }
    }
    if (tokenpath) mtc_db_set_tokenpath(tokenpath);

    /* Connect to Neon */
    PGconn *conn = mtc_db_connect();
    if (!conn) {
        fprintf(stderr,
                "cleanup-tpm: cannot connect to Neon DB.  "
                "Set MERKLE_NEON or use --tokenpath.\n");
        return 1;
    }

    /* Look up cert at target_idx to learn its subject (for the plan) */
    char subject[256] = {0};
    {
        struct json_object *cert =
            mtc_db_load_certificate(conn, target_idx);
        if (cert) {
            struct json_object *sc, *tbs, *subj_v;
            if (json_object_object_get_ex(cert,
                    "standalone_certificate", &sc) &&
                json_object_object_get_ex(sc, "tbs_entry", &tbs) &&
                json_object_object_get_ex(tbs, "subject", &subj_v)) {
                const char *s = json_object_get_string(subj_v);
                if (s) snprintf(subject, sizeof(subject), "%s", s);
            }
            json_object_put(cert);
        }
    }

    /* Walk TPM for any dir with `index` file == target_idx */
    tpm_match_t *matches = NULL;
    int n_matches = 0;
    if (walk_tpm_for_index(tpm_dir, target_idx, &matches, &n_matches) != 0) {
        PQfinish(conn);
        return 1;
    }

    /* Peer cache */
    char peers_path[1024];
    snprintf(peers_path, sizeof(peers_path),
             "%s/peers/%d", tpm_dir, target_idx);
    struct stat st;
    int has_peers = (stat(peers_path, &st) == 0);

    /* Print plan */
    printf("=== cleanup-tpm plan: index %d ===\n", target_idx);
    if (subject[0])
        printf("  cert subject: '%s'\n", subject);
    else
        printf("  cert subject: (no row in mtc_certificates "
               "for index %d)\n", target_idx);
    printf("  ~/.TPM dirs to remove: %d\n", n_matches);
    for (k = 0; k < n_matches; k++)
        printf("    - %s   (mtc_public_keys.name='%s')\n",
               matches[k].path, matches[k].name);
    if (has_peers)
        printf("    - %s   (peer cache)\n", peers_path);
    printf("  Neon deletions:\n");
    printf("    - mtc_log_entries       WHERE index      = %d\n",
           target_idx);
    printf("    - mtc_certificates      WHERE index      = %d\n",
           target_idx);
    printf("    - mtc_revocations       WHERE cert_index = %d\n",
           target_idx);
    printf("    - mtc_enrollment_nonces WHERE ca_index   = %d\n",
           target_idx);
    for (k = 0; k < n_matches; k++)
        printf("    - mtc_public_keys       WHERE key_name = '%s'\n",
               matches[k].name);
    if (g_no_restart)
        printf("  Service: NOT touched (--no-restart)\n");
    else
        printf("  Service: stop mtc-ca.service, mutate, start "
               "mtc-ca.service\n");
    printf("\n");
    printf("WARNING: removing a log entry invalidates cosigned "
           "proofs covering it.\n");
    printf("Use only on test/junk indices.\n\n");

    if (g_dry_run) {
        printf("=== dry-run; no changes made ===\n");
        free(matches);
        PQfinish(conn);
        return 0;
    }

    /* Confirm */
    if (!g_yes) {
        char buf[16];
        printf("Type 'yes' to proceed: ");
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin) ||
            strncmp(buf, "yes", 3) != 0 ||
            (buf[3] != '\n' && buf[3] != '\0')) {
            printf("aborted\n");
            free(matches);
            PQfinish(conn);
            return 1;
        }
    }

    /* Stop service */
    if (run_systemctl("stop") != 0) {
        free(matches);
        PQfinish(conn);
        return 1;
    }

    /* Delete from Neon — Neon connection is to hosted Postgres, so
     * stopping mtc-ca.service has no effect on it. */
    char idx_str[16];
    snprintf(idx_str, sizeof(idx_str), "%d", target_idx);

    int rc = 0;
    rc |= neon_delete(conn, "DELETE mtc_log_entries",
        "DELETE FROM mtc_log_entries WHERE index = $1", idx_str);
    rc |= neon_delete(conn, "DELETE mtc_certificates",
        "DELETE FROM mtc_certificates WHERE index = $1", idx_str);
    rc |= neon_delete(conn, "DELETE mtc_revocations",
        "DELETE FROM mtc_revocations WHERE cert_index = $1", idx_str);
    rc |= neon_delete(conn, "DELETE mtc_enrollment_nonces",
        "DELETE FROM mtc_enrollment_nonces WHERE ca_index = $1", idx_str);
    for (k = 0; k < n_matches; k++)
        rc |= neon_delete(conn, "DELETE mtc_public_keys",
            "DELETE FROM mtc_public_keys WHERE key_name = $1",
            matches[k].name);

    /* Remove TPM dirs */
    for (k = 0; k < n_matches; k++)
        rc |= rm_rf(matches[k].path);
    if (has_peers)
        rc |= rm_rf(peers_path);

    /* Restart service */
    if (run_systemctl("start") != 0) {
        fprintf(stderr,
            "cleanup-tpm: WARNING — Neon and TPM mutated, but "
            "service failed to restart.  Run 'sudo systemctl start "
            "mtc-ca.service' manually.\n");
        free(matches);
        PQfinish(conn);
        return 1;
    }

    if (rc != 0) {
        fprintf(stderr,
            "cleanup-tpm: completed with one or more errors above; "
            "review the log.\n");
        free(matches);
        PQfinish(conn);
        return 1;
    }

    printf("=== cleanup-tpm done: index %d removed ===\n", target_idx);
    free(matches);
    PQfinish(conn);
    return 0;
}
