/*
 * fips-manifest-list — show contents of the FIPS-manifest log.
 *
 * Joins mtc_fips_manifest_entries against mtc_log_entries (for
 * tbs_data) and mtc_revocations (for the publisher cert's revocation
 * status).  Read-only; talks directly to the Neon database via
 * MERKLE_NEON (env var or first MERKLE_NEON= line under --tokenpath
 * file, default ~/.env).
 *
 * Usage:
 *   fips-manifest-list                       # table view, all rows
 *   fips-manifest-list --package P           # filter by package
 *   fips-manifest-list --publisher D
 *   fips-manifest-list --version V
 *   fips-manifest-list --limit N             # default 50
 *   fips-manifest-list --json                # emit JSON instead of table
 *   fips-manifest-list <log_index>           # detail view for one entry
 *   fips-manifest-list --tokenpath FILE      # default $HOME/.env
 */

#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libpq-fe.h>

#define die(fmt, ...) do { \
    fprintf(stderr, "fips-manifest-list: " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

/* Pull MERKLE_NEON: prefer the env var; fall back to an explicit
 * --tokenpath file (or $HOME/.env).  Same convention mtc_rebuild_tiles
 * uses; kept inline here to avoid pulling in the full mtc_db module. */
static char *load_merkle_neon(const char *tokenpath)
{
    const char *e = getenv("MERKLE_NEON");
    if (e && e[0]) return strdup(e);

    char default_path[1024];
    if (!tokenpath) {
        const char *home = getenv("HOME");
        if (!home) home = "/root";
        snprintf(default_path, sizeof(default_path), "%s/.env", home);
        tokenpath = default_path;
    }
    FILE *fp = fopen(tokenpath, "r");
    if (!fp) die("cannot read tokenpath %s", tokenpath);
    char line[4096];
    char *result = NULL;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "MERKLE_NEON", 11) != 0) continue;
        p += 11;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '=') continue;
        p++;
        if (*p == '"') {
            p++;
            char *q = strchr(p, '"');
            if (!q) continue;
            *q = 0;
        } else {
            char *q = p;
            while (*q && *q != '\n' && *q != '\r' && *q != ' ' && *q != '\t')
                q++;
            *q = 0;
        }
        result = strdup(p);
        break;
    }
    fclose(fp);
    if (!result) die("MERKLE_NEON not found in env or %s", tokenpath);
    return result;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [<log_index>] [options]\n"
        "  --package P         Filter by package\n"
        "  --publisher D       Filter by publisher\n"
        "  --version V         Filter by version\n"
        "  --limit N           Cap rows (default 50, 0 = no limit)\n"
        "  --json              Emit JSON instead of table\n"
        "  --tokenpath FILE    .env with MERKLE_NEON (default: $HOME/.env)\n"
        "  -v, --verbose       Show extra fields in detail view\n"
        "  -h, --help\n",
        prog);
    exit(2);
}

static int g_verbose = 0;

/* ---------- list view ---------- */

static void render_table(PGresult *r)
{
    int n = PQntuples(r);
    int wi[5] = { 8, 25, 16, 16, 12 };  /* idx | submitted_at | publisher | package | version */
    int rc[n];
    for (int i = 0; i < n; i++) rc[i] = (PQgetisnull(r, i, 5) ? 0 : 1);

    /* Compute column widths */
    for (int i = 0; i < n; i++) {
        int l;
        l = (int)strlen(PQgetvalue(r, i, 0)); if (l > wi[0]) wi[0] = l;
        l = (int)strlen(PQgetvalue(r, i, 1)); if (l > wi[1]) wi[1] = l;
        l = (int)strlen(PQgetvalue(r, i, 2)); if (l > wi[2]) wi[2] = l;
        l = (int)strlen(PQgetvalue(r, i, 3)); if (l > wi[3]) wi[3] = l;
        l = (int)strlen(PQgetvalue(r, i, 4)); if (l > wi[4]) wi[4] = l;
    }
    printf("%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
           wi[0], "log_index", wi[1], "submitted_at",
           wi[2], "publisher", wi[3], "package", wi[4], "version", "rev");
    for (int i = 0; i < (wi[0] + wi[1] + wi[2] + wi[3] + wi[4] + 13); i++) putchar('-');
    putchar('\n');
    for (int i = 0; i < n; i++) {
        printf("%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
               wi[0], PQgetvalue(r, i, 0),
               wi[1], PQgetvalue(r, i, 1),
               wi[2], PQgetvalue(r, i, 2),
               wi[3], PQgetvalue(r, i, 3),
               wi[4], PQgetvalue(r, i, 4),
               rc[i] ? "REVOKED" : "");
    }
    if (n == 0) puts("(no rows)");
    else printf("\n%d row%s\n", n, n == 1 ? "" : "s");
}

static void render_json_list(PGresult *r)
{
    int n = PQntuples(r);
    struct json_object *arr = json_object_new_array();
    for (int i = 0; i < n; i++) {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "log_index",
            json_object_new_int(atoi(PQgetvalue(r, i, 0))));
        json_object_object_add(o, "submitted_at",
            json_object_new_string(PQgetvalue(r, i, 1)));
        json_object_object_add(o, "publisher",
            json_object_new_string(PQgetvalue(r, i, 2)));
        json_object_object_add(o, "package",
            json_object_new_string(PQgetvalue(r, i, 3)));
        json_object_object_add(o, "version",
            json_object_new_string(PQgetvalue(r, i, 4)));
        json_object_object_add(o, "publisher_cert_revoked",
            json_object_new_boolean(!PQgetisnull(r, i, 5)));
        json_object_array_add(arr, o);
    }
    printf("%s\n", json_object_to_json_string_ext(arr,
        JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_put(arr);
}

/* ---------- detail view ---------- */

static void render_detail(PGconn *c, int log_index)
{
    char ix[32];
    snprintf(ix, sizeof(ix), "%d", log_index);
    const char *p[1] = { ix };
    PGresult *r = PQexecParams(c,
        "SELECT m.log_index, m.publisher, m.package, m.version, m.submitted_at,"
        "       le.tbs_data,"
        "       (SELECT 1 FROM mtc_revocations rv "
        "          WHERE rv.cert_index = (le.tbs_data->>'publisher_cert_index')::int "
        "          LIMIT 1) AS revoked,"
        "       (le.tbs_data->>'publisher_cert_index')::int AS pub_cert_idx "
        "FROM mtc_fips_manifest_entries m "
        "JOIN mtc_log_entries le ON le.index = m.log_index "
        "WHERE m.log_index = $1",
        1, NULL, p, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_TUPLES_OK)
        die("detail query failed: %s", PQerrorMessage(c));
    if (PQntuples(r) == 0) {
        printf("no manifest at log_index %d\n", log_index);
        PQclear(r);
        return;
    }

    const char *tbs_str = PQgetvalue(r, 0, 5);
    struct json_object *tbs = json_tokener_parse(tbs_str);

    printf("log_index:            %s\n", PQgetvalue(r, 0, 0));
    printf("publisher:            %s\n", PQgetvalue(r, 0, 1));
    printf("package:              %s\n", PQgetvalue(r, 0, 2));
    printf("version:              %s\n", PQgetvalue(r, 0, 3));
    printf("submitted_at:         %s\n", PQgetvalue(r, 0, 4));
    printf("publisher_cert_index: %s%s\n", PQgetvalue(r, 0, 7),
           PQgetisnull(r, 0, 6) ? "" : "  (cert REVOKED)");

    if (tbs) {
        struct json_object *v;
        if (json_object_object_get_ex(tbs, "alg", &v))
            printf("alg:                  %s\n", json_object_get_string(v));
        if (json_object_object_get_ex(tbs, "schema_version", &v))
            printf("schema_version:       %d\n", json_object_get_int(v));
        if (json_object_object_get_ex(tbs, "not_before", &v))
            printf("not_before:           %.0f\n", json_object_get_double(v));
        if (json_object_object_get_ex(tbs, "expires", &v))
            printf("expires:              %.0f\n", json_object_get_double(v));
        if (json_object_object_get_ex(tbs, "git_commit", &v))
            printf("git_commit:           %s\n", json_object_get_string(v));
        struct json_object *files;
        if (json_object_object_get_ex(tbs, "files", &files))
            printf("files:                %zu\n",
                   (size_t)json_object_array_length(files));

        if (g_verbose && files) {
            int nf = json_object_array_length(files);
            for (int i = 0; i < nf; i++) {
                struct json_object *fe = json_object_array_get_idx(files, i);
                struct json_object *p_v, *h_v;
                json_object_object_get_ex(fe, "path", &p_v);
                json_object_object_get_ex(fe, "sha256", &h_v);
                printf("  [%3d] %.16s...  %s\n", i,
                       json_object_get_string(h_v),
                       json_object_get_string(p_v));
            }
        }
        json_object_put(tbs);
    }
    PQclear(r);
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    const char *filter_package = NULL;
    const char *filter_publisher = NULL;
    const char *filter_version = NULL;
    const char *tokenpath = NULL;
    int limit = 50;
    int as_json = 0;
    int detail_index = -1;

    static struct option opts[] = {
        {"package",    required_argument, 0, 'p'},
        {"publisher",  required_argument, 0, 'P'},
        {"version",    required_argument, 0, 'V'},
        {"limit",      required_argument, 0, 'l'},
        {"json",       no_argument,       0, 'j'},
        {"tokenpath",  required_argument, 0, 't'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "p:P:V:l:jt:vh", opts, NULL)) != -1) {
        switch (c) {
            case 'p': filter_package   = optarg; break;
            case 'P': filter_publisher = optarg; break;
            case 'V': filter_version   = optarg; break;
            case 'l': limit = atoi(optarg);      break;
            case 'j': as_json = 1;               break;
            case 't': tokenpath = optarg;        break;
            case 'v': g_verbose = 1;             break;
            default:  usage(argv[0]);
        }
    }
    if (optind < argc) {
        char *end;
        long v = strtol(argv[optind], &end, 10);
        if (*end != 0 || v < 0) usage(argv[0]);
        detail_index = (int)v;
    }

    char *conninfo = load_merkle_neon(tokenpath);
    PGconn *conn = PQconnectdb(conninfo);
    free(conninfo);
    if (PQstatus(conn) != CONNECTION_OK)
        die("PQconnectdb: %s", PQerrorMessage(conn));

    if (detail_index >= 0) {
        render_detail(conn, detail_index);
    } else {
        /* Build query with optional filters.  Use $1..$3 placeholders so we
         * never concatenate user-controlled strings into SQL. */
        char sql[2048];
        const char *params[3] = {0};
        int nparams = 0;
        int n = snprintf(sql, sizeof(sql),
            "SELECT m.log_index, "
            "       to_char(m.submitted_at AT TIME ZONE 'UTC', "
            "               'YYYY-MM-DD HH24:MI:SS'), "
            "       m.publisher, m.package, m.version,"
            "       (SELECT 1 FROM mtc_revocations rv "
            "          JOIN mtc_log_entries le ON le.index = m.log_index "
            "          WHERE rv.cert_index = "
            "            (le.tbs_data->>'publisher_cert_index')::int "
            "          LIMIT 1) "
            "FROM mtc_fips_manifest_entries m "
            "WHERE 1=1");
        if (filter_publisher) {
            n += snprintf(sql + n, sizeof(sql) - n,
                          " AND m.publisher = $%d", ++nparams);
            params[nparams - 1] = filter_publisher;
        }
        if (filter_package) {
            n += snprintf(sql + n, sizeof(sql) - n,
                          " AND m.package = $%d", ++nparams);
            params[nparams - 1] = filter_package;
        }
        if (filter_version) {
            n += snprintf(sql + n, sizeof(sql) - n,
                          " AND m.version = $%d", ++nparams);
            params[nparams - 1] = filter_version;
        }
        n += snprintf(sql + n, sizeof(sql) - n,
                      " ORDER BY m.log_index DESC");
        if (limit > 0)
            snprintf(sql + n, sizeof(sql) - n, " LIMIT %d", limit);

        PGresult *r = PQexecParams(conn, sql, nparams, NULL, params,
                                   NULL, NULL, 0);
        if (PQresultStatus(r) != PGRES_TUPLES_OK)
            die("query failed: %s", PQerrorMessage(conn));
        if (as_json) render_json_list(r);
        else render_table(r);
        PQclear(r);
    }

    PQfinish(conn);
    return 0;
}
