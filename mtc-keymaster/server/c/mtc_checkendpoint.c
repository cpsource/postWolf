/* mtc_checkendpoint.c — AbuseIPDB CHECK endpoint client with optional
 *                       PostgreSQL (Neon) caching.
 *
 * Two public entry points:
 *   mtc_init()            — load API key, optionally connect to DB
 *   mtc_checkendpoint()   — query AbuseIPDB (or DB cache) for an IP
 *
 * See README-abuseipdb.md for API details. */

#include "mtc_checkendpoint.h"
#include "mtc_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <libpq-fe.h>

/* ------------------------------------------------------------------ */
/* Module state                                                        */
/* ------------------------------------------------------------------ */

static char    s_api_key[256]    = {0};
static PGconn *s_conn           = NULL;
static int     s_verbose        = 0;
static int     s_abuse_threshold = 75;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Scan a file for KEY=value.  Returns 1 on success, 0 if not found. */
static int scan_env_for_key(const char *filepath, const char *keyname,
                            char *dst, int dstSz)
{
    FILE *f;
    char line[1024];
    int  prefix_len;

    f = fopen(filepath, "r");
    if (!f) return 0;

    prefix_len = (int)strlen(keyname);

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, keyname, (size_t)prefix_len) == 0 &&
            line[prefix_len] == '=') {
            char *val = line + prefix_len + 1;
            int len;
            /* Strip quotes and newline */
            while (*val == '"' || *val == '\'') val++;
            len = (int)strlen(val);
            while (len > 0 && (val[len-1] == '\n' || val[len-1] == '\r' ||
                   val[len-1] == '"' || val[len-1] == '\''))
                val[--len] = 0;
            snprintf(dst, (size_t)dstSz, "%s", val);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* libcurl write callback — accumulates response into a dynamic buffer. */
struct curl_buf {
    char  *data;
    size_t len;
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    struct curl_buf *buf = (struct curl_buf *)userp;
    char *tmp;

    tmp = (char *)realloc(buf->data, buf->len + total + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/* ------------------------------------------------------------------ */
/* Schema                                                              */
/* ------------------------------------------------------------------ */

static int init_schema(PGconn *conn)
{
    PGresult *res;
    const char *sql =
        "CREATE TABLE IF NOT EXISTS abuseipdb ("
        "  idx SERIAL PRIMARY KEY,"
        "  ipaddr TEXT NOT NULL,"
        "  response JSONB,"
        "  abuse_confidence_score INTEGER NOT NULL,"
        "  requested_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE INDEX IF NOT EXISTS abuseipdb_ipaddr_idx "
        "  ON abuseipdb (ipaddr);";

    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[checkendpoint] schema init failed: %s\n",
                PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/* DB cache                                                            */
/* ------------------------------------------------------------------ */

/* Returns score (0-100) if cached, or -1 if not found / error. */
static int db_cache_lookup(const char *ipaddr)
{
    PGresult *res;
    const char *params[1];
    int score;

    if (!s_conn) return -1;

    params[0] = ipaddr;
    res = PQexecParams(s_conn,
        "SELECT abuse_confidence_score FROM abuseipdb "
        "WHERE ipaddr = $1 ORDER BY requested_at DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    score = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    if (s_verbose)
        printf("[checkendpoint] cache hit for %s -> score %d\n", ipaddr, score);

    return score;
}

/* Insert a result into the cache. Returns 0 on success. */
static int db_cache_insert(const char *ipaddr, const char *json_response,
                           int score)
{
    PGresult *res;
    char score_str[16];
    const char *params[3];

    if (!s_conn) return -1;

    snprintf(score_str, sizeof(score_str), "%d", score);
    params[0] = ipaddr;
    params[1] = json_response;
    params[2] = score_str;

    res = PQexecParams(s_conn,
        "INSERT INTO abuseipdb (ipaddr, response, abuse_confidence_score) "
        "VALUES ($1, $2, $3)",
        3, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[checkendpoint] cache insert failed: %s\n",
                PQerrorMessage(s_conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    if (s_verbose)
        printf("[checkendpoint] cached %s -> score %d\n", ipaddr, score);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void mtc_set_abuse_threshold(int threshold)
{
    s_abuse_threshold = threshold;
}

int mtc_get_abuse_threshold(void)
{
    return s_abuse_threshold;
}

int mtc_init(void)
{
    const char *env;

    /* 1. Load ABUSEIPDB_KEY: env var first, then ~/.env */
    env = getenv("ABUSEIPDB_KEY");
    if (env && *env) {
        snprintf(s_api_key, sizeof(s_api_key), "%s", env);
    } else {
        const char *home = getenv("HOME");
        char path[512];
        if (!home) home = "/tmp";
        snprintf(path, sizeof(path), "%s/.env", home);
        if (!scan_env_for_key(path, "ABUSEIPDB_KEY",
                              s_api_key, sizeof(s_api_key))) {
            s_api_key[0] = '\0';
            fprintf(stderr, "[checkendpoint] ABUSEIPDB_KEY not found\n");
            return -2;
        }
    }

    if (s_verbose)
        printf("[checkendpoint] API key loaded (%zu chars)\n",
               strlen(s_api_key));

    /* 2. Optional DB connection */
    if (mtc_db_get_connstr()) {
        s_conn = mtc_db_connect();
        if (s_conn) {
            if (init_schema(s_conn) < 0) {
                fprintf(stderr,
                    "[checkendpoint] DB schema failed, continuing without cache\n");
                PQfinish(s_conn);
                s_conn = NULL;
            } else {
                if (s_verbose)
                    printf("[checkendpoint] DB cache enabled\n");
            }
        } else {
            fprintf(stderr,
                "[checkendpoint] DB connect failed, continuing without cache\n");
        }
    } else {
        if (s_verbose)
            printf("[checkendpoint] no MERKLE_NEON, DB cache disabled\n");
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    return 0;
}

int mtc_checkendpoint(char *ipaddr)
{
    CURL *curl;
    CURLcode cres;
    struct curl_buf buf = {NULL, 0};
    struct curl_slist *headers = NULL;
    char url[512];
    char key_header[300];
    char *encoded_ip;
    struct json_object *root = NULL, *data_obj = NULL, *score_obj = NULL;
    int score = -1;

    if (s_api_key[0] == '\0')
        return -2;

    /* Check DB cache first */
    if (s_conn) {
        int cached = db_cache_lookup(ipaddr);
        if (cached >= 0)
            return cached;
    }

    if (s_verbose)
        printf("[checkendpoint] querying AbuseIPDB for %s\n", ipaddr);

    /* Build request */
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[checkendpoint] curl_easy_init failed\n");
        return -1;
    }

    encoded_ip = curl_easy_escape(curl, ipaddr, 0);
    if (!encoded_ip) {
        fprintf(stderr, "[checkendpoint] url-encode failed\n");
        curl_easy_cleanup(curl);
        return -1;
    }

    snprintf(url, sizeof(url),
        "https://api.abuseipdb.com/api/v2/check"
        "?ipAddress=%s&maxAgeInDays=90&verbose", encoded_ip);
    curl_free(encoded_ip);

    snprintf(key_header, sizeof(key_header), "Key: %s", s_api_key);
    headers = curl_slist_append(headers, key_header);
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    cres = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (cres != CURLE_OK) {
        fprintf(stderr, "[checkendpoint] curl error: %s\n",
                curl_easy_strerror(cres));
        free(buf.data);
        return -1;
    }

    if (s_verbose)
        printf("[checkendpoint] response (%zu bytes): %s\n",
               buf.len, buf.data);

    /* Parse JSON */
    root = json_tokener_parse(buf.data);
    if (!root) {
        fprintf(stderr, "[checkendpoint] JSON parse failed\n");
        free(buf.data);
        return -1;
    }

    if (!json_object_object_get_ex(root, "data", &data_obj) ||
        !json_object_object_get_ex(data_obj, "abuseConfidenceScore",
                                   &score_obj)) {
        fprintf(stderr, "[checkendpoint] missing data.abuseConfidenceScore\n");
        if (s_verbose)
            fprintf(stderr, "[checkendpoint] response body: %s\n", buf.data);
        json_object_put(root);
        free(buf.data);
        return -1;
    }

    score = json_object_get_int(score_obj);

    if (s_verbose)
        printf("[checkendpoint] abuseConfidenceScore = %d\n", score);

    /* Cache to DB */
    if (s_conn)
        db_cache_insert(ipaddr, buf.data, score);

    json_object_put(root);
    free(buf.data);
    return score;
}

/* ------------------------------------------------------------------ */
/* Standalone test main                                                */
/* ------------------------------------------------------------------ */

#if defined(TEST_MAIN)

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-v] <ipaddr>\n", prog);
}

int main(int argc, char *argv[])
{
    int i, ret;
    char *ipaddr = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            s_verbose = 1;
        } else if (argv[i][0] == '-') {
            usage(argv[0]);
            return 1;
        } else {
            ipaddr = argv[i];
        }
    }

    if (!ipaddr) {
        usage(argv[0]);
        return 1;
    }

    ret = mtc_init();
    if (ret < 0) {
        fprintf(stderr, "mtc_init failed (%d)\n", ret);
        return 1;
    }

    ret = mtc_checkendpoint(ipaddr);
    printf("mtc_checkendpoint(\"%s\") = %d\n", ipaddr, ret);

    if (s_conn)
        PQfinish(s_conn);
    curl_global_cleanup();

    return (ret < 0) ? 1 : 0;
}

#endif /* TEST_MAIN */
