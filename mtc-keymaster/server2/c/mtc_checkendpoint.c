/******************************************************************************
 * File:        mtc_checkendpoint.c
 * Purpose:     AbuseIPDB CHECK endpoint client with optional PostgreSQL
 *              (Neon) caching.
 *
 * Description:
 *   Queries the AbuseIPDB v2 CHECK endpoint for an IP address's abuse
 *   confidence score.  When a PostgreSQL connection string is available
 *   (MERKLE_NEON), results are cached so that repeat lookups within the
 *   TTL window avoid an external API call.
 *
 *   Two public entry points:
 *     mtc_init()          — load API key, optionally connect to DB
 *     mtc_checkendpoint() — query AbuseIPDB (or DB cache) for an IP
 *
 *   See README-abuseipdb.md for API details.
 *
 * Dependencies:
 *   mtc_checkendpoint.h
 *   mtc_db.h
 *   stdio.h, stdlib.h, string.h
 *   curl/curl.h
 *   json-c/json.h
 *   libpq-fe.h
 *
 * Notes:
 *   - NOT thread-safe.  All module state is file-scoped static.
 *   - curl_global_init() is called inside mtc_init(); the caller must
 *     not call it beforehand.
 *   - DB connection failure is non-fatal — the module falls back to
 *     uncached API queries.
 *
 * Created:     2026-04-13
 ******************************************************************************/

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

/* ABUSEIPDB_CACHE_TTL_INTERVAL + default threshold live in config.h
 * (pulled in via mtc_checkendpoint.h). */

static char    s_api_key[256]    = {0};   /**< AbuseIPDB API key           */
static PGconn *s_conn           = NULL;   /**< DB connection (NULL = off)  */
static int     s_verbose        = 0;      /**< Verbose logging flag        */
static int     s_abuse_threshold = MTC_ABUSE_DEFAULT_THRESHOLD;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    scan_env_for_key
 *
 * Description:
 *   Scans a KEY=value style file for the given key name and copies the
 *   value into dst.  Strips surrounding quotes and trailing newlines.
 *
 * Input Arguments:
 *   filepath   - Path to the file to scan (e.g. "~/.env").
 *   keyname    - Key to search for (matched as a line prefix before '=').
 *   dst        - Caller-owned buffer that receives the value.
 *   dstSz      - Size of dst in bytes.
 *
 * Returns:
 *   1  if the key was found and copied into dst.
 *   0  if the file could not be opened or the key was not found.
 *
 * Notes:
 *   - Lines longer than 1024 bytes are silently truncated.
 *   - The file is always closed before returning.
 ******************************************************************************/
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
            /* Strip surrounding quotes and trailing whitespace */
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

/******************************************************************************
 * Struct:      curl_buf
 *
 * Description:
 *   Dynamic buffer used by curl_write_cb to accumulate an HTTP response.
 *   Allocated by the caller (on stack); data is heap-allocated by realloc
 *   inside the callback.
 *
 *   Ownership: caller must free(data) after use.
 ******************************************************************************/
struct curl_buf {
    char  *data;    /**< Heap-allocated response body (NULL initially) */
    size_t len;     /**< Current length in bytes (excludes NUL)        */
};

/******************************************************************************
 * Function:    curl_write_cb
 *
 * Description:
 *   libcurl CURLOPT_WRITEFUNCTION callback.  Accumulates received data
 *   into a dynamically growing curl_buf via realloc.
 *
 * Input Arguments:
 *   ptr    - Pointer to received data (from libcurl).
 *   size   - Always 1 (per libcurl documentation).
 *   nmemb  - Number of bytes received in this call.
 *   userp  - Pointer to a struct curl_buf (set via CURLOPT_WRITEDATA).
 *
 * Returns:
 *   Number of bytes consumed (size * nmemb) on success.
 *   0 on allocation failure, which causes libcurl to abort the transfer.
 *
 * Side Effects:
 *   Reallocates buf->data; updates buf->len.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    init_schema
 *
 * Description:
 *   Ensures the abuseipdb cache table and unique index exist in the
 *   connected PostgreSQL database.  Also adds the updated_at column
 *   to older table versions that lack it.
 *
 * Input Arguments:
 *   conn  - Active PostgreSQL connection.  Must not be NULL.
 *
 * Returns:
 *    0  on success.
 *   -1  if any DDL statement failed (error logged to stderr).
 *
 * Side Effects:
 *   Creates/alters the abuseipdb table and index in the database.
 ******************************************************************************/
static int init_schema(PGconn *conn)
{
    PGresult *res;
    const char *sql =
        "CREATE TABLE IF NOT EXISTS abuseipdb ("
        "  idx SERIAL PRIMARY KEY,"
        "  ipaddr TEXT NOT NULL,"
        "  response JSONB,"
        "  abuse_confidence_score INTEGER NOT NULL,"
        "  requested_at TIMESTAMPTZ DEFAULT now(),"
        "  updated_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS abuseipdb_ipaddr_idx "
        "  ON abuseipdb (ipaddr);"
        /* Add updated_at to existing tables that lack it */
        "ALTER TABLE abuseipdb ADD COLUMN IF NOT EXISTS "
        "  updated_at TIMESTAMPTZ DEFAULT now();";

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

/******************************************************************************
 * Function:    db_cache_lookup
 *
 * Description:
 *   Looks up an IP address in the local DB cache and returns its abuse
 *   confidence score if the entry is still fresh (within the TTL window).
 *   Stale entries are treated as cache misses so the caller will re-query
 *   the API and upsert the fresh result.
 *
 * Input Arguments:
 *   ipaddr  - Null-terminated IP address string.  Must not be NULL.
 *
 * Returns:
 *   0..100  cached abuseConfidenceScore if entry is fresh.
 *  -1       if no DB connection, no matching row, entry is stale, or
 *           a query error occurred.
 ******************************************************************************/
static int db_cache_lookup(const char *ipaddr)
{
    PGresult *res;
    const char *params[1];
    int score;
    const char *is_fresh;

    if (!s_conn) return -1;

    params[0] = ipaddr;
    res = PQexecParams(s_conn,
        "SELECT abuse_confidence_score,"
        "  (COALESCE(updated_at, requested_at) > now() - INTERVAL '"
        ABUSEIPDB_CACHE_TTL_INTERVAL "') AS is_fresh "
        "FROM abuseipdb "
        "WHERE ipaddr = $1 ORDER BY requested_at DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    score = atoi(PQgetvalue(res, 0, 0));
    is_fresh = PQgetvalue(res, 0, 1);
    PQclear(res);

    if (is_fresh[0] != 't') {
        if (s_verbose)
            printf("[checkendpoint] cache stale for %s (older than %d days)\n",
                   ipaddr, ABUSEIPDB_CACHE_TTL_DAYS);
        return -1;  /* treat as cache miss — caller will re-query and update */
    }

    if (s_verbose)
        printf("[checkendpoint] cache hit for %s -> score %d\n", ipaddr, score);

    return score;
}

/******************************************************************************
 * Function:    db_cache_upsert
 *
 * Description:
 *   Inserts or updates an AbuseIPDB result in the cache.  Uses PostgreSQL
 *   ON CONFLICT (upsert) so existing rows are updated with the latest
 *   score, response JSON, and timestamp.
 *
 * Input Arguments:
 *   ipaddr         - Null-terminated IP address string.
 *   json_response  - Raw JSON response body from the AbuseIPDB API.
 *   score          - Parsed abuseConfidenceScore (0-100).
 *
 * Returns:
 *   0   on success.
 *  -1   if no DB connection or the query failed (error logged to stderr).
 *
 * Side Effects:
 *   Inserts or updates a row in the abuseipdb table.
 ******************************************************************************/
static int db_cache_upsert(const char *ipaddr, const char *json_response,
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
        "VALUES ($1, $2, $3) "
        "ON CONFLICT (ipaddr) DO UPDATE SET "
        "  response = EXCLUDED.response, "
        "  abuse_confidence_score = EXCLUDED.abuse_confidence_score, "
        "  updated_at = now()",
        3, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[checkendpoint] cache upsert failed: %s\n",
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

/******************************************************************************
 * Function:    mtc_set_abuse_threshold
 *
 * Description:
 *   Sets the module-wide abuse confidence score threshold.  Scores at or
 *   above this value cause request rejection.
 *
 * Input Arguments:
 *   threshold  - New threshold value (0-100).
 ******************************************************************************/
void mtc_set_abuse_threshold(int threshold)
{
    s_abuse_threshold = threshold;
}

/******************************************************************************
 * Function:    mtc_get_abuse_threshold
 *
 * Description:
 *   Returns the current abuse confidence score threshold.
 *
 * Returns:
 *   Current threshold (0-100).  Default is 75.
 ******************************************************************************/
int mtc_get_abuse_threshold(void)
{
    return s_abuse_threshold;
}

/******************************************************************************
 * Function:    mtc_init
 *
 * Description:
 *   Initialises the AbuseIPDB module.  Loads the API key from the
 *   ABUSEIPDB_KEY environment variable or from ~/.env.  If a database
 *   connection string is available (via mtc_db_get_connstr()), connects
 *   to PostgreSQL and ensures the cache schema exists.  Finally calls
 *   curl_global_init().
 *
 * Returns:
 *    0  on success (API key loaded; DB is optional).
 *   -1  on general failure.
 *   -2  if no API key was found (module is non-functional).
 *
 * Side Effects:
 *   - Populates s_api_key, s_conn module state.
 *   - Calls curl_global_init(CURL_GLOBAL_DEFAULT).
 *   - May create/alter the abuseipdb table in the database.
 *   - Logs diagnostics to stderr on failure.
 *
 * Notes:
 *   Must be called exactly once before mtc_checkendpoint().
 *   DB connection failure is non-fatal — the module falls back to
 *   uncached API queries.
 ******************************************************************************/
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

    /* 2. Optional DB connection — failure is non-fatal */
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

/******************************************************************************
 * Function:    mtc_checkendpoint
 *
 * Description:
 *   Queries AbuseIPDB for the abuse confidence score of the given IP
 *   address.  If a DB cache is available and holds a fresh entry (within
 *   ABUSEIPDB_CACHE_TTL_DAYS), the cached score is returned without an
 *   API call.  Otherwise the AbuseIPDB v2 CHECK endpoint is called and
 *   the result is cached for future lookups.
 *
 * Input Arguments:
 *   ipaddr  - Null-terminated IPv4 or IPv6 address string.  Must not be
 *             NULL.  Caller retains ownership.
 *
 * Returns:
 *   0..100  abuseConfidenceScore on success.
 *  -1       on network error, curl failure, or JSON parse failure.
 *  -2       if no API key is configured.
 *
 * Side Effects:
 *   - Makes an HTTPS request to api.abuseipdb.com (on cache miss).
 *   - Upserts the result into the DB cache (if connected).
 *   - Logs diagnostics to stderr/stdout when s_verbose is set.
 ******************************************************************************/
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

    /* Parse JSON — extract data.abuseConfidenceScore */
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

    /* Cache to DB (inserts new or updates stale) */
    if (s_conn)
        db_cache_upsert(ipaddr, buf.data, score);

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
