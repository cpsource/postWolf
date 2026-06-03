/******************************************************************************
 * File:        mqc_abuseipdb.c
 * Purpose:     AbuseIPDB lookup (libcurl + JSON), used by the server-side
 *              accept-prologue to fail-closed against known-bad source IPs.
 *
 * Description:
 *   Split out of mqc_common.c so MQC client binaries (qsh, fips-manifest-*,
 *   fetch-publisher-key, ...) don't transitively drag libcurl into their
 *   link.  Only mqc_ratelimit.c's accept-prologue references mqc_abuse_check,
 *   so this TU is pulled into the archive resolution only on server links.
 *
 * Dependencies:
 *   libcurl, json-c
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>

#define MQC_ABUSE_THRESHOLD  25  /* reject if abuse score >= 25% */

struct abuse_buf { char *data; size_t sz; };

static size_t abuse_write_cb(void *ptr, size_t size, size_t nmemb, void *ud)
{
    struct abuse_buf *b = (struct abuse_buf *)ud;
    size_t total = size * nmemb;
    char *tmp = realloc(b->data, b->sz + total + 1);
    if (!tmp) return 0;
    b->data = tmp;
    memcpy(b->data + b->sz, ptr, total);
    b->sz += total;
    b->data[b->sz] = '\0';
    return total;
}

/* Strip matching quotes (single or double) from a value in-place. */
static char *strip_quotes(char *val)
{
    size_t len = strlen(val);
    if (len >= 2 &&
        ((val[0] == '"'  && val[len-1] == '"') ||
         (val[0] == '\'' && val[len-1] == '\''))) {
        val[len-1] = '\0';
        val++;
    }
    return val;
}

/* Read the AbuseIPDB API token from environment or ~/.env.
 * Accepts both ABUSEIPDB_TOKEN and ABUSEIPDB_KEY. */
static const char *get_abuseipdb_token(void)
{
    static char token[512] = {0};
    const char *env;
    FILE *f;
    char line[512];
    char path[512];
    const char *home;

    if (token[0]) return token;

    env = getenv("ABUSEIPDB_TOKEN");
    if (!env || !*env)
        env = getenv("ABUSEIPDB_KEY");
    if (env && *env) {
        snprintf(token, sizeof(token), "%s", env);
        return token;
    }

    home = getenv("HOME");
    if (!home) return NULL;
    snprintf(path, sizeof(path), "%s/.env", home);

    f = fopen(path, "r");
    if (!f) return NULL;

    while (fgets(line, sizeof(line), f)) {
        char *val = NULL;
        if (strncmp(line, "ABUSEIPDB_TOKEN=", 16) == 0)
            val = line + 16;
        else if (strncmp(line, "ABUSEIPDB_KEY=", 14) == 0)
            val = line + 14;
        if (val) {
            char *nl = strchr(val, '\n');
            if (nl) *nl = '\0';
            val = strip_quotes(val);
            snprintf(token, sizeof(token), "%s", val);
            fclose(f);
            return token;
        }
    }
    fclose(f);
    return NULL;
}

/* Check an IP against AbuseIPDB. Returns abuse confidence score (0-100),
 * or -1 if the check is unavailable (no token, network error). */
static int abuseipdb_check(const char *ip)
{
    const char *api_token = get_abuseipdb_token();
    char url[512];
    char auth_header[600];
    int attempt, score = -1;

    if (!api_token || !ip || !*ip)
        return -1;

    snprintf(url, sizeof(url),
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90",
        ip);
    snprintf(auth_header, sizeof(auth_header), "Key: %s", api_token);

    for (attempt = 0; attempt < 2; attempt++) {
        CURL *curl;
        CURLcode cres;
        struct curl_slist *headers = NULL;
        struct abuse_buf buf = {NULL, 0};

        curl = curl_easy_init();
        if (!curl) return -1;

        headers = curl_slist_append(headers, auth_header);
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, abuse_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

        cres = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if (cres != CURLE_OK || !buf.data) {
            free(buf.data);
            if (attempt == 0)
                MQC_SECURITY("ABUSEIPDB_RETRY: %s attempt 1 failed (%s), retrying",
                             ip, curl_easy_strerror(cres));
            continue;
        }

        {
            struct json_object *obj = json_tokener_parse(buf.data);
            struct json_object *data_obj, *score_obj;
            if (obj &&
                json_object_object_get_ex(obj, "data", &data_obj) &&
                json_object_object_get_ex(data_obj, "abuseConfidenceScore", &score_obj)) {
                score = json_object_get_int(score_obj);
            }
            if (obj) json_object_put(obj);
        }
        free(buf.data);
        break;
    }
    return score;
}

/* Check IP and reject if abuse score >= threshold. Returns 0 = OK, -1 = reject.
 *
 * Cache flow: consult Redis (mqc:<ip>:abuse) first; on hit, decide from
 * the cached score and skip the HTTPS call.  On miss, query AbuseIPDB
 * and store the resulting score (0..100) with TTL = abuse_cache_ttl_sec.
 * Network errors / missing API token (score < 0) are NOT cached.
 *
 * Two short-circuits run before any cache or API work:
 *   1. bypass_mask & MQC_BYPASS_ABUSE — a validated MQCBYPASS token
 *      authorised skipping the gate for this connection.  No logging
 *      here (the prologue already emitted BYPASS_HIT).
 *   2. mqc_abuse_allowlist_match(ip) — the operator pre-approved this
 *      IP/CIDR via mqc-abuse-allowlist in /etc/postWolf/config. */
int mqc_abuse_check(const char *ip)
{
    int score = -1;
    int from_cache = 0;

    if (mqc_current_bypass_mask() & MQC_BYPASS_ABUSE)
        return 0;
    if (mqc_abuse_allowlist_match(ip)) {
        MQC_SECURITY("ABUSEIPDB_ALLOWLIST_HIT: %s — bypassing AbuseIPDB "
                     "(mqc-abuse-allowlist)", ip);
        return 0;
    }

    if (mqc_abuse_cache_get(ip, &score))
        from_cache = 1;
    else
        score = abuseipdb_check(ip);

    if (score < 0) {
        MQC_SECURITY("ABUSEIPDB_FAIL_OPEN: %s lookup failed", ip);
        return 0;
    }

    if (!from_cache)
        mqc_abuse_cache_put(ip, score, (int)mqc_rt_cfg()->abuse_cache_ttl_sec);

    if (score >= MQC_ABUSE_THRESHOLD) {
        MQC_SECURITY("ABUSEIPDB_REJECTED: %s score=%d (threshold=%d, %s)",
                     ip, score, MQC_ABUSE_THRESHOLD,
                     from_cache ? "cached" : "fresh");
        return -1;
    }
    MQC_SECURITY("ABUSEIPDB_OK: %s score=%d (threshold=%d, %s)",
                 ip, score, MQC_ABUSE_THRESHOLD,
                 from_cache ? "cached" : "fresh");
    return 0;
}
