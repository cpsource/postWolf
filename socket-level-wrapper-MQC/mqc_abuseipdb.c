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

/* Read ABUSEIPDB_TOKEN from environment or ~/.env. Returns NULL if not found. */
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
        if (strncmp(line, "ABUSEIPDB_TOKEN=", 16) == 0) {
            char *val = line + 16;
            char *nl = strchr(val, '\n');
            if (nl) *nl = '\0';
            if (strlen(val) >= 2 && val[0] == '"' && val[strlen(val)-1] == '"') {
                val[strlen(val)-1] = '\0';
                val++;
            }
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
    CURL *curl;
    CURLcode cres;
    char url[512];
    char auth_header[600];
    struct curl_slist *headers = NULL;
    struct abuse_buf buf = {NULL, 0};
    int score = -1;

    if (!api_token || !ip || !*ip)
        return -1;  /* no token = skip check */

    curl = curl_easy_init();
    if (!curl) return -1;

    snprintf(url, sizeof(url),
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90",
        ip);
    snprintf(auth_header, sizeof(auth_header), "Key: %s", api_token);

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
        return -1;
    }

    /* Parse: {"data":{"abuseConfidenceScore":N}} */
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
    return score;
}

/* Check IP and reject if abuse score >= threshold. Returns 0 = OK, -1 = reject. */
int mqc_abuse_check(const char *ip)
{
    int score = abuseipdb_check(ip);
    if (score < 0) return 0;  /* no token or error = allow (fail-open) */
    if (score >= MQC_ABUSE_THRESHOLD) {
        MQC_SECURITY("ABUSEIPDB_REJECTED: %s score=%d (threshold=%d)",
                     ip, score, MQC_ABUSE_THRESHOLD);
        return -1;
    }
    MQC_LOG("AbuseIPDB: %s score=%d (OK)", ip, score);
    return 0;
}
