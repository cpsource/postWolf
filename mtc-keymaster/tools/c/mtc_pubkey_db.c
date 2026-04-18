/******************************************************************************
 * File:        mtc_pubkey_db.c
 * Purpose:     Store public keys in the Neon mtc_public_keys table.
 *
 * Description:
 *   Connects to Neon PostgreSQL via the MERKLE_NEON connection string
 *   and upserts a public key by key_name. Used by bootstrap_ca and
 *   bootstrap_leaf after successful enrollment.
 *
 * Dependencies:
 *   libpq (PostgreSQL client library)
 *
 * Created:     2026-04-15
 ******************************************************************************/

#include "mtc_pubkey_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>

/******************************************************************************
 * Function:    get_connstr  (static)
 *
 * Description:
 *   Resolve the MERKLE_NEON connection string from $MERKLE_NEON env var
 *   or ~/.env file.
 ******************************************************************************/
static const char *get_connstr(void)
{
    static char connstr[1024] = {0};
    const char *env;
    FILE *f;
    char line[1024];
    char path[512];
    const char *home;

    if (connstr[0])
        return connstr;

    /* Try environment variable */
    env = getenv("MERKLE_NEON");
    if (env && *env) {
        snprintf(connstr, sizeof(connstr), "%s", env);
        return connstr;
    }

    /* Try ~/.env */
    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(path, sizeof(path), "%s/.env", home);

    f = fopen(path, "r");
    if (!f)
        return NULL;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MERKLE_NEON=", 12) == 0) {
            char *val = line + 12;
            char *nl = strchr(val, '\n');
            if (nl) *nl = '\0';
            /* Strip quotes */
            if (*val == '"' || *val == '\'') {
                val++;
                char *end = strrchr(val, '"');
                if (!end) end = strrchr(val, '\'');
                if (end) *end = '\0';
            }
            snprintf(connstr, sizeof(connstr), "%s", val);
            fclose(f);
            return connstr;
        }
    }
    fclose(f);
    return NULL;
}

/******************************************************************************
 * Function:    mtc_store_public_key
 *
 * Description:
 *   Connect to Neon and upsert a public key in mtc_public_keys.
 *   Non-fatal: logs warnings on failure.
 ******************************************************************************/
void mtc_store_public_key(const char *key_name, const char *key_value)
{
    const char *cs;
    PGconn *conn;
    PGresult *res;
    const char *params[2];

    if (!key_name || !key_value)
        return;

    cs = get_connstr();
    if (!cs) {
        fprintf(stderr, "[pubkey-db] MERKLE_NEON not found, skipping key store\n");
        return;
    }

    conn = PQconnectdb(cs);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[pubkey-db] DB connect failed: %s\n",
                PQerrorMessage(conn));
        PQfinish(conn);
        return;
    }

    params[0] = key_name;
    params[1] = key_value;

    res = PQexecParams(conn,
        "INSERT INTO mtc_public_keys (key_name, key_value) "
        "VALUES ($1, $2) "
        "ON CONFLICT (key_name) DO UPDATE SET "
        "key_value = EXCLUDED.key_value, "
        "created_utc = CURRENT_TIMESTAMP",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[pubkey-db] upsert failed: %s\n",
                PQerrorMessage(conn));
    } else {
        printf("[pubkey-db] stored public key for '%s' in Neon\n", key_name);
    }

    PQclear(res);
    PQfinish(conn);
}
