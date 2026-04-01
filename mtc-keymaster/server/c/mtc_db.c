/* mtc_db.c — PostgreSQL (Neon) persistence for MTC CA server.
 *
 * Same schema as the Python server's db.py. Reads MERKLE_NEON from
 * environment or ~/.env for the connection string. */

#include "mtc_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Connection string                                                   */
/* ------------------------------------------------------------------ */

const char *mtc_db_get_connstr(void)
{
    static char connstr[1024] = {0};
    const char *env;
    FILE *f;

    if (connstr[0])
        return connstr;

    /* Check environment first */
    env = getenv("MERKLE_NEON");
    if (env && *env) {
        snprintf(connstr, sizeof(connstr), "%s", env);
        return connstr;
    }

    /* Fall back to ~/.env */
    {
        const char *home = getenv("HOME");
        char path[512];
        char line[1024];
        if (!home) home = "/tmp";
        snprintf(path, sizeof(path), "%s/.env", home);
        f = fopen(path, "r");
        if (!f) return NULL;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "MERKLE_NEON=", 12) == 0) {
                char *val = line + 12;
                /* Strip quotes and newline */
                while (*val == '"' || *val == '\'') val++;
                {
                    int len = (int)strlen(val);
                    while (len > 0 && (val[len-1] == '\n' || val[len-1] == '\r' ||
                           val[len-1] == '"' || val[len-1] == '\''))
                        val[--len] = 0;
                }
                snprintf(connstr, sizeof(connstr), "%s", val);
                fclose(f);
                return connstr;
            }
        }
        fclose(f);
    }

    return NULL;
}

PGconn *mtc_db_connect(void)
{
    const char *cs = mtc_db_get_connstr();
    PGconn *conn;

    if (!cs) {
        fprintf(stderr, "[db] MERKLE_NEON not found in env or ~/.env\n");
        return NULL;
    }

    conn = PQconnectdb(cs);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[db] connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }

    printf("[db] connected to Neon PostgreSQL\n");
    return conn;
}

/* ------------------------------------------------------------------ */
/* Schema                                                              */
/* ------------------------------------------------------------------ */

int mtc_db_init_schema(PGconn *conn)
{
    PGresult *res;
    const char *sql =
        "CREATE TABLE IF NOT EXISTS mtc_log_entries ("
        "  index INTEGER PRIMARY KEY,"
        "  entry_type SMALLINT NOT NULL,"
        "  tbs_data JSONB,"
        "  serialized BYTEA NOT NULL,"
        "  leaf_hash BYTEA NOT NULL,"
        "  created_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE TABLE IF NOT EXISTS mtc_checkpoints ("
        "  id SERIAL PRIMARY KEY,"
        "  log_id TEXT NOT NULL,"
        "  tree_size INTEGER NOT NULL,"
        "  root_hash TEXT NOT NULL,"
        "  ts DOUBLE PRECISION NOT NULL,"
        "  created_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE TABLE IF NOT EXISTS mtc_landmarks ("
        "  id SERIAL PRIMARY KEY,"
        "  tree_size INTEGER NOT NULL UNIQUE,"
        "  created_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE TABLE IF NOT EXISTS mtc_certificates ("
        "  index INTEGER PRIMARY KEY,"
        "  certificate JSONB NOT NULL,"
        "  created_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE TABLE IF NOT EXISTS mtc_ca_config ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ");";

    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] schema init failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Log entries                                                         */
/* ------------------------------------------------------------------ */

int mtc_db_save_entry(PGconn *conn, int index, int entry_type,
                      const char *tbs_json, const uint8_t *serialized,
                      int serialized_sz, const uint8_t *leaf_hash)
{
    PGresult *res;
    char idx_str[16], type_str[8];
    const char *params[5];
    int paramLengths[5];
    int paramFormats[5];

    snprintf(idx_str, sizeof(idx_str), "%d", index);
    snprintf(type_str, sizeof(type_str), "%d", entry_type);

    params[0] = idx_str;           paramLengths[0] = 0; paramFormats[0] = 0;
    params[1] = type_str;          paramLengths[1] = 0; paramFormats[1] = 0;
    params[2] = tbs_json;          paramLengths[2] = 0; paramFormats[2] = 0;
    params[3] = (const char*)serialized; paramLengths[3] = serialized_sz; paramFormats[3] = 1;
    params[4] = (const char*)leaf_hash;  paramLengths[4] = 32;           paramFormats[4] = 1;

    res = PQexecParams(conn,
        "INSERT INTO mtc_log_entries (index, entry_type, tbs_data, serialized, leaf_hash) "
        "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (index) DO NOTHING",
        5, NULL, params, paramLengths, paramFormats, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] save_entry failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int mtc_db_load_entries(PGconn *conn, struct json_object **out_arr)
{
    PGresult *res;
    int i, rows;

    res = PQexecParams(conn,
        "SELECT index, entry_type, tbs_data, serialized, leaf_hash "
        "FROM mtc_log_entries ORDER BY index",
        0, NULL, NULL, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[db] load_entries failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    rows = PQntuples(res);
    *out_arr = json_object_new_array();

    for (i = 0; i < rows; i++) {
        struct json_object *entry = json_object_new_object();
        json_object_object_add(entry, "index",
            json_object_new_int(atoi(PQgetvalue(res, i, 0))));
        json_object_object_add(entry, "entry_type",
            json_object_new_int(atoi(PQgetvalue(res, i, 1))));

        /* tbs_data (JSONB, text format) */
        if (!PQgetisnull(res, i, 2)) {
            struct json_object *tbs = json_tokener_parse(PQgetvalue(res, i, 2));
            json_object_object_add(entry, "tbs_data",
                tbs ? tbs : json_object_new_null());
        }

        /* serialized (BYTEA, comes as hex escape in text mode) */
        {
            size_t bin_len = 0;
            unsigned char *bin = PQunescapeBytea(
                (const unsigned char*)PQgetvalue(res, i, 3), &bin_len);
            if (bin) {
                /* Store as hex string */
                char *hex = (char*)malloc(bin_len * 2 + 1);
                int j;
                for (j = 0; j < (int)bin_len; j++)
                    snprintf(hex + j * 2, 3, "%02x", bin[j]);
                json_object_object_add(entry, "serialized_hex",
                    json_object_new_string(hex));
                json_object_object_add(entry, "serialized_len",
                    json_object_new_int((int)bin_len));
                free(hex);
                PQfreemem(bin);
            }
        }

        json_object_array_add(*out_arr, entry);
    }

    PQclear(res);
    return rows;
}

/* ------------------------------------------------------------------ */
/* Checkpoints                                                         */
/* ------------------------------------------------------------------ */

int mtc_db_save_checkpoint(PGconn *conn, const char *log_id,
                           int tree_size, const char *root_hash, double ts)
{
    PGresult *res;
    char ts_str[32], sz_str[16];
    const char *params[4];

    snprintf(sz_str, sizeof(sz_str), "%d", tree_size);
    snprintf(ts_str, sizeof(ts_str), "%.6f", ts);
    params[0] = log_id;
    params[1] = sz_str;
    params[2] = root_hash;
    params[3] = ts_str;

    res = PQexecParams(conn,
        "INSERT INTO mtc_checkpoints (log_id, tree_size, root_hash, ts) "
        "VALUES ($1, $2, $3, $4)",
        4, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] save_checkpoint failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int mtc_db_load_checkpoints(PGconn *conn, const char *log_id,
                            struct json_object **out_arr)
{
    PGresult *res;
    int i, rows;
    const char *params[1] = { log_id };

    res = PQexecParams(conn,
        "SELECT log_id, tree_size, root_hash, ts "
        "FROM mtc_checkpoints WHERE log_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return -1;
    }

    rows = PQntuples(res);
    *out_arr = json_object_new_array();

    for (i = 0; i < rows; i++) {
        struct json_object *cp = json_object_new_object();
        json_object_object_add(cp, "log_id",
            json_object_new_string(PQgetvalue(res, i, 0)));
        json_object_object_add(cp, "tree_size",
            json_object_new_int(atoi(PQgetvalue(res, i, 1))));
        json_object_object_add(cp, "root_hash",
            json_object_new_string(PQgetvalue(res, i, 2)));
        json_object_object_add(cp, "timestamp",
            json_object_new_double(atof(PQgetvalue(res, i, 3))));
        json_object_array_add(*out_arr, cp);
    }

    PQclear(res);
    return rows;
}

/* ------------------------------------------------------------------ */
/* Landmarks                                                           */
/* ------------------------------------------------------------------ */

int mtc_db_save_landmark(PGconn *conn, int tree_size)
{
    PGresult *res;
    char sz_str[16];
    const char *params[1];

    snprintf(sz_str, sizeof(sz_str), "%d", tree_size);
    params[0] = sz_str;

    res = PQexecParams(conn,
        "INSERT INTO mtc_landmarks (tree_size) VALUES ($1) "
        "ON CONFLICT (tree_size) DO NOTHING",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int mtc_db_load_landmarks(PGconn *conn, int *out, int max_count)
{
    PGresult *res;
    int i, rows;

    res = PQexec(conn, "SELECT tree_size FROM mtc_landmarks ORDER BY tree_size");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }

    rows = PQntuples(res);
    if (rows > max_count) rows = max_count;

    for (i = 0; i < rows; i++)
        out[i] = atoi(PQgetvalue(res, i, 0));

    PQclear(res);
    return rows;
}

/* ------------------------------------------------------------------ */
/* Certificates                                                        */
/* ------------------------------------------------------------------ */

int mtc_db_save_certificate(PGconn *conn, int index, const char *cert_json)
{
    PGresult *res;
    char idx_str[16];
    const char *params[2];

    snprintf(idx_str, sizeof(idx_str), "%d", index);
    params[0] = idx_str;
    params[1] = cert_json;

    res = PQexecParams(conn,
        "INSERT INTO mtc_certificates (index, certificate) VALUES ($1, $2) "
        "ON CONFLICT (index) DO UPDATE SET certificate = EXCLUDED.certificate",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] save_certificate failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

struct json_object *mtc_db_load_certificate(PGconn *conn, int index)
{
    PGresult *res;
    char idx_str[16];
    const char *params[1];

    snprintf(idx_str, sizeof(idx_str), "%d", index);
    params[0] = idx_str;

    res = PQexecParams(conn,
        "SELECT certificate FROM mtc_certificates WHERE index = $1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }

    {
        struct json_object *obj = json_tokener_parse(PQgetvalue(res, 0, 0));
        PQclear(res);
        return obj;
    }
}

int mtc_db_load_all_certificates(PGconn *conn,
                                  struct json_object ***out, int *count)
{
    PGresult *res;
    int i, rows, max_idx = 0;

    res = PQexec(conn,
        "SELECT index, certificate FROM mtc_certificates ORDER BY index");

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        *count = 0;
        return -1;
    }

    rows = PQntuples(res);

    /* Find max index to size the array */
    for (i = 0; i < rows; i++) {
        int idx = atoi(PQgetvalue(res, i, 0));
        if (idx > max_idx) max_idx = idx;
    }

    *count = max_idx + 1;
    *out = (struct json_object**)calloc((size_t)(*count), sizeof(struct json_object*));

    for (i = 0; i < rows; i++) {
        int idx = atoi(PQgetvalue(res, i, 0));
        (*out)[idx] = json_tokener_parse(PQgetvalue(res, i, 1));
    }

    PQclear(res);
    return rows;
}

/* ------------------------------------------------------------------ */
/* CA config                                                           */
/* ------------------------------------------------------------------ */

int mtc_db_save_config(PGconn *conn, const char *key, const char *value)
{
    PGresult *res;
    const char *params[2] = { key, value };

    res = PQexecParams(conn,
        "INSERT INTO mtc_ca_config (key, value) VALUES ($1, $2) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

char *mtc_db_load_config(PGconn *conn, const char *key)
{
    PGresult *res;
    const char *params[1] = { key };
    char *val;

    res = PQexecParams(conn,
        "SELECT value FROM mtc_ca_config WHERE key = $1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }

    val = strdup(PQgetvalue(res, 0, 0));
    PQclear(res);
    return val;
}
