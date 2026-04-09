/* mtc_db.c — PostgreSQL (Neon) persistence for MTC CA server.
 *
 * Same schema as the Python server's db.py. Reads MERKLE_NEON from
 * environment, --tokenpath file, or ~/.env for the connection string. */

#include "mtc_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Connection string                                                   */
/* ------------------------------------------------------------------ */

static char s_tokenpath[512] = {0};

void mtc_db_set_tokenpath(const char *path)
{
    if (path)
        snprintf(s_tokenpath, sizeof(s_tokenpath), "%s", path);
}

/* Scan a file for a MERKLE_NEON= line, write value into dst.
 * Returns 1 on success, 0 if not found or file unreadable. */
static int scan_env_file(const char *filepath, char *dst, int dstSz)
{
    FILE *f;
    char line[1024];

    f = fopen(filepath, "r");
    if (!f) return 0;
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
            snprintf(dst, (size_t)dstSz, "%s", val);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

const char *mtc_db_get_connstr(void)
{
    static char connstr[1024] = {0};
    const char *env;

    if (connstr[0])
        return connstr;

    /* 1. Check environment variable */
    env = getenv("MERKLE_NEON");
    if (env && *env) {
        snprintf(connstr, sizeof(connstr), "%s", env);
        return connstr;
    }

    /* 2. Check --tokenpath file */
    if (s_tokenpath[0] && scan_env_file(s_tokenpath, connstr, sizeof(connstr)))
        return connstr;

    /* 3. Fall back to ~/.env */
    {
        const char *home = getenv("HOME");
        char path[512];
        if (!home) home = "/tmp";
        snprintf(path, sizeof(path), "%s/.env", home);
        if (scan_env_file(path, connstr, sizeof(connstr)))
            return connstr;
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
    fflush(stdout);
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
        ");"
        "CREATE TABLE IF NOT EXISTS mtc_revocations ("
        "  id SERIAL PRIMARY KEY,"
        "  cert_index INTEGER NOT NULL,"
        "  reason TEXT,"
        "  revoked_at DOUBLE PRECISION NOT NULL,"
        "  created_at TIMESTAMPTZ DEFAULT now()"
        ");"
        "CREATE TABLE IF NOT EXISTS mtc_enrollment_nonces ("
        "  nonce TEXT PRIMARY KEY,"
        "  domain TEXT NOT NULL,"
        "  fp TEXT NOT NULL,"
        "  ca_index INTEGER NOT NULL DEFAULT -1,"
        "  expires_at TIMESTAMPTZ NOT NULL,"
        "  status TEXT NOT NULL DEFAULT 'pending',"
        "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
        ");"
        "ALTER TABLE mtc_enrollment_nonces ADD COLUMN IF NOT EXISTS "
        "  ca_index INTEGER NOT NULL DEFAULT -1;"
        "CREATE INDEX IF NOT EXISTS idx_nonce_domain_fp "
        "  ON mtc_enrollment_nonces (domain, fp) "
        "  WHERE status = 'pending';";

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
/* Revocations                                                         */
/* ------------------------------------------------------------------ */

int mtc_db_save_revocation(PGconn *conn, int cert_index, const char *reason)
{
    PGresult *res;
    char idx_str[16], ts_str[32];
    const char *params[3];

    snprintf(idx_str, sizeof(idx_str), "%d", cert_index);
    snprintf(ts_str, sizeof(ts_str), "%.6f", (double)time(NULL));
    params[0] = idx_str;
    params[1] = reason ? reason : "unspecified";
    params[2] = ts_str;

    res = PQexecParams(conn,
        "INSERT INTO mtc_revocations (cert_index, reason, revoked_at) "
        "VALUES ($1, $2, $3)",
        3, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] save_revocation failed: %s\n",
            PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int mtc_db_load_revocations(PGconn *conn, int *indices, int max_count)
{
    PGresult *res;
    int i, rows;

    res = PQexec(conn,
        "SELECT cert_index FROM mtc_revocations ORDER BY cert_index");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;
    }

    rows = PQntuples(res);
    if (rows > max_count) rows = max_count;

    for (i = 0; i < rows; i++)
        indices[i] = atoi(PQgetvalue(res, i, 0));

    PQclear(res);
    return rows;
}

int mtc_db_is_revoked(PGconn *conn, int cert_index)
{
    PGresult *res;
    char idx_str[16];
    const char *params[1];
    int found;

    snprintf(idx_str, sizeof(idx_str), "%d", cert_index);
    params[0] = idx_str;

    res = PQexecParams(conn,
        "SELECT 1 FROM mtc_revocations WHERE cert_index = $1 LIMIT 1",
        1, NULL, params, NULL, NULL, 0);

    found = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    PQclear(res);
    return found;
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

/* ------------------------------------------------------------------ */
/* Enrollment nonces                                                   */
/* ------------------------------------------------------------------ */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

int mtc_db_create_nonce(PGconn *conn, const char *domain, const char *fp_hex,
                        int ca_index, char *nonce_out, long *expires_out)
{
    PGresult *res;
    const char *params[2];
    WC_RNG rng;
    uint8_t rand_bytes[32]; /* 256-bit */
    char ttl_str[32], ca_idx_str[16];
    const char *ins_params[5];
    int i;

    if (!conn) return -1;

    /* Expire stale nonces first */
    mtc_db_expire_nonces(conn);

    /* Reject if a pending nonce already exists for this domain+fp */
    params[0] = domain;
    params[1] = fp_hex;
    res = PQexecParams(conn,
        "SELECT nonce FROM mtc_enrollment_nonces "
        "WHERE domain = $1 AND fp = $2 AND status = 'pending' "
        "AND expires_at > now() LIMIT 1",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        PQclear(res);
        return -1; /* duplicate pending */
    }
    PQclear(res);

    /* Generate 256-bit random nonce */
    if (wc_InitRng(&rng) != 0) return -1;
    if (wc_RNG_GenerateBlock(&rng, rand_bytes, sizeof(rand_bytes)) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    wc_FreeRng(&rng);

    for (i = 0; i < 32; i++)
        snprintf(nonce_out + i * 2, 3, "%02x", rand_bytes[i]);
    nonce_out[64] = '\0';

    *expires_out = (long)time(NULL) + MTC_NONCE_TTL_SECS;

    /* Insert pending nonce */
    snprintf(ttl_str, sizeof(ttl_str), "%d seconds", MTC_NONCE_TTL_SECS);
    snprintf(ca_idx_str, sizeof(ca_idx_str), "%d", ca_index);
    ins_params[0] = nonce_out;
    ins_params[1] = domain;
    ins_params[2] = fp_hex;
    ins_params[3] = ca_idx_str;
    ins_params[4] = ttl_str;

    res = PQexecParams(conn,
        "INSERT INTO mtc_enrollment_nonces "
        "(nonce, domain, fp, ca_index, expires_at) "
        "VALUES ($1, $2, $3, $4, now() + $5::interval)",
        5, NULL, ins_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] nonce insert failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int mtc_db_find_ca_for_domain(PGconn *conn, const char *domain)
{
    PGresult *res;
    char subject[256];
    const char *params[1];
    int ca_index;

    if (!conn) return -1;

    /* CAs are enrolled with subject "<domain>-ca" */
    snprintf(subject, sizeof(subject), "%s-ca", domain);
    params[0] = subject;

    res = PQexecParams(conn,
        "SELECT index FROM mtc_certificates "
        "WHERE certificate->'standalone_certificate'->'tbs_entry'->>'subject' = $1 "
        "ORDER BY index DESC LIMIT 1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    ca_index = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return ca_index;
}

int mtc_db_validate_nonce(PGconn *conn, const char *nonce_hex,
                          const char *domain, const char *fp_hex)
{
    PGresult *res;
    int valid;

    if (!conn) return 0;

    /* Validate nonce: must exist, be pending, and not expired.
     * If domain is non-empty, also match domain.
     * If fp_hex is non-empty, also match fp.
     * The nonce was bound to domain+fp at creation time, so matching
     * the nonce alone is sufficient — but we check what the caller
     * provides for defense-in-depth. */
    if (domain && domain[0] && fp_hex && fp_hex[0]) {
        const char *params[3] = { nonce_hex, domain, fp_hex };
        res = PQexecParams(conn,
            "SELECT 1 FROM mtc_enrollment_nonces "
            "WHERE nonce = $1 AND domain = $2 AND fp = $3 "
            "AND status = 'pending' AND expires_at > now()",
            3, NULL, params, NULL, NULL, 0);
    }
    else if (domain && domain[0]) {
        const char *params[2] = { nonce_hex, domain };
        res = PQexecParams(conn,
            "SELECT 1 FROM mtc_enrollment_nonces "
            "WHERE nonce = $1 AND domain = $2 "
            "AND status = 'pending' AND expires_at > now()",
            2, NULL, params, NULL, NULL, 0);
    }
    else {
        const char *params[1] = { nonce_hex };
        res = PQexecParams(conn,
            "SELECT 1 FROM mtc_enrollment_nonces "
            "WHERE nonce = $1 "
            "AND status = 'pending' AND expires_at > now()",
            1, NULL, params, NULL, NULL, 0);
    }

    valid = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    PQclear(res);
    return valid;
}

int mtc_db_validate_and_consume_nonce(PGconn *conn, const char *nonce_hex,
                                      const char *domain, const char *fp_hex)
{
    PGresult *res;
    int consumed;

    if (!conn) return 0;

    /* Atomic: UPDATE only if pending+unexpired+matching, consume in one shot.
     * If zero rows affected, the nonce was invalid, expired, or already used.
     * This eliminates the TOCTOU race between validate and consume. */
    if (domain && domain[0] && fp_hex && fp_hex[0]) {
        const char *params[3] = { nonce_hex, domain, fp_hex };
        res = PQexecParams(conn,
            "UPDATE mtc_enrollment_nonces SET status = 'consumed' "
            "WHERE nonce = $1 AND domain = $2 AND fp = $3 "
            "AND status = 'pending' AND expires_at > now()",
            3, NULL, params, NULL, NULL, 0);
    }
    else if (domain && domain[0]) {
        const char *params[2] = { nonce_hex, domain };
        res = PQexecParams(conn,
            "UPDATE mtc_enrollment_nonces SET status = 'consumed' "
            "WHERE nonce = $1 AND domain = $2 "
            "AND status = 'pending' AND expires_at > now()",
            2, NULL, params, NULL, NULL, 0);
    }
    else {
        const char *params[1] = { nonce_hex };
        res = PQexecParams(conn,
            "UPDATE mtc_enrollment_nonces SET status = 'consumed' "
            "WHERE nonce = $1 "
            "AND status = 'pending' AND expires_at > now()",
            1, NULL, params, NULL, NULL, 0);
    }

    consumed = (PQresultStatus(res) == PGRES_COMMAND_OK &&
                atoi(PQcmdTuples(res)) > 0);
    PQclear(res);
    return consumed;
}

void mtc_db_consume_nonce(PGconn *conn, const char *nonce_hex)
{
    PGresult *res;
    const char *params[1];

    if (!conn) return;

    params[0] = nonce_hex;
    res = PQexecParams(conn,
        "UPDATE mtc_enrollment_nonces SET status = 'consumed' "
        "WHERE nonce = $1",
        1, NULL, params, NULL, NULL, 0);
    PQclear(res);
}

void mtc_db_expire_nonces(PGconn *conn)
{
    PGresult *res;
    if (!conn) return;

    res = PQexec(conn,
        "UPDATE mtc_enrollment_nonces SET status = 'expired' "
        "WHERE status = 'pending' AND expires_at <= now()");
    PQclear(res);
}
