/******************************************************************************
 * File:        mtc_db.c
 * Purpose:     PostgreSQL (Neon) persistence for MTC CA server.
 *
 * Description:
 *   Implements CRUD operations for all MTC CA server state stored in
 *   PostgreSQL (hosted on Neon).  The schema is compatible with the Python
 *   server's db.py so both implementations can share the same database.
 *
 *   Connection strings are resolved from MERKLE_NEON via environment
 *   variable, --tokenpath file, or ~/.env fallback.
 *
 * Dependencies:
 *   mtc_db.h
 *   stdio.h, stdlib.h, string.h, time.h
 *   libpq-fe.h          (PostgreSQL client)
 *   json-c/json.h       (JSON serialization)
 *   wolfssl/options.h    (wolfCrypt build options)
 *   wolfssl/wolfcrypt/random.h  (CSPRNG for nonce generation)
 *
 * Notes:
 *   - NOT thread-safe.  s_tokenpath and the connstr cache are
 *     file-scoped static storage.  All calls sharing a PGconn must be
 *     serialised externally.
 *   - All PGresult pointers are cleared before returning.
 *   - Nonce generation uses wolfCrypt WC_RNG (256-bit CSPRNG).
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include "mtc_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Connection string                                                   */
/* ------------------------------------------------------------------ */

static char s_tokenpath[512] = {0};  /**< Optional --tokenpath override */

/******************************************************************************
 * Function:    mtc_db_set_tokenpath
 *
 * Description:
 *   Stores an explicit file path to search for the MERKLE_NEON connection
 *   string.  Typically set from the --tokenpath command-line argument.
 *
 * Input Arguments:
 *   path  - Null-terminated file path.  If NULL, the tokenpath is cleared.
 *           The string is copied into internal storage.
 ******************************************************************************/
void mtc_db_set_tokenpath(const char *path)
{
    if (path)
        snprintf(s_tokenpath, sizeof(s_tokenpath), "%s", path);
}

/******************************************************************************
 * Function:    scan_env_file
 *
 * Description:
 *   Scans a KEY=value style file for a MERKLE_NEON= line and copies the
 *   value into dst.  Strips surrounding quotes and trailing whitespace.
 *
 * Input Arguments:
 *   filepath  - Path to the file to scan.
 *   dst       - Caller-owned buffer that receives the value.
 *   dstSz     - Size of dst in bytes.
 *
 * Returns:
 *   1  if MERKLE_NEON was found and copied.
 *   0  if the file could not be opened or the key was not found.
 *
 * Notes:
 *   Lines longer than 1024 bytes are silently truncated.
 *   File is always closed before returning.
 ******************************************************************************/
static int scan_env_file(const char *filepath, char *dst, int dstSz)
{
    FILE *f;
    char line[1024];

    f = fopen(filepath, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MERKLE_NEON=", 12) == 0) {
            char *val = line + 12;
            /* Strip surrounding quotes and trailing whitespace */
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

/******************************************************************************
 * Function:    mtc_db_get_connstr
 *
 * Description:
 *   Resolves the PostgreSQL connection string from one of three sources
 *   (in priority order): $MERKLE_NEON env var, --tokenpath file, or
 *   ~/.env fallback.  The result is cached in a static buffer so
 *   subsequent calls return immediately.
 *
 * Returns:
 *   Pointer to an internal static buffer with the connection string.
 *   NULL if MERKLE_NEON was not found in any source.
 *
 * Notes:
 *   Returned pointer must NOT be freed by the caller.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_connect
 *
 * Description:
 *   Connects to PostgreSQL using the connection string resolved by
 *   mtc_db_get_connstr().
 *
 * Returns:
 *   Active PGconn pointer on success.  Caller owns the connection and
 *   must call PQfinish() when done.
 *   NULL on failure (error logged to stderr; the half-open connection
 *   is cleaned up internally).
 *
 * Side Effects:
 *   Prints a success message to stdout with fflush.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_ensure_connected
 *
 * Description:
 *   Checks if the DB connection is still alive. If the connection has
 *   dropped (Neon idle timeout, network blip), attempts to reconnect.
 *   Call before any DB operation to handle transient failures.
 *
 * Input Arguments:
 *   conn_ptr  - Pointer to the PGconn pointer (e.g., &store->db).
 *               On reconnect, the old connection is freed and replaced.
 *
 * Returns:
 *    0  if the connection is good (possibly after reconnect).
 *   -1  if reconnect failed (connection is NULL).
 ******************************************************************************/
int mtc_db_ensure_connected(PGconn **conn_ptr)
{
    if (!conn_ptr) return -1;

    /* No connection at all */
    if (!*conn_ptr) {
        *conn_ptr = mtc_db_connect();
        return *conn_ptr ? 0 : -1;
    }

    /* Check if connection is still alive */
    if (PQstatus(*conn_ptr) == CONNECTION_OK) {
        /* Connection looks OK, but Neon may have closed it server-side.
         * Send a lightweight query to confirm. */
        PGresult *res = PQexec(*conn_ptr, "SELECT 1");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
            PQclear(res);
            return 0;  /* Connection is good */
        }
        PQclear(res);
        /* Fall through to reconnect */
    }

    /* Connection is dead — reconnect */
    fprintf(stderr, "[db] connection lost, attempting reconnect...\n");
    PQfinish(*conn_ptr);
    *conn_ptr = NULL;

    *conn_ptr = mtc_db_connect();
    if (*conn_ptr) {
        fprintf(stderr, "[db] reconnected successfully\n");
        return 0;
    }

    fprintf(stderr, "[db] reconnect failed\n");
    return -1;
}

/* ------------------------------------------------------------------ */
/* Schema                                                              */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    mtc_db_init_schema
 *
 * Description:
 *   Creates all required tables, indexes, and applies column migrations
 *   for the MTC CA database.  All statements use IF NOT EXISTS / ADD
 *   COLUMN IF NOT EXISTS, so this is safe to call on every startup.
 *
 * Input Arguments:
 *   conn  - Active PostgreSQL connection.  Must not be NULL.
 *
 * Returns:
 *    0  on success.
 *   -1  if any DDL statement failed (error logged to stderr).
 *
 * Side Effects:
 *   Creates/alters tables: mtc_log_entries, mtc_checkpoints,
 *   mtc_landmarks, mtc_certificates, mtc_ca_config, mtc_revocations,
 *   mtc_enrollment_nonces.
 ******************************************************************************/
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
        /* Migration: add ca_index to older nonce tables that lack it */
        "ALTER TABLE mtc_enrollment_nonces ADD COLUMN IF NOT EXISTS "
        "  ca_index INTEGER NOT NULL DEFAULT -1;"
        /* Migration: operator-assigned label for ~/.TPM/<domain>-<label>/ */
        "ALTER TABLE mtc_enrollment_nonces ADD COLUMN IF NOT EXISTS "
        "  label TEXT;"
        /* Migration: make fp nullable so the CA can issue long-lived
         * reservation nonces (fp late-bound at consume).  Running this
         * on a schema where fp is already nullable is a no-op. */
        "ALTER TABLE mtc_enrollment_nonces ALTER COLUMN fp DROP NOT NULL;"
        /* Partial index for efficient pending-nonce lookups by domain+fp */
        "CREATE INDEX IF NOT EXISTS idx_nonce_domain_fp "
        "  ON mtc_enrollment_nonces (domain, fp) "
        "  WHERE status = 'pending';"
        /* Uniqueness: one pending label per (domain, label).  Partial so
         * legacy no-label rows (label IS NULL) are unconstrained. */
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_nonce_domain_label_pending "
        "  ON mtc_enrollment_nonces (domain, label) "
        "  WHERE status = 'pending' AND label IS NOT NULL;";

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

/******************************************************************************
 * Function:    mtc_db_save_entry
 *
 * Description:
 *   Persists a Merkle tree log entry.  Uses ON CONFLICT DO NOTHING so
 *   duplicate inserts for the same index are silently ignored.
 *
 * Input Arguments:
 *   conn           - Active PostgreSQL connection.
 *   index          - Log entry index (primary key).
 *   entry_type     - Entry type code.
 *   tbs_json       - JSON string of the TBS data (may be NULL).
 *   serialized     - Binary serialized entry (sent as BYTEA, binary format).
 *   serialized_sz  - Length of serialized in bytes.
 *   leaf_hash      - 32-byte leaf hash (sent as BYTEA, binary format).
 *
 * Returns:
 *    0  on success.
 *   -1  on query failure.
 ******************************************************************************/
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
    /* Binary format for BYTEA columns */
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

/******************************************************************************
 * Function:    mtc_db_load_entries
 *
 * Description:
 *   Loads all log entries from mtc_log_entries, ordered by index.
 *   Builds a json_object array where each element contains: index,
 *   entry_type, tbs_data, serialized_hex, and serialized_len.
 *
 * Input Arguments:
 *   conn     - Active PostgreSQL connection.
 *   out_arr  - Pointer that receives a new json_object array.
 *
 * Returns:
 *   Number of rows loaded (>= 0), or -1 on query failure.
 *
 * Notes:
 *   Caller owns *out_arr and must free with json_object_put().
 *   BYTEA columns are returned in text mode and unescaped via
 *   PQunescapeBytea, then re-encoded as hex strings in JSON.
 ******************************************************************************/
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

        /* tbs_data: JSONB stored as text — parse back into a json_object */
        if (!PQgetisnull(res, i, 2)) {
            struct json_object *tbs = json_tokener_parse(PQgetvalue(res, i, 2));
            json_object_object_add(entry, "tbs_data",
                tbs ? tbs : json_object_new_null());
        }

        /* serialized: BYTEA in text mode → unescape → re-encode as hex */
        {
            size_t bin_len = 0;
            unsigned char *bin = PQunescapeBytea(
                (const unsigned char*)PQgetvalue(res, i, 3), &bin_len);
            if (bin) {
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

/******************************************************************************
 * Function:    mtc_db_save_checkpoint
 *
 * Description:
 *   Inserts a Merkle tree checkpoint record.
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   log_id     - Log identifier string.
 *   tree_size  - Number of leaves at checkpoint time.
 *   root_hash  - Hex-encoded root hash string.
 *   ts         - UNIX timestamp (double precision).
 *
 * Returns:
 *    0  on success.
 *   -1  on query failure.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_load_checkpoints
 *
 * Description:
 *   Loads all checkpoints for a given log ID, ordered by insertion order.
 *   Returns a json_object array of checkpoint objects.
 *
 * Input Arguments:
 *   conn     - Active PostgreSQL connection.
 *   log_id   - Log identifier to filter by.
 *   out_arr  - Pointer that receives a new json_object array.
 *
 * Returns:
 *   Number of rows loaded (>= 0), or -1 on query failure.
 *
 * Notes:
 *   Caller owns *out_arr and must free with json_object_put().
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_save_landmark
 *
 * Description:
 *   Records a landmark tree size.  Uses ON CONFLICT DO NOTHING so
 *   duplicate tree sizes are silently ignored.
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   tree_size  - Tree size to record.
 *
 * Returns:
 *    0  on success.
 *   -1  on query failure.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_load_landmarks
 *
 * Description:
 *   Loads landmark tree sizes into a caller-owned integer array, sorted
 *   in ascending order.
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   out        - Caller-owned array to fill with tree sizes.
 *   max_count  - Capacity of out.  Rows beyond this limit are dropped.
 *
 * Returns:
 *   Number of landmarks written to out.  0 on query failure.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_save_certificate
 *
 * Description:
 *   Saves or updates a certificate JSON blob.  Uses ON CONFLICT to upsert
 *   if the index already exists.
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   index      - Certificate log index (primary key).
 *   cert_json  - JSON string of the certificate.
 *
 * Returns:
 *    0  on success.
 *   -1  on query failure.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_load_certificate
 *
 * Description:
 *   Loads a single certificate by log index and parses it from JSON.
 *
 * Input Arguments:
 *   conn   - Active PostgreSQL connection.
 *   index  - Certificate log index to look up.
 *
 * Returns:
 *   Parsed json_object on success.  Caller owns and must free with
 *   json_object_put().
 *   NULL if not found or on error.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_load_all_certificates
 *
 * Description:
 *   Loads all certificates into an index-addressed array.  Allocates a
 *   calloc'd array of (max_index + 1) json_object pointers; slots without
 *   a certificate are NULL.
 *
 * Input Arguments:
 *   conn   - Active PostgreSQL connection.
 *   out    - Receives a calloc'd array of json_object pointers.
 *   count  - Receives the array length (max_index + 1).
 *
 * Returns:
 *   Number of certificate rows loaded (>= 0), or -1 on failure.
 *
 * Notes:
 *   Caller must free each non-NULL element with json_object_put(), then
 *   free(*out) itself.
 ******************************************************************************/
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

    /* Find max index to size the array — indices may be sparse */
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

/******************************************************************************
 * Function:    mtc_db_save_revocation
 *
 * Description:
 *   Records a certificate revocation with a timestamp and optional reason.
 *
 * Input Arguments:
 *   conn        - Active PostgreSQL connection.
 *   cert_index  - Log index of the certificate to revoke.
 *   reason      - Human-readable reason.  NULL defaults to "unspecified".
 *
 * Returns:
 *    0  on success.
 *   -1  on query failure.
 *
 * Notes:
 *   Multiple revocation records for the same cert_index are allowed
 *   (the table has no unique constraint on cert_index).
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_load_revocations
 *
 * Description:
 *   Loads revoked certificate indices into a caller-owned array, sorted
 *   in ascending order.
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   indices    - Caller-owned array to fill with cert indices.
 *   max_count  - Capacity of indices.  Rows beyond this are dropped.
 *
 * Returns:
 *   Number of revocations written to indices.  0 on query failure.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_is_revoked
 *
 * Description:
 *   Checks whether a certificate has been revoked by looking for any
 *   matching row in mtc_revocations.
 *
 * Input Arguments:
 *   conn        - Active PostgreSQL connection.
 *   cert_index  - Log index of the certificate to check.
 *
 * Returns:
 *   1  if at least one revocation record exists.
 *   0  if not revoked, or on query error.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_save_config
 *
 * Description:
 *   Saves a CA configuration key/value pair.  Uses ON CONFLICT to upsert
 *   if the key already exists.
 *
 * Input Arguments:
 *   conn   - Active PostgreSQL connection.
 *   key    - Configuration key (primary key).
 *   value  - Configuration value string.
 *
 * Returns:
 *    0  on success.
 *   -1  on query failure.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_load_config
 *
 * Description:
 *   Loads a CA configuration value by key.
 *
 * Input Arguments:
 *   conn  - Active PostgreSQL connection.
 *   key   - Configuration key to look up.
 *
 * Returns:
 *   strdup'd value string on success.  Caller must free().
 *   NULL if the key was not found or on query error.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_create_nonce
 *
 * Description:
 *   Generates a 256-bit cryptographically random enrollment nonce using
 *   wolfCrypt WC_RNG and inserts it into the mtc_enrollment_nonces table
 *   with status 'pending'.  Stale nonces are expired first.  If a pending
 *   nonce already exists for the given domain+fp pair and has not yet
 *   expired, that existing nonce is returned unchanged (idempotent
 *   reissue) — no new row is inserted.
 *
 * Input Arguments:
 *   conn         - Active PostgreSQL connection.  Must not be NULL.
 *   domain       - Domain name bound to this nonce.
 *   fp_hex       - Public key fingerprint (hex) bound to this nonce.
 *   ca_index     - Log index of the issuing CA (-1 for CA self-enrollment
 *                  via DNS).
 *   nonce_out    - Buffer for the hex nonce.  Must be at least
 *                  MTC_NONCE_HEX_LEN + 1 (65) bytes.
 *   expires_out  - Receives the UNIX expiration timestamp.
 *
 * Returns:
 *    0  on success (new or reused nonce written to nonce_out).
 *   -1  on failure (NULL conn, RNG error, or DB insert error).
 *
 * Side Effects:
 *   - Expires stale nonces via mtc_db_expire_nonces().
 *   - Inserts a row into mtc_enrollment_nonces.
 ******************************************************************************/
int mtc_db_create_nonce(PGconn *conn, const char *domain, const char *fp_hex,
                        int ca_index, const char *label,
                        long ttl_secs,
                        char *nonce_out, long *expires_out,
                        char *label_out, size_t label_out_sz)
{
    PGresult *res;
    WC_RNG rng;
    uint8_t rand_bytes[32]; /* 256-bit nonce */
    char ttl_str[32], ca_idx_str[16];
    const char *ins_params[6];
    int i;

    if (!conn) return -1;
    if (label_out && label_out_sz > 0) label_out[0] = '\0';
    if (ttl_secs <= 0) ttl_secs = MTC_NONCE_TTL_SECS;

    /* Expire stale nonces first */
    mtc_db_expire_nonces(conn);

    /* If a pending non-expired nonce already exists matching the
     * incoming constraints, return it again (idempotent reissue).
     * Match key depends on which fields the caller pinned:
     *   - fp_hex given:  (domain, fp)
     *   - fp_hex NULL:   (domain, label) for long-lived reservation
     *                    mode; label must also be non-NULL.
     * Label is immutable once set — return whatever the FIRST call
     * stored. */
    if (fp_hex) {
        const char *params[2] = { domain, fp_hex };
        res = PQexecParams(conn,
            "SELECT nonce, EXTRACT(EPOCH FROM expires_at)::bigint, label "
            "FROM mtc_enrollment_nonces "
            "WHERE domain = $1 AND fp = $2 AND status = 'pending' "
            "AND expires_at > now() LIMIT 1",
            2, NULL, params, NULL, NULL, 0);
    } else if (label && label[0]) {
        const char *params[2] = { domain, label };
        res = PQexecParams(conn,
            "SELECT nonce, EXTRACT(EPOCH FROM expires_at)::bigint, label "
            "FROM mtc_enrollment_nonces "
            "WHERE domain = $1 AND label = $2 AND fp IS NULL "
            "AND status = 'pending' AND expires_at > now() LIMIT 1",
            2, NULL, params, NULL, NULL, 0);
    } else {
        /* No fp AND no label — fail.  A fingerprint-less nonce must
         * at least pin the label so a leaked nonce can't be used for
         * an arbitrary identity within the domain. */
        fprintf(stderr, "[db] refusing to issue nonce with neither "
                "fp nor label\n");
        return -1;
    }

    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        const char *existing = PQgetvalue(res, 0, 0);
        const char *exp_s    = PQgetvalue(res, 0, 1);
        if (existing && strlen(existing) == MTC_NONCE_HEX_LEN) {
            memcpy(nonce_out, existing, MTC_NONCE_HEX_LEN);
            nonce_out[MTC_NONCE_HEX_LEN] = '\0';
            *expires_out = strtol(exp_s, NULL, 10);
            if (label_out && label_out_sz > 0 && !PQgetisnull(res, 0, 2)) {
                snprintf(label_out, label_out_sz, "%s",
                         PQgetvalue(res, 0, 2));
            }
            PQclear(res);
            return 0;
        }
    }
    PQclear(res);

    /* Generate 256-bit random nonce via wolfCrypt CSPRNG */
    if (wc_InitRng(&rng) != 0) return -1;
    if (wc_RNG_GenerateBlock(&rng, rand_bytes, sizeof(rand_bytes)) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    wc_FreeRng(&rng);

    for (i = 0; i < 32; i++)
        snprintf(nonce_out + i * 2, 3, "%02x", rand_bytes[i]);
    nonce_out[64] = '\0';

    *expires_out = (long)time(NULL) + ttl_secs;

    /* Insert pending nonce with TTL-based expiration.  fp and label
     * columns are both nullable: pass NULL via a NULL entry in
     * paramValues. */
    snprintf(ttl_str, sizeof(ttl_str), "%ld seconds", ttl_secs);
    snprintf(ca_idx_str, sizeof(ca_idx_str), "%d", ca_index);
    ins_params[0] = nonce_out;
    ins_params[1] = domain;
    ins_params[2] = fp_hex;      /* NULL OK */
    ins_params[3] = ca_idx_str;
    ins_params[4] = ttl_str;
    ins_params[5] = (label && label[0]) ? label : NULL;

    res = PQexecParams(conn,
        "INSERT INTO mtc_enrollment_nonces "
        "(nonce, domain, fp, ca_index, expires_at, label) "
        "VALUES ($1, $2, $3, $4, now() + $5::interval, $6)",
        6, NULL, ins_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] nonce insert failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    /* Echo the input label back via label_out when the caller asked. */
    if (label_out && label_out_sz > 0 && label && label[0])
        snprintf(label_out, label_out_sz, "%s", label);

    return 0;
}

/******************************************************************************
 * Function:    mtc_db_find_ca_for_domain
 *
 * Description:
 *   Searches mtc_certificates for a registered CA matching the given
 *   domain.  CAs are enrolled with subject "<domain>-ca", so this
 *   function builds that pattern and queries for the most recent match.
 *
 * Input Arguments:
 *   conn    - Active PostgreSQL connection.  Must not be NULL.
 *   domain  - Domain name to search for.
 *
 * Returns:
 *   CA log index (>= 0) on success.
 *  -1  if not found, no connection, or on query error.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_validate_nonce
 *
 * Description:
 *   Validates a nonce without consuming it.  Checks that the nonce exists,
 *   has status 'pending', and is not expired.  Optionally matches domain
 *   and/or fingerprint for defense-in-depth (the nonce is bound to
 *   domain+fp at creation time, so matching the nonce alone is sufficient,
 *   but callers may provide additional fields).
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   nonce_hex  - Hex-encoded nonce to validate.
 *   domain     - Domain to match (NULL or "" to skip domain check).
 *   fp_hex     - Fingerprint to match (NULL or "" to skip fp check).
 *
 * Returns:
 *   1  if the nonce is valid (pending, unexpired, matching).
 *   0  if invalid, expired, consumed, not found, or no connection.
 *
 * Notes:
 *   For enrollment flows, prefer mtc_db_validate_and_consume_nonce()
 *   to avoid TOCTOU races between validation and consumption.
 ******************************************************************************/
int mtc_db_validate_nonce(PGconn *conn, const char *nonce_hex,
                          const char *domain, const char *fp_hex)
{
    PGresult *res;
    int valid;

    if (!conn) return 0;

    /* Match specificity depends on what the caller provides — defense-in-depth */
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

/******************************************************************************
 * Function:    mtc_db_validate_and_consume_nonce
 *
 * Description:
 *   Atomically validates and consumes a nonce in a single UPDATE query.
 *   The WHERE clause enforces pending status, unexpired, and optional
 *   domain/fp matching.  If zero rows are affected, the nonce was invalid,
 *   expired, or already consumed.  This eliminates the TOCTOU race
 *   between separate validate and consume steps.
 *
 * Input Arguments:
 *   conn          - Active PostgreSQL connection.
 *   nonce_hex     - Hex-encoded nonce to validate and consume.
 *   domain        - Domain to match (NULL or "" to skip domain check).
 *   fp_hex        - Fingerprint to match (NULL or "" to skip fp check).
 *   label_out     - May be NULL.  On success, receives the stored label
 *                   (empty string if the row's label is NULL).  Buffer
 *                   must be at least MTC_LABEL_MAX + 1 bytes.
 *   label_out_sz  - Size of label_out (ignored if NULL).
 *
 * Returns:
 *   1  if the nonce was valid and is now consumed.
 *   0  if invalid, expired, already consumed, or no connection.
 ******************************************************************************/
int mtc_db_validate_and_consume_nonce(PGconn *conn, const char *nonce_hex,
                                      const char *domain, const char *fp_hex,
                                      char *label_out, size_t label_out_sz)
{
    PGresult *res;
    int consumed;

    if (!conn) return 0;
    if (label_out && label_out_sz > 0) label_out[0] = '\0';

    /* Atomic: UPDATE only if pending+unexpired+matching, consume in one
     * shot.  RETURNING label so the caller can echo it in the bootstrap
     * response JSON.
     *
     * Late-bind semantics: the stored fp may be NULL (long-lived
     * reservation nonce).  The fp predicate accepts (fp = $3 OR fp IS
     * NULL), and the SET clause writes the actual consumer fp into
     * the row via COALESCE. */
    if (domain && domain[0] && fp_hex && fp_hex[0]) {
        const char *params[3] = { nonce_hex, domain, fp_hex };
        res = PQexecParams(conn,
            "UPDATE mtc_enrollment_nonces "
            "SET status = 'consumed', fp = COALESCE(fp, $3) "
            "WHERE nonce = $1 AND domain = $2 "
            "AND (fp = $3 OR fp IS NULL) "
            "AND status = 'pending' AND expires_at > now() "
            "RETURNING label",
            3, NULL, params, NULL, NULL, 0);
    }
    else if (domain && domain[0]) {
        const char *params[2] = { nonce_hex, domain };
        res = PQexecParams(conn,
            "UPDATE mtc_enrollment_nonces SET status = 'consumed' "
            "WHERE nonce = $1 AND domain = $2 "
            "AND status = 'pending' AND expires_at > now() "
            "RETURNING label",
            2, NULL, params, NULL, NULL, 0);
    }
    else {
        const char *params[1] = { nonce_hex };
        res = PQexecParams(conn,
            "UPDATE mtc_enrollment_nonces SET status = 'consumed' "
            "WHERE nonce = $1 "
            "AND status = 'pending' AND expires_at > now() "
            "RETURNING label",
            1, NULL, params, NULL, NULL, 0);
    }

    consumed = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    if (consumed && label_out && label_out_sz > 0 &&
        !PQgetisnull(res, 0, 0)) {
        snprintf(label_out, label_out_sz, "%s", PQgetvalue(res, 0, 0));
    }
    PQclear(res);
    return consumed;
}

/******************************************************************************
 * Function:    mtc_db_consume_nonce
 *
 * Description:
 *   Unconditionally marks a nonce as consumed regardless of its current
 *   status or expiration.
 *
 * Input Arguments:
 *   conn       - Active PostgreSQL connection.
 *   nonce_hex  - Hex-encoded nonce to consume.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_db_expire_nonces
 *
 * Description:
 *   Bulk-expires all pending nonces that have passed their TTL by setting
 *   status = 'expired' where status = 'pending' and expires_at <= now().
 *
 * Input Arguments:
 *   conn  - Active PostgreSQL connection.
 *
 * Side Effects:
 *   Updates rows in mtc_enrollment_nonces.
 ******************************************************************************/
void mtc_db_expire_nonces(PGconn *conn)
{
    PGresult *res;
    if (!conn) return;

    res = PQexec(conn,
        "UPDATE mtc_enrollment_nonces SET status = 'expired' "
        "WHERE status = 'pending' AND expires_at <= now()");
    PQclear(res);
}

/******************************************************************************
 * Function:    mtc_db_cancel_nonce
 *
 * Description:
 *   Early-cancel a pending reservation nonce.  Atomically expires the
 *   row matching (domain, label, ca_index) if status = 'pending'.
 *   Authorization: the caller's ca_index (MQC peer_index) must match
 *   the row's stored ca_index — so only the CA that issued the
 *   reservation can cancel it.  Idempotent: a second call against a
 *   row that was already cancelled/consumed returns 0, not error.
 *
 * Input Arguments:
 *   conn             - Active PostgreSQL connection.
 *   domain           - Domain the nonce was issued for.
 *   label            - Label the nonce was bound to.
 *   caller_ca_index  - MQC caller's cert_index; must equal row's ca_index.
 *
 * Returns:
 *    1  if a row was cancelled.
 *    0  if no matching pending row was found (not an error).
 *   -1  on DB error (bad connection, malformed query).
 ******************************************************************************/
int mtc_db_cancel_nonce(PGconn *conn, const char *domain,
                        const char *label, int caller_ca_index)
{
    PGresult *res;
    char ca_idx_str[16];
    const char *params[3];
    int rc;

    if (!conn || !domain || !label) return -1;

    snprintf(ca_idx_str, sizeof(ca_idx_str), "%d", caller_ca_index);
    params[0] = domain;
    params[1] = label;
    params[2] = ca_idx_str;

    res = PQexecParams(conn,
        "UPDATE mtc_enrollment_nonces SET status = 'expired' "
        "WHERE domain = $1 AND label = $2 AND ca_index = $3 "
        "AND status = 'pending' "
        "RETURNING nonce",
        3, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[db] cancel_nonce failed: %s\n",
                PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    rc = (PQntuples(res) > 0) ? 1 : 0;
    PQclear(res);
    return rc;
}

/******************************************************************************
 * Function:    mtc_db_get_public_key
 *
 * Description:
 *   Look up a public key PEM by key_name from the mtc_public_keys table.
 *
 * Input Arguments:
 *   conn      - Active PostgreSQL connection.
 *   key_name  - Key name to look up.
 *
 * Returns:
 *   strdup'd PEM string on success.  Caller must free().
 *   NULL if not found or on error.
 ******************************************************************************/
char *mtc_db_get_public_key(PGconn *conn, const char *key_name)
{
    PGresult *res;
    const char *params[1];
    char *val;

    if (!conn || !key_name) return NULL;

    params[0] = key_name;
    res = PQexecParams(conn,
        "SELECT key_value FROM mtc_public_keys WHERE key_name = $1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL;
    }

    val = strdup(PQgetvalue(res, 0, 0));
    PQclear(res);
    return val;
}

/******************************************************************************
 * Function:    mtc_db_save_public_key
 *
 * Description:
 *   Upsert a public key PEM in the mtc_public_keys table.  Called by the
 *   bootstrap enrollment handler right after persisting the cert, so the
 *   server's own state stays self-contained and we don't rely on clients
 *   to push their pubkey into Neon out of band.
 *
 *   key_name follows the on-disk TPM directory convention:
 *     - just <subject>              for a label-less leaf / CA
 *     - <subject>-<label>           for a labelled leaf
 *   That way `/public-key/<dir_name>` queries resolve straight from the
 *   same string the client uses as its TPM directory name.
 *
 * Input Arguments:
 *   conn      - Active PostgreSQL connection.
 *   key_name  - Canonical identifier (see above).
 *   key_pem   - Full PEM-encoded public key, newline-separated.
 *
 * Returns:
 *    0  on success (INSERT or UPDATE).
 *   -1  on query failure.
 ******************************************************************************/
int mtc_db_save_public_key(PGconn *conn, const char *key_name,
                           const char *key_pem)
{
    PGresult *res;
    const char *params[2];

    if (!conn || !key_name || !key_pem) return -1;

    params[0] = key_name;
    params[1] = key_pem;
    res = PQexecParams(conn,
        "INSERT INTO mtc_public_keys (key_name, key_value) VALUES ($1, $2) "
        "ON CONFLICT (key_name) DO UPDATE SET key_value = EXCLUDED.key_value",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] save_public_key failed: %s\n",
                PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}
