/* mtc_db.h — PostgreSQL (Neon) persistence for MTC CA server */

#ifndef MTC_DB_H
#define MTC_DB_H

#include <libpq-fe.h>
#include <json-c/json.h>
#include <stdint.h>

/* Get connection string from ~/.env (MERKLE_NEON) or environment.
 * Returns NULL if not found. */
const char *mtc_db_get_connstr(void);

/* Connect to PostgreSQL. Returns NULL on failure. */
PGconn *mtc_db_connect(void);

/* Create tables if they don't exist. Returns 0 on success. */
int mtc_db_init_schema(PGconn *conn);

/* --- Log entries --- */
int  mtc_db_save_entry(PGconn *conn, int index, int entry_type,
                       const char *tbs_json, const uint8_t *serialized,
                       int serialized_sz, const uint8_t *leaf_hash);
int  mtc_db_load_entries(PGconn *conn, struct json_object **out_arr);

/* --- Checkpoints --- */
int  mtc_db_save_checkpoint(PGconn *conn, const char *log_id,
                            int tree_size, const char *root_hash, double ts);
int  mtc_db_load_checkpoints(PGconn *conn, const char *log_id,
                             struct json_object **out_arr);

/* --- Landmarks --- */
int  mtc_db_save_landmark(PGconn *conn, int tree_size);
int  mtc_db_load_landmarks(PGconn *conn, int *out, int max_count);

/* --- Certificates --- */
int  mtc_db_save_certificate(PGconn *conn, int index, const char *cert_json);
struct json_object *mtc_db_load_certificate(PGconn *conn, int index);
int  mtc_db_load_all_certificates(PGconn *conn,
                                   struct json_object ***out, int *count);

/* --- CA config (key persistence) --- */
int  mtc_db_save_config(PGconn *conn, const char *key, const char *value);
char *mtc_db_load_config(PGconn *conn, const char *key);

#endif
