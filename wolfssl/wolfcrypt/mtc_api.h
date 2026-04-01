/*
 * MTC Public API (C).
 *
 * User-facing API for Merkle Tree Certificate operations.
 * Wraps HTTP calls to the CA/Log server and local ~/.TPM storage
 * into clean C function calls.
 *
 * Usage:
 *     mtc_conn_t *conn = MTC_Connect("http://localhost:8443");
 *     mtc_cert_t *cert = MTC_Enroll(conn, "urn:ajax-inc:app:myapp", NULL);
 *     mtc_verify_t *result = MTC_Verify(conn, cert->index);
 *     MTC_Free_Verify(result);
 *     MTC_Free_Cert(cert);
 *     MTC_Disconnect(conn);
 */

#ifndef WOLFSSL_MTC_API_H
#define WOLFSSL_MTC_API_H

/* Avoid C99 headers for C89 compatibility */
#ifndef __cplusplus
    #ifndef bool
        #define bool  int
        #define true  1
        #define false 0
        #define MTC_BOOL_DEFINED
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Types
 * ----------------------------------------------------------------------- */

typedef struct mtc_conn mtc_conn_t;

typedef struct mtc_cert {
    int          index;
    char        *subject;
    char        *trust_anchor_id;
    double       not_before;
    double       not_after;
    char        *extensions_json;    /* JSON string of extensions */
    bool         has_landmark;
    char        *local_path;         /* path in ~/.TPM, or NULL */
} mtc_cert_t;

typedef struct mtc_verify {
    int          index;
    char        *subject;
    bool         valid;
    bool         inclusion_proof;
    bool         cosignature_valid;
    bool         not_expired;
    int          landmark_valid;     /* 1=valid, 0=invalid, -1=not checked */
    char        *error;              /* NULL if no error */
} mtc_verify_t;

typedef struct mtc_find_result {
    int          index;
    char        *subject;
} mtc_find_result_t;

typedef struct mtc_find_results {
    int                  count;
    mtc_find_result_t   *results;
} mtc_find_results_t;

typedef struct mtc_status {
    char        *server_url;
    char        *ca_name;
    char        *log_id;
    int          tree_size;
    char        *root_hash;
    int          landmark_count;
    int          local_cert_count;
} mtc_status_t;

typedef struct mtc_extensions {
    int          count;
    char       **keys;
    char       **values;
} mtc_extensions_t;

/* -----------------------------------------------------------------------
 * Connection
 * ----------------------------------------------------------------------- */

/* Connect to a CA/Log server and bootstrap trust.
 * Returns NULL on failure. */
mtc_conn_t *MTC_Connect(const char *server_url);

/* Disconnect and free connection resources. */
void MTC_Disconnect(mtc_conn_t *conn);

/* Set the local certificate store path (default: ~/.TPM). */
void MTC_Conn_SetStorePath(mtc_conn_t *conn, const char *path);

/* Connection accessors (struct is opaque). */
const char *MTC_Conn_CA_Name(const mtc_conn_t *conn);
const char *MTC_Conn_Log_ID(const mtc_conn_t *conn);
int         MTC_Conn_Tree_Size(const mtc_conn_t *conn);

/* -----------------------------------------------------------------------
 * Enrollment
 * ----------------------------------------------------------------------- */

/* Generate keys, request a certificate, store in ~/.TPM.
 * algorithm: "EC-P256" or "Ed25519" (NULL defaults to EC-P256).
 * extensions: optional, may be NULL.
 * Returns NULL on failure. Caller must MTC_Free_Cert(). */
mtc_cert_t *MTC_Enroll(mtc_conn_t *conn,
                        const char *subject,
                        const char *algorithm,
                        int validity_days,
                        const mtc_extensions_t *extensions);

/* -----------------------------------------------------------------------
 * Verification
 * ----------------------------------------------------------------------- */

/* Verify a certificate by index. Checks ~/.TPM first, then server.
 * Returns NULL on failure. Caller must MTC_Free_Verify(). */
mtc_verify_t *MTC_Verify(mtc_conn_t *conn, int index);

/* -----------------------------------------------------------------------
 * Search
 * ----------------------------------------------------------------------- */

/* Search certificates by subject (case-insensitive substring).
 * Returns NULL on failure. Caller must MTC_Free_Find(). */
mtc_find_results_t *MTC_Find(mtc_conn_t *conn, const char *query);

/* -----------------------------------------------------------------------
 * Local certificates
 * ----------------------------------------------------------------------- */

/* List all certificates in ~/.TPM.
 * count is set to the number of results.
 * Returns NULL if none. Caller must free each cert and the array. */
mtc_cert_t **MTC_List(int *count);

/* -----------------------------------------------------------------------
 * Status
 * ----------------------------------------------------------------------- */

/* Get server and trust store status.
 * Returns NULL on failure. Caller must MTC_Free_Status(). */
mtc_status_t *MTC_Status(mtc_conn_t *conn);

/* -----------------------------------------------------------------------
 * Renewal
 * ----------------------------------------------------------------------- */

/* Renew a certificate with fresh keys, same subject/extensions.
 * Old cert/key archived as .old in ~/.TPM.
 * Returns NULL on failure. Caller must MTC_Free_Cert(). */
mtc_cert_t *MTC_Renew(mtc_conn_t *conn, int index, int validity_days);

/* -----------------------------------------------------------------------
 * Revocation
 * ----------------------------------------------------------------------- */

/* Request revocation of a certificate.
 * Returns 0 on success, -1 on failure.
 * Note: actual revocation is enforced by relying parties, not the holder. */
int MTC_Revoke(mtc_conn_t *conn, int index);

/* -----------------------------------------------------------------------
 * Memory management
 * ----------------------------------------------------------------------- */

void MTC_Free_Cert(mtc_cert_t *cert);
void MTC_Free_Verify(mtc_verify_t *result);
void MTC_Free_Find(mtc_find_results_t *results);
void MTC_Free_Status(mtc_status_t *status);

/* -----------------------------------------------------------------------
 * Utility
 * ----------------------------------------------------------------------- */

/* Build an extensions struct. Caller must MTC_Free_Extensions(). */
mtc_extensions_t *MTC_Extensions_New(void);
int MTC_Extensions_Add(mtc_extensions_t *ext, const char *key, const char *value);
void MTC_Free_Extensions(mtc_extensions_t *ext);

/* Return last error message, or NULL. */
const char *MTC_Last_Error(void);

#ifdef __cplusplus
}
#endif

#ifdef MTC_BOOL_DEFINED
    #undef bool
    #undef true
    #undef false
    #undef MTC_BOOL_DEFINED
#endif

#endif /* WOLFSSL_MTC_API_H */
