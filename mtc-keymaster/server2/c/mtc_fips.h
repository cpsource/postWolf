/******************************************************************************
 * File:        mtc_fips.h
 * Purpose:     FIPS-manifest submission handler (entry_type 0x02 in the log).
 *
 * Description:
 *   Implements the spec-canonical-leaf v1 acceptance pipeline (see
 *   ../../../fips-framework/spec-canonical-leaf.md §"Server-side
 *   validation order"): pre-crypto length filter, strict JSON parse,
 *   canonical-form byte-equality round-trip, cert lookup + revocation
 *   check, ML-DSA-87 signature verify, time-bound check, append via
 *   mtc_store_add_entry, and receipt build.
 *
 *   The FIPS-manifest leaves share the existing transparency log
 *   (mtc_log_entries) with cert leaves (entry_type 0x01); the
 *   per-package/per-version search index lives in
 *   mtc_fips_manifest_entries (created by mtc_db_init_schema).
 ******************************************************************************/

#ifndef MTC_FIPS_H
#define MTC_FIPS_H

#include <stdint.h>
#include <stddef.h>
#include <json-c/json.h>

#include "mtc_store.h"

/* Public-input size guard (matches spec §"Server-side validation order"
 * step 1 "body.len > 16 MiB" rule).  Pre-crypto filter — no JSON parse
 * runs above this size. */
#define MTC_FIPS_BODY_MAX     (16 * 1024 * 1024)

/* Schema version this server implements.  Bumping is a flag-day cutover. */
#define MTC_FIPS_SCHEMA_VERSION 1

/* Entry-type byte prefix for FIPS-manifest leaves.  Cert leaves use
 * 0x01; FIPS manifests use 0x02.  See spec §"Wire format". */
#define MTC_FIPS_ENTRY_TYPE   0x02

/**
 * @brief Process a /fips/manifest submission body.
 *
 * @param store         Live MtcStore (DB connection + tree + cosigner key).
 * @param body          Raw POST body bytes (UTF-8 canonical JSON, no
 *                      0x02 entry-type prefix — that's added internally
 *                      before the leaf is appended).
 * @param body_len      Length of body in bytes.
 * @param out_receipt   On success, receives a fresh json_object holding
 *                      the receipt (leaf_index, leaf_bytes_b64,
 *                      inclusion_proof, tree_size, tree_root,
 *                      cosignatures).  Caller json_object_put()s.
 * @param out_status    On failure, receives the HTTP-shaped status code
 *                      (400 for bad input, 403 for revoked publisher,
 *                      500 for internal error).
 * @param out_err_msg   Operator-facing error string (logged at INFO,
 *                      NOT echoed to the client unmodified per the
 *                      spec's "without disclosing which check failed"
 *                      posture).
 * @param err_msg_sz    Size of out_err_msg buffer.
 *
 * @return  0 on success, -1 on failure.
 */
int mtc_fips_submit(MtcStore *store,
                    const uint8_t *body, size_t body_len,
                    struct json_object **out_receipt,
                    int *out_status,
                    char *out_err_msg, size_t err_msg_sz);

/**
 * @brief Browse the FIPS-manifest log (read-only).
 *
 * Server-side replacement for direct DB access from leaves: lets any
 * client with a valid MQC handshake browse mtc_fips_manifest_entries
 * (joined against mtc_log_entries / mtc_revocations) without holding
 * MERKLE_NEON credentials.
 *
 * @param store              Live MtcStore (DB connection).
 * @param filter_publisher   Optional exact-match filter (NULL = no filter).
 * @param filter_package     Optional exact-match filter (NULL = no filter).
 * @param filter_version     Optional exact-match filter (NULL = no filter).
 * @param limit              Cap rows in list mode (<=0 means default 50).
 * @param detail_log_index   If >= 0, return single-row detail (includes
 *                           parsed manifest tbs_data); otherwise list mode.
 * @param out_response       On success, fresh json_object (caller frees).
 * @param out_status         HTTP-shaped status (200, 400, 404, 500).
 * @param out_err_msg        Operator-facing error string.
 * @param err_msg_sz         Size of out_err_msg buffer.
 *
 * @return 0 on success, -1 on failure.
 */
int mtc_fips_list(MtcStore *store,
                  const char *filter_publisher,
                  const char *filter_package,
                  const char *filter_version,
                  int limit,
                  int detail_log_index,
                  struct json_object **out_response,
                  int *out_status,
                  char *out_err_msg, size_t err_msg_sz);

/* Bounds applied by mtc_fips_list to filter strings (length only — values
 * are passed via PQexecParams placeholders, so SQL injection is impossible
 * regardless; this is a pre-DB sanity / DoS guard).  Must be >= the
 * matching ingest-side maxima in mtc_fips_submit. */
#define MTC_FIPS_LIST_FILTER_MAX  256

/* Default + maximum row cap for the list-mode response.  A leaf calling
 * /fips/list with no ?limit= gets the default; values above the cap are
 * silently clamped. */
#define MTC_FIPS_LIST_LIMIT_DEFAULT 50
#define MTC_FIPS_LIST_LIMIT_MAX     1000

/* Bound on revoke-request body size — pre-crypto filter, well above
 * any legitimate JSON envelope (PEM ~3.5 KiB + sig hex ~9.2 KiB). */
#define MTC_FIPS_REVOKE_BODY_MAX  (32 * 1024)

/* Freshness window for revoke timestamps (seconds, ±). */
#define MTC_FIPS_REVOKE_SKEW_SEC  300

/**
 * @brief Process a /fips/revoke submission body.
 *
 * Mirrors the cert-revoke validation pipeline but for FIPS-manifest
 * leaves.  Authorisation: either the publisher leaf cert (self-revoke)
 * OR the publisher's CA may sign.  See spec-canonical-leaf.md
 * "Manifest revocation".
 *
 * @param store         Live MtcStore.
 * @param body          Raw POST body (UTF-8 JSON envelope).
 * @param body_len      Length of body in bytes.
 * @param out_response  On success, fresh json_object (caller frees) of
 *                      shape {revoked:true, log_index, revoker_kind,
 *                      revoker_cert_index, reason}.
 * @param out_status    HTTP-shaped status (200, 400, 403, 404, 500).
 * @param out_err_msg   Operator-facing error string (logged at INFO/WARN,
 *                      NOT echoed unmodified to the client).
 * @param err_msg_sz    Size of out_err_msg buffer.
 *
 * @return 0 on success, -1 on failure.
 */
int mtc_fips_revoke(MtcStore *store,
                    const uint8_t *body, size_t body_len,
                    struct json_object **out_response,
                    int *out_status,
                    char *out_err_msg, size_t err_msg_sz);

/**
 * @brief Read-side: get latest revocation for a manifest by log_index.
 *
 * Used by /fips/revoked/<n>.  If the manifest has never been revoked,
 * out_response is `{log_index, revoked: false}`; if it has,
 * `{log_index, revoked: true, revoker_kind, revoker_cert_index,
 *  reason, revoked_at}` (latest row).
 *
 * @return 0 on success, -1 on failure (sets out_status).
 */
int mtc_fips_revoke_status(MtcStore *store, int log_index,
                           struct json_object **out_response,
                           int *out_status,
                           char *out_err_msg, size_t err_msg_sz);

#endif /* MTC_FIPS_H */
