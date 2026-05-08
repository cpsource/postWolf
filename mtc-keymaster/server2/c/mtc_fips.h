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

#endif /* MTC_FIPS_H */
