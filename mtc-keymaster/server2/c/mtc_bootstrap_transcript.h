/**
 * @file mtc_bootstrap_transcript.h
 * @brief Binary transcript builder for the bootstrap-response signature.
 *
 * @details
 * TODO #11 / ChatGPT review item #11.  The pre-fix design signed the
 * canonical-JSON serialization of the bootstrap response, relying on
 * json-c's `JSON_C_TO_STRING_PLAIN` flag to produce identical bytes
 * across the parse → mutate → serialize cycle on both signer and
 * verifier.  That implicit-canonicalization contract is fragile: a
 * json-c version bump that changes whitespace, key escaping, or
 * float formatting silently breaks signature verify.
 *
 * This module replaces the canonical-JSON contract with a fixed
 * binary transcript.  Same idiom as the MQC handshake transcript
 * (`MQC_HANDSHAKE_LABEL` / SHA-256-of-binary) and the DH bootstrap
 * transcript (`MTC_BOOTSTRAP_DH_LABEL` / 113-byte concat).  No
 * floats, no Unicode quirks, no library dependencies beyond json-c
 * for field extraction.
 *
 * Wire-format flag-day: the ctx label is bumped from
 * `mtc-bootstrap/v1\n\x00` to `mtc-bootstrap/v2\n\x00` so a v1
 * signature can never be confused with a v2 signature.  Per CLAUDE.md
 * "MQC wire-format invariants are NOT operator-tunable" and per
 * project memory `project_mqc_no_backwards_compat`, server + clients
 * are rebuilt and redeployed together.
 *
 * Linked into both the server (`mtc_server`) and the operator tools
 * (`bootstrap_ca`, `bootstrap_leaf`) so signer + verifier share a
 * single canonical implementation.
 */

#ifndef MTC_BOOTSTRAP_TRANSCRIPT_H
#define MTC_BOOTSTRAP_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>

/* Per-version protocol byte at the start of every transcript. */
#define MTC_BOOTSTRAP_RESP_TRANSCRIPT_V2  0x02

/* Versioned ctx label passed to wc_dilithium_sign_ctx_msg /
 * wc_dilithium_verify_ctx_msg.  16 bytes including the trailing NUL. */
#define MTC_BOOTSTRAP_LABEL      "mtc-bootstrap/v2\n\x00"
#define MTC_BOOTSTRAP_LABEL_LEN  16

/* Comfortable upper bound for the transcript buffer.  A full PEM
 * (~3.5 KB) plus the small fixed fields and length prefixes adds
 * up to well under 8 KB.  Callers should size their stack/heap
 * buffer accordingly. */
#define MTC_BOOTSTRAP_TRANSCRIPT_MAX  8192

/**
 * @brief  Build the binary transcript that `ca_response_sig` covers.
 *
 * @details
 * Format (all multi-byte integers big-endian):
 *
 *   [u8:        version = MTC_BOOTSTRAP_RESP_TRANSCRIPT_V2]
 *   [u32: cosigner_pem_len][cosigner_pem_bytes]
 *   [u32: index]
 *   [u32: subject_len][subject_bytes]
 *   [u32: spk_hash_len][spk_hash_bytes]
 *   [u32: spk_algo_len][spk_algo_bytes]
 *   [u64: not_before_unix]
 *   [u64: not_after_unix]
 *   [u32: label_len][label_bytes]
 *
 * Field extraction order is fixed.  Empty `label` is encoded as
 * length 0; a missing `label` JSON key is treated as the empty
 * string.  Both not_before / not_after are truncated to integer
 * UNIX seconds to remove the float-format dependency.  Negative
 * values for `index` are rejected (the cert index is always
 * non-negative on the wire).
 *
 * Required JSON shape:
 *   resp.index                                                (int)
 *   resp.standalone_certificate.tbs_entry.subject             (string)
 *   resp.standalone_certificate.tbs_entry.subject_public_key_hash
 *                                                              (string)
 *   resp.standalone_certificate.tbs_entry.subject_public_key_algorithm
 *                                                              (string)
 *   resp.standalone_certificate.tbs_entry.not_before          (number)
 *   resp.standalone_certificate.tbs_entry.not_after           (number)
 *   resp.ca_cosigner_pem                                      (string)
 *   resp.label                                                (string, optional)
 *
 * @param[in]  resp     Parsed bootstrap-response JSON object.
 * @param[out] out      Output buffer.
 * @param[in]  out_sz   Size of @p out.  Recommended:
 *                      MTC_BOOTSTRAP_TRANSCRIPT_MAX.
 * @param[out] out_len  Bytes written to @p out on success.
 *
 * @return 0 on success.  -1 if any required field is missing,
 *         wrong-typed, or the buffer overflows.  On failure a
 *         `[mtc-boot-resp] ...` reason is printed to stderr and
 *         @p out_len is left untouched.
 */
int mtc_bootstrap_response_transcript(struct json_object *resp,
                                      unsigned char *out,
                                      size_t out_sz,
                                      size_t *out_len);

#endif /* MTC_BOOTSTRAP_TRANSCRIPT_H */
