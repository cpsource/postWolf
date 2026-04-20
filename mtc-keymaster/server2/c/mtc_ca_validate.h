/**
 * @file mtc_ca_validate.h
 * @brief Shared CA certificate validation (DNS TXT + X.509 parsing).
 *
 * @details
 * Extracted from mtc_http.c so that both the HTTP endpoint and the DH
 * bootstrap port can validate CA enrollment requests.
 *
 * @date 2026-04-14
 */

#ifndef MTC_CA_VALIDATE_H
#define MTC_CA_VALIDATE_H

#include <json-c/json.h>

/**
 * @brief  Validate a CA certificate in the request extensions.
 *
 * @details
 * If extensions contain ca_certificate_pem, parses the X.509 cert,
 * verifies CA:TRUE, extracts SAN DNS name and SPKI fingerprint, and
 * validates domain ownership via DNS TXT record.  All CAs require
 * DNS validation (no root CA bypass).  CA enrollment does not use
 * an enrollment nonce — only leaf enrollment does.
 *
 * When @p spki_fp_out is non-NULL, writes the hex-encoded SHA-256 of
 * the X.509's SPKI (64 chars + NUL) so the caller can cross-check
 * that the separately-submitted `public_key_pem` field in the
 * enrollment body has the same fingerprint.  Without this check an
 * attacker could submit a legitimate operator's public X.509 in
 * `ca_certificate_pem` alongside their own `public_key_pem` — the
 * DNS check would pass (against the legit SPKI) while the minted
 * cert would bind to the attacker's key.
 *
 * @param[in]  extensions      JSON extensions object (may be NULL).
 * @param[out] spki_fp_out     Receives the 64-hex-char SPKI fingerprint.
 *                              May be NULL (skip the capture).
 * @param[in]  spki_fp_out_sz  Size of @p spki_fp_out (needs >= 65).
 * @param[out] san_out         Receives the first SAN DNS name extracted
 *                              from the X.509 cert (NUL-terminated).
 *                              Caller uses this to verify the enrollment
 *                              body's `subject` field equals
 *                              `<san_out>-ca`.  May be NULL.
 * @param[in]  san_out_sz      Size of @p san_out.
 *
 * @return  1 if not a CA request or validation succeeds.  0 if rejected.
 */
int mtc_validate_ca_cert(struct json_object *extensions,
                         char *spki_fp_out, size_t spki_fp_out_sz,
                         char *san_out, size_t san_out_sz);

/**
 * @brief  Validate DNS TXT record at _mtc-ca.<domain>.
 *
 * @param[in] domain  Domain name to query.
 * @param[in] fp_hex  Expected SHA-256 fingerprint (64 hex chars).
 *
 * @return  1 if matching TXT record found.  0 if no match.
 */
int mtc_validate_ca_dns_txt(const char *domain, const char *fp_hex);

#endif /* MTC_CA_VALIDATE_H */
