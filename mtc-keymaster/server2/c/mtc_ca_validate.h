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
 * @param[in] extensions  JSON extensions object (may be NULL).
 *
 * @return  1 if not a CA request or validation succeeds.  0 if rejected.
 */
int mtc_validate_ca_cert(struct json_object *extensions);

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
