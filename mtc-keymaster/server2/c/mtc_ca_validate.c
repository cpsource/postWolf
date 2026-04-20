/******************************************************************************
 * File:        mtc_ca_validate.c
 * Purpose:     Shared CA certificate validation (DNS TXT + X.509 parsing).
 *
 * Description:
 *   Validates CA enrollment requests by parsing the X.509 certificate,
 *   checking Basic Constraints (CA:TRUE), extracting the SAN DNS name
 *   and SPKI fingerprint, and verifying domain ownership via DNS TXT
 *   record at _mtc-ca.<domain>.
 *
 *   Extracted from mtc_http.c so both the HTTP endpoint and the DH
 *   bootstrap port share the same validation logic.
 *
 * Dependencies:
 *   mtc_ca_validate.h
 *   mtc_log.h                     (LOG_* macros)
 *   resolv.h, arpa/nameser.h     (DNS TXT lookups)
 *   wolfssl/wolfcrypt/asn.h       (X.509 parsing)
 *   wolfssl/wolfcrypt/sha256.h    (SPKI fingerprint)
 *   json-c/json.h                 (extensions parsing)
 *
 * Created:     2026-04-14
 ******************************************************************************/

#include "mtc_ca_validate.h"
#include "mtc_log.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/types.h>

/******************************************************************************
 * Function:    ca_to_hex  (static)
 *
 * Description:
 *   Convert binary data to lowercase hex string.
 ******************************************************************************/
static void ca_to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

/******************************************************************************
 * Function:    mtc_validate_ca_dns_txt
 *
 * Description:
 *   Queries DNS for _mtc-ca.<domain> TXT records and validates against
 *   the expected fingerprint.
 *
 *   TXT record format:
 *     v=mtc-ca1; fp=sha256:<hex>
 *
 * Input Arguments:
 *   domain  - Domain name (e.g. "example.com").
 *   fp_hex  - Expected SHA-256 fingerprint (64 hex chars).
 *
 * Returns:
 *   1  if a matching TXT record is found.
 *   0  if no match, DNS query failed, or parse error.
 ******************************************************************************/
int mtc_validate_ca_dns_txt(const char *domain, const char *fp_hex)
{
    char qname[256];
    unsigned char answer[4096];
    int ans_len, i;
    ns_msg msg;
    ns_rr rr;

    snprintf(qname, sizeof(qname), "_mtc-ca.%s", domain);

    LOG_INFO("DNS lookup: %s", qname);
    LOG_INFO("  expecting: v=mtc-ca1; fp=sha256:%s", fp_hex);

    ans_len = res_query(qname, ns_c_in, ns_t_txt, answer, sizeof(answer));
    if (ans_len < 0) {
        int err = h_errno;
        const char *reason;
        switch (err) {
            case HOST_NOT_FOUND: reason = "domain not found (NXDOMAIN)"; break;
            case NO_DATA:        reason = "no TXT records exist"; break;
            case TRY_AGAIN:      reason = "DNS timeout or temporary failure"; break;
            case NO_RECOVERY:    reason = "DNS server error (non-recoverable)"; break;
            default:             reason = "unknown error"; break;
        }
        LOG_WARN("DNS query failed for %s: %s (h_errno=%d)", qname, reason, err);
        return 0;
    }

    if (ns_initparse(answer, ans_len, &msg) < 0) {
        LOG_WARN("failed to parse DNS response for %s", qname);
        return 0;
    }

    {
        int txt_count = 0;
        int total = ns_msg_count(msg, ns_s_an);
        LOG_DEBUG("DNS response: %d answer records for %s", total, qname);

        for (i = 0; i < total; i++) {
            if (ns_parserr(&msg, ns_s_an, i, &rr) == 0 &&
                ns_rr_type(rr) == ns_t_txt) {
                const unsigned char *rdata = ns_rr_rdata(rr);
                int rdlen = ns_rr_rdlen(rr);
                if (rdlen > 1) {
                    int txt_len = rdata[0];
                    if (txt_len <= rdlen - 1) {
                        char txt[512];
                        if (txt_len >= (int)sizeof(txt))
                            txt_len = (int)sizeof(txt) - 1;
                        memcpy(txt, rdata + 1, txt_len);
                        txt[txt_len] = '\0';
                        txt_count++;
                        LOG_INFO("  found TXT[%d]: \"%s\"", txt_count, txt);

                        /* Parse TXT record fields by splitting on ';'
                         * and matching exact key=value pairs. */
                        {
                            char tmp[512];
                            char *field, *saveptr;
                            const char *v_val = NULL, *fp_val = NULL;

                            snprintf(tmp, sizeof(tmp), "%s", txt);
                            for (field = strtok_r(tmp, ";", &saveptr);
                                 field != NULL;
                                 field = strtok_r(NULL, ";", &saveptr)) {
                                while (*field == ' ') field++;
                                if (strncmp(field, "v=", 2) == 0)
                                    v_val = field + 2;
                                else if (strncmp(field, "fp=sha256:", 10) == 0)
                                    fp_val = field + 10;
                            }

                            /* Log what we parsed vs what we need */
                            if (v_val)
                                LOG_DEBUG("    parsed: v=%s fp=%s",
                                          v_val, fp_val ? fp_val : "(none)");

                            if (v_val && strcmp(v_val, "mtc-ca1") == 0 &&
                                fp_val && strcmp(fp_val, fp_hex) == 0) {
                                LOG_INFO("  MATCH: v=mtc-ca1 for %s", qname);
                                return 1;
                            }

                            /* Log mismatch details */
                            if (v_val && fp_val) {
                                if (strcmp(fp_val, fp_hex) != 0)
                                    LOG_WARN("  mismatch: fingerprint differs");
                            }
                        }
                    }
                }
            }
        }

        if (txt_count == 0)
            LOG_WARN("no TXT records found in DNS response for %s", qname);
        else
            LOG_WARN("no matching TXT record for %s (%d record(s) checked)",
                     qname, txt_count);
    }

    return 0;
}

/******************************************************************************
 * Function:    mtc_validate_ca_cert
 *
 * Description:
 *   If extensions contain ca_certificate_pem, parses the X.509 cert,
 *   verifies CA:TRUE in Basic Constraints, extracts the SAN DNS name
 *   and SPKI SHA-256 fingerprint, and validates domain ownership via
 *   DNS TXT record (v=mtc-ca1; fp=sha256:<hex>).
 *
 *   All CAs require DNS validation (no root CA bypass).
 *   CA enrollment does not use a nonce — only leaf enrollment does.
 *   If no ca_certificate_pem is present, returns 1 (not a CA request).
 *
 * Input Arguments:
 *   extensions - Request extensions json_object (may be NULL).
 *
 * Returns:
 *   1  if not a CA request, or CA validated successfully.
 *   0  if CA validation failed (rejected).
 ******************************************************************************/
int mtc_validate_ca_cert(struct json_object *extensions,
                         char *spki_fp_out, size_t spki_fp_out_sz,
                         char *san_out, size_t san_out_sz)
{
    struct json_object *ca_cert_val;
    const char *ca_cert_pem;
    DecodedCert decoded;
    int ret;
    const unsigned char *pem_bytes;
    unsigned char der_buf[16384];  /* ML-DSA-87 certs are ~10KB */
    int der_sz;
    int pem_len;
    char fp_hex[65];

    if (spki_fp_out && spki_fp_out_sz > 0) spki_fp_out[0] = '\0';
    if (san_out && san_out_sz > 0) san_out[0] = '\0';
    if (!extensions)
        return 1;

    if (!json_object_object_get_ex(extensions, "ca_certificate_pem", &ca_cert_val))
        return 1;

    ca_cert_pem = json_object_get_string(ca_cert_val);
    if (!ca_cert_pem || strlen(ca_cert_pem) == 0)
        return 1;

    LOG_DEBUG("CA certificate PEM found, validating...");

    /* Convert PEM to DER */
    pem_bytes = (const unsigned char *)ca_cert_pem;
    pem_len = (int)strlen(ca_cert_pem);
    LOG_TRACE("PEM length: %d bytes", pem_len);
    if (pem_len > 16000) {
        LOG_WARN("CA cert PEM too large (%d bytes)", pem_len);
        return 0;
    }
    der_sz = (int)sizeof(der_buf);
    ret = wc_CertPemToDer(pem_bytes, pem_len, der_buf, der_sz, CERT_TYPE);
    if (ret < 0) {
        LOG_WARN("PEM to DER conversion failed: %d", ret);
        return 0;
    }
    der_sz = ret;
    LOG_TRACE("DER size: %d bytes", der_sz);

    /* Parse the certificate */
    wc_InitDecodedCert(&decoded, der_buf, (word32)der_sz, NULL);
    ret = wc_ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        LOG_WARN("certificate parse failed: %d", ret);
        wc_FreeDecodedCert(&decoded);
        return 0;
    }

    /* Check Basic Constraints: CA:TRUE */
    if (!decoded.isCA) {
        LOG_WARN("certificate is not a CA (isCA=0)");
        wc_FreeDecodedCert(&decoded);
        return 0;
    }
    LOG_DEBUG("CA:TRUE, pathlen:%d", decoded.pathLength);

    /* All CAs require DNS validation — no root CA bypass */

    /* Extract SAN DNS name */
    {
        DNS_entry *san = decoded.altNames;
        char domain[256] = {0};

        while (san) {
            if (san->type == ASN_DNS_TYPE && san->name) {
                snprintf(domain, sizeof(domain), "%s", san->name);
                break;
            }
            san = san->next;
        }

        if (domain[0] == '\0') {
            LOG_WARN("no SAN DNS name found in CA cert");
            wc_FreeDecodedCert(&decoded);
            return 0;
        }

        LOG_DEBUG("SAN DNS: %s", domain);

        /* Export the SAN so the caller can verify subject == <SAN>-ca. */
        if (san_out && san_out_sz > 0) {
            snprintf(san_out, san_out_sz, "%s", domain);
        }

        /* Compute SHA-256 fingerprint of SubjectPublicKeyInfo DER */
        {
            wc_Sha256 sha;
            uint8_t h[32];
            uint8_t spki_buf[4096];  /* ML-DSA-87 SPKI is ~2.6KB */
            word32 spki_sz = sizeof(spki_buf);

            ret = wc_GetSubjectPubKeyInfoDerFromCert(
                der_buf, (word32)der_sz, spki_buf, &spki_sz);
            if (ret != 0) {
                LOG_WARN("failed to extract SPKI: %d", ret);
                wc_FreeDecodedCert(&decoded);
                return 0;
            }

            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, spki_buf, spki_sz);
            wc_Sha256Final(&sha, h);
            wc_Sha256Free(&sha);
            ca_to_hex(h, 32, fp_hex);
        }

        LOG_DEBUG("public key fingerprint: %.16s...", fp_hex);

        wc_FreeDecodedCert(&decoded);

        /* Export the fp so the caller can cross-check against the
         * separately-submitted `public_key_pem` field.  See the
         * header-file rationale for why this matters. */
        if (spki_fp_out && spki_fp_out_sz >= sizeof(fp_hex)) {
            memcpy(spki_fp_out, fp_hex, sizeof(fp_hex));
        }

        return mtc_validate_ca_dns_txt(domain, fp_hex);
    }
}
