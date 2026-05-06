/******************************************************************************
 *
 *   ╔══════════════════════════════════════════════════════════════════╗
 *   ║                                                                  ║
 *   ║   WARNING — DO NOT TREAT THE PARSED X.509 AS A TRUST OBJECT      ║
 *   ║                                                                  ║
 *   ║   This file parses ca_certificate_pem with `NO_VERIFY`.  The     ║
 *   ║   X.509 wrapper is used as a STRUCTURED CONTAINER for the SAN    ║
 *   ║   DNS name and the SPKI bytes — nothing else.  Its signature    ║
 *   ║   chain, issuer, validity dates, and any embedded extensions    ║
 *   ║   are NOT trusted by this code.  The actual trust anchor is     ║
 *   ║   the DNSSEC-pinned SPKI hash at _mqc-ca.<domain>                ║
 *   ║   (sha3-256:<HEX> kh= field).                                    ║
 *   ║                                                                  ║
 *   ║   If you are adding a new code path that reuses the parsed       ║
 *   ║   `DecodedCert` from this file:                                  ║
 *   ║                                                                  ║
 *   ║     - DO NOT assume the cert is signed by a trusted issuer.      ║
 *   ║     - DO NOT use NotBefore/NotAfter as a freshness check         ║
 *   ║       (the cert is operator-supplied, not minted by us).         ║
 *   ║     - DO NOT extract Basic Constraints / KeyUsage and treat      ║
 *   ║       them as authority claims.                                  ║
 *   ║     - DO use the SAN DNS name to look up the DNSSEC TXT.         ║
 *   ║     - DO use the SubjectPublicKeyInfo DER as input to the        ║
 *   ║       SHA3-256 fingerprint check against the TXT pin.            ║
 *   ║                                                                  ║
 *   ║   Adding a `wolfSSL_CertManagerVerifyBuffer` here would be       ║
 *   ║   theatre, not security: the threat model already assumes the    ║
 *   ║   submitter could be anyone, and the DNSSEC pin is the           ║
 *   ║   authoritative gate.  See "Trust model" below for the full      ║
 *   ║   rationale and the spec § "CA X.509 wrapper" for the public     ║
 *   ║   description.                                                   ║
 *   ║                                                                  ║
 *   ║   TODO #71 (ChatGPT review item #12, closed 2026-05-06).         ║
 *   ║                                                                  ║
 *   ╚══════════════════════════════════════════════════════════════════╝
 *
 * File:        mtc_ca_validate.c
 * Purpose:     Shared CA certificate validation (DNSSEC TXT + X.509 parsing).
 *
 * Description:
 *   Validates CA enrollment requests by parsing the X.509 certificate,
 *   checking Basic Constraints (CA:TRUE), extracting the SAN DNS name
 *   and SPKI fingerprint, and verifying domain ownership via a
 *   DNSSEC-validated TXT record at _mqc-ca.<domain>.
 *
 *   Extracted from mtc_http.c so both the HTTP endpoint and the DH
 *   bootstrap port share the same validation logic.
 *
 *   Wire-format history (this file is the canonical record of the
 *   change since the README files describe it from the MQC side):
 *
 *   - PRE-mqc-3 (deprecated, removed): _mtc-ca.<domain> TXT
 *     containing `v=mtc-ca1; fp=sha256:<HEX>`, queried via
 *     libresolv `res_query` with NO DNSSEC validation.  An MITM
 *     between the server and the recursive resolver could
 *     substitute the TXT and pin any key.
 *
 *   - mqc-3 (current): _mqc-ca.<domain> TXT containing
 *     `v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<HEX>`,
 *     queried via libunbound with full DNSSEC chain validation
 *     (root anchor + per-zone DNSKEY/RRSIG).  An unsigned or
 *     bogus zone fails closed; the SPKI hash is SHA3-256 over
 *     the canonical SubjectPublicKeyInfo DER (encoding-stable;
 *     matches TODO #53's resolution).
 *
 *   No backwards compat — single-deployment cutover; servers
 *   and operators upgrade together.  Operators publish the new
 *   record using mtc-keymaster/tools/python/ca_dns_txt.py
 *   pointed at the CA cert's pubkey.
 *
 *   ---------------------------------------------------------------
 *   Trust model (README-issues.md issue #4):
 *
 *   The submitted ca_certificate_pem is parsed with NO_VERIFY.
 *   The X.509 cert in this code path is a STRUCTURED CONTAINER,
 *   NOT a real X.509 trust object.  Specifically:
 *
 *     - The trust authority for the CA's public key is the
 *       DNSSEC-pinned SPKI hash (`kh=sha3-256:<HEX>` at
 *       _mqc-ca.<domain>).  An attacker who cannot publish a
 *       matching DNSSEC-signed TXT cannot enroll, regardless of
 *       what the X.509 cert says.
 *
 *     - The cert is consumed for two pieces of structured data
 *       only:
 *         (a) the SAN DNS name (the domain to look up in DNSSEC),
 *         (b) the SubjectPublicKeyInfo DER (the bytes whose
 *             SHA3-256 must match the pinned `kh=` value).
 *
 *     - The cert's signature chain is intentionally NOT
 *       verified.  A self-signed cert, a cert chained to a real
 *       WebPKI CA, and a cert with a syntactically-valid but
 *       cryptographically-invalid signature are all treated
 *       identically — the only thing that matters is whether
 *       (SAN, SHA3-256(SPKI DER)) lines up with the published
 *       DNSSEC pin.  Adding a self-signature check here would
 *       be theatre, not security: it would not improve the
 *       trust story (DNSSEC pinning already authenticates the
 *       SPKI), and it would not prove control of the private
 *       key (any attacker can re-submit a self-signed cert
 *       generated by someone else).  Real proof-of-possession
 *       belongs to a separate challenge-response flow tracked
 *       under README-issues.md issue #5.
 *
 *     - The X.509 also gets used downstream by other paths
 *       (e.g., outbound TLS proofs in the ca_certificate_pem
 *       extension, or future log-revocation messages).  Those
 *       paths can still want signature verification if and when
 *       they re-introduce it; the NO_VERIFY contract here is
 *       LOCAL to mtc_validate_ca_cert.
 *   ---------------------------------------------------------------
 *
 * Dependencies:
 *   mtc_ca_validate.h
 *   mtc_dnssec_pin.h              (DNSSEC-validated TXT lookup)
 *   mtc_log.h                     (LOG_* macros)
 *   wolfssl/wolfcrypt/asn.h       (X.509 parsing)
 *   wolfssl/wolfcrypt/sha3.h      (SPKI fingerprint, SHA3-256)
 *   json-c/json.h                 (extensions parsing)
 *
 * Created:     2026-04-14
 * Modified:    2026-05-04  (mqc-3: drop _mtc-ca./SHA-256/res_query;
 *              switch to _mqc-ca./SHA3-256/libunbound DNSSEC)
 ******************************************************************************/

#include "mtc_ca_validate.h"
#include "mtc_dnssec_pin.h"
#include "mtc_domain.h"
#include "mtc_log.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha3.h>
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

/* mtc_canonicalize_domain moved to mtc_domain.c (see
 * README-issues.md issue #6).  The implementation is pure libc
 * so the operator tools in tools/c/ can compile it in without
 * dragging the wolfSSL/json-c headers this translation unit
 * pulls in. */

/******************************************************************************
 * Function:    mtc_validate_ca_dns_txt
 *
 * Description:
 *   Verifies domain ownership for a CA-enrollment request by checking
 *   that _mqc-ca.<domain> publishes a DNSSEC-validated TXT record
 *   containing kh=sha3-256:<expected_fp>.
 *
 *   Calls into mqc_dnssec_validate_ca_kh in mtc_dnssec_pin.c, which
 *   does the libunbound query + chain validation; only the *value*
 *   match logic and logging live here.
 *
 *   TXT record format (mqc-3, see file header for the deprecated
 *   pre-mqc-3 format):
 *     v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<HEX>
 *
 *   The DNSSEC chain is mandatory: an unsigned or bogus zone fails
 *   closed.  This closes the DNS-resolver-MITM attack class that
 *   the prior libresolv path left open.
 *
 * Input Arguments:
 *   domain  - Domain name (e.g. "example.com").
 *   fp_hex  - Expected SHA3-256 fingerprint of the CA cert SPKI DER
 *             (64 lowercase-hex chars).
 *
 * Returns:
 *   1  if the DNSSEC chain validates AND a matching TXT record is found.
 *   0  on any failure (mismatch, bogus chain, insecure zone, no record,
 *      resolver error, parse error).
 ******************************************************************************/
int mtc_validate_ca_dns_txt(const char *domain, const char *fp_hex)
{
    mqc_dnssec_status_t st;

    LOG_INFO("DNSSEC lookup: _mqc-ca.%s", domain);
    LOG_INFO("  expecting: kh=sha3-256:%s", fp_hex);

    st = mqc_dnssec_validate_ca_kh(domain, fp_hex);
    if (st == MQC_DNSSEC_OK) {
        LOG_INFO("  MATCH: kh=sha3-256:%.16s... at _mqc-ca.%s",
                 fp_hex, domain);
        return 1;
    }
    LOG_WARN("DNSSEC validation failed for _mqc-ca.%s: %s",
             domain, mqc_dnssec_status_string(st));
    return 0;
}

/******************************************************************************
 * Function:    mtc_validate_ca_cert
 *
 * Description:
 *   If extensions contain ca_certificate_pem, parses the X.509 cert,
 *   verifies CA:TRUE in Basic Constraints, extracts the SAN DNS name
 *   and SPKI SHA3-256 fingerprint, and validates domain ownership via
 *   a DNSSEC-validated TXT record at _mqc-ca.<domain> in the form
 *   `v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<HEX>`.
 *
 *   The X.509 cert's signature chain is intentionally NOT verified
 *   (parsed with NO_VERIFY).  In this code path the cert is a
 *   structured container — the trust anchor is the DNSSEC pin, not
 *   the signature.  See the file header "Trust model" block
 *   (README-issues.md issue #4) for why this is by design.
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
    /* NO_VERIFY is intentional: see file-header "Trust model"
     * block.  The cert is a structured container we mine for
     * (SAN, SPKI DER); the DNSSEC pin is the trust authority, so
     * the cert's own signature carries no security value here. */
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

        LOG_DEBUG("SAN DNS (raw): %s", domain);

        /* Canonicalize + reject weird names (issue #6).  The
         * canonical form is what we hand back to the caller and
         * what every downstream comparison/DNSSEC-query path uses,
         * so a SAN of "EXAMPLE.com." and a SAN of "example.com" are
         * treated identically here, while "*.example.com",
         * "_mqc-ca.example.com", IDN bytes, and similar pathology
         * are refused outright. */
        {
            char canon[256];
            if (mtc_canonicalize_domain(domain, canon, sizeof(canon)) != 0) {
                LOG_WARN("CA cert SAN failed canonicalization: '%s'",
                         domain);
                wc_FreeDecodedCert(&decoded);
                return 0;
            }
            snprintf(domain, sizeof(domain), "%s", canon);
        }

        LOG_DEBUG("SAN DNS (canonical): %s", domain);

        /* Export the SAN so the caller can verify subject == <SAN>-ca. */
        if (san_out && san_out_sz > 0) {
            snprintf(san_out, san_out_sz, "%s", domain);
        }

        /* Compute SHA3-256 fingerprint of SubjectPublicKeyInfo DER.
         * Switched from SHA-256 in mqc-3 to align with the wire
         * format on _mqc-ca.<domain> TXT (kh=sha3-256:<HEX>) and
         * with TODO #53's "hash the canonical SPKI DER" resolution. */
        {
            wc_Sha3 sha;
            uint8_t h[WC_SHA3_256_DIGEST_SIZE];
            uint8_t spki_buf[4096];  /* ML-DSA-87 SPKI is ~2.6KB */
            word32 spki_sz = sizeof(spki_buf);

            ret = wc_GetSubjectPubKeyInfoDerFromCert(
                der_buf, (word32)der_sz, spki_buf, &spki_sz);
            if (ret != 0) {
                LOG_WARN("failed to extract SPKI: %d", ret);
                wc_FreeDecodedCert(&decoded);
                return 0;
            }

            wc_InitSha3_256(&sha, NULL, INVALID_DEVID);
            wc_Sha3_256_Update(&sha, spki_buf, spki_sz);
            wc_Sha3_256_Final(&sha, h);
            wc_Sha3_256_Free(&sha);
            ca_to_hex(h, WC_SHA3_256_DIGEST_SIZE, fp_hex);
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
