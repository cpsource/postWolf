/*
 * mqc_dnssec_pin.h
 *
 * Public interface for MQC's DNSSEC TXT-pin machinery.  Source
 * is `mqc_dnssec_pin.c` in this same directory; a near-identical
 * copy in `mtc-keymaster/server2/c/mtc_dnssec_pin.{c,h}` carries
 * the server-only `mqc_dnssec_validate_ca_kh` wrapper for the
 * port-8445 enrollment validator (kept parallel so each tree
 * can drift independently).
 */

#ifndef MQC_DNSSEC_PIN_H
#define MQC_DNSSEC_PIN_H

#include <stddef.h>

#define MQC_DNSSEC_HASH_HEX_LEN 64

typedef enum {
    MQC_DNSSEC_OK = 0,
    MQC_DNSSEC_NO_DATA,
    MQC_DNSSEC_BOGUS,
    MQC_DNSSEC_INSECURE,
    MQC_DNSSEC_RESOLVE_ERROR,
    MQC_DNSSEC_PARSE_ERROR,
    MQC_DNSSEC_HASH_MISMATCH
} mqc_dnssec_status_t;

/*
 * P0 / TODO #9b show-tpm surface — fetch the parent log's
 * cosigner-key fingerprint from a DNSSEC-validated TXT record
 * at `_mqc-cosigner.<parent_domain>`.  Expected RR shape:
 *
 *   v=MQC1; role=cosigner; alg=ML-DSA-87; kh=sha3-256:<HEX>
 *
 * Returns MQC_DNSSEC_OK iff DNSSEC chain validates AND some TXT
 * RR carries the full v=/role=/alg=/kh= bundle in one record.
 * On success out_hex receives 64 lowercase-hex chars + NUL.
 *
 * Used by mqc_load_ca_pubkey to authenticate the bootstrap-port
 * fetch of the cosigner PEM, eliminating the global
 * ~/.TPM/ca-cosigner.pem TOFU window for first-contact MQC
 * clients (show-tpm and friends that didn't go through
 * bootstrap_leaf / bootstrap_ca).
 */
mqc_dnssec_status_t mqc_dnssec_fetch_cosigner_kh(const char *parent_domain,
                                                 char *out_hex);

const char *mqc_dnssec_status_string(mqc_dnssec_status_t st);

#endif /* MQC_DNSSEC_PIN_H */
