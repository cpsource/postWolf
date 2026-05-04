/*
 * mtc_dnssec_pin.h
 *
 * Public interface for the server-side DNSSEC TXT pin
 * machinery (port 8445 / CA-enrollment validation).  The
 * implementation lives in mtc_dnssec_pin.c (a server-tree copy
 * of socket-level-wrapper-MQC/mqc_dnssec_pin.c — kept identical
 * apart from the new mqc_dnssec_validate_ca_kh wrapper so
 * future fixes can drift in either tree without forcing
 * cross-tree edits).
 */

#ifndef MTC_DNSSEC_PIN_H
#define MTC_DNSSEC_PIN_H

#include <stddef.h>

#define MTC_DNSSEC_HASH_HEX_LEN 64

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
 * Caller-supplied hash variant: returns MQC_DNSSEC_OK iff the
 * DNSSEC chain to _mqc-ca.<domain> validates AND some TXT RR
 * carries kh=sha3-256:<expected_hash>.  expected_hash MUST be
 * 64 lowercase-hex chars.
 */
mqc_dnssec_status_t mqc_dnssec_validate_ca_kh(const char *domain,
                                              const char *expected_hash);

const char *mqc_dnssec_status_string(mqc_dnssec_status_t st);

#endif /* MTC_DNSSEC_PIN_H */
