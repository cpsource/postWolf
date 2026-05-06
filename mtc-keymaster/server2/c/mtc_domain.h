/**
 * @file mtc_domain.h
 * @brief Shared domain-name canonicalization gate.
 *
 * @details
 * Single LDH/ASCII gate for every domain that flows into a
 * comparison or a DNSSEC query.  Built into the server (called
 * from mtc_ca_validate / mtc_http) and into the operator tools
 * that take `--domain` on the command line, so pathological
 * inputs are caught before any network round trip.
 *
 * Originally part of mtc_ca_validate.c; extracted in mqc-3 so
 * the operator tools in tools/c/ can compile it in without dragging in the full
 * mtc_ca_validate translation unit (which depends on wolfSSL
 * X.509 + json-c headers).  See README-issues.md issue #6.
 */

#ifndef MTC_DOMAIN_H
#define MTC_DOMAIN_H

#include <stddef.h>

/**
 * @brief  Canonicalize and validate a domain name.
 *
 * @details
 * Accepts: ASCII LDH per-label names ([a-z0-9-], 1-63 chars per
 * label, total <= 253 bytes), case-insensitive — uppercase input
 * is lowercased into @p out.  A single trailing `.` is stripped
 * (treated as canonical-equivalent to the un-dotted form).
 *
 * Rejects (returns -1, leaves @p out cleared, prints a brief
 * `[mtc-domain] ...` reason to stderr):
 *   - empty or > 253 byte input
 *   - non-ASCII byte (any 0x80-0xFF) — operators must punycode
 *     IDN domains themselves and submit the `xn--...` form
 *   - any character outside `[A-Za-z0-9.-]`
 *   - leading or trailing `-` or `.`, consecutive `.`
 *   - any label longer than 63 bytes
 *   - wildcard prefix `*.`
 *   - any label starting with `_` (catches `_mqc-ca.example.com`
 *     and similar reserved-namespace abuse)
 *
 * The function is loggless beyond the stderr line so it works
 * the same in the server (where the message lands in the
 * journal) and in tool processes (where it lands on the user's
 * terminal).
 *
 * @param[in]  in      Input domain (NUL-terminated).
 * @param[out] out     Buffer for the canonical form.
 * @param[in]  out_sz  Size of @p out.  MUST be >= strlen(in)+1.
 *
 * @return  0 on accept (with canonical form written to @p out).
 *          -1 on reject (with @p out cleared).
 */
int mtc_canonicalize_domain(const char *in, char *out, size_t out_sz);

/**
 * @brief  Canonicalize and validate an operator-assigned label.
 *
 * @details
 * Labels are stored verbatim in the DB and used by client tools
 * to name per-leaf TPM directories (`~/.TPM/<domain>-<label>/`),
 * so the server must validate them before persisting.  Mirrors
 * the client-side check in bootstrap_leaf / bootstrap_ca /
 * issue_leaf_nonce so a malicious `/enrollment/nonce` caller
 * can't bypass it.
 *
 * Accepts: 1..MTC_LABEL_MAX bytes from the charset
 * `[A-Za-z0-9._-]`.  Case is preserved (label dirs are
 * case-sensitive).
 *
 * Rejects (returns -1, leaves @p out cleared, prints `[mtc-label]
 * ...` to stderr):
 *   - empty or > MTC_LABEL_MAX bytes
 *   - any character outside `[A-Za-z0-9._-]`
 *   - bare `.` or `..` (path-traversal smell)
 *   - leading `-` or `.`
 *
 * @param[in]  in      Input label (NUL-terminated).
 * @param[out] out     Buffer for the canonical form.
 * @param[in]  out_sz  Size of @p out.  MUST be >= strlen(in)+1.
 *
 * @return  0 on accept (with canonical form written to @p out).
 *          -1 on reject (with @p out cleared).
 */
/* Kept in lockstep with MTC_LABEL_MAX in mtc_db.h.  Defined here so
 * mtc_domain stays self-contained for the operator tools that link
 * it without pulling in mtc_db.h's wolfSSL/Postgres header chain. */
#ifndef MTC_LABEL_MAX
#define MTC_LABEL_MAX 64
#endif
int mtc_canonicalize_label(const char *in, char *out, size_t out_sz);

#endif /* MTC_DOMAIN_H */
