/*
 * mtc_domain.c
 *
 * Implementation of the shared LDH/ASCII canonicalization gate.
 * See mtc_domain.h for the contract and README-issues.md issue
 * #6 for the design rationale.
 *
 * Self-contained: depends only on libc + the prototype in
 * mtc_domain.h, so server and tool builds can compile it in
 * without pulling extra dependencies.  Diagnostics go to stderr;
 * the server's systemd unit captures stderr → journal, and CLI
 * tools print to the operator's terminal.
 */

#include "mtc_domain.h"

#include <stdio.h>
#include <string.h>

int mtc_canonicalize_domain(const char *in, char *out, size_t out_sz)
{
    size_t in_len, i;
    size_t label_len = 0;
    int prev_was_dot = 1;       /* leading '.' would be rejected */

    if (out && out_sz > 0) out[0] = '\0';
    if (!in || !out || out_sz == 0) return -1;

    in_len = strlen(in);
    if (in_len == 0 || in_len > 253) {
        fprintf(stderr,
                "[mtc-domain] reject: empty or > 253 bytes (%zu)\n",
                in_len);
        return -1;
    }

    /* Strip a single trailing dot if present. */
    if (in[in_len - 1] == '.') {
        in_len--;
        if (in_len == 0) {
            fprintf(stderr, "[mtc-domain] reject: bare trailing dot\n");
            return -1;
        }
    }

    if (in_len + 1 > out_sz) {
        fprintf(stderr,
                "[mtc-domain] reject: out buffer too small (%zu < %zu)\n",
                out_sz, in_len + 1);
        return -1;
    }

    if (in_len >= 2 && in[0] == '*' && in[1] == '.') {
        fprintf(stderr,
                "[mtc-domain] reject: wildcard prefix '*.'\n");
        return -1;
    }

    for (i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];

        if (c & 0x80) {
            fprintf(stderr,
                    "[mtc-domain] reject: non-ASCII byte at offset %zu "
                    "— punycode the domain to xn--... before submitting\n",
                    i);
            return -1;
        }

        if (c == '.') {
            if (prev_was_dot) {
                fprintf(stderr,
                        "[mtc-domain] reject: empty label at offset %zu\n",
                        i);
                return -1;
            }
            label_len = 0;
            prev_was_dot = 1;
            out[i] = '.';
            continue;
        }

        if (prev_was_dot) {
            if (c == '_') {
                fprintf(stderr,
                        "[mtc-domain] reject: label starts with '_' at "
                        "offset %zu — reserved-namespace names "
                        "(e.g., _mqc-ca.example.com) are rejected\n", i);
                return -1;
            }
            if (c == '-') {
                fprintf(stderr,
                        "[mtc-domain] reject: label starts with '-' at "
                        "offset %zu\n", i);
                return -1;
            }
        }

        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-')) {
            fprintf(stderr,
                    "[mtc-domain] reject: invalid char 0x%02x at offset %zu\n",
                    c, i);
            return -1;
        }

        if (++label_len > 63) {
            fprintf(stderr,
                    "[mtc-domain] reject: label > 63 bytes at offset %zu\n",
                    i);
            return -1;
        }

        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        out[i] = (char)c;
        prev_was_dot = 0;
    }

    if (in[in_len - 1] == '-') {
        fprintf(stderr, "[mtc-domain] reject: trailing '-'\n");
        return -1;
    }

    out[in_len] = '\0';
    return 0;
}

int mtc_canonicalize_label(const char *in, char *out, size_t out_sz)
{
    size_t in_len, i;

    if (out && out_sz > 0) out[0] = '\0';
    if (!in || !out || out_sz == 0) return -1;

    in_len = strlen(in);
    if (in_len == 0) {
        fprintf(stderr, "[mtc-label] reject: empty\n");
        return -1;
    }
    if (in_len > MTC_LABEL_MAX) {
        fprintf(stderr,
                "[mtc-label] reject: %zu bytes > MTC_LABEL_MAX (%d)\n",
                in_len, MTC_LABEL_MAX);
        return -1;
    }
    if (in_len + 1 > out_sz) {
        fprintf(stderr,
                "[mtc-label] reject: out buffer too small (%zu < %zu)\n",
                out_sz, in_len + 1);
        return -1;
    }

    /* Path-traversal smell: bare "." or ".." would let a label
     * become a parent / current dir reference if a tool ever
     * `mkdir`s `<domain>-<label>/`. */
    if (strcmp(in, ".") == 0 || strcmp(in, "..") == 0) {
        fprintf(stderr, "[mtc-label] reject: bare '%s'\n", in);
        return -1;
    }

    if (in[0] == '-') {
        fprintf(stderr, "[mtc-label] reject: leading '-'\n");
        return -1;
    }
    if (in[0] == '.') {
        fprintf(stderr, "[mtc-label] reject: leading '.'\n");
        return -1;
    }

    for (i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            fprintf(stderr,
                    "[mtc-label] reject: invalid char 0x%02x at offset %zu\n",
                    c, i);
            return -1;
        }
        out[i] = (char)c;
    }
    out[in_len] = '\0';
    return 0;
}
