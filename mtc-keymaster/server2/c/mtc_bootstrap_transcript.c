/*
 * mtc_bootstrap_transcript.c
 *
 * TODO #11 / ChatGPT review item #11: replace canonical-JSON-based
 * signing of the bootstrap response with a fixed binary transcript.
 * See mtc_bootstrap_transcript.h for contract + format.
 *
 * Self-contained: depends on libc + json-c.  Compiled into both
 * mtc_server and the operator tools (bootstrap_ca / bootstrap_leaf)
 * so signer and verifier walk the parsed JSON identically.
 */

#include "mtc_bootstrap_transcript.h"

#include <stdio.h>
#include <string.h>

static int put_u8(unsigned char *out, size_t out_sz, size_t *cur,
                  unsigned char v)
{
    if (*cur + 1 > out_sz) return -1;
    out[(*cur)++] = v;
    return 0;
}

static int put_u32_be(unsigned char *out, size_t out_sz, size_t *cur,
                      uint32_t v)
{
    if (*cur + 4 > out_sz) return -1;
    out[(*cur)++] = (unsigned char)((v >> 24) & 0xff);
    out[(*cur)++] = (unsigned char)((v >> 16) & 0xff);
    out[(*cur)++] = (unsigned char)((v >>  8) & 0xff);
    out[(*cur)++] = (unsigned char)( v        & 0xff);
    return 0;
}

static int put_u64_be(unsigned char *out, size_t out_sz, size_t *cur,
                      uint64_t v)
{
    int i;
    if (*cur + 8 > out_sz) return -1;
    for (i = 7; i >= 0; i--)
        out[(*cur)++] = (unsigned char)((v >> (i * 8)) & 0xff);
    return 0;
}

static int put_lp_str(unsigned char *out, size_t out_sz, size_t *cur,
                      const char *s, size_t s_len)
{
    if (s_len > 0xFFFFFFFFu) return -1;
    if (put_u32_be(out, out_sz, cur, (uint32_t)s_len) != 0) return -1;
    if (*cur + s_len > out_sz) return -1;
    if (s_len > 0)
        memcpy(out + *cur, s, s_len);
    *cur += s_len;
    return 0;
}

int mtc_bootstrap_response_transcript(struct json_object *resp,
                                      unsigned char *out,
                                      size_t out_sz,
                                      size_t *out_len)
{
    if (!resp || !out || out_sz == 0 || !out_len)
        return -1;

    struct json_object *sc = NULL, *tbs = NULL, *val = NULL;

    if (!json_object_object_get_ex(resp, "standalone_certificate", &sc)) {
        fprintf(stderr,
                "[mtc-boot-resp] missing standalone_certificate\n");
        return -1;
    }
    if (!json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
        fprintf(stderr,
                "[mtc-boot-resp] missing standalone_certificate.tbs_entry\n");
        return -1;
    }

    const char *cosigner_pem = NULL;
    if (!json_object_object_get_ex(resp, "ca_cosigner_pem", &val) ||
        (cosigner_pem = json_object_get_string(val)) == NULL) {
        fprintf(stderr, "[mtc-boot-resp] missing ca_cosigner_pem\n");
        return -1;
    }

    if (!json_object_object_get_ex(resp, "index", &val)) {
        fprintf(stderr, "[mtc-boot-resp] missing index\n");
        return -1;
    }
    int index = json_object_get_int(val);
    if (index < 0) {
        fprintf(stderr, "[mtc-boot-resp] negative index (%d)\n", index);
        return -1;
    }

    const char *subject = NULL;
    if (!json_object_object_get_ex(tbs, "subject", &val) ||
        (subject = json_object_get_string(val)) == NULL) {
        fprintf(stderr, "[mtc-boot-resp] missing tbs_entry.subject\n");
        return -1;
    }

    const char *spk_hash = NULL;
    if (!json_object_object_get_ex(tbs, "subject_public_key_hash", &val) ||
        (spk_hash = json_object_get_string(val)) == NULL) {
        fprintf(stderr,
                "[mtc-boot-resp] missing tbs_entry.subject_public_key_hash\n");
        return -1;
    }

    const char *spk_algo = NULL;
    if (!json_object_object_get_ex(tbs, "subject_public_key_algorithm",
                                   &val) ||
        (spk_algo = json_object_get_string(val)) == NULL) {
        fprintf(stderr,
                "[mtc-boot-resp] missing tbs_entry.subject_public_key_algorithm\n");
        return -1;
    }

    if (!json_object_object_get_ex(tbs, "not_before", &val)) {
        fprintf(stderr, "[mtc-boot-resp] missing tbs_entry.not_before\n");
        return -1;
    }
    /* Truncate float seconds-since-epoch to an integer.  Removes the
     * float-format dependency that motivated this rewrite. */
    uint64_t not_before = (uint64_t)json_object_get_double(val);

    if (!json_object_object_get_ex(tbs, "not_after", &val)) {
        fprintf(stderr, "[mtc-boot-resp] missing tbs_entry.not_after\n");
        return -1;
    }
    uint64_t not_after = (uint64_t)json_object_get_double(val);

    /* Optional label.  Treat missing key as empty string (length 0). */
    const char *label = "";
    if (json_object_object_get_ex(resp, "label", &val)) {
        const char *s = json_object_get_string(val);
        if (s) label = s;
    }

    size_t cur = 0;
    if (put_u8(out, out_sz, &cur, MTC_BOOTSTRAP_RESP_TRANSCRIPT_V2) != 0)
        goto overflow;
    if (put_lp_str(out, out_sz, &cur,
                   cosigner_pem, strlen(cosigner_pem)) != 0)
        goto overflow;
    if (put_u32_be(out, out_sz, &cur, (uint32_t)index) != 0)
        goto overflow;
    if (put_lp_str(out, out_sz, &cur, subject, strlen(subject)) != 0)
        goto overflow;
    if (put_lp_str(out, out_sz, &cur, spk_hash, strlen(spk_hash)) != 0)
        goto overflow;
    if (put_lp_str(out, out_sz, &cur, spk_algo, strlen(spk_algo)) != 0)
        goto overflow;
    if (put_u64_be(out, out_sz, &cur, not_before) != 0)
        goto overflow;
    if (put_u64_be(out, out_sz, &cur, not_after) != 0)
        goto overflow;
    if (put_lp_str(out, out_sz, &cur, label, strlen(label)) != 0)
        goto overflow;

    *out_len = cur;
    return 0;

overflow:
    fprintf(stderr,
            "[mtc-boot-resp] transcript buffer overflow (out_sz=%zu)\n",
            out_sz);
    return -1;
}
