#include "read-config.h"

#include <augeas.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_PREFIX "/files/etc/postWolf/config/"

static augeas *aug;

int init_augeas(void) {
    if (aug)
        return 0;
    /* AUG_NO_MODL_AUTOLOAD skips augeas's default scan of every
     * .aug file under /usr/share/augeas/lenses/dist/ — about 200
     * files for ~1 s on this box.  We only ever read
     * /etc/postWolf/config via the Myconf lens, so wire that one
     * up explicitly and call aug_load().  Net cost on cold start
     * drops from ~1000 ms to <10 ms.  Surfaced during P2a
     * smoke testing where the per-handshake setup_total was
     * 14.6 s on first connection — the previous fix (keep aug
     * open across batch reads) collapsed the 14× re-scan to a
     * single one-second hit; this fix makes the single hit go
     * away too. */
    /* loadpath: include both /usr/local/share/augeas/lenses (where
     * the postWolf kit / Makefile.tools install lays down myconf.aug)
     * and /usr/share/augeas/lenses (Ubuntu's distro default).
     * augeas's compile-time default varies — Ubuntu's default
     * doesn't include /usr/local on some builds, which silently
     * makes the Myconf module unloadable and `read_config_url`
     * always returns NULL.  Naming both paths explicitly makes the
     * lookup work regardless of how libaugeas was compiled. */
    aug = aug_init(NULL,
                   "/usr/local/share/augeas/lenses:/usr/share/augeas/lenses",
                   AUG_NO_MODL_AUTOLOAD);
    if (!aug)
        return -1;
    if (aug_set(aug, "/augeas/load/Myconf/lens", "Myconf.lns") < 0 ||
        aug_set(aug, "/augeas/load/Myconf/incl", "/etc/postWolf/config") < 0 ||
        aug_load(aug) < 0) {
        aug_close(aug);
        aug = NULL;
        return -1;
    }
    return 0;
}

void close_augeas(void) {
    if (aug) {
        aug_close(aug);
        aug = NULL;
    }
}

char *get_augeas(const char *key) {
    if (!aug || !key)
        return NULL;

    char path[512];
    int n = snprintf(path, sizeof(path), "%s%s", CONFIG_PREFIX, key);
    if (n < 0 || (size_t)n >= sizeof(path))
        return NULL;

    const char *value = NULL;
    if (aug_get(aug, path, &value) != 1 || !value)
        return NULL;

    return strdup(value);
}

char *read_config_url(const char *key) {
    if (init_augeas() != 0)
        return NULL;
    /* Do NOT close after each get: tearing down and re-creating the
     * augeas context per key forces a re-scan of /usr/share/augeas/lenses
     * and costs ~1 second per call.  A loader that reads ~14 keys in
     * a row burns ~15 s on cold start, blowing the MQC handshake
     * deadline.  Augeas memory is bounded; keeping one context open
     * for process lifetime is the right move.  Callers who genuinely
     * need to release the context can call close_augeas() explicitly. */
    char *raw = get_augeas(key);
    if (!raw)
        return NULL;

    fprintf(stderr, "Using %s from /etc/postWolf/config: %s\n", key, raw);

    const char *p = raw;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://",  7) == 0) p += 7;
    if (p != raw)
        memmove(raw, p, strlen(p) + 1);

    return raw;
}

/* Parse raw as a positive integer.  Returns 0 on success (out
 * receives the value), -1 on invalid input (out untouched).  Exposed
 * for direct unit testing without an Augeas backend. */
int parse_long_strict(const char *raw, long *out) {
    if (!raw || !out) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(raw, &end, 10);
    if (errno || end == raw || *end != '\0' || v <= 0)
        return -1;
    *out = v;
    return 0;
}

long read_config_long(const char *key, long default_val) {
    if (init_augeas() != 0)
        return default_val;
    /* Do NOT close after each get: tearing down and re-creating the
     * augeas context per key forces a re-scan of /usr/share/augeas/lenses
     * and costs ~1 second per call.  A loader that reads ~14 keys in
     * a row burns ~15 s on cold start, blowing the MQC handshake
     * deadline.  Augeas memory is bounded; keeping one context open
     * for process lifetime is the right move.  Callers who genuinely
     * need to release the context can call close_augeas() explicitly. */
    char *raw = get_augeas(key);
    if (!raw)
        return default_val;

    long v = 0;
    if (parse_long_strict(raw, &v) != 0) {
        fprintf(stderr,
                "[%s] /etc/postWolf/config: invalid value '%s', "
                "using default %ld\n", key, raw, default_val);
        free(raw);
        return default_val;
    }
    fprintf(stderr,
            "[%s] /etc/postWolf/config: %ld\n", key, v);
    free(raw);
    return v;
}

int read_config_bool(const char *key, int default_val) {
    if (init_augeas() != 0)
        return default_val;
    char *raw = get_augeas(key);
    if (!raw)
        return default_val;

    /* Case-insensitive match against the usual Yes/No vocabulary. */
    int v = -1;
    if (!strcasecmp(raw, "yes")  || !strcasecmp(raw, "true") ||
        !strcasecmp(raw, "on")   || !strcmp(raw, "1"))
        v = 1;
    else if (!strcasecmp(raw, "no") || !strcasecmp(raw, "false") ||
             !strcasecmp(raw, "off") || !strcmp(raw, "0"))
        v = 0;

    if (v < 0) {
        fprintf(stderr,
                "[%s] /etc/postWolf/config: invalid bool '%s', "
                "using default %s\n", key, raw, default_val ? "Yes" : "No");
        free(raw);
        return default_val;
    }
    fprintf(stderr,
            "[%s] /etc/postWolf/config: %s\n", key, v ? "Yes" : "No");
    free(raw);
    return v;
}

char *read_config_str(const char *key, const char *default_val) {
    if (init_augeas() != 0)
        return default_val ? strdup(default_val) : NULL;
    /* Do NOT close after each get: tearing down and re-creating the
     * augeas context per key forces a re-scan of /usr/share/augeas/lenses
     * and costs ~1 second per call.  A loader that reads ~14 keys in
     * a row burns ~15 s on cold start, blowing the MQC handshake
     * deadline.  Augeas memory is bounded; keeping one context open
     * for process lifetime is the right move.  Callers who genuinely
     * need to release the context can call close_augeas() explicitly. */
    char *raw = get_augeas(key);
    if (!raw)
        return default_val ? strdup(default_val) : NULL;

    fprintf(stderr,
            "[%s] /etc/postWolf/config: %s\n", key, raw);
    return raw;
}

#ifdef TEST_MAIN

#include <assert.h>

static int run_parse_long_tests(void) {
    int fails = 0;
    long out;

    /* Happy path: positive integer. */
    out = 0;
    if (parse_long_strict("42", &out) != 0 || out != 42) {
        fprintf(stderr, "FAIL parse_long_strict(\"42\")\n"); fails++;
    }
    /* Larger positive. */
    out = 0;
    if (parse_long_strict("1048576", &out) != 0 || out != 1048576) {
        fprintf(stderr, "FAIL parse_long_strict(\"1048576\")\n"); fails++;
    }
    /* Zero rejected. */
    if (parse_long_strict("0", &out) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(\"0\") accepted\n"); fails++;
    }
    /* Negative rejected. */
    if (parse_long_strict("-5", &out) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(\"-5\") accepted\n"); fails++;
    }
    /* Non-numeric rejected. */
    if (parse_long_strict("abc", &out) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(\"abc\") accepted\n"); fails++;
    }
    /* Trailing garbage rejected. */
    if (parse_long_strict("42x", &out) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(\"42x\") accepted\n"); fails++;
    }
    /* Empty string rejected. */
    if (parse_long_strict("", &out) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(\"\") accepted\n"); fails++;
    }
    /* NULL inputs rejected. */
    if (parse_long_strict(NULL, &out) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(NULL) accepted\n"); fails++;
    }
    if (parse_long_strict("42", NULL) == 0) {
        fprintf(stderr, "FAIL parse_long_strict(out=NULL) accepted\n"); fails++;
    }

    if (fails == 0)
        printf("parse_long_strict: 9/9 OK\n");
    return fails;
}

static int run_read_config_tests(void) {
    int fails = 0;

    /* read_config_long with absent key returns the default. */
    long v = read_config_long("global/this-key-does-not-exist-12345", 999);
    if (v != 999) {
        fprintf(stderr, "FAIL read_config_long absent-key: got %ld, want 999\n", v);
        fails++;
    }

    /* read_config_str with absent key returns a strdup of the default. */
    char *s = read_config_str("global/this-key-does-not-exist-12345", "fallback");
    if (!s || strcmp(s, "fallback") != 0) {
        fprintf(stderr, "FAIL read_config_str absent-key: got %s, want fallback\n",
                s ? s : "(null)");
        fails++;
    }
    free(s);

    /* read_config_str with NULL default returns NULL when key absent. */
    s = read_config_str("global/this-key-does-not-exist-12345", NULL);
    if (s != NULL) {
        fprintf(stderr, "FAIL read_config_str absent-key+NULL-default: got %s, want (null)\n",
                s);
        free(s);
        fails++;
    }

    if (fails == 0)
        printf("read_config_long/_str absent-key fallback: 3/3 OK\n");
    return fails;
}

int main(void) {
    int fails = 0;

    /* Pure parser tests (no Augeas dependency). */
    fails += run_parse_long_tests();

    /* Live config tests — exercise the full /etc/postWolf/config path
     * for absent-key fallback only (we don't assume any specific key
     * is set in the live config). */
    fails += run_read_config_tests();

    /* Existing get_augeas exploration test, kept for compatibility. */
    if (init_augeas() != 0) {
        fprintf(stderr, "init_augeas failed\n");
        return 1;
    }
    const char *keys[] = { "global/url-bootstrap", "global/does-not-exist" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        char *v = get_augeas(keys[i]);
        printf("%-25s = %s\n", keys[i], v ? v : "(not found)");
        free(v);
    }
    close_augeas();

    if (fails) {
        fprintf(stderr, "TEST FAILED: %d failure(s)\n", fails);
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
#endif
