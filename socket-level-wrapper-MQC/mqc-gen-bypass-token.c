/******************************************************************************
 * File:        mqc-gen-bypass-token.c
 * Purpose:     Stand-alone CLI that prints a fresh MQCBYPASS token.
 *
 * Description:
 *   Generates a 99-byte MQCBYPASS line (or just its 88-hex payload) for
 *   manual / scripted use: hand it to a colleague who needs to bypass
 *   AbuseIPDB from a flagged VPN exit, paste into a shell that doesn't
 *   have ~/.mqc-master-password, or feed into a non-qsh client that
 *   sets MQC_BYPASS_TOKEN manually.
 *
 *   The token is bound to the source IP the SERVER will see (so it
 *   cannot be replayed from a different IP) and has a ±300s freshness
 *   window — keep it brief.
 *
 * Usage:
 *   mqc-gen-bypass-token --src-ip=IP [--bits=N] [--master=FILE] [--line]
 *
 * Examples:
 *   mqc-gen-bypass-token --src-ip=98.33.86.7
 *   mqc-gen-bypass-token --src-ip=98.33.86.7 --bits=0x0f --line
 *
 * Defaults:
 *   --bits=0x01           AbuseIPDB-only bypass
 *   --master=$HOME/.mqc-master-password (0600 required)
 *
 * Output (one line):
 *   default              88 hex chars (paste into MQC_BYPASS_TOKEN env)
 *   --line               99-byte "MQCBYPASS:<hex>\n" wire line
 *
 * No network — pure local file read + HMAC.
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --src-ip=IP [--bits=N] [--master=FILE] [--line]\n\n"
        "Generates a fresh MQCBYPASS token bound to the given source IP.\n"
        "Default --bits is 0x01 (AbuseIPDB-only).  Token freshness window\n"
        "is ±%ds, so use within ~5 minutes of generation.\n",
        prog, MQC_BYPASS_FRESHNESS_SEC);
    exit(1);
}

static char *read_master_password(const char *path)
{
    FILE *f;
    struct stat st;
    char buf[1024];
    char *out;
    size_t len;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return NULL;
    }
    if ((st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0) {
        fprintf(stderr, "%s: mode 0%o — refusing to read (chmod 600)\n",
                path, (unsigned)(st.st_mode & 0777));
        return NULL;
    }
    f = fopen(path, "r");
    if (!f) { fprintf(stderr, "%s: cannot open\n", path); return NULL; }
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f); fprintf(stderr, "%s: empty\n", path); return NULL;
    }
    fclose(f);

    len = strlen(buf);
    while (len && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                   buf[len-1] == ' '  || buf[len-1] == '\t'))
        buf[--len] = '\0';
    if (len == 0) {
        fprintf(stderr, "%s: blank line\n", path); return NULL;
    }
    out = strdup(buf);
    return out;
}

int main(int argc, char *argv[])
{
    const char *src_ip = NULL;
    const char *master_path = NULL;
    uint32_t bits = MQC_BYPASS_ABUSE;
    int want_line = 0;
    char master_path_buf[512];
    char *master = NULL;
    char line[MQC_BYPASS_LINE_LEN];
    int i;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--src-ip=", 9) == 0) {
            src_ip = argv[i] + 9;
        } else if (strncmp(argv[i], "--bits=", 7) == 0) {
            const char *v = argv[i] + 7;
            char *endp;
            unsigned long n = strtoul(v, &endp, 0);
            if (*v == '\0' || *endp != '\0' ||
                n == 0 || n > MQC_BYPASS_VALID_MASK) {
                fprintf(stderr,
                    "invalid --bits=%s (valid mask: 0x%x)\n",
                    v, MQC_BYPASS_VALID_MASK);
                return 1;
            }
            bits = (uint32_t)n;
        } else if (strncmp(argv[i], "--master=", 9) == 0) {
            master_path = argv[i] + 9;
        } else if (strcmp(argv[i], "--line") == 0) {
            want_line = 1;
        } else {
            usage(argv[0]);
        }
    }
    if (!src_ip || !*src_ip) usage(argv[0]);

    if (!master_path) {
        const char *home = getenv("HOME");
        if (!home) { fprintf(stderr, "$HOME unset\n"); return 1; }
        snprintf(master_path_buf, sizeof(master_path_buf),
                 "%s/.mqc-master-password", home);
        master_path = master_path_buf;
    }

    master = read_master_password(master_path);
    if (!master) return 1;

    if (mqc_bypass_make(master, (uint64_t)time(NULL), bits, src_ip, line) != 0) {
        fprintf(stderr, "token build failed\n");
        free(master);
        return 1;
    }
    free(master);

    if (want_line) {
        fwrite(line, 1, MQC_BYPASS_LINE_LEN, stdout);
    } else {
        fwrite(line + MQC_BYPASS_PREFIX_LEN, 1, MQC_BYPASS_HEX_LEN, stdout);
        fputc('\n', stdout);
    }
    return 0;
}
