/* test_name_check.c — issue #9 regression: expected-identity check.
 *
 * Exercises mqc_connect's post-verify name check (Section 10.7 of
 * the MQC spec) against a live MQC listener.  Three scenarios:
 *
 *   1. wrong expected_name           -> mqc_connect MUST fail
 *   2. disabled name check           -> mqc_connect SHOULD succeed
 *   3. IP literal, no expected_name  -> mqc_connect MUST fail
 *
 * The implicit positive baseline (derived expected_name == host) is
 * already covered by `mqc --encode | mqc --decode` in the smoke tests
 * — this binary only chases the negative paths and the explicit
 * opt-out.
 *
 * Defaults assume a local factsorlie deployment (the postWolf
 * reference setup); override with --tpm / --server / --port.
 *
 * Build:   make tests/test_name_check
 * Run:     ./tests/test_name_check
 * Exit:    0 = all pass, 1 = at least one failure, 2 = setup error.
 */

#include "mqc.h"
#include "mqc_peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#define DEFAULT_TPM     "/home/ubuntu/.TPM/factsorlie.com"
#define DEFAULT_SERVER  "factsorlie.com:8446"
#define DEFAULT_HOST    "factsorlie.com"
#define DEFAULT_PORT    8446

static const char *g_tpm    = DEFAULT_TPM;
static const char *g_server = DEFAULT_SERVER;
static const char *g_host   = DEFAULT_HOST;
static int         g_port   = DEFAULT_PORT;
static unsigned char g_ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];

static mqc_ctx_t *mk_ctx(void) {
    mqc_cfg_t cfg = {0};
    cfg.role         = MQC_CLIENT;
    cfg.tpm_path     = g_tpm;
    cfg.mtc_server   = g_server;
    cfg.ca_pubkey    = g_ca_pubkey;
    cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
    return mqc_ctx_new(&cfg);
}

static int expect_connect_fail(const char *label, mqc_ctx_t *ctx,
                               const char *host) {
    mqc_conn_t *c = mqc_connect(ctx, host, g_port);
    if (c) {
        mqc_close(c);
        fprintf(stderr, "[%s] FAIL: connect succeeded but should have failed\n",
                label);
        return 1;
    }
    fprintf(stderr, "[%s] OK: connect rejected\n", label);
    return 0;
}

static int expect_connect_ok(const char *label, mqc_ctx_t *ctx) {
    mqc_conn_t *c = mqc_connect(ctx, g_host, g_port);
    if (!c) {
        fprintf(stderr, "[%s] FAIL: connect rejected but should have succeeded\n",
                label);
        return 1;
    }
    mqc_close(c);
    fprintf(stderr, "[%s] OK: connect succeeded\n", label);
    return 0;
}

static int resolve_v4(const char *host, char *out, size_t outsz) {
    struct addrinfo hints = {0}, *res = NULL;
    int rc;
    hints.ai_family = AF_INET;
    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;
    void *addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    inet_ntop(AF_INET, addr, out, (socklen_t)outsz);
    freeaddrinfo(res);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--tpm DIR] [--server HOST:PORT] [--host HOST] [--port N]\n"
        "Defaults: tpm=%s server=%s host=%s port=%d\n",
        prog, DEFAULT_TPM, DEFAULT_SERVER, DEFAULT_HOST, DEFAULT_PORT);
}

int main(int argc, char **argv) {
    int fails = 0, i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tpm")    && i + 1 < argc) g_tpm    = argv[++i];
        else if (!strcmp(argv[i], "--server") && i + 1 < argc) g_server = argv[++i];
        else if (!strcmp(argv[i], "--host")   && i + 1 < argc) g_host   = argv[++i];
        else if (!strcmp(argv[i], "--port")   && i + 1 < argc) g_port   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            usage(argv[0]); return 2;
        }
    }

    if (mqc_load_ca_pubkey(g_server, g_ca_pubkey) != 0) {
        fprintf(stderr, "could not load CA cosigner pubkey from %s\n", g_server);
        return 2;
    }

    /* Warmup: mqc_peer_verify drops the FIRST connection that misses
     * the local revocation cache, fetches the status, and persists it
     * — the next connection then finds the cache fresh and proceeds.
     * Run a couple of happy-path connects so the negative tests below
     * exercise the name-check code path, not the first-contact-drop
     * path.  Failures here are tolerated (server-side rate limits
     * from prior runs in the same process can drop early connects);
     * the test below is the load-bearing assertion. */
    for (i = 0; i < 3; i++) {
        mqc_ctx_t *ctx = mk_ctx();
        if (ctx) {
            mqc_conn_t *c = mqc_connect(ctx, g_host, g_port);
            if (c) mqc_close(c);
            mqc_ctx_free(ctx);
        }
    }

    /* 1. wrong expected_name -> reject */
    {
        mqc_ctx_t *ctx = mk_ctx();
        if (!ctx) { fprintf(stderr, "mqc_ctx_new failed\n"); return 2; }
        mqc_ctx_set_expected_name(ctx, "evil.example");
        fails += expect_connect_fail("wrong-name", ctx, g_host);
        mqc_ctx_free(ctx);
    }

    /* 2. disabled name check -> accept */
    {
        mqc_ctx_t *ctx = mk_ctx();
        if (!ctx) { fprintf(stderr, "mqc_ctx_new failed\n"); return 2; }
        mqc_ctx_disable_name_check(ctx);
        fails += expect_connect_ok("disabled", ctx);
        mqc_ctx_free(ctx);
    }

    /* 3. dial by IPv4 literal, no expected_name -> reject */
    {
        char ipbuf[64];
        if (resolve_v4(g_host, ipbuf, sizeof(ipbuf)) != 0) {
            fprintf(stderr, "[ip-literal] SKIP: cannot resolve %s\n", g_host);
        } else {
            mqc_ctx_t *ctx = mk_ctx();
            if (!ctx) { fprintf(stderr, "mqc_ctx_new failed\n"); return 2; }
            fails += expect_connect_fail("ip-literal", ctx, ipbuf);
            mqc_ctx_free(ctx);
        }
    }

    if (fails) {
        fprintf(stderr, "TEST FAILED: %d failure(s)\n", fails);
        return 1;
    }
    fprintf(stderr, "ALL P2c NEGATIVE TESTS PASSED\n");
    return 0;
}
