/*
 * test_quic_mtls.c - Reproduce QUIC mutual TLS (client cert) failure
 *
 * Tests QUIC handshake with SSL_VERIFY_PEER on the server side,
 * using the same QUIC test infrastructure as tests/quic.c.
 *
 * Build: gcc -o test_quic_mtls test_quic_mtls.c -I. -DWOLFSSL_USE_OPTIONS_H \
 *        -L/usr/local/lib -lwolfssl -lm -lpthread
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef WOLFSSL_QUIC
#error "wolfSSL must be built with --enable-quic"
#endif

/* ---- Minimal QUIC test harness ---- */

#define NUM_LEVELS 4  /* initial, early_data, handshake, application */

typedef struct OutputBuffer {
    byte    data[64*1024];
    size_t  len;
} OutputBuffer;

typedef struct QuicTestCtx {
    const char    *name;
    WOLFSSL       *ssl;
    OutputBuffer   output[NUM_LEVELS];  /* per encryption level */
    int            verbose;
} QuicTestCtx;

static int on_set_encryption_secrets(WOLFSSL *ssl,
    WOLFSSL_ENCRYPTION_LEVEL level,
    const uint8_t *rx_secret, const uint8_t *tx_secret, size_t secret_len)
{
    QuicTestCtx *ctx = (QuicTestCtx*)wolfSSL_get_app_data(ssl);
    (void)rx_secret; (void)tx_secret; (void)secret_len;
    if (ctx->verbose)
        printf("[%s] set_encryption_secrets level=%d rx=%s tx=%s\n",
            ctx->name, level, rx_secret ? "yes" : "no",
            tx_secret ? "yes" : "no");
    return 1;
}

static int on_add_handshake_data(WOLFSSL *ssl,
    WOLFSSL_ENCRYPTION_LEVEL level,
    const uint8_t *data, size_t len)
{
    QuicTestCtx *ctx = (QuicTestCtx*)wolfSSL_get_app_data(ssl);
    if (ctx->verbose)
        printf("[%s] add_handshake_data level=%d len=%zu\n",
            ctx->name, level, len);
    if (level >= NUM_LEVELS) return 0;
    if (ctx->output[level].len + len > sizeof(ctx->output[level].data)) {
        fprintf(stderr, "[%s] output buffer overflow at level %d!\n",
            ctx->name, level);
        return 0;
    }
    memcpy(ctx->output[level].data + ctx->output[level].len, data, len);
    ctx->output[level].len += len;
    return 1;
}

static int on_flush_flight(WOLFSSL *ssl)
{
    (void)ssl;
    return 1;
}

static int on_send_alert(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
    uint8_t alert)
{
    QuicTestCtx *ctx = (QuicTestCtx*)wolfSSL_get_app_data(ssl);
    printf("[%s] *** ALERT level=%d alert=%d ***\n", ctx->name, level, alert);
    return 1;
}

static void hexdump(const char *label, const byte *data, size_t len)
{
    size_t i;
    printf("%s (%zu bytes):\n", label, len);
    for (i = 0; i < len && i < 64; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len > 64) printf("... (%zu more)", len - 64);
    printf("\n");
}

static WOLFSSL_QUIC_METHOD quic_method = {
    on_set_encryption_secrets,
    on_add_handshake_data,
    on_flush_flight,
    on_send_alert,
};

/* Forward all per-level output from src to dst */
static int forward_data(QuicTestCtx *src, QuicTestCtx *dst, int verbose)
{
    int ret, level;
    int any = 0;
    for (level = 0; level < NUM_LEVELS; level++) {
        if (src->output[level].len == 0) continue;
        any = 1;
        if (verbose)
            printf("[%s -> %s] forwarding %zu bytes at level %d\n",
                src->name, dst->name, src->output[level].len, level);
        ret = wolfSSL_provide_quic_data(dst->ssl,
            (WOLFSSL_ENCRYPTION_LEVEL)level,
            src->output[level].data, src->output[level].len);
        src->output[level].len = 0;
        if (ret != WOLFSSL_SUCCESS) return ret;
    }
    return any ? WOLFSSL_SUCCESS : 0;
}

static int has_output(QuicTestCtx *ctx)
{
    int i;
    for (i = 0; i < NUM_LEVELS; i++)
        if (ctx->output[i].len > 0) return 1;
    return 0;
}

/* ---- Cert files ---- */
#define CERT_DIR  "/home/ubuntu/ssh/certs/"
#define SRV_CERT  CERT_DIR "server-cert.pem"
#define SRV_KEY   CERT_DIR "server-key.pem"
#define CLI_CERT  CERT_DIR "client-cert.pem"
#define CLI_KEY   CERT_DIR "client-key.pem"
#define CA_CERT   CERT_DIR "ca-cert.pem"

int main(int argc, char **argv)
{
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    QuicTestCtx client, server;
    int ret, n, steps;
    int verbose = (argc > 1 && strcmp(argv[1], "-v") == 0);
    int done = 0;
    static const byte tp_c[] = {0, 1, 2, 3};
    static const byte tp_s[] = {4, 5, 6, 7};

    wolfSSL_Init();
    if (verbose)
        wolfSSL_Debugging_ON();

    printf("=== QUIC Mutual TLS Test ===\n");

    /* ---- Server CTX ---- */
    ctx_s = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx_s) { fprintf(stderr, "CTX_new server failed\n"); return 1; }

    if (wolfSSL_CTX_use_certificate_file(ctx_s, SRV_CERT,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "server cert load failed\n"); return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx_s, SRV_KEY,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "server key load failed\n"); return 1;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx_s, CA_CERT, NULL)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "server CA load failed\n"); return 1;
    }

    /* ---- Client CTX ---- */
    ctx_c = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx_c) { fprintf(stderr, "CTX_new client failed\n"); return 1; }

    if (wolfSSL_CTX_use_certificate_file(ctx_c, CLI_CERT,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "client cert load failed\n"); return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx_c, CLI_KEY,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "client key load failed\n"); return 1;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx_c, CA_CERT, NULL)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "client CA load failed\n"); return 1;
    }

    /* ---- Server SSL ---- */
    memset(&server, 0, sizeof(server));
    server.name = "server";
    server.verbose = verbose;
    server.ssl = wolfSSL_new(ctx_s);
    if (!server.ssl) { fprintf(stderr, "SSL_new server failed\n"); return 1; }
    wolfSSL_set_app_data(server.ssl, &server);
    wolfSSL_set_quic_method(server.ssl, &quic_method);
    wolfSSL_set_quic_transport_params(server.ssl, tp_s, sizeof(tp_s));
    /* THIS IS THE KEY: enable client cert verification */
    wolfSSL_set_verify(server.ssl, SSL_VERIFY_PEER, NULL);
    wolfSSL_set_accept_state(server.ssl);

    /* ---- Client SSL ---- */
    memset(&client, 0, sizeof(client));
    client.name = "client";
    client.verbose = verbose;
    client.ssl = wolfSSL_new(ctx_c);
    if (!client.ssl) { fprintf(stderr, "SSL_new client failed\n"); return 1; }
    wolfSSL_set_app_data(client.ssl, &client);
    wolfSSL_set_quic_method(client.ssl, &quic_method);
    wolfSSL_set_quic_transport_params(client.ssl, tp_c, sizeof(tp_c));
    wolfSSL_set_verify(client.ssl, SSL_VERIFY_NONE, NULL);
    wolfSSL_set_connect_state(client.ssl);

    printf("Starting QUIC handshake with VERIFY_PEER...\n");

    /* ---- Drive handshake ---- */
    /* Step 1: Client sends ClientHello */
    ret = wolfSSL_connect(client.ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(client.ssl, ret);
        if (err != SSL_ERROR_WANT_READ) {
            char buf[256];
            wolfSSL_ERR_error_string((unsigned long)err, buf);
            fprintf(stderr, "Client initial connect error: %d %s\n", err, buf);
            return 1;
        }
    }
    printf("[OK] Client sent ClientHello (%zu bytes)\n", client.output[0].len);

    for (steps = 0; steps < 20 && !done; steps++) {
        /* Forward client → server */
        if (has_output(&client)) {
            int lvl;
            for (lvl = 0; lvl < NUM_LEVELS; lvl++)
                if (client.output[lvl].len > 0)
                    hexdump("  client handshake data",
                            client.output[lvl].data, client.output[lvl].len);
            ret = forward_data(&client, &server, verbose);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "forward client->server failed: %d\n", ret);
                break;
            }
            n = wolfSSL_quic_read_write(server.ssl);
            if (n != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(server.ssl, n);
                if (err != SSL_ERROR_WANT_READ) {
                    char buf[256];
                    wolfSSL_ERR_error_string((unsigned long)err, buf);
                    fprintf(stderr, "[FAIL] Server error: %d %s\n", err, buf);
                    break;
                }
            }
            if (wolfSSL_is_init_finished(server.ssl)) {
                printf("[OK] Server handshake complete!\n");
                done = 1;
                break;
            }
        }

        /* Forward server → client */
        if (has_output(&server)) {
            ret = forward_data(&server, &client, verbose);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "forward server->client failed: %d\n", ret);
                break;
            }
            n = wolfSSL_quic_read_write(client.ssl);
            if (n != WOLFSSL_SUCCESS) {
                int err = wolfSSL_get_error(client.ssl, n);
                if (err != SSL_ERROR_WANT_READ) {
                    char buf[256];
                    wolfSSL_ERR_error_string((unsigned long)err, buf);
                    fprintf(stderr, "[FAIL] Client error: %d %s\n", err, buf);
                    break;
                }
            }
            if (wolfSSL_is_init_finished(client.ssl)) {
                printf("[OK] Client handshake complete!\n");
            }
        }

        if (!has_output(&client) && !has_output(&server)) {
            if (wolfSSL_is_init_finished(server.ssl) &&
                wolfSSL_is_init_finished(client.ssl)) {
                done = 1;
            }
            else {
                fprintf(stderr, "[FAIL] Stuck: no output from either side\n");
                break;
            }
        }
    }

    if (done) {
        WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(server.ssl);
        if (peer) {
            char *cn = wolfSSL_X509_get_subjectCN(peer);
            printf("[OK] Server got client cert CN=%s\n", cn ? cn : "(null)");
            wolfSSL_X509_free(peer);
        }
        else {
            printf("[WARN] Server did NOT get client cert\n");
        }
        printf("\n=== PASS: QUIC mutual TLS works! ===\n");
    }
    else {
        printf("\n=== FAIL: QUIC mutual TLS handshake failed ===\n");
    }

    wolfSSL_free(client.ssl);
    wolfSSL_free(server.ssl);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_Cleanup();

    return done ? 0 : 1;
}
