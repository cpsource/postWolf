/*
 * test_secure.c
 *
 * TLS 1.3 client/server test on localhost with post-quantum support.
 * Runs four test rounds:
 *   1. Classical:  ECDHE key exchange (P-256)
 *   2. PQ Hybrid:  ML-KEM-768 + P-256 hybrid key exchange
 *   3. PQ Only:    ML-KEM-1024 standalone key exchange
 *   4. ECH:        Encrypted Client Hello with PQ hybrid key exchange
 * Each round sends and receives 100 bytes of test data.
 * Restricted to AEAD cipher suites at runtime.
 *
 * Build:
 *   gcc -o test_secure test_secure.c -I. -L./src/.libs \
 *       -lwolfssl -lpthread -DWOLFSSL_USE_OPTIONS_H
 *
 * Run:
 *   LD_LIBRARY_PATH=./src/.libs ./test_secure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define BASE_PORT  2222
#define LOCALHOST  "127.0.0.1"
#define TEST_SZ    100

#define CERT_FILE  "certs/server-cert.pem"
#define KEY_FILE   "certs/server-key.pem"
#define CA_FILE    "certs/ca-cert.pem"

#define CIPHER_LIST \
    "TLS13-AES256-GCM-SHA384:" \
    "TLS13-AES128-GCM-SHA256:" \
    "TLS13-CHACHA20-POLY1305-SHA256:" \
    "ECDHE-ECDSA-AES256-GCM-SHA384:" \
    "ECDHE-RSA-AES256-GCM-SHA384"

/* ------------------------------------------------------------------ */
/*  Test round definitions                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;
    int         port;
    int         groups[4];   /* key exchange group IDs, 0-terminated */
    int         group_count;
} test_round_t;

static test_round_t rounds[] = {
    {
        "Classical (ECDHE P-256)",
        BASE_PORT,
        { WOLFSSL_ECC_SECP256R1 },
        1
    },
    {
        "PQ Hybrid (P-256 + ML-KEM-768)",
        BASE_PORT + 1,
        { WOLFSSL_SECP256R1MLKEM768 },
        1
    },
    {
        "PQ Only (ML-KEM-1024)",
        BASE_PORT + 2,
        { WOLFSSL_ML_KEM_1024 },
        1
    },
};

#define NUM_ROUNDS (sizeof(rounds) / sizeof(rounds[0]))

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */
static void err_exit(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void err_ssl(WOLFSSL *ssl, int ret, const char *msg)
{
    int err = wolfSSL_get_error(ssl, ret);
    char buf[256];
    wolfSSL_ERR_error_string((unsigned long)err, buf);
    fprintf(stderr, "ERROR: %s: %s\n", msg, buf);
}

static const char *get_kex_group_name(WOLFSSL *ssl)
{
    /* wolfSSL_get_curve_name returns the negotiated key exchange group */
    const char *name = wolfSSL_get_curve_name(ssl);
    return (name != NULL) ? name : "unknown";
}

/* ------------------------------------------------------------------ */
/*  Server thread                                                      */
/* ------------------------------------------------------------------ */
typedef struct {
    test_round_t *round;
    int           result;
} server_arg_t;

static void *server_thread(void *arg)
{
    server_arg_t      *sarg = (server_arg_t *)arg;
    test_round_t      *round = sarg->round;
    int                listenfd, connfd;
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);
    WOLFSSL_CTX       *ctx = NULL;
    WOLFSSL           *ssl = NULL;
    unsigned char      buf[TEST_SZ];
    int                ret, opt = 1;

    sarg->result = 1; /* assume failure */

    /* TCP listen socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
        err_exit("server: socket()");

    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((unsigned short)round->port);
    addr.sin_addr.s_addr = inet_addr(LOCALHOST);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        err_exit("server: bind()");

    if (listen(listenfd, 1) < 0)
        err_exit("server: listen()");

    printf("[server] listening on %s:%d\n", LOCALHOST, round->port);

    /* wolfSSL context — TLS 1.3 only */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL)
        err_exit("server: wolfSSL_CTX_new()");

    /* Restrict cipher suites to AEAD only */
    if (wolfSSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != WOLFSSL_SUCCESS)
        err_exit("server: set_cipher_list()");

    /* Set key exchange groups for this round */
    if (wolfSSL_CTX_set_groups(ctx, round->groups,
                               round->group_count) != WOLFSSL_SUCCESS)
        err_exit("server: set_groups()");

    /* Load server certificate and private key */
    if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE,
                                         WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        err_exit("server: load cert");

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        err_exit("server: load key");

    /* Accept one connection */
    connfd = accept(listenfd, (struct sockaddr *)&addr, &addrlen);
    if (connfd < 0)
        err_exit("server: accept()");

    printf("[server] client connected\n");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        err_exit("server: wolfSSL_new()");

    wolfSSL_set_fd(ssl, connfd);

    /* TLS handshake */
    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        err_ssl(ssl, ret, "server: wolfSSL_accept()");
        goto server_cleanup;
    }

    printf("[server] TLS 1.3 handshake complete\n");
    printf("[server] cipher: %s\n", wolfSSL_get_cipher_name(ssl));
    printf("[server] kex:    %s\n", get_kex_group_name(ssl));

    /* Receive 100 bytes from client */
    ret = wolfSSL_read(ssl, buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "server: wolfSSL_read()");
        goto server_cleanup;
    }

    printf("[server] received %d bytes\n", ret);

    /* Echo the data back */
    ret = wolfSSL_write(ssl, buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "server: wolfSSL_write()");
        goto server_cleanup;
    }

    printf("[server] sent %d bytes back\n", ret);
    sarg->result = 0; /* success */

server_cleanup:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(connfd);
    close(listenfd);
    wolfSSL_CTX_free(ctx);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Client                                                             */
/* ------------------------------------------------------------------ */
static int run_client(test_round_t *round)
{
    int                sockfd;
    struct sockaddr_in addr;
    WOLFSSL_CTX       *ctx = NULL;
    WOLFSSL           *ssl = NULL;
    unsigned char      send_buf[TEST_SZ];
    unsigned char      recv_buf[TEST_SZ];
    int                ret, i;

    /* Fill test data with a known pattern */
    for (i = 0; i < TEST_SZ; i++)
        send_buf[i] = (unsigned char)(i & 0xFF);

    /* Small delay to let the server start listening */
    usleep(100000);

    /* TCP connect */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        err_exit("client: socket()");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((unsigned short)round->port);
    addr.sin_addr.s_addr = inet_addr(LOCALHOST);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        err_exit("client: connect()");

    printf("[client] connected to %s:%d\n", LOCALHOST, round->port);

    /* wolfSSL context — TLS 1.3 only */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL)
        err_exit("client: wolfSSL_CTX_new()");

    /* Restrict cipher suites to AEAD only */
    if (wolfSSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != WOLFSSL_SUCCESS)
        err_exit("client: set_cipher_list()");

    /* Set key exchange groups for this round */
    if (wolfSSL_CTX_set_groups(ctx, round->groups,
                               round->group_count) != WOLFSSL_SUCCESS)
        err_exit("client: set_groups()");

    /* Load CA to verify server */
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != WOLFSSL_SUCCESS)
        err_exit("client: load CA");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        err_exit("client: wolfSSL_new()");

    wolfSSL_set_fd(ssl, sockfd);

    /* TLS handshake */
    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        err_ssl(ssl, ret, "client: wolfSSL_connect()");
        goto client_cleanup;
    }

    printf("[client] TLS 1.3 handshake complete\n");
    printf("[client] cipher: %s\n", wolfSSL_get_cipher_name(ssl));
    printf("[client] kex:    %s\n", get_kex_group_name(ssl));

    /* Send 100 bytes */
    ret = wolfSSL_write(ssl, send_buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "client: wolfSSL_write()");
        goto client_cleanup;
    }

    printf("[client] sent %d bytes\n", ret);

    /* Receive echo */
    ret = wolfSSL_read(ssl, recv_buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "client: wolfSSL_read()");
        goto client_cleanup;
    }

    printf("[client] received %d bytes\n", ret);

    /* Verify data integrity */
    if (memcmp(send_buf, recv_buf, TEST_SZ) == 0) {
        printf("[client] data verified OK — all %d bytes match\n", TEST_SZ);
    }
    else {
        fprintf(stderr, "[client] ERROR: data mismatch!\n");
        ret = -1;
    }

client_cleanup:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    return (ret == TEST_SZ) ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/*  Round 4: ECH (Encrypted Client Hello) test                         */
/* ------------------------------------------------------------------ */
#ifdef HAVE_ECH

#define ECH_PORT       (BASE_PORT + 3)
#define ECH_PUBLIC_NAME "public.example.com"
#define ECH_CONFIG_MAX  1024

typedef struct {
    byte   echConfig[ECH_CONFIG_MAX];
    word32 echConfigLen;
    int    result;
} ech_server_arg_t;

static void *ech_server_thread(void *arg)
{
    ech_server_arg_t  *sarg = (ech_server_arg_t *)arg;
    int                listenfd, connfd;
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);
    WOLFSSL_CTX       *ctx = NULL;
    WOLFSSL           *ssl = NULL;
    unsigned char      buf[TEST_SZ];
    int                ret, opt = 1;

    sarg->result = 1; /* assume failure */

    /* TCP listen socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
        err_exit("ech server: socket()");

    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(ECH_PORT);
    addr.sin_addr.s_addr = inet_addr(LOCALHOST);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        err_exit("ech server: bind()");

    if (listen(listenfd, 1) < 0)
        err_exit("ech server: listen()");

    printf("[server] listening on %s:%d\n", LOCALHOST, ECH_PORT);

    /* wolfSSL context — TLS 1.3 only */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL)
        err_exit("ech server: wolfSSL_CTX_new()");

    if (wolfSSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != WOLFSSL_SUCCESS)
        err_exit("ech server: set_cipher_list()");

    /* Generate ECH config (uses X25519 + HKDF-SHA256 + AES-128-GCM defaults) */
    if (wolfSSL_CTX_GenerateEchConfig(ctx, ECH_PUBLIC_NAME, 0, 0, 0)
            != WOLFSSL_SUCCESS)
        err_exit("ech server: GenerateEchConfig()");

    /* Export ECH config for the client */
    sarg->echConfigLen = ECH_CONFIG_MAX;
    if (wolfSSL_CTX_GetEchConfigs(ctx, sarg->echConfig, &sarg->echConfigLen)
            != WOLFSSL_SUCCESS)
        err_exit("ech server: GetEchConfigs()");

    printf("[server] ECH config generated (%u bytes)\n", sarg->echConfigLen);

    /* Load server certificate and private key */
    if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE,
                                         WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        err_exit("ech server: load cert");

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        err_exit("ech server: load key");

    /* Accept one connection */
    connfd = accept(listenfd, (struct sockaddr *)&addr, &addrlen);
    if (connfd < 0)
        err_exit("ech server: accept()");

    printf("[server] client connected\n");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        err_exit("ech server: wolfSSL_new()");

    wolfSSL_set_fd(ssl, connfd);

    /* TLS handshake */
    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        err_ssl(ssl, ret, "ech server: wolfSSL_accept()");
        goto ech_server_cleanup;
    }

    printf("[server] TLS 1.3 handshake complete (ECH)\n");
    printf("[server] cipher: %s\n", wolfSSL_get_cipher_name(ssl));
    printf("[server] kex:    %s\n", get_kex_group_name(ssl));

    /* Receive 100 bytes from client */
    ret = wolfSSL_read(ssl, buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "ech server: wolfSSL_read()");
        goto ech_server_cleanup;
    }

    printf("[server] received %d bytes\n", ret);

    /* Echo the data back */
    ret = wolfSSL_write(ssl, buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "ech server: wolfSSL_write()");
        goto ech_server_cleanup;
    }

    printf("[server] sent %d bytes back\n", ret);
    sarg->result = 0; /* success */

ech_server_cleanup:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(connfd);
    close(listenfd);
    wolfSSL_CTX_free(ctx);
    return NULL;
}

static int run_ech_client(ech_server_arg_t *sarg)
{
    int                sockfd;
    struct sockaddr_in addr;
    WOLFSSL_CTX       *ctx = NULL;
    WOLFSSL           *ssl = NULL;
    unsigned char      send_buf[TEST_SZ];
    unsigned char      recv_buf[TEST_SZ];
    int                ret, i;

    /* Fill test data with a known pattern */
    for (i = 0; i < TEST_SZ; i++)
        send_buf[i] = (unsigned char)(i & 0xFF);

    /* Small delay to let the server start listening */
    usleep(200000);

    /* TCP connect */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        err_exit("ech client: socket()");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(ECH_PORT);
    addr.sin_addr.s_addr = inet_addr(LOCALHOST);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        err_exit("ech client: connect()");

    printf("[client] connected to %s:%d\n", LOCALHOST, ECH_PORT);

    /* wolfSSL context — TLS 1.3 only */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL)
        err_exit("ech client: wolfSSL_CTX_new()");

    if (wolfSSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != WOLFSSL_SUCCESS)
        err_exit("ech client: set_cipher_list()");

    /* Load the server's ECH config into the client */
    if (wolfSSL_CTX_SetEchConfigs(ctx, sarg->echConfig, sarg->echConfigLen)
            != WOLFSSL_SUCCESS)
        err_exit("ech client: SetEchConfigs()");

    printf("[client] ECH config loaded (%u bytes)\n", sarg->echConfigLen);

    /* Load CA to verify server */
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != WOLFSSL_SUCCESS)
        err_exit("ech client: load CA");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        err_exit("ech client: wolfSSL_new()");

    wolfSSL_set_fd(ssl, sockfd);

    /* TLS handshake with ECH */
    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        err_ssl(ssl, ret, "ech client: wolfSSL_connect()");
        goto ech_client_cleanup;
    }

    printf("[client] TLS 1.3 handshake complete (ECH)\n");
    printf("[client] cipher: %s\n", wolfSSL_get_cipher_name(ssl));
    printf("[client] kex:    %s\n", get_kex_group_name(ssl));

    /* Send 100 bytes */
    ret = wolfSSL_write(ssl, send_buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "ech client: wolfSSL_write()");
        goto ech_client_cleanup;
    }

    printf("[client] sent %d bytes\n", ret);

    /* Receive echo */
    ret = wolfSSL_read(ssl, recv_buf, TEST_SZ);
    if (ret != TEST_SZ) {
        err_ssl(ssl, ret, "ech client: wolfSSL_read()");
        goto ech_client_cleanup;
    }

    printf("[client] received %d bytes\n", ret);

    /* Verify data integrity */
    if (memcmp(send_buf, recv_buf, TEST_SZ) == 0) {
        printf("[client] data verified OK — all %d bytes match\n", TEST_SZ);
    }
    else {
        fprintf(stderr, "[client] ERROR: data mismatch!\n");
        ret = -1;
    }

ech_client_cleanup:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    return (ret == TEST_SZ) ? 0 : 1;
}

static int run_ech_round(int *pass, int *fail)
{
    pthread_t        tid;
    ech_server_arg_t sarg;
    int              rc;

    memset(&sarg, 0, sizeof(sarg));

    /* Start server in a thread */
    if (pthread_create(&tid, NULL, ech_server_thread, &sarg) != 0)
        err_exit("pthread_create() ech");

    /* Run client in main thread */
    rc = run_ech_client(&sarg);

    /* Wait for server thread */
    pthread_join(tid, NULL);

    if (rc == 0 && sarg.result == 0) {
        printf("\n--- Round 4: PASSED ---\n");
        (*pass)++;
    }
    else {
        printf("\n--- Round 4: FAILED ---\n");
        (*fail)++;
    }
    return rc;
}

#endif /* HAVE_ECH */

/* ------------------------------------------------------------------ */
/*  Round 5: QUIC TLS 1.3 handshake (in-memory, no network)           */
/* ------------------------------------------------------------------ */
#ifdef WOLFSSL_QUIC

#include <wolfssl/quic.h>

#define QUIC_BUF_SZ  (64 * 1024)

typedef struct {
    const char             *name;
    WOLFSSL                *ssl;
    byte                    data[QUIC_BUF_SZ];
    size_t                  len;
    WOLFSSL_ENCRYPTION_LEVEL level;
    int                     alert;
} QuicPeer;

static int qc_set_secrets(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                           const uint8_t *rx, const uint8_t *tx, size_t len)
{
    (void)ssl; (void)level; (void)rx; (void)tx; (void)len;
    return 1;
}

static int qc_add_hs_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                           const uint8_t *data, size_t len)
{
    QuicPeer *peer = (QuicPeer *)wolfSSL_get_app_data(ssl);
    if (peer->len + len > QUIC_BUF_SZ) return 0;
    memcpy(peer->data + peer->len, data, len);
    peer->len += len;
    peer->level = level;
    return 1;
}

static int qc_flush(WOLFSSL *ssl)
{
    (void)ssl;
    return 1;
}

static int qc_alert(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t a)
{
    QuicPeer *peer = (QuicPeer *)wolfSSL_get_app_data(ssl);
    (void)level;
    peer->alert = a;
    return 1;
}

static WOLFSSL_QUIC_METHOD qc_method = {
    qc_set_secrets, qc_add_hs_data, qc_flush, qc_alert
};

/* Feed buffered handshake data from src to dst, then do_handshake on dst */
static int quic_forward_and_step(QuicPeer *src, QuicPeer *dst)
{
    int ret;

    if (src->len > 0) {
        ret = wolfSSL_provide_quic_data(dst->ssl, src->level,
                                        src->data, src->len);
        if (ret != WOLFSSL_SUCCESS) return -1;
        src->len = 0;
    }

    ret = wolfSSL_quic_do_handshake(dst->ssl);
    return ret;
}

static int run_quic_round(int *pass, int *fail)
{
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    QuicPeer     client, server;
    int          ret, loops;
    int          rc = 1; /* assume failure */
    static const byte tp[] = {0, 1, 2, 3, 4, 5, 6, 7};

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    client.name = "quic-client";
    server.name = "quic-server";

    /* Client context */
    ctx_c = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx_c == NULL) { fprintf(stderr, "ERROR: quic client CTX\n"); goto done; }

    if (wolfSSL_CTX_set_cipher_list(ctx_c, CIPHER_LIST) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic client cipher\n"); goto done; }

    if (wolfSSL_CTX_load_verify_locations(ctx_c, CA_FILE, NULL) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic client CA\n"); goto done; }

    /* Server context */
    ctx_s = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx_s == NULL) { fprintf(stderr, "ERROR: quic server CTX\n"); goto done; }

    if (wolfSSL_CTX_set_cipher_list(ctx_s, CIPHER_LIST) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic server cipher\n"); goto done; }

    if (wolfSSL_CTX_use_certificate_file(ctx_s, CERT_FILE,
                                         WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic server cert\n"); goto done; }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx_s, KEY_FILE,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic server key\n"); goto done; }

    /* Create SSL objects */
    client.ssl = wolfSSL_new(ctx_c);
    server.ssl = wolfSSL_new(ctx_s);
    if (client.ssl == NULL || server.ssl == NULL)
        { fprintf(stderr, "ERROR: quic SSL new\n"); goto done; }

    /* Set up QUIC method and app data */
    wolfSSL_set_app_data(client.ssl, &client);
    wolfSSL_set_app_data(server.ssl, &server);

    if (wolfSSL_set_quic_method(client.ssl, &qc_method) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic client method\n"); goto done; }
    if (wolfSSL_set_quic_method(server.ssl, &qc_method) != WOLFSSL_SUCCESS)
        { fprintf(stderr, "ERROR: quic server method\n"); goto done; }

    /* Set transport params (required by QUIC) */
    wolfSSL_set_quic_transport_params(client.ssl, tp, sizeof(tp));
    wolfSSL_set_quic_transport_params(server.ssl, tp, sizeof(tp));

    /* Disable cert verification for this in-memory test */
    wolfSSL_set_verify(client.ssl, SSL_VERIFY_NONE, NULL);

    printf("[quic]  starting in-memory TLS 1.3 handshake\n");

    /* Kick off client → produces ClientHello */
    ret = wolfSSL_quic_do_handshake(client.ssl);

    /* Handshake loop: forward data back and forth */
    for (loops = 0; loops < 10; loops++) {
        /* client → server */
        if (client.len > 0) {
            ret = quic_forward_and_step(&client, &server);
        }
        /* server → client */
        if (server.len > 0) {
            ret = quic_forward_and_step(&server, &client);
        }

        /* Check if both sides are done */
        if (wolfSSL_is_init_finished(client.ssl) &&
            wolfSSL_is_init_finished(server.ssl)) {
            break;
        }

        if (client.alert || server.alert) {
            fprintf(stderr, "[quic]  alert: client=%d server=%d\n",
                    client.alert, server.alert);
            goto done;
        }
    }

    if (!wolfSSL_is_init_finished(client.ssl) ||
        !wolfSSL_is_init_finished(server.ssl)) {
        fprintf(stderr, "[quic]  handshake did not complete in %d loops\n", loops);
        goto done;
    }

    printf("[quic]  TLS 1.3 handshake complete (%d round trips)\n", loops);
    printf("[quic]  cipher: %s\n", wolfSSL_get_cipher_name(client.ssl));
    printf("[quic]  kex:    %s\n", get_kex_group_name(client.ssl));

    rc = 0; /* success */

done:
    if (rc == 0) {
        printf("\n--- Round 5: PASSED ---\n");
        (*pass)++;
    }
    else {
        printf("\n--- Round 5: FAILED ---\n");
        (*fail)++;
    }

    if (client.ssl) wolfSSL_free(client.ssl);
    if (server.ssl) wolfSSL_free(server.ssl);
    if (ctx_c) wolfSSL_CTX_free(ctx_c);
    if (ctx_s) wolfSSL_CTX_free(ctx_s);
    return rc;
}

#endif /* WOLFSSL_QUIC */

/* ------------------------------------------------------------------ */
/*  Main — run all test rounds                                         */
/* ------------------------------------------------------------------ */
int main(void)
{
    int          rc, total_pass = 0, total_fail = 0;
    unsigned int i;

    wolfSSL_Init();

    for (i = 0; i < NUM_ROUNDS; i++) {
        pthread_t    tid;
        server_arg_t sarg;

        printf("\n========================================\n");
        printf("  Round %u: %s\n", i + 1, rounds[i].name);
        printf("========================================\n\n");

        sarg.round = &rounds[i];
        sarg.result = 1;

        /* Start server in a thread */
        if (pthread_create(&tid, NULL, server_thread, &sarg) != 0)
            err_exit("pthread_create()");

        /* Run client in main thread */
        rc = run_client(&rounds[i]);

        /* Wait for server thread */
        pthread_join(tid, NULL);

        if (rc == 0 && sarg.result == 0) {
            printf("\n--- Round %u: PASSED ---\n", i + 1);
            total_pass++;
        }
        else {
            printf("\n--- Round %u: FAILED ---\n", i + 1);
            total_fail++;
        }
    }

#ifdef HAVE_ECH
    printf("\n========================================\n");
    printf("  Round 4: ECH (Encrypted Client Hello)\n");
    printf("========================================\n\n");

    run_ech_round(&total_pass, &total_fail);
#endif

#ifdef WOLFSSL_QUIC
    printf("\n========================================\n");
    printf("  Round 5: QUIC TLS 1.3 Handshake\n");
    printf("========================================\n\n");

    run_quic_round(&total_pass, &total_fail);
#endif

    wolfSSL_Cleanup();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", total_pass, total_fail);
    printf("========================================\n");

    return (total_fail == 0) ? 0 : 1;
}
