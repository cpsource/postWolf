/* slc.c — Socket Level Connection API implementation
 *
 * Copyright (C) 2026 Cal Page. All rights reserved.
 */

#include "slc.h"

/* wolfssl/options.h MUST come before any other wolfSSL headers.
 * It defines the feature macros (HAVE_ECH, HAVE_MTC, etc.) that
 * control conditional compilation in the rest of the library. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#ifdef HAVE_ECH
#include <wolfssl/wolfcrypt/hpke.h>
#endif
#ifdef HAVE_TRUST_ANCHOR_IDS
#include <wolfssl/wolfcrypt/hash.h>
#endif
#ifdef HAVE_MTC
#include <wolfssl/wolfcrypt/mtc.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* --- Internal structures --- */

struct slc_ctx {
    WOLFSSL_CTX    *wctx;
    slc_role_t      role;
    /* MTC config (optional) */
    char           *mtc_server;
    unsigned char  *ca_pubkey;
    int             ca_pubkey_sz;
    int             mtc_leaf_index;  /* -1 = not yet discovered */
};

struct slc_conn {
    WOLFSSL *ssl;
    int      fd;
};

/* --- Init guard --- */

static int slc_init_count = 0;

static int slc_ensure_init(void)
{
    if (slc_init_count == 0) {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS)
            return -1;
    }
    slc_init_count++;
    return 0;
}

static void slc_maybe_cleanup(void)
{
    if (slc_init_count > 0) {
        slc_init_count--;
        if (slc_init_count == 0)
            wolfSSL_Cleanup();
    }
}

/* --- Context --- */

slc_ctx_t *slc_ctx_new(const slc_cfg_t *cfg)
{
    slc_ctx_t *ctx;
    WOLFSSL_METHOD *method;

    if (cfg == NULL)
        return NULL;

    if (slc_ensure_init() != 0)
        return NULL;

    ctx = (slc_ctx_t *)calloc(1, sizeof(slc_ctx_t));
    if (ctx == NULL) {
        slc_maybe_cleanup();
        return NULL;
    }

    ctx->role = cfg->role;
    ctx->mtc_leaf_index = -1;

    if (cfg->role == SLC_CLIENT)
        method = wolfTLSv1_3_client_method();
    else
        method = wolfTLSv1_3_server_method();

    ctx->wctx = wolfSSL_CTX_new(method);
    if (ctx->wctx == NULL) {
        free(ctx);
        slc_maybe_cleanup();
        return NULL;
    }

    /* Load identity — MTC or traditional X.509 */
#ifdef HAVE_MTC
    if (cfg->mtc_store != NULL) {
        /* MTC mode: load certificate.json + private_key.pem from TPM dir */
        if (wolfSSL_CTX_use_MTC_certificate(ctx->wctx, cfg->mtc_store)
                != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx->wctx);
            free(ctx);
            slc_maybe_cleanup();
            return NULL;
        }
    } else
#endif
    {
        /* Traditional X.509 mode */
        if (cfg->cert_file != NULL) {
            if (wolfSSL_CTX_use_certificate_file(ctx->wctx, cfg->cert_file,
                    WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
                wolfSSL_CTX_free(ctx->wctx);
                free(ctx);
                slc_maybe_cleanup();
                return NULL;
            }
        }

        if (cfg->key_file != NULL) {
            if (wolfSSL_CTX_use_PrivateKey_file(ctx->wctx, cfg->key_file,
                    WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
                wolfSSL_CTX_free(ctx->wctx);
                free(ctx);
                slc_maybe_cleanup();
                return NULL;
            }
        }
    }

    /* Load CA for peer verification */
    if (cfg->ca_file != NULL) {
        if (wolfSSL_CTX_load_verify_locations(ctx->wctx, cfg->ca_file, NULL)
                != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx->wctx);
            free(ctx);
            slc_maybe_cleanup();
            return NULL;
        }
    }

    /* Enable peer verification — role-aware:
     *   - MTC mode: disable X.509 chain verification — trust comes from
     *     Merkle proof + cosignature, not CA chains
     *   - With ca_file: mutual TLS (both sides present and verify certs)
     *   - Server without ca_file: one-way TLS (server doesn't demand client cert)
     *   - Client without ca_file: still verify the server's cert */
#ifdef HAVE_MTC
    if (cfg->mtc_store != NULL) {
        /* MTC: wolfSSL handles MTC proof verification internally when
         * the peer presents a CTC_MTC_PROOF certificate. Disable
         * traditional X.509 chain validation. */
        wolfSSL_CTX_set_verify(ctx->wctx, WOLFSSL_VERIFY_NONE, NULL);
    } else
#endif
    if (cfg->ca_file != NULL) {
        wolfSSL_CTX_set_verify(ctx->wctx,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else if (cfg->role == SLC_SERVER) {
        wolfSSL_CTX_set_verify(ctx->wctx, WOLFSSL_VERIFY_NONE, NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx->wctx, WOLFSSL_VERIFY_PEER, NULL);
    }

#ifdef HAVE_ECH
    if (cfg->role == SLC_SERVER && cfg->ech_public_name != NULL) {
        /* Server: generate ECH keypair (X25519 + HKDF-SHA256 + AES-128-GCM)
         * maxNameLen=128 pads inner SNI to uniform length, preventing
         * traffic analysis from revealing the requested server name. */
        if (wolfSSL_CTX_GenerateEchConfigEx(ctx->wctx, cfg->ech_public_name,
                DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
                HPKE_AES_128_GCM, 128) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx->wctx);
            free(ctx);
            slc_maybe_cleanup();
            return NULL;
        }
        wolfSSL_CTX_SetEchEnable(ctx->wctx, 1);
    }
    else if (cfg->role == SLC_CLIENT && cfg->ech_configs_b64 != NULL) {
        /* Client: load server's ECH config */
        if (wolfSSL_CTX_SetEchConfigsBase64(ctx->wctx, cfg->ech_configs_b64,
                (word32)strlen(cfg->ech_configs_b64)) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx->wctx);
            free(ctx);
            slc_maybe_cleanup();
            return NULL;
        }
        wolfSSL_CTX_SetEchEnable(ctx->wctx, 1);
    }
#else
    if (cfg->ech_configs_b64 != NULL || cfg->ech_public_name != NULL) {
        /* ECH requested but not compiled in */
        wolfSSL_CTX_free(ctx->wctx);
        free(ctx);
        slc_maybe_cleanup();
        return NULL;
    }
#endif

    return ctx;
}

int slc_ctx_get_ech_configs(slc_ctx_t *ctx, unsigned char *buf, int *sz)
{
#ifdef HAVE_ECH
    word32 len;

    if (ctx == NULL || ctx->wctx == NULL || sz == NULL)
        return -1;

    if (buf == NULL) {
        /* Query required size */
        len = 0;
        wolfSSL_CTX_GetEchConfigs(ctx->wctx, NULL, &len);
        *sz = (int)len;
        return 0;
    }

    len = (word32)*sz;
    if (wolfSSL_CTX_GetEchConfigs(ctx->wctx, buf, &len) != WOLFSSL_SUCCESS)
        return -1;

    *sz = (int)len;
    return 0;
#else
    (void)ctx; (void)buf; (void)sz;
    return -1;
#endif
}

int slc_ctx_set_mtc(slc_ctx_t *ctx, const char *mtc_server,
                    const unsigned char *ca_pubkey, int ca_pubkey_sz)
{
    if (ctx == NULL || mtc_server == NULL || ca_pubkey == NULL ||
            ca_pubkey_sz <= 0)
        return -1;

    /* Free previous MTC config if any */
    free(ctx->mtc_server);
    free(ctx->ca_pubkey);

    ctx->mtc_server = strdup(mtc_server);
    if (ctx->mtc_server == NULL)
        return -1;

    ctx->ca_pubkey = (unsigned char *)malloc((size_t)ca_pubkey_sz);
    if (ctx->ca_pubkey == NULL) {
        free(ctx->mtc_server);
        ctx->mtc_server = NULL;
        return -1;
    }
    memcpy(ctx->ca_pubkey, ca_pubkey, (size_t)ca_pubkey_sz);
    ctx->ca_pubkey_sz = ca_pubkey_sz;
    ctx->mtc_leaf_index = -1; /* will be discovered during connect/accept */

#ifdef HAVE_TRUST_ANCHOR_IDS
    /* Register the MTC CA public key as a trust anchor ID so the server
     * knows this client supports MTC verification and can send an MTC
     * certificate chain instead of a traditional X.509 chain.
     * The trust anchor ID is the SHA-256 hash of the CA public key. */
    {
        byte anchor_id[WC_SHA256_DIGEST_SIZE];
        if (wc_Sha256Hash((const byte *)ca_pubkey, (word32)ca_pubkey_sz,
                          anchor_id) == 0) {
            wolfSSL_CTX_UseTrustAnchorId(ctx->wctx, anchor_id,
                                         sizeof(anchor_id));
        }
    }
#endif

#ifdef HAVE_MTC
    /* Register the CA public key as a cosigner so wolfSSL can verify
     * peer MTC cosignatures during the TLS handshake. */
    {
        /* Cosigner ID is "<log_id>.ca" — we use the SHA-256 hash of the
         * CA pubkey as a compact identifier for the AddCosigner call. */
        byte cosigner_id[WC_SHA256_DIGEST_SIZE];
        if (wc_Sha256Hash((const byte *)ca_pubkey, (word32)ca_pubkey_sz,
                          cosigner_id) == 0) {
            wolfSSL_MTC_AddCosigner(ctx->wctx,
                cosigner_id, sizeof(cosigner_id),
                (const unsigned char *)ca_pubkey, (unsigned int)ca_pubkey_sz,
                CTC_ED25519);
        }
    }
#endif

    return 0;
}

int slc_ctx_load_mtc(slc_ctx_t *ctx, const char *tpm_path)
{
#ifdef HAVE_MTC
    if (ctx == NULL || tpm_path == NULL)
        return -1;

    if (wolfSSL_CTX_use_MTC_certificate(ctx->wctx, tpm_path)
            != WOLFSSL_SUCCESS)
        return -1;

    return 0;
#else
    (void)ctx; (void)tpm_path;
    return -1;
#endif
}

void slc_ctx_free(slc_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->wctx != NULL)
        wolfSSL_CTX_free(ctx->wctx);

    free(ctx->mtc_server);
    free(ctx->ca_pubkey);
    free(ctx);

    slc_maybe_cleanup();
}

/* --- Connection helpers --- */

static slc_conn_t *slc_conn_new(slc_ctx_t *ctx, int fd)
{
    slc_conn_t *conn;

    conn = (slc_conn_t *)calloc(1, sizeof(slc_conn_t));
    if (conn == NULL)
        return NULL;

    conn->fd = fd;
    conn->ssl = wolfSSL_new(ctx->wctx);
    if (conn->ssl == NULL) {
        free(conn);
        return NULL;
    }

    if (wolfSSL_set_fd(conn->ssl, fd) != WOLFSSL_SUCCESS) {
        wolfSSL_free(conn->ssl);
        free(conn);
        return NULL;
    }

    return conn;
}

/* TODO: MTC verification during handshake
 * When MTC is configured (ctx->mtc_server != NULL), connect/accept should:
 * 1. Hash the peer certificate's subject key ID
 * 2. Query the MTC server for the leaf entry
 * 3. Verify the Merkle inclusion proof
 * 4. Verify the Ed25519 cosignature against ctx->ca_pubkey
 * 5. Check revocation status
 * For now, TLS 1.3 certificate verification is handled by wolfSSL. */

/* --- ECH cache (~/.TPM/ech/<host>.conf) --- */

#ifdef HAVE_ECH

/* Build path: ~/.TPM/ech/<host>.conf */
static int slc_ech_cache_path(const char *host, char *out, int outsz)
{
    const char *home = getenv("HOME");
    if (home == NULL)
        return -1;
    snprintf(out, (size_t)outsz, "%s/.TPM/ech/%s.conf", home, host);
    return 0;
}

/* Ensure ~/.TPM/ech/ directory exists */
static int slc_ech_cache_mkdir(void)
{
    char path[512];
    const char *home = getenv("HOME");
    if (home == NULL)
        return -1;

    snprintf(path, sizeof(path), "%s/.TPM", home);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/.TPM/ech", home);
    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* Read cached ECH config. Returns malloc'd base64 string or NULL. */
static char *slc_ech_cache_load(const char *host)
{
    char path[512];
    FILE *fp;
    long sz;
    char *buf;

    if (slc_ech_cache_path(host, path, (int)sizeof(path)) != 0)
        return NULL;

    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;

    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0 || sz > 8192) {
        fclose(fp);
        return NULL;
    }

    buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }

    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        fclose(fp);
        free(buf);
        return NULL;
    }
    fclose(fp);

    buf[sz] = '\0';
    /* Strip trailing whitespace */
    while (sz > 0 && (buf[sz-1] == '\n' || buf[sz-1] == '\r'))
        buf[--sz] = '\0';

    return buf;
}

/* Save ECH config to cache. */
static int slc_ech_cache_save(const char *host, const char *ech_b64)
{
    char path[512];
    FILE *fp;

    if (slc_ech_cache_mkdir() != 0)
        return -1;
    if (slc_ech_cache_path(host, path, (int)sizeof(path)) != 0)
        return -1;

    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;

    fprintf(fp, "%s\n", ech_b64);
    fclose(fp);
    return 0;
}

/* Fetch ECH config from server over plain TLS (no ECH).
 * Sends "GET /ech/configs" and reads the response body.
 * Returns malloc'd base64 string or NULL. */
static char *slc_ech_fetch(slc_ctx_t *ctx, const char *host, int port)
{
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    char request[256];
    char response[8192];
    int fd = -1;
    int ret, n, total;
    char *body;
    WOLFSSL *ssl;

    /* Resolve and connect (plain TCP) */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return NULL;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return NULL;

    /* TLS handshake without ECH */
    ssl = wolfSSL_new(ctx->wctx);
    if (ssl == NULL) { close(fd); return NULL; }
    wolfSSL_set_fd(ssl, fd);

    /* Explicitly disable ECH for this bootstrap connection */
    wolfSSL_SetEchEnable(ssl, 0);

    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        close(fd);
        return NULL;
    }

    /* Send GET /ech/configs */
    snprintf(request, sizeof(request),
        "GET /ech/configs HTTP/1.0\r\nHost: %s\r\n\r\n", host);
    wolfSSL_write(ssl, request, (int)strlen(request));

    /* Read response */
    total = 0;
    while (total < (int)sizeof(response) - 1) {
        n = wolfSSL_read(ssl, response + total,
                         (int)sizeof(response) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    response[total] = '\0';

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(fd);

    /* Find body after \r\n\r\n */
    body = strstr(response, "\r\n\r\n");
    if (body == NULL) return NULL;
    body += 4;

    /* Strip whitespace */
    n = (int)strlen(body);
    while (n > 0 && (body[n-1] == '\n' || body[n-1] == '\r' || body[n-1] == ' '))
        body[--n] = '\0';

    if (n <= 0) return NULL;

    return strdup(body);
}

/* Apply cached or fetched ECH config to the SSL object.
 * Returns 0 on success, -1 if ECH unavailable (non-fatal). */
static int slc_ech_auto(slc_ctx_t *ctx, WOLFSSL *ssl,
                        const char *host, int port)
{
    char *ech_b64;

    /* Try cache first */
    ech_b64 = slc_ech_cache_load(host);
    if (ech_b64 != NULL) {
        if (wolfSSL_SetEchConfigsBase64(ssl, ech_b64,
                (word32)strlen(ech_b64)) == WOLFSSL_SUCCESS) {
            wolfSSL_SetEchEnable(ssl, 1);
            free(ech_b64);
            return 0;
        }
        /* Cached config invalid (possibly rotated) — delete and refetch */
        free(ech_b64);
    }

    /* Fetch from server */
    ech_b64 = slc_ech_fetch(ctx, host, port);
    if (ech_b64 == NULL)
        return -1;

    /* Save to cache */
    slc_ech_cache_save(host, ech_b64);

    /* Apply to this connection */
    if (wolfSSL_SetEchConfigsBase64(ssl, ech_b64,
            (word32)strlen(ech_b64)) == WOLFSSL_SUCCESS) {
        wolfSSL_SetEchEnable(ssl, 1);
        free(ech_b64);
        return 0;
    }

    free(ech_b64);
    return -1;
}

/* Check if the context has no ECH config set (neither via cfg nor set_mtc) */
static int cfg_has_no_ech(slc_ctx_t *ctx)
{
    /* If ECH was configured at context level (via ech_configs_b64 or
     * ech_public_name in slc_cfg_t), wolfSSL_CTX already has it.
     * We only auto-fetch if nothing was configured. */
    byte enabled = 0;
    word32 len = 0;
    /* If GetEchConfigs returns data, ECH was already configured */
    wolfSSL_CTX_GetEchConfigs(ctx->wctx, NULL, &len);
    (void)enabled;
    return (len == 0) ? 1 : 0;
}

#endif /* HAVE_ECH */

/* --- Public API --- */

slc_conn_t *slc_connect(slc_ctx_t *ctx, const char *host, int port)
{
    slc_conn_t *conn;
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    int fd = -1;
    int ret;

    if (ctx == NULL || host == NULL || ctx->role != SLC_CLIENT)
        return NULL;

    /* Resolve hostname */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return NULL;

    /* Try each resolved address */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        return NULL;

    /* Create SSL connection */
    conn = slc_conn_new(ctx, fd);
    if (conn == NULL) {
        close(fd);
        return NULL;
    }

#ifdef HAVE_ECH
    /* Auto-ECH: if no ECH config was set on the context, try to load
     * from ~/.TPM/ech/<host>.conf or fetch from server. ECH failure
     * is non-fatal — we fall through to connect without ECH. */
    if (cfg_has_no_ech(ctx)) {
        slc_ech_auto(ctx, conn->ssl, host, port);
    }
#endif

    /* TLS handshake */
    ret = wolfSSL_connect(conn->ssl);
    if (ret != WOLFSSL_SUCCESS) {
#ifdef HAVE_ECH
        /* ECH handshake failed — may be stale cache. Clear cache and
         * retry without ECH rather than failing the connection. */
        {
            char path[512];
            if (slc_ech_cache_path(host, path, (int)sizeof(path)) == 0)
                unlink(path);
        }
        wolfSSL_SetEchEnable(conn->ssl, 0);
        /* Re-attempt handshake on a fresh socket */
        wolfSSL_free(conn->ssl);
        close(fd);
        free(conn);

        /* Reconnect without ECH */
        fd = -1;
        if (getaddrinfo(host, port_str, &hints, &res) == 0) {
            for (rp = res; rp != NULL; rp = rp->ai_next) {
                fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (fd < 0) continue;
                if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
                close(fd);
                fd = -1;
            }
            freeaddrinfo(res);
        }
        if (fd < 0) return NULL;

        conn = slc_conn_new(ctx, fd);
        if (conn == NULL) { close(fd); return NULL; }

        ret = wolfSSL_connect(conn->ssl);
        if (ret != WOLFSSL_SUCCESS) {
            wolfSSL_free(conn->ssl);
            close(fd);
            free(conn);
            return NULL;
        }
#else
        wolfSSL_free(conn->ssl);
        close(fd);
        free(conn);
        return NULL;
#endif
    }

    return conn;
}

int slc_listen(const char *host, int port)
{
    struct sockaddr_in addr;
    int fd;
    int opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (host != NULL && strcmp(host, "0.0.0.0") != 0) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        if (getaddrinfo(host, NULL, &hints, &res) == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
            addr.sin_addr = sin->sin_addr;
            freeaddrinfo(res);
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

slc_conn_t *slc_accept(slc_ctx_t *ctx, int listen_fd)
{
    slc_conn_t *conn;
    struct sockaddr_in client_addr;
    socklen_t addr_sz = sizeof(client_addr);
    int client_fd;
    int ret;

    if (ctx == NULL || ctx->role != SLC_SERVER)
        return NULL;

    client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_sz);
    if (client_fd < 0)
        return NULL;

    conn = slc_conn_new(ctx, client_fd);
    if (conn == NULL) {
        close(client_fd);
        return NULL;
    }

    /* TLS handshake */
    ret = wolfSSL_accept(conn->ssl);
    if (ret != WOLFSSL_SUCCESS) {
        wolfSSL_free(conn->ssl);
        close(client_fd);
        free(conn);
        return NULL;
    }

    return conn;
}

int slc_read(slc_conn_t *conn, void *buf, int sz)
{
    if (conn == NULL || conn->ssl == NULL)
        return -1;
    return wolfSSL_read(conn->ssl, buf, sz);
}

int slc_recv(slc_conn_t *conn, void *buf, int sz)
{
    return slc_read(conn, buf, sz);
}

int slc_write(slc_conn_t *conn, const void *buf, int sz)
{
    if (conn == NULL || conn->ssl == NULL)
        return -1;
    return wolfSSL_write(conn->ssl, buf, sz);
}

int slc_send(slc_conn_t *conn, const void *buf, int sz)
{
    return slc_write(conn, buf, sz);
}

void slc_close(slc_conn_t *conn)
{
    if (conn == NULL)
        return;

    if (conn->ssl != NULL) {
        wolfSSL_shutdown(conn->ssl);
        wolfSSL_free(conn->ssl);
    }

    if (conn->fd >= 0)
        close(conn->fd);

    free(conn);
}

int slc_get_fd(slc_conn_t *conn)
{
    if (conn == NULL)
        return -1;
    return conn->fd;
}
