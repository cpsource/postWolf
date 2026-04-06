/* mtc_server.c — MTC CA/Log Server (C implementation).
 *
 * Equivalent to server/python/server.py but using wolfcrypt for crypto,
 * json-c for JSON, and file-based storage instead of PostgreSQL.
 *
 * Build:
 *   make
 *
 * Usage:
 *   ./mtc_server [--host HOST] [--port PORT] [--data-dir DIR]
 *                [--ca-name NAME] [--log-id ID]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "mtc_store.h"
#include "mtc_http.h"
#include "mtc_checkendpoint.h"

static void usage(const char *prog)
{
    printf("MTC CA/Log Server (C)\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --host HOST      Bind address (default: 0.0.0.0)\n");
    printf("  --port PORT      Bind port (default: 8443)\n");
    printf("  --data-dir DIR   Data storage directory (default: ./mtc-data)\n");
    printf("  --tokenpath FILE .env file to read MERKLE_NEON from\n");
    printf("  --ca-name NAME   CA name (default: MTC-CA-C)\n");
    printf("  --log-id ID      Log identifier (default: 32473.2)\n");
    printf("  --abuse-threshold N  AbuseIPDB score threshold (default: 75)\n");
    printf("  --tls-cert FILE  PEM server certificate (enables TLS)\n");
    printf("  --tls-key FILE   PEM server private key\n");
    printf("  --tls-ca FILE    CA cert for client verification\n");
    printf("  --ech-name NAME  ECH public name (e.g., factsorlie.com)\n");
    printf("  -h               Show this help\n");
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *host = "0.0.0.0";
    int port = 8443;
    const char *data_dir = "./mtc-data";
    const char *tokenpath = NULL;
    const char *ca_name = "MTC-CA-C";
    const char *log_id = "32473.2";
    const char *tls_cert = NULL;
    const char *tls_key = NULL;
    const char *tls_ca = NULL;
    const char *ech_name = NULL;
    MtcStore store;
    mtc_tls_cfg_t tls_cfg;
    int i;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc)
            data_dir = argv[++i];
        else if (strcmp(argv[i], "--tokenpath") == 0 && i + 1 < argc)
            tokenpath = argv[++i];
        else if (strcmp(argv[i], "--ca-name") == 0 && i + 1 < argc)
            ca_name = argv[++i];
        else if (strcmp(argv[i], "--log-id") == 0 && i + 1 < argc)
            log_id = argv[++i];
        else if (strcmp(argv[i], "--abuse-threshold") == 0 && i + 1 < argc)
            mtc_set_abuse_threshold(atoi(argv[++i]));
        else if (strcmp(argv[i], "--tls-cert") == 0 && i + 1 < argc)
            tls_cert = argv[++i];
        else if (strcmp(argv[i], "--tls-key") == 0 && i + 1 < argc)
            tls_key = argv[++i];
        else if (strcmp(argv[i], "--tls-ca") == 0 && i + 1 < argc)
            tls_ca = argv[++i];
        else if (strcmp(argv[i], "--ech-name") == 0 && i + 1 < argc)
            ech_name = argv[++i];
        else if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]); return 0;
        }
    }

    wolfSSL_Init();

    /* Ignore SIGPIPE from closed connections */
    signal(SIGPIPE, SIG_IGN);

    /* Set token path for MERKLE_NEON lookup */
    if (tokenpath)
        mtc_db_set_tokenpath(tokenpath);

    /* Initialize AbuseIPDB module (non-fatal if key missing) */
    {
        int rc = mtc_init();
        if (rc == -2)
            printf("[server] AbuseIPDB key not found, IP checking disabled\n");
        else if (rc < 0)
            fprintf(stderr, "[server] AbuseIPDB init failed (%d)\n", rc);
        else
            printf("[server] AbuseIPDB module initialized\n");
    }

    /* Initialize store */
    if (mtc_store_init(&store, data_dir, ca_name, log_id) != 0) {
        fprintf(stderr, "Failed to initialize MTC store\n");
        return 1;
    }

    /* Set up TLS config (NULL if no --tls-cert given → plain mode) */
    memset(&tls_cfg, 0, sizeof(tls_cfg));
    tls_cfg.cert_file       = tls_cert;
    tls_cfg.key_file        = tls_key;
    tls_cfg.ca_file         = tls_ca;
    tls_cfg.ech_public_name = ech_name;

    /* Run HTTP server (blocks) */
    mtc_http_serve(host, port, &store, tls_cert ? &tls_cfg : NULL);

    mtc_store_free(&store);
    wolfSSL_Cleanup();
    return 0;
}
