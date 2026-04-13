/******************************************************************************
 * File:        mtc_server.c
 * Purpose:     MTC CA/Log Server entry point (C implementation).
 *
 * Description:
 *   Main entry point for the MTC (Merkle Tree Certificates) CA/Log server.
 *   Parses command-line arguments, initialises subsystems (logging, wolfSSL,
 *   rate limiter, AbuseIPDB, certificate store), and starts the blocking
 *   HTTP(-over-TLS) server.
 *
 *   Equivalent to server/python/server.py but using wolfCrypt for crypto,
 *   json-c for JSON, and file-based storage with optional PostgreSQL (Neon)
 *   persistence.
 *
 *   Build:  make
 *   Usage:  ./mtc_server [options]   (run with -h for full option list)
 *
 * Dependencies:
 *   stdio.h, stdlib.h, string.h, signal.h
 *   wolfssl/options.h, wolfssl/ssl.h
 *   mtc_store.h        (certificate store / Merkle tree)
 *   mtc_http.h         (HTTP server)
 *   mtc_checkendpoint.h (AbuseIPDB)
 *   mtc_log.h          (logging)
 *   mtc_ratelimit.h    (Redis rate limiter)
 *
 * Notes:
 *   - Single-threaded.  The server blocks in mtc_http_serve().
 *   - SIGPIPE is ignored so that closed-connection writes return errors
 *     rather than terminating the process.
 *   - Subsystem init failures (AbuseIPDB, Redis) are non-fatal; only
 *     mtc_store_init failure is fatal.
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/logging.h>

#include "mtc_store.h"
#include "mtc_http.h"
#include "mtc_checkendpoint.h"
#include "mtc_log.h"
#include "mtc_ratelimit.h"

/******************************************************************************
 * Function:    wolfssl_log_bridge
 *
 * Description:
 *   Callback for wolfSSL_SetLoggingCb().  Maps wolfSSL log levels to MTC
 *   log levels and forwards messages into the MTC logging subsystem.
 ******************************************************************************/
static void wolfssl_log_bridge(const int logLevel, const char *const logMessage)
{
    int mtc_level;
    switch (logLevel) {
        case ERROR_LOG: mtc_level = MTC_LOG_ERROR; break;
        case INFO_LOG:  mtc_level = MTC_LOG_DEBUG; break;
        case ENTER_LOG: mtc_level = MTC_LOG_TRACE; break;
        case LEAVE_LOG: mtc_level = MTC_LOG_TRACE; break;
        default:        mtc_level = MTC_LOG_TRACE; break;
    }
    mtc_log(mtc_level, "[wolfSSL] %s", logMessage);
}

/******************************************************************************
 * Function:    usage
 *
 * Description:
 *   Prints the command-line usage/help text to stdout.
 *
 * Input Arguments:
 *   prog  - Program name (argv[0]).
 ******************************************************************************/
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
    printf("  --log-level N    Log level: 0=error 1=warn 2=info 3=debug 4=trace (default: 2)\n");
    printf("  --log-file PATH  Log file (default: /var/log/mtc/mtc_server.log)\n");
    printf("  -h, --help       Show this help\n");
}

/******************************************************************************
 * Function:    main
 *
 * Description:
 *   Server entry point.  Parses command-line arguments and initialises
 *   subsystems in the following order:
 *
 *     1. Logging (mtc_log_init)
 *     2. wolfSSL library (wolfSSL_Init)
 *     3. SIGPIPE suppression
 *     4. Redis rate limiter (non-fatal)
 *     5. DB tokenpath (if --tokenpath)
 *     6. AbuseIPDB module (non-fatal)
 *     7. Certificate store (fatal on failure)
 *     8. TLS configuration (optional)
 *     9. HTTP server (blocks forever)
 *
 *   On shutdown (unreachable in normal operation), cleans up the store,
 *   rate limiter, wolfSSL, and log file.
 *
 * Input Arguments:
 *   argc  - Argument count.
 *   argv  - Argument vector.
 *
 * Returns:
 *   0  on clean exit.
 *   1  if the MTC store failed to initialise.
 ******************************************************************************/
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
    int log_level = MTC_LOG_INFO;
    const char *log_file = NULL;
    MtcStore store;
    mtc_tls_cfg_t tls_cfg;
    int i;

    /* Parse command-line arguments */
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
        else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc)
            log_level = atoi(argv[++i]);
        else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc)
            log_file = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        }
    }

    /* 1. Initialize logging */
    mtc_log_init(log_file, log_level);

    /* 2. Initialize wolfSSL library */
    wolfSSL_Init();

    /* 2a. Bridge wolfSSL debug output into MTC logging */
    wolfSSL_SetLoggingCb(wolfssl_log_bridge);
    if (log_level >= MTC_LOG_DEBUG)
        wolfSSL_Debugging_ON();

    /* 3. Ignore SIGPIPE — closed-connection writes return errors instead
     *    of killing the process */
    signal(SIGPIPE, SIG_IGN);

    /* 4. Initialize Redis-backed rate limiter (non-fatal if unavailable) */
    mtc_ratelimit_init("127.0.0.1", 6379);

    /* 5. Set token path for MERKLE_NEON DB connection string lookup */
    if (tokenpath)
        mtc_db_set_tokenpath(tokenpath);

    /* 6. Initialize AbuseIPDB module (non-fatal if key missing) */
    {
        int rc = mtc_init();
        if (rc == -2)
            printf("[server] AbuseIPDB key not found, IP checking disabled\n");
        else if (rc < 0)
            fprintf(stderr, "[server] AbuseIPDB init failed (%d)\n", rc);
        else
            printf("[server] AbuseIPDB module initialized\n");
    }

    /* 7. Initialize certificate store — fatal on failure */
    if (mtc_store_init(&store, data_dir, ca_name, log_id) != 0) {
        fprintf(stderr, "Failed to initialize MTC store\n");
        return 1;
    }

    /* 8. Set up TLS config (NULL if no --tls-cert → plain HTTP mode) */
    memset(&tls_cfg, 0, sizeof(tls_cfg));
    tls_cfg.cert_file       = tls_cert;
    tls_cfg.key_file        = tls_key;
    tls_cfg.ca_file         = tls_ca;
    tls_cfg.ech_public_name = ech_name;

    /* 9. Run HTTP server (blocks indefinitely) */
    mtc_http_serve(host, port, &store, tls_cert ? &tls_cfg : NULL);

    /* Cleanup (unreachable in normal operation) */
    mtc_store_free(&store);
    mtc_ratelimit_close();
    wolfSSL_Cleanup();
    mtc_log_close();
    return 0;
}
