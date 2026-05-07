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
 *   Uses wolfCrypt for crypto, json-c for JSON, and PostgreSQL (Neon) for
 *   persistence with file-based fallback.
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
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/logging.h>

#include "mtc_store.h"
#include "mtc_http.h"
#include "mtc_bootstrap.h"
#include "mqc.h"
#include "mtc_checkendpoint.h"
#include "mtc_log.h"
#include "mtc_ratelimit.h"
#include "../../read-config/read-config.h"

/******************************************************************************
 * Function:    reload_thread
 *
 * Description:
 *   sigwait()-based reload worker (TODO #56 fix).  Runs as a dedicated
 *   pthread inside the parent process; sigwait blocks until SIGHUP is
 *   delivered, then calls mtc_store_reload(store) to refresh the
 *   parent's in-memory tree/cert state from the DB.
 *
 *   The motivating bug: bootstrap children fork off the parent, mutate
 *   the DB on enrollment commit, and exit; the parent's in-memory
 *   MtcStore never sees those mutations until the next service
 *   restart.  Subsequent /certificate/N lookups handled by NEW forked
 *   children inherit the parent's stale state and serve 404 for an
 *   index that's already in the DB.
 *
 *   Bootstrap children raise SIGHUP to getppid() right after a
 *   successful commit; this thread picks it up and resyncs.
 *
 *   Blocks SIGHUP must be set up in the main thread BEFORE listener
 *   threads are created so listeners inherit the block and SIGHUP is
 *   only ever delivered to this thread (via sigwait).
 ******************************************************************************/
static void *reload_thread(void *arg)
{
    MtcStore *store = (MtcStore *)arg;
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGHUP);

    while (1) {
        if (sigwait(&set, &sig) != 0)
            continue;
        if (sig != SIGHUP) continue;

        LOG_INFO("reload: SIGHUP received, refreshing store from DB");
        /* Exclusive lock excludes every listener fork until reload
         * completes.  No timeout — reload is tree-only post-phase-2,
         * sub-second at current scale; listeners briefly stall their
         * accept loops, which is exactly the desired behavior (no
         * fork inherits a transiently-empty store). */
        pthread_rwlock_wrlock(&store->reload_lock);
        if (mtc_store_reload(store) != 0) {
            LOG_WARN("reload: mtc_store_reload failed");
        } else {
            /* In DB mode (TODO #74 phase 2) cert_count is always 0 —
             * certs are no longer mirrored in RAM.  Tree size is the
             * meaningful "size of the log" indicator post-reload. */
            LOG_INFO("reload: store now at %d entries", store->tree.size);
        }
        pthread_rwlock_unlock(&store->reload_lock);
    }
    return NULL;
}

/* Pull port number out of [global] <key> in /etc/postWolf/config.
 * The value is a URL like https://host:8446 — split on the last ':'
 * and atoi the tail.  Returns 0 if the key is missing or the URL has
 * no port. */
static int port_from_config_url(const char *key)
{
    char *url = read_config_url(key);
    if (!url) return 0;
    char *colon = strrchr(url, ':');
    int p = colon ? atoi(colon + 1) : 0;
    free(url);
    return p;
}

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
    printf("  --dh-port PORT   Bootstrap DH port for pre-TLS enrollment (default: disabled)\n");
    printf("  --mqc-port PORT  MQC listener port (default: disabled)\n");
    printf("  --tpm-path PATH  TPM identity path for MQC (e.g., ~/.TPM/factsorlie.com-ca)\n");
    printf("  --mtc-server URL MTC server URL for MQC peer verification\n");
    printf("  --log-level N    Log level: 0=error 1=warn 2=info 3=debug 4=trace (default: 2)\n");
    printf("  --log-file PATH  Log file (default: /var/log/mtc/mtc_server.log)\n");
    printf("  --mqc-time       Emit per-handshake stage timings to stderr (off by default)\n");
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
    int dh_port = 0;
    int mqc_port = 0;
    int port_from_cli = 0;
    int dh_port_from_cli = 0;
    int mqc_port_from_cli = 0;
    const char *tpm_path = NULL;
    const char *mtc_server_url = NULL;
    int log_level = MTC_LOG_INFO;
    const char *log_file = NULL;
    MtcStore store;
    mtc_tls_cfg_t tls_cfg;
    int i;

    /* Parse command-line arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
            port_from_cli = 1;
        }
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
        else if (strcmp(argv[i], "--dh-port") == 0 && i + 1 < argc) {
            dh_port = atoi(argv[++i]);
            dh_port_from_cli = 1;
        }
        else if (strcmp(argv[i], "--mqc-port") == 0 && i + 1 < argc) {
            mqc_port = atoi(argv[++i]);
            mqc_port_from_cli = 1;
        }
        else if (strcmp(argv[i], "--tpm-path") == 0 && i + 1 < argc)
            tpm_path = argv[++i];
        else if (strcmp(argv[i], "--mtc-server") == 0 && i + 1 < argc)
            mtc_server_url = argv[++i];
        else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc)
            log_level = atoi(argv[++i]);
        else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc)
            log_file = argv[++i];
        else if (strcmp(argv[i], "--mqc-time") == 0)
            mqc_set_time_enabled(1);
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        }
    }

    /* 0. Resolve ports: CLI flag wins; otherwise read URL value out of
     *    /etc/postWolf/config and use the trailing :port.
     *      url-local     → --port      (TLS HTTP, default 8444)
     *      url-bootstrap → --dh-port   (DH bootstrap, 8445)
     *      url-server    → --mqc-port  (MQC, 8446)                       */
    if (!port_from_cli) {
        int p = port_from_config_url("global/url-local");
        if (p) port = p;
    }
    if (!dh_port_from_cli) {
        int p = port_from_config_url("global/url-bootstrap");
        if (p) dh_port = p;
    }
    if (!mqc_port_from_cli) {
        int p = port_from_config_url("global/url-server");
        if (p) mqc_port = p;
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

    /* 3a. Reap forked per-connection children + maintain the
     *     active-child counter that mqc-max-children backpressure
     *     reads.  Replaces the prior `signal(SIGCHLD, SIG_IGN)` --
     *     SIG_IGN was kernel-side auto-reap with no visibility, but
     *     we now need a count so the listener can hold off on
     *     accept() during a fork-storm. */
    mtc_install_child_reaper();

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

    /* 7a. SIGHUP-driven store reload (TODO #56 fix).
     *
     * Block SIGHUP in the main thread BEFORE creating any listener
     * threads.  pthread_sigmask is per-thread, but child threads
     * inherit the parent's mask at creation, so blocking SIGHUP here
     * propagates to mtc_bootstrap_start's bootstrap_thread, MQC's
     * listener thread, and HTTP serve in the main thread.
     *
     * Then spawn a dedicated reload thread that sigwait()s on SIGHUP
     * and calls mtc_store_reload to refresh the in-memory store.
     * Bootstrap children raise SIGHUP to getppid() after a successful
     * enrollment commit, which gets delivered to this thread (the
     * only one with SIGHUP unblocked, by virtue of sigwait pulling it
     * off the queue).                                                  */
    {
        sigset_t set;
        pthread_t reload_tid;
        sigemptyset(&set);
        sigaddset(&set, SIGHUP);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
        if (pthread_create(&reload_tid, NULL, reload_thread, &store) != 0) {
            LOG_WARN("reload thread failed to start (errno=%d), "
                     "store will go stale after enrollments", errno);
        } else {
            pthread_detach(reload_tid);
        }
    }

    /* 8. Set up TLS config (NULL if no --tls-cert → plain HTTP mode) */
    memset(&tls_cfg, 0, sizeof(tls_cfg));
    tls_cfg.cert_file       = tls_cert;
    tls_cfg.key_file        = tls_key;
    tls_cfg.ca_file         = tls_ca;
    tls_cfg.ech_public_name = ech_name;

    /* 8a. Start DH bootstrap listener if --dh-port was given */
    if (dh_port > 0) {
        if (mtc_bootstrap_start(host, dh_port, &store) != 0)
            LOG_WARN("bootstrap listener failed to start on port %d", dh_port);
    }

    /* 8b. Start MQC listener if --mqc-port was given */
    if (mqc_port > 0) {
        if (!tpm_path) {
            fprintf(stderr, "--mqc-port requires --tpm-path\n");
            return 1;
        }
        /* Build MTC server URL from host:port if not explicitly given */
        char mtc_url_buf[256];
        const char *mtc_url = mtc_server_url;
        if (!mtc_url) {
            snprintf(mtc_url_buf, sizeof(mtc_url_buf),
                     "https://%s:%d", host, port);
            mtc_url = mtc_url_buf;
        }
        if (mtc_mqc_start(host, mqc_port, &store, tpm_path, mtc_url,
                          store.ca_pub_key, store.ca_pub_key_sz) != 0)
            LOG_WARN("MQC listener failed to start on port %d", mqc_port);
    }

    /* 9. Run HTTP server (blocks indefinitely) — unless the operator
     *    has disabled the local TLS port via /etc/postWolf/config
     *    (`url-local-port-disabled`).  Default: Yes (port 8444 off).
     *
     *    Nothing on this deployment talks to 8444 — every C client
     *    speaks MQC on 8446 and the bootstrap port serves its own
     *    traffic on 8445.  Keeping 8444 off by default removes the
     *    plain-HTTP attack surface that ChatGPT review item #7 was
     *    flagging.  Operators with Python tooling that hits the TLS
     *    API can flip the knob to No.
     *
     *    When disabled, the main thread waits forever — the detached
     *    bootstrap + MQC listener threads continue serving, and
     *    systemd's Restart=on-failure policy still applies. */
    int local_disabled = read_config_bool("global/url-local-port-disabled", 1);
    if (local_disabled) {
        LOG_INFO("local TLS HTTP port (%d) DISABLED via "
                 "url-local-port-disabled (config); bootstrap (8445) "
                 "and MQC (8446) listeners remain active", port);
        for (;;) pause();
    } else {
        mtc_http_serve(host, port, &store, tls_cert ? &tls_cfg : NULL);
    }

    /* Cleanup (unreachable in normal operation) */
    mtc_store_free(&store);
    mtc_ratelimit_close();
    wolfSSL_Cleanup();
    mtc_log_close();
    return 0;
}
