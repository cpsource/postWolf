/*
 * qsh — MQC shell client (post-quantum, TCP transport)
 *
 * Connects to qshd via MQC (ML-KEM-768 + ML-DSA-87 + Merkle inclusion +
 * cosignature + revocation check), puts the local terminal in raw mode,
 * and runs an interactive shell session.  Identity is the MTC subject
 * bound to the client's TPM directory — no X.509, no CRL.
 *
 * Usage:  qsh --host=HOST [--port=N] [--tpm-path=PATH] [--user=NAME]
 *             [--mtc-server=URL] [--expected-name=NAME]
 *
 * Frame protocol on the MQC bytestream (mirrors qshd):
 *
 *   0x01 OPEN_SHELL  payload: rows(u16 BE) cols(u16 BE)        C -> S
 *   0x02 DATA        payload: raw shell bytes                  bidirectional
 *   0x03 RESIZE      payload: rows(u16 BE) cols(u16 BE)        C -> S
 *   0x04 SHELL_EXIT  payload: empty                            S -> C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <pwd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include "mqc.h"
#include "mqc_peer.h"
#include "read-config.h"

#define FRAME_OPEN_SHELL  0x01
#define FRAME_DATA        0x02
#define FRAME_RESIZE      0x03
#define FRAME_SHELL_EXIT  0x04

#define FALLBACK_PORT     1024              /* used only if config is silent */
#define FALLBACK_SERVER   "localhost:8444"
#define BUF_SZ            32768
#define FRAME_SZ          (BUF_SZ + 8)

static struct termios orig_termios;
static int raw_mode_set;
static volatile sig_atomic_t got_winch;
static volatile sig_atomic_t running = 1;

static void restore_terminal(void)
{
    if (raw_mode_set) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_mode_set = 0;
    }
}

static void set_raw_mode(void)
{
    struct termios raw;
    if (!isatty(STDIN_FILENO)) return;
    tcgetattr(STDIN_FILENO, &orig_termios);
    raw = orig_termios;
    cfmakeraw(&raw);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_mode_set = 1;
}

static void get_winsize(uint16_t *rows, uint16_t *cols)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    } else {
        *rows = 24;
        *cols = 80;
    }
}

static void sigwinch_handler(int sig) { (void)sig; got_winch = 1; }
static void sig_handler(int sig)      { (void)sig; running = 0; }

static char *resolve_mtc_server(void)
{
    char *cfg = read_config_url("global/url-server");
    if (cfg && *cfg) return cfg;
    if (cfg) free(cfg);
    return strdup(FALLBACK_SERVER);
}

/* Build a winsize-bearing frame in dst: [type][rows BE][cols BE]. */
static int build_winsize_frame(uint8_t *dst, uint8_t type,
                               uint16_t rows, uint16_t cols)
{
    dst[0] = type;
    dst[1] = (uint8_t)(rows >> 8);
    dst[2] = (uint8_t)(rows & 0xff);
    dst[3] = (uint8_t)(cols >> 8);
    dst[4] = (uint8_t)(cols & 0xff);
    return 5;
}

static int send_data(mqc_conn_t *conn, const void *payload, int len)
{
    uint8_t hdr[1 + BUF_SZ];
    if (len <= 0 || len > BUF_SZ) return -1;
    hdr[0] = FRAME_DATA;
    memcpy(hdr + 1, payload, (size_t)len);
    return mqc_write(conn, hdr, 1 + len);
}

/* ------------------------------------------------------------------ */
/*  Session                                                            */
/* ------------------------------------------------------------------ */

/* Returns 0 on normal exit (SHELL_EXIT received or stdin EOF),
 *        -1 on connection error (caller may retry). */
static int run_session(mqc_conn_t *conn)
{
    uint8_t frame[FRAME_SZ];
    uint8_t in[BUF_SZ];
    int     mqc_fd = mqc_get_fd(conn);
    uint16_t rows, cols;
    int len;

    /* OPEN_SHELL */
    get_winsize(&rows, &cols);
    len = build_winsize_frame(frame, FRAME_OPEN_SHELL, rows, cols);
    if (mqc_write(conn, frame, len) < 0) return -1;

    set_raw_mode();

    while (running) {
        struct pollfd pfds[2];
        int rv, n;

        pfds[0].fd = mqc_fd;        pfds[0].events = POLLIN;
        pfds[1].fd = STDIN_FILENO;  pfds[1].events = POLLIN;

        rv = poll(pfds, 2, 1000);
        if (rv < 0) {
            if (errno == EINTR) {
                if (got_winch) {
                    got_winch = 0;
                    get_winsize(&rows, &cols);
                    len = build_winsize_frame(frame, FRAME_RESIZE, rows, cols);
                    if (mqc_write(conn, frame, len) < 0) {
                        restore_terminal();
                        return -1;
                    }
                }
                continue;
            }
            restore_terminal();
            return -1;
        }

        /* MQC -> stdout */
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            n = mqc_read(conn, frame, sizeof(frame));
            if (n <= 0) {
                restore_terminal();
                return -1;
            }
            switch (frame[0]) {
                case FRAME_DATA:
                    if (n > 1)
                        (void)!write(STDOUT_FILENO, frame + 1,
                                     (size_t)(n - 1));
                    break;
                case FRAME_SHELL_EXIT:
                    restore_terminal();
                    return 0;
                default:
                    fprintf(stderr, "\r\nqsh: unknown frame 0x%02x\r\n",
                            frame[0]);
                    break;
            }
        }

        /* stdin -> MQC */
        if (pfds[1].revents & POLLIN) {
            ssize_t r = read(STDIN_FILENO, in, sizeof(in));
            if (r > 0) {
                if (send_data(conn, in, (int)r) < 0) {
                    restore_terminal();
                    return -1;
                }
            } else if (r == 0) {
                restore_terminal();
                return 0;   /* stdin EOF — clean exit */
            }
        }
    }

    restore_terminal();
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --host=HOST [options]\n\n"
        "Options:\n"
        "  --host=HOST              Server hostname or IP\n"
        "  --port=N                 TCP port (default: /etc/postWolf/config\n"
        "                           qsh/qshd-port, else %d)\n"
        "  --tpm-path=PATH          Client's MTC identity dir\n"
        "                           (default: ~/.TPM/default)\n"
        "  --user=NAME              Shortcut: --tpm-path=~/.TPM/NAME\n"
        "  --mtc-server=URL         Override /etc/postWolf/config global/url-server\n"
        "  --expected-name=NAME     Expected server subject (default: --host)\n",
        prog, FALLBACK_PORT);
    exit(1);
}

int main(int argc, char *argv[])
{
    const char *host = NULL;
    const char *tpm_path = NULL;
    const char *mtc_server_override = NULL;
    const char *expected_name = NULL;
    char tpm_buf[512];
    int port = (int)read_config_long("qsh/qshd-port", FALLBACK_PORT);
    int i, retries;
    char *mtc_url;
    unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];
    mqc_cfg_t cfg;
    mqc_ctx_t *ctx;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--host=", 7) == 0)
            host = argv[i] + 7;
        else if (strncmp(argv[i], "--port=", 7) == 0)
            port = atoi(argv[i] + 7);
        else if (strncmp(argv[i], "--tpm-path=", 11) == 0)
            tpm_path = argv[i] + 11;
        else if (strncmp(argv[i], "--user=", 7) == 0) {
            const char *home = getenv("HOME");
            if (!home) home = ".";
            snprintf(tpm_buf, sizeof(tpm_buf),
                     "%s/.TPM/%s", home, argv[i] + 7);
            tpm_path = tpm_buf;
        }
        else if (strncmp(argv[i], "--mtc-server=", 13) == 0)
            mtc_server_override = argv[i] + 13;
        else if (strncmp(argv[i], "--expected-name=", 16) == 0)
            expected_name = argv[i] + 16;
        else
            usage(argv[0]);
    }
    if (!host) usage(argv[0]);

    if (!tpm_path) {
        const char *home = getenv("HOME");
        if (!home) home = ".";
        snprintf(tpm_buf, sizeof(tpm_buf), "%s/.TPM/default", home);
        tpm_path = tpm_buf;
    }

    signal(SIGWINCH, sigwinch_handler);
    signal(SIGINT,   sig_handler);
    signal(SIGTERM,  sig_handler);
    signal(SIGPIPE,  SIG_IGN);
    atexit(restore_terminal);

    mtc_url = mtc_server_override ? strdup(mtc_server_override)
                                  : resolve_mtc_server();
    if (mqc_load_ca_pubkey(mtc_url, ca_pubkey) != 0) {
        fprintf(stderr, "qsh: cannot load CA cosigner pubkey from %s\n",
                mtc_url);
        free(mtc_url);
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.role         = MQC_CLIENT;
    cfg.tpm_path     = tpm_path;
    cfg.mtc_server   = mtc_url;
    cfg.ca_pubkey    = ca_pubkey;
    cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;

    ctx = mqc_ctx_new(&cfg);
    if (!ctx) {
        fprintf(stderr, "qsh: mqc_ctx_new failed (tpm-path=%s)\n", tpm_path);
        free(mtc_url);
        return 1;
    }
    if (expected_name)
        mqc_ctx_set_expected_name(ctx, expected_name);

    for (retries = 0; running; retries++) {
        mqc_conn_t *conn;
        int rc;

        if (retries > 0) {
            restore_terminal();
            fprintf(stderr, "qsh: reconnecting in 2s...\n");
            sleep(2);
            if (!running) break;
        }

        fprintf(stderr, "qsh: connecting to %s:%d via MQC...\n", host, port);
        conn = mqc_connect(ctx, host, port);
        if (!conn) {
            if (retries >= 5) {
                fprintf(stderr, "qsh: giving up after %d attempts\n",
                        retries + 1);
                break;
            }
            continue;
        }

        fprintf(stderr, "qsh: connected — server subject '%s' (peer_index=%d)\n",
                mqc_get_peer_subject(conn) ? mqc_get_peer_subject(conn) : "?",
                mqc_get_peer_index(conn));
        retries = -1;   /* reset; ++ at loop head makes 0 next iter */

        rc = run_session(conn);
        mqc_close(conn);

        if (rc == 0) break;          /* SHELL_EXIT or stdin EOF — done */
        if (!running) break;
        fprintf(stderr, "qsh: connection lost\n");
    }

    mqc_ctx_free(ctx);
    free(mtc_url);
    fprintf(stderr, "qsh: disconnected\n");
    return 0;
}
