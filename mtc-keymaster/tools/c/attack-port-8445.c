/******************************************************************************
 * File:        attack-port-8445.c
 * Purpose:     Adversarial probe for the DH bootstrap / lookup port.
 *
 * Description:
 *   Opens a fresh TCP connection to host:8445 for each "attack", sends
 *   malformed / hostile input, reads whatever the server says back (or
 *   notices the connection close), and prints a one-line verdict per
 *   attempt.  Every well-handled probe should either get a polite
 *   error JSON or a clean connection close; an unexpected hang, long
 *   silence, or protocol-violating response is the interesting signal.
 *
 * Scope of attacks:
 *   - Connection-level: empty connect, immediate close.
 *   - Format-level: random bytes, not-JSON, truncated, unbalanced braces.
 *   - Protocol-level: missing op, unknown op, wrong type, empty op.
 *   - Input validation: path traversal, very long path, null bytes in
 *     path, SQL-like strings, non-ASCII, control characters.
 *   - Size attacks: oversized payload, deeply-nested JSON.
 *   - DH-flow attacks: garbage hex, wrong-length hex, non-hex chars.
 *   - Slow-loris: byte-by-byte write without closing.
 *
 * Usage:
 *   attack-port-8445 [-s|--server HOST] [-p|--port PORT]
 *                    [-d|--delay MS]    [-v|--verbose]
 *                    [-h|--help]
 *
 *   Rate-limiter note: the bootstrap port gates read-op lookups at
 *   RL_READ (60/min) and DH-enrollment at RL_BOOTSTRAP (3/min).  If
 *   you run the full battery twice in quick succession, expect the
 *   server to start refusing us with "rate limited" messages — that's
 *   correct behaviour, not a bug.  Pass --delay 200 to pace.
 *
 * NOT FOR USE AGAINST SERVERS YOU DON'T CONTROL.  This is for testing
 * your own deployment's robustness — the point is to catch crashes,
 * hangs, or protocol-violating responses before an actual adversary
 * does.  Running it against someone else's server is obnoxious at
 * best and illegal at worst.
 *
 * Created:     2026-04-19
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define DEFAULT_HOST    "factsorlie.com"
#define DEFAULT_PORT    8445
#define RECV_TIMEOUT_MS 2000
#define RECV_BUF_SZ     65536

static int         g_verbose = 0;
static int         g_delay_ms = 0;

/* ----------------------------------------------------------------------
 * ANSI colours (auto-off when stdout isn't a TTY)
 * -------------------------------------------------------------------- */
static const char *C_RESET, *C_GREEN, *C_YELLOW, *C_RED, *C_CYAN, *C_DIM;
static void init_colors(void)
{
    if (isatty(fileno(stdout))) {
        C_RESET  = "\033[0m";
        C_GREEN  = "\033[32m";
        C_YELLOW = "\033[33m";
        C_RED    = "\033[31m";
        C_CYAN   = "\033[36m";
        C_DIM    = "\033[2m";
    } else {
        C_RESET = C_GREEN = C_YELLOW = C_RED = C_CYAN = C_DIM = "";
    }
}

/* ----------------------------------------------------------------------
 * Socket helpers
 * -------------------------------------------------------------------- */

static int open_socket(const char *host, int port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[8];
    int fd = -1;
    struct timeval tv;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    tv.tv_sec  =  timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Send all; partial writes swallowed in short-timeout best-effort. */
static int send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = send(fd, p, remaining, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        p += n; remaining -= (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, char *buf, int bufsz)
{
    int total = 0;
    while (total < bufsz - 1) {
        ssize_t n = recv(fd, buf + total, bufsz - 1 - total, 0);
        if (n <= 0) break;
        total += (int)n;
    }
    buf[total] = '\0';
    return total;
}

/* ----------------------------------------------------------------------
 * Reporting
 * -------------------------------------------------------------------- */

static int g_attack_num = 0;
static int g_attacks_passed = 0;  /* server replied cleanly */
static int g_attacks_timeout = 0;
static int g_attacks_crashed = 0; /* connect failed — server AWOL? */

/* Print a short preview of a response: first 80 chars, one-line. */
static void preview(const char *s, int n)
{
    int i;
    int lim = n < 80 ? n : 80;
    printf("%s", C_DIM);
    for (i = 0; i < lim; i++) {
        if (s[i] == '\n' || s[i] == '\r') printf("\\n");
        else if (s[i] < 32 || s[i] > 126) printf("\\x%02x", (unsigned char)s[i]);
        else putchar(s[i]);
    }
    if (n > 80) printf("...");
    printf("%s", C_RESET);
}

static void report(const char *name, int sent, int got, const char *resp,
                   int fd_opened)
{
    g_attack_num++;
    printf("%s[%02d]%s %-30s ", C_CYAN, g_attack_num, C_RESET, name);

    if (!fd_opened) {
        printf("%sCONNECT FAILED%s — server may be down\n", C_RED, C_RESET);
        g_attacks_crashed++;
        return;
    }
    if (got == 0) {
        printf("%sclosed silent%s (sent=%dB)\n", C_YELLOW, C_RESET, sent);
        g_attacks_passed++;
    } else {
        printf("%sreply %dB%s  sent=%dB  ", C_GREEN, got, C_RESET, sent);
        preview(resp, got);
        printf("\n");
        g_attacks_passed++;
    }

    if (g_delay_ms > 0) usleep(g_delay_ms * 1000);
}

/* ----------------------------------------------------------------------
 * Individual attacks
 * -------------------------------------------------------------------- */

static void attack_raw(const char *name, const char *host, int port,
                       const void *payload, size_t len)
{
    int fd = open_socket(host, port, RECV_TIMEOUT_MS);
    char buf[RECV_BUF_SZ];
    int got;
    if (fd < 0) { report(name, 0, 0, NULL, 0); return; }

    if (len > 0) send_all(fd, payload, len);
    /* Signal EOF so the server knows we're done writing. */
    shutdown(fd, SHUT_WR);
    got = recv_all(fd, buf, sizeof(buf));
    close(fd);
    report(name, (int)len, got, buf, 1);
}

static void attack_empty_connect(const char *host, int port)
{
    attack_raw("empty-connect (no data)", host, port, "", 0);
}

static void attack_random_bytes(const char *host, int port)
{
    unsigned char buf[64];
    int i;
    srand((unsigned)time(NULL));
    for (i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)rand();
    attack_raw("random-bytes (64)", host, port, buf, sizeof(buf));
}

static void attack_not_json(const char *host, int port)
{
    const char *p = "this is not json at all, just words";
    attack_raw("not-json", host, port, p, strlen(p));
}

static void attack_truncated_json(const char *host, int port)
{
    const char *p = "{\"op\":";
    attack_raw("truncated-json", host, port, p, strlen(p));
}

static void attack_unbalanced_braces(const char *host, int port)
{
    const char *p = "{{{{{{{{{{";
    attack_raw("unbalanced-braces (open)", host, port, p, strlen(p));
}

static void attack_closing_braces(const char *host, int port)
{
    const char *p = "}}}}}}}}}}";
    attack_raw("unbalanced-braces (close)", host, port, p, strlen(p));
}

static void attack_empty_object(const char *host, int port)
{
    const char *p = "{}";
    attack_raw("empty-object", host, port, p, strlen(p));
}

static void attack_unknown_op(const char *host, int port)
{
    const char *p = "{\"op\":\"destroy_database\"}";
    attack_raw("unknown-op", host, port, p, strlen(p));
}

static void attack_op_wrong_type(const char *host, int port)
{
    const char *p = "{\"op\":42}";
    attack_raw("op-is-integer", host, port, p, strlen(p));
}

static void attack_empty_op(const char *host, int port)
{
    const char *p = "{\"op\":\"\"}";
    attack_raw("empty-op-string", host, port, p, strlen(p));
}

static void attack_path_traversal(const char *host, int port)
{
    const char *p = "{\"op\":\"http_get\",\"path\":\"/../../etc/passwd\"}";
    attack_raw("path-traversal", host, port, p, strlen(p));
}

static void attack_path_sqlish(const char *host, int port)
{
    const char *p = "{\"op\":\"http_get\",\"path\":\"/certificate/1 OR 1=1\"}";
    attack_raw("sqlish-path", host, port, p, strlen(p));
}

static void attack_long_path(const char *host, int port)
{
    char buf[8192];
    int i;
    memcpy(buf, "{\"op\":\"http_get\",\"path\":\"/", 26);
    for (i = 26; i < (int)sizeof(buf) - 5; i++) buf[i] = 'A';
    memcpy(buf + sizeof(buf) - 5, "\"}", 3);
    attack_raw("long-path (~8 KB)", host, port, buf, sizeof(buf) - 2);
}

static void attack_null_in_path(const char *host, int port)
{
    const char payload[] =
        "{\"op\":\"http_get\",\"path\":\"/cert\0ificate/1\"}";
    attack_raw("null-byte-in-path", host, port,
               payload, sizeof(payload) - 1);
}

static void attack_non_ascii(const char *host, int port)
{
    const char *p = "{\"op\":\"http_get\",\"path\":\"/\xe6\x97\xa5\xe6\x9c\xac\xc2\xa0\"}";
    attack_raw("non-ascii-path", host, port, p, strlen(p));
}

static void attack_control_chars(const char *host, int port)
{
    const char *p = "{\"op\":\"http_get\",\"path\":\"/\x07\x08\x0b\x0c\"}";
    attack_raw("control-chars-path", host, port, p, strlen(p));
}

static void attack_deep_nest(const char *host, int port)
{
    char buf[4096];
    int i, depth = 200;
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos,
                    "{\"op\":\"http_get\",\"path\":");
    for (i = 0; i < depth; i++) buf[pos++] = '[';
    buf[pos++] = '1';
    for (i = 0; i < depth; i++) buf[pos++] = ']';
    buf[pos++] = '}';
    attack_raw("deep-json-nest", host, port, buf, pos);
}

static void attack_huge_payload(const char *host, int port)
{
    size_t sz = 256 * 1024;
    char *buf = malloc(sz);
    int pos;
    if (!buf) return;
    pos = snprintf(buf, sz, "{\"op\":\"http_get\",\"path\":\"/");
    memset(buf + pos, 'X', sz - pos - 3);
    memcpy(buf + sz - 3, "\"}", 3);
    attack_raw("huge-payload (256 KB)", host, port, buf, sz - 1);
    free(buf);
}

static void attack_dh_garbage_hex(const char *host, int port)
{
    const char *p = "{\"dh_public_key\":\"this-is-not-hex-at-all!!\"}";
    attack_raw("dh-garbage-hex", host, port, p, strlen(p));
}

static void attack_dh_short_hex(const char *host, int port)
{
    const char *p = "{\"dh_public_key\":\"deadbeef\"}";
    attack_raw("dh-short-hex (8 chars)", host, port, p, strlen(p));
}

static void attack_dh_wrong_type(const char *host, int port)
{
    const char *p = "{\"dh_public_key\":null}";
    attack_raw("dh-null-pubkey", host, port, p, strlen(p));
}

static void attack_slow_loris(const char *host, int port)
{
    const char *p = "{\"op\":\"http_get\",\"path\":\"/log/checkpoint\"}";
    /* 200ms per byte × 42 bytes = 8.4 s total — well past any
     * reasonable server-side wall-clock budget for a single request. */
    int fd = open_socket(host, port, RECV_TIMEOUT_MS);
    size_t i;
    char buf[RECV_BUF_SZ];
    int got;

    if (fd < 0) { report("slow-loris (byte/200ms)", 0, 0, NULL, 0); return; }
    for (i = 0; i < strlen(p); i++) {
        if (send_all(fd, p + i, 1) != 0) break;
        usleep(200 * 1000);
    }
    shutdown(fd, SHUT_WR);
    got = recv_all(fd, buf, sizeof(buf));
    close(fd);
    report("slow-loris (byte/200ms)", (int)strlen(p), got, buf, 1);
}

/* ----------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Adversarial probe for the postWolf DH bootstrap / lookup port.\n"
        "Sends ~22 malformed requests and prints what the server says back.\n"
        "\n"
        "Usage: %s [options]\n"
        "  -s, --server HOST   Target host (default: %s)\n"
        "  -p, --port PORT     Target port (default: %d)\n"
        "  -d, --delay MS      Pause between attacks in ms (default: 0)\n"
        "  -v, --verbose       Extra output\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Use only against servers you control.\n",
        prog, DEFAULT_HOST, DEFAULT_PORT);
}

int main(int argc, char **argv)
{
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    int i;

    for (i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-s") || !strcmp(argv[i], "--server"))
            && i + 1 < argc)   host = argv[++i];
        else if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port"))
            && i + 1 < argc)   port = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-d") || !strcmp(argv[i], "--delay"))
            && i + 1 < argc)   g_delay_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            g_verbose = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    init_colors();

    printf("%sAttacking %s:%d%s  (delay=%dms)\n\n",
           C_CYAN, host, port, C_RESET, g_delay_ms);

    /* Connection-level */
    attack_empty_connect(host, port);

    /* Format-level */
    attack_random_bytes(host, port);
    attack_not_json(host, port);
    attack_truncated_json(host, port);
    attack_unbalanced_braces(host, port);
    attack_closing_braces(host, port);

    /* Protocol-level */
    attack_empty_object(host, port);
    attack_unknown_op(host, port);
    attack_op_wrong_type(host, port);
    attack_empty_op(host, port);

    /* Input validation */
    attack_path_traversal(host, port);
    attack_path_sqlish(host, port);
    attack_long_path(host, port);
    attack_null_in_path(host, port);
    attack_non_ascii(host, port);
    attack_control_chars(host, port);

    /* Size */
    attack_deep_nest(host, port);
    attack_huge_payload(host, port);

    /* DH flow */
    attack_dh_garbage_hex(host, port);
    attack_dh_short_hex(host, port);
    attack_dh_wrong_type(host, port);

    /* Slow-loris */
    attack_slow_loris(host, port);

    printf("\n%sSummary:%s  total=%d  replied/closed-cleanly=%d  "
           "connect-failed=%d  timeouts=%d\n",
           C_CYAN, C_RESET,
           g_attack_num, g_attacks_passed,
           g_attacks_crashed, g_attacks_timeout);

    if (g_attacks_crashed > 0) {
        printf("%sWARNING:%s some connects failed — server may be down "
               "or rate-limiting us.\n", C_RED, C_RESET);
        return 1;
    }
    return 0;
}
