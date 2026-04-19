/******************************************************************************
 * File:        attack-port-8446.c
 * Purpose:     Adversarial probe for the MQC (post-quantum authenticated)
 *              port.
 *
 * Description:
 *   8446 runs MQC — a length-prefixed binary handshake built on
 *   ML-KEM-768 + ML-DSA-87 + AES-256-GCM.  A proper client would need
 *   the full crypto stack; this tool is a dumb attacker who has none of
 *   that and just throws ugly bytes at the port to see what happens.
 *
 *   Nothing here is expected to "succeed" (a well-behaved MQC server
 *   rejects every probe as an invalid handshake and closes the
 *   connection).  What we're looking for:
 *
 *     - Hangs.  Server should bound how long it waits for handshake
 *       data.  If a probe keeps a forked child alive for minutes, that's
 *       a slow-loris / resource-exhaustion vector.
 *     - Unbounded-allocation responses to huge "claimed length" frame
 *       headers.  Server should cap frame sizes at a sane limit.
 *     - Crashes or anomalous replies after malformed input.
 *     - Protocol confusion — TLS ClientHello or HTTP on the wrong port
 *       shouldn't trip any code that tries to interpret them.
 *
 * Attack catalogue (22):
 *   Connection: empty-connect, 2-byte-short-close.
 *   Random / noise: 64B random, 1 KB random, 64 KB random, all-zeroes,
 *                   all-0xff.
 *   Protocol confusion: fake HTTP GET, fake TLS ClientHello,
 *                       JSON-looking first bytes.
 *   Frame-header attacks: size-0, size-1B, size-4GB, truncated header.
 *   Payload attacks: small claimed-size + huge actual body, huge
 *                    claimed-size + tiny actual body.
 *   Handshake-shape: plausible-looking JSON with wrong fields, cert_index
 *                    = -1 / huge / non-numeric.
 *   Timing: slow-loris (one byte / 200 ms), fragmented-write burst.
 *
 * Usage:
 *   attack-port-8446 [-s|--server HOST] [-p|--port PORT]
 *                    [-d|--delay MS]    [-v|--verbose]
 *                    [-h|--help]
 *
 * NOT FOR USE AGAINST SERVERS YOU DON'T CONTROL.
 *
 * Created:     2026-04-19
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#define DEFAULT_HOST    "factsorlie.com"
#define DEFAULT_PORT    8446
#define RECV_TIMEOUT_MS 3000
#define RECV_BUF_SZ     65536

static int g_verbose = 0;
static int g_delay_ms = 0;

/* ----------------------------------------------------------------------
 * ANSI colours
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
static int g_attacks_passed = 0;
static int g_attacks_crashed = 0;
static int g_attacks_hung = 0;

/* MQC replies are binary — show a hex preview of the first N bytes. */
static void hex_preview(const char *s, int n, int max)
{
    int i;
    int lim = n < max ? n : max;
    printf("%s", C_DIM);
    for (i = 0; i < lim; i++) {
        printf("%02x ", (unsigned char)s[i]);
        if ((i + 1) % 16 == 0 && i + 1 < lim) printf(" ");
    }
    if (n > max) printf("...");
    printf("%s", C_RESET);
}

static void report(const char *name, int sent, int got, const char *resp,
                   int fd_opened, double elapsed_sec)
{
    g_attack_num++;
    printf("%s[%02d]%s %-30s ", C_CYAN, g_attack_num, C_RESET, name);

    if (!fd_opened) {
        printf("%sCONNECT FAILED%s\n", C_RED, C_RESET);
        g_attacks_crashed++;
        return;
    }
    if (got == 0) {
        printf("%sclosed silent%s (sent=%dB, %.2fs)\n",
               C_YELLOW, C_RESET, sent, elapsed_sec);
        g_attacks_passed++;
    } else {
        printf("%sreply %dB%s sent=%dB  %.2fs  ",
               C_GREEN, got, C_RESET, sent, elapsed_sec);
        hex_preview(resp, got, 24);
        printf("\n");
        g_attacks_passed++;
    }
    /* Server budget for the handshake is MQC_HANDSHAKE_TOTAL_SEC (5 s
     * by default), so a drop at ~5–6 s is expected behavior from the
     * server deadline enforcer.  Flag only genuinely pathological
     * hangs that exceed that by a margin. */
    if (elapsed_sec > 10.0) {
        g_attacks_hung++;
        printf("    %sNOTE:%s long-hang may indicate slow-loris vector\n",
               C_YELLOW, C_RESET);
    }

    if (g_delay_ms > 0) usleep(g_delay_ms * 1000);
}

/* ----------------------------------------------------------------------
 * Attack primitive: open, send, recv, close, report.
 * -------------------------------------------------------------------- */

static void attack_raw(const char *name, const char *host, int port,
                       const void *payload, size_t len)
{
    int fd = open_socket(host, port, RECV_TIMEOUT_MS);
    char buf[RECV_BUF_SZ];
    int got;
    struct timeval t0, t1;
    double elapsed;

    gettimeofday(&t0, NULL);
    if (fd < 0) { report(name, 0, 0, NULL, 0, 0.0); return; }

    if (len > 0) send_all(fd, payload, len);
    shutdown(fd, SHUT_WR);
    got = recv_all(fd, buf, sizeof(buf));
    close(fd);

    gettimeofday(&t1, NULL);
    elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    report(name, (int)len, got, buf, 1, elapsed);
}

/* ----------------------------------------------------------------------
 * Individual attacks
 * -------------------------------------------------------------------- */

static void a_empty_connect(const char *h, int p)
{
    attack_raw("empty-connect", h, p, "", 0);
}

static void a_short_two(const char *h, int p)
{
    attack_raw("2-byte-short-close", h, p, "\x00\x00", 2);
}

static void a_random64(const char *h, int p)
{
    unsigned char buf[64];
    int i;
    for (i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)rand();
    attack_raw("random-64B", h, p, buf, sizeof(buf));
}

static void a_random1k(const char *h, int p)
{
    unsigned char buf[1024];
    int i;
    for (i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)rand();
    attack_raw("random-1 KB", h, p, buf, sizeof(buf));
}

static void a_random64k(const char *h, int p)
{
    unsigned char *buf = malloc(65536);
    int i;
    if (!buf) return;
    for (i = 0; i < 65536; i++) buf[i] = (unsigned char)rand();
    attack_raw("random-64 KB", h, p, buf, 65536);
    free(buf);
}

static void a_all_zeros(const char *h, int p)
{
    unsigned char buf[256];
    memset(buf, 0, sizeof(buf));
    attack_raw("all-zeros-256B", h, p, buf, sizeof(buf));
}

static void a_all_ffs(const char *h, int p)
{
    unsigned char buf[256];
    memset(buf, 0xff, sizeof(buf));
    attack_raw("all-0xff-256B", h, p, buf, sizeof(buf));
}

static void a_fake_http(const char *h, int p)
{
    const char *s = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    attack_raw("fake-HTTP-GET", h, p, s, strlen(s));
}

static void a_fake_tls(const char *h, int p)
{
    /* Classic TLS 1.2 ClientHello prefix. */
    unsigned char tls[] = {
        0x16, 0x03, 0x01, 0x00, 0xa0,        /* record header: handshake, TLS 1.0, len 160 */
        0x01, 0x00, 0x00, 0x9c,              /* handshake: ClientHello, len 156 */
        0x03, 0x03,                          /* client version: TLS 1.2 */
        /* 32 bytes random */
        0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x00,                                 /* session id len */
    };
    attack_raw("fake-TLS-ClientHello", h, p, tls, sizeof(tls));
}

static void a_fake_json(const char *h, int p)
{
    const char *s = "{\"op\":\"please_enroll_me\",\"i\":\"am\",\"mqc\":false}";
    attack_raw("fake-JSON-shape", h, p, s, strlen(s));
}

/* 4-byte big-endian length prefix with claimed size N, no payload */
static void send_len_only(const char *name, const char *h, int p, uint32_t sz)
{
    unsigned char buf[4];
    buf[0] = (sz >> 24) & 0xff;
    buf[1] = (sz >> 16) & 0xff;
    buf[2] = (sz >>  8) & 0xff;
    buf[3] =  sz        & 0xff;
    attack_raw(name, h, p, buf, 4);
}

static void a_frame_len_zero(const char *h, int p)
{
    send_len_only("frame-len-zero",       h, p, 0x00000000);
}

static void a_frame_len_one(const char *h, int p)
{
    send_len_only("frame-len-1",          h, p, 0x00000001);
}

static void a_frame_len_huge(const char *h, int p)
{
    send_len_only("frame-len-4GB",        h, p, 0xffffffff);
}

static void a_frame_len_trunc(const char *h, int p)
{
    attack_raw("frame-len-truncated-2B", h, p, "\x00\xff", 2);
}

static void a_small_claim_huge_body(const char *h, int p)
{
    /* "I'm sending 16 bytes" then send 8 KB. */
    unsigned char buf[8200];
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x10;  /* 16 */
    memset(buf + 4, 0x41, sizeof(buf) - 4);
    attack_raw("small-claim-huge-body",   h, p, buf, sizeof(buf));
}

static void a_huge_claim_tiny_body(const char *h, int p)
{
    /* "I'm sending 1 MB" then send 16 bytes and close. */
    unsigned char buf[20];
    buf[0] = 0x00; buf[1] = 0x10; buf[2] = 0x00; buf[3] = 0x00;  /* ~1 MB */
    memset(buf + 4, 0x42, sizeof(buf) - 4);
    attack_raw("huge-claim-tiny-body",    h, p, buf, sizeof(buf));
}

static void a_json_wrong_fields(const char *h, int p)
{
    /* Plausible-looking outer frame: 4-byte length prefix + JSON body. */
    const char *body = "{\"hello\":\"mqc\",\"cert_index\":\"not a number\"}";
    size_t blen = strlen(body);
    size_t total = 4 + blen;
    unsigned char *buf = malloc(total);
    if (!buf) return;
    buf[0] = (blen >> 24) & 0xff;
    buf[1] = (blen >> 16) & 0xff;
    buf[2] = (blen >>  8) & 0xff;
    buf[3] =  blen        & 0xff;
    memcpy(buf + 4, body, blen);
    attack_raw("json-wrong-fields",       h, p, buf, total);
    free(buf);
}

static void a_cert_index_neg(const char *h, int p)
{
    const char *body = "{\"cert_index\":-1,\"proto\":\"mqc-v1\"}";
    size_t blen = strlen(body);
    unsigned char buf[256];
    buf[0] = 0; buf[1] = 0; buf[2] = (blen >> 8) & 0xff; buf[3] = blen & 0xff;
    memcpy(buf + 4, body, blen);
    attack_raw("cert_index=-1",           h, p, buf, 4 + blen);
}

static void a_cert_index_huge(const char *h, int p)
{
    const char *body = "{\"cert_index\":999999999,\"proto\":\"mqc-v1\"}";
    size_t blen = strlen(body);
    unsigned char buf[256];
    buf[0] = 0; buf[1] = 0; buf[2] = (blen >> 8) & 0xff; buf[3] = blen & 0xff;
    memcpy(buf + 4, body, blen);
    attack_raw("cert_index=9999..",       h, p, buf, 4 + blen);
}

static void a_slow_loris(const char *host, int port)
{
    const char *p = "{\"cert_index\":1,\"proto\":\"mqc-v1\"}";
    size_t plen = strlen(p);
    unsigned char buf[4 + 48];
    int fd, got;
    size_t i;
    char rbuf[RECV_BUF_SZ];
    struct timeval t0, t1;
    double elapsed;

    buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = (unsigned char)plen;
    memcpy(buf + 4, p, plen);

    gettimeofday(&t0, NULL);
    fd = open_socket(host, port, RECV_TIMEOUT_MS);
    if (fd < 0) { report("slow-loris (byte/200ms)", 0, 0, NULL, 0, 0.0); return; }
    for (i = 0; i < 4 + plen; i++) {
        if (send_all(fd, buf + i, 1) != 0) break;
        usleep(200 * 1000);
    }
    shutdown(fd, SHUT_WR);
    got = recv_all(fd, rbuf, sizeof(rbuf));
    close(fd);
    gettimeofday(&t1, NULL);
    elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    report("slow-loris (byte/200ms)", (int)(4 + plen), got, rbuf, 1, elapsed);
}

static void a_fragment_burst(const char *host, int port)
{
    /* Hundreds of 1-byte writes, no delay, then close.  Stresses any
     * read-coalescing assumption on the server. */
    unsigned char buf[512];
    int fd, got, i;
    char rbuf[RECV_BUF_SZ];
    struct timeval t0, t1;
    double elapsed;

    for (i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)rand();

    gettimeofday(&t0, NULL);
    fd = open_socket(host, port, RECV_TIMEOUT_MS);
    if (fd < 0) { report("fragment-burst (512 x 1B)", 0, 0, NULL, 0, 0.0); return; }
    for (i = 0; i < (int)sizeof(buf); i++) send_all(fd, buf + i, 1);
    shutdown(fd, SHUT_WR);
    got = recv_all(fd, rbuf, sizeof(rbuf));
    close(fd);
    gettimeofday(&t1, NULL);
    elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    report("fragment-burst (512 x 1B)", (int)sizeof(buf), got, rbuf, 1, elapsed);
}

/* =====================================================================
 * Part B — socket-layer shenanigans (raw POSIX socket API, no MQC)
 * =====================================================================
 *
 * These probes poke at the TCP / socket-state machine rather than at
 * MQC-level protocol parsing.  Each opens a fresh socket with whatever
 * knobs the attack name implies, does the stunt, records elapsed time,
 * and reports what came back.  Some have no server-visible payload
 * at all — the interesting thing is whether the server handles the
 * resulting socket state gracefully.
 * --------------------------------------------------------------------- */

/* Generic raw-open helper that lets a caller pre-configure socket options
 * before connect().  Returns the connected fd or -1. */
static int open_socket_pre(const char *host, int port,
                           void (*pre_connect)(int fd))
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
        if (pre_connect) pre_connect(fd);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    tv.tv_sec = RECV_TIMEOUT_MS / 1000;
    tv.tv_usec = (RECV_TIMEOUT_MS % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

static void pre_linger_zero(int fd)
{
    struct linger lg = { 1, 0 };  /* on, timeout 0 → send RST on close */
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
}

static void pre_tiny_sndbuf(int fd)
{
    int n = 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n));
}

static void pre_nodelay(int fd)
{
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

static void pre_no_keepalive(int fd)
{
    int off = 0;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &off, sizeof(off));
}

/* Report one Part-B attack outcome given only elapsed time + bytes
 * read (most don't send enough to elicit a reply). */
static void report_b(const char *name, double elapsed_sec,
                     int got, const char *resp, int outcome_ok)
{
    g_attack_num++;
    printf("%s[%02d]%s %-34s ", C_CYAN, g_attack_num, C_RESET, name);
    if (!outcome_ok) {
        printf("%sSYSCALL FAILED%s (%s)\n", C_RED, C_RESET, strerror(errno));
        g_attacks_crashed++;
        return;
    }
    if (got > 0) {
        printf("%sreply %dB%s  %.2fs  ", C_GREEN, got, C_RESET, elapsed_sec);
        hex_preview(resp, got, 16);
        printf("\n");
    } else {
        printf("%sno reply%s  %.2fs\n", C_YELLOW, C_RESET, elapsed_sec);
    }
    g_attacks_passed++;
    if (elapsed_sec > 10.0) {
        g_attacks_hung++;
        printf("    %sNOTE:%s long-hang may indicate slow-loris vector\n",
               C_YELLOW, C_RESET);
    }
    if (g_delay_ms > 0) usleep(g_delay_ms * 1000);
}

/* --- 1. Half-close SHUT_WR immediately -------------------------------- */
static void b_shutwr_immediate(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("shutwr-immediate", 0, 0, NULL, 0); return; }
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("shutwr-immediate", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 2. Half-close SHUT_RD, then send garbage ------------------------- */
static void b_shutrd_then_send(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    const char *p = "garbage-after-shutrd";
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("shutrd-then-send", 0, 0, NULL, 0); return; }
    shutdown(fd, SHUT_RD);
    send(fd, p, strlen(p), MSG_NOSIGNAL);
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("shutrd-then-send", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 3. RST on close, no data ----------------------------------------- */
static void b_rst_nodata(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, pre_linger_zero);
    if (fd < 0) { report_b("rst-close-nodata", 0, 0, NULL, 0); return; }
    /* No SHUT_WR — just close.  linger=0 → RST. */
    got = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    if (got < 0) got = 0;
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("rst-close-nodata", e, got, rbuf, 1);
}

/* --- 4. Send a few bytes, then RST ------------------------------------ */
static void b_rst_afterbytes(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, pre_linger_zero);
    if (fd < 0) { report_b("rst-after-8B", 0, 0, NULL, 0); return; }
    send(fd, "\x00\x00\x00\x42" "abcd", 8, MSG_NOSIGNAL);
    got = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    if (got < 0) got = 0;
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("rst-after-8B", e, got, rbuf, 1);
}

/* --- 5. Connect, sit silent for 6 s, close ---------------------------- */
static void b_silent_6s(const char *host, int port)
{
    int fd;
    char rbuf[256];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("silent-6s-close", 0, 0, NULL, 0); return; }
    sleep(6);
    got = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    if (got < 0) got = 0;
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("silent-6s-close", e, got, rbuf, 1);
}

/* --- 6. Urgent-data single byte --------------------------------------- */
static void b_oob_single(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("oob-single", 0, 0, NULL, 0); return; }
    send(fd, "!", 1, MSG_OOB | MSG_NOSIGNAL);
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("oob-single", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 7. Urgent-data flood --------------------------------------------- */
static void b_oob_flood(const char *host, int port)
{
    int fd, i;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("oob-flood-20", 0, 0, NULL, 0); return; }
    for (i = 0; i < 20; i++) send(fd, "U", 1, MSG_OOB | MSG_NOSIGNAL);
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("oob-flood-20", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 8. Tiny SO_SNDBUF then blast 64 KB ------------------------------- */
static void b_tinybuf_huge_push(const char *host, int port)
{
    int fd;
    unsigned char *buf = malloc(65536);
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    int i;
    if (!buf) return;
    for (i = 0; i < 65536; i++) buf[i] = (unsigned char)rand();
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, pre_tiny_sndbuf);
    if (fd < 0) { free(buf); report_b("tinybuf-push-64KB", 0, 0, NULL, 0); return; }
    send(fd, buf, 65536, MSG_NOSIGNAL);
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    free(buf);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("tinybuf-push-64KB", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 9. NODELAY + 1-byte sends (many syscalls, tiny packets) ----------- */
static void b_nodelay_byte_spray(const char *host, int port)
{
    int fd, i;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, pre_nodelay);
    if (fd < 0) { report_b("nodelay-byte-spray-64", 0, 0, NULL, 0); return; }
    for (i = 0; i < 64; i++) {
        unsigned char b = (unsigned char)rand();
        send(fd, &b, 1, MSG_NOSIGNAL);
    }
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("nodelay-byte-spray-64", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 10. Two concurrent connections, interleaved writes --------------- */
static void b_parallel_interleaved_2(const char *host, int port)
{
    int fd1, fd2, i;
    char r1[32], r2[32];
    int g1 = 0, g2 = 0;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd1 = open_socket_pre(host, port, NULL);
    fd2 = open_socket_pre(host, port, NULL);
    if (fd1 < 0 || fd2 < 0) {
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        report_b("parallel-interleaved-2", 0, 0, NULL, 0); return;
    }
    for (i = 0; i < 32; i++) {
        char b = 'A' + (i & 31);
        send(fd1, &b, 1, MSG_NOSIGNAL);
        send(fd2, &b, 1, MSG_NOSIGNAL);
    }
    shutdown(fd1, SHUT_WR); shutdown(fd2, SHUT_WR);
    g1 = recv(fd1, r1, sizeof(r1), 0); if (g1 < 0) g1 = 0;
    g2 = recv(fd2, r2, sizeof(r2), 0); if (g2 < 0) g2 = 0;
    close(fd1); close(fd2);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    (void)r2;
    report_b("parallel-interleaved-2", e, g1 + g2, r1, 1);
}

/* --- 11. Open 5, hold 2 s, close all ---------------------------------- */
static void b_parallel_hold5(const char *host, int port)
{
    int fds[5];
    int i, got_total = 0;
    char rbuf[64];
    int ok = 1;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    for (i = 0; i < 5; i++) {
        fds[i] = open_socket_pre(host, port, NULL);
        if (fds[i] < 0) ok = 0;
    }
    if (!ok) {
        for (i = 0; i < 5; i++) if (fds[i] >= 0) close(fds[i]);
        report_b("parallel-hold-5", 0, 0, NULL, 0); return;
    }
    sleep(2);
    for (i = 0; i < 5; i++) {
        int g = recv(fds[i], rbuf, sizeof(rbuf), MSG_DONTWAIT);
        if (g > 0) got_total += g;
        close(fds[i]);
    }
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("parallel-hold-5", e, got_total, rbuf, 1);
}

/* --- 12. 50 connect-close churn --------------------------------------- */
static void b_churn_50(const char *host, int port)
{
    int i, ok_count = 0;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    for (i = 0; i < 50; i++) {
        int fd = open_socket_pre(host, port, NULL);
        if (fd >= 0) { ok_count++; close(fd); }
    }
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    g_attack_num++;
    printf("%s[%02d]%s %-34s %saccepted %d/50%s  %.2fs\n",
           C_CYAN, g_attack_num, C_RESET, "churn-50-connects",
           ok_count == 50 ? C_GREEN : C_YELLOW, ok_count, C_RESET, e);
    g_attacks_passed++;
    if (g_delay_ms > 0) usleep(g_delay_ms * 1000);
}

/* --- 13. Send after SHUT_WR (should EPIPE) ---------------------------- */
static void b_send_after_shutwr(const char *host, int port)
{
    int fd;
    ssize_t n2;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("send-after-shutwr", 0, 0, NULL, 0); return; }
    shutdown(fd, SHUT_WR);
    n2 = send(fd, "z", 1, MSG_NOSIGNAL);   /* expect -1 / EPIPE */
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    (void)n2;
    report_b("send-after-shutwr", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 14. No-keepalive + connect + 1 byte + silent 4s ----------------- */
static void b_nokeepalive_ghost(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, pre_no_keepalive);
    if (fd < 0) { report_b("no-keepalive-ghost", 0, 0, NULL, 0); return; }
    send(fd, "g", 1, MSG_NOSIGNAL);
    sleep(4);
    got = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    if (got < 0) got = 0;
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("no-keepalive-ghost", e, got, rbuf, 1);
}

/* --- 15. 1 MB single write -------------------------------------------- */
static void b_huge_single_write(const char *host, int port)
{
    int fd;
    size_t sz = 1024 * 1024;
    unsigned char *buf = malloc(sz);
    int i;
    ssize_t sent;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    if (!buf) return;
    for (i = 0; i < (int)sz; i++) buf[i] = (unsigned char)rand();
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { free(buf); report_b("huge-single-write-1MB", 0, 0, NULL, 0); return; }
    sent = send(fd, buf, sz, MSG_NOSIGNAL);
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    free(buf);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    (void)sent;
    report_b("huge-single-write-1MB", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 16. SHUT_RDWR, hold, close --------------------------------------- */
static void b_shutrdwr_hold(const char *host, int port)
{
    int fd;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("shutrdwr-hold-2s", 0, 0, NULL, 0); return; }
    shutdown(fd, SHUT_RDWR);
    sleep(2);
    got = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    if (got < 0) got = 0;
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("shutrdwr-hold-2s", e, got, rbuf, 1);
}

/* --- 17. Zero-length send loop --------------------------------------- */
static void b_zero_len_sends(const char *host, int port)
{
    int fd, i;
    char rbuf[64];
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("zero-len-sends-100", 0, 0, NULL, 0); return; }
    for (i = 0; i < 100; i++) send(fd, "", 0, MSG_NOSIGNAL);
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("zero-len-sends-100", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 18. MSG_PEEK bomb ------------------------------------------------ */
static void b_msgpeek_bomb(const char *host, int port)
{
    int fd, i;
    char rbuf[64];
    int peeked = 0;
    int got;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("msgpeek-bomb-100", 0, 0, NULL, 0); return; }
    send(fd, "\x00\x00\x00\x08" "junkjunk", 12, MSG_NOSIGNAL);
    for (i = 0; i < 100; i++) {
        int n = recv(fd, rbuf, sizeof(rbuf), MSG_PEEK | MSG_DONTWAIT);
        if (n > 0) peeked = n;
    }
    shutdown(fd, SHUT_WR);
    got = recv(fd, rbuf, sizeof(rbuf), 0);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    (void)peeked;
    report_b("msgpeek-bomb-100", e, got > 0 ? got : 0, rbuf, 1);
}

/* --- 19. Rapid reconnect on the same source port --------------------- */
static void b_reconnect_rapid_10(const char *host, int port)
{
    int i, ok_count = 0;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    for (i = 0; i < 10; i++) {
        int fd = open_socket_pre(host, port, NULL);
        if (fd < 0) continue;
        ok_count++;
        send(fd, "r", 1, MSG_NOSIGNAL);
        shutdown(fd, SHUT_WR);
        close(fd);
    }
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    g_attack_num++;
    printf("%s[%02d]%s %-34s %saccepted %d/10%s  %.2fs\n",
           C_CYAN, g_attack_num, C_RESET, "reconnect-rapid-10",
           ok_count == 10 ? C_GREEN : C_YELLOW, ok_count, C_RESET, e);
    g_attacks_passed++;
    if (g_delay_ms > 0) usleep(g_delay_ms * 1000);
}

/* --- 20. Non-blocking connect, immediate close (abort pre-handshake) -- */
static void b_nonblock_close(const char *host, int port)
{
    int fd;
    int flags;
    struct timeval t0, t1;
    double e;
    gettimeofday(&t0, NULL);
    fd = open_socket_pre(host, port, NULL);
    if (fd < 0) { report_b("nonblock-close", 0, 0, NULL, 0); return; }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    close(fd);
    gettimeofday(&t1, NULL);
    e = (t1.tv_sec-t0.tv_sec) + (t1.tv_usec-t0.tv_usec)/1e6;
    report_b("nonblock-close", e, 0, NULL, 1);
}

static void run_part_b(const char *host, int port)
{
    printf("\n%s--- Part B: socket-layer shenanigans ---%s\n\n",
           C_CYAN, C_RESET);
    b_shutwr_immediate(host, port);
    b_shutrd_then_send(host, port);
    b_rst_nodata(host, port);
    b_rst_afterbytes(host, port);
    b_silent_6s(host, port);
    b_oob_single(host, port);
    b_oob_flood(host, port);
    b_tinybuf_huge_push(host, port);
    b_nodelay_byte_spray(host, port);
    b_parallel_interleaved_2(host, port);
    b_parallel_hold5(host, port);
    b_churn_50(host, port);
    b_send_after_shutwr(host, port);
    b_nokeepalive_ghost(host, port);
    b_huge_single_write(host, port);
    b_shutrdwr_hold(host, port);
    b_zero_len_sends(host, port);
    b_msgpeek_bomb(host, port);
    b_reconnect_rapid_10(host, port);
    b_nonblock_close(host, port);
}

/* ----------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Adversarial probe for the postWolf MQC port.  Throws ugly\n"
        "bytes at the MQC listener and reports what comes back.\n"
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
    srand((unsigned)time(NULL));

    printf("%sAttacking %s:%d (MQC)%s  (delay=%dms)\n\n",
           C_CYAN, host, port, C_RESET, g_delay_ms);

    a_empty_connect(host, port);
    a_short_two(host, port);
    a_random64(host, port);
    a_random1k(host, port);
    a_random64k(host, port);
    a_all_zeros(host, port);
    a_all_ffs(host, port);
    a_fake_http(host, port);
    a_fake_tls(host, port);
    a_fake_json(host, port);
    a_frame_len_zero(host, port);
    a_frame_len_one(host, port);
    a_frame_len_huge(host, port);
    a_frame_len_trunc(host, port);
    a_small_claim_huge_body(host, port);
    a_huge_claim_tiny_body(host, port);
    a_json_wrong_fields(host, port);
    a_cert_index_neg(host, port);
    a_cert_index_huge(host, port);
    a_slow_loris(host, port);
    a_fragment_burst(host, port);

    run_part_b(host, port);

    printf("\n%sSummary:%s  total=%d  replied/closed=%d  "
           "connect-failed=%d  long-hangs(>10s)=%d\n",
           C_CYAN, C_RESET,
           g_attack_num, g_attacks_passed,
           g_attacks_crashed, g_attacks_hung);

    if (g_attacks_hung > 0) {
        printf("%sWARNING:%s some probes kept the socket open for >10s — "
               "possible slow-loris vector on the MQC side.\n",
               C_YELLOW, C_RESET);
        return 2;
    }
    if (g_attacks_crashed > 0) {
        printf("%sWARNING:%s some connects failed — server may be down "
               "or rate-limiting us.\n", C_RED, C_RESET);
        return 1;
    }
    return 0;
}
