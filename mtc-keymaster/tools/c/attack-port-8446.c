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

#include "../../read-config/read-config.h"

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

/* --- Phase 1 wire-format attacks (P1.11) -----------------------------
 *
 * After Phase 1 (commit 6b4c380b6) the MQC server requires every
 * ClientHello to declare version=0,
 * suite="MQC_MLKEM768_MLDSA87_AES256GCM_SHA256", mode="clear", and
 * to use the renamed kem_pub field with exact byte length (1184 B
 * for ML-KEM-768 pub, 4627 B for ML-DSA-87 sig).  Each attack below
 * sends a length-prefixed JSON ClientHello with exactly one field
 * violation and expects the server to reject with an MQC_SECURITY
 * log line and a quick disconnect. */

/* Send a bare JSON ClientHello (no length prefix — read_json_block
 * reads byte-by-byte tracking {} depth). */
static void send_json(const char *name, const char *host, int port,
                      const char *body)
{
    attack_raw(name, host, port, body, strlen(body));
}

static void a_p1_no_version(const char *h, int p)
{
    send_json("p1-no-version", h, p,
        "{\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
}

static void a_p1_wrong_version(const char *h, int p)
{
    send_json("p1-wrong-version", h, p,
        "{\"version\":99,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
}

static void a_p1_wrong_suite(const char *h, int p)
{
    send_json("p1-wrong-suite", h, p,
        "{\"version\":0,\"suite\":\"BANANA\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
}

static void a_p1_wrong_mode(const char *h, int p)
{
    send_json("p1-wrong-mode", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"carrot\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
}

static void a_p1_old_field_names(const char *h, int p)
{
    /* Pre-Phase-1 wire format.  Should fail strict-parse since
     * `version` is missing. */
    send_json("p1-pre-phase1-format", h, p,
        "{\"cert_index\":1,\"mlkem_encaps_key\":\"00\","
        "\"signature\":\"00\"}");
}

static void a_p1_kem_pub_short(const char *h, int p)
{
    /* kem_pub hex is 1 byte instead of 1184. */
    send_json("p1-kem_pub-too-short", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"ab\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
}

static void a_p1_sig_wrong_length(const char *h, int p)
{
    /* signature hex is 2 bytes instead of 4627. */
    send_json("p1-sig-too-short", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"abcd\"}");
}

static void a_p1_trailing_garbage(const char *h, int p)
{
    /* JSON object followed by junk.  read_json_block returns at the
     * matching '}', so trailing garbage after the closing brace is
     * actually never seen by the parser — this attack documents that
     * the wire framing reads only the minimal JSON object.  Server
     * should accept the JSON and then fail strict-parse on the
     * field validations (kem_pub length).  Renamed accordingly. */
    send_json("p1-min-json-then-garbage", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}xxx");
}

/* ----------------------------------------------------------------------
 * P3a — strict JSON parsing (issue #11) negative tests.  Each attack
 * sends a ClientHello variant that should be rejected by the strict
 * parser BEFORE any cryptographic primitive runs.  Pass criterion is
 * the same as the other attacks above: the server replies / closes
 * the connection promptly without hanging.  The `journalctl -u
 * mtc-ca.service` log should show a matching MQC-SECURITY line for
 * each: e.g. `field 'cert_index' appears 2 times`, `field 'kem_pub'
 * invalid hex`, etc.
 * -------------------------------------------------------------------- */

static void a_p3a_duplicate_cert_index(const char *h, int p)
{
    /* json-c silently keeps the LAST value when keys repeat — strict
     * parser MUST reject ANY duplicate of a defined field. */
    send_json("p3a-duplicate-cert_index", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"cert_index\":2,\"signature\":\"00\"}");
}

static void a_p3a_leading_zero(const char *h, int p)
{
    /* Leading zero on a number — JSON spec disallows; strict tokener
     * MUST reject. */
    send_json("p3a-leading-zero", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":01,"
        "\"signature\":\"00\"}");
}

static void a_p3a_trailing_comma(const char *h, int p)
{
    /* Trailing comma after last field — json-c extension; strict
     * MUST reject. */
    send_json("p3a-trailing-comma", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\",}");
}

static void a_p3a_c_comment(const char *h, int p)
{
    /* C-style block comment inside the JSON object — json-c
     * extension that strict mode MUST reject. */
    send_json("p3a-c-comment", h, p,
        "{\"version\":0/*hi*/,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
}

static void a_p3a_int_overflow(const char *h, int p)
{
    /* cert_index that overflows int32.  json_object_get_int silently
     * saturates; strict reader MUST detect via int64 + range check. */
    send_json("p3a-int-overflow", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\","
        "\"cert_index\":99999999999999999,\"signature\":\"00\"}");
}

static void a_p3a_unknown_field(const char *h, int p)
{
    /* Extra top-level field not in the v0 allowlist — strict MUST
     * reject; v0 has no extension registry. */
    send_json("p3a-unknown-field", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\",\"extra\":\"x\"}");
}

static void a_p3a_bad_utf8(const char *h, int p)
{
    /* Lone 0xFF byte inside a string — invalid UTF-8 sequence;
     * JSON_TOKENER_VALIDATE_UTF8 MUST reject. */
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"\xff\xff\",\"kem_pub\":\"00\",\"cert_index\":1,"
        "\"signature\":\"00\"}");
    attack_raw("p3a-bad-utf8", h, p, buf, (size_t)n);
}

/* ----------------------------------------------------------------------
 * P3b — per-IP distinct cert_index throttle (issue #12).  Fires 11
 * ClientHello variants from one IP with distinct cert_index values
 * inside a 60-second window.  With the default mqc-rl-cert-per-min=10
 * the 11th attempt MUST be rejected with `CERT_RATE_LIMITED` in the
 * server log.  Each individual attempt is otherwise wire-valid for
 * the strict parser (correct field set, correct lengths) so the
 * rejection MUST come from the per-cert throttle, not the parser.
 * The signature won't actually verify — that's fine; the throttle
 * runs BEFORE peer_verify, so we observe the throttle behavior even
 * with bogus signature bytes.
 *
 * The test assumes Redis is reachable from the server and that no
 * other client is sharing this IP's cert-rotation budget at the same
 * time.  In CI this is fine.
 * -------------------------------------------------------------------- */
static void a_p3b_cert_rotation(const char *h, int p)
{
    /* 1184 bytes of '0' for kem_pub, 4627 bytes of '0' for signature. */
    static char kem_pub[2 * 1184 + 1];
    static char sig    [2 * 4627 + 1];
    char body[2 * (1184 + 4627) + 512];
    int i, n;

    if (kem_pub[0] == '\0') {
        memset(kem_pub, '0', sizeof(kem_pub) - 1);
        memset(sig,     '0', sizeof(sig)     - 1);
    }

    for (i = 9000; i < 9011; i++) {
        char name[64];
        snprintf(name, sizeof(name), "p3b-cert-rotation-#%d", i - 8999);
        n = snprintf(body, sizeof(body),
            "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
            "\"mode\":\"clear\",\"kem_pub\":\"%s\",\"cert_index\":%d,"
            "\"signature\":\"%s\"}", kem_pub, i, sig);
        if (n < 0 || n >= (int)sizeof(body)) return;
        attack_raw(name, h, p, body, (size_t)n);
    }
}

static void a_p3a_uppercase_hex(const char *h, int p)
{
    /* Right-length kem_pub (2368 hex chars = 1184 B) but with one
     * uppercase pair embedded.  Strict reader MUST reject the
     * uppercase rather than silently normalising — silent
     * normalisation would let an attacker round-trip a re-cased
     * payload past a signer that hashes the raw bytes. */
    char body[6000];
    char kem_pub[2369];
    int i;
    for (i = 0; i < 2368; i++) kem_pub[i] = 'a';   /* all lowercase */
    kem_pub[10] = 'A';                              /* one uppercase */
    kem_pub[2368] = '\0';

    snprintf(body, sizeof(body),
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"%s\",\"cert_index\":1,"
        "\"signature\":\"00\"}", kem_pub);
    send_json("p3a-uppercase-hex", h, p, body);
}

/* ----------------------------------------------------------------------
 * P3c — encrypted-identity-mode (spec §7) wire attacks.  These probe
 * the encrypted-mode handshake bodies in mqc_encrypted.c that landed
 * in Phase 7 commit 2 (`a287aa8d0`).  Server-side dispatch is
 * mqc_accept_auto: peeks the first JSON for `"mode":"encrypted"` and
 * routes to mqc_accept_encrypted_post.
 *
 * What we CAN attack here without crypto knowledge of the server:
 *   - Phase-1 strict-parse rejection (mode shape, field set, hex
 *     length, etc.) -- caught at JSON-parse layer, before any KEM.
 *   - Phase-1 OK + phase-2 garbage -- server processes phase-1
 *     normally (ML-KEM encapsulate against attacker-supplied bytes),
 *     sends its phase-1 reply, then tries to AEAD-open our garbage
 *     phase-2 frame; GCM auth MUST fail.
 *
 * What we CANNOT attack from here:
 *   - Producing valid AEAD-sealed phase-2 frames -- would require
 *     deriving the early-secret schedule from the server's actual
 *     ML-KEM ciphertext, i.e., running ML-KEM-768 in this binary.
 *     Out of scope for the wire-attack pack.
 * -------------------------------------------------------------------- */

/* Phase-1 with mode="encrypted" but NO kem_pub field.  Strict parser
 * at mqc_json_no_duplicates / no_unknown_keys MUST reject. */
static void a_p3c_enc_phase1_no_kem(const char *h, int p)
{
    send_json("p3c-enc-phase1-no-kem", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encrypted\"}");
}

/* Phase-1 with mode="encrypted" AND a clear-mode cert_index field
 * tucked in.  Encrypted phase-1 has 4 fields; cert_index is unknown
 * and MUST be rejected by mqc_json_no_unknown_keys.  Defends against
 * a "best of both modes" smuggling attempt. */
static void a_p3c_enc_phase1_extra_cert_index(const char *h, int p)
{
    send_json("p3c-enc-phase1-extra-cert_index", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encrypted\",\"kem_pub\":\"00\","
        "\"cert_index\":1}");
}

/* Phase-1 with mode="encrypted" AND a clear-mode signature field.
 * Same rejection class as cert_index above. */
static void a_p3c_enc_phase1_extra_signature(const char *h, int p)
{
    send_json("p3c-enc-phase1-extra-signature", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encrypted\",\"kem_pub\":\"00\","
        "\"signature\":\"00\"}");
}

/* Mode-shape mismatch: clear-mode "shape" (4 fields, no signature)
 * with mode literally set to "clear".  Auto-detect routes to
 * mqc_accept_clear_post, which then rejects on missing
 * cert_index / signature.  Confirms the strict-parser rejection
 * fires symmetrically across modes. */
static void a_p3c_enc_clear_shape_with_clear_label(const char *h, int p)
{
    send_json("p3c-enc-clear-shape-with-clear-label", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"clear\",\"kem_pub\":\"00\"}");
}

/* Phase-1 with kem_pub of the wrong length (1 byte instead of
 * 1184).  Hits mqc_json_get_hex_strict's pre-crypto length filter
 * before any ML-KEM call. */
static void a_p3c_enc_phase1_kem_short(const char *h, int p)
{
    send_json("p3c-enc-phase1-kem-too-short", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encrypted\",\"kem_pub\":\"ab\"}");
}

/* Phase-1 with mode literal misspelled as "encryptd".  Auto-detect
 * sees no `"mode":"encrypted"` substring and falls through to
 * clear-mode dispatch; the clear-mode strict parser then rejects
 * because mode != "clear". */
static void a_p3c_enc_phase1_mode_typo(const char *h, int p)
{
    send_json("p3c-enc-phase1-mode-typo", h, p,
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encryptd\",\"kem_pub\":\"00\"}");
}

/* Phase-1 OK (1184-byte kem_pub of zeros, server runs ML-KEM
 * encapsulate against it and replies with its CT_s) followed by 100
 * bytes of garbage as "phase 2".  No length prefix, just bytes -- so
 * the server's mqc_enc_recv reads 4 bytes as the length prefix
 * (which decodes to whatever junk happens to be in the first 4
 * bytes) and then either rejects on length-out-of-range OR reads N
 * more bytes and AEAD-fails.  Either way it's a clean rejection.
 * This exercises the post-phase-1-OK error path in
 * mqc_accept_encrypted_post. */
static void a_p3c_enc_phase1_ok_then_junk(const char *h, int p)
{
    static char kem_pub[2 * 1184 + 1];
    char body[6000];
    int n;
    int fd;
    char rbuf[RECV_BUF_SZ];
    int got;
    struct timeval t0, t1;
    double elapsed;
    unsigned char garbage[100];
    size_t i;

    if (kem_pub[0] == '\0') {
        memset(kem_pub, '0', sizeof(kem_pub) - 1);
    }
    n = snprintf(body, sizeof(body),
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encrypted\",\"kem_pub\":\"%s\"}", kem_pub);
    if (n < 0 || n >= (int)sizeof(body)) return;

    for (i = 0; i < sizeof(garbage); i++) garbage[i] = (unsigned char)rand();

    gettimeofday(&t0, NULL);
    fd = open_socket(h, p, RECV_TIMEOUT_MS);
    if (fd < 0) {
        report("p3c-enc-phase1-ok-then-junk", 0, 0, NULL, 0, 0.0);
        return;
    }
    /* Send phase-1 (server should reply with its own phase-1) */
    send_all(fd, body, (size_t)n);
    /* Read whatever the server sends back (its phase-1 ServerHello,
     * roughly 2400 bytes of JSON) — we don't parse it; we just
     * blindly send garbage as the "phase-2" frame. */
    got = recv_all(fd, rbuf, sizeof(rbuf));
    (void)got;
    /* Now send 100 random bytes as phase 2 */
    send_all(fd, garbage, sizeof(garbage));
    shutdown(fd, SHUT_WR);
    /* Drain any final close-handshake bytes */
    got = recv_all(fd, rbuf, sizeof(rbuf));
    close(fd);
    gettimeofday(&t1, NULL);
    elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
    report("p3c-enc-phase1-ok-then-junk",
           (int)(n + sizeof(garbage)), got, rbuf, 1, elapsed);
}

/* Phase-1 OK + immediate close — server sends its phase-1 reply,
 * then waits for phase-2; the close arrives and the read times
 * out.  Tests the slow-loris deadline on the encrypted path. */
static void a_p3c_enc_phase1_ok_then_close(const char *h, int p)
{
    static char kem_pub[2 * 1184 + 1];
    char body[6000];
    int n;
    if (kem_pub[0] == '\0') {
        memset(kem_pub, '0', sizeof(kem_pub) - 1);
    }
    n = snprintf(body, sizeof(body),
        "{\"version\":0,\"suite\":\"MQC_MLKEM768_MLDSA87_AES256GCM_SHA256\","
        "\"mode\":\"encrypted\",\"kem_pub\":\"%s\"}", kem_pub);
    if (n > 0 && n < (int)sizeof(body))
        attack_raw("p3c-enc-phase1-ok-then-close", h, p, body, (size_t)n);
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
    int host_from_cli = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-s") || !strcmp(argv[i], "--server"))
            && i + 1 < argc) { host = argv[++i]; host_from_cli = 1; }
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

    /* CLI -s wins; otherwise [global] url-server in /etc/postWolf/config.
     * Port is fixed by the binary identity; only the host is overridden. */
    if (!host_from_cli) {
        char *cfg = read_config_url("global/url-server");
        if (cfg) {
            char *colon = strrchr(cfg, ':');
            if (colon) *colon = '\0';
            host = cfg;
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
    /* Phase 1 wire-format attacks (P1.11) */
    a_p1_no_version(host, port);
    a_p1_wrong_version(host, port);
    a_p1_wrong_suite(host, port);
    a_p1_wrong_mode(host, port);
    a_p1_old_field_names(host, port);
    a_p1_kem_pub_short(host, port);
    a_p1_sig_wrong_length(host, port);
    a_p1_trailing_garbage(host, port);
    /* Phase 3a strict-parsing attacks (P3a.6, issue #11) */
    a_p3a_duplicate_cert_index(host, port);
    a_p3a_leading_zero(host, port);
    a_p3a_trailing_comma(host, port);
    a_p3a_c_comment(host, port);
    a_p3a_int_overflow(host, port);
    a_p3a_unknown_field(host, port);
    a_p3a_bad_utf8(host, port);
    a_p3a_uppercase_hex(host, port);
    /* Phase 3b per-cert throttle (P3b.7, issue #12) */
    a_p3b_cert_rotation(host, port);
    /* Phase 7 / P3c encrypted-mode wire attacks */
    a_p3c_enc_phase1_no_kem(host, port);
    a_p3c_enc_phase1_extra_cert_index(host, port);
    a_p3c_enc_phase1_extra_signature(host, port);
    a_p3c_enc_clear_shape_with_clear_label(host, port);
    a_p3c_enc_phase1_kem_short(host, port);
    a_p3c_enc_phase1_mode_typo(host, port);
    a_p3c_enc_phase1_ok_then_junk(host, port);
    a_p3c_enc_phase1_ok_then_close(host, port);
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
