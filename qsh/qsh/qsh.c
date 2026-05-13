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
 *   0x05 CMD_REQ     payload: "/get\n<json>" or "/put\n<json>" C -> S
 *   0x06 CMD_RESP    payload: <json> (result or {"error":...}) S -> C
 *
 * See README-specifications.md (one directory up) for the JSON shape.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <pwd.h>
#include <zlib.h>
#include <json-c/json.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include "mqc.h"
#include "mqc_peer.h"
#include "read-config.h"

#define FRAME_OPEN_SHELL  0x01
#define FRAME_DATA        0x02
#define FRAME_RESIZE      0x03
#define FRAME_SHELL_EXIT  0x04
#define FRAME_CMD_REQ     0x05
#define FRAME_CMD_RESP    0x06

/* Printed by --version.  Bumped in lockstep with CHANGELOG.md by
 * /cut-release; the dev branch carries the *next* release's number. */
#define QSH_VERSION       "0.2.3-dev-2"

#define FALLBACK_PORT     1024              /* used only if config is silent */
#define FALLBACK_SERVER   "localhost:8444"
#define BUF_SZ            32768
#define FRAME_SZ          (BUF_SZ + 8)
#define QSH_CMD_MAX       256               /* longest slash-command line */
#define QSH_RAW_MAX       (256 * 1024)      /* max raw payload bytes per /get|/put */

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
/*  Slash-command helpers (/get and /put)                              */
/*  See README-specifications.md for the wire format.                  */
/* ------------------------------------------------------------------ */

static void local_msg(const char *fmt, ...)
{
    /* In raw mode the cursor is wherever the shell left it; emit a fresh
     * CRLF, the message, then another CRLF so it looks like a normal
     * status line above the next prompt. */
    va_list ap;
    fputs("\r\n", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs("\r\n", stderr);
    fflush(stderr);
}

static char *hex_encode(const unsigned char *in, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    char *out = malloc(n * 2 + 1);
    size_t i;
    if (!out) return NULL;
    for (i = 0; i < n; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
    return out;
}

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *in, unsigned char **out, size_t *outlen)
{
    size_t n = strlen(in), i;
    unsigned char *buf;
    if (n & 1) return -1;
    buf = malloc(n / 2 ? n / 2 : 1);
    if (!buf) return -1;
    for (i = 0; i < n; i += 2) {
        int hi = hex_digit(in[i]), lo = hex_digit(in[i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -1; }
        buf[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out    = buf;
    *outlen = n / 2;
    return 0;
}

/* zlib deflate to a freshly-malloc'd buffer. */
static int zlib_deflate_alloc(const unsigned char *in, size_t inlen,
                              unsigned char **out, size_t *outlen)
{
    uLongf bound = compressBound((uLong)inlen);
    unsigned char *buf = malloc(bound);
    if (!buf) return -1;
    if (compress2(buf, &bound, in, (uLong)inlen, Z_DEFAULT_COMPRESSION) != Z_OK) {
        free(buf);
        return -1;
    }
    *out    = buf;
    *outlen = (size_t)bound;
    return 0;
}

/* zlib inflate to a buffer of exactly `expected` bytes. */
static int zlib_inflate_alloc(const unsigned char *in, size_t inlen,
                              size_t expected, unsigned char **out)
{
    uLongf got = (uLongf)expected;
    unsigned char *buf = malloc(expected ? expected : 1);
    if (!buf) return -1;
    if (uncompress(buf, &got, in, (uLong)inlen) != Z_OK || got != expected) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

/* Render mode bits into ls -l form (`-rwxr-xr-x`).  out must be 11 bytes. */
static void mode_to_string(mode_t m, char *out)
{
    if      (S_ISDIR(m))  out[0] = 'd';
    else if (S_ISLNK(m))  out[0] = 'l';
    else if (S_ISCHR(m))  out[0] = 'c';
    else if (S_ISBLK(m))  out[0] = 'b';
    else if (S_ISFIFO(m)) out[0] = 'p';
    else if (S_ISSOCK(m)) out[0] = 's';
    else                  out[0] = '-';
    out[1] = (m & S_IRUSR) ? 'r' : '-';
    out[2] = (m & S_IWUSR) ? 'w' : '-';
    out[3] = (m & S_IXUSR) ? 'x' : '-';
    out[4] = (m & S_IRGRP) ? 'r' : '-';
    out[5] = (m & S_IWGRP) ? 'w' : '-';
    out[6] = (m & S_IXGRP) ? 'x' : '-';
    out[7] = (m & S_IROTH) ? 'r' : '-';
    out[8] = (m & S_IWOTH) ? 'w' : '-';
    out[9] = (m & S_IXOTH) ? 'x' : '-';
    out[10] = '\0';
}

/* Parse the 9 mode bits out of an ls -l style string.  Returns -1 on
 * malformed input.  Only the trailing 9 characters are inspected — the
 * leading file-type character is informational. */
static int mode_from_string(const char *s, mode_t *out)
{
    mode_t m = 0;
    if (!s || strlen(s) < 10) return -1;
    s += 1; /* skip type byte */
    if (s[0] == 'r') m |= S_IRUSR; else if (s[0] != '-') return -1;
    if (s[1] == 'w') m |= S_IWUSR; else if (s[1] != '-') return -1;
    if (s[2] == 'x') m |= S_IXUSR; else if (s[2] != '-') return -1;
    if (s[3] == 'r') m |= S_IRGRP; else if (s[3] != '-') return -1;
    if (s[4] == 'w') m |= S_IWGRP; else if (s[4] != '-') return -1;
    if (s[5] == 'x') m |= S_IXGRP; else if (s[5] != '-') return -1;
    if (s[6] == 'r') m |= S_IROTH; else if (s[6] != '-') return -1;
    if (s[7] == 'w') m |= S_IWOTH; else if (s[7] != '-') return -1;
    if (s[8] == 'x') m |= S_IXOTH; else if (s[8] != '-') return -1;
    *out = m;
    return 0;
}

/* Send an already-built FRAME_CMD_REQ payload (verb-line + JSON). */
static int send_cmd_req(mqc_conn_t *conn, const char *verb, const char *body)
{
    size_t vlen = strlen(verb), blen = strlen(body);
    size_t plen = 1 + vlen + 1 + blen;
    unsigned char *buf;
    int rc;
    if (plen > 1024 * 1024) return -1;
    buf = malloc(plen);
    if (!buf) return -1;
    buf[0] = FRAME_CMD_REQ;
    memcpy(buf + 1, verb, vlen);
    buf[1 + vlen] = '\n';
    memcpy(buf + 1 + vlen + 1, body, blen);
    rc = mqc_write(conn, buf, (int)plen);
    free(buf);
    return rc;
}

/* Block reading MQC frames until a FRAME_CMD_RESP arrives or the
 * connection dies.  FRAME_DATA frames that arrive in the meantime are
 * written to stdout so the terminal stays coherent.  Returns the
 * malloc'd JSON body (caller frees) or NULL on error. */
static char *await_cmd_resp(mqc_conn_t *conn)
{
    uint8_t frame[FRAME_SZ];
    for (;;) {
        int n = mqc_read(conn, frame, sizeof(frame));
        if (n <= 0) return NULL;
        switch (frame[0]) {
            case FRAME_DATA:
                if (n > 1)
                    (void)!write(STDOUT_FILENO, frame + 1, (size_t)(n - 1));
                break;
            case FRAME_CMD_RESP: {
                char *body = malloc((size_t)n);
                if (!body) return NULL;
                memcpy(body, frame + 1, (size_t)(n - 1));
                body[n - 1] = '\0';
                return body;
            }
            case FRAME_SHELL_EXIT:
                local_msg("qsh: shell exited while command in flight");
                return NULL;
            default:
                local_msg("qsh: unexpected frame 0x%02x while awaiting "
                          "command response", frame[0]);
                return NULL;
        }
    }
}

static struct json_object *parse_resp(const char *body)
{
    struct json_tokener *tok = json_tokener_new();
    struct json_object  *obj;
    if (!tok) return NULL;
    obj = json_tokener_parse_ex(tok, body, (int)strlen(body));
    if (!obj || json_tokener_get_error(tok) != json_tokener_success) {
        if (obj) json_object_put(obj);
        json_tokener_free(tok);
        return NULL;
    }
    json_tokener_free(tok);
    return obj;
}

/* /get <remote> <local> — fetch a file from the server. */
static void do_get(mqc_conn_t *conn, const char *remote, const char *local)
{
    struct json_object *req = json_object_new_object();
    const char *body_text;
    char *resp;
    struct json_object *resp_obj, *jerr, *jdata, *jproto, *jbytes, *jcomp;
    unsigned char *hex_bytes = NULL, *raw = NULL;
    size_t hex_len = 0, raw_len = 0;
    int compressed, fd;
    mode_t mode = 0644;
    long byte_count;

    if (!req) { local_msg("/get: out of memory"); return; }
    json_object_object_add(req, "from", json_object_new_string(remote));
    json_object_object_add(req, "compressed", json_object_new_boolean(1));
    body_text = json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN);

    if (send_cmd_req(conn, "/get", body_text) < 0) {
        local_msg("/get: send failed");
        json_object_put(req);
        return;
    }
    json_object_put(req);

    resp = await_cmd_resp(conn);
    if (!resp) { local_msg("/get: no response"); return; }
    resp_obj = parse_resp(resp);
    free(resp);
    if (!resp_obj) { local_msg("/get: malformed response"); return; }

    if (json_object_object_get_ex(resp_obj, "error", &jerr)) {
        local_msg("/get: server: %s", json_object_get_string(jerr));
        goto out;
    }
    if (!json_object_object_get_ex(resp_obj, "data",       &jdata) ||
        !json_object_object_get_ex(resp_obj, "byte_count", &jbytes) ||
        !json_object_object_get_ex(resp_obj, "compressed", &jcomp)) {
        local_msg("/get: response missing required fields");
        goto out;
    }
    compressed = json_object_get_boolean(jcomp);
    byte_count = json_object_get_int64(jbytes);
    if (byte_count < 0 || byte_count > QSH_RAW_MAX) {
        local_msg("/get: byte_count %ld out of range", byte_count);
        goto out;
    }
    if (json_object_object_get_ex(resp_obj, "protection", &jproto)) {
        if (mode_from_string(json_object_get_string(jproto), &mode) != 0)
            mode = 0644;
    }
    if (hex_decode(json_object_get_string(jdata), &hex_bytes, &hex_len) != 0) {
        local_msg("/get: bad hex in response");
        goto out;
    }
    if (compressed) {
        if (zlib_inflate_alloc(hex_bytes, hex_len, (size_t)byte_count, &raw) != 0) {
            local_msg("/get: inflate failed");
            goto out;
        }
        raw_len = (size_t)byte_count;
    } else {
        if (hex_len != (size_t)byte_count) {
            local_msg("/get: length mismatch (hex=%zu byte_count=%ld)",
                      hex_len, byte_count);
            goto out;
        }
        raw = hex_bytes;
        hex_bytes = NULL;
        raw_len = hex_len;
    }

    fd = open(local, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        local_msg("/get: open(%s): %s", local, strerror(errno));
        goto out;
    }
    if ((size_t)write(fd, raw, raw_len) != raw_len) {
        local_msg("/get: write(%s): %s", local, strerror(errno));
        close(fd);
        goto out;
    }
    fchmod(fd, mode);
    close(fd);
    local_msg("/get: wrote %zu byte%s to %s",
              raw_len, raw_len == 1 ? "" : "s", local);

out:
    free(hex_bytes);
    free(raw);
    json_object_put(resp_obj);
}

/* /put <local> <remote> — push a file to the server. */
static void do_put(mqc_conn_t *conn, const char *local, const char *remote)
{
    struct stat st;
    int fd;
    unsigned char *raw = NULL, *compbuf = NULL;
    size_t raw_len = 0, payload_len = 0;
    const unsigned char *payload_bytes;
    char *hex_str = NULL;
    char mode_str[11];
    struct json_object *req = NULL, *resp_obj = NULL, *jerr, *jbytes;
    const char *body_text;
    char *resp = NULL;

    fd = open(local, O_RDONLY);
    if (fd < 0) {
        local_msg("/put: open(%s): %s", local, strerror(errno));
        return;
    }
    if (fstat(fd, &st) != 0) {
        local_msg("/put: stat(%s): %s", local, strerror(errno));
        close(fd);
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        local_msg("/put: %s is not a regular file", local);
        close(fd);
        return;
    }
    if (st.st_size > QSH_RAW_MAX) {
        local_msg("/put: %s is %lld bytes (max %d)",
                  local, (long long)st.st_size, QSH_RAW_MAX);
        close(fd);
        return;
    }
    raw_len = (size_t)st.st_size;
    raw = malloc(raw_len ? raw_len : 1);
    if (!raw) { close(fd); local_msg("/put: out of memory"); return; }
    if (raw_len && (size_t)read(fd, raw, raw_len) != raw_len) {
        local_msg("/put: read(%s): %s", local, strerror(errno));
        close(fd);
        free(raw);
        return;
    }
    close(fd);

    if (zlib_deflate_alloc(raw, raw_len, &compbuf, &payload_len) != 0) {
        local_msg("/put: deflate failed");
        free(raw);
        return;
    }
    payload_bytes = compbuf;

    hex_str = hex_encode(payload_bytes, payload_len);
    if (!hex_str) { local_msg("/put: hex encode failed"); goto out; }

    mode_to_string(st.st_mode, mode_str);

    req = json_object_new_object();
    if (!req) { local_msg("/put: out of memory"); goto out; }
    json_object_object_add(req, "to",         json_object_new_string(remote));
    json_object_object_add(req, "compressed", json_object_new_boolean(1));
    json_object_object_add(req, "protection", json_object_new_string(mode_str));
    json_object_object_add(req, "byte_count", json_object_new_int64((int64_t)raw_len));
    json_object_object_add(req, "data",       json_object_new_string(hex_str));
    body_text = json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN);

    if (send_cmd_req(conn, "/put", body_text) < 0) {
        local_msg("/put: send failed");
        goto out;
    }

    resp = await_cmd_resp(conn);
    if (!resp) { local_msg("/put: no response"); goto out; }
    resp_obj = parse_resp(resp);
    if (!resp_obj) { local_msg("/put: malformed response"); goto out; }

    if (json_object_object_get_ex(resp_obj, "error", &jerr)) {
        local_msg("/put: server: %s", json_object_get_string(jerr));
        goto out;
    }
    if (json_object_object_get_ex(resp_obj, "byte_count", &jbytes)) {
        local_msg("/put: server wrote %ld byte%s to %s",
                  (long)json_object_get_int64(jbytes),
                  json_object_get_int64(jbytes) == 1 ? "" : "s",
                  remote);
    } else {
        local_msg("/put: ok");
    }

out:
    free(raw);
    free(compbuf);
    free(hex_str);
    free(resp);
    if (req)      json_object_put(req);
    if (resp_obj) json_object_put(resp_obj);
}

/* Parse a buffered "/get|/put A B" and dispatch.  Returns 0 if it ran
 * (recognised verb), -1 if not recognised. */
static int dispatch_slash_command(mqc_conn_t *conn, const char *line)
{
    char buf[QSH_CMD_MAX + 1];
    char *verb, *arg1, *arg2, *extra, *save;

    snprintf(buf, sizeof(buf), "%s", line);
    verb = strtok_r(buf, " \t", &save);
    if (!verb) return -1;
    arg1 = strtok_r(NULL, " \t", &save);
    arg2 = strtok_r(NULL, " \t", &save);
    extra = strtok_r(NULL, " \t", &save);

    if (strcmp(verb, "/get") == 0) {
        if (!arg1 || !arg2 || extra) {
            local_msg("/get: usage: /get <remote-from> <local-to>");
            return 0;
        }
        do_get(conn, arg1, arg2);
        return 0;
    }
    if (strcmp(verb, "/put") == 0) {
        if (!arg1 || !arg2 || extra) {
            local_msg("/put: usage: /put <local-from> <remote-to>");
            return 0;
        }
        do_put(conn, arg1, arg2);
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Session                                                            */
/* ------------------------------------------------------------------ */

/* Returns 0 on normal exit (SHELL_EXIT received or stdin EOF),
 *        -1 on connection error (caller may retry). */
/* run_session returns:
 *    0  -- clean exit (SHELL_EXIT from server, or stdin EOF)
 *   -1  -- session ended in failure; *got_any_frame says whether
 *          the server ever spoke (used by the caller to distinguish
 *          ACL-deny / refused from a mid-session disconnect).
 */
static int run_session(mqc_conn_t *conn, int *got_any_frame)
{
    uint8_t frame[FRAME_SZ];
    uint8_t in[BUF_SZ];
    int     mqc_fd = mqc_get_fd(conn);
    uint16_t rows, cols;
    int len;

    /* Slash-command line-buffering state.  See README-specifications.md
     * §5 "Client UX".  We only intercept '/' when it is the first byte
     * of a fresh user line — that is, since the last '\r' or '\n' the
     * user typed locally.  When buffering, keystrokes are NOT forwarded
     * to the remote PTY; Enter dispatches the command, Backspace edits,
     * Ctrl-C cancels. */
    int  at_line_start = 1;
    int  in_cmd_mode   = 0;
    char cmd_buf[QSH_CMD_MAX + 1];
    int  cmd_len = 0;

    *got_any_frame = 0;

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
            *got_any_frame = 1;
            switch (frame[0]) {
                case FRAME_DATA:
                    if (n > 1)
                        (void)!write(STDOUT_FILENO, frame + 1,
                                     (size_t)(n - 1));
                    break;
                case FRAME_SHELL_EXIT:
                    restore_terminal();
                    return 0;
                case FRAME_CMD_RESP:
                    /* Should only arrive while await_cmd_resp() is on
                     * the stack; reaching here means the server sent an
                     * unsolicited response.  Render nothing and move on. */
                    fprintf(stderr, "\r\nqsh: unsolicited CMD_RESP\r\n");
                    break;
                default:
                    fprintf(stderr, "\r\nqsh: unknown frame 0x%02x\r\n",
                            frame[0]);
                    break;
            }
        }

        /* stdin -> MQC (with slash-command interception).  When
         * `in_cmd_mode` is on, bytes accumulate in cmd_buf and are NOT
         * forwarded; Enter dispatches.  When off, bytes pass through
         * via a batched mqc_write — but we still scan them for the
         * "fresh-line + '/'" trigger and for line-end transitions. */
        if (pfds[1].revents & POLLIN) {
            ssize_t r = read(STDIN_FILENO, in, sizeof(in));
            uint8_t pass_buf[BUF_SZ];
            int     pass_len = 0;
            int     ii;

            if (r == 0) { restore_terminal(); return 0; }
            if (r < 0)  { continue; }

            for (ii = 0; ii < r; ii++) {
                unsigned char c = in[ii];

                if (in_cmd_mode) {
                    if (c == '\r' || c == '\n') {
                        cmd_buf[cmd_len] = '\0';
                        /* Newline before dispatch so output sits on a
                         * fresh line.  The shell never saw any of this. */
                        (void)!write(STDOUT_FILENO, "\r\n", 2);
                        if (cmd_len > 0) {
                            if (dispatch_slash_command(conn, cmd_buf) != 0)
                                local_msg("qsh: unknown command '%s' "
                                          "(expected /get or /put)", cmd_buf);
                        }
                        cmd_len = 0;
                        in_cmd_mode = 0;
                        at_line_start = 1;
                    } else if (c == 0x7f || c == 0x08) {
                        if (cmd_len > 0) {
                            cmd_len--;
                            (void)!write(STDOUT_FILENO, "\b \b", 3);
                        }
                    } else if (c == 0x03) {
                        /* Ctrl-C cancels the buffered command. */
                        (void)!write(STDOUT_FILENO, "^C\r\n", 4);
                        cmd_len = 0;
                        in_cmd_mode = 0;
                        at_line_start = 1;
                    } else if (cmd_len < QSH_CMD_MAX) {
                        cmd_buf[cmd_len++] = (char)c;
                        (void)!write(STDOUT_FILENO, &c, 1);
                    } else {
                        (void)!write(STDOUT_FILENO, "\a", 1);
                    }
                    continue;
                }

                if (at_line_start && c == '/') {
                    in_cmd_mode = 1;
                    cmd_buf[0]  = '/';
                    cmd_len     = 1;
                    (void)!write(STDOUT_FILENO, "/", 1);
                    continue;
                }

                pass_buf[pass_len++] = c;
                at_line_start = (c == '\r' || c == '\n') ? 1 : 0;
            }

            if (pass_len > 0) {
                if (send_data(conn, pass_buf, pass_len) < 0) {
                    restore_terminal();
                    return -1;
                }
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
    int port;
    int i, retries;
    char *mtc_url;
    unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];
    mqc_cfg_t cfg;
    mqc_ctx_t *ctx;

    /* --version is handled before any config-file lookups so its
     * output is exactly one line on stdout, even when /etc/postWolf
     * is missing or read_config_long would have logged a "using ..."
     * notice on stderr. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("qsh %s\n", QSH_VERSION);
            return 0;
        }
    }

    port = (int)read_config_long("qsh/qshd-port", FALLBACK_PORT);

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
    else if (tpm_path[0] == '~' && tpm_path[1] == '/') {
        const char *home = getenv("HOME");
        if (!home) home = ".";
        snprintf(tpm_buf, sizeof(tpm_buf), "%s%s", home, tpm_path + 1);
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

        {
            int got_any = 0;
            rc = run_session(conn, &got_any);
            mqc_close(conn);

            if (rc == 0) break;          /* SHELL_EXIT or stdin EOF — done */
            if (!running) break;
            if (!got_any) {
                /* Server hung up before sending a single frame.  Most
                 * likely the qshd ACL refused our cert_index (check
                 * `journalctl -u qshd` on the server).  No point
                 * retrying — the rejection is deterministic. */
                fprintf(stderr,
                        "qsh: server closed connection before responding "
                        "(qshd ACL refused cert_index=%d?)\n",
                        mqc_get_peer_index(conn));
                break;
            }
            /* Session ran for a while then dropped — could be transient.
             * Allow retries via the existing budget. */
            retries = -1;   /* ++ at loop head makes 0 next iter */
        }

        fprintf(stderr, "qsh: connection lost\n");
    }

    mqc_ctx_free(ctx);
    free(mtc_url);
    fprintf(stderr, "qsh: disconnected\n");
    return 0;
}
