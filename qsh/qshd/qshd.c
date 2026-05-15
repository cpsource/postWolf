/*
 * qshd — MQC shell daemon (post-quantum, TCP transport)
 *
 * Listens on TCP for MQC connections.  After a successful MQC handshake
 * (ML-KEM-768 + ML-DSA-87 + Merkle inclusion proof + cosignature), the
 * client's identity is its verified MTC subject (cert_index N, e.g.
 * "factsorlie.com-Alice").  The server forkpty()s a shell for the
 * session — same UX as the QUIC original.
 *
 * Usage:  qshd [--port=N] [--tpm-path=PATH] [--user=NAME] [--mtc-server=URL]
 *
 * Frame protocol on the MQC bytestream (MQC preserves message boundaries,
 * so every mqc_write is delivered as one mqc_read with the same length):
 *
 *   byte 0   type
 *   bytes 1+ payload (type-specific)
 *
 *   0x01 OPEN_SHELL  payload: rows(u16 BE) cols(u16 BE)        C -> S, first frame
 *   0x02 DATA        payload: raw shell bytes                  bidirectional
 *   0x03 RESIZE      payload: rows(u16 BE) cols(u16 BE)        C -> S
 *   0x04 SHELL_EXIT  payload: empty                            S -> C, last frame
 *   0x05 CMD_REQ     payload: "/get\n<json>" or "/put\n<json>" C -> S
 *   0x06 CMD_RESP    payload: <json> (result or {"error":...}) S -> C
 *
 * See ../README-specifications.md for the JSON shape and limits.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <pty.h>
#include <pwd.h>
#include <grp.h>
#include <termios.h>
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

#define FALLBACK_PORT     1024              /* used only if config is silent */
#define FALLBACK_SERVER   "localhost:8444"
#define BUF_SZ            32768
#define FRAME_SZ          (BUF_SZ + 8)
#define ACL_PATH          "/etc/qsh/qshd/config"
#define QSHD_RAW_MAX      (256 * 1024)      /* matches qsh client */

static const char *run_user = NULL;
static volatile sig_atomic_t running = 1;

/* ------------------------------------------------------------------ */
/*  Cert-index ACL                                                     */
/*  Rules read from /etc/qsh/qshd/config, one per line:                */
/*    allow N        allow N-M       — permit a cert_index (or range)  */
/*    deny  N        deny  N-M       — refuse a cert_index (or range)  */
/*    default allow                  — flip fall-through to allow      */
/*    default deny                   — explicit (this is the default)  */
/*  First match wins.  If no rule matches, the default policy applies. */
/*  File missing → DENY everyone (fail-closed; operator must opt in).  */
/* ------------------------------------------------------------------ */

typedef struct acl_rule {
    int               allow;        /* 1 = allow, 0 = deny */
    int               low;          /* inclusive */
    int               high;         /* inclusive */
    struct acl_rule  *next;
} acl_rule_t;

static acl_rule_t *acl_head          = NULL;
static int         acl_default_allow = 0;   /* 1 if `default allow` appeared */

static int parse_range(const char *s, int *low, int *high)
{
    char *end;
    long  l, h;

    errno = 0;
    l = strtol(s, &end, 10);
    if (errno || end == s || l < 0) return -1;
    if (*end == '\0') {
        *low = *high = (int)l;
        return 0;
    }
    if (*end != '-') return -1;
    s = end + 1;
    errno = 0;
    h = strtol(s, &end, 10);
    if (errno || end == s || *end != '\0' || h < l) return -1;
    *low  = (int)l;
    *high = (int)h;
    return 0;
}

static int load_acl(void)
{
    FILE        *f;
    char         line[256];
    int          lineno = 0;
    acl_rule_t **tail   = &acl_head;
    int          n      = 0;

    f = fopen(ACL_PATH, "r");
    if (!f) {
        fprintf(stderr,
                "[qshd] cannot open %s: %s — fall-through DENIES every connection\n",
                ACL_PATH, strerror(errno));
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = line, *nl, *verb, *arg, *extra;
        int   allow_rule, low, high;

        lineno++;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;
        if ((nl = strchr(p, '\n'))) *nl = '\0';

        verb  = strtok(p, " \t");
        arg   = strtok(NULL, " \t");
        extra = strtok(NULL, " \t");
        if (!verb || !arg || extra) {
            fprintf(stderr, "[qshd] %s:%d: malformed line\n",
                    ACL_PATH, lineno);
            fclose(f);
            return -1;
        }

        if (strcmp(verb, "default") == 0) {
            if (strcmp(arg, "allow") == 0)      acl_default_allow = 1;
            else if (strcmp(arg, "deny") == 0)  acl_default_allow = 0;
            else {
                fprintf(stderr, "[qshd] %s:%d: bad default '%s' "
                        "(expected allow|deny)\n", ACL_PATH, lineno, arg);
                fclose(f);
                return -1;
            }
            continue;       /* not a range rule — keep parsing */
        }

        if (strcmp(verb, "allow") == 0)      allow_rule = 1;
        else if (strcmp(verb, "deny") == 0)  allow_rule = 0;
        else {
            fprintf(stderr, "[qshd] %s:%d: unknown verb '%s' "
                    "(expected allow|deny|default)\n",
                    ACL_PATH, lineno, verb);
            fclose(f);
            return -1;
        }

        if (parse_range(arg, &low, &high) != 0) {
            fprintf(stderr, "[qshd] %s:%d: bad index/range '%s'\n",
                    ACL_PATH, lineno, arg);
            fclose(f);
            return -1;
        }

        {
            acl_rule_t *r = calloc(1, sizeof(*r));
            if (!r) { fclose(f); return -1; }
            r->allow = allow_rule;
            r->low   = low;
            r->high  = high;
            *tail = r;
            tail  = &r->next;
            n++;
        }
    }
    fclose(f);

    fprintf(stderr, "[qshd] loaded %d ACL rule(s) from %s "
            "(fall-through: %s)\n",
            n, ACL_PATH, acl_default_allow ? "allow" : "deny");
    return 0;
}

static void free_acl(void)
{
    acl_rule_t *r = acl_head, *nx;
    while (r) { nx = r->next; free(r); r = nx; }
    acl_head = NULL;
}

/* Returns 1 if cert_index may connect, 0 otherwise. */
static int acl_check(int idx)
{
    const acl_rule_t *r;
    for (r = acl_head; r; r = r->next)
        if (idx >= r->low && idx <= r->high)
            return r->allow;
    return acl_default_allow;       /* fall-through */
}

static void sig_handler(int sig) { (void)sig; running = 0; }
static void sigchld_handler(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

/* Resolve the MTC-server URL: /etc/postWolf/config global/url-server,
 * else FALLBACK_SERVER.  Caller frees. */
static char *resolve_mtc_server(void)
{
    char *cfg = read_config_url("global/url-server");
    if (cfg && *cfg) return cfg;
    if (cfg) free(cfg);
    return strdup(FALLBACK_SERVER);
}

/* Map an MTC subject like "factsorlie.com-Alice" to its label "Alice".
 * If the subject is a bare leaf ("factsorlie.com") or a CA
 * ("factsorlie.com-ca"), the function returns the empty string — the
 * caller falls back to the unix account selected by --user. */
static void subject_to_label(const char *subject, char *out, size_t outsz)
{
    const char *dash;

    out[0] = '\0';
    if (!subject || !*subject) return;

    dash = strchr(subject, '-');
    if (!dash || !dash[1]) return;
    if (strcmp(dash + 1, "ca") == 0) return;

    snprintf(out, outsz, "%s", dash + 1);
}

/* ------------------------------------------------------------------ */
/*  Slash-command handlers (/get and /put)                             */
/*  See ../README-specifications.md for the wire format.               */
/* ------------------------------------------------------------------ */

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

static int mode_from_string(const char *s, mode_t *out)
{
    mode_t m = 0;
    if (!s || strlen(s) < 10) return -1;
    s += 1;
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

/* Build and send a FRAME_CMD_RESP carrying a single JSON object.
 * Takes ownership of `obj` and frees it (json_object_put). */
static int send_cmd_resp(mqc_conn_t *conn, struct json_object *obj)
{
    const char    *body = json_object_to_json_string_ext(obj,
                              JSON_C_TO_STRING_PLAIN);
    size_t         blen = strlen(body);
    size_t         plen = 1 + blen;
    unsigned char *buf;
    int            rc;
    if (plen > 1024 * 1024) { json_object_put(obj); return -1; }
    buf = malloc(plen);
    if (!buf) { json_object_put(obj); return -1; }
    buf[0] = FRAME_CMD_RESP;
    memcpy(buf + 1, body, blen);
    rc = mqc_write(conn, buf, (int)plen);
    free(buf);
    json_object_put(obj);
    return rc;
}

static struct json_object *err_obj(const char *fmt, ...)
{
    struct json_object *o = json_object_new_object();
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    json_object_object_add(o, "error", json_object_new_string(buf));
    return o;
}

/* Handle a /get request body.  Returns a freshly-built response object
 * (success or error); caller hands it to send_cmd_resp(). */
static struct json_object *handle_get(const char *body, const char *peer)
{
    struct json_tokener *tok = json_tokener_new();
    struct json_object  *req, *jfrom, *jcomp;
    const char *from;
    int compressed_req;
    struct stat st;
    int fd;
    unsigned char *raw = NULL, *payload = NULL;
    size_t raw_len, payload_len;
    char  *hex_str = NULL;
    char   mode_str[11];
    struct json_object *resp;

    if (!tok) return err_obj("oom");
    req = json_tokener_parse_ex(tok, body, (int)strlen(body));
    if (!req || json_tokener_get_error(tok) != json_tokener_success) {
        if (req) json_object_put(req);
        json_tokener_free(tok);
        return err_obj("malformed JSON");
    }
    json_tokener_free(tok);

    if (!json_object_object_get_ex(req, "from", &jfrom) ||
        !json_object_is_type(jfrom, json_type_string)) {
        json_object_put(req);
        return err_obj("missing 'from'");
    }
    from = json_object_get_string(jfrom);
    if (from && from[0] == '~') {
        json_object_put(req);
        return err_obj("'~' is not expanded — use an absolute path");
    }
    compressed_req = 1;
    if (json_object_object_get_ex(req, "compressed", &jcomp))
        compressed_req = json_object_get_boolean(jcomp);

    fprintf(stderr, "[qshd:%d] /get from='%s' for '%s'\n",
            (int)getpid(), from, peer ? peer : "?");

    fd = open(from, O_RDONLY);
    if (fd < 0) {
        resp = err_obj("open: %s", strerror(errno));
        json_object_put(req);
        return resp;
    }
    if (fstat(fd, &st) != 0) {
        resp = err_obj("stat: %s", strerror(errno));
        close(fd); json_object_put(req); return resp;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd); json_object_put(req);
        return err_obj("not a regular file");
    }
    if (st.st_size > QSHD_RAW_MAX) {
        close(fd); json_object_put(req);
        return err_obj("file too large (%lld > %d)",
                       (long long)st.st_size, QSHD_RAW_MAX);
    }
    raw_len = (size_t)st.st_size;
    raw = malloc(raw_len ? raw_len : 1);
    if (!raw) { close(fd); json_object_put(req); return err_obj("oom"); }
    if (raw_len && (size_t)read(fd, raw, raw_len) != raw_len) {
        resp = err_obj("read: %s", strerror(errno));
        close(fd); free(raw); json_object_put(req); return resp;
    }
    close(fd);

    if (compressed_req) {
        if (zlib_deflate_alloc(raw, raw_len, &payload, &payload_len) != 0) {
            free(raw); json_object_put(req);
            return err_obj("deflate failed");
        }
        free(raw);
        raw = NULL;
    } else {
        payload     = raw;
        payload_len = raw_len;
        raw         = NULL;
    }
    hex_str = hex_encode(payload, payload_len);
    free(payload);
    if (!hex_str) { json_object_put(req); return err_obj("hex encode failed"); }

    mode_to_string(st.st_mode, mode_str);

    resp = json_object_new_object();
    json_object_object_add(resp, "from",       json_object_new_string(from));
    json_object_object_add(resp, "compressed", json_object_new_boolean(compressed_req));
    json_object_object_add(resp, "protection", json_object_new_string(mode_str));
    json_object_object_add(resp, "byte_count", json_object_new_int64((int64_t)raw_len));
    json_object_object_add(resp, "data",       json_object_new_string(hex_str));

    free(hex_str);
    json_object_put(req);
    return resp;
}

/* Handle a /put request body. */
static struct json_object *handle_put(const char *body, const char *peer)
{
    struct json_tokener *tok = json_tokener_new();
    struct json_object  *req, *jto, *jcomp, *jproto, *jbytes, *jdata;
    const char *to;
    int compressed_req;
    long byte_count;
    mode_t mode = 0644;
    unsigned char *hex_bytes = NULL, *raw = NULL;
    size_t hex_len = 0, raw_len = 0;
    int fd;
    struct json_object *resp;

    if (!tok) return err_obj("oom");
    req = json_tokener_parse_ex(tok, body, (int)strlen(body));
    if (!req || json_tokener_get_error(tok) != json_tokener_success) {
        if (req) json_object_put(req);
        json_tokener_free(tok);
        return err_obj("malformed JSON");
    }
    json_tokener_free(tok);

    if (!json_object_object_get_ex(req, "to",         &jto)    ||
        !json_object_object_get_ex(req, "byte_count", &jbytes) ||
        !json_object_object_get_ex(req, "data",       &jdata)  ||
        !json_object_is_type(jto,    json_type_string) ||
        !json_object_is_type(jdata,  json_type_string)) {
        json_object_put(req);
        return err_obj("missing/wrong-typed required field(s)");
    }
    to             = json_object_get_string(jto);
    if (to && to[0] == '~') {
        json_object_put(req);
        return err_obj("'~' is not expanded — use an absolute path");
    }
    byte_count     = (long)json_object_get_int64(jbytes);
    compressed_req = 1;
    if (json_object_object_get_ex(req, "compressed", &jcomp))
        compressed_req = json_object_get_boolean(jcomp);
    if (byte_count < 0 || byte_count > QSHD_RAW_MAX) {
        json_object_put(req);
        return err_obj("byte_count %ld out of range", byte_count);
    }
    if (json_object_object_get_ex(req, "protection", &jproto)) {
        if (mode_from_string(json_object_get_string(jproto), &mode) != 0) {
            json_object_put(req);
            return err_obj("bad protection string");
        }
    }

    fprintf(stderr, "[qshd:%d] /put to='%s' byte_count=%ld for '%s'\n",
            (int)getpid(), to, byte_count, peer ? peer : "?");

    if (hex_decode(json_object_get_string(jdata),
                   &hex_bytes, &hex_len) != 0) {
        json_object_put(req);
        return err_obj("bad hex in 'data'");
    }
    if (compressed_req) {
        if (zlib_inflate_alloc(hex_bytes, hex_len,
                               (size_t)byte_count, &raw) != 0) {
            free(hex_bytes);
            json_object_put(req);
            return err_obj("inflate failed");
        }
        raw_len = (size_t)byte_count;
    } else {
        if (hex_len != (size_t)byte_count) {
            free(hex_bytes);
            json_object_put(req);
            return err_obj("hex length != byte_count");
        }
        raw     = hex_bytes;
        hex_bytes = NULL;
        raw_len = hex_len;
    }
    free(hex_bytes);

    fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        resp = err_obj("open: %s", strerror(errno));
        free(raw); json_object_put(req); return resp;
    }
    if (raw_len && (size_t)write(fd, raw, raw_len) != raw_len) {
        resp = err_obj("write: %s", strerror(errno));
        close(fd); unlink(to);
        free(raw); json_object_put(req); return resp;
    }
    fchmod(fd, mode);
    close(fd);
    free(raw);

    resp = json_object_new_object();
    json_object_object_add(resp, "to",         json_object_new_string(to));
    json_object_object_add(resp, "byte_count", json_object_new_int64((int64_t)raw_len));
    json_object_put(req);
    return resp;
}

/* Top-level dispatcher: parse the verb line (everything before the
 * first '\n') and route to /get or /put.  Always sends one response
 * frame, even on error, so the client's await loop terminates. */
static int handle_cmd_frame(mqc_conn_t *conn,
                            const unsigned char *payload, int payload_len,
                            const char *peer)
{
    const char *p   = (const char *)payload;
    const char *nl  = memchr(payload, '\n', (size_t)payload_len);
    const char *body;
    char        verb[16];
    size_t      vlen, blen;
    struct json_object *resp;

    if (!nl) return send_cmd_resp(conn, err_obj("missing verb line"));
    vlen = (size_t)(nl - p);
    if (vlen >= sizeof(verb))
        return send_cmd_resp(conn, err_obj("verb too long"));
    memcpy(verb, p, vlen);
    verb[vlen] = '\0';

    body = nl + 1;
    blen = (size_t)payload_len - (vlen + 1);
    if (blen == 0) return send_cmd_resp(conn, err_obj("empty body"));

    {
        /* json-c parsers want a NUL-terminated string. */
        char *body_z = malloc(blen + 1);
        if (!body_z) return send_cmd_resp(conn, err_obj("oom"));
        memcpy(body_z, body, blen);
        body_z[blen] = '\0';

        if (strcmp(verb, "/get") == 0)
            resp = handle_get(body_z, peer);
        else if (strcmp(verb, "/put") == 0)
            resp = handle_put(body_z, peer);
        else
            resp = err_obj("unknown verb '%s'", verb);

        free(body_z);
    }

    /* Outcome log line — one per /get|/put attempt regardless of
     * result.  Format mirrors the [qshd:<pid>] prefix the rest of
     * the daemon uses so journalctl -u qshd shows transfers next to
     * accept and shell-start events. */
    {
        struct json_object *jerr = NULL, *jpath = NULL, *jbytes = NULL;
        if (json_object_object_get_ex(resp, "error", &jerr)) {
            fprintf(stderr, "[qshd:%d] %s FAIL for '%s': %s\n",
                    (int)getpid(), verb, peer ? peer : "?",
                    json_object_get_string(jerr));
        } else {
            const char *which = strcmp(verb, "/get") == 0 ? "from" : "to";
            json_object_object_get_ex(resp, which, &jpath);
            json_object_object_get_ex(resp, "byte_count", &jbytes);
            fprintf(stderr, "[qshd:%d] %s OK %s='%s' byte_count=%ld for '%s'\n",
                    (int)getpid(), verb, which,
                    jpath  ? json_object_get_string(jpath)   : "?",
                    jbytes ? (long)json_object_get_int64(jbytes) : -1L,
                    peer ? peer : "?");
        }
    }

    return send_cmd_resp(conn, resp);
}

/* ------------------------------------------------------------------ */
/*  PTY session                                                        */
/* ------------------------------------------------------------------ */

static pid_t fork_shell(int *pty_master_out, uint16_t rows, uint16_t cols,
                        const char *peer_subject)
{
    struct winsize ws = {0};
    pid_t pid;
    int flags;
    char label[64];

    ws.ws_row = rows;
    ws.ws_col = cols;

    subject_to_label(peer_subject, label, sizeof(label));

    pid = forkpty(pty_master_out, NULL, NULL, &ws);
    if (pid < 0) {
        perror("[qshd] forkpty");
        return -1;
    }

    if (pid == 0) {
        /* Child: set up environment from MTC identity, drop privs to
         * --user if requested, exec the login shell. */
        const char *identity = label[0] ? label : peer_subject;

        setenv("TERM", "xterm-256color", 1);
        if (identity && identity[0]) {
            setenv("USER",    identity, 1);
            setenv("LOGNAME", identity, 1);
        }

        if (run_user) {
            struct passwd *pw = getpwnam(run_user);
            if (!pw) {
                fprintf(stderr, "[qshd] unknown --user: %s\n", run_user);
                _exit(1);
            }
            setenv("HOME", pw->pw_dir, 1);
            if (chdir(pw->pw_dir) != 0) perror("[qshd] chdir");
            if (initgroups(run_user, pw->pw_gid) != 0) perror("initgroups");
            if (setgid(pw->pw_gid) != 0) { perror("setgid"); _exit(1); }
            if (setuid(pw->pw_uid) != 0) { perror("setuid"); _exit(1); }
        } else {
            /* No --user: qshd is running as some real account already
             * (systemd's User=); land the shell in that account's home
             * dir.  systemd sets cwd=/ for service units, so without
             * this fixup the user is dropped into / instead of ~. */
            struct passwd *pw = getpwuid(getuid());
            if (pw) {
                setenv("HOME", pw->pw_dir, 1);
                if (chdir(pw->pw_dir) != 0) perror("[qshd] chdir");
            }
        }

        execl("/bin/bash", "bash", "--login", (char *)NULL);
        _exit(1);
    }

    flags = fcntl(*pty_master_out, F_GETFL, 0);
    fcntl(*pty_master_out, F_SETFL, flags | O_NONBLOCK);

    fprintf(stderr, "[qshd:%d] shell started for '%s' (%ux%u)\n",
            (int)pid, peer_subject ? peer_subject : "?", cols, rows);
    return pid;
}

static int send_frame(mqc_conn_t *conn, uint8_t type,
                      const void *payload, int payload_len)
{
    uint8_t hdr[1 + BUF_SZ + 8];
    if (payload_len < 0 || payload_len > BUF_SZ) return -1;
    hdr[0] = type;
    if (payload_len > 0)
        memcpy(hdr + 1, payload, (size_t)payload_len);
    return mqc_write(conn, hdr, 1 + payload_len);
}

static void session_loop(mqc_conn_t *conn)
{
    uint8_t  in_frame[FRAME_SZ];
    uint8_t  out_buf[BUF_SZ];
    int      pty_master = -1;
    pid_t    shell_pid  = -1;
    int      n;
    int      mqc_fd = mqc_get_fd(conn);
    const char *peer = mqc_get_peer_subject(conn);

    /* ---- First frame must be OPEN_SHELL ---- */
    n = mqc_read(conn, in_frame, sizeof(in_frame));
    if (n < 5 || in_frame[0] != FRAME_OPEN_SHELL) {
        fprintf(stderr, "[qshd:%d] bad first frame from '%s' (n=%d, type=0x%02x)\n",
                (int)getpid(), peer ? peer : "?",
                n > 0 ? in_frame[0] : 0, n);
        return;
    }
    {
        uint16_t rows = ((uint16_t)in_frame[1] << 8) | in_frame[2];
        uint16_t cols = ((uint16_t)in_frame[3] << 8) | in_frame[4];
        shell_pid = fork_shell(&pty_master, rows, cols, peer);
        if (shell_pid < 0) return;
        /* Forward any extra bytes that rode along with OPEN_SHELL */
        if (n > 5)
            (void)!write(pty_master, in_frame + 5, (size_t)(n - 5));
    }

    /* ---- Main poll loop ---- */
    while (running && pty_master >= 0) {
        struct pollfd pfds[2];
        int rv;

        pfds[0].fd = mqc_fd;       pfds[0].events = POLLIN;
        pfds[1].fd = pty_master;   pfds[1].events = POLLIN;

        rv = poll(pfds, 2, -1);
        if (rv < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* MQC -> PTY (input from client) */
        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            n = mqc_read(conn, in_frame, sizeof(in_frame));
            if (n <= 0) break;
            switch (in_frame[0]) {
                case FRAME_DATA:
                    if (n > 1 && pty_master >= 0)
                        (void)!write(pty_master, in_frame + 1,
                                     (size_t)(n - 1));
                    break;
                case FRAME_RESIZE:
                    if (n >= 5 && pty_master >= 0) {
                        struct winsize ws = {0};
                        ws.ws_row = ((uint16_t)in_frame[1] << 8) | in_frame[2];
                        ws.ws_col = ((uint16_t)in_frame[3] << 8) | in_frame[4];
                        ioctl(pty_master, TIOCSWINSZ, &ws);
                    }
                    break;
                case FRAME_CMD_REQ:
                    if (handle_cmd_frame(conn, in_frame + 1, n - 1, peer) < 0) {
                        fprintf(stderr, "[qshd:%d] CMD response send failed\n",
                                (int)getpid());
                    }
                    break;
                default:
                    fprintf(stderr, "[qshd:%d] unknown frame type 0x%02x\n",
                            (int)getpid(), in_frame[0]);
                    break;
            }
        }

        /* PTY -> MQC (output from shell) */
        if (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = read(pty_master, out_buf, sizeof(out_buf));
            if (r > 0) {
                if (send_frame(conn, FRAME_DATA, out_buf, (int)r) < 0)
                    break;
            } else if (r == 0 || (r < 0 && errno != EAGAIN
                                       && errno != EWOULDBLOCK
                                       && errno != EINTR)) {
                /* Shell exited */
                close(pty_master);
                pty_master = -1;
                if (shell_pid > 0) waitpid(shell_pid, NULL, WNOHANG);
                shell_pid = -1;
                send_frame(conn, FRAME_SHELL_EXIT, NULL, 0);
                break;
            }
        }
    }

    if (pty_master >= 0) close(pty_master);
    if (shell_pid > 0) {
        kill(shell_pid, SIGHUP);
        waitpid(shell_pid, NULL, 0);
    }
}

/* ------------------------------------------------------------------ */
/*  CLI                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --tpm-path=PATH [options]\n\n"
        "Options:\n"
        "  --tpm-path=PATH    Server's MTC identity dir (required)\n"
        "  --port=N           TCP port to listen on\n"
        "                     (default: /etc/postWolf/config qsh/qshd-port,\n"
        "                      else %d)\n"
        "  --user=NAME        Drop privileges to this unix account after fork\n"
        "  --mtc-server=URL   Override /etc/postWolf/config global/url-server\n",
        prog, FALLBACK_PORT);
    exit(1);
}

int main(int argc, char *argv[])
{
    const char *tpm_path = NULL;
    const char *mtc_server_override = NULL;
    char tpm_buf[512];
    int port = (int)read_config_long("qsh/qshd-port", FALLBACK_PORT);
    int i, listen_fd;
    char *mtc_url;
    unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];
    mqc_cfg_t cfg;
    mqc_ctx_t *ctx;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--tpm-path=", 11) == 0)
            tpm_path = argv[i] + 11;
        else if (strncmp(argv[i], "--port=", 7) == 0)
            port = atoi(argv[i] + 7);
        else if (strncmp(argv[i], "--user=", 7) == 0)
            run_user = argv[i] + 7;
        else if (strncmp(argv[i], "--mtc-server=", 13) == 0)
            mtc_server_override = argv[i] + 13;
        else
            usage(argv[0]);
    }
    if (!tpm_path) usage(argv[0]);
    if (tpm_path[0] == '~' && tpm_path[1] == '/') {
        const char *home = getenv("HOME");
        if (!home) home = ".";
        snprintf(tpm_buf, sizeof(tpm_buf), "%s%s", home, tpm_path + 1);
        tpm_path = tpm_buf;
    }

    /* Install SIGINT / SIGTERM without SA_RESTART so the blocking
     * accept() in mqc_accept_auto returns -1/EINTR on shutdown — the
     * main loop then sees `running == 0` and exits cleanly.  SIGCHLD
     * keeps SA_RESTART so reaping doesn't disturb other syscalls. */
    {
        struct sigaction sa_exit  = {0};
        struct sigaction sa_chld  = {0};
        sa_exit.sa_handler = sig_handler;       /* no SA_RESTART */
        sigaction(SIGINT,  &sa_exit, NULL);
        sigaction(SIGTERM, &sa_exit, NULL);
        sa_chld.sa_handler = sigchld_handler;
        sa_chld.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
        sigaction(SIGCHLD, &sa_chld, NULL);
        signal(SIGPIPE, SIG_IGN);
    }

    mtc_url = mtc_server_override ? strdup(mtc_server_override)
                                  : resolve_mtc_server();
    if (mqc_load_ca_pubkey(mtc_url, ca_pubkey) != 0) {
        fprintf(stderr, "[qshd] cannot load CA cosigner pubkey from %s\n",
                mtc_url);
        free(mtc_url);
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.role         = MQC_SERVER;
    cfg.tpm_path     = tpm_path;
    cfg.mtc_server   = mtc_url;
    cfg.ca_pubkey    = ca_pubkey;
    cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;

    ctx = mqc_ctx_new(&cfg);
    if (!ctx) {
        fprintf(stderr, "[qshd] mqc_ctx_new failed (check %s)\n", tpm_path);
        free(mtc_url);
        return 1;
    }

    if (load_acl() != 0) {
        fprintf(stderr, "[qshd] ACL parse failed — refusing to start\n");
        mqc_ctx_free(ctx);
        free(mtc_url);
        return 1;
    }

    /* Land the daemon (and every per-connection fork) in the running
     * user's $HOME, so relative paths in /get and /put resolve under
     * ~ instead of systemd's default cwd of "/" — which the ubuntu
     * uid can't write to anyway.  The forkpty child overrides this
     * again for the shell, but the parent of the forkpty (where
     * handle_cmd_frame runs) inherits this cwd. */
    {
        struct passwd *pw = getpwuid(getuid());
        if (pw && pw->pw_dir && chdir(pw->pw_dir) == 0)
            fprintf(stderr, "[qshd] cwd set to %s\n", pw->pw_dir);
        else
            fprintf(stderr, "[qshd] cwd left as '/' (no usable HOME)\n");
    }

    listen_fd = mqc_listen(NULL, port);
    if (listen_fd < 0) {
        fprintf(stderr, "[qshd] mqc_listen failed on port %d\n", port);
        free_acl();
        mqc_ctx_free(ctx);
        free(mtc_url);
        return 1;
    }

    fprintf(stderr, "[qshd] listening on TCP port %d (MTC server: %s)\n",
            port, mtc_url);
    if (run_user)
        fprintf(stderr, "[qshd] sessions will drop to unix user '%s'\n",
                run_user);

    while (running) {
        mqc_conn_t *conn = mqc_accept_auto(ctx, listen_fd);
        char peer_ip[64] = "?";
        struct sockaddr_in pa;
        socklen_t pa_len = sizeof(pa);
        pid_t pid;

        if (!conn) continue;

        if (getpeername(mqc_get_fd(conn), (struct sockaddr *)&pa, &pa_len) == 0)
            inet_ntop(AF_INET, &pa.sin_addr, peer_ip, sizeof(peer_ip));

        fprintf(stderr, "[qshd] accepted '%s' from %s (peer_index=%d)\n",
                mqc_get_peer_subject(conn)
                  ? mqc_get_peer_subject(conn) : "?",
                peer_ip,
                mqc_get_peer_index(conn));

        if (!acl_check(mqc_get_peer_index(conn))) {
            fprintf(stderr, "[qshd] DENIED by ACL: peer_index=%d "
                    "subject='%s' from %s\n",
                    mqc_get_peer_index(conn),
                    mqc_get_peer_subject(conn)
                      ? mqc_get_peer_subject(conn) : "?",
                    peer_ip);
            mqc_close(conn);
            continue;
        }

        pid = fork();
        if (pid < 0) {
            perror("[qshd] fork");
            mqc_close(conn);
            continue;
        }
        if (pid == 0) {
            close(listen_fd);
            session_loop(conn);
            mqc_close(conn);
            _exit(0);
        }
        mqc_close(conn);
    }

    close(listen_fd);
    free_acl();
    mqc_ctx_free(ctx);
    free(mtc_url);
    fprintf(stderr, "[qshd] shutdown\n");
    return 0;
}
