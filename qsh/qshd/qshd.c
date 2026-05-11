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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <pty.h>
#include <pwd.h>
#include <grp.h>
#include <termios.h>

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
#define ACL_PATH          "/etc/qsh/qshd/config"

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
