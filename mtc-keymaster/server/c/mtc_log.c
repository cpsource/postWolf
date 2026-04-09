/* mtc_log.c — Logging for MTC CA server.
 *
 * Writes timestamped messages to /var/log/mtc/mtc_server.log (or custom path).
 * Also writes to stdout for systemd journal capture. */

#include "mtc_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

static FILE *s_logfp    = NULL;
static int   s_level    = MTC_LOG_INFO;
static int   s_to_file  = 0;

static const char *level_str(int level)
{
    switch (level) {
        case MTC_LOG_ERROR: return "ERROR";
        case MTC_LOG_WARN:  return "WARN ";
        case MTC_LOG_INFO:  return "INFO ";
        case MTC_LOG_DEBUG: return "DEBUG";
        case MTC_LOG_TRACE: return "TRACE";
        default:            return "???? ";
    }
}

int mtc_log_init(const char *log_file, int level)
{
    const char *path = log_file ? log_file : "/var/log/mtc/mtc_server.log";
    char dir[512];
    const char *last_slash;

    s_level = level;

    /* Extract directory and create if needed */
    last_slash = strrchr(path, '/');
    if (last_slash && (last_slash - path) < (int)sizeof(dir)) {
        memcpy(dir, path, (size_t)(last_slash - path));
        dir[last_slash - path] = '\0';
        if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[log] cannot create %s: %s (logging to stderr)\n",
                    dir, strerror(errno));
            s_logfp = stderr;
            return -1;
        }
    }

    s_logfp = fopen(path, "a");
    if (!s_logfp) {
        fprintf(stderr, "[log] cannot open %s: %s (logging to stderr)\n",
                path, strerror(errno));
        s_logfp = stderr;
        return -1;
    }

    /* Line-buffered so messages appear promptly */
    setvbuf(s_logfp, NULL, _IOLBF, 0);
    s_to_file = 1;

    mtc_log(MTC_LOG_INFO, "logging started (level=%d, file=%s)", level, path);
    return 0;
}

void mtc_log_close(void)
{
    if (s_logfp && s_to_file) {
        fclose(s_logfp);
        s_logfp = NULL;
        s_to_file = 0;
    }
}

void mtc_log_set_level(int level)
{
    s_level = level;
}

int mtc_log_get_level(void)
{
    return s_level;
}

void mtc_log(int level, const char *fmt, ...)
{
    va_list ap;
    time_t now;
    struct tm tm;
    char ts[32];

    if (level > s_level)
        return;

    now = time(NULL);
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    /* Write to log file (or stderr fallback) */
    if (s_logfp) {
        fprintf(s_logfp, "%s [%s] ", ts, level_str(level));
        va_start(ap, fmt);
        vfprintf(s_logfp, fmt, ap);
        va_end(ap);
        fprintf(s_logfp, "\n");
    }

    /* Also write to stdout for systemd journal */
    printf("%s [%s] ", ts, level_str(level));
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}
