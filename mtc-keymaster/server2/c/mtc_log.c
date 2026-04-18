/******************************************************************************
 * File:        mtc_log.c
 * Purpose:     Logging subsystem for the MTC CA server.
 *
 * Description:
 *   Writes timestamped, level-tagged messages to a configurable log file
 *   (default /var/log/mtc/mtc_server.log) and simultaneously to stdout
 *   for systemd journal capture.  The log file is opened in append mode
 *   with line buffering for prompt output.
 *
 * Dependencies:
 *   mtc_log.h
 *   stdio.h, stdarg.h, string.h, time.h
 *   sys/stat.h   (mkdir for log directory creation)
 *   errno.h
 *
 * Notes:
 *   - NOT thread-safe.  All module state is file-scoped static.
 *   - On init failure the module falls back to stderr — logging never
 *     silently drops messages.
 *   - Every message is written to both the log file AND stdout (dual
 *     output).
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include "mtc_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

static FILE *s_logfp    = NULL;          /**< Log file handle (stderr fallback) */
static int   s_level    = MTC_LOG_INFO;  /**< Current log level                 */
static int   s_to_file  = 0;            /**< 1 if s_logfp is a real file
                                              (not stderr), so we know to
                                              fclose() on shutdown            */

/******************************************************************************
 * Function:    level_str
 *
 * Description:
 *   Returns a fixed-width string label for a log level constant.
 *
 * Input Arguments:
 *   level  - Log level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 *
 * Returns:
 *   Static string pointer (e.g. "ERROR", "WARN ", "INFO ").
 *   Returns "???? " for unrecognised levels.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_log_init
 *
 * Description:
 *   Initialises the logging subsystem.  Creates the parent directory if
 *   needed, opens the log file in append mode with line buffering, and
 *   records the initial log level.  On any failure, falls back to stderr
 *   so that logging continues.
 *
 * Input Arguments:
 *   log_file  - Path to the log file.  NULL defaults to
 *               /var/log/mtc/mtc_server.log.
 *   level     - Initial log level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 *
 * Returns:
 *    0  on success.
 *   -1  if the directory could not be created or the file could not be
 *       opened (logging falls back to stderr).
 *
 * Side Effects:
 *   - May call mkdir() to create the log directory.
 *   - Opens a file handle stored in s_logfp.
 *   - Writes an initial "logging started" message.
 ******************************************************************************/
int mtc_log_init(const char *log_file, int level)
{
    const char *path = log_file ? log_file : "/var/log/mtc/mtc_server.log";
    char dir[512];
    const char *last_slash;

    s_level = level;

    /* Extract parent directory and create if needed */
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

/******************************************************************************
 * Function:    mtc_log_close
 *
 * Description:
 *   Closes the log file handle if one was opened by mtc_log_init().
 *   No-op if logging was never initialised, already closed, or using
 *   the stderr fallback.
 ******************************************************************************/
void mtc_log_close(void)
{
    if (s_logfp && s_to_file) {
        fclose(s_logfp);
        s_logfp = NULL;
        s_to_file = 0;
    }
}

/******************************************************************************
 * Function:    mtc_log_set_level
 *
 * Description:
 *   Sets the log level at runtime.
 *
 * Input Arguments:
 *   level  - New log level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 ******************************************************************************/
void mtc_log_set_level(int level)
{
    s_level = level;
}

/******************************************************************************
 * Function:    mtc_log_get_level
 *
 * Description:
 *   Returns the current log level.
 *
 * Returns:
 *   Current level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 ******************************************************************************/
int mtc_log_get_level(void)
{
    return s_level;
}

/******************************************************************************
 * Function:    mtc_log
 *
 * Description:
 *   Core logging function.  Formats a timestamped message with a level
 *   tag and writes it to both the log file (or stderr fallback) and
 *   stdout (for systemd journal capture).  Messages above the current
 *   log level are silently dropped.
 *
 * Input Arguments:
 *   level  - Message level.  Dropped if > s_level.
 *   fmt    - printf-style format string.
 *   ...    - Format arguments.
 *
 * Side Effects:
 *   Writes to s_logfp and stdout.
 ******************************************************************************/
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
