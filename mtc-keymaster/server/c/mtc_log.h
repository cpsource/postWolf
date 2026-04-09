/* mtc_log.h — Logging for MTC CA server.
 *
 * Log levels:
 *   0 = ERROR   — errors only
 *   1 = WARN    — errors + warnings
 *   2 = INFO    — connections, enrollment, rejections (default)
 *   3 = DEBUG   — protocol trace (hello, handshake steps, request details)
 *   4 = TRACE   — everything including raw data
 */

#ifndef MTC_LOG_H
#define MTC_LOG_H

#define MTC_LOG_ERROR  0
#define MTC_LOG_WARN   1
#define MTC_LOG_INFO   2
#define MTC_LOG_DEBUG  3
#define MTC_LOG_TRACE  4

/* Initialize logging. Creates /var/log/mtc/ if needed.
 * log_file: path to log file (NULL = /var/log/mtc/mtc_server.log)
 * level: MTC_LOG_ERROR..MTC_LOG_TRACE
 * Returns 0 on success, -1 on failure (falls back to stderr). */
int  mtc_log_init(const char *log_file, int level);

/* Close log file. */
void mtc_log_close(void);

/* Set log level at runtime. */
void mtc_log_set_level(int level);
int  mtc_log_get_level(void);

/* Log a message. Use the macros below instead of calling directly. */
void mtc_log(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Convenience macros */
#define LOG_ERROR(...)  mtc_log(MTC_LOG_ERROR, __VA_ARGS__)
#define LOG_WARN(...)   mtc_log(MTC_LOG_WARN,  __VA_ARGS__)
#define LOG_INFO(...)   mtc_log(MTC_LOG_INFO,  __VA_ARGS__)
#define LOG_DEBUG(...)  mtc_log(MTC_LOG_DEBUG, __VA_ARGS__)
#define LOG_TRACE(...)  mtc_log(MTC_LOG_TRACE, __VA_ARGS__)

#endif
