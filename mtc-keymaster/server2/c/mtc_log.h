/**
 * @file mtc_log.h
 * @brief Logging subsystem for the MTC CA server.
 *
 * @details
 * Provides levelled logging with timestamps to a configurable log file
 * (default /var/log/mtc/mtc_server.log) and simultaneously to stdout
 * for systemd journal capture.
 *
 * Log levels (ascending verbosity):
 *   - 0 ERROR — errors only
 *   - 1 WARN  — errors + warnings
 *   - 2 INFO  — connections, enrollment, rejections (default)
 *   - 3 DEBUG — protocol trace (hello, handshake steps, request details)
 *   - 4 TRACE — everything including raw data
 *
 * Thread safety: NOT thread-safe.  All state is file-scoped static.
 * Callers must serialise access (the server is single-threaded).
 *
 * @date 2026-04-13
 */

#ifndef MTC_LOG_H
#define MTC_LOG_H

/** @name Log level constants
 *  @{ */
#define MTC_LOG_ERROR  0   /**< Errors only                             */
#define MTC_LOG_WARN   1   /**< Errors + warnings                       */
#define MTC_LOG_INFO   2   /**< Connections, enrollment, rejections      */
#define MTC_LOG_DEBUG  3   /**< Protocol trace, request details          */
#define MTC_LOG_TRACE  4   /**< Everything including raw data            */
/** @} */

/**
 * @brief    Initialise the logging subsystem.
 *
 * @details
 * Opens the log file for appending (creates the parent directory if
 * needed).  Sets line-buffered mode so messages appear promptly.
 * On failure, falls back to stderr.
 *
 * @param[in] log_file  Path to the log file.  NULL defaults to
 *                       /var/log/mtc/mtc_server.log.
 * @param[in] level     Initial log level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 *
 * @return
 *   0   on success.
 *  -1   if the log file could not be opened (logging falls back to stderr).
 */
int  mtc_log_init(const char *log_file, int level);

/**
 * @brief    Close the log file.
 *
 * @details
 * Closes the file handle opened by mtc_log_init().  Safe to call if
 * logging was never initialised or already closed (no-op).
 */
void mtc_log_close(void);

/**
 * @brief    Set the log level at runtime.
 *
 * @param[in] level  New log level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 */
void mtc_log_set_level(int level);

/**
 * @brief    Get the current log level.
 *
 * @return   Current level (MTC_LOG_ERROR..MTC_LOG_TRACE).
 */
int  mtc_log_get_level(void);

/**
 * @brief    Write a log message (use the LOG_* macros instead).
 *
 * @details
 * Formats a timestamped, level-tagged message and writes it to both the
 * log file (or stderr fallback) and stdout.  Messages above the current
 * level are silently dropped.
 *
 * @param[in] level  Message level.
 * @param[in] fmt    printf-style format string.
 * @param[in] ...    Format arguments.
 */
void mtc_log(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/** @name Convenience macros
 *  Prefer these over calling mtc_log() directly.
 *  @{ */
#define LOG_ERROR(...)  mtc_log(MTC_LOG_ERROR, __VA_ARGS__)
#define LOG_WARN(...)   mtc_log(MTC_LOG_WARN,  __VA_ARGS__)
#define LOG_INFO(...)   mtc_log(MTC_LOG_INFO,  __VA_ARGS__)
#define LOG_DEBUG(...)  mtc_log(MTC_LOG_DEBUG, __VA_ARGS__)
#define LOG_TRACE(...)  mtc_log(MTC_LOG_TRACE, __VA_ARGS__)
/** @} */

#endif
