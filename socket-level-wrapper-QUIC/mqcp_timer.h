/* mqcp_timer.h — Monotonic clock and timer utilities */

#ifndef MQCP_TIMER_H
#define MQCP_TIMER_H

#include <stdint.h>

/* Get current monotonic time in microseconds. */
uint64_t mqcp_now_us(void);

/* Convert milliseconds to microseconds. */
static inline uint64_t mqcp_ms_to_us(uint64_t ms) { return ms * 1000; }

/* Returns 1 if deadline has passed (0 means no deadline set). */
static inline int mqcp_timer_expired(uint64_t deadline, uint64_t now) {
    return deadline != 0 && now >= deadline;
}

/* Compute timeout in microseconds from now until deadline.
 * Returns 0 if already expired or no deadline. */
static inline uint64_t mqcp_timer_remaining(uint64_t deadline, uint64_t now) {
    if (deadline == 0 || now >= deadline) return 0;
    return deadline - now;
}

#endif /* MQCP_TIMER_H */
