/* mqcp_timer.c — Monotonic clock */

#include "mqcp_timer.h"
#include <time.h>

uint64_t mqcp_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}
