#ifndef NP_UTILS_H
#define NP_UTILS_H

#include <stdint.h>
#include <time.h>

typedef struct {
    struct timespec start;
} np_timer_t;

void   np_timer_start(np_timer_t *t);
double np_timer_elapsed_ms(np_timer_t *t);
double np_timer_elapsed_sec(np_timer_t *t);

/**
 * Fisher-Yates shuffle for a uint16_t array.
 */
void np_shuffle_u16(uint16_t *arr, uint32_t len);

/**
 * Lookup well-known service name for a port (TCP).
 * Returns "unknown" if not found.
 */
const char *np_service_name(uint16_t port);




#endif /* NP_UTILS_H */