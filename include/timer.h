#pragma once

#include <time.h>

typedef struct {
    struct timespec start;
} np_timer_t;

void np_timer_start(np_timer_t *t);
double np_timer_elapsed_ms(const np_timer_t *t);
double np_timer_elapsed_sec(const np_timer_t *t);