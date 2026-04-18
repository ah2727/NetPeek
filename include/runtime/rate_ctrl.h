#ifndef NP_RATE_CTRL_H
#define NP_RATE_CTRL_H

#include <stdbool.h>
#include <stdint.h>

typedef struct np_rate_ctrl
{
    uint32_t min_rate;
    uint32_t max_rate;
    uint32_t current_rate;
    uint32_t additive_step;

    double tokens;
    uint64_t last_refill_ns;

    uint64_t window_start_ns;
    uint64_t sent_in_window;
    uint64_t retrans_in_window;
    double last_retrans_ratio;
} np_rate_ctrl_t;

void np_rate_ctrl_init(np_rate_ctrl_t *ctrl,
                       uint32_t min_rate,
                       uint32_t max_rate);

uint64_t np_rate_ctrl_now_ns(void);
void np_rate_ctrl_refill(np_rate_ctrl_t *ctrl, uint64_t now_ns);
uint64_t np_rate_ctrl_delay_us(np_rate_ctrl_t *ctrl, uint64_t now_ns);
void np_rate_ctrl_consume(np_rate_ctrl_t *ctrl, double tokens, uint64_t now_ns);

void np_rate_ctrl_note_send(np_rate_ctrl_t *ctrl);
void np_rate_ctrl_note_retrans(np_rate_ctrl_t *ctrl);
bool np_rate_ctrl_tick(np_rate_ctrl_t *ctrl, uint64_t now_ns);

#endif
