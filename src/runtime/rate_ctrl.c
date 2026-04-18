#include "runtime/rate_ctrl.h"

#include <time.h>

static uint32_t clamp_u32(uint32_t value, uint32_t min_v, uint32_t max_v)
{
    if (value < min_v)
        return min_v;
    if (value > max_v)
        return max_v;
    return value;
}

uint64_t np_rate_ctrl_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

void np_rate_ctrl_init(np_rate_ctrl_t *ctrl,
                       uint32_t min_rate,
                       uint32_t max_rate)
{
    if (!ctrl)
        return;

    if (min_rate == 0)
        min_rate = 1;
    if (max_rate == 0)
        max_rate = min_rate;
    if (min_rate > max_rate)
        min_rate = max_rate;

    ctrl->min_rate = min_rate;
    ctrl->max_rate = max_rate;
    ctrl->current_rate = min_rate;

    uint32_t delta = (max_rate - min_rate) / 20u;
    ctrl->additive_step = delta ? delta : 1u;

    ctrl->tokens = (double)ctrl->current_rate;
    ctrl->last_refill_ns = np_rate_ctrl_now_ns();

    ctrl->window_start_ns = ctrl->last_refill_ns;
    ctrl->sent_in_window = 0;
    ctrl->retrans_in_window = 0;
    ctrl->last_retrans_ratio = 0.0;
}

void np_rate_ctrl_refill(np_rate_ctrl_t *ctrl, uint64_t now_ns)
{
    if (!ctrl)
        return;

    if (now_ns <= ctrl->last_refill_ns)
        return;

    uint64_t elapsed_ns = now_ns - ctrl->last_refill_ns;
    double add = ((double)elapsed_ns / 1000000000.0) * (double)ctrl->current_rate;
    ctrl->tokens += add;

    double max_tokens = (double)ctrl->current_rate;
    if (ctrl->tokens > max_tokens)
        ctrl->tokens = max_tokens;

    ctrl->last_refill_ns = now_ns;
}

uint64_t np_rate_ctrl_delay_us(np_rate_ctrl_t *ctrl, uint64_t now_ns)
{
    if (!ctrl)
        return 0;

    np_rate_ctrl_refill(ctrl, now_ns);
    if (ctrl->tokens >= 1.0)
        return 0;

    double need = 1.0 - ctrl->tokens;
    double sec = need / (double)ctrl->current_rate;
    if (sec <= 0.0)
        return 0;

    return (uint64_t)(sec * 1000000.0);
}

void np_rate_ctrl_consume(np_rate_ctrl_t *ctrl, double tokens, uint64_t now_ns)
{
    if (!ctrl)
        return;

    np_rate_ctrl_refill(ctrl, now_ns);
    ctrl->tokens -= tokens;
    if (ctrl->tokens < 0.0)
        ctrl->tokens = 0.0;
}

void np_rate_ctrl_note_send(np_rate_ctrl_t *ctrl)
{
    if (!ctrl)
        return;
    ctrl->sent_in_window++;
}

void np_rate_ctrl_note_retrans(np_rate_ctrl_t *ctrl)
{
    if (!ctrl)
        return;
    ctrl->retrans_in_window++;
}

bool np_rate_ctrl_tick(np_rate_ctrl_t *ctrl, uint64_t now_ns)
{
    if (!ctrl)
        return false;

    const uint64_t window_ns = 1000000000ull;
    if (now_ns - ctrl->window_start_ns < window_ns)
        return false;

    double ratio = 0.0;
    if (ctrl->sent_in_window > 0)
        ratio = (double)ctrl->retrans_in_window / (double)ctrl->sent_in_window;

    ctrl->last_retrans_ratio = ratio;

    if (ratio > 0.02)
    {
        uint32_t next = (uint32_t)((double)ctrl->current_rate * 0.7);
        ctrl->current_rate = clamp_u32(next, ctrl->min_rate, ctrl->max_rate);
    }
    else
    {
        ctrl->current_rate = clamp_u32(ctrl->current_rate + ctrl->additive_step,
                                       ctrl->min_rate,
                                       ctrl->max_rate);
    }

    if (ctrl->tokens > (double)ctrl->current_rate)
        ctrl->tokens = (double)ctrl->current_rate;

    ctrl->window_start_ns = now_ns;
    ctrl->sent_in_window = 0;
    ctrl->retrans_in_window = 0;
    return true;
}
