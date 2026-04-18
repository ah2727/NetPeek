#include "scanner_internal.h"
#include "runtime/rate_ctrl.h"
#include "runtime/stats.h"

#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

typedef struct np_thread_rate_state
{
    const np_config_t *cfg;
    np_rate_ctrl_t ctrl;
    bool initialized;
} np_thread_rate_state_t;

static __thread np_thread_rate_state_t g_rate_state;

static pthread_mutex_t g_serial_probe_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_serial_probe_us = 0;

static pthread_mutex_t g_rst_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_rst_us = 0;
static uint64_t g_prev_rst_gap_us = 0;
static uint32_t g_rst_pattern_count = 0;
static uint64_t g_rst_backoff_us = 0;

static void ensure_rate_state(const np_config_t *cfg)
{
    if (!cfg)
        return;

    if (g_rate_state.initialized && g_rate_state.cfg == cfg)
        return;

    uint32_t min_rate = cfg->min_rate ? cfg->min_rate : 1;
    uint32_t max_rate = cfg->max_rate ? cfg->max_rate : min_rate;
    if (max_rate < min_rate)
        max_rate = min_rate;

    np_rate_ctrl_init(&g_rate_state.ctrl, min_rate, max_rate);
    g_rate_state.cfg = cfg;
    g_rate_state.initialized = true;
    np_stats_set_rate(g_rate_state.ctrl.current_rate, g_rate_state.ctrl.last_retrans_ratio);
}

uint64_t np_now_monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000ull) + ((uint64_t)ts.tv_nsec / 1000ull);
}

bool np_host_timeout_reached(const np_config_t *cfg, uint64_t started_us)
{
    if (!cfg || cfg->host_timeout_ms == 0)
        return false;

    uint64_t elapsed_us = np_now_monotonic_us() - started_us;
    return elapsed_us >= ((uint64_t)cfg->host_timeout_ms * 1000ull);
}

uint32_t np_effective_timeout_ms(const np_config_t *cfg)
{
    if (!cfg)
        return NP_DEFAULT_TIMEOUT;

    uint32_t timeout = cfg->initial_rtt_timeout_ms;
    if (timeout == 0)
        timeout = cfg->timeout_ms;

    if (cfg->min_rtt_timeout_ms > 0 && timeout < cfg->min_rtt_timeout_ms)
        timeout = cfg->min_rtt_timeout_ms;

    if (cfg->max_rtt_timeout_ms > 0 && timeout > cfg->max_rtt_timeout_ms)
        timeout = cfg->max_rtt_timeout_ms;

    if (timeout == 0)
        timeout = cfg->timeout_ms ? cfg->timeout_ms : NP_DEFAULT_TIMEOUT;

    return timeout;
}

static uint64_t apply_jitter(uint64_t base_us, uint32_t jitter_us)
{
    if (jitter_us == 0)
        return base_us;
    return base_us + (uint64_t)(rand() % (int)(jitter_us + 1u));
}

static uint64_t apply_t0_spread(uint64_t base_us)
{
    uint64_t span = base_us / 5u;
    int64_t delta = (int64_t)(rand() % (int)(span * 2u + 1u)) - (int64_t)span;
    int64_t value = (int64_t)base_us + delta;
    if (value < 0)
        value = 0;
    return (uint64_t)value;
}

void np_wait_probe_budget(const np_config_t *cfg, uint64_t *last_probe_us)
{
    if (!cfg || !last_probe_us)
        return;

    if (cfg->timing_template == NP_TIMING_TEMPLATE_0)
    {
        pthread_mutex_lock(&g_serial_probe_lock);

        uint64_t now = np_now_monotonic_us();
        uint64_t min_interval = cfg->scan_delay_us ? cfg->scan_delay_us : 300000000ull;
        min_interval = apply_t0_spread(min_interval);
        min_interval = apply_jitter(min_interval, cfg->evasion.scan_jitter_us);

        if (g_last_serial_probe_us > 0 && now < g_last_serial_probe_us + min_interval)
        {
            uint64_t sleep_us = (g_last_serial_probe_us + min_interval) - now;
            usleep((useconds_t)sleep_us);
        }

        g_last_serial_probe_us = np_now_monotonic_us();
        *last_probe_us = g_last_serial_probe_us;
        pthread_mutex_unlock(&g_serial_probe_lock);
        return;
    }

    ensure_rate_state(cfg);

    while (1)
    {
        uint64_t now_ns = np_rate_ctrl_now_ns();
        uint64_t delay_us = np_rate_ctrl_delay_us(&g_rate_state.ctrl, now_ns);
        if (delay_us == 0)
        {
            np_rate_ctrl_consume(&g_rate_state.ctrl, 1.0, now_ns);
            if (np_rate_ctrl_tick(&g_rate_state.ctrl, now_ns))
            {
                np_stats_set_rate(g_rate_state.ctrl.current_rate,
                                  g_rate_state.ctrl.last_retrans_ratio);
            }

            if (cfg->evasion.defeat_rst_ratelimit)
            {
                pthread_mutex_lock(&g_rst_lock);
                uint64_t backoff = g_rst_backoff_us;
                if (g_rst_backoff_us > 1000)
                    g_rst_backoff_us /= 2;
                pthread_mutex_unlock(&g_rst_lock);
                if (backoff > 0)
                    usleep((useconds_t)backoff);
            }

            if (cfg->evasion.scan_jitter_us > 0)
                usleep((useconds_t)(rand() % (int)(cfg->evasion.scan_jitter_us + 1u)));

            *last_probe_us = np_now_monotonic_us();
            return;
        }

        if (cfg->scan_delay_us > 0 && delay_us < cfg->scan_delay_us)
            delay_us = cfg->scan_delay_us;
        if (cfg->max_scan_delay_us > 0 && delay_us > cfg->max_scan_delay_us)
            delay_us = cfg->max_scan_delay_us;

        delay_us = apply_jitter(delay_us, cfg->evasion.scan_jitter_us);
        usleep((useconds_t)delay_us);
    }
}

void np_note_probe_sent(const np_config_t *cfg)
{
    ensure_rate_state(cfg);
    if (!g_rate_state.initialized)
        return;
    np_rate_ctrl_note_send(&g_rate_state.ctrl);
    np_stats_inc_pkts_sent(1);
}

void np_note_probe_retransmission(const np_config_t *cfg)
{
    ensure_rate_state(cfg);
    if (!g_rate_state.initialized)
        return;
    np_rate_ctrl_note_retrans(&g_rate_state.ctrl);
}

void np_timing_note_rst_observation(const np_config_t *cfg, uint64_t now_us)
{
    if (!cfg || !cfg->evasion.defeat_rst_ratelimit)
        return;

    pthread_mutex_lock(&g_rst_lock);

    if (g_last_rst_us > 0)
    {
        uint64_t gap = now_us - g_last_rst_us;
        if (g_prev_rst_gap_us > 0)
        {
            uint64_t delta = (gap > g_prev_rst_gap_us)
                ? (gap - g_prev_rst_gap_us)
                : (g_prev_rst_gap_us - gap);
            if (delta <= 5000)
                g_rst_pattern_count++;
            else
                g_rst_pattern_count = 0;
        }
        g_prev_rst_gap_us = gap;
    }

    g_last_rst_us = now_us;

    if (g_rst_pattern_count >= 6)
    {
        if (g_rst_backoff_us == 0)
            g_rst_backoff_us = 250000;
        else
            g_rst_backoff_us *= 2;

        if (g_rst_backoff_us > 30000000)
            g_rst_backoff_us = 30000000;
    }

    pthread_mutex_unlock(&g_rst_lock);
}

