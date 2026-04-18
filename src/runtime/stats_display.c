#include "runtime/stats.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>

static pthread_t g_stats_thread;
static volatile int g_stats_running;
static struct timespec g_started_at;

static uint64_t diff_ms(const struct timespec *a, const struct timespec *b)
{
    uint64_t sec = (uint64_t)(b->tv_sec - a->tv_sec);
    int64_t ns = b->tv_nsec - a->tv_nsec;
    return sec * 1000ull + (uint64_t)(ns / 1000000ll);
}

static int term_columns(void)
{
    struct winsize ws;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

static void format_eta(uint64_t elapsed_ms, double done_pct, char *out, size_t out_sz)
{
    if (done_pct <= 0.01)
    {
        snprintf(out, out_sz, "--");
        return;
    }

    double total_ms = (double)elapsed_ms / (done_pct / 100.0);
    uint64_t rem_ms = (uint64_t)(total_ms - (double)elapsed_ms);
    uint64_t sec = rem_ms / 1000ull;
    snprintf(out, out_sz, "%llum%llus", (unsigned long long)(sec / 60ull), (unsigned long long)(sec % 60ull));
}

static void format_line(const np_stats_snapshot_t *snap,
                        uint64_t tx_pps,
                        uint64_t rx_pps,
                        const struct timespec *now,
                        char *out,
                        size_t out_sz)
{
    uint64_t progress_total = snap->work_total ? snap->work_total : snap->hosts_total;
    uint64_t progress_done = snap->work_total ? snap->work_completed : snap->hosts_completed;
    double pct = progress_total ? ((double)progress_done * 100.0 / (double)progress_total) : 100.0;
    if (pct > 100.0)
        pct = 100.0;

    uint64_t elapsed_ms = diff_ms(&g_started_at, now);
    char eta[32];
    format_eta(elapsed_ms, pct, eta, sizeof(eta));

    struct tm tm_now;
    time_t wall = time(NULL);
    localtime_r(&wall, &tm_now);
    char hhmmss[16];
    strftime(hhmmss, sizeof(hhmmss), "%H:%M:%S", &tm_now);

    snprintf(out,
             out_sz,
             "[%s] %.1f%% done | %llu/%llu hosts | %llu pps TX | %llu pps RX | %llu open | ETA %s",
             hhmmss,
             pct,
             (unsigned long long)snap->hosts_completed,
             (unsigned long long)snap->hosts_total,
             (unsigned long long)tx_pps,
             (unsigned long long)rx_pps,
             (unsigned long long)snap->ports_open,
             eta);
}

static void *stats_thread_main(void *arg)
{
    (void)arg;

    np_stats_snapshot_t prev;
    np_stats_snapshot_t cur;
    memset(&prev, 0, sizeof(prev));

    struct timespec prev_ts;
    clock_gettime(CLOCK_MONOTONIC, &prev_ts);

    while (g_stats_running)
    {
        usleep(250000);

        np_stats_snapshot(&cur);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        uint64_t elapsed_ms = diff_ms(&prev_ts, &now);
        if (elapsed_ms == 0)
            elapsed_ms = 1;

        uint64_t tx_delta = cur.pkts_sent - prev.pkts_sent;
        uint64_t rx_delta = cur.pkts_recv - prev.pkts_recv;
        uint64_t tx_pps = (tx_delta * 1000ull) / elapsed_ms;
        uint64_t rx_pps = (rx_delta * 1000ull) / elapsed_ms;

        char line[256];
        format_line(&cur, tx_pps, rx_pps, &now, line, sizeof(line));

        int cols = term_columns();
        if ((int)strlen(line) > cols - 1)
            line[cols - 1] = '\0';

        fprintf(stderr, "\r%-*s", cols - 1, line);
        fflush(stderr);

        prev = cur;
        prev_ts = now;
    }

    int cols = term_columns();
    fprintf(stderr, "\r%-*s\r", cols - 1, "");
    fflush(stderr);
    return NULL;
}

bool np_stats_display_should_run(const np_config_t *cfg)
{
    if (!cfg)
        return false;

    if (cfg->suppress_progress)
        return false;

    if (cfg->output_fmt == NP_OUTPUT_JSON || cfg->output_fmt == NP_OUTPUT_CSV)
        return false;

    return isatty(STDERR_FILENO) == 1;
}

int np_stats_display_start(const np_config_t *cfg)
{
    if (!np_stats_display_should_run(cfg))
        return 0;

    if (g_stats_running)
        return 0;

    g_stats_running = 1;
    clock_gettime(CLOCK_MONOTONIC, &g_started_at);
    if (pthread_create(&g_stats_thread, NULL, stats_thread_main, NULL) != 0)
    {
        g_stats_running = 0;
        return -1;
    }
    return 0;
}

void np_stats_display_stop(void)
{
    if (!g_stats_running)
        return;

    g_stats_running = 0;
    pthread_join(g_stats_thread, NULL);
}
