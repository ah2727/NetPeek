#include "metrics.h"

#include <stdio.h>
#include <string.h>

/* ── ANSI color codes ───────────────────────────────────────────── */
#define CLR_RESET       "\033[0m"
#define CLR_BOLD        "\033[1m"
#define CLR_DIM         "\033[2m"
#define CLR_GREEN       "\033[32m"
#define CLR_RED         "\033[31m"
#define CLR_YELLOW      "\033[33m"
#define CLR_CYAN        "\033[36m"
#define CLR_MAGENTA     "\033[35m"
#define CLR_BRIGHT_CYAN "\033[96m"
#define CLR_WHITE       "\033[97m"
#define CLR_BG_GREEN    "\033[42m"
#define CLR_BG_RED      "\033[41m"
#define CLR_BG_YELLOW   "\033[43m"
#define CLR_BG_MAGENTA  "\033[45m"
#define CLR_BG_CYAN     "\033[46m"
#define CLR_BG_WHITE    "\033[47;30m"

/* ── Box-drawing ────────────────────────────────────────────────── */
#define BOX_H   "─"
#define BOX_V   "│"
#define BOX_TL  "┌"
#define BOX_TR  "┐"
#define BOX_BL  "└"
#define BOX_BR  "┘"
#define BOX_LT  "├"
#define BOX_RT  "┤"

/* ── Icons (Unicode) ────────────────────────────────────────────── */
#define ICON_METRICS  "📊"
#define ICON_CHECK    "✔"
#define ICON_CROSS    "✖"
#define ICON_FILTER   "⚡"
#define ICON_UNKNOWN  "❓"
#define ICON_CLOCK    "⏱"
#define ICON_SPEED    "🚀"
#define ICON_SCANS    "🔍"
#define ICON_BAR_FULL "█"
#define ICON_BAR_MED  "▓"
#define ICON_BAR_LOW  "░"

/* ── TTY detection ──────────────────────────────────────────────── */
#ifndef _WIN32
#include <unistd.h>
static int stdout_is_tty(void) { return isatty(fileno(stdout)); }
#else
#include <io.h>
static int stdout_is_tty(void) { return _isatty(_fileno(stdout)); }
#endif

/* Return color string only when stdout is a tty */
static const char *clr(const char *code)
{
    return stdout_is_tty() ? code : "";
}

/* ── Helper: draw a horizontal rule ─────────────────────────────── */
static void hline(const char *left, const char *right, int width)
{
    printf("  %s%s%s", clr(CLR_DIM), left, clr(CLR_RESET));
    for (int i = 0; i < width; i++)
        printf("%s%s%s", clr(CLR_DIM), BOX_H, clr(CLR_RESET));
    printf("%s%s%s\n", clr(CLR_DIM), right, clr(CLR_RESET));
}

/* ── Helper: print a bar graph ──────────────────────────────────── */
static void print_bar(unsigned long long value,
                      unsigned long long max_val,
                      const char *bar_color,
                      int bar_width)
{
    int filled = 0;
    if (max_val > 0)
        filled = (int)((double)value / (double)max_val * bar_width);
    if (filled > bar_width)
        filled = bar_width;

    printf("%s", clr(bar_color));
    for (int i = 0; i < filled; i++)
        printf("%s", ICON_BAR_FULL);
    printf("%s", clr(CLR_DIM));
    for (int i = filled; i < bar_width; i++)
        printf("%s", ICON_BAR_LOW);
    printf("%s", clr(CLR_RESET));
}

/* ── Helper: print a labeled metric row ─────────────────────────── */
static void print_metric_row(const char *icon,
                             const char *label,
                             const char *value_color,
                             const char *value_str,
                             unsigned long long bar_val,
                             unsigned long long bar_max,
                             const char *bar_color)
{
    const int LABEL_W  = 22;
    const int VALUE_W  = 14;
    const int BAR_W    = 20;

    /* left border */
    printf("  %s%s%s ", clr(CLR_DIM), BOX_V, clr(CLR_RESET));

    /* icon + label */
    printf(" %s %s%s%-*s%s",
           icon,
           clr(CLR_BOLD), clr(CLR_WHITE),
           LABEL_W, label,
           clr(CLR_RESET));

    /* value */
    printf("%s%s%-*s%s",
           clr(CLR_BOLD), clr(value_color),
           VALUE_W, value_str,
           clr(CLR_RESET));

    /* bar graph */
    if (bar_max > 0)
    {
        printf(" ");
        print_bar(bar_val, bar_max, bar_color, BAR_W);
    }
    else
    {
        /* pad to keep alignment */
        printf(" ");
        for (int i = 0; i < BAR_W; i++)
            printf(" ");
    }

    /* right border */
    printf(" %s%s%s\n", clr(CLR_DIM), BOX_V, clr(CLR_RESET));
}

/* ── Helper: print a separator row inside the box ───────────────── */
static void inner_sep(int width)
{
    hline(BOX_LT, BOX_RT, width);
}

/* ──────────────────────────────────────────────────────────────── */

void np_metrics_init(np_metrics_t *m)
{
    if (!m)
        return;

    memset(m, 0, sizeof(*m));
}

void np_metrics_update(np_metrics_t *m,
                       np_port_state_t state,
                       double rtt_ms)
{
    if (!m)
        return;

    m->total_scans++;

    switch (state)
    {
    case NP_PORT_OPEN:
        m->open_ports++;
        break;

    case NP_PORT_CLOSED:
        m->closed_ports++;
        break;

    case NP_PORT_FILTERED:
        m->filtered_ports++;
        break;

    case NP_PORT_UNKNOWN:
    case NP_PORT_OPEN_FILTERED:
        m->open_filtered_ports++;
        break;

    default:
        m->unknown_ports++;
        break;
    }

    if (rtt_ms >= 0.0)
    {
        m->total_rtt_ms += rtt_ms;
        m->rtt_samples++;
    }
}

void np_metrics_print(const np_metrics_t *m,
                      double elapsed_sec)
{
    if (!m)
        return;

    double avg_rtt = 0.0;
    if (m->rtt_samples > 0)
        avg_rtt = m->total_rtt_ms / (double)m->rtt_samples;

    double rate = 0.0;
    if (elapsed_sec > 0.0)
        rate = (double)m->total_scans / elapsed_sec;

    /* Box inner width (must be wide enough for icon+label+value+bar) */
    const int BOX_INNER_W = 64;

    char vbuf[64];

    printf("\n");

    /* ── Title ──────────────────────────────────────────────────── */
    hline(BOX_TL, BOX_TR, BOX_INNER_W);

    printf("  %s%s%s ", clr(CLR_DIM), BOX_V, clr(CLR_RESET));
    printf(" %s  %s%s%s Scan Metrics",
           ICON_METRICS,
           clr(CLR_BOLD), clr(CLR_BRIGHT_CYAN),
           clr(CLR_RESET));
    /* Re-apply after reset — print title colored */
    /* We'll just do it inline: */
    /* Clear and redo */
    printf("\r");                         /* carriage return   */
    printf("  %s%s%s ", clr(CLR_DIM), BOX_V, clr(CLR_RESET));

    {
        /* Compute visible title width and pad */
        const char *title = " Scan Metrics";
        int title_vis_len = 2 + 1 + (int)strlen(title); /* icon(~2) + space + title */

        printf(" %s  %s%s%s%s",
               ICON_METRICS,
               clr(CLR_BOLD), clr(CLR_BRIGHT_CYAN),
               title,
               clr(CLR_RESET));

        int pad = BOX_INNER_W - title_vis_len - 1;
        for (int i = 0; i < pad; i++)
            printf(" ");
    }

    printf("%s%s%s\n", clr(CLR_DIM), BOX_V, clr(CLR_RESET));

    inner_sep(BOX_INNER_W);

    /* ── Port Counts Section ────────────────────────────────────── */

    /* Total scans */
    snprintf(vbuf, sizeof(vbuf), "%llu",
             (unsigned long long)m->total_scans);
    print_metric_row(ICON_SCANS, "Total Scans",
                     CLR_BRIGHT_CYAN, vbuf,
                     0, 0, "");

    /* Open ports */
    snprintf(vbuf, sizeof(vbuf), "%llu",
             (unsigned long long)m->open_ports);
    print_metric_row(ICON_CHECK, "Open Ports",
                     CLR_GREEN, vbuf,
                     m->open_ports, m->total_scans, CLR_GREEN);

    /* Closed ports */
    snprintf(vbuf, sizeof(vbuf), "%llu",
             (unsigned long long)m->closed_ports);
    print_metric_row(ICON_CROSS, "Closed Ports",
                     CLR_RED, vbuf,
                     m->closed_ports, m->total_scans, CLR_RED);

    /* Filtered ports */
    snprintf(vbuf, sizeof(vbuf), "%llu",
             (unsigned long long)m->filtered_ports);
    print_metric_row(ICON_FILTER, "Filtered Ports",
                     CLR_YELLOW, vbuf,
                     m->filtered_ports, m->total_scans, CLR_YELLOW);

    /* Open|Filtered ports */
    snprintf(vbuf, sizeof(vbuf), "%llu",
             (unsigned long long)m->open_filtered_ports);
    print_metric_row(ICON_FILTER, "Open|Filtered",
                     CLR_MAGENTA, vbuf,
                     m->open_filtered_ports, m->total_scans, CLR_MAGENTA);

    /* Unknown ports */
    snprintf(vbuf, sizeof(vbuf), "%llu",
             (unsigned long long)m->unknown_ports);
    print_metric_row(ICON_UNKNOWN, "Unknown Ports",
                     CLR_DIM, vbuf,
                     m->unknown_ports, m->total_scans, CLR_DIM);

    inner_sep(BOX_INNER_W);

    /* ── Performance Section ────────────────────────────────────── */

    /* Average RTT */
    snprintf(vbuf, sizeof(vbuf), "%.2f ms", avg_rtt);

    {
        /* Color the RTT value by magnitude */
        const char *rtt_color = CLR_GREEN;
        if (avg_rtt > 500.0)
            rtt_color = CLR_RED;
        else if (avg_rtt > 200.0)
            rtt_color = CLR_YELLOW;
        else if (avg_rtt > 100.0)
            rtt_color = CLR_CYAN;

        print_metric_row(ICON_CLOCK, "Average RTT",
                         rtt_color, vbuf,
                         0, 0, "");
    }

    /* Scan rate */
    snprintf(vbuf, sizeof(vbuf), "%.2f ports/sec", rate);
    print_metric_row(ICON_SPEED, "Scan Rate",
                     CLR_BRIGHT_CYAN, vbuf,
                     0, 0, "");

    /* Elapsed time */
    {
        int hrs = (int)(elapsed_sec / 3600.0);
        int mins = (int)((elapsed_sec - hrs * 3600) / 60.0);
        double secs = elapsed_sec - hrs * 3600 - mins * 60;

        if (hrs > 0)
            snprintf(vbuf, sizeof(vbuf), "%dh %dm %.1fs", hrs, mins, secs);
        else if (mins > 0)
            snprintf(vbuf, sizeof(vbuf), "%dm %.1fs", mins, secs);
        else
            snprintf(vbuf, sizeof(vbuf), "%.2fs", secs);

        print_metric_row(ICON_CLOCK, "Elapsed Time",
                         CLR_WHITE, vbuf,
                         0, 0, "");
    }

    /* ── Percentage Breakdown Ribbon ────────────────────────────── */
    inner_sep(BOX_INNER_W);

    printf("  %s%s%s ", clr(CLR_DIM), BOX_V, clr(CLR_RESET));

    if (m->total_scans > 0)
    {
        double pct_open   = 100.0 * m->open_ports       / m->total_scans;
        double pct_closed = 100.0 * m->closed_ports      / m->total_scans;
        double pct_filt   = 100.0 * m->filtered_ports    / m->total_scans;
        double pct_ofilt  = 100.0 * m->open_filtered_ports / m->total_scans;
        double pct_unk    = 100.0 * m->unknown_ports     / m->total_scans;

        const int RIBBON_W = 40;

        int seg_open  = (int)(pct_open  / 100.0 * RIBBON_W + 0.5);
        int seg_close = (int)(pct_closed / 100.0 * RIBBON_W + 0.5);
        int seg_filt  = (int)(pct_filt  / 100.0 * RIBBON_W + 0.5);
        int seg_ofilt = (int)(pct_ofilt / 100.0 * RIBBON_W + 0.5);
        int seg_unk   = RIBBON_W - seg_open - seg_close - seg_filt - seg_ofilt;
        if (seg_unk < 0) seg_unk = 0;

        printf(" ");

        /* Open = green bg */
        if (seg_open > 0)
        {
            printf("%s%s", clr(CLR_BG_GREEN), clr(CLR_BOLD));
            for (int i = 0; i < seg_open; i++) printf(" ");
            printf("%s", clr(CLR_RESET));
        }
        /* Closed = red bg */
        if (seg_close > 0)
        {
            printf("%s%s", clr(CLR_BG_RED), clr(CLR_BOLD));
            for (int i = 0; i < seg_close; i++) printf(" ");
            printf("%s", clr(CLR_RESET));
        }
        /* Filtered = yellow bg */
        if (seg_filt > 0)
        {
            printf("%s%s", clr(CLR_BG_YELLOW), clr(CLR_BOLD));
            for (int i = 0; i < seg_filt; i++) printf(" ");
            printf("%s", clr(CLR_RESET));
        }
        /* Open|Filtered = magenta bg */
        if (seg_ofilt > 0)
        {
            printf("%s%s", clr(CLR_BG_MAGENTA), clr(CLR_BOLD));
            for (int i = 0; i < seg_ofilt; i++) printf(" ");
            printf("%s", clr(CLR_RESET));
        }
        /* Unknown = white bg */
        if (seg_unk > 0)
        {
            printf("%s", clr(CLR_BG_WHITE));
            for (int i = 0; i < seg_unk; i++) printf(" ");
            printf("%s", clr(CLR_RESET));
        }

        /* Percentage labels to the right of the ribbon */
        printf("  %s%s%.0f%%%s",
               clr(CLR_BOLD), clr(CLR_GREEN),
               pct_open, clr(CLR_RESET));
        printf(" %s%s%.0f%%%s",
               clr(CLR_BOLD), clr(CLR_RED),
               pct_closed, clr(CLR_RESET));
        if (pct_filt > 0.0)
            printf(" %s%s%.0f%%%s",
                   clr(CLR_BOLD), clr(CLR_YELLOW),
                   pct_filt, clr(CLR_RESET));

        /* pad remaining */
        /* approximate visible chars used: 1 + RIBBON_W + pct labels ~18 */
        int used = 1 + RIBBON_W + 18;
        int remaining = BOX_INNER_W - used;
        for (int i = 0; i < remaining; i++)
            printf(" ");
    }
    else
    {
        printf(" %sNo scan data available.%s",
               clr(CLR_DIM), clr(CLR_RESET));
        int pad = BOX_INNER_W - 25;
        for (int i = 0; i < pad; i++)
            printf(" ");
    }

    printf("%s%s%s\n", clr(CLR_DIM), BOX_V, clr(CLR_RESET));

    /* ── Legend ──────────────────────────────────────────────────── */
    inner_sep(BOX_INNER_W);

    printf("  %s%s%s ", clr(CLR_DIM), BOX_V, clr(CLR_RESET));
    {
        int vis_len = 0;
        printf(" %s%s■%s Open  ",
               clr(CLR_BOLD), clr(CLR_GREEN), clr(CLR_RESET));
        vis_len += 10;

        printf("%s%s■%s Closed  ",
               clr(CLR_BOLD), clr(CLR_RED), clr(CLR_RESET));
        vis_len += 11;

        printf("%s%s■%s Filtered  ",
               clr(CLR_BOLD), clr(CLR_YELLOW), clr(CLR_RESET));
        vis_len += 13;

        printf("%s%s■%s Open|Filt  ",
               clr(CLR_BOLD), clr(CLR_MAGENTA), clr(CLR_RESET));
        vis_len += 14;

        printf("%s%s■%s Unknown",
               clr(CLR_BOLD), clr(CLR_DIM), clr(CLR_RESET));
        vis_len += 10;

        int pad = BOX_INNER_W - vis_len - 1;
        for (int i = 0; i < pad; i++)
            printf(" ");
    }
    printf("%s%s%s\n", clr(CLR_DIM), BOX_V, clr(CLR_RESET));

    /* ── Bottom border ──────────────────────────────────────────── */
    hline(BOX_BL, BOX_BR, BOX_INNER_W);

    printf("\n");
}
