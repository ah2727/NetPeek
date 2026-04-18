/*
 * ui/style.h — Shared ANSI / Unicode / box-drawing constants
 *
 * Included by output_*.c files.  Never defines types — only presentation.
 */

#ifndef NP_OUTPUT_STYLE_H
#define NP_OUTPUT_STYLE_H

#include <stdio.h>

/* ── ANSI color codes ──────────────────────────────────────────── */
#define CLR_RESET         "\033[0m"
#define CLR_BOLD          "\033[1m"
#define CLR_DIM           "\033[2m"
#define CLR_ITALIC        "\033[3m"
#define CLR_UNDERLINE     "\033[4m"
#define CLR_GREEN         "\033[32m"
#define CLR_RED           "\033[31m"
#define CLR_YELLOW        "\033[33m"
#define CLR_CYAN          "\033[36m"
#define CLR_MAGENTA       "\033[35m"
#define CLR_BLUE          "\033[34m"
#define CLR_BRIGHT_CYAN   "\033[96m"
#define CLR_BRIGHT_GREEN  "\033[92m"
#define CLR_BRIGHT_RED    "\033[91m"
#define CLR_BRIGHT_YELLOW "\033[93m"
#define CLR_WHITE         "\033[97m"
#define CLR_BG_GREEN      "\033[42m"
#define CLR_BG_RED        "\033[41m"
#define CLR_BG_YELLOW     "\033[43m"
#define CLR_BG_CYAN       "\033[46m"

/* ── Box-drawing ───────────────────────────────────────────────── */
#define BOX_H     "─"
#define BOX_V     "│"
#define BOX_TL    "┌"
#define BOX_TR    "┐"
#define BOX_BL    "└"
#define BOX_BR    "┘"
#define BOX_LT    "├"
#define BOX_RT    "┤"
#define BOX_CROSS "┼"
#define BOX_TT    "┬"
#define BOX_BT    "┴"

/* ── Icons (Unicode) ───────────────────────────────────────────── */
#define ICON_OS        "🖥"
#define ICON_TARGET    "🎯"
#define ICON_LOCK      "🔒"
#define ICON_CHECK     "✔"
#define ICON_CROSS     "✖"
#define ICON_WARN      "⚠"
#define ICON_INFO      "ℹ"
#define ICON_FINGER    "🔬"
#define ICON_BANNER    "📜"
#define ICON_GAUGE     "📊"
#define ICON_PROBE     "📡"
#define ICON_CLOCK     "⏱"
#define ICON_GRAPH     "📈"
#define ICON_GUESS     "🤔"
#define ICON_NET       "🌐"
#define ICON_DB        "🗄"
#define ICON_BAR_FULL  "█"
#define ICON_BAR_MED   "▓"
#define ICON_BAR_HALF  "▒"
#define ICON_BAR_LOW   "░"
#define ICON_DOT       "●"
#define ICON_ARROW     "➜"
#define ICON_DIAMOND   "◆"
#define ICON_STAR      "★"

/* ── TTY detection ─────────────────────────────────────────────── */
#ifndef _WIN32
#include <unistd.h>
static inline int np_fp_is_tty(FILE *fp) { return isatty(fileno(fp)); }
#else
#include <io.h>
static inline int np_fp_is_tty(FILE *fp) { return _isatty(_fileno(fp)); }
#endif

/*
 * np_clr() — return the ANSI code only when writing to a TTY,
 *            otherwise return "".
 */
static inline const char *np_clr(FILE *fp, const char *code)
{
    return np_fp_is_tty(fp) ? code : "";
}

/* ── Drawing helpers ───────────────────────────────────────────── */

static inline void np_hline(FILE *fp, const char *left,
                            const char *right, int w)
{
    fprintf(fp, "  %s%s", np_clr(fp, CLR_DIM), left);
    for (int i = 0; i < w; i++)
        fprintf(fp, "%s", BOX_H);
    fprintf(fp, "%s%s\n", right, np_clr(fp, CLR_RESET));
}

static inline void np_hline_multi(FILE *fp, const char *left,
                                  const char *mid, const char *right,
                                  const int *cols, int ncols)
{
    fprintf(fp, "  %s%s", np_clr(fp, CLR_DIM), left);
    for (int c = 0; c < ncols; c++) {
        for (int i = 0; i < cols[c] + 2; i++)
            fprintf(fp, "%s", BOX_H);
        if (c < ncols - 1)
            fprintf(fp, "%s", mid);
    }
    fprintf(fp, "%s%s\n", right, np_clr(fp, CLR_RESET));
}

static inline void np_confidence_bar(FILE *fp, unsigned int pct, int width)
{
    const char *bar_clr;
    if      (pct >= 80) bar_clr = CLR_BRIGHT_GREEN;
    else if (pct >= 50) bar_clr = CLR_YELLOW;
    else if (pct >= 25) bar_clr = CLR_BRIGHT_YELLOW;
    else                bar_clr = CLR_BRIGHT_RED;

    int filled = (int)((double)pct / 100.0 * width + 0.5);
    if (filled > width) filled = width;

    fprintf(fp, "%s%s", np_clr(fp, CLR_BOLD), np_clr(fp, bar_clr));
    for (int i = 0; i < filled; i++)
        fprintf(fp, "%s", ICON_BAR_FULL);
    fprintf(fp, "%s", np_clr(fp, CLR_DIM));
    for (int i = filled; i < width; i++)
        fprintf(fp, "%s", ICON_BAR_LOW);
    fprintf(fp, "%s", np_clr(fp, CLR_RESET));
}

static inline void np_print_confidence(FILE *fp, unsigned int pct)
{
    const char *clr;
    if      (pct >= 80) clr = CLR_BRIGHT_GREEN;
    else if (pct >= 50) clr = CLR_YELLOW;
    else if (pct >= 25) clr = CLR_BRIGHT_YELLOW;
    else                clr = CLR_BRIGHT_RED;

    fprintf(fp, "%s%s%u%%%s",
            np_clr(fp, CLR_BOLD), np_clr(fp, clr), pct,
            np_clr(fp, CLR_RESET));
}

#endif /* NP_OUTPUT_STYLE_H */
