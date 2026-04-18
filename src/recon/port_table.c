#include "recon/port_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/ioctl.h>
#include <unistd.h>
#endif

enum { NP_PORT_TABLE_COLS = 5 };

typedef struct {
    const char *h;
    size_t min_w;
    size_t max_w;
} np_col_def_t;

typedef struct {
    const char *h;
    const char *v;
    const char *tl;
    const char *tm;
    const char *tr;
    const char *ml;
    const char *mm;
    const char *mr;
    const char *bl;
    const char *bm;
    const char *br;
} np_border_t;

static int np_fp_is_tty(FILE *fp)
{
#ifndef _WIN32
    return fp && isatty(fileno(fp)) == 1;
#else
    (void)fp;
    return 0;
#endif
}

static bool np_env_utf8(const char *v)
{
    if (!v || !v[0])
        return false;

    return strstr(v, "UTF-8") || strstr(v, "utf-8") || strstr(v, "UTF8") || strstr(v, "utf8");
}

static bool np_use_unicode(FILE *fp, const np_port_table_opts_t *opts)
{
    if (opts && opts->force_ascii)
        return false;
    if (!np_fp_is_tty(fp))
        return false;

    if (np_env_utf8(getenv("LC_ALL")))
        return true;
    if (np_env_utf8(getenv("LC_CTYPE")))
        return true;
    return np_env_utf8(getenv("LANG"));
}

static int np_term_columns(FILE *fp)
{
    int cols = 80;
    const char *env_cols = getenv("COLUMNS");
    if (env_cols && env_cols[0])
    {
        int parsed = atoi(env_cols);
        if (parsed > 20)
            cols = parsed;
    }

#ifndef _WIN32
    if (np_fp_is_tty(fp))
    {
        struct winsize ws;
        if (ioctl(fileno(fp), TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
            cols = (int)ws.ws_col;
    }
#else
    (void)fp;
#endif

    return cols;
}

static size_t np_strwidth(const char *s)
{
    return s ? strlen(s) : 0;
}

static void np_print_hr(FILE *fp,
                        const char *indent,
                        const np_border_t *b,
                        const size_t widths[NP_PORT_TABLE_COLS],
                        const char *l,
                        const char *m,
                        const char *r)
{
    fprintf(fp, "%s%s", indent, l);
    for (int i = 0; i < NP_PORT_TABLE_COLS; i++)
    {
        for (size_t j = 0; j < widths[i] + 2; j++)
            fputs(b->h, fp);
        if (i < NP_PORT_TABLE_COLS - 1)
            fputs(m, fp);
    }
    fprintf(fp, "%s\n", r);
}

static void np_print_cell(FILE *fp, const char *text, size_t width)
{
    const char *s = text ? text : "-";
    size_t len = strlen(s);

    if (len <= width)
    {
        fprintf(fp, "%-*s", (int)width, s);
        return;
    }

    if (width <= 3)
    {
        for (size_t i = 0; i < width; i++)
            fputc('.', fp);
        return;
    }

    fwrite(s, 1, width - 3, fp);
    fputs("...", fp);
}

static void np_print_row(FILE *fp,
                         const char *indent,
                         const np_border_t *b,
                         const size_t widths[NP_PORT_TABLE_COLS],
                         const char *c1,
                         const char *c2,
                         const char *c3,
                         const char *c4,
                         const char *c5)
{
    const char *cells[NP_PORT_TABLE_COLS] = {c1, c2, c3, c4, c5};

    fprintf(fp, "%s%s", indent, b->v);
    for (int i = 0; i < NP_PORT_TABLE_COLS; i++)
    {
        fputc(' ', fp);
        np_print_cell(fp, cells[i], widths[i]);
        fputc(' ', fp);
        fputs(b->v, fp);
    }
    fputc('\n', fp);
}

void np_port_table_render(FILE *fp,
                          const np_port_table_row_t *rows,
                          uint32_t row_count,
                          const np_port_table_opts_t *opts)
{
    if (!fp)
        return;

    static const np_col_def_t cols[NP_PORT_TABLE_COLS] = {
        {.h = "Port", .min_w = 4, .max_w = 5},
        {.h = "Proto", .min_w = 5, .max_w = 5},
        {.h = "Service", .min_w = 7, .max_w = 24},
        {.h = "State", .min_w = 5, .max_w = 13},
        {.h = "Version", .min_w = 7, .max_w = 30},
    };

    static const np_border_t unicode = {
        .h = "─", .v = "│",
        .tl = "┌", .tm = "┬", .tr = "┐",
        .ml = "├", .mm = "┼", .mr = "┤",
        .bl = "└", .bm = "┴", .br = "┘",
    };
    static const np_border_t ascii = {
        .h = "-", .v = "|",
        .tl = "+", .tm = "+", .tr = "+",
        .ml = "+", .mm = "+", .mr = "+",
        .bl = "+", .bm = "+", .br = "+",
    };

    const char *indent = (opts && opts->indent) ? opts->indent : "";
    const np_border_t *b = np_use_unicode(fp, opts) ? &unicode : &ascii;
    size_t widths[NP_PORT_TABLE_COLS];

    for (int i = 0; i < NP_PORT_TABLE_COLS; i++)
        widths[i] = np_strwidth(cols[i].h);

    for (uint32_t i = 0; i < row_count; i++)
    {
        const char *cells[NP_PORT_TABLE_COLS] = {
            rows[i].port,
            rows[i].proto,
            rows[i].service,
            rows[i].state,
            rows[i].version,
        };

        for (int c = 0; c < NP_PORT_TABLE_COLS; c++)
        {
            size_t len = np_strwidth(cells[c][0] ? cells[c] : "-");
            if (len > widths[c])
                widths[c] = len;
        }
    }

    for (int i = 0; i < NP_PORT_TABLE_COLS; i++)
    {
        if (widths[i] < cols[i].min_w)
            widths[i] = cols[i].min_w;
        if (widths[i] > cols[i].max_w)
            widths[i] = cols[i].max_w;
    }

    int term_cols = np_term_columns(fp);
    int avail = term_cols - (int)strlen(indent);
    if (avail < 40)
        avail = 40;

    size_t total = (size_t)(NP_PORT_TABLE_COLS + 1);
    for (int i = 0; i < NP_PORT_TABLE_COLS; i++)
        total += widths[i] + 2;

    while ((int)total > avail)
    {
        bool shrank = false;
        int shrink_order[NP_PORT_TABLE_COLS] = {4, 2, 3, 1, 0};
        for (int s = 0; s < NP_PORT_TABLE_COLS; s++)
        {
            int idx = shrink_order[s];
            if (widths[idx] > cols[idx].min_w)
            {
                widths[idx]--;
                total--;
                shrank = true;
                break;
            }
        }
        if (!shrank)
            break;
    }

    np_print_hr(fp, indent, b, widths, b->tl, b->tm, b->tr);
    np_print_row(fp, indent, b, widths,
                 cols[0].h, cols[1].h, cols[2].h, cols[3].h, cols[4].h);
    np_print_hr(fp, indent, b, widths, b->ml, b->mm, b->mr);

    if (row_count == 0)
    {
        np_print_row(fp, indent, b, widths, "-", "-", "none", "-", "-");
    }
    else
    {
        for (uint32_t i = 0; i < row_count; i++)
            np_print_row(fp, indent, b, widths,
                         rows[i].port[0] ? rows[i].port : "-",
                         rows[i].proto[0] ? rows[i].proto : "-",
                         rows[i].service[0] ? rows[i].service : "-",
                         rows[i].state[0] ? rows[i].state : "-",
                         rows[i].version[0] ? rows[i].version : "-");
    }

    np_print_hr(fp, indent, b, widths, b->bl, b->bm, b->br);
}
