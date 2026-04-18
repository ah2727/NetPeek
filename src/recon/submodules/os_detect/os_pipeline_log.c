#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "logger.h"

typedef enum
{
    NP_PIPE_LOG_INFO  = 0,
    NP_PIPE_LOG_WARN  = 1,
    NP_PIPE_LOG_ERR   = 2,
    NP_PIPE_LOG_DEBUG = 3
} np_pipe_log_level_t;

static const char *log_level_str[] = {
    "INFO", "WARN", "ERR ", "DBG "
};

void pipe_log(np_pipe_log_level_t level, const char *stage,
              const char *fmt, ...)
{
    /* ── Gate: only errors bypass verbose check ── */
    if (level != NP_PIPE_LOG_ERR && !np_logger_is_verbose())
        return;

    if (level < NP_PIPE_LOG_INFO || level > NP_PIPE_LOG_DEBUG)
        level = NP_PIPE_LOG_INFO;

    va_list ap;
    va_start(ap, fmt);
    np_error(NP_ERR_RUNTIME, "[netpeek][pipeline][%s][%s] ",
            log_level_str[level], stage);
    np_verror(NP_ERR_RUNTIME, fmt, ap);
    np_error(NP_ERR_RUNTIME, "\n");
    va_end(ap);
}
