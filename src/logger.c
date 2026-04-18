#include "logger.h"
#include <stdbool.h>

static np_log_level_t log_level = NP_LOG_DEBUG;
static bool log_verbose = false;

void np_logger_init(np_log_level_t level, FILE *out)
{
    log_level = level;
    np_error_set_verbosity(level);
    if (out && out != stderr)
        np_error_set_sink_file(out, false);
    else
        np_error_set_sink_stderr();
}

void np_logger_set_level(np_log_level_t level)
{
    log_level = level;
    np_error_set_verbosity(level);
}

void np_logger_set_verbose(bool enabled)
{
    log_verbose = enabled;
    if (enabled && np_error_get_verbosity() < NP_LOG_VERBOSE)
        np_error_set_verbosity(NP_LOG_VERBOSE);
}

void np_log(np_log_level_t level, const char *fmt, ...)
{
    if (level > log_level)
        return;
    if (!log_verbose && level >= NP_LOG_INFO)
        return;

    va_list args;
    va_start(args, fmt);
    np_verror(NP_ERR_RUNTIME, fmt, args);
    va_end(args);
}

bool np_logger_is_verbose(void)
{
    return log_verbose;
}
