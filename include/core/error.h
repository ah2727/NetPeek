#ifndef NP_CORE_ERROR_H
#define NP_CORE_ERROR_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

typedef enum
{
    NP_ERR_NET = 0,
    NP_ERR_IO,
    NP_ERR_PARSE,
    NP_ERR_RUNTIME,
    NP_ERR_NPE,
    NP_ERR_OS
} np_err_t;

typedef enum
{
    NP_LOG_QUIET = 0,
    NP_LOG_NORMAL,
    NP_LOG_VERBOSE,
    NP_LOG_DEBUG,
    NP_LOG_TRACE
} np_log_verbosity_t;

typedef enum
{
    NP_ERR_SINK_STDERR = 0,
    NP_ERR_SINK_FILE,
    NP_ERR_SINK_SYSLOG,
    NP_ERR_SINK_CALLBACK
} np_err_sink_t;

typedef void (*np_error_callback_t)(const char *timestamp,
                                    np_log_verbosity_t level,
                                    np_err_t code,
                                    const char *message,
                                    void *user);

void np_error(np_err_t code, const char *fmt, ...);
void np_verror(np_err_t code, const char *fmt, va_list ap);
void np_perror(const char *ctx);

void np_error_set_verbosity(np_log_verbosity_t level);
np_log_verbosity_t np_error_get_verbosity(void);

void np_error_set_sink_stderr(void);
bool np_error_set_sink_file(FILE *fp, bool own_file);
bool np_error_set_sink_file_path(const char *path);
bool np_error_set_sink_syslog(const char *ident);
void np_error_set_sink_callback(np_error_callback_t callback, void *user);
void np_error_shutdown(void);

bool np_error_parse_verbosity(const char *value, np_log_verbosity_t *out);
void np_error_init_from_env(void);

#endif
