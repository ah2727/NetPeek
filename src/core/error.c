#define _POSIX_C_SOURCE 200809L

#include "core/error.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__APPLE__) || defined(__linux__)
#include <syslog.h>
#define NP_HAS_SYSLOG 1
#else
#define NP_HAS_SYSLOG 0
#endif

typedef struct
{
    pthread_mutex_t lock;
    np_log_verbosity_t verbosity;
    np_err_sink_t sink;
    FILE *file;
    bool own_file;
    np_error_callback_t callback;
    void *callback_user;
    bool env_initialized;
    bool syslog_open;
} np_error_state_t;

static np_error_state_t g_error = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .verbosity = NP_LOG_NORMAL,
    .sink = NP_ERR_SINK_STDERR,
    .file = NULL,
    .own_file = false,
    .callback = NULL,
    .callback_user = NULL,
    .env_initialized = false,
    .syslog_open = false,
};

static const char *verbosity_str(np_log_verbosity_t level)
{
    switch (level)
    {
    case NP_LOG_QUIET:
        return "QUIET";
    case NP_LOG_NORMAL:
        return "NORMAL";
    case NP_LOG_VERBOSE:
        return "VERBOSE";
    case NP_LOG_DEBUG:
        return "DEBUG";
    case NP_LOG_TRACE:
        return "TRACE";
    default:
        return "UNKNOWN";
    }
}

static const char *err_str(np_err_t code)
{
    switch (code)
    {
    case NP_ERR_NET:
        return "NET";
    case NP_ERR_IO:
        return "IO";
    case NP_ERR_PARSE:
        return "PARSE";
    case NP_ERR_RUNTIME:
        return "RUNTIME";
    case NP_ERR_NPE:
        return "NPE";
    case NP_ERR_OS:
        return "OS";
    default:
        return "UNKNOWN";
    }
}

static np_log_verbosity_t code_level(np_err_t code)
{
    switch (code)
    {
    case NP_ERR_NET:
    case NP_ERR_IO:
    case NP_ERR_PARSE:
    case NP_ERR_OS:
        return NP_LOG_NORMAL;
    case NP_ERR_RUNTIME:
    case NP_ERR_NPE:
        return NP_LOG_VERBOSE;
    default:
        return NP_LOG_NORMAL;
    }
}

static void format_timestamp(char *out, size_t out_len)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    snprintf(out,
             out_len,
             "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tmv.tm_year + 1900,
             tmv.tm_mon + 1,
             tmv.tm_mday,
             tmv.tm_hour,
             tmv.tm_min,
             tmv.tm_sec,
             ts.tv_nsec / 1000000L);
}

static bool should_emit(np_err_t code)
{
    if (g_error.verbosity == NP_LOG_QUIET)
        return false;

    return code_level(code) <= g_error.verbosity;
}

bool np_error_parse_verbosity(const char *value, np_log_verbosity_t *out)
{
    if (!value || !out)
        return false;

    if (strcmp(value, "quiet") == 0)
        *out = NP_LOG_QUIET;
    else if (strcmp(value, "normal") == 0)
        *out = NP_LOG_NORMAL;
    else if (strcmp(value, "verbose") == 0)
        *out = NP_LOG_VERBOSE;
    else if (strcmp(value, "debug") == 0)
        *out = NP_LOG_DEBUG;
    else if (strcmp(value, "trace") == 0)
        *out = NP_LOG_TRACE;
    else
        return false;

    return true;
}

void np_error_init_from_env(void)
{
    pthread_mutex_lock(&g_error.lock);
    if (g_error.env_initialized)
    {
        pthread_mutex_unlock(&g_error.lock);
        return;
    }
    g_error.env_initialized = true;

    const char *v = getenv("NP_LOG_VERBOSITY");
    np_log_verbosity_t lvl;
    if (v && np_error_parse_verbosity(v, &lvl))
        g_error.verbosity = lvl;

    const char *sink = getenv("NP_LOG_SINK");
    if (sink && strcmp(sink, "file") == 0)
    {
        const char *path = getenv("NP_LOG_FILE");
        if (path)
        {
            FILE *fp = fopen(path, "a");
            if (fp)
            {
                g_error.sink = NP_ERR_SINK_FILE;
                g_error.file = fp;
                g_error.own_file = true;
            }
        }
    }
    else if (sink && strcmp(sink, "syslog") == 0)
    {
#if NP_HAS_SYSLOG
        openlog("netpeek", LOG_PID | LOG_NDELAY, LOG_USER);
        g_error.sink = NP_ERR_SINK_SYSLOG;
        g_error.syslog_open = true;
#endif
    }

    pthread_mutex_unlock(&g_error.lock);
}

void np_error_set_verbosity(np_log_verbosity_t level)
{
    pthread_mutex_lock(&g_error.lock);
    g_error.verbosity = level;
    pthread_mutex_unlock(&g_error.lock);
}

np_log_verbosity_t np_error_get_verbosity(void)
{
    np_log_verbosity_t level;
    pthread_mutex_lock(&g_error.lock);
    level = g_error.verbosity;
    pthread_mutex_unlock(&g_error.lock);
    return level;
}

void np_error_set_sink_stderr(void)
{
    pthread_mutex_lock(&g_error.lock);
    if (g_error.own_file && g_error.file)
        fclose(g_error.file);
    g_error.sink = NP_ERR_SINK_STDERR;
    g_error.file = NULL;
    g_error.own_file = false;
    g_error.callback = NULL;
    g_error.callback_user = NULL;
    pthread_mutex_unlock(&g_error.lock);
}

bool np_error_set_sink_file(FILE *fp, bool own_file)
{
    if (!fp)
        return false;

    pthread_mutex_lock(&g_error.lock);
    if (g_error.own_file && g_error.file)
        fclose(g_error.file);
    g_error.sink = NP_ERR_SINK_FILE;
    g_error.file = fp;
    g_error.own_file = own_file;
    g_error.callback = NULL;
    g_error.callback_user = NULL;
    pthread_mutex_unlock(&g_error.lock);
    return true;
}

bool np_error_set_sink_file_path(const char *path)
{
    if (!path)
        return false;

    FILE *fp = fopen(path, "a");
    if (!fp)
        return false;

    return np_error_set_sink_file(fp, true);
}

bool np_error_set_sink_syslog(const char *ident)
{
#if NP_HAS_SYSLOG
    pthread_mutex_lock(&g_error.lock);
    if (g_error.own_file && g_error.file)
        fclose(g_error.file);
    openlog(ident ? ident : "netpeek", LOG_PID | LOG_NDELAY, LOG_USER);
    g_error.sink = NP_ERR_SINK_SYSLOG;
    g_error.file = NULL;
    g_error.own_file = false;
    g_error.callback = NULL;
    g_error.callback_user = NULL;
    g_error.syslog_open = true;
    pthread_mutex_unlock(&g_error.lock);
    return true;
#else
    (void)ident;
    return false;
#endif
}

void np_error_set_sink_callback(np_error_callback_t callback, void *user)
{
    pthread_mutex_lock(&g_error.lock);
    if (g_error.own_file && g_error.file)
        fclose(g_error.file);
    g_error.sink = NP_ERR_SINK_CALLBACK;
    g_error.file = NULL;
    g_error.own_file = false;
    g_error.callback = callback;
    g_error.callback_user = user;
    pthread_mutex_unlock(&g_error.lock);
}

void np_verror(np_err_t code, const char *fmt, va_list ap)
{
    np_error_init_from_env();

    pthread_mutex_lock(&g_error.lock);
    if (!should_emit(code))
    {
        pthread_mutex_unlock(&g_error.lock);
        return;
    }

    char ts[64];
    format_timestamp(ts, sizeof(ts));

    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    switch (g_error.sink)
    {
    case NP_ERR_SINK_STDERR:
    {
        char line[2304];
        snprintf(line, sizeof(line), "%s [%s] [%s] %s\n", ts, verbosity_str(g_error.verbosity), err_str(code), msg);
        fputs(line, stderr);
        break;
    }
    case NP_ERR_SINK_FILE:
        if (g_error.file)
        {
            char line[2304];
            snprintf(line, sizeof(line), "%s [%s] [%s] %s\n", ts, verbosity_str(g_error.verbosity), err_str(code), msg);
            fputs(line, g_error.file);
            fflush(g_error.file);
        }
        break;
    case NP_ERR_SINK_SYSLOG:
#if NP_HAS_SYSLOG
        syslog(LOG_ERR, "[%s] %s", err_str(code), msg);
#endif
        break;
    case NP_ERR_SINK_CALLBACK:
        if (g_error.callback)
            g_error.callback(ts, g_error.verbosity, code, msg, g_error.callback_user);
        break;
    }

    pthread_mutex_unlock(&g_error.lock);
}

void np_error(np_err_t code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    np_verror(code, fmt, ap);
    va_end(ap);
}

void np_perror(const char *ctx)
{
    int e = errno;
    if (!ctx)
        ctx = "errno";
    np_error(NP_ERR_OS, "%s: %s", ctx, strerror(e));
}

void np_error_shutdown(void)
{
    pthread_mutex_lock(&g_error.lock);
    if (g_error.own_file && g_error.file)
        fclose(g_error.file);
    g_error.file = NULL;
    g_error.own_file = false;
    g_error.callback = NULL;
    g_error.callback_user = NULL;
#if NP_HAS_SYSLOG
    if (g_error.syslog_open)
    {
        closelog();
        g_error.syslog_open = false;
    }
#endif
    pthread_mutex_unlock(&g_error.lock);
}
