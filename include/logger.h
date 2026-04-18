#ifndef NP_LOGGER_H
#define NP_LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "core/error.h"

typedef np_log_verbosity_t np_log_level_t;

#define NP_LOG_ERROR NP_LOG_NORMAL
#define NP_LOG_WARN NP_LOG_NORMAL
#define NP_LOG_INFO NP_LOG_VERBOSE
#define NP_LOG_TRACE_LVL NP_LOG_TRACE

void np_logger_init(np_log_level_t level, FILE *out);
void np_logger_set_level(np_log_level_t level);
void np_logger_set_verbose(bool enabled);
bool np_logger_is_verbose(void);   /* ← NEW */
void np_log(np_log_level_t level, const char *fmt, ...);

#define LOGE(...) np_error(NP_ERR_RUNTIME, __VA_ARGS__)
#define LOGW(...) np_error(NP_ERR_RUNTIME, __VA_ARGS__)
#define LOGI(...) np_log(NP_LOG_INFO, __VA_ARGS__)
#define LOGD(...) np_log(NP_LOG_DEBUG, __VA_ARGS__)
#define LOGT(...) np_log(NP_LOG_TRACE_LVL, __VA_ARGS__)

#endif /* NP_LOGGER_H */
