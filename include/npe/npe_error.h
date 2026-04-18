/*****************************************************************************
 * npe_error.h — Error codes and error handling
 *****************************************************************************/

#ifndef NPE_ERROR_H
#define NPE_ERROR_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return a human-readable string for the given error code.
 * The returned pointer is to static storage; do not free.
 */
const char *npe_error_string(npe_error_t err);

/**
 * Log an error with contextual information.
 *
 * @param err      Error code.
 * @param module   Module name (e.g. "loader", "scheduler").
 * @param fmt      printf-style format string.
 */
void npe_error_log(npe_error_t err,
                   const char *module,
                   const char *fmt, ...);

/**
 * Extract the error message from a Lua state after a pcall failure.
 * Returns a heap-allocated string; caller must free().
 * Returns NULL if no error message is available.
 */
char *npe_error_from_lua(void *lua_state);

/**
 * Error handler callback type.
 */
typedef void (*npe_error_handler_fn)(npe_error_t  err,
                                     const char  *module,
                                     const char  *message,
                                     void        *userdata);

/**
 * Set a global error handler callback.
 * Pass NULL to revert to the default (stderr) handler.
 */
void npe_error_set_handler(npe_error_handler_fn fn, void *userdata);

/**
 * Translate an errno value to the closest npe_error_t.
 */
npe_error_t npe_error_from_errno(int err_no);

#ifdef __cplusplus
}
#endif

#endif /* NPE_ERROR_H */
