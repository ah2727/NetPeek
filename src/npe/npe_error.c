/*****************************************************************************
 * npe_error.c — Error codes, message lookup, and reporting
 * Provides human-readable messages for every npe_error_t value, a pluggable
 * error-handler callback, errno translation, and Lua pcall error extraction.
 *****************************************************************************/

#include "npe_error.h"
#include "core/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

/*============================================================================
 * Internal: Error String Table
 *============================================================================*/

typedef struct {
    npe_error_t  code;
    const char  *message;
} npe_error_entry_t;

static const npe_error_entry_t error_table[] = {
    { NPE_OK,                          "Success"                                },
    { NPE_ERROR_GENERIC,               "Generic error"                          },
    { NPE_ERROR_MEMORY,                "Out of memory"                          },
    { NPE_ERROR_INVALID_ARG,           "Invalid argument"                       },
    { NPE_ERROR_NOT_FOUND,             "Resource not found"                     },
    { NPE_ERROR_TIMEOUT,               "Operation timed out"                    },
    { NPE_ERROR_CONNECTION,            "Connection error"                       },
    { NPE_ERROR_PERMISSION,            "Permission denied"                      },
    { NPE_ERROR_SCRIPT_SYNTAX,         "Script syntax/load error"               },
    { NPE_ERROR_SCRIPT_RUNTIME,        "Script runtime error"                   },
    { NPE_ERROR_SCRIPT_ABORTED,        "Script aborted/cancelled"               },
    { NPE_ERROR_SANDBOX_VIOLATION,     "Sandbox violation"                      },
    { NPE_ERROR_DEPENDENCY,            "Dependency error"                       },
    { NPE_ERROR_UNSUPPORTED,           "Unsupported operation"                  },
    { NPE_ERROR_IO,                    "I/O error"                              },
    { NPE_ERROR_PARSE,                 "Parse error"                            },
    { NPE_ERROR_SSL,                   "SSL/TLS error"                          },
    { NPE_ERROR_DNS,                   "DNS resolution error"                   },
    { NPE_ERROR_PROTOCOL,              "Protocol error"                         },
};

#define ERROR_TABLE_SIZE  (sizeof(error_table) / sizeof(error_table[0]))

/*============================================================================
 * Internal: Global Error Handler Callback
 *============================================================================*/

static pthread_mutex_t      g_handler_lock  = PTHREAD_MUTEX_INITIALIZER;
static npe_error_handler_fn g_handler_fn    = NULL;
static void                *g_handler_udata = NULL;

/*============================================================================
 * Internal Helpers
 *============================================================================*/

/**
 * Write a timestamp prefix into buf (ISO-8601 local time with milliseconds).
 * Returns the number of characters written.
 */
static int
write_timestamp(char *buf, size_t bufsz)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_local;
    localtime_r(&ts.tv_sec, &tm_local);

    int n = (int)strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%S", &tm_local);
    n += snprintf(buf + n, bufsz - (size_t)n, ".%03ld",
                  ts.tv_nsec / 1000000L);
    return n;
}

/**
 * Default error handler — prints to stderr.
 */
static void
default_error_handler(npe_error_t  err,
                      const char  *module,
                      const char  *message,
                      void        *userdata)
{
    (void)userdata;

    char ts[64];
    write_timestamp(ts, sizeof(ts));

    np_error(NP_ERR_RUNTIME, "[%s] NPE ERROR (%s) [%s]: %s\n",
            ts,
            npe_error_string(err),
            module ? module : "unknown",
            message ? message : "(no message)");
}

/*============================================================================
 * Public API: Error String Lookup
 *============================================================================*/

const char *
npe_error_string(npe_error_t err)
{
    for (size_t i = 0; i < ERROR_TABLE_SIZE; i++) {
        if (error_table[i].code == err)
            return error_table[i].message;
    }
    return "Unknown error code";
}

/*============================================================================
 * Public API: Error Logging
 *============================================================================*/

void
npe_error_log(npe_error_t  err,
              const char  *module,
              const char  *fmt, ...)
{
    if (!fmt)
        return;

    /* Format the caller's message. */
    char    msgbuf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
    va_end(ap);

    /* Dispatch to the registered (or default) handler. */
    pthread_mutex_lock(&g_handler_lock);
    npe_error_handler_fn fn    = g_handler_fn;
    void                *udata = g_handler_udata;
    pthread_mutex_unlock(&g_handler_lock);

    if (fn) {
        fn(err, module, msgbuf, udata);
    } else {
        default_error_handler(err, module, msgbuf, NULL);
    }
}

/*============================================================================
 * Public API: Lua Error Extraction
 *============================================================================*/

/*
 * We avoid including lua.h in the public header by accepting void*.
 * Internally we cast to lua_State* and use the Lua C API.
 */
#include <lua.h>
#include <lauxlib.h>

char *
npe_error_from_lua(void *lua_state)
{
    if (!lua_state)
        return NULL;

    lua_State *L = (lua_State *)lua_state;

    /* After a failed lua_pcall, the error object is on top of the stack. */
    if (lua_gettop(L) == 0)
        return NULL;

    const char *errmsg = NULL;

    if (lua_isstring(L, -1)) {
        errmsg = lua_tostring(L, -1);
    } else if (lua_isuserdata(L, -1) || lua_istable(L, -1)) {
        /*
         * Try __tostring metamethod for error objects.
         */
        if (luaL_callmeta(L, -1, "__tostring")) {
            errmsg = lua_tostring(L, -1);
            /* Pop the tostring result after we strdup it below. */
        }
    }

    char *result = NULL;
    if (errmsg) {
        result = strdup(errmsg);
    } else {
        /* Provide a generic message with the Lua type name. */
        const char *tname = lua_typename(L, lua_type(L, -1));
        size_t needed = strlen(tname) + 64;
        result = malloc(needed);
        if (result)
            snprintf(result, needed, "(non-string error object of type %s)", tname);
    }

    /* Pop the error object (and possible tostring result). */
    lua_settop(L, lua_gettop(L) - 1);

    return result;
}

/*============================================================================
 * Public API: Set/Clear Global Error Handler
 *============================================================================*/

void
npe_error_set_handler(npe_error_handler_fn fn, void *userdata)
{
    pthread_mutex_lock(&g_handler_lock);
    g_handler_fn    = fn;
    g_handler_udata = userdata;
    pthread_mutex_unlock(&g_handler_lock);
}

/*============================================================================
 * Public API: Translate errno → npe_error_t
 *============================================================================*/

npe_error_t
npe_error_from_errno(int err_no)
{
    switch (err_no) {
    case 0:
        return NPE_OK;

    case ENOMEM:
        return NPE_ERROR_MEMORY;

    case EINVAL:
        return NPE_ERROR_INVALID_ARG;

    case ENOENT:
    case ENODEV:
    case ESRCH:
        return NPE_ERROR_NOT_FOUND;

    case EIO:
    case EPIPE:
    case ENOSPC:
        return NPE_ERROR_IO;

    case ETIMEDOUT:
        return NPE_ERROR_TIMEOUT;

    case EACCES:
    case EPERM:
        return NPE_ERROR_PERMISSION;

    case ECONNREFUSED:
    case ECONNRESET:
    case ECONNABORTED:
    case ENETUNREACH:
    case EHOSTUNREACH:
        return NPE_ERROR_CONNECTION;

    case EAGAIN:
        return NPE_ERROR_TIMEOUT;

    case EEXIST:
        return NPE_ERROR_INVALID_ARG;

    case ECANCELED:
        return NPE_ERROR_SCRIPT_ABORTED;

    default:
        return NPE_ERROR_GENERIC;
    }
}
