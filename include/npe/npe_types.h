/* include/npe/npe_types.h */

#ifndef NPE_TYPES_H
#define NPE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* ── Legacy error names are forbidden ───────────────────────────── */
#ifdef NPE_ERROR_INVALID_ARG
#error "Use NPE_ERROR_INVALID_ARG instead of NPE_ERROR_INVALID_ARG"
#endif
#ifdef NPE_ERROR_PARSE
#error "Use NPE_ERROR_PARSE instead of NPE_ERROR_PARSE"
#endif
#ifdef NPE_ERROR_MEMORY
#error "Use NPE_ERROR_MEMORY instead of NPE_ERROR_MEMORY"
#endif

/*============================================================================
 * Version Information
 *============================================================================*/

#define NPE_VERSION_MAJOR 1
#define NPE_VERSION_MINOR 0
#define NPE_VERSION_PATCH 0
#define NPE_VERSION_STRING "1.0.0"

/*============================================================================
 * Configuration Limits
 *============================================================================*/

#define NPE_MAX_NAME 256 /* generic name buffer   */
#define NPE_MAX_SCRIPT_NAME 256
#define NPE_MAX_SCRIPT_AUTHOR 128
#define NPE_MAX_SCRIPT_DESC 1024
#define NPE_MAX_SCRIPT_CATEGORIES 16
#define NPE_MAX_SCRIPT_ARGS 64
#define NPE_MAX_DEPENDENCIES 32
#define NPE_MAX_PORTS_RULE 256
#define NPE_MAX_OUTPUT_SIZE (1024 * 1024) /* 1MB */
#define NPE_DEFAULT_TIMEOUT_MS 30000
#define NPE_MAX_CONCURRENT_SCRIPTS 256
#define NPE_SCRIPT_EXTENSION ".npe" /* script file suffix */

/*============================================================================
 * Forward Declarations
 *============================================================================*/

typedef struct npe_engine npe_engine_t;
typedef struct npe_script npe_script_t;
typedef struct npe_context npe_context_t;
typedef struct npe_result npe_result_t;
typedef struct npe_host npe_host_t;
typedef struct npe_port npe_port_t;
typedef struct npe_socket npe_socket_t;
typedef struct npe_buffer npe_buffer_t;
typedef struct npe_table npe_table_t;
typedef struct npe_value npe_value_t;
typedef struct npe_vm npe_vm_t;

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum npe_error
{
    NPE_OK = 0,
    NPE_ERROR_GENERIC = -1,
    NPE_ERROR_MEMORY = -2,
    NPE_ERROR_INVALID_ARG = -3,
    NPE_ERROR_NOT_FOUND = -4,
    NPE_ERROR_TIMEOUT = -5,
    NPE_ERROR_CONNECTION = -6,
    NPE_ERROR_PERMISSION = -7,
    NPE_ERROR_SCRIPT_SYNTAX = -8,
    NPE_ERROR_SCRIPT_RUNTIME = -9,
    NPE_ERROR_SCRIPT_ABORTED = -10,
    NPE_ERROR_SANDBOX_VIOLATION = -11,
    NPE_ERROR_DEPENDENCY = -12,
    NPE_ERROR_UNSUPPORTED = -13,
    NPE_ERROR_IO = -14,
    NPE_ERROR_PARSE = -15,
    NPE_ERROR_SSL = -16,
    NPE_ERROR_DNS = -17,
    NPE_ERROR_PROTOCOL = -18,
    NPE_ERROR_NOMEM = -19,
    NPE_ERROR_NOT_INIT = -20,
    NPE_ERROR_SYSTEM = -21
} npe_error_t;

/*============================================================================
 * Script Categories  (bitmask — combinable via OR)
 *============================================================================*/

typedef enum npe_category
{
    NPE_CAT_NONE = 0,
    NPE_CAT_AUTH = (1 << 0),
    NPE_CAT_BROADCAST = (1 << 1),
    NPE_CAT_BRUTE = (1 << 2),
    NPE_CAT_DEFAULT = (1 << 3),
    NPE_CAT_DISCOVERY = (1 << 4),
    NPE_CAT_DOS = (1 << 5),
    NPE_CAT_EXPLOIT = (1 << 6),
    NPE_CAT_EXTERNAL = (1 << 7),
    NPE_CAT_FUZZER = (1 << 8),
    NPE_CAT_INTRUSIVE = (1 << 9),
    NPE_CAT_MALWARE = (1 << 10),
    NPE_CAT_SAFE = (1 << 11),
    NPE_CAT_VERSION = (1 << 12),
    NPE_CAT_VULN = (1 << 13),
} npe_category_t;

/*============================================================================
 * Script Execution Phases
 *============================================================================*/

typedef enum npe_phase
{
    NPE_PHASE_PRERULE,
    NPE_PHASE_HOSTRULE,
    NPE_PHASE_PORTRULE,
    NPE_PHASE_POSTRULE,
} npe_phase_t;

/*============================================================================
 * Port States
 *============================================================================*/

typedef enum npe_port_state
{
    NPE_PORT_UNKNOWN = 0,
    NPE_PORT_OPEN = 1,
    NPE_PORT_CLOSED = 2,
    NPE_PORT_FILTERED = 3,
    NPE_PORT_UNFILTERED = 4,
    NPE_PORT_OPEN_FILTERED = 5,
    NPE_PORT_CLOSED_FILTERED = 6,
} npe_port_state_t;

/*============================================================================
 * Protocol Types
 *============================================================================*/

typedef enum npe_protocol
{
    NPE_PROTO_UNKNOWN = 0,
    NPE_PROTO_TCP = 1,
    NPE_PROTO_UDP = 2,
    NPE_PROTO_SCTP = 3,
} npe_protocol_t;

/*============================================================================
 * Value Types (for Lua ↔ C bridge)
 *============================================================================*/

typedef enum npe_value_type
{
    NPE_VAL_NIL,
    NPE_VAL_BOOL,
    NPE_VAL_INT,
    NPE_VAL_FLOAT,
    NPE_VAL_STRING,
    NPE_VAL_BUFFER,
    NPE_VAL_TABLE,
    NPE_VAL_FUNCTION,
    NPE_VAL_USERDATA,
} npe_value_type_t;

/*============================================================================
 * Socket Types
 *============================================================================*/

typedef enum npe_socket_type
{
    NPE_SOCK_TCP,
    NPE_SOCK_UDP,
    NPE_SOCK_RAW,
    NPE_SOCK_SSL,
} npe_socket_type_t;

/*============================================================================
 * Log / Verbosity Levels
 *============================================================================*/

typedef enum npe_log_level
{
    NPE_LOG_SILENT = 0,
    NPE_LOG_ERROR = 1,
    NPE_LOG_WARN = 2,
    NPE_LOG_INFO = 3,
    NPE_LOG_DEBUG = 4,
    NPE_LOG_TRACE = 5,
} npe_log_level_t;

/*============================================================================
 * Script State (lifecycle of a single execution)
 *============================================================================*/

typedef enum npe_script_state
{
    NPE_SCRIPT_IDLE,       /* Loaded but not scheduled          */
    NPE_SCRIPT_QUEUED,     /* Waiting in scheduler work-queue   */
    NPE_SCRIPT_RUNNING,    /* Currently executing in a Lua VM   */
    NPE_SCRIPT_WAITING_IO, /* Yielded — waiting on I/O          */
    NPE_SCRIPT_FINISHED,   /* Completed successfully            */
    NPE_SCRIPT_FAILED,     /* Completed with error              */
    NPE_SCRIPT_TIMED_OUT,  /* Killed due to timeout             */
    NPE_SCRIPT_ABORTED,    /* Cancelled by user / engine        */
} npe_script_state_t;

/*============================================================================
 * Core Structures
 *============================================================================*/

/* ---- Dynamic buffer ---------------------------------------------------- */
struct npe_buffer
{
    uint8_t *data;
    size_t size;
    size_t capacity;
    bool owned; /* true → npe_buffer_free() releases data */
};

/* ---- Generic tagged value (C ↔ Lua bridge) ----------------------------- */
struct npe_value
{
    npe_value_type_t type;
    union
    {
        bool b;
        int64_t i;
        double f;
        char *s; /* heap-allocated, NUL-terminated         */
        npe_buffer_t *buf;
        npe_table_t *tbl;
        void *ud; /* userdata / function ref                */
    } v;
};

/* ---- Simple key/value pair (used inside npe_table) ---------------------- */
typedef struct npe_kv
{
    char *key; /* NULL for array-style (integer index)    */
    npe_value_t val;
} npe_kv_t;

/* ---- Associative / array table ----------------------------------------- */
struct npe_table
{
    npe_kv_t *entries;
    size_t count;
    size_t capacity;
};

/* ---- Port descriptor --------------------------------------------------- */
struct npe_port
{
    uint16_t number;
    npe_protocol_t protocol;
    npe_port_state_t state;
    char *service_name; /* e.g. "http", "ssh" — may be NULL */
    char *version_info; /* version banner    — may be NULL   */
};

/* ---- Host descriptor --------------------------------------------------- */
struct npe_host
{
    char ip[64];        /* IPv4 or IPv6 textual              */
    char hostname[256]; /* reverse-DNS name  — may be ""     */
    uint8_t mac[6];     /* MAC address       — all-zero = NA */
    npe_port_t *ports;
    size_t port_count;
    npe_table_t *os_info; /* OS fingerprint table — may be NULL*/
};

/* ---- Per-script execution result --------------------------------------- */
struct npe_result
{
    npe_error_t status;
    npe_value_t output; /* Script return value               */
    double elapsed_ms;  /* Wall-clock time                   */
    struct timespec start_time;
    struct timespec end_time;
};

/* ---- User-supplied arguments (--script-args) --------------------------- */
typedef struct npe_script_arg
{
    char *key;
    char *value;
} npe_script_arg_t;

typedef struct npe_args
{
    npe_script_arg_t items[NPE_MAX_SCRIPT_ARGS];
    size_t count;
} npe_args_t;


/** Possible reasons a script yields */
typedef enum npe_yield_reason {
    NPE_REASON_YIELD_NONE,            /* Not yielded                             */
    NPE_REASON_YIELD_SOCKET_READ,     /* Waiting for socket read readiness       */
    NPE_REASON_YIELD_SOCKET_WRITE,    /* Waiting for socket write readiness      */
    NPE_REASON_YIELD_SOCKET_CONNECT,  /* Waiting for connect() completion        */
    NPE_REASON_YIELD_DNS,             /* Waiting for DNS resolution              */
    NPE_REASON_YIELD_SLEEP,           /* Explicit npe.sleep() call               */
} npe_yield_reason_t;



typedef enum npe_yield_type
{
    NPE_YIELD_NONE = 0,
    NPE_YIELD_READ,
    NPE_YIELD_WRITE,
    NPE_YIELD_CONNECT,
    NPE_YIELD_SLEEP,
    NPE_YIELD_UNKNOWN,
} npe_yield_type_t;

typedef struct npe_yield_info
{
    npe_yield_reason_t reason;
    npe_yield_type_t type;
    int fd;
    int timeout_ms;
} npe_yield_info_t;

/*============================================================================
 * Callback Signatures
 *============================================================================*/

/**
 * Logging callback.
 *   @param level    severity
 *   @param module   originating module, e.g. "loader", "scheduler"
 *   @param message  formatted message
 *   @param userdata opaque pointer passed during engine configuration
 */
typedef void (*npe_log_fn)(npe_log_level_t level,
                           const char *module,
                           const char *message,
                           void *userdata);

/**
 * Progress callback — fired whenever a script changes state.
 *   @param script  the script whose state changed
 *   @param state   new state
 *   @param ud      opaque user pointer
 */
typedef void (*npe_progress_fn)(const npe_script_t *script,
                                npe_script_state_t state,
                                void *ud);

/**
 * Result callback — fired when a single script finishes.
 *   @param script  originating script
 *   @param result  execution result (borrowed — copy if needed)
 *   @param ud      opaque user pointer
 */
typedef void (*npe_result_fn)(const npe_script_t *script,
                              const npe_result_t *result,
                              void *ud);

/*============================================================================
 * Helper Macros
 *============================================================================*/

#define NPE_UNUSED(x) ((void)(x))
#define NPE_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define NPE_ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define NPE_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define NPE_MAX(a, b) (((a) > (b)) ? (a) : (b))

/* Category mask helpers */
#define NPE_CAT_HAS(mask, cat) (((mask) & (cat)) != 0)
#define NPE_CAT_SET(mask, cat) ((mask) |= (cat))
#define NPE_CAT_CLR(mask, cat) ((mask) &= ~(cat))

/* Quick error check */
#define NPE_FAILED(err) ((err) != NPE_OK)
#define NPE_SUCCEEDED(err) ((err) == NPE_OK)

#endif /* NPE_TYPES_H */
