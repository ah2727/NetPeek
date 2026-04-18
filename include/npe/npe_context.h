/*****************************************************************************
 * npe_context.h — Per-script execution context
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *****************************************************************************/

#ifndef NPE_CONTEXT_H
#define NPE_CONTEXT_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_engine    npe_engine_t;
typedef struct npe_vm        npe_vm_t;
typedef struct npe_script    npe_script_t;
typedef struct npe_registry  npe_registry_t;

/* ── Context flags ───────────────────────────────────────────────────────── */
typedef enum npe_ctx_flag {
    NPE_CTX_FLAG_NONE       = 0,
    NPE_CTX_FLAG_VERBOSE    = (1 << 0),
    NPE_CTX_FLAG_FORCED     = (1 << 1),
    NPE_CTX_FLAG_SAFE_MODE  = (1 << 2),
    NPE_CTX_FLAG_TIMED_OUT  = (1 << 3),
    NPE_CTX_FLAG_ABORTED    = (1 << 4),
    NPE_CTX_FLAG_FINISHED   = (1 << 5),
} npe_ctx_flag_t;

/* ── Context state ───────────────────────────────────────────────────────── */
typedef enum npe_ctx_state {
    NPE_CTX_STATE_INIT = 0,
    NPE_CTX_STATE_RULE,
    NPE_CTX_STATE_RUNNING,
    NPE_CTX_STATE_COMPLETED,
    NPE_CTX_STATE_ACTION,
    NPE_CTX_STATE_POSTACTION,
    NPE_CTX_STATE_DONE,
    NPE_CTX_STATE_ERROR,
    NPE_CTX_STATE_TIMEOUT,
    NPE_CTX_STATE_ABORTED,
} npe_ctx_state_t;

/* ── Context structure ───────────────────────────────────────────────────── */
struct npe_context {
    /* Identity */
    uint64_t            id;
    npe_ctx_state_t     state;
    uint32_t            flags;

    /* References (borrowed, not owned) */
    npe_engine_t       *engine;
    const npe_script_t *script;
    npe_vm_t           *vm;

    /* Target (deep-copied, owned by context) */
    npe_host_t          host;
    npe_port_t          port;
    bool                has_port;

    /* Script arguments */
    npe_args_t          args;

    /* Private key-value store (persists across phases within one execution) */
    npe_table_t        *store;

    /* Result accumulation */
    npe_result_t        result;

    /* Last error info */
    npe_error_t         last_error;
    char                last_error_msg[256];

    /* Timing */
    struct timespec     created_at;
    struct timespec     started_at;
    uint32_t            timeout_ms;
    double              elapsed_ms;

    /* Linked list hook (used by scheduler) */
    npe_context_t      *next;
};

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * Create a new execution context for a (script, host, port) tuple.
 *
 * @param engine   Owning engine (borrowed).
 * @param script   Script to execute (borrowed).
 * @param host     Target host (deep-copied into context).
 * @param port     Target port (deep-copied; NULL if not portrule).
 * @param[out] out Receives the new context.
 * @return NPE_OK or NPE_ERROR_MEMORY.
 */
npe_error_t npe_context_create(npe_engine_t       *engine,
                               const npe_script_t *script,
                               const npe_host_t   *host,
                               const npe_port_t   *port,
                               npe_context_t     **out);

/**
 * Destroy a context and free all owned resources.  Sets *ctx to NULL.
 */
void npe_context_destroy(npe_context_t **ctx);

/*============================================================================
 * Lua Table Pushers — push context data onto a lua_State stack
 *============================================================================*/

/**
 * Push the host information as a Lua table onto the stack.
 */
npe_error_t npe_context_push_host(npe_context_t *ctx, void *lua_state);

/**
 * Push the port information as a Lua table onto the stack.
 * Returns NPE_ERROR_INVALID_ARG if ctx->has_port is false.
 */
npe_error_t npe_context_push_port(npe_context_t *ctx, void *lua_state);

/**
 * Push the script arguments as a Lua table onto the stack.
 */
npe_error_t npe_context_push_args(npe_context_t *ctx, void *lua_state);

/*============================================================================
 * Private Store (inter-phase persistence)
 *============================================================================*/

/**
 * Store a value under the given key.  Deep-copies the value.
 */
npe_error_t npe_context_store_set(npe_context_t     *ctx,
                                  const char        *key,
                                  const npe_value_t *value);

/**
 * Retrieve a value from the store.  Returns NULL if not found.
 */
const npe_value_t *npe_context_store_get(const npe_context_t *ctx,
                                         const char          *key);

/*============================================================================
 * State / Flag Helpers
 *============================================================================*/

void npe_context_set_state(npe_context_t *ctx, npe_ctx_state_t state);
void npe_context_set_flag(npe_context_t *ctx, npe_ctx_flag_t flag);
void npe_context_clear_flag(npe_context_t *ctx, npe_ctx_flag_t flag);
bool npe_context_has_flag(const npe_context_t *ctx, npe_ctx_flag_t flag);

#ifdef __cplusplus
}
#endif

#endif /* NPE_CONTEXT_H */
