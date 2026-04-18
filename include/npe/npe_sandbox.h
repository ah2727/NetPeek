/*****************************************************************************
 * npe_sandbox.h — Sandbox and security restrictions
 *****************************************************************************/

#ifndef NPE_SANDBOX_H
#define NPE_SANDBOX_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Sandbox Configuration
 *============================================================================*/

typedef struct npe_sandbox_config {
    size_t      memory_limit;          /* bytes; 0 → 64 MiB               */
    uint32_t    timeout_ms;            /* 0 → 30000                       */
    uint64_t    max_instructions;      /* 0 → 10 000 000                  */
    uint32_t    max_connections;       /* 0 → 100                         */
    bool        allow_localhost;       /* connect to 127.0.0.1?           */
    bool        allow_raw_sockets;
    const char *allowed_paths[16];     /* additional readable directories */
    size_t      allowed_path_count;
} npe_sandbox_config_t;

/*============================================================================
 * API
 *============================================================================*/

/**
 * Apply sandbox restrictions to a lua_State.
 *
 * Removes dangerous globals (os.execute, io.*, etc.), installs instruction
 * count hooks, and sets up memory tracking.
 *
 * @param lua_state  The lua_State* to sandbox.
 * @param config     Sandbox options (NULL → defaults).
 * @return NPE_OK or NPE_ERROR_GENERIC.
 */
npe_error_t npe_sandbox_apply(void                       *lua_state,
                              const npe_sandbox_config_t *config);

/**
 * Set a memory limit on the lua_State's allocator.
 */
npe_error_t npe_sandbox_set_memory_limit(void *lua_state, size_t bytes);

/**
 * Set an execution timeout (instruction count based).
 */
npe_error_t npe_sandbox_set_timeout(void *lua_state, uint32_t ms);

/**
 * Install the debug hook for instruction counting.
 */
npe_error_t npe_sandbox_install_hooks(void *lua_state);

/**
 * Validate that a file path is within the allowed set of directories.
 *
 * @param path    Absolute or relative path to check.
 * @param config  Sandbox configuration with allowed paths.
 * @return true if the path is allowed.
 */
bool npe_sandbox_check_path(const char                 *path,
                            const npe_sandbox_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* NPE_SANDBOX_H */
