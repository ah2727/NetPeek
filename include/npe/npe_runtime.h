/* include/npe/npe_runtime.h
 *
 * Lua VM wrapper and runtime management.
 *
 * An npe_vm_t wraps a single lua_State and provides:
 *   - Creation with pre-loaded NPE libraries (socket, crypto, …).
 *   - Sandbox enforcement (restricted globals, I/O limits).
 *   - Script compilation and execution (call rule → action).
 *   - Coroutine yield / resume for async I/O.
 *   - Memory and instruction-count limits.
 *   - A pool of reusable VMs to amortise Lua state creation cost.
 *
 * The runtime is driven by the scheduler — each worker thread acquires a VM
 * from the pool, runs a work item, then returns the VM.
 */

#ifndef NPE_RUNTIME_H
#define NPE_RUNTIME_H

#include "npe_types.h"
#include "npe_script.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Runtime Configuration
 *============================================================================*/

typedef struct npe_runtime_config {
    /* ---- Memory limits ------------------------------------------------- */
    size_t      max_memory_bytes;       /* Per-VM heap cap (0 → 64 MiB)    */

    /* ---- Instruction limits (anti-infinite-loop) ----------------------- */
    uint64_t    max_instructions;       /* 0 → unlimited                   */

    /* ---- Sandbox ------------------------------------------------------- */
    bool        sandbox_enable;
    bool        allow_raw_sockets;

    /* ---- Pre-loaded libraries ------------------------------------------ */
    bool        load_npe_socket;        /* npe.socket  (TCP/UDP/SSL)       */
    bool        load_npe_http;          /* npe.http    (high-level HTTP)   */
    bool        load_npe_json;          /* npe.json    (encode / decode)   */
    bool        load_npe_crypto;        /* npe.crypto  (hash, HMAC, …)    */
    bool        load_npe_dns;           /* npe.dns     (resolver)          */
    bool        load_npe_string;        /* npe.string  (extended string)   */
    bool        load_npe_packet;        /* npe.packet  (raw packet craft)  */
    bool        load_npe_brute;         /* npe.brute   (brute-force util)  */
    bool        load_npe_vuln;          /* npe.vuln    (vuln reporting)    */

    /* ---- Logging ------------------------------------------------------- */
    npe_log_fn      log_fn;
    void           *log_userdata;
    npe_log_level_t log_level;
} npe_runtime_config_t;

/*============================================================================
 * Single VM Instance
 *============================================================================*/

/**
 * Create a new Lua VM with NPE standard libraries loaded.
 *
 * @param[in]  config  Runtime options (NULL → defaults with all libs loaded).
 * @param[out] out     Receives the new VM handle.
 * @return NPE_OK or error.
 */
npe_error_t npe_vm_create(const npe_runtime_config_t *config,
                          npe_vm_t                  **out);

/**
 * Destroy the VM and free all associated Lua state.  Sets *vm to NULL.
 */
void npe_vm_destroy(npe_vm_t **vm);

/**
 * Reset the VM to a clean post-creation state so it can be reused for
 * another script without the cost of full destruction + creation.
 *
 * Clears globals, resets memory counters, but keeps pre-loaded C libs.
 */
npe_error_t npe_vm_reset(npe_vm_t *vm);

/*============================================================================
 * Script Compilation
 *============================================================================*/

/**
 * Compile (but do not execute) a script's Lua source inside the VM.
 *
 * After this call, the compiled chunk is on the Lua stack and ready to be
 * called via npe_vm_call_rule() / npe_vm_call_action().
 *
 * @param vm      Target VM.
 * @param script  The script whose source.text will be compiled.
 * @return NPE_OK, NPE_ERROR_SCRIPT_SYNTAX.
 */
npe_error_t npe_vm_compile(npe_vm_t           *vm,
                           const npe_script_t *script);

/*============================================================================
 * Rule Evaluation
 *============================================================================*/

/**
 * Call the appropriate rule function for a given phase.
 *
 *   NPE_PHASE_PRERULE  → calls prerule(host)   → bool
 *   NPE_PHASE_HOSTRULE → calls hostrule(host)  → bool
 *   NPE_PHASE_PORTRULE → calls portrule(host, port) → bool
 *   NPE_PHASE_POSTRULE → calls postrule()      → bool
 *
 * @param vm      VM with a compiled script.
 * @param phase   Which rule to invoke.
 * @param host    Target host (NULL for postrule).
 * @param port    Target port (NULL except for portrule).
 * @param[out] match  true if the rule returned a truthy value.
 * @return NPE_OK, NPE_ERROR_SCRIPT_RUNTIME, NPE_ERROR_TIMEOUT.
 */
npe_error_t npe_vm_call_rule(npe_vm_t           *vm,
                             npe_phase_t         phase,
                             const npe_host_t   *host,
                             const npe_port_t   *port,
                             bool               *match);

/*============================================================================
 * Action Execution
 *============================================================================*/

/**
 * Call the script's action() function.
 *
 * @param vm      VM with a compiled script whose rule matched.
 * @param host    Target host (borrowed).
 * @param port    Target port (borrowed, may be NULL).
 * @param[out] result  Populated with the script's return value and timing.
 *                     Caller must call npe_result_free_members() when done.
 * @return NPE_OK, NPE_ERROR_SCRIPT_RUNTIME, NPE_ERROR_TIMEOUT,
 *         NPE_ERROR_SCRIPT_ABORTED.
 */
npe_error_t npe_vm_call_action(npe_vm_t           *vm,
                               const npe_host_t   *host,
                               const npe_port_t   *port,
                               npe_result_t       *result);

/*============================================================================
 * Coroutine Yield / Resume (async I/O support)
 *============================================================================*/



/**
 * Check whether the VM is in a yielded (suspended) state.
 */
bool npe_vm_is_yielded(const npe_vm_t *vm);

/**
 * Get information about why the VM yielded.
 */
npe_error_t npe_vm_yield_info(const npe_vm_t *vm,
                              npe_yield_info_t *info);

/**
 * Resume a yielded VM after the awaited I/O event has fired.
 *
 * @param vm        The yielded VM.
 * @param io_error  NPE_OK if I/O succeeded; appropriate error otherwise.
 *                  The script sees this as the return value of the I/O call.
 * @return NPE_OK              Script resumed and either finished or yielded again.
 *         NPE_ERROR_*         Script hit a runtime error after resume.
 */
npe_error_t npe_vm_resume(npe_vm_t    *vm,
                          npe_error_t  io_error);

/*============================================================================
 * Context Injection
 *============================================================================*/

/**
 * Attach a per-execution context to the VM (made available to Lua code as
 * a global "npe.context").
 *
 * @param vm   Target VM.
 * @param ctx  Context handle (borrowed — must outlive the VM usage).
 */
npe_error_t npe_vm_set_context(npe_vm_t    *vm,
                               npe_context_t *ctx);

/**
 * Inject script arguments (--script-args) into the VM's global table.
 */
npe_error_t npe_vm_set_args(npe_vm_t       *vm,
                            const npe_args_t *args);

/*============================================================================
 * Resource Queries
 *============================================================================*/

/**
 * Return the current Lua heap usage of the VM in bytes.
 */
size_t npe_vm_memory_usage(const npe_vm_t *vm);

/**
 * Return the number of Lua instructions executed since the last reset.
 */
uint64_t npe_vm_instruction_count(const npe_vm_t *vm);

/*============================================================================
 * Abort
 *============================================================================*/

/**
 * Set the abort flag on this VM.
 *
 * The next Lua debug hook (instruction count) will raise an error that
 * unwinds the stack and causes call_action / call_rule to return
 * NPE_ERROR_SCRIPT_ABORTED.
 *
 * Thread-safe.
 */
npe_error_t npe_vm_abort(npe_vm_t *vm);

/*============================================================================
 * VM Pool — amortise creation cost across many work items
 *============================================================================*/

typedef struct npe_vm_pool npe_vm_pool_t;

typedef struct npe_vm_pool_config {
    size_t                      initial_size;   /* Pre-warmed VMs (0 → 4)  */
    size_t                      max_size;       /* Hard cap (0 → max_concurrent) */
    const npe_runtime_config_t *vm_config;      /* Template for new VMs    */
} npe_vm_pool_config_t;

/**
 * Create a VM pool.
 */
npe_error_t npe_vm_pool_create(const npe_vm_pool_config_t *config,
                               npe_vm_pool_t             **out);

/**
 * Destroy the pool and all idle VMs within it.
 */
void npe_vm_pool_destroy(npe_vm_pool_t **pool);

/**
 * Acquire a VM from the pool.  If no idle VM is available and the pool has
 * not reached max_size, a new one is created on the fly.
 *
 * @param[out] vm  Receives the VM handle.
 * @return NPE_OK, NPE_ERROR_MEMORY, or NPE_ERROR_TIMEOUT if the pool is
 *         at capacity and all VMs are in use.
 */
npe_error_t npe_vm_pool_acquire(npe_vm_pool_t *pool,
                                npe_vm_t     **vm);

/**
 * Return a VM to the pool.  The VM is reset before being placed on the
 * idle list.
 *
 * @param pool  Pool handle.
 * @param vm    VM to return.  Set to NULL on return.
 */
npe_error_t npe_vm_pool_release(npe_vm_pool_t *pool,
                                npe_vm_t     **vm);

/**
 * Return the number of VMs currently idle in the pool.
 */
size_t npe_vm_pool_idle_count(const npe_vm_pool_t *pool);

/**
 * Return the total number of VMs managed by the pool (idle + in-use).
 */
size_t npe_vm_pool_total_count(const npe_vm_pool_t *pool);

npe_error_t npe_vm_load_script(npe_vm_t *vm, const npe_script_t *script);

#ifdef __cplusplus
}
#endif

#endif /* NPE_RUNTIME_H */
