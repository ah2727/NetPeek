/*****************************************************************************
 * npe_sandbox.c — Sandbox and security restrictions for Lua script execution
 *
 * Removes dangerous globals, installs instruction-count debug hooks, and
 * wraps the Lua allocator with a memory-tracking layer.
 *****************************************************************************/

#include "npe_sandbox.h"
#include "npe_error.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <inttypes.h>
#include <errno.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/*============================================================================
 * Compile-time Defaults
 *============================================================================*/

#define NPE_SANDBOX_DEFAULT_MEMORY_LIMIT      (64UL * 1024 * 1024) /* 64 MiB */
#define NPE_SANDBOX_DEFAULT_TIMEOUT_MS        30000U
#define NPE_SANDBOX_DEFAULT_MAX_INSTRUCTIONS  10000000ULL
#define NPE_SANDBOX_DEFAULT_MAX_CONNECTIONS   100U

/** Hook granularity — number of instructions between hook calls. */
#define NPE_SANDBOX_HOOK_INTERVAL             10000

/*============================================================================
 * Per-State Sandbox Context
 *============================================================================*/

/**
 * Stored in the Lua registry under a light-userdata key so the allocator
 * and the debug hook can retrieve it.
 */
typedef struct npe_sandbox_ctx {
    /* Memory tracking */
    size_t   memory_used;
    size_t   memory_limit;

    /* Instruction counting / timeout */
    uint64_t instructions_executed;
    uint64_t max_instructions;
    uint32_t timeout_ms;

    /* Wall-clock start (set just before script execution) */
    struct timespec start_time;

    /* Connection budget */
    uint32_t connections_used;
    uint32_t max_connections;

    /* Path whitelist (shallow copy of config pointers — valid for
     * the duration of the sandbox lifetime). */
    const char *allowed_paths[16];
    size_t      allowed_path_count;
    bool        allow_localhost;
    bool        allow_raw_sockets;

    /* Original allocator (so we can chain). */
    lua_Alloc   orig_alloc;
    void       *orig_alloc_ud;
} npe_sandbox_ctx_t;

/** Unique address used as a Lua registry key. */
static const char sandbox_ctx_key = 'S';

/*============================================================================
 * Internal: Registry Helpers
 *============================================================================*/

static void
sandbox_ctx_store(lua_State *L, npe_sandbox_ctx_t *ctx)
{
    lua_pushlightuserdata(L, (void *)&sandbox_ctx_key);
    lua_pushlightuserdata(L, ctx);
    lua_rawset(L, LUA_REGISTRYINDEX);
}

static npe_sandbox_ctx_t *
sandbox_ctx_fetch(lua_State *L)
{
    lua_pushlightuserdata(L, (void *)&sandbox_ctx_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    npe_sandbox_ctx_t *ctx = (npe_sandbox_ctx_t *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return ctx;
}

/*============================================================================
 * Internal: Memory-Tracking Allocator
 *============================================================================*/

/**
 * Custom Lua allocator that enforces a byte ceiling.
 *
 * The Lua allocator protocol:
 *   - ptr==NULL, nsize>0  → malloc(nsize)
 *   - ptr!=NULL, nsize==0 → free(ptr)
 *   - ptr!=NULL, nsize>0  → realloc(ptr, nsize)
 */
static void *
sandbox_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    npe_sandbox_ctx_t *ctx = (npe_sandbox_ctx_t *)ud;

    if (nsize == 0) {
        /* Free. */
        if (ptr) {
            if (ctx->memory_used >= osize)
                ctx->memory_used -= osize;
            else
                ctx->memory_used = 0;
        }
        /* Chain to the original allocator for the actual free. */
        ctx->orig_alloc(ctx->orig_alloc_ud, ptr, osize, 0);
        return NULL;
    }

    /* Check if the new allocation would exceed the limit. */
    size_t delta = nsize > osize ? (nsize - osize) : 0;
    if (ctx->memory_limit > 0 &&
        ctx->memory_used + delta > ctx->memory_limit) {
        /* Deny the allocation. */
        return NULL;
    }

    void *newptr = ctx->orig_alloc(ctx->orig_alloc_ud, ptr, osize, nsize);
    if (newptr) {
        /* Adjust bookkeeping. */
        if (nsize > osize)
            ctx->memory_used += (nsize - osize);
        else if (osize > nsize)
            ctx->memory_used -= (osize - nsize);
    }
    return newptr;
}

/*============================================================================
 * Internal: Instruction-Count Debug Hook
 *============================================================================*/

/**
 * Elapsed wall-clock milliseconds since ctx->start_time.
 */
static double
elapsed_ms(const npe_sandbox_ctx_t *ctx)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double sec  = (double)(now.tv_sec  - ctx->start_time.tv_sec);
    double nsec = (double)(now.tv_nsec - ctx->start_time.tv_nsec);
    return sec * 1000.0 + nsec / 1e6;
}

/**
 * Lua debug hook — called every NPE_SANDBOX_HOOK_INTERVAL instructions.
 */
static void
sandbox_hook(lua_State *L, lua_Debug *ar)
{
    (void)ar;

    npe_sandbox_ctx_t *ctx = sandbox_ctx_fetch(L);
    if (!ctx)
        return;

    ctx->instructions_executed += NPE_SANDBOX_HOOK_INTERVAL;

    /* Instruction limit. */
    if (ctx->max_instructions > 0 &&
        ctx->instructions_executed >= ctx->max_instructions) {
        luaL_error(L, "sandbox: instruction limit exceeded (%" PRIu64 ")",
                   ctx->max_instructions);
        return;   /* luaL_error does not return, but keep for clarity. */
    }

    /* Wall-clock timeout. */
    if (ctx->timeout_ms > 0 && elapsed_ms(ctx) > (double)ctx->timeout_ms) {
        luaL_error(L, "sandbox: execution timeout (%" PRIu32 " ms)",
                   ctx->timeout_ms);
        return;
    }
}

/*============================================================================
 * Internal: Remove / Neuter Dangerous Globals
 *============================================================================*/

/**
 * Nil-out a global name.
 */
static void
remove_global(lua_State *L, const char *name)
{
    lua_pushnil(L);
    lua_setglobal(L, name);
}

/**
 * Nil-out a field inside a global table (e.g., os.execute).
 */
static void
remove_table_field(lua_State *L, const char *table, const char *field)
{
    lua_getglobal(L, table);
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_pushnil(L);
    lua_setfield(L, -2, field);
    lua_pop(L, 1);
}

/**
 * Stub function that always returns an error.
 */
static int
blocked_function(lua_State *L)
{
    return luaL_error(L, "sandbox: this function is blocked");
}

/**
 * Replace a global function with the blocked stub.
 */
static void
block_global(lua_State *L, const char *name)
{
    lua_pushcfunction(L, blocked_function);
    lua_setglobal(L, name);
}

/**
 * Replace a table field function with the blocked stub.
 */
static void
block_table_field(lua_State *L, const char *table, const char *field)
{
    lua_getglobal(L, table);
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_pushcfunction(L, blocked_function);
    lua_setfield(L, -2, field);
    lua_pop(L, 1);
}

/**
 * Apply all removals / blocks to the Lua state.
 */
static void
sandbox_restrict_globals(lua_State *L, const npe_sandbox_config_t *config)
{
    (void)config;

    /* ── Completely remove the io library ── */
    remove_global(L, "io");

    /* ── Neuter dangerous os functions, keep benign ones ── */
    remove_table_field(L, "os", "execute");
    remove_table_field(L, "os", "exit");
    remove_table_field(L, "os", "getenv");
    remove_table_field(L, "os", "remove");
    remove_table_field(L, "os", "rename");
    remove_table_field(L, "os", "tmpname");
    remove_table_field(L, "os", "setlocale");

    /* ── Block loadfile / dofile (arbitrary file execution) ── */
    block_global(L, "loadfile");
    block_global(L, "dofile");

    /* ── Remove the debug library entirely (can escape sandboxes) ── */
    remove_global(L, "debug");

    /* ── Remove package.loadlib (loads arbitrary C shared objects) ── */
    remove_table_field(L, "package", "loadlib");

    /*
     * We intentionally keep:
     *   - require()   → controlled via package.path / package.cpath
     *   - load()      → needed for loading scripts from strings
     *   - pcall/xpcall → error handling
     *   - coroutine   → non-dangerous
     *   - string/table/math → essential
     *   - os.clock, os.date, os.time, os.difftime → benign
     */

    /* ── Restrict package search paths to the NSE script directory ── */
    block_table_field(L, "package", "loadlib");
    remove_table_field(L, "package", "cpath");   /* no C modules */
}

/*============================================================================
 * Internal: Sandbox-Safe File-Open Wrapper
 *============================================================================*/

/**
 * Replacement for io.open that checks the sandbox path whitelist.
 * Pushed as a Lua C function if limited file access is desired.
 */
static int
sandbox_io_open(lua_State *L)
{
    const char *path = luaL_checkstring(L, 1);
    const char *mode = luaL_optstring(L, 2, "r");

    /* Only allow read modes. */
    if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'))
        return luaL_error(L, "sandbox: write access is denied");

    npe_sandbox_ctx_t *ctx = sandbox_ctx_fetch(L);

    /* Resolve to absolute path for comparison. */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved))
        return luaL_error(L, "sandbox: cannot resolve path '%s'", path);

    /* Check against allowed paths. */
    bool allowed = false;
    if (ctx) {
        for (size_t i = 0; i < ctx->allowed_path_count; i++) {
            const char *prefix = ctx->allowed_paths[i];
            size_t plen = strlen(prefix);
            if (strncmp(resolved, prefix, plen) == 0 &&
                (resolved[plen] == '/' || resolved[plen] == '\0')) {
                allowed = true;
                break;
            }
        }
    }

    if (!allowed)
        return luaL_error(L, "sandbox: path '%s' is not in the whitelist", path);

    /* Use standard fopen. */
    FILE *f = fopen(resolved, mode);
    if (!f) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    /* Push as a light userdata — in a real implementation we'd wrap in a
     * full userdata with a metatable for :read(), :close(), etc. */
    FILE **ud = (FILE **)lua_newuserdata(L, sizeof(FILE *));
    *ud = f;
    luaL_getmetatable(L, LUA_FILEHANDLE);
    lua_setmetatable(L, -2);

    return 1;
}

/*============================================================================
 * Internal: Apply the Sandbox-Safe IO (optional)
 *============================================================================*/

static void
sandbox_install_safe_io(lua_State *L, const npe_sandbox_config_t *config)
{
    if (!config || config->allowed_path_count == 0) {
        /* No paths configured — io stays fully removed. */
        return;
    }

    /* Create a minimal "io" table with only open. */
    lua_newtable(L);
    lua_pushcfunction(L, sandbox_io_open);
    lua_setfield(L, -2, "open");
    lua_setglobal(L, "io");
}

/*============================================================================
 * Public API: npe_sandbox_apply
 *============================================================================*/

npe_error_t
npe_sandbox_apply(void                       *lua_state,
                  const npe_sandbox_config_t *config)
{
    if (!lua_state)
        return NPE_ERROR_INVALID_ARG;

    lua_State *L = (lua_State *)lua_state;

    /* ── Build effective configuration (merge with defaults) ── */
    npe_sandbox_config_t eff;
    memset(&eff, 0, sizeof(eff));

    if (config) {
        memcpy(&eff, config, sizeof(eff));
    }

    if (eff.memory_limit      == 0) eff.memory_limit      = NPE_SANDBOX_DEFAULT_MEMORY_LIMIT;
    if (eff.timeout_ms        == 0) eff.timeout_ms        = NPE_SANDBOX_DEFAULT_TIMEOUT_MS;
    if (eff.max_instructions  == 0) eff.max_instructions  = NPE_SANDBOX_DEFAULT_MAX_INSTRUCTIONS;
    if (eff.max_connections   == 0) eff.max_connections   = NPE_SANDBOX_DEFAULT_MAX_CONNECTIONS;

    /* ── Allocate and populate the per-state context ── */
    npe_sandbox_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NPE_ERROR_NOMEM;

    ctx->memory_limit        = eff.memory_limit;
    ctx->timeout_ms          = eff.timeout_ms;
    ctx->max_instructions    = eff.max_instructions;
    ctx->max_connections     = eff.max_connections;
    ctx->allow_localhost     = eff.allow_localhost;
    ctx->allow_raw_sockets   = eff.allow_raw_sockets;
    ctx->allowed_path_count  = eff.allowed_path_count;

    for (size_t i = 0; i < eff.allowed_path_count && i < 16; i++)
        ctx->allowed_paths[i] = eff.allowed_paths[i];

    /* Record the wall-clock start. */
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);

    /* Store in the Lua registry. */
    sandbox_ctx_store(L, ctx);

    /* ── Install the memory-tracking allocator ── */
    ctx->orig_alloc = lua_getallocf(L, &ctx->orig_alloc_ud);
    lua_setallocf(L, sandbox_alloc, ctx);

    /* ── Restrict globals ── */
    sandbox_restrict_globals(L, &eff);

    /* ── Optionally install a sandboxed io.open ── */
    sandbox_install_safe_io(L, &eff);

    /* ── Install the instruction-count debug hook ── */
    lua_sethook(L, sandbox_hook, LUA_MASKCOUNT, NPE_SANDBOX_HOOK_INTERVAL);

    return NPE_OK;
}

/*============================================================================
 * Public API: npe_sandbox_set_memory_limit
 *============================================================================*/

npe_error_t
npe_sandbox_set_memory_limit(void *lua_state, size_t bytes)
{
    if (!lua_state)
        return NPE_ERROR_INVALID_ARG;

    lua_State *L = (lua_State *)lua_state;
    npe_sandbox_ctx_t *ctx = sandbox_ctx_fetch(L);
    if (!ctx) {
        npe_error_log(NPE_ERROR_NOT_INIT, "sandbox",
                      "set_memory_limit called before sandbox_apply");
        return NPE_ERROR_NOT_INIT;
    }

    ctx->memory_limit = bytes;
    return NPE_OK;
}

/*============================================================================
 * Public API: npe_sandbox_set_timeout
 *============================================================================*/

npe_error_t
npe_sandbox_set_timeout(void *lua_state, uint32_t ms)
{
    if (!lua_state)
        return NPE_ERROR_INVALID_ARG;

    lua_State *L = (lua_State *)lua_state;
    npe_sandbox_ctx_t *ctx = sandbox_ctx_fetch(L);
    if (!ctx) {
        npe_error_log(NPE_ERROR_NOT_INIT, "sandbox",
                      "set_timeout called before sandbox_apply");
        return NPE_ERROR_NOT_INIT;
    }

    ctx->timeout_ms = ms;
    return NPE_OK;
}

/*============================================================================
 * Public API: npe_sandbox_install_hooks
 *============================================================================*/

npe_error_t
npe_sandbox_install_hooks(void *lua_state)
{
    if (!lua_state)
        return NPE_ERROR_INVALID_ARG;

    lua_State *L = (lua_State *)lua_state;
    npe_sandbox_ctx_t *ctx = sandbox_ctx_fetch(L);
    if (!ctx) {
        npe_error_log(NPE_ERROR_NOT_INIT, "sandbox",
                      "install_hooks called before sandbox_apply");
        return NPE_ERROR_NOT_INIT;
    }

    /* Reset the instruction counter. */
    ctx->instructions_executed = 0;

    /* Reset the wall-clock timer. */
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);

    /* (Re-)install the debug hook. */
    lua_sethook(L, sandbox_hook, LUA_MASKCOUNT, NPE_SANDBOX_HOOK_INTERVAL);

    return NPE_OK;
}

/*============================================================================
 * Public API: npe_sandbox_check_path
 *============================================================================*/

bool
npe_sandbox_check_path(const char                 *path,
                       const npe_sandbox_config_t *config)
{
    if (!path || !config)
        return false;

    /* Resolve symlinks and normalise. */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved))
        return false;

    for (size_t i = 0; i < config->allowed_path_count && i < 16; i++) {
        const char *prefix = config->allowed_paths[i];
        if (!prefix)
            continue;

        char resolved_prefix[PATH_MAX];
        if (!realpath(prefix, resolved_prefix))
            continue;

        size_t plen = strlen(resolved_prefix);
        if (strncmp(resolved, resolved_prefix, plen) == 0 &&
            (resolved[plen] == '/' || resolved[plen] == '\0')) {
            return true;
        }
    }

    return false;
}
