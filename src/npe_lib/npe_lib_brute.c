/*****************************************************************************
 * npe_lib_brute.c — Brute-force attack framework (implementation)
 *
 * Provides reusable credential brute-force logic for NPE scripts.
 * Supports dictionary attacks, combinatorial generation, adaptive delays,
 * multi-threading, and protocol-specific authentication callbacks.
 *
 *****************************************************************************/


#include "npe_lib_brute.h"
#include "core/error.h"
#include "npe_types.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

/* ---- Compatibility shims for npe_error_t constants ---- */
#define NPE_ERR_INVALID     NPE_ERROR_INVALID_ARG
#define NPE_ERROR_MEMORY       NPE_ERROR_MEMORY
#define NPE_ERROR_IO          NPE_ERROR_IO
#define NPE_ERROR_GENERIC    NPE_ERROR_GENERIC
#define NPE_ERR_CALLBACK    NPE_ERROR_SCRIPT_RUNTIME
/* ---------------------------------------------------------------------------
 * Platform threading abstraction
 * --------------------------------------------------------------------------- */

#ifdef _WIN32
  #include <windows.h>
  typedef HANDLE              npe_thread_t;
  typedef CRITICAL_SECTION    npe_mutex_t;
  typedef CONDITION_VARIABLE  npe_cond_t;

  static inline void npe_mutex_init(npe_mutex_t *m)    { InitializeCriticalSection(m); }
  static inline void npe_mutex_destroy(npe_mutex_t *m) { DeleteCriticalSection(m); }
  static inline void npe_mutex_lock(npe_mutex_t *m)    { EnterCriticalSection(m); }
  static inline void npe_mutex_unlock(npe_mutex_t *m)  { LeaveCriticalSection(m); }

  static inline void npe_cond_init(npe_cond_t *c)                       { InitializeConditionVariable(c); }
  static inline void npe_cond_destroy(npe_cond_t *c)                    { (void)c; }
  static inline void npe_cond_signal(npe_cond_t *c)                     { WakeConditionVariable(c); }
  static inline void npe_cond_broadcast(npe_cond_t *c)                  { WakeAllConditionVariable(c); }
  static inline void npe_cond_wait(npe_cond_t *c, npe_mutex_t *m)      { SleepConditionVariableCS(c, m, INFINITE); }

  static inline void npe_sleep_ms(uint32_t ms) { Sleep(ms); }

  static uint64_t npe_time_ms(void) {
      FILETIME ft;
      GetSystemTimeAsFileTime(&ft);
      uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
      return t / 10000ULL - 11644473600000ULL;
  }

  typedef DWORD (WINAPI *npe_thread_func_t)(LPVOID);

  static inline int npe_thread_create(npe_thread_t *t, DWORD (WINAPI *func)(LPVOID), void *arg) {
      *t = CreateThread(NULL, 0, func, arg, 0, NULL);
      return (*t == NULL) ? -1 : 0;
  }
  static inline void npe_thread_join(npe_thread_t t) {
      WaitForSingleObject(t, INFINITE);
      CloseHandle(t);
  }

  #define NPE_THREAD_RETURN_TYPE  DWORD WINAPI
  #define NPE_THREAD_RETURN       return 0

#else
  #include <pthread.h>
  #include <unistd.h>
  #include <sys/time.h>

  typedef pthread_t       npe_thread_t;
  typedef pthread_mutex_t npe_mutex_t;
  typedef pthread_cond_t  npe_cond_t;

  static inline void npe_mutex_init(npe_mutex_t *m)    { pthread_mutex_init(m, NULL); }
  static inline void npe_mutex_destroy(npe_mutex_t *m) { pthread_mutex_destroy(m); }
  static inline void npe_mutex_lock(npe_mutex_t *m)    { pthread_mutex_lock(m); }
  static inline void npe_mutex_unlock(npe_mutex_t *m)  { pthread_mutex_unlock(m); }

  static inline void npe_cond_init(npe_cond_t *c)                       { pthread_cond_init(c, NULL); }
  static inline void npe_cond_destroy(npe_cond_t *c)                    { pthread_cond_destroy(c); }
  static inline void npe_cond_signal(npe_cond_t *c)                     { pthread_cond_signal(c); }
  static inline void npe_cond_broadcast(npe_cond_t *c)                  { pthread_cond_broadcast(c); }
  static inline void npe_cond_wait(npe_cond_t *c, npe_mutex_t *m)      { pthread_cond_wait(c, m); }

  static inline void npe_sleep_ms(uint32_t ms) { usleep((useconds_t)ms * 1000u); }

  static uint64_t npe_time_ms(void) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
  }

  static inline int npe_thread_create(npe_thread_t *t, void *(*func)(void *), void *arg) {
      return pthread_create(t, NULL, func, arg);
  }
  static inline void npe_thread_join(npe_thread_t t) {
      pthread_join(t, NULL);
  }

  #define NPE_THREAD_RETURN_TYPE  void *
  #define NPE_THREAD_RETURN       return NULL

#endif

/* ---------------------------------------------------------------------------
 * Internal dynamic string list
 * --------------------------------------------------------------------------- */

typedef struct npe_strlist {
    char   **items;
    uint32_t count;
    uint32_t capacity;
} npe_strlist_t;

static void strlist_init(npe_strlist_t *sl) {
    sl->items    = NULL;
    sl->count    = 0;
    sl->capacity = 0;
}

static void strlist_free(npe_strlist_t *sl) {
    for (uint32_t i = 0; i < sl->count; i++) {
        free(sl->items[i]);
    }
    free(sl->items);
    strlist_init(sl);
}

static npe_error_t strlist_add(npe_strlist_t *sl, const char *str) {
    if (!str) return NPE_ERR_INVALID;

    if (sl->count >= sl->capacity) {
        uint32_t new_cap = (sl->capacity == 0) ? 64 : sl->capacity * 2;
        char **tmp = (char **)realloc(sl->items, sizeof(char *) * new_cap);
        if (!tmp) return NPE_ERROR_MEMORY;
        sl->items    = tmp;
        sl->capacity = new_cap;
    }

    sl->items[sl->count] = strdup(str);
    if (!sl->items[sl->count]) return NPE_ERROR_MEMORY;
    sl->count++;
    return NPE_OK;
}

static npe_error_t strlist_load_file(npe_strlist_t *sl, const char *path) {
    if (!path) return NPE_ERR_INVALID;

    FILE *fp = fopen(path, "r");
    if (!fp) return NPE_ERROR_IO;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        /* strip trailing newline / carriage return */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue; /* skip blank lines */

        npe_error_t err = strlist_add(sl, line);
        if (err != NPE_OK) {
            fclose(fp);
            return err;
        }
    }

    fclose(fp);
    return NPE_OK;
}

/* Fisher-Yates shuffle for a pair-index array */
static void shuffle_uint64(uint64_t *arr, uint64_t n) {
    if (n <= 1) return;
    for (uint64_t i = n - 1; i > 0; i--) {
        uint64_t j = (uint64_t)rand() % (i + 1);
        uint64_t tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

/* ---------------------------------------------------------------------------
 * Engine internal structure
 * --------------------------------------------------------------------------- */

struct npe_brute_engine {

    /* configuration (immutable after create) */
    npe_brute_options_t options;

    /* credential lists */
    npe_strlist_t usernames;
    npe_strlist_t passwords;

    /* work queue: linearised (user_idx * pw_count + pw_idx) indices */
    uint64_t *work_queue;
    uint64_t  work_total;
    uint64_t  work_next;       /* next index to hand out */

    /* synchronisation */
    npe_mutex_t mutex;
    npe_cond_t  cond;
    volatile bool stopped;

    /* statistics (protected by mutex) */
    npe_brute_stats_t stats;

    /* result (first success, protected by mutex) */
    npe_brute_result_t result;
    bool result_set;

    /* timing */
    uint64_t start_time_ms;
};

/* ---------------------------------------------------------------------------
 * Engine lifecycle
 * --------------------------------------------------------------------------- */

npe_error_t npe_brute_create(const npe_brute_options_t *options,
                             npe_brute_engine_t **out_engine)
{
    if (!options || !out_engine) return NPE_ERR_INVALID;

    npe_brute_engine_t *engine = (npe_brute_engine_t *)calloc(1, sizeof(*engine));
    if (!engine) return NPE_ERROR_MEMORY;

    engine->options = *options;

    /* sensible defaults */
    if (engine->options.threads == 0)
        engine->options.threads = 1;
    if (engine->options.max_attempts == 0)
        engine->options.max_attempts = UINT32_MAX;

    strlist_init(&engine->usernames);
    strlist_init(&engine->passwords);

    engine->work_queue  = NULL;
    engine->work_total  = 0;
    engine->work_next   = 0;
    engine->stopped     = false;
    engine->result_set  = false;

    memset(&engine->stats,  0, sizeof(engine->stats));
    memset(&engine->result, 0, sizeof(engine->result));

    npe_mutex_init(&engine->mutex);
    npe_cond_init(&engine->cond);

    *out_engine = engine;
    return NPE_OK;
}

void npe_brute_destroy(npe_brute_engine_t *engine) {
    if (!engine) return;

    strlist_free(&engine->usernames);
    strlist_free(&engine->passwords);
    free(engine->work_queue);

    /* free duplicated result strings */
    if (engine->result.username) free((void *)engine->result.username);
    if (engine->result.password) free((void *)engine->result.password);

    npe_mutex_destroy(&engine->mutex);
    npe_cond_destroy(&engine->cond);

    free(engine);
}

/* ---------------------------------------------------------------------------
 * Credential list management
 * --------------------------------------------------------------------------- */

npe_error_t npe_brute_add_username(npe_brute_engine_t *engine, const char *username) {
    if (!engine || !username) return NPE_ERR_INVALID;
    return strlist_add(&engine->usernames, username);
}

npe_error_t npe_brute_add_password(npe_brute_engine_t *engine, const char *password) {
    if (!engine || !password) return NPE_ERR_INVALID;
    return strlist_add(&engine->passwords, password);
}

npe_error_t npe_brute_load_username_file(npe_brute_engine_t *engine, const char *path) {
    if (!engine || !path) return NPE_ERR_INVALID;
    return strlist_load_file(&engine->usernames, path);
}

npe_error_t npe_brute_load_password_file(npe_brute_engine_t *engine, const char *path) {
    if (!engine || !path) return NPE_ERR_INVALID;
    return strlist_load_file(&engine->passwords, path);
}

/* ---------------------------------------------------------------------------
 * Worker thread context
 * --------------------------------------------------------------------------- */

typedef struct npe_brute_worker_ctx {
    npe_brute_engine_t  *engine;
    npe_brute_auth_cb    callback;
    void                *userdata;
} npe_brute_worker_ctx_t;

/* Fetch next work item.  Returns false when no more work. */
static bool worker_fetch(npe_brute_engine_t *engine,
                         uint64_t *out_index)
{
    bool got = false;
    npe_mutex_lock(&engine->mutex);

    if (!engine->stopped && engine->work_next < engine->work_total) {
        /* respect max_attempts */
        if (engine->stats.attempts < (uint64_t)engine->options.max_attempts) {
            *out_index = engine->work_queue[engine->work_next++];
            got = true;
        }
    }

    npe_mutex_unlock(&engine->mutex);
    return got;
}

/* Record an attempt result */
static void worker_record(npe_brute_engine_t *engine,
                          bool success,
                          const char *username,
                          const char *password)
{
    npe_mutex_lock(&engine->mutex);

    engine->stats.attempts++;
    if (success) {
        engine->stats.successes++;

        if (!engine->result_set) {
            engine->result.success  = true;
            engine->result.username = strdup(username);
            engine->result.password = strdup(password);
            engine->result.attempts = (int)engine->stats.attempts;
            engine->result_set      = true;
        }

        if (engine->options.stop_on_success) {
            engine->stopped = true;
            npe_cond_broadcast(&engine->cond);
        }
    } else {
        engine->stats.failures++;
    }

    npe_mutex_unlock(&engine->mutex);
}

/* Worker thread entry point */
static NPE_THREAD_RETURN_TYPE brute_worker_func(void *arg) {
    npe_brute_worker_ctx_t *ctx = (npe_brute_worker_ctx_t *)arg;
    npe_brute_engine_t *engine  = ctx->engine;

    uint64_t linear_index;

    while (worker_fetch(engine, &linear_index)) {

        /* decode the linearised index back to user/password indices */
        uint32_t pw_count  = engine->passwords.count;
        uint32_t user_idx  = (uint32_t)(linear_index / pw_count);
        uint32_t pw_idx    = (uint32_t)(linear_index % pw_count);

        const char *username = engine->usernames.items[user_idx];
        const char *password = engine->passwords.items[pw_idx];

        /* optional inter-attempt delay */
        if (engine->options.delay_ms > 0) {
            npe_sleep_ms(engine->options.delay_ms);
        }

        /* invoke the protocol-specific authentication callback */
        bool success = false;
        npe_error_t err = ctx->callback(username, password, ctx->userdata, &success);

        if (err != NPE_OK) {
            /*
             * Treat callback errors (network timeout, connection refused, etc.)
             * as a failed attempt rather than aborting the whole run.
             * The caller can inspect stats afterwards.
             */
            success = false;
        }

        worker_record(engine, success, username, password);

        /* early exit check (stop_on_success already flips engine->stopped) */
        if (engine->stopped) break;
    }

    NPE_THREAD_RETURN;
}

/* ---------------------------------------------------------------------------
 * Build the work queue (cartesian product of usernames × passwords)
 * --------------------------------------------------------------------------- */

static npe_error_t build_work_queue(npe_brute_engine_t *engine) {

    uint64_t u_count = engine->usernames.count;
    uint64_t p_count = engine->passwords.count;

    if (u_count == 0 || p_count == 0)
        return NPE_ERR_INVALID;

    uint64_t total = u_count * p_count;

    /* overflow check */
    if (total / u_count != p_count)
        return NPE_ERROR_MEMORY;

    engine->work_queue = (uint64_t *)malloc(sizeof(uint64_t) * total);
    if (!engine->work_queue)
        return NPE_ERROR_MEMORY;

    for (uint64_t i = 0; i < total; i++) {
        engine->work_queue[i] = i;
    }

    if (engine->options.randomize) {
        srand((unsigned int)time(NULL));
        shuffle_uint64(engine->work_queue, total);
    }

    engine->work_total = total;
    engine->work_next  = 0;

    return NPE_OK;
}

/* ---------------------------------------------------------------------------
 * Execution
 * --------------------------------------------------------------------------- */

npe_error_t npe_brute_run(npe_brute_engine_t *engine,
                          npe_brute_auth_cb callback,
                          void *userdata,
                          npe_brute_result_t *result)
{
    if (!engine || !callback)
        return NPE_ERR_INVALID;

    /* build the work queue from the current credential lists */
    npe_error_t err = build_work_queue(engine);
    if (err != NPE_OK)
        return err;

    /* reset runtime state */
    engine->stopped    = false;
    engine->result_set = false;
    memset(&engine->stats,  0, sizeof(engine->stats));
    memset(&engine->result, 0, sizeof(engine->result));

    engine->start_time_ms = npe_time_ms();

    uint32_t num_threads = engine->options.threads;

    /* clamp thread count to work items so we don't spawn idle threads */
    if ((uint64_t)num_threads > engine->work_total)
        num_threads = (uint32_t)engine->work_total;

    /* allocate thread handles and per-thread context */
    npe_thread_t *threads = (npe_thread_t *)calloc(num_threads, sizeof(npe_thread_t));
    npe_brute_worker_ctx_t *contexts =
        (npe_brute_worker_ctx_t *)calloc(num_threads, sizeof(npe_brute_worker_ctx_t));

    if (!threads || !contexts) {
        free(threads);
        free(contexts);
        return NPE_ERROR_MEMORY;
    }

    /* launch worker threads */
    uint32_t launched = 0;
    for (uint32_t i = 0; i < num_threads; i++) {
        contexts[i].engine   = engine;
        contexts[i].callback = callback;
        contexts[i].userdata = userdata;

#ifdef _WIN32
        if (npe_thread_create(&threads[i],
                              (DWORD (WINAPI *)(LPVOID))brute_worker_func,
                              &contexts[i]) == 0) {
            launched++;
        }
#else
        if (npe_thread_create(&threads[i], brute_worker_func, &contexts[i]) == 0) {
            launched++;
        }
#endif
    }

    if (launched == 0) {
        free(threads);
        free(contexts);
        return NPE_ERROR_GENERIC;
    }

    /* join all threads */
    for (uint32_t i = 0; i < launched; i++) {
        npe_thread_join(threads[i]);
    }

    free(threads);
    free(contexts);

    /* finalise elapsed time */
    npe_mutex_lock(&engine->mutex);
    engine->stats.elapsed_ms = npe_time_ms() - engine->start_time_ms;
    npe_mutex_unlock(&engine->mutex);

    /* copy result out */
    if (result) {
        npe_mutex_lock(&engine->mutex);
        if (engine->result_set) {
            result->success  = true;
            result->username = engine->result.username ? strdup(engine->result.username) : NULL;
            result->password = engine->result.password ? strdup(engine->result.password) : NULL;
            result->attempts = engine->result.attempts;
        } else {
            result->success  = false;
            result->username = NULL;
            result->password = NULL;
            result->attempts = (int)engine->stats.attempts;
        }
        npe_mutex_unlock(&engine->mutex);
    }

    return NPE_OK;
}

/* ---------------------------------------------------------------------------
 * Stop (can be called from any thread, including signal handlers)
 * --------------------------------------------------------------------------- */

void npe_brute_stop(npe_brute_engine_t *engine) {
    if (!engine) return;

    npe_mutex_lock(&engine->mutex);
    engine->stopped = true;
    npe_cond_broadcast(&engine->cond);
    npe_mutex_unlock(&engine->mutex);
}

/* ---------------------------------------------------------------------------
 * Statistics
 * --------------------------------------------------------------------------- */

npe_error_t npe_brute_get_stats(npe_brute_engine_t *engine,
                                npe_brute_stats_t *stats)
{
    if (!engine || !stats) return NPE_ERR_INVALID;

    npe_mutex_lock(&engine->mutex);
    *stats = engine->stats;
    /* update elapsed if still running */
    if (engine->start_time_ms > 0) {
        stats->elapsed_ms = npe_time_ms() - engine->start_time_ms;
    }
    npe_mutex_unlock(&engine->mutex);

    return NPE_OK;
}

/* ---------------------------------------------------------------------------
 * Lua binding helpers
 *
 * Assumes the host embeds a Lua-compatible VM exposed through npe_vm_t.
 * Each C function below is registered into the "brute" Lua table.
 * --------------------------------------------------------------------------- */

/* forward declarations for the Lua C-function signatures                      *
 * npe_vm_t wraps lua_State; we cast as needed.                                */

/* We assume the following minimal VM helpers exist (declared in npe_vm.h):
 *
 *   void        *npe_vm_state(npe_vm_t *vm);           // -> lua_State *
 *   npe_error_t  npe_vm_register_cfunc(npe_vm_t *vm,
 *                    const char *table, const char *name,
 *                    int (*cfunc)(void *L));
 *
 * And the standard Lua C API is available via <lua.h> / <lauxlib.h>.
 */
#include "npe/npe_vm.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Metatype name used for the engine userdata */
#define BRUTE_ENGINE_MT "npe.brute.engine"

/* ---------- helper: push engine userdata --------------------------------- */

static npe_brute_engine_t **brute_check_engine(lua_State *L, int idx) {
    return (npe_brute_engine_t **)luaL_checkudata(L, idx, BRUTE_ENGINE_MT);
}

/* ---------- brute.new(options_table) -> engine_ud ------------------------ */

static int l_brute_new(lua_State *L) {
    npe_brute_options_t opts;
    memset(&opts, 0, sizeof(opts));

    if (lua_istable(L, 1)) {
        lua_getfield(L, 1, "threads");
        if (!lua_isnil(L, -1)) opts.threads = (uint32_t)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 1, "max_attempts");
        if (!lua_isnil(L, -1)) opts.max_attempts = (uint32_t)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 1, "delay_ms");
        if (!lua_isnil(L, -1)) opts.delay_ms = (uint32_t)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 1, "timeout_ms");
        if (!lua_isnil(L, -1)) opts.timeout_ms = (uint32_t)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 1, "stop_on_success");
        if (!lua_isnil(L, -1)) opts.stop_on_success = lua_toboolean(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 1, "randomize");
        if (!lua_isnil(L, -1)) opts.randomize = lua_toboolean(L, -1);
        lua_pop(L, 1);
    }

    npe_brute_engine_t *engine = NULL;
    npe_error_t err = npe_brute_create(&opts, &engine);
    if (err != NPE_OK) {
        return luaL_error(L, "brute.new: failed to create engine (%d)", (int)err);
    }

    npe_brute_engine_t **ud =
        (npe_brute_engine_t **)lua_newuserdata(L, sizeof(npe_brute_engine_t *));
    *ud = engine;

    luaL_getmetatable(L, BRUTE_ENGINE_MT);
    lua_setmetatable(L, -2);

    return 1; /* return the userdata */
}

/* ---------- engine:add_username_list(table) ------------------------------ */

static int l_brute_add_username_list(lua_State *L) {
    npe_brute_engine_t **ud = brute_check_engine(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);

    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
        const char *u = lua_tostring(L, -1);
        if (u) npe_brute_add_username(*ud, u);
        lua_pop(L, 1); /* pop value, keep key */
    }
    return 0;
}

/* ---------- engine:add_password_list(table) ------------------------------ */

static int l_brute_add_password_list(lua_State *L) {
    npe_brute_engine_t **ud = brute_check_engine(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);

    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
        const char *p = lua_tostring(L, -1);
        if (p) npe_brute_add_password(*ud, p);
        lua_pop(L, 1);
    }
    return 0;
}

/* ---------- Lua callback wrapper ---------------------------------------- */

/*
 * We need to call a Lua function from the C auth callback.
 * Because Lua states are NOT thread-safe, we serialise callback invocations
 * through a dedicated mutex when multi-threaded.  For true parallelism the
 * user should use coroutine-based concurrency at the Lua level; the C
 * threading here is mainly for protocols implemented entirely in C.
 */

typedef struct l_brute_cb_ctx {
    lua_State  *L;
    int         cb_ref;      /* registry reference to the Lua callback */
    npe_mutex_t lua_mutex;   /* serialise Lua calls */
} l_brute_cb_ctx_t;

static npe_error_t l_brute_auth_trampoline(const char *username,
                                           const char *password,
                                           void *userdata,
                                           bool *success)
{
    l_brute_cb_ctx_t *ctx = (l_brute_cb_ctx_t *)userdata;
    *success = false;

    npe_mutex_lock(&ctx->lua_mutex);

    lua_State *L = ctx->L;
    int top = lua_gettop(L);

    /* push the callback */
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->cb_ref);
    lua_pushstring(L, username);
    lua_pushstring(L, password);

    int pcall_err = lua_pcall(L, 2, 1, 0);
    if (pcall_err != 0) {
        /* log and swallow the error */
        const char *msg = lua_tostring(L, -1);
        np_error(NP_ERR_RUNTIME, "[brute] Lua callback error: %s\n", msg ? msg : "(unknown)");
        lua_settop(L, top);
        npe_mutex_unlock(&ctx->lua_mutex);
        return NPE_ERR_CALLBACK;
    }

    *success = lua_toboolean(L, -1);
    lua_settop(L, top);

    npe_mutex_unlock(&ctx->lua_mutex);
    return NPE_OK;
}

/* ---------- engine:run(callback) -> result_table ------------------------ */

static int l_brute_run(lua_State *L) {
    npe_brute_engine_t **ud = brute_check_engine(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    /* store the Lua callback in the registry */
    lua_pushvalue(L, 2);
    int cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    l_brute_cb_ctx_t cb_ctx;
    cb_ctx.L      = L;
    cb_ctx.cb_ref = cb_ref;
    npe_mutex_init(&cb_ctx.lua_mutex);

    npe_brute_result_t result;
    memset(&result, 0, sizeof(result));

    npe_error_t err = npe_brute_run(*ud, l_brute_auth_trampoline, &cb_ctx, &result);

    /* clean up the callback reference */
    luaL_unref(L, LUA_REGISTRYINDEX, cb_ref);
    npe_mutex_destroy(&cb_ctx.lua_mutex);

    if (err != NPE_OK && err != NPE_ERR_CALLBACK) {
        return luaL_error(L, "brute:run failed (%d)", (int)err);
    }

    /* build result table */
    lua_newtable(L);

    lua_pushboolean(L, result.success);
    lua_setfield(L, -2, "success");

    if (result.username) {
        lua_pushstring(L, result.username);
        lua_setfield(L, -2, "username");
        free((void *)result.username);
    }
    if (result.password) {
        lua_pushstring(L, result.password);
        lua_setfield(L, -2, "password");
        free((void *)result.password);
    }

    lua_pushinteger(L, result.attempts);
    lua_setfield(L, -2, "attempts");

    /* also attach stats */
    npe_brute_stats_t stats;
    npe_brute_get_stats(*ud, &stats);

    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)stats.attempts);
    lua_setfield(L, -2, "attempts");
    lua_pushinteger(L, (lua_Integer)stats.successes);
    lua_setfield(L, -2, "successes");
    lua_pushinteger(L, (lua_Integer)stats.failures);
    lua_setfield(L, -2, "failures");
    lua_pushinteger(L, (lua_Integer)stats.elapsed_ms);
    lua_setfield(L, -2, "elapsed_ms");
    lua_setfield(L, -2, "stats");

    return 1; /* return the result table */
}

/* ---------- engine:stop() ----------------------------------------------- */

static int l_brute_stop(lua_State *L) {
    npe_brute_engine_t **ud = brute_check_engine(L, 1);
    npe_brute_stop(*ud);
    return 0;
}

/* ---------- __gc metamethod --------------------------------------------- */

static int l_brute_gc(lua_State *L) {
    npe_brute_engine_t **ud = brute_check_engine(L, 1);
    if (*ud) {
        npe_brute_destroy(*ud);
        *ud = NULL;
    }
    return 0;
}

/* ---------- __tostring metamethod --------------------------------------- */

static int l_brute_tostring(lua_State *L) {
    npe_brute_engine_t **ud = brute_check_engine(L, 1);
    lua_pushfstring(L, "brute.engine(%p)", (void *)*ud);
    return 1;
}

/* ---------- registration ------------------------------------------------ */

static const luaL_Reg brute_methods[] = {
    { "add_username_list", l_brute_add_username_list },
    { "add_password_list", l_brute_add_password_list },
    { "run",               l_brute_run               },
    { "stop",              l_brute_stop              },
    { NULL, NULL }
};

static const luaL_Reg brute_meta[] = {
    { "__gc",       l_brute_gc       },
    { "__tostring", l_brute_tostring },
    { NULL, NULL }
};

static const luaL_Reg brute_funcs[] = {
    { "new", l_brute_new },
    { NULL, NULL }
};

npe_error_t npe_brute_register(npe_vm_t *vm) {
    if (!vm) return NPE_ERR_INVALID;

    lua_State *L = (lua_State *)npe_vm_state(vm);
    if (!L) return NPE_ERR_INVALID;

    /* create the metatable for engine userdata */
    luaL_newmetatable(L, BRUTE_ENGINE_MT);

    /* metatable.__index = metatable  (so methods resolve on the ud itself) */
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    /* register instance methods */
#if LUA_VERSION_NUM >= 502
    luaL_setfuncs(L, brute_methods, 0);
    luaL_setfuncs(L, brute_meta, 0);
#else
    luaL_register(L, NULL, brute_methods);
    luaL_register(L, NULL, brute_meta);
#endif

    lua_pop(L, 1); /* pop metatable */

    /* register the "brute" module table */
#if LUA_VERSION_NUM >= 502
    luaL_newlib(L, brute_funcs);
    lua_setglobal(L, "brute");
#else
    luaL_register(L, "brute", brute_funcs);
    lua_pop(L, 1);
#endif

    return NPE_OK;
}

