/*****************************************************************************
 * npe_engine.c — Engine init, run loop, shutdown
 *****************************************************************************/

#include "npe/npe_engine.h"
#include "npe/npe_types.h"
#include "npe/npe_error.h"
#include "npe/npe_loader.h"
#include "npe/npe_registry.h"
#include "npe/npe_scheduler.h"
#include "npe/npe_runtime.h"
#include "npe/npe_context.h"
#include "npe/npe_result.h"
#include "npe/npe_sandbox.h"
#include "npe/npe_script.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <fnmatch.h>
#include <errno.h>
#include <stdatomic.h>
#include <lua.h>



struct npe_engine
{
    npe_registry_t *registry;
    npe_loader_t *loader;
    npe_vm_pool_t *vm_pool;
    npe_scheduler_t *scheduler;
    npe_result_collector_t *results;
    npe_host_t *hosts;
    size_t host_count;
    size_t host_capacity;

    char *script_dir;
    char *script_db_path;

    size_t thread_pool_size;
    uint32_t default_timeout_ms;

    npe_args_t script_args;
    npe_log_fn log_fn;
    void *log_userdata;
    npe_log_level_t log_level;

    npe_progress_fn progress_fn;
    void *progress_userdata;

    atomic_bool initialized;
    atomic_bool running;
    atomic_bool abort_requested;

    size_t scripts_finished;
    size_t scripts_failed;
    size_t scripts_timed_out;

    struct timespec created_at;
};

extern int luaopen_npe_http_lib(lua_State *L);



static void engine_log(const npe_engine_t *engine, npe_log_level_t level, const char *fmt, ...)
{
    if (!engine || level < engine->log_level)
        return;

    va_list args;
    va_start(args, fmt);
    char buf[4096];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (engine->log_fn)
    {
        engine->log_fn(level, "npe_engine", buf, engine->log_userdata);
    }
    else
    {
        np_log_level_t np_level = (np_log_level_t)level;
        np_log(np_level, "[npe_engine] %s", buf);
    }
}

static npe_error_t engine_grow_hosts(npe_engine_t *engine)
{
    size_t new_cap = engine->host_capacity == 0 ? 16 : engine->host_capacity * 2;
    npe_host_t *new_hosts = realloc(engine->hosts, new_cap * sizeof(npe_host_t));
    if (!new_hosts)
    {
        LOGE("Failed to grow host array to %zu", new_cap);
        return NPE_ERROR_MEMORY;
    }
    engine->hosts = new_hosts;
    engine->host_capacity = new_cap;
    LOGD("Host array grown to capacity %zu", new_cap);
    return NPE_OK;
}

static void engine_result_callback(const npe_script_t *script, const npe_result_t *result, void *userdata)
{
    npe_engine_t *engine = (npe_engine_t *)userdata;
    if (!engine || !result)
        return;

    npe_result_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.phase = (npe_phase_t)-1;
    entry.protocol = NPE_PROTO_UNKNOWN;

    if (script)
    {
        const char *name = script->filename[0] ? script->filename : script->meta.name;
        if (name && name[0])
            snprintf(entry.script_name, sizeof(entry.script_name), "%s", name);
    }

    entry.result = *result;
    (void)npe_result_collector_add(engine->results, &entry);

    if (result->status == NPE_OK)
        engine->scripts_finished++;
    else
        engine->scripts_failed++;
}

static uint64_t timespec_diff_ms(const struct timespec *start, const struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000ULL +
           (end->tv_nsec - start->tv_nsec) / 1000000ULL;
}

npe_error_t npe_engine_create(const npe_engine_config_t *config, npe_engine_t **out)
{
    if (!out)
        return NPE_ERROR_INVALID_ARG;

    npe_engine_t *engine = calloc(1, sizeof(npe_engine_t));
    if (!engine)
    {
        LOGE("Failed to allocate engine");
        return NPE_ERROR_NOMEM;
    }

    clock_gettime(CLOCK_MONOTONIC, &engine->created_at);

    if (config)
    {
        engine->thread_pool_size = config->thread_pool_size > 0 ? config->thread_pool_size : 4;
        engine->default_timeout_ms = config->default_timeout_ms > 0 ? config->default_timeout_ms : NPE_DEFAULT_TIMEOUT_MS;
        engine->log_level = config->log_level;
        engine->log_fn = config->log_callback;
        engine->log_userdata = config->log_userdata;
        if (config->script_dir)
            engine->script_dir = strdup(config->script_dir);
        if (config->script_db_path)
            engine->script_db_path = strdup(config->script_db_path);
    }
    else
    {
        engine->thread_pool_size = 4;
        engine->default_timeout_ms = NPE_DEFAULT_TIMEOUT_MS;
        engine->log_level = NPE_LOG_INFO;
        engine->log_fn = NULL;
        engine->log_userdata = NULL;
    }

    atomic_store(&engine->initialized, false);
    atomic_store(&engine->running, false);
    atomic_store(&engine->abort_requested, false);

    npe_error_t err;

    err = npe_registry_create(&engine->registry);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    npe_loader_config_t loader_cfg = {0};
    err = npe_loader_create(&loader_cfg, &engine->loader);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    npe_vm_pool_config_t vm_cfg = {
        .initial_size = engine->thread_pool_size,
        .max_size = engine->thread_pool_size * 2,
        .vm_config = NULL // Uses defaults
    };
    err = npe_vm_pool_create(&vm_cfg, &engine->vm_pool);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    err = npe_result_collector_create(&engine->results);
    if (err != NPE_OK)
    {
        npe_engine_destroy(&engine);
        return err;
    }

    atomic_store(&engine->initialized, true);
    LOGI("Engine created: threads=%zu, timeout=%ums",
         engine->thread_pool_size, engine->default_timeout_ms);

    *out = engine;
    return NPE_OK;
}

void npe_engine_destroy(npe_engine_t **engine)
{
    if (!engine || !*engine)
        return;

    npe_engine_t *e = *engine;
    LOGD("Destroying engine");

    if (atomic_load(&e->running))
    {
        LOGW("Engine still running, requesting abort");
        atomic_store(&e->abort_requested, true);
        if (e->scheduler)
        {
            npe_scheduler_shutdown(e->scheduler);
            npe_scheduler_wait(e->scheduler, 5000); // Wait up to 5 seconds
        }
    }
    if (e->results)
        npe_result_collector_destroy(&e->results);
    if (e->vm_pool)
        npe_vm_pool_destroy(&e->vm_pool);
    if (e->loader)
        npe_loader_destroy(&e->loader);
    if (e->registry)
        npe_registry_destroy(e->registry);

    if (e->hosts)
    {
        for (size_t i = 0; i < e->host_count; i++)
        {
            if (e->hosts[i].ports)
                free(e->hosts[i].ports);
        }
        free(e->hosts);
    }
    free(e->script_dir);
    free(e->script_db_path);
    free(e);
    *engine = NULL;
}

npe_error_t npe_engine_load_scripts(npe_engine_t *engine)
{
    if (!engine)
        return NPE_ERROR_INVALID_ARG;

    if (!atomic_load(&engine->initialized))
        return NPE_ERROR_NOT_INIT;

    const char *script_dir = engine->script_dir ? engine->script_dir : "scripts/";

    engine_log(engine, NPE_LOG_INFO, "Loading scripts from: %s", script_dir);

    /* ---- scan the directory for .npe files ---- */

    size_t scan_count = 0;
    npe_error_t err = npe_loader_scan_directory(engine->loader, &scan_count);
    if (err != NPE_OK)
    {
        engine_log(engine, NPE_LOG_ERROR,
                   "Failed to scan script directory: %s",
                   npe_error_string(err));
        return err;
    }

    engine_log(engine, NPE_LOG_DEBUG, "Found %zu .npe file(s)", scan_count);

    /* ---- load all discovered scripts into the registry ---- */

    err = npe_loader_load_all(engine->loader, engine->registry);
    if (err != NPE_OK)
    {
        engine_log(engine, NPE_LOG_ERROR,
                   "Failed to load scripts: %s",
                   npe_error_string(err));
        return err;
    }

    size_t loaded_count = npe_registry_script_count(engine->registry);

    if (loaded_count == 0)
    {
        engine_log(engine, NPE_LOG_WARN, "No scripts loaded from '%s'", script_dir);
    }
    else
    {
        engine_log(engine, NPE_LOG_INFO, "Loaded %zu script(s)", loaded_count);
    }

    return NPE_OK;
}

size_t npe_engine_script_count(const npe_engine_t *engine)
{
    if (!engine || !engine->registry)
        return 0;
    return npe_registry_script_count(engine->registry);
}

npe_error_t npe_engine_select_by_category(npe_engine_t *engine, uint32_t mask)
{
    if (!engine || !engine->registry)
        return NPE_ERROR_INVALID_ARG;

    npe_script_filter_t filter = {0};
    const npe_script_t **scripts = NULL;
    size_t count = 0;

    npe_error_t err = npe_registry_query_scripts(engine->registry, &filter, &scripts, &count);
    if (err != NPE_OK)
        return err;

    size_t selected = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (scripts[i]->meta.categories & mask)
        {
            ((npe_script_t *)scripts[i])->selected = true;
            selected++;
        }
    }
    LOGD("Selected %zu scripts by category mask 0x%x", selected, mask);
    npe_registry_free_query(scripts);
    return NPE_OK;
}

npe_error_t npe_engine_select_by_name(npe_engine_t *engine, const char *name)
{
    if (!engine || !name)
        return NPE_ERROR_INVALID_ARG;

    const npe_script_t *script = NULL;
    npe_error_t err = npe_registry_find_script(engine->registry, name, &script);
    if (err != NPE_OK)
    {
        LOGW("Script not found: %s", name);
        return err;
    }

    ((npe_script_t *)script)->selected = true;
    LOGD("Selected script: %s", name);
    return NPE_OK;
}

typedef enum expr_tok_type {
    EXPR_TOK_EOF = 0,
    EXPR_TOK_IDENT,
    EXPR_TOK_AND,
    EXPR_TOK_OR,
    EXPR_TOK_NOT,
    EXPR_TOK_LPAREN,
    EXPR_TOK_RPAREN,
} expr_tok_type_t;

typedef struct expr_lexer {
    const char *src;
    size_t pos;
    expr_tok_type_t tok;
    char lexeme[128];
} expr_lexer_t;

static uint32_t expr_category_mask(const char *token)
{
    if (!token)
        return 0;
    if (strcasecmp(token, "default") == 0) return NPE_CAT_DEFAULT;
    if (strcasecmp(token, "safe") == 0) return NPE_CAT_SAFE;
    if (strcasecmp(token, "discovery") == 0) return NPE_CAT_DISCOVERY;
    if (strcasecmp(token, "vuln") == 0) return NPE_CAT_VULN;
    if (strcasecmp(token, "intrusive") == 0) return NPE_CAT_INTRUSIVE;
    if (strcasecmp(token, "auth") == 0) return NPE_CAT_AUTH;
    if (strcasecmp(token, "brute") == 0) return NPE_CAT_BRUTE;
    if (strcasecmp(token, "exploit") == 0) return NPE_CAT_EXPLOIT;
    if (strcasecmp(token, "broadcast") == 0) return NPE_CAT_BROADCAST;
    if (strcasecmp(token, "dos") == 0) return NPE_CAT_DOS;
    if (strcasecmp(token, "external") == 0) return NPE_CAT_EXTERNAL;
    if (strcasecmp(token, "fuzzer") == 0) return NPE_CAT_FUZZER;
    if (strcasecmp(token, "malware") == 0) return NPE_CAT_MALWARE;
    if (strcasecmp(token, "version") == 0) return NPE_CAT_VERSION;
    return 0;
}

static void expr_lex_next(expr_lexer_t *lx)
{
    while (lx->src[lx->pos] == ' ' || lx->src[lx->pos] == '\t' || lx->src[lx->pos] == '\n')
        lx->pos++;

    char c = lx->src[lx->pos];
    if (c == '\0')
    {
        lx->tok = EXPR_TOK_EOF;
        lx->lexeme[0] = '\0';
        return;
    }
    if (c == '(')
    {
        lx->tok = EXPR_TOK_LPAREN;
        lx->lexeme[0] = c;
        lx->lexeme[1] = '\0';
        lx->pos++;
        return;
    }
    if (c == ')')
    {
        lx->tok = EXPR_TOK_RPAREN;
        lx->lexeme[0] = c;
        lx->lexeme[1] = '\0';
        lx->pos++;
        return;
    }
    if (c == ',')
    {
        lx->tok = EXPR_TOK_OR;
        snprintf(lx->lexeme, sizeof(lx->lexeme), "or");
        lx->pos++;
        return;
    }

    size_t i = 0;
    while (lx->src[lx->pos] &&
           lx->src[lx->pos] != ' ' && lx->src[lx->pos] != '\t' && lx->src[lx->pos] != '\n' &&
           lx->src[lx->pos] != '(' && lx->src[lx->pos] != ')' && lx->src[lx->pos] != ',')
    {
        if (i + 1 < sizeof(lx->lexeme))
            lx->lexeme[i++] = lx->src[lx->pos];
        lx->pos++;
    }
    lx->lexeme[i] = '\0';

    if (strcasecmp(lx->lexeme, "and") == 0) lx->tok = EXPR_TOK_AND;
    else if (strcasecmp(lx->lexeme, "or") == 0) lx->tok = EXPR_TOK_OR;
    else if (strcasecmp(lx->lexeme, "not") == 0) lx->tok = EXPR_TOK_NOT;
    else lx->tok = EXPR_TOK_IDENT;
}

static bool expr_match_ident(const npe_script_t *script, const char *ident)
{
    if (!script || !ident || ident[0] == '\0')
        return false;

    if (strcasecmp(ident, "all") == 0)
        return true;

    uint32_t cat = expr_category_mask(ident);
    if (cat != 0)
        return (script->meta.categories & cat) != 0;

    if (strchr(ident, '*'))
        return fnmatch(ident, script->filename, 0) == 0;

    return strcasecmp(script->filename, ident) == 0;
}

static bool expr_parse_or(expr_lexer_t *lx, const npe_script_t *script);

static bool expr_parse_primary(expr_lexer_t *lx, const npe_script_t *script)
{
    if (lx->tok == EXPR_TOK_LPAREN)
    {
        expr_lex_next(lx);
        bool v = expr_parse_or(lx, script);
        if (lx->tok == EXPR_TOK_RPAREN)
            expr_lex_next(lx);
        return v;
    }

    if (lx->tok == EXPR_TOK_IDENT)
    {
        bool v = expr_match_ident(script, lx->lexeme);
        expr_lex_next(lx);
        return v;
    }

    return false;
}

static bool expr_parse_not(expr_lexer_t *lx, const npe_script_t *script)
{
    if (lx->tok == EXPR_TOK_NOT)
    {
        expr_lex_next(lx);
        return !expr_parse_not(lx, script);
    }
    return expr_parse_primary(lx, script);
}

static bool expr_parse_and(expr_lexer_t *lx, const npe_script_t *script)
{
    bool v = expr_parse_not(lx, script);
    while (lx->tok == EXPR_TOK_AND)
    {
        expr_lex_next(lx);
        v = v && expr_parse_not(lx, script);
    }
    return v;
}

static bool expr_parse_or(expr_lexer_t *lx, const npe_script_t *script)
{
    bool v = expr_parse_and(lx, script);
    while (lx->tok == EXPR_TOK_OR)
    {
        expr_lex_next(lx);
        v = v || expr_parse_and(lx, script);
    }
    return v;
}

npe_error_t npe_engine_select_by_expression(npe_engine_t *engine, const char *expr)
{
    if (!engine || !expr)
        return NPE_ERROR_INVALID_ARG;

    npe_error_t clear_err = npe_engine_select_clear(engine);
    if (clear_err != NPE_OK)
        return clear_err;

    const npe_script_t **scripts = NULL;
    size_t count = 0;
    npe_error_t qerr = npe_registry_query_scripts(engine->registry, NULL, &scripts, &count);
    if (qerr != NPE_OK)
        return qerr;

    for (size_t i = 0; i < count; i++)
    {
        expr_lexer_t lx = {
            .src = expr,
            .pos = 0,
            .tok = EXPR_TOK_EOF,
            .lexeme = {0},
        };
        expr_lex_next(&lx);
        bool selected = expr_parse_or(&lx, scripts[i]);
        ((npe_script_t *)scripts[i])->selected = selected;
    }

    npe_registry_free_query(scripts);
    return NPE_OK;
}

npe_error_t npe_engine_select_clear(npe_engine_t *engine)
{
    if (!engine || !engine->registry)
        return NPE_ERROR_INVALID_ARG;

    const npe_script_t **scripts = NULL;
    size_t count = 0;
    if (npe_registry_query_scripts(engine->registry, NULL, &scripts, &count) == NPE_OK)
    {
        for (size_t i = 0; i < count; i++)
        {
            ((npe_script_t *)scripts[i])->selected = false;
        }
        npe_registry_free_query(scripts);
    }
    LOGD("Cleared all script selections");
    return NPE_OK;
}

size_t npe_engine_selected_count(const npe_engine_t *engine)
{
    if (!engine || !engine->registry)
        return 0;

    const npe_script_t **scripts = NULL;
    size_t count = 0;
    size_t selected = 0;

    if (npe_registry_query_scripts(engine->registry, NULL, &scripts, &count) == NPE_OK)
    {
        for (size_t i = 0; i < count; i++)
        {
            if (scripts[i]->selected)
                selected++;
        }
        npe_registry_free_query(scripts);
    }
    return selected;
}

npe_error_t npe_engine_add_host(npe_engine_t *engine, const npe_host_t *host)
{
    if (!engine || !host)
        return NPE_ERROR_INVALID_ARG;

    if (engine->host_count >= engine->host_capacity)
    {
        npe_error_t err = engine_grow_hosts(engine);
        if (err != NPE_OK)
            return err;
    }

    npe_host_t *dst = &engine->hosts[engine->host_count];
    memcpy(dst, host, sizeof(npe_host_t));
    if (host->port_count > 0)
    {
        dst->ports = malloc(host->port_count * sizeof(npe_port_t));
        if (!dst->ports)
        {
            LOGE("Failed to allocate ports for host %s", host->ip);
            return NPE_ERROR_MEMORY;
        }
        memcpy(dst->ports, host->ports, host->port_count * sizeof(npe_port_t));
    }

    engine->host_count++;
    LOGD("Added host %s with %zu ports", host->ip, host->port_count);
    return NPE_OK;
}

npe_error_t npe_engine_add_host_ip(npe_engine_t *engine, const char *ip)
{
    if (!engine || !ip)
        return NPE_ERROR_INVALID_ARG;

    npe_host_t host;
    memset(&host, 0, sizeof(host));
    snprintf(host.ip, sizeof(host.ip), "%s", ip);
    return npe_engine_add_host(engine, &host);
}

npe_error_t npe_engine_clear_hosts(npe_engine_t *engine)
{
    if (!engine)
        return NPE_ERROR_INVALID_ARG;

    if (engine->hosts)
    {
        for (size_t i = 0; i < engine->host_count; i++)
        {
            if (engine->hosts[i].ports)
                free(engine->hosts[i].ports);
        }
        free(engine->hosts);
        engine->hosts = NULL;
    }
    engine->host_count = 0;
    engine->host_capacity = 0;
    LOGD("Cleared all hosts");
    return NPE_OK;
}

size_t npe_engine_host_count(const npe_engine_t *engine)
{
    return engine ? engine->host_count : 0;
}

npe_error_t npe_engine_run(npe_engine_t *engine)
{
    if (!engine)
        return NPE_ERROR_INVALID_ARG;
    if (!atomic_load(&engine->initialized))
        return NPE_ERROR_GENERIC;

    size_t selected = npe_engine_selected_count(engine);
    if (selected == 0)
    {
        LOGW("No scripts selected");
        return NPE_OK;
    }
    if (engine->host_count == 0)
    {
        LOGW("No hosts to scan");
        return NPE_OK;
    }

    LOGI("Starting engine run: %zu scripts, %zu hosts", selected, engine->host_count);

    atomic_store(&engine->running, true);
    atomic_store(&engine->abort_requested, false);
    engine->scripts_finished = 0;
    engine->scripts_failed = 0;
    engine->scripts_timed_out = 0;

    npe_scheduler_config_t sched_cfg = {
        .thread_count = engine->thread_pool_size,
        .queue_capacity = 4096,
        .default_timeout_ms = engine->default_timeout_ms,
        .engine = engine,
        .registry = engine->registry,
        .vm_pool = engine->vm_pool,
        .result_callback = engine_result_callback,
        .result_userdata = engine,
        .progress_callback = engine->progress_fn,
        .progress_userdata = engine->progress_userdata,
        .log_fn = engine->log_fn,
        .log_userdata = engine->log_userdata,
        .log_level = engine->log_level,
    };

    npe_error_t err = npe_scheduler_create(&sched_cfg, &engine->scheduler);
    if (err != NPE_OK)
    {
        LOGE("Scheduler creation failed: %d", err);
        atomic_store(&engine->running, false);
        return err;
    }

    err = npe_scheduler_run(engine->scheduler);
    if (err != NPE_OK)
    {
        LOGE("Scheduler run failed: %d", err);
        npe_scheduler_destroy(&engine->scheduler);
        engine->scheduler = NULL;
        atomic_store(&engine->running, false);
        return err;
    }

    size_t queued_work = 0;
    npe_error_t run_err = NPE_OK;

    LOGD("Queuing prerule phase");
    {
        npe_script_filter_t filter;
        memset(&filter, 0, sizeof(filter));
        filter.phase = NPE_PHASE_PRERULE;

        const npe_script_t **prerules = NULL;
        size_t prerule_count = 0;
        npe_error_t qerr = npe_registry_query_scripts(engine->registry, &filter, &prerules, &prerule_count);
        if (qerr == NPE_OK && prerule_count > 0)
        {
            for (size_t i = 0; i < prerule_count; i++)
            {
                if (!prerules[i]->selected)
                    continue;

                npe_host_t dummy;
                memset(&dummy, 0, sizeof(dummy));
                snprintf(dummy.ip, sizeof(dummy.ip), "0.0.0.0");
                npe_error_t sq = npe_scheduler_queue(engine->scheduler, prerules[i], NPE_PHASE_PRERULE, &dummy, NULL, &engine->script_args);
                if (sq != NPE_OK)
                {
                    LOGE("Failed to queue prerule '%s': %s", prerules[i]->filename, npe_error_string(sq));
                    run_err = sq;
                    break;
                }
                queued_work++;
            }
            npe_registry_free_query(prerules);
        }
    }

    if (run_err == NPE_OK)
    {
        LOGD("Queuing host/port phases for %zu hosts", engine->host_count);
        for (size_t h = 0; h < engine->host_count && run_err == NPE_OK && !atomic_load(&engine->abort_requested); h++)
        {
            const npe_host_t *host = &engine->hosts[h];

            npe_script_filter_t filter;
            memset(&filter, 0, sizeof(filter));
            filter.phase = NPE_PHASE_HOSTRULE;

            const npe_script_t **hostrules = NULL;
            size_t hc = 0;
            npe_error_t qerr = npe_registry_query_scripts(engine->registry, &filter, &hostrules, &hc);
            if (qerr == NPE_OK && hc > 0)
            {
                for (size_t i = 0; i < hc && run_err == NPE_OK; i++)
                {
                    const npe_script_t *found = NULL;
                    npe_error_t ferr = npe_registry_find_script(engine->registry, hostrules[i]->filename, &found);
                    if (ferr == NPE_OK && found && found->selected)
                    {
                        npe_error_t sq = npe_scheduler_queue(engine->scheduler, found, NPE_PHASE_HOSTRULE, host, NULL, &engine->script_args);
                        if (sq != NPE_OK)
                        {
                            LOGE("Failed to queue hostrule '%s': %s", found->filename, npe_error_string(sq));
                            run_err = sq;
                            break;
                        }
                        queued_work++;
                    }
                }
                npe_registry_free_query(hostrules);
            }

            for (size_t p = 0; p < host->port_count && run_err == NPE_OK; p++)
            {
                const npe_port_t *port = &host->ports[p];
                if (port->state != NPE_PORT_OPEN)
                    continue;

                npe_script_filter_t pf;
                memset(&pf, 0, sizeof(pf));
                pf.phase = NPE_PHASE_PORTRULE;
                pf.port = port->number;

                const npe_script_t **portrules = NULL;
                size_t prc = 0;
                npe_error_t pq = npe_registry_query_scripts(engine->registry, &pf, &portrules, &prc);
                if (pq == NPE_OK && prc > 0)
                {
                    for (size_t i = 0; i < prc && run_err == NPE_OK; i++)
                    {
                        const npe_script_t *found = NULL;
                        npe_error_t ferr = npe_registry_find_script(engine->registry, portrules[i]->filename, &found);
                        if (ferr == NPE_OK && found && found->selected)
                        {
                            npe_error_t sq = npe_scheduler_queue(engine->scheduler, found, NPE_PHASE_PORTRULE, host, port, &engine->script_args);
                            if (sq != NPE_OK)
                            {
                                LOGE("Failed to queue portrule '%s': %s", found->filename, npe_error_string(sq));
                                run_err = sq;
                                break;
                            }
                            queued_work++;
                        }
                    }
                    npe_registry_free_query(portrules);
                }
            }
        }
    }

    if (run_err == NPE_OK && !atomic_load(&engine->abort_requested))
    {
        LOGD("Queuing postrule phase");
        npe_script_filter_t filter;
        memset(&filter, 0, sizeof(filter));
        filter.phase = NPE_PHASE_POSTRULE;

        const npe_script_t **postrules = NULL;
        size_t ptc = 0;
        npe_error_t qerr = npe_registry_query_scripts(engine->registry, &filter, &postrules, &ptc);
        if (qerr == NPE_OK && ptc > 0)
        {
            for (size_t i = 0; i < ptc && run_err == NPE_OK; i++)
            {
                if (!postrules[i]->selected)
                    continue;

                npe_host_t dummy;
                memset(&dummy, 0, sizeof(dummy));
                snprintf(dummy.ip, sizeof(dummy.ip), "0.0.0.0");
                npe_error_t sq = npe_scheduler_queue(engine->scheduler, postrules[i], NPE_PHASE_POSTRULE, &dummy, NULL, &engine->script_args);
                if (sq != NPE_OK)
                {
                    LOGE("Failed to queue postrule '%s': %s", postrules[i]->filename, npe_error_string(sq));
                    run_err = sq;
                    break;
                }
                queued_work++;
            }
            npe_registry_free_query(postrules);
        }
    }

    if (queued_work == 0)
        LOGW("No work was queued; check host/port configuration");

    if (run_err == NPE_OK)
    {
        err = npe_scheduler_wait(engine->scheduler, 0);
        if (err != NPE_OK)
        {
            LOGW("Scheduler wait returned %d", err);
            run_err = err;
        }

    }

    npe_scheduler_wait(engine->scheduler, 5000);
    npe_scheduler_destroy(&engine->scheduler);
    engine->scheduler = NULL;
    atomic_store(&engine->running, false);

    LOGI("Engine run complete: finished=%zu, failed=%zu", engine->scripts_finished, engine->scripts_failed);

    return run_err;
}

npe_error_t npe_engine_abort(npe_engine_t *engine)
{
    if (!engine)
        return NPE_ERROR_INVALID_ARG;
    LOGW("Abort requested");
    atomic_store(&engine->abort_requested, true);
    if (engine->scheduler)
        npe_scheduler_shutdown(engine->scheduler); // FIX: Removed &
    return NPE_OK;
}

npe_error_t npe_engine_get_results(const npe_engine_t *engine, const npe_result_t **results, size_t *count)
{
    if (!engine || !results || !count)
        return NPE_ERROR_INVALID_ARG;

    npe_result_entry_t *entries = NULL;
    size_t entry_count = 0;
    npe_error_t err = npe_result_collector_get_all(engine->results, &entries, &entry_count);
    if (err != NPE_OK)
        return err;

    if (entry_count == 0)
    {
        *results = NULL;
        *count = 0;
        free(entries);
        return NPE_OK;
    }

    npe_result_t *flat = calloc(entry_count, sizeof(npe_result_t));
    if (!flat)
    {
        free(entries);
        return NPE_ERROR_MEMORY;
    }

    for (size_t i = 0; i < entry_count; i++)
    {
        flat[i] = entries[i].result;
    }

    free(entries);
    *results = flat;
    *count = entry_count;
    return NPE_OK;
}

npe_error_t npe_engine_get_result_entries(const npe_engine_t *engine,
                                          npe_result_entry_t **entries,
                                          size_t *count)
{
    if (!engine || !entries || !count)
        return NPE_ERROR_INVALID_ARG;

    return npe_result_collector_get_all(engine->results, entries, count);
}

npe_error_t npe_engine_get_stats(const npe_engine_t *engine, npe_engine_stats_t *stats)
{
    if (!engine || !stats)
        return NPE_ERROR_INVALID_ARG;

    memset(stats, 0, sizeof(*stats));
    stats->scripts_total = npe_registry_script_count(engine->registry);
    stats->scripts_selected = npe_engine_selected_count(engine);
    stats->scripts_finished = engine->scripts_finished;
    stats->scripts_failed = engine->scripts_failed;
    stats->scripts_timed_out = engine->scripts_timed_out;
    stats->hosts_total = engine->host_count;

    if (engine->scheduler)
    {
        npe_scheduler_stats_t ss;
        npe_scheduler_get_stats(engine->scheduler, &ss);
        stats->scripts_running = ss.total_running;
        stats->scripts_queued = ss.queue_depth;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    stats->uptime_ms = timespec_diff_ms(&engine->created_at, &now);

    return NPE_OK;
}

const char *npe_engine_version(void)
{
    return NPE_VERSION_STRING;
}
