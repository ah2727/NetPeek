/*****************************************************************************
 * npe_context.c — Per-script execution context implementation
 * ───────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *****************************************************************************/

#include "npe_context.h"
#include "npe_script.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Lua header — we accept void* in the public API to avoid leaking lua.h */
#include <lua.h>
#include <lauxlib.h>

/*============================================================================
 * Internal helpers
 *============================================================================*/

static const char *protocol_str(npe_protocol_t p)
{
    switch (p)
    {
    case NPE_PROTO_TCP:
        return "tcp";
    case NPE_PROTO_UDP:
        return "udp";
    case NPE_PROTO_SCTP:
        return "sctp";
    default:
        return "unknown";
    }
}

static char *ctx_strdup(const char *s)
{
    if (!s)
        return NULL;
    size_t len = strlen(s) + 1;
    char *d = malloc(len);
    if (d)
    {
        memcpy(d, s, len);
    }
    else
    {
        np_log(NP_LOG_ERROR, "ctx_strdup: malloc failed for %zu bytes", len);
    }
    return d;
}

static void free_value(npe_value_t *v);

static void free_table(npe_table_t *table)
{
    if (!table)
        return;

    for (size_t i = 0; i < table->count; i++)
    {
        free(table->entries[i].key);
        table->entries[i].key = NULL;
        free_value(&table->entries[i].val);
    }

    free(table->entries);
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
    free(table);
}

static npe_buffer_t *clone_buffer(const npe_buffer_t *src)
{
    if (!src)
        return NULL;

    npe_buffer_t *dst = calloc(1, sizeof(*dst));
    if (!dst)
        return NULL;

    dst->size = src->size;
    dst->capacity = src->size;
    dst->owned = true;

    if (src->size > 0 && src->data)
    {
        dst->data = malloc(src->size);
        if (!dst->data)
        {
            free(dst);
            return NULL;
        }
        memcpy(dst->data, src->data, src->size);
    }

    return dst;
}

static npe_table_t *clone_table(const npe_table_t *src)
{
    if (!src)
        return NULL;

    npe_table_t *dst = calloc(1, sizeof(*dst));
    if (!dst)
        return NULL;

    if (src->count == 0)
        return dst;

    dst->entries = calloc(src->count, sizeof(npe_kv_t));
    if (!dst->entries)
    {
        free(dst);
        return NULL;
    }

    dst->capacity = src->count;
    dst->count = src->count;

    for (size_t i = 0; i < src->count; i++)
    {
        if (src->entries[i].key)
        {
            dst->entries[i].key = ctx_strdup(src->entries[i].key);
            if (!dst->entries[i].key)
            {
                free_table(dst);
                return NULL;
            }
        }

        dst->entries[i].val = (npe_value_t){0};
        switch (src->entries[i].val.type)
        {
        case NPE_VAL_STRING:
            dst->entries[i].val.type = NPE_VAL_STRING;
            dst->entries[i].val.v.s = ctx_strdup(src->entries[i].val.v.s ? src->entries[i].val.v.s : "");
            if (!dst->entries[i].val.v.s)
            {
                free_table(dst);
                return NULL;
            }
            break;
        case NPE_VAL_BUFFER:
            dst->entries[i].val.type = NPE_VAL_BUFFER;
            dst->entries[i].val.v.buf = clone_buffer(src->entries[i].val.v.buf);
            if (src->entries[i].val.v.buf && !dst->entries[i].val.v.buf)
            {
                free_table(dst);
                return NULL;
            }
            break;
        case NPE_VAL_TABLE:
            dst->entries[i].val.type = NPE_VAL_TABLE;
            dst->entries[i].val.v.tbl = clone_table(src->entries[i].val.v.tbl);
            if (src->entries[i].val.v.tbl && !dst->entries[i].val.v.tbl)
            {
                free_table(dst);
                return NULL;
            }
            break;
        default:
            dst->entries[i].val = src->entries[i].val;
            break;
        }
    }

    return dst;
}

static void deep_copy_value(npe_value_t *dst, const npe_value_t *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->type = src->type;

    switch (src->type)
    {
    case NPE_VAL_NIL:
    case NPE_VAL_BOOL:
    case NPE_VAL_INT:
    case NPE_VAL_FLOAT:
    case NPE_VAL_FUNCTION:
    case NPE_VAL_USERDATA:
        dst->v = src->v;
        break;
    case NPE_VAL_STRING:
        if (src->v.s)
        {
            dst->v.s = ctx_strdup(src->v.s);
            if (!dst->v.s)
            {
                np_log(NP_LOG_WARN, "deep_copy_value: failed to duplicate string");
            }
        }
        else
        {
            dst->v.s = ctx_strdup("");
        }
        break;
    case NPE_VAL_BUFFER:
        dst->v.buf = clone_buffer(src->v.buf);
        if (src->v.buf && !dst->v.buf)
        {
            dst->type = NPE_VAL_NIL;
            np_log(NP_LOG_WARN, "deep_copy_value: failed to duplicate buffer");
        }
        break;
    case NPE_VAL_TABLE:
        dst->v.tbl = clone_table(src->v.tbl);
        if (src->v.tbl && !dst->v.tbl)
        {
            dst->type = NPE_VAL_NIL;
            np_log(NP_LOG_WARN, "deep_copy_value: failed to duplicate table");
        }
        break;
    default:
        dst->type = NPE_VAL_NIL;
        break;
    }
}

static void free_value(npe_value_t *v)
{
    if (!v)
        return;
    switch (v->type)
    {
    case NPE_VAL_STRING:
        free(v->v.s);
        v->v.s = NULL;
        break;
    case NPE_VAL_BUFFER:
        if (v->v.buf)
        {
            if (v->v.buf->owned)
                free(v->v.buf->data);
            free(v->v.buf);
            v->v.buf = NULL;
        }
        break;
    case NPE_VAL_TABLE:
        free_table(v->v.tbl);
        v->v.tbl = NULL;
        break;
    default:
        break;
    }
    v->type = NPE_VAL_NIL;
}

/*============================================================================
 * Deep-copy helpers for host / port
 *============================================================================*/

static npe_error_t deep_copy_port(npe_port_t *dst, const npe_port_t *src)
{
    np_log(NP_LOG_DEBUG, "deep_copy_port: copying port %d/%s",
           src->number, protocol_str(src->protocol));

    dst->number = src->number;
    dst->protocol = src->protocol;
    dst->state = src->state;
    dst->service_name = ctx_strdup(src->service_name);
    dst->version_info = ctx_strdup(src->version_info);

    if ((src->service_name && !dst->service_name) ||
        (src->version_info && !dst->version_info))
    {
        np_log(NP_LOG_WARN, "deep_copy_port: memory allocation failed for port %d",
               src->number);
        return NPE_ERROR_MEMORY;
    }

    return NPE_OK;
}

static void free_port_contents(npe_port_t *p)
{
    if (!p)
        return;

    np_log(NP_LOG_DEBUG, "free_port_contents: freeing port %d", p->number);

    free(p->service_name);
    free(p->version_info);
    p->service_name = NULL;
    p->version_info = NULL;
}

static npe_error_t deep_copy_host(npe_host_t *dst, const npe_host_t *src)
{
    np_log(NP_LOG_DEBUG, "deep_copy_host: copying host %s", src->ip);

    memset(dst, 0, sizeof(*dst));

    snprintf(dst->ip, sizeof(dst->ip), "%s", src->ip);
    snprintf(dst->hostname, sizeof(dst->hostname), "%s", src->hostname);
    memcpy(dst->mac, src->mac, sizeof(dst->mac));

    dst->port_count = src->port_count;
    dst->os_info = clone_table(src->os_info);
    if (src->os_info && !dst->os_info)
    {
        np_log(NP_LOG_WARN, "deep_copy_host: failed to duplicate os_info table");
        return NPE_ERROR_MEMORY;
    }

    if (src->port_count > 0 && src->ports)
    {
        dst->ports = calloc(src->port_count, sizeof(npe_port_t));
        if (!dst->ports)
        {
            np_log(NP_LOG_ERROR, "deep_copy_host: calloc failed for %zu ports",
                   src->port_count);
            return NPE_ERROR_MEMORY;
        }
        for (size_t i = 0; i < src->port_count; i++)
        {
            npe_error_t err = deep_copy_port(&dst->ports[i], &src->ports[i]);
            if (NPE_FAILED(err))
            {
                np_log(NP_LOG_ERROR, "deep_copy_host: failed to copy port %zu", i);
                return err;
            }
        }
        np_log(NP_LOG_DEBUG, "deep_copy_host: copied %zu ports for host %s",
               src->port_count, src->ip);
    }
    else if (src->port_count > 0)
    {
        np_log(NP_LOG_WARN, "deep_copy_host: port_count=%zu but ports is NULL",
               src->port_count);
    }
    return NPE_OK;
}

static void free_host_contents(npe_host_t *h)
{
    if (!h)
        return;

    np_log(NP_LOG_DEBUG, "free_host_contents: freeing host %s with %zu ports",
           h->ip, h->port_count);

    if (h->ports)
    {
        for (size_t i = 0; i < h->port_count; i++)
            free_port_contents(&h->ports[i]);
        free(h->ports);
        h->ports = NULL;
    }
    h->port_count = 0;

    free_table(h->os_info);
    h->os_info = NULL;
}

/*============================================================================
 * Deep-copy args
 *============================================================================*/

static npe_error_t deep_copy_args(npe_args_t *dst, const npe_args_t *src)
{
    np_log(NP_LOG_DEBUG, "deep_copy_args: copying %zu arguments", src->count);

    dst->count = src->count;
    for (size_t i = 0; i < src->count; i++)
    {
        dst->items[i].key = ctx_strdup(src->items[i].key);
        dst->items[i].value = ctx_strdup(src->items[i].value);

        if ((src->items[i].key && !dst->items[i].key) ||
            (src->items[i].value && !dst->items[i].value))
        {
            np_log(NP_LOG_WARN, "deep_copy_args: memory allocation failed for arg %zu", i);
            return NPE_ERROR_MEMORY;
        }
    }
    return NPE_OK;
}

static void free_args(npe_args_t *a)
{
    if (a->count > 0)
    {
        np_log(NP_LOG_DEBUG, "free_args: freeing %zu arguments", a->count);
    }

    for (size_t i = 0; i < a->count; i++)
    {
        free(a->items[i].key);
        free(a->items[i].value);
        a->items[i].key = NULL;
        a->items[i].value = NULL;
    }
    a->count = 0;
}

/*============================================================================
 * Lifecycle
 *============================================================================*/

npe_error_t npe_context_create(npe_engine_t *engine,
                               const npe_script_t *script,
                               const npe_host_t *host,
                               const npe_port_t *port,
                               npe_context_t **out)
{
    np_log(NP_LOG_INFO, "npe_context_create: creating new context for host %s",
           host ? host->ip : "NULL");

    if (!engine || !script || !host || !out)
    {
        np_log(NP_LOG_ERROR, "npe_context_create: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    npe_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        np_log(NP_LOG_ERROR, "npe_context_create: calloc failed");
        return NPE_ERROR_MEMORY;
    }

    static _Atomic uint64_t next_id = 1;
    ctx->id = next_id++;
    ctx->state = NPE_CTX_STATE_INIT;
    ctx->flags = NPE_CTX_FLAG_NONE;
    ctx->engine = engine;
    ctx->script = script;
    ctx->vm = NULL;
    ctx->store = NULL;
    ctx->next = NULL;
    ctx->timeout_ms = NPE_DEFAULT_TIMEOUT_MS;

    np_log(NP_LOG_DEBUG, "npe_context_create: context id=%lu created", ctx->id);

    npe_error_t err = deep_copy_host(&ctx->host, host);
    if (NPE_FAILED(err))
    {
        np_log(NP_LOG_ERROR, "npe_context_create: failed to copy host");
        free(ctx);
        return err;
    }

    if (port)
    {
        err = deep_copy_port(&ctx->port, port);
        if (NPE_FAILED(err))
        {
            np_log(NP_LOG_ERROR, "npe_context_create: failed to copy port");
            free_host_contents(&ctx->host);
            free(ctx);
            return err;
        }
        ctx->has_port = true;
        np_log(NP_LOG_DEBUG, "npe_context_create: port %d associated", port->number);
    }

    clock_gettime(CLOCK_MONOTONIC, &ctx->created_at);

    ctx->result.status = NPE_OK;
    ctx->result.output.type = NPE_VAL_NIL;

    *out = ctx;

    np_log(NP_LOG_INFO, "npe_context_create: context id=%lu ready for host %s",
           ctx->id, host->ip);
    return NPE_OK;
}

void npe_context_destroy(npe_context_t **ctx)
{
    if (!ctx || !*ctx)
    {
        np_log(NP_LOG_WARN, "npe_context_destroy: NULL context");
        return;
    }

    npe_context_t *c = *ctx;

    np_log(NP_LOG_INFO, "npe_context_destroy: destroying context id=%lu", c->id);

    free_host_contents(&c->host);
    if (c->has_port)
        free_port_contents(&c->port);
    free_args(&c->args);
    free_value(&c->result.output);

    if (c->store)
    {
        np_log(NP_LOG_DEBUG, "npe_context_destroy: freeing store table");
        free_table(c->store);
        c->store = NULL;
    }

    free(c);
    *ctx = NULL;

    np_log(NP_LOG_DEBUG, "npe_context_destroy: context destroyed");
}

/*============================================================================
 * Lua Table Pushers
 *============================================================================*/

static const char *port_state_str(npe_port_state_t s)
{
    switch (s)
    {
    case NPE_PORT_OPEN:
        return "open";
    case NPE_PORT_CLOSED:
        return "closed";
    case NPE_PORT_FILTERED:
        return "filtered";
    case NPE_PORT_UNFILTERED:
        return "unfiltered";
    case NPE_PORT_OPEN_FILTERED:
        return "open|filtered";
    case NPE_PORT_CLOSED_FILTERED:
        return "closed|filtered";
    default:
        return "unknown";
    }
}

npe_error_t npe_context_push_host(npe_context_t *ctx, void *lua_state)
{
    if (!ctx || !lua_state)
    {
        np_log(NP_LOG_ERROR, "npe_context_push_host: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    lua_State *L = (lua_State *)lua_state;

    np_log(NP_LOG_DEBUG, "npe_context_push_host: pushing host %s to Lua", ctx->host.ip);

    lua_newtable(L);

    lua_pushstring(L, ctx->host.ip);
    lua_setfield(L, -2, "ip");

    lua_pushstring(L, ctx->host.hostname);
    lua_setfield(L, -2, "hostname");

    lua_pushinteger(L, (lua_Integer)ctx->host.port_count);
    lua_setfield(L, -2, "port_count");

    return NPE_OK;
}

npe_error_t npe_context_push_port(npe_context_t *ctx, void *lua_state)
{
    if (!ctx || !lua_state)
    {
        np_log(NP_LOG_ERROR, "npe_context_push_port: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    if (!ctx->has_port)
    {
        np_log(NP_LOG_ERROR, "npe_context_push_port: context has no port");
        return NPE_ERROR_INVALID_ARG;
    }

    lua_State *L = (lua_State *)lua_state;

    np_log(NP_LOG_DEBUG, "npe_context_push_port: pushing port %d to Lua", ctx->port.number);

    lua_newtable(L);

    lua_pushinteger(L, (lua_Integer)ctx->port.number);
    lua_setfield(L, -2, "number");

    lua_pushstring(L, protocol_str(ctx->port.protocol));
    lua_setfield(L, -2, "protocol");

    lua_pushstring(L, port_state_str(ctx->port.state));
    lua_setfield(L, -2, "state");

    if (ctx->port.service_name)
    {
        lua_pushstring(L, ctx->port.service_name);
        lua_setfield(L, -2, "service");
    }

    if (ctx->port.version_info)
    {
        lua_pushstring(L, ctx->port.version_info);
        lua_setfield(L, -2, "version");
    }

    return NPE_OK;
}

npe_error_t npe_context_push_args(npe_context_t *ctx, void *lua_state)
{
    if (!ctx || !lua_state)
    {
        np_log(NP_LOG_ERROR, "npe_context_push_args: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    lua_State *L = (lua_State *)lua_state;

    np_log(NP_LOG_DEBUG, "npe_context_push_args: pushing %zu arguments to Lua",
           ctx->args.count);

    lua_newtable(L);

    for (size_t i = 0; i < ctx->args.count; i++)
    {
        const char *key = ctx->args.items[i].key;
        const char *value = ctx->args.items[i].value;
        if (!key)
            continue;
        lua_pushstring(L, value ? value : "");
        lua_setfield(L, -2, key);
    }

    return NPE_OK;
}

/*============================================================================
 * Private Store
 *============================================================================*/

npe_error_t npe_context_store_set(npe_context_t *ctx,
                                  const char *key,
                                  const npe_value_t *value)
{
    if (!ctx || !key || !value)
    {
        np_log(NP_LOG_ERROR, "npe_context_store_set: invalid arguments");
        return NPE_ERROR_INVALID_ARG;
    }

    /* Lazy-init the store table */
    if (!ctx->store)
    {
        ctx->store = calloc(1, sizeof(npe_table_t));
        if (!ctx->store)
        {
            np_log(NP_LOG_ERROR, "npe_context_store_set: calloc failed for store");
            return NPE_ERROR_MEMORY;
        }
        np_log(NP_LOG_DEBUG, "npe_context_store_set: initialized store for ctx id=%lu",
               ctx->id);
    }

    npe_table_t *t = ctx->store;

    /* Check for existing key — overwrite */
    for (size_t i = 0; i < t->count; i++)
    {
        if (t->entries[i].key && strcmp(t->entries[i].key, key) == 0)
        {
            np_log(NP_LOG_DEBUG, "npe_context_store_set: overwriting key '%s' in ctx id=%lu",
                   key, ctx->id);
            free_value(&t->entries[i].val);
            deep_copy_value(&t->entries[i].val, value);
            return NPE_OK;
        }
    }

    /* Grow if needed */
    if (t->count >= t->capacity)
    {
        size_t new_cap = t->capacity ? t->capacity * 2 : 8;
        npe_kv_t *tmp = realloc(t->entries, new_cap * sizeof(npe_kv_t));
        if (!tmp)
        {
            np_log(NP_LOG_ERROR, "npe_context_store_set: realloc failed for %zu entries",
                   new_cap);
            return NPE_ERROR_MEMORY;
        }
        t->entries = tmp;
        t->capacity = new_cap;
        np_log(NP_LOG_DEBUG, "npe_context_store_set: store grown to capacity %zu",
               new_cap);
    }

    npe_kv_t *kv = &t->entries[t->count++];
    kv->key = ctx_strdup(key);
    if (!kv->key)
    {
        np_log(NP_LOG_ERROR, "npe_context_store_set: strdup failed for key '%s'", key);
        t->count--;
        return NPE_ERROR_MEMORY;
    }

    deep_copy_value(&kv->val, value);

    np_log(NP_LOG_DEBUG, "npe_context_store_set: stored key '%s' in ctx id=%lu (total: %zu)",
           key, ctx->id, t->count);

    return NPE_OK;
}

const npe_value_t *npe_context_store_get(const npe_context_t *ctx,
                                         const char *key)
{
    if (!ctx || !key)
    {
        np_log(NP_LOG_WARN, "npe_context_store_get: invalid arguments");
        return NULL;
    }

    if (!ctx->store)
    {
        np_log(NP_LOG_DEBUG, "npe_context_store_get: no store for ctx id=%lu", ctx->id);
        return NULL;
    }

    const npe_table_t *t = ctx->store;
    for (size_t i = 0; i < t->count; i++)
    {
        if (t->entries[i].key && strcmp(t->entries[i].key, key) == 0)
        {
            np_log(NP_LOG_DEBUG, "npe_context_store_get: found key '%s' in ctx id=%lu",
                   key, ctx->id);
            return &t->entries[i].val;
        }
    }

    np_log(NP_LOG_DEBUG, "npe_context_store_get: key '%s' not found in ctx id=%lu",
           key, ctx->id);
    return NULL;
}

/*============================================================================
 * State / Flag Helpers
 *============================================================================*/

void npe_context_set_state(npe_context_t *ctx, npe_ctx_state_t state)
{
    if (ctx)
    {
        const char *state_str = "UNKNOWN";
        switch (state)
        {
        case NPE_CTX_STATE_INIT:
            state_str = "INIT";
            break;
        case NPE_CTX_STATE_RUNNING:
            state_str = "RUNNING";
            break;
        case NPE_CTX_STATE_COMPLETED:
            state_str = "COMPLETED";
            break;
        case NPE_CTX_STATE_ERROR:
            state_str = "ERROR";
            break;
        case NPE_CTX_STATE_TIMEOUT:
            state_str = "TIMEOUT";
            break;
        }
        np_log(NP_LOG_DEBUG, "npe_context_set_state: ctx id=%lu -> %s",
               ctx->id, state_str);
        ctx->state = state;
    }
}

void npe_context_set_flag(npe_context_t *ctx, npe_ctx_flag_t flag)
{
    if (ctx)
    {
        np_log(NP_LOG_DEBUG, "npe_context_set_flag: ctx id=%lu, flag=0x%x",
               ctx->id, flag);
        ctx->flags |= (uint32_t)flag;
    }
}

void npe_context_clear_flag(npe_context_t *ctx, npe_ctx_flag_t flag)
{
    if (ctx)
    {
        np_log(NP_LOG_DEBUG, "npe_context_clear_flag: ctx id=%lu, flag=0x%x",
               ctx->id, flag);
        ctx->flags &= ~(uint32_t)flag;
    }
}

bool npe_context_has_flag(const npe_context_t *ctx, npe_ctx_flag_t flag)
{
    bool result = ctx ? (ctx->flags & (uint32_t)flag) != 0 : false;
    if (np_logger_is_verbose())
    {
        np_log(NP_LOG_DEBUG, "npe_context_has_flag: ctx id=%lu, flag=0x%x -> %s",
               ctx ? ctx->id : 0, flag, result ? "true" : "false");
    }
    return result;
}
