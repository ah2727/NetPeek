/*****************************************************************************
 * npe_registry.c — Script database and category index
 *****************************************************************************/

#include "npe/npe_registry.h"
#include "npe/npe_script.h"
#include "logger.h"

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <time.h>

#define NPE_REGISTRY_CACHE_MAGIC "NPE_REGISTRY_CACHE_V1"

static const uint8_t *find_bytes(const uint8_t *hay,
                                 size_t hay_len,
                                 const uint8_t *needle,
                                 size_t needle_len)
{
    if (!hay || !needle || needle_len == 0 || hay_len < needle_len)
        return NULL;
    for (size_t i = 0; i + needle_len <= hay_len; i++)
    {
        if (memcmp(hay + i, needle, needle_len) == 0)
            return hay + i;
    }
    return NULL;
}

struct npe_registry
{
    pthread_rwlock_t lock;

    const npe_script_t **scripts;
    size_t script_count;
    size_t script_cap;

    npe_service_fp_t *service_fps;
    size_t service_fp_count;
    size_t service_fp_cap;

    npe_shared_entry_t *shared;
    size_t shared_count;
    size_t shared_cap;
};

struct npe_registry_iter
{
    const npe_registry_t *reg;
    size_t index;
};

static char *reg_strdup(const char *s)
{
    if (!s)
        return NULL;
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (!out)
        return NULL;
    memcpy(out, s, n);
    return out;
}

static void reg_write_escaped(FILE *fp, const char *s)
{
    if (!fp || !s)
        return;

    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    {
        switch (*p)
        {
        case '\\': fputs("\\\\", fp); break;
        case '\t': fputs("\\t", fp); break;
        case '\n': fputs("\\n", fp); break;
        case '\r': fputs("\\r", fp); break;
        default: fputc(*p, fp); break;
        }
    }
}

static void reg_unescape_inplace(char *s)
{
    if (!s)
        return;

    char *rd = s;
    char *wr = s;
    while (*rd)
    {
        if (*rd == '\\' && rd[1] != '\0')
        {
            rd++;
            switch (*rd)
            {
            case 't': *wr++ = '\t'; break;
            case 'n': *wr++ = '\n'; break;
            case 'r': *wr++ = '\r'; break;
            case '\\': *wr++ = '\\'; break;
            default:
                *wr++ = *rd;
                break;
            }
            rd++;
            continue;
        }

        *wr++ = *rd++;
    }

    *wr = '\0';
}

static const char *script_name(const npe_script_t *script)
{
    if (!script)
        return NULL;
    if (script->filename[0] != '\0')
        return script->filename;
    return script->meta.name;
}

static bool script_has_phase_local(const npe_script_t *script, npe_phase_t phase)
{
    if (!script)
        return false;
    switch (phase)
    {
    case NPE_PHASE_PRERULE:
        return script->meta.has_prerule;
    case NPE_PHASE_HOSTRULE:
        return script->meta.has_hostrule;
    case NPE_PHASE_PORTRULE:
        return script->meta.has_portrule;
    case NPE_PHASE_POSTRULE:
        return script->meta.has_postrule;
    default:
        return false;
    }
}

static bool script_matches_port(const npe_script_t *script,
                                uint16_t port,
                                npe_protocol_t proto)
{
    if (!script)
        return false;
    if (!script->meta.has_portrule)
        return false;

    bool port_match = (script->meta.interest_port_count == 0);
    for (size_t i = 0; i < script->meta.interest_port_count; i++)
    {
        if (script->meta.interest_ports[i] == port)
        {
            port_match = true;
            break;
        }
    }
    if (!port_match)
        return false;

    if (script->meta.interest_protocol_count == 0)
        return true;
    for (size_t i = 0; i < script->meta.interest_protocol_count; i++)
    {
        if (script->meta.interest_protocols[i] == proto)
            return true;
    }
    return false;
}

static npe_error_t ensure_script_cap(npe_registry_t *reg, size_t need)
{
    if (need <= reg->script_cap)
        return NPE_OK;
    size_t cap = reg->script_cap == 0 ? 32 : reg->script_cap * 2;
    while (cap < need)
        cap *= 2;
    const npe_script_t **tmp = (const npe_script_t **)realloc(reg->scripts, cap * sizeof(*tmp));
    if (!tmp){
        LOGE("Failed to allocate script capacity %zu", cap);
        return NPE_ERROR_MEMORY;
    }
    reg->scripts = tmp;
    reg->script_cap = cap;LOGD("Expanded script capacity to %zu", cap);
    return NPE_OK;
}

static npe_error_t ensure_fp_cap(npe_registry_t *reg, size_t need)
{
    if (need <= reg->service_fp_cap)
        return NPE_OK;
    size_t cap = reg->service_fp_cap == 0 ? 32 : reg->service_fp_cap * 2;
    while (cap < need)
        cap *= 2;
    npe_service_fp_t *tmp = (npe_service_fp_t *)realloc(reg->service_fps, cap * sizeof(*tmp));
    if (!tmp)
    {
        LOGE("Failed to allocate service FP capacity %zu", cap);
        return NPE_ERROR_MEMORY;
    }
    reg->service_fps = tmp;
    reg->service_fp_cap = cap;
    LOGD("Expanded service FP capacity to %zu", cap);
    return NPE_OK;
}

static npe_error_t ensure_shared_cap(npe_registry_t *reg, size_t need)
{
    if (need <= reg->shared_cap)
        return NPE_OK;
    size_t cap = reg->shared_cap == 0 ? 32 : reg->shared_cap * 2;
    while (cap < need)
        cap *= 2;
    npe_shared_entry_t *tmp = (npe_shared_entry_t *)realloc(reg->shared, cap * sizeof(*tmp));
    if (!tmp)
    {
        LOGE("Failed to allocate shared capacity %zu", cap);
        return NPE_ERROR_MEMORY;
    }
    reg->shared = tmp;
    reg->shared_cap = cap;
    LOGD("Expanded shared capacity to %zu", cap);
    return NPE_OK;
}

static void free_shared_value(npe_value_t *value)
{
    if (!value)
        return;
    if (value->type == NPE_VAL_STRING)
    {
        free(value->v.s);
        value->v.s = NULL;
    }
    value->type = NPE_VAL_NIL;
}

static npe_error_t copy_value(npe_value_t *dst, const npe_value_t *src)
{
    if (!dst || !src)
        return NPE_ERROR_INVALID_ARG;
    memset(dst, 0, sizeof(*dst));
    dst->type = src->type;

    switch (src->type)
    {
    case NPE_VAL_NIL:
        return NPE_OK;
    case NPE_VAL_BOOL:
        dst->v.b = src->v.b;
        return NPE_OK;
    case NPE_VAL_INT:
        dst->v.i = src->v.i;
        return NPE_OK;
    case NPE_VAL_FLOAT:
        dst->v.f = src->v.f;
        return NPE_OK;
    case NPE_VAL_STRING:
        dst->v.s = reg_strdup(src->v.s ? src->v.s : "");
        if (!dst->v.s){
            LOGE("Failed to copy string value");
            return NPE_ERROR_MEMORY;
        }
        return NPE_OK;
    default:
        return NPE_ERROR_UNSUPPORTED;
    }
}

npe_error_t npe_registry_create(npe_registry_t **out)
{
    if (!out)
        return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    npe_registry_t *reg = (npe_registry_t *)calloc(1, sizeof(*reg));
    if (!reg)
    {
        LOGE("Failed to allocate registry");
        return NPE_ERROR_MEMORY;
    }

    if (pthread_rwlock_init(&reg->lock, NULL) != 0)
    {
        LOGE("Failed to initialize registry lock");
        free(reg);
        return NPE_ERROR_GENERIC;
    }

    LOGI("Registry created");
    *out = reg;
    return NPE_OK;
}

void npe_registry_destroy(npe_registry_t *reg)
{
    if (!reg)
        return;

    pthread_rwlock_wrlock(&reg->lock);

    LOGI("Destroying registry: %zu scripts, %zu FPs, %zu shared", 
         reg->script_count, reg->service_fp_count, reg->shared_count);

    free(reg->scripts);
    reg->scripts = NULL;
    reg->script_count = 0;

    free(reg->service_fps);
    reg->service_fps = NULL;
    reg->service_fp_count = 0;

    for (size_t i = 0; i < reg->shared_count; i++)
    {
        free_shared_value(&reg->shared[i].value);
    }
    free(reg->shared);
    reg->shared = NULL;
    reg->shared_count = 0;

    pthread_rwlock_unlock(&reg->lock);
    pthread_rwlock_destroy(&reg->lock);
    free(reg);
}

void npe_registry_clear(npe_registry_t *reg)
{
    if (!reg)
        return;

    pthread_rwlock_wrlock(&reg->lock);

    LOGI("Clearing registry: %zu scripts, %zu FPs, %zu shared",
         reg->script_count, reg->service_fp_count, reg->shared_count);

    reg->script_count = 0;
    reg->service_fp_count = 0;

    for (size_t i = 0; i < reg->shared_count; i++)
    {
        free_shared_value(&reg->shared[i].value);
    }
    reg->shared_count = 0;

    pthread_rwlock_unlock(&reg->lock);
}

npe_error_t npe_registry_add_script(npe_registry_t *reg, const npe_script_t *script)
{
    if (!reg || !script)
        return NPE_ERROR_INVALID_ARG;

    pthread_rwlock_wrlock(&reg->lock);

    const char *name = script_name(script);
    for (size_t i = 0; i < reg->script_count; i++)
    {
        if (strcmp(script_name(reg->scripts[i]), name) == 0)
        {
            LOGW("Script '%s' already registered", name);
            pthread_rwlock_unlock(&reg->lock);
            return NPE_ERROR_GENERIC;
        }
    }

    npe_error_t err = ensure_script_cap(reg, reg->script_count + 1);
    if (err == NPE_OK)
    {
        reg->scripts[reg->script_count++] = script;
        LOGI("Added script '%s' (total: %zu)", name, reg->script_count);
    }

    pthread_rwlock_unlock(&reg->lock);
    return err;
}

npe_error_t npe_registry_remove_script(npe_registry_t *reg, const char *name)
{
    if (!reg || !name)
        return NPE_ERROR_INVALID_ARG;

    pthread_rwlock_wrlock(&reg->lock);
    for (size_t i = 0; i < reg->script_count; i++)
    {
        if (strcmp(script_name(reg->scripts[i]), name) == 0)
        {
            memmove(&reg->scripts[i], &reg->scripts[i + 1],
                    (reg->script_count - i - 1) * sizeof(reg->scripts[0]));
            reg->script_count--;
            LOGI("Removed script '%s' (remaining: %zu)", name, reg->script_count);
            pthread_rwlock_unlock(&reg->lock);
            return NPE_OK;
        }
    }LOGW("Script '%s' not found for removal", name);
    pthread_rwlock_unlock(&reg->lock);
    return NPE_ERROR_NOT_FOUND;
}

npe_error_t npe_registry_find_script(const npe_registry_t *reg,
                                     const char *name,
                                     const npe_script_t **out)
{
    if (!reg || !name || !out)
        return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    for (size_t i = 0; i < reg->script_count; i++)
    {
        if (strcmp(script_name(reg->scripts[i]), name) == 0)
        {
            *out = reg->scripts[i];
            LOGD("Found script '%s'", name);
            pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
            return NPE_OK;
        }
    }
    LOGD("Script '%s' not found", name);
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return NPE_ERROR_NOT_FOUND;
}

npe_error_t npe_registry_query_scripts(const npe_registry_t *reg,
                                       const npe_script_filter_t *filter,
                                       const npe_script_t ***out,
                                       size_t *count)
{
    if (!reg || !out || !count)
        return NPE_ERROR_INVALID_ARG;
    *out = NULL;
    *count = 0;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);

    const npe_script_t **list = (const npe_script_t **)calloc(reg->script_count + 1, sizeof(*list));
    if (!list)
    {
        LOGE("Failed to allocate query result list");
        pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
        return NPE_ERROR_MEMORY;
    }

    for (size_t i = 0; i < reg->script_count; i++)
    {
        const npe_script_t *s = reg->scripts[i];
        bool ok = true;

        if (filter)
        {
            if (filter->name_pattern &&
                fnmatch(filter->name_pattern, script_name(s), 0) != 0)
            {
                ok = false;
            }

            if (ok && filter->category)
            {
                if (s->meta.categories == 0)
                    ok = false;
            }

            if (ok && (int)filter->phase >= 0 && !script_has_phase_local(s, filter->phase))
            {
                ok = false;
            }

            if (ok && filter->port > 0)
            {
                npe_protocol_t proto = (int)filter->protocol >= 0 ? filter->protocol : NPE_PROTO_UNKNOWN;
                if (!script_matches_port(s, filter->port, proto))
                    ok = false;
            }

            if (ok && filter->safe_only && (s->meta.categories & NPE_CAT_INTRUSIVE))
            {
                ok = false;
            }
        }

        if (ok)
            list[(*count)++] = s;
    }

    LOGD("Query matched %zu scripts", *count);
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);

    *out = list;
    return NPE_OK;
}

void npe_registry_free_query(const npe_script_t **list)
{
    free((void *)list);
}

size_t npe_registry_script_count(const npe_registry_t *reg)
{
    if (!reg)
        return 0;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    size_t n = reg->script_count;
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return n;
}

npe_registry_iter_t *npe_registry_script_iter_begin(const npe_registry_t *reg)
{
    if (!reg)
        return NULL;
    npe_registry_iter_t *iter = (npe_registry_iter_t *)calloc(1, sizeof(*iter));
    if (!iter)
    {
        LOGE("Failed to allocate iterator");
        return NULL;
    }
    iter->reg = reg;
    return iter;
}

const npe_script_t *npe_registry_script_iter_next(npe_registry_iter_t *iter)
{
    if (!iter || !iter->reg)
        return NULL;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&iter->reg->lock);
    if (iter->index >= iter->reg->script_count)
    {
        pthread_rwlock_unlock((pthread_rwlock_t *)&iter->reg->lock);
        return NULL;
    }
    const npe_script_t *out = iter->reg->scripts[iter->index++];
    pthread_rwlock_unlock((pthread_rwlock_t *)&iter->reg->lock);
    return out;
}

void npe_registry_script_iter_end(npe_registry_iter_t *iter)
{
    free(iter);
}

npe_error_t npe_registry_check_dependencies(const npe_registry_t *reg,
                                            char ***missing,
                                            size_t *count)
{
    if (!reg || !missing || !count)
        return NPE_ERROR_INVALID_ARG;
    *missing = NULL;
    *count = 0;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    char **list = (char **)calloc(reg->script_count * NPE_MAX_DEPENDENCIES + 1, sizeof(char *));
    if (!list)
    {
        LOGE("Failed to allocate dependency check list");
        pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
        return NPE_ERROR_MEMORY;
    }

    for (size_t i = 0; i < reg->script_count; i++)
    {
        const npe_script_t *s = reg->scripts[i];
        for (size_t d = 0; d < s->meta.dependency_count; d++)
        {
            const char *dep = s->meta.dependencies[d];
            bool found = false;
            for (size_t j = 0; j < reg->script_count; j++)
            {
                if (strcmp(script_name(reg->scripts[j]), dep) == 0)
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                bool exists = false;
                for (size_t k = 0; k < *count; k++)
                {
                    if (strcmp(list[k], dep) == 0)
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    list[*count] = reg_strdup(dep);
                    if (!list[*count])
                    {
                        LOGE("Failed to copy dependency name");
                        pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
                        for (size_t x = 0; x < *count; x++)
                            free(list[x]);
                        free(list);
                        return NPE_ERROR_MEMORY;
                    }
                    (*count)++;
                }
            }
        }
    }

    if (*count > 0)
        LOGW("Found %zu missing dependencies", *count);

    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);

    *missing = list;
    return (*count == 0) ? NPE_OK : NPE_ERROR_DEPENDENCY;
}

npe_error_t npe_registry_resolve_order(const npe_registry_t *reg,
                                       const npe_script_t ***order,
                                       size_t *count)
{
    if (!reg || !order || !count)
        return NPE_ERROR_INVALID_ARG;
    *order = NULL;
    *count = 0;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    size_t n = reg->script_count;
    const npe_script_t **sorted = (const npe_script_t **)calloc(n + 1, sizeof(*sorted));
    int *indegree = (int *)calloc(n, sizeof(int));
    bool *used = (bool *)calloc(n, sizeof(bool));

    if (!sorted || !indegree || !used)
    {
        LOGE("Failed to allocate dependency resolution structures");
        free(sorted);
        free(indegree);
        free(used);
        pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
        return NPE_ERROR_MEMORY;
    }

    for (size_t i = 0; i < n; i++)
    {
        const npe_script_t *s = reg->scripts[i];
        for (size_t d = 0; d < s->meta.dependency_count; d++)
        {
            for (size_t j = 0; j < n; j++)
            {
                if (strcmp(script_name(reg->scripts[j]), s->meta.dependencies[d]) == 0)
                {
                    indegree[i]++;
                    break;
                }
            }
        }
    }

    for (size_t pass = 0; pass < n; pass++)
    {
        bool found_node = false;
        size_t next_idx = 0;
        for (size_t i = 0; i < n; i++)
        {
            if (!used[i] && indegree[i] == 0)
            {
                found_node = true;
                next_idx = i;
                break;
            }
        }
        if (!found_node)
        {
            LOGE("Circular dependency detected");
            free(sorted);
            free(indegree);
            free(used);
            pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
            return NPE_ERROR_DEPENDENCY;
        }

        used[next_idx] = true;
        sorted[*count] = reg->scripts[next_idx];
        (*count)++;

        const char *resolved = script_name(reg->scripts[next_idx]);
        for (size_t i = 0; i < n; i++)
        {
            if (used[i])
                continue;
            const npe_script_t *s = reg->scripts[i];
            for (size_t d = 0; d < s->meta.dependency_count; d++)
            {
                if (strcmp(s->meta.dependencies[d], resolved) == 0)
                {
                    indegree[i]--;
                }
            }
        }
    }

    LOGI("Resolved execution order for %zu scripts", *count);
    free(indegree);
    free(used);
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);

    *order = sorted;
    return NPE_OK;
}

void npe_registry_free_order(const npe_script_t **order)
{
    free((void *)order);
}

npe_error_t npe_registry_add_service_fp(npe_registry_t *reg,
                                        const npe_service_fp_t *fp)
{
    if (!reg || !fp)
        return NPE_ERROR_INVALID_ARG;
    pthread_rwlock_wrlock(&reg->lock);

    npe_error_t err = ensure_fp_cap(reg, reg->service_fp_count + 1);
    if (err == NPE_OK)
    {
        reg->service_fps[reg->service_fp_count++] = *fp;
        LOGI("Added service FP '%s' (total: %zu)", fp->name, reg->service_fp_count);
    }

    pthread_rwlock_unlock(&reg->lock);
    return err;
}

npe_error_t npe_registry_remove_service_fp(npe_registry_t *reg,
                                           const char *name,
                                           npe_protocol_t proto,
                                           uint16_t port)
{
    if (!reg || !name)
        return NPE_ERROR_INVALID_ARG;
    pthread_rwlock_wrlock(&reg->lock);

    for (size_t i = 0; i < reg->service_fp_count; i++)
    {
        npe_service_fp_t *fp = &reg->service_fps[i];
        if (strcmp(fp->name, name) == 0 && fp->protocol == proto && fp->port == port)
        {
            memmove(&reg->service_fps[i], &reg->service_fps[i + 1],
                    (reg->service_fp_count - i - 1) * sizeof(reg->service_fps[0]));
            reg->service_fp_count--;
            LOGI("Removed service FP '%s' (remaining: %zu)", name, reg->service_fp_count);
            pthread_rwlock_unlock(&reg->lock);
            return NPE_OK;
        }
    }

    LOGW("Service FP '%s' not found for removal", name);
    pthread_rwlock_unlock(&reg->lock);
    return NPE_ERROR_NOT_FOUND;
}

npe_error_t npe_registry_match_service(const npe_registry_t *reg,
                                       npe_protocol_t proto,
                                       uint16_t port,
                                       const uint8_t *response,
                                       size_t resp_len,
                                       const npe_service_fp_t **out)
{
    if (!reg || !response || resp_len == 0 || !out)
        return NPE_ERROR_INVALID_ARG;
    *out = NULL;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    for (size_t i = 0; i < reg->service_fp_count; i++)
    {
        const npe_service_fp_t *fp = &reg->service_fps[i];
        if (fp->protocol != proto)
            continue;
        if (fp->port != 0 && fp->port != port)
            continue;
        if (!fp->match_pattern || fp->match_len == 0)
            continue;

        if (resp_len >= fp->match_len &&
            find_bytes(response, resp_len, fp->match_pattern, fp->match_len) != NULL)
        {
            *out = fp;
            LOGI("Matched service '%s' on port %u", fp->name, port);
            pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
            return NPE_OK;
        }
    }
    LOGD("No service match for port %u", port);
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return NPE_ERROR_NOT_FOUND;
}

size_t npe_registry_service_fp_count(const npe_registry_t *reg)
{
    if (!reg)
        return 0;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    size_t n = reg->service_fp_count;
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return n;
}

npe_error_t npe_registry_load_service_fp_file(npe_registry_t *reg,
                                              const char *path)
{
    (void)reg;
    (void)path;
    return NPE_ERROR_UNSUPPORTED;
}

npe_error_t npe_registry_shared_set(npe_registry_t *reg,
                                    const char *key,
                                    const npe_value_t *value,
                                    const char *writer)
{
    if (!reg || !key || !value)
        return NPE_ERROR_INVALID_ARG;

    pthread_rwlock_wrlock(&reg->lock);

    for (size_t i = 0; i < reg->shared_count; i++)
    {
        if (strcmp(reg->shared[i].key, key) == 0)
        {
            free_shared_value(&reg->shared[i].value);
            npe_error_t err = copy_value(&reg->shared[i].value, value);
            if (err == NPE_OK)
            {
                reg->shared[i].timestamp_us = (uint64_t)time(NULL) * 1000000ULL;
                reg->shared[i].writer_script = writer;
                LOGD("Updated shared key '%s'", key);
            }
            pthread_rwlock_unlock(&reg->lock);
            return err;
        }
    }

    npe_error_t err = ensure_shared_cap(reg, reg->shared_count + 1);
    if (err != NPE_OK)
    {
        pthread_rwlock_unlock(&reg->lock);
        return err;
    }

    npe_shared_entry_t *dst = &reg->shared[reg->shared_count];
    memset(dst, 0, sizeof(*dst));
    snprintf(dst->key, sizeof(dst->key), "%s", key);
    err = copy_value(&dst->value, value);
    if (err == NPE_OK)
    {
        dst->timestamp_us = (uint64_t)time(NULL) * 1000000ULL;
        dst->writer_script = writer;
        reg->shared_count++;
        LOGI("Added shared key '%s' (total: %zu)", key, reg->shared_count);
    }

    pthread_rwlock_unlock(&reg->lock);
    return err;
}

npe_error_t npe_registry_shared_get(const npe_registry_t *reg,
                                    const char *key,
                                    npe_shared_entry_t *out)
{
    if (!reg || !key || !out)
        return NPE_ERROR_INVALID_ARG;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    for (size_t i = 0; i < reg->shared_count; i++)
    {
        if (strcmp(reg->shared[i].key, key) == 0)
        {
            *out = reg->shared[i];LOGD("Retrieved shared key '%s'", key);
            pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
            return NPE_OK;
        }
    }

    LOGD("Shared key '%s' not found", key);
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return NPE_ERROR_NOT_FOUND;
}
npe_error_t npe_registry_shared_remove(npe_registry_t *reg, const char *key)
{
    if (!reg || !key)
        return NPE_ERROR_INVALID_ARG;

    pthread_rwlock_wrlock(&reg->lock);
    for (size_t i = 0; i < reg->shared_count; i++)
    {
        if (strcmp(reg->shared[i].key, key) == 0)
        {
            free_shared_value(&reg->shared[i].value);
            memmove(&reg->shared[i], &reg->shared[i + 1],
                    (reg->shared_count - i - 1) * sizeof(reg->shared[0]));
            reg->shared_count--;
            LOGI("Removed shared key '%s' (remaining: %zu)", key, reg->shared_count);
            pthread_rwlock_unlock(&reg->lock);
            return NPE_OK;
        }
    }
    LOGW("Shared key '%s' not found for removal", key);
    pthread_rwlock_unlock(&reg->lock);
    return NPE_ERROR_NOT_FOUND;
}

void npe_registry_shared_clear(npe_registry_t *reg)
{
    if (!reg)
        return;
    pthread_rwlock_wrlock(&reg->lock);
    LOGI("Clearing %zu shared entries", reg->shared_count);
    for (size_t i = 0; i < reg->shared_count; i++)
    {
        free_shared_value(&reg->shared[i].value);
    }
    reg->shared_count = 0;
    pthread_rwlock_unlock(&reg->lock);
}

size_t npe_registry_shared_count(const npe_registry_t *reg)
{
    if (!reg)
        return 0;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    size_t n = reg->shared_count;
    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return n;
}

const npe_shared_entry_t *npe_registry_shared_next(const npe_registry_t *reg,
                                                   const npe_shared_entry_t *iter)
{
    if (!reg)
        return NULL;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);

    if (reg->shared_count == 0)
    {
        pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
        return NULL;
    }

    if (!iter)
    {
        const npe_shared_entry_t *out = &reg->shared[0];
        pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
        return out;
    }

    for (size_t i = 0; i + 1 < reg->shared_count; i++)
    {
        if (&reg->shared[i] == iter)
        {
            const npe_shared_entry_t *out = &reg->shared[i + 1];
            pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
            return out;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return NULL;
}

npe_error_t npe_registry_get_stats(const npe_registry_t *reg,
                                   npe_registry_stats_t *out)
{
    if (!reg || !out)
        return NPE_ERROR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);
    out->total_scripts = reg->script_count;
    out->total_service_fps = reg->service_fp_count;
    out->shared_entries = reg->shared_count;

    for (size_t i = 0; i < reg->script_count; i++)
    {
        if (reg->scripts[i]->meta.has_prerule)
            out->scripts_by_phase[NPE_PHASE_PRERULE]++;
        if (reg->scripts[i]->meta.has_hostrule)
            out->scripts_by_phase[NPE_PHASE_HOSTRULE]++;
        if (reg->scripts[i]->meta.has_portrule)
            out->scripts_by_phase[NPE_PHASE_PORTRULE]++;
        if (reg->scripts[i]->meta.has_postrule)
            out->scripts_by_phase[NPE_PHASE_POSTRULE]++;
    }

    out->categories_count = 0;
    uint32_t all_categories = 0;
    for (size_t i = 0; i < reg->script_count; i++)
    {
        all_categories |= reg->scripts[i]->meta.categories;
    }
    for (size_t bit = 0; bit < 32; bit++)
    {
        if ((all_categories & (1u << bit)) != 0)
            out->categories_count++;
    }

    LOGD("Stats: %zu scripts, %zu FPs, %zu shared, %zu categories",
         out->total_scripts, out->total_service_fps, out->shared_entries, out->categories_count);

    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);
    return NPE_OK;
}

npe_error_t npe_registry_save_cache(const npe_registry_t *reg, const char *path)
{
    if (!reg || !path || !path[0])
        return NPE_ERROR_INVALID_ARG;

    FILE *fp = fopen(path, "wb");
    if (!fp)
        return NPE_ERROR_IO;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&reg->lock);

    fprintf(fp, "%s\n", NPE_REGISTRY_CACHE_MAGIC);
    fprintf(fp, "shared %zu\n", reg->shared_count);

    for (size_t i = 0; i < reg->shared_count; i++)
    {
        const npe_shared_entry_t *e = &reg->shared[i];
        const char *writer = e->writer_script ? e->writer_script : "";

        fputs("S\t", fp);
        reg_write_escaped(fp, e->key);
        fputc('\t', fp);

        switch (e->value.type)
        {
        case NPE_VAL_NIL:
            fprintf(fp, "N\t%llu\t", (unsigned long long)e->timestamp_us);
            reg_write_escaped(fp, writer);
            fputc('\t', fp);
            fputc('\n', fp);
            break;
        case NPE_VAL_BOOL:
            fprintf(fp, "B\t%llu\t", (unsigned long long)e->timestamp_us);
            reg_write_escaped(fp, writer);
            fprintf(fp, "\t%d\n", e->value.v.b ? 1 : 0);
            break;
        case NPE_VAL_INT:
            fprintf(fp, "I\t%llu\t", (unsigned long long)e->timestamp_us);
            reg_write_escaped(fp, writer);
            fprintf(fp, "\t%lld\n", (long long)e->value.v.i);
            break;
        case NPE_VAL_FLOAT:
            fprintf(fp, "F\t%llu\t", (unsigned long long)e->timestamp_us);
            reg_write_escaped(fp, writer);
            fprintf(fp, "\t%.17g\n", e->value.v.f);
            break;
        case NPE_VAL_STRING:
            fprintf(fp, "S\t%llu\t", (unsigned long long)e->timestamp_us);
            reg_write_escaped(fp, writer);
            fputc('\t', fp);
            reg_write_escaped(fp, e->value.v.s ? e->value.v.s : "");
            fputc('\n', fp);
            break;
        default:
            /* Skip unsupported value types when serializing cache. */
            fputc('\n', fp);
            break;
        }
    }

    pthread_rwlock_unlock((pthread_rwlock_t *)&reg->lock);

    if (fclose(fp) != 0)
        return NPE_ERROR_IO;

    return NPE_OK;
}

npe_error_t npe_registry_load_cache(npe_registry_t *reg, const char *path)
{
    if (!reg || !path || !path[0])
        return NPE_ERROR_INVALID_ARG;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NPE_ERROR_IO;

    char line[8192];
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return NPE_ERROR_PARSE;
    }

    size_t line_len = strlen(line);
    if (line_len > 0 && line[line_len - 1] == '\n')
        line[line_len - 1] = '\0';

    if (strcmp(line, NPE_REGISTRY_CACHE_MAGIC) != 0)
    {
        fclose(fp);
        return NPE_ERROR_PARSE;
    }

    pthread_rwlock_wrlock(&reg->lock);
    for (size_t i = 0; i < reg->shared_count; i++)
        free_shared_value(&reg->shared[i].value);
    reg->shared_count = 0;

    while (fgets(line, sizeof(line), fp))
    {
        line_len = strlen(line);
        if (line_len > 0 && line[line_len - 1] == '\n')
            line[line_len - 1] = '\0';

        if (strncmp(line, "shared ", 7) == 0)
            continue;

        if (line[0] != 'S' || line[1] != '\t')
            continue;

        char *save = NULL;
        strtok_r(line, "\t", &save);
        char *key = strtok_r(NULL, "\t", &save);
        char *type = strtok_r(NULL, "\t", &save);
        char *ts = strtok_r(NULL, "\t", &save);
        char *writer = strtok_r(NULL, "\t", &save);
        char *value = strtok_r(NULL, "", &save);

        if (!key || !type || !ts)
            continue;

        reg_unescape_inplace(key);
        reg_unescape_inplace(writer);
        reg_unescape_inplace(value);

        npe_error_t err = ensure_shared_cap(reg, reg->shared_count + 1);
        if (err != NPE_OK)
        {
            pthread_rwlock_unlock(&reg->lock);
            fclose(fp);
            return err;
        }

        npe_shared_entry_t *entry = &reg->shared[reg->shared_count];
        memset(entry, 0, sizeof(*entry));
        snprintf(entry->key, sizeof(entry->key), "%s", key);
        entry->timestamp_us = (uint64_t)strtoull(ts, NULL, 10);
        (void)writer;
        entry->writer_script = NULL;

        if (strcmp(type, "N") == 0)
        {
            entry->value.type = NPE_VAL_NIL;
        }
        else if (strcmp(type, "B") == 0)
        {
            entry->value.type = NPE_VAL_BOOL;
            entry->value.v.b = value && atoi(value) != 0;
        }
        else if (strcmp(type, "I") == 0)
        {
            entry->value.type = NPE_VAL_INT;
            entry->value.v.i = value ? strtoll(value, NULL, 10) : 0;
        }
        else if (strcmp(type, "F") == 0)
        {
            entry->value.type = NPE_VAL_FLOAT;
            entry->value.v.f = value ? strtod(value, NULL) : 0.0;
        }
        else if (strcmp(type, "S") == 0)
        {
            entry->value.type = NPE_VAL_STRING;
            entry->value.v.s = reg_strdup(value ? value : "");
            if (!entry->value.v.s)
            {
                pthread_rwlock_unlock(&reg->lock);
                fclose(fp);
                return NPE_ERROR_MEMORY;
            }
        }
        else
        {
            continue;
        }

        reg->shared_count++;
    }

    pthread_rwlock_unlock(&reg->lock);
    fclose(fp);
    return NPE_OK;
}
