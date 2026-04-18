/*****************************************************************************
 * npe_lib_regex.c — PCRE2-based regular expression library for NPE
 *
 * Implements the C API and Lua bindings declared in npe_lib_regex.h.
 * Uses PCRE2 (8-bit) as the backend engine.
 *****************************************************************************/

#define PCRE2_CODE_UNIT_WIDTH 8

#include "npe_lib_regex.h"
#include "npe_types.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#include <pcre2.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "npe_vm.h"

// Error code compatibility shims
#define NPE_ERROR_INVALID_ARG     NPE_ERROR_INVALID_ARG
#define NPE_ERROR_NOT_FOUND       NPE_ERROR_NOT_FOUND
#define NPE_ERR_NOT_SUPPORTED   NPE_ERROR_UNSUPPORTED
#define NPE_ERR_REGEXNPE_ERROR_GENERIC
#define NPE_ERR_REGEX_COMPILE   NPE_ERROR_PARSE
#define NPE_ERROR_MEMORY           NPE_ERROR_MEMORY
#define NPE_ERR_REGEX           NPE_ERROR_GENERIC



/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL STRUCTURES
 * ═══════════════════════════════════════════════════════════════════════════ */

struct npe_regex {
    pcre2_code           *code;
    char                 *pattern_str;
    npe_regex_flag_t      flags;
    size_t                capture_count;
    bool                  jit_compiled;

    /* compile error info (valid only on compile failure) */
    int                   compile_error;
    PCRE2_SIZE            compile_error_offset;
};

/* ── Global state ────────────────────────────────────────────────────────── */

static bool              g_jit_enabled  = true;
static npe_regex_stats_t g_stats        = {0};
static pthread_mutex_t   g_stats_mutex  = PTHREAD_MUTEX_INITIALIZER;

/* ── Pattern cache ───────────────────────────────────────────────────────── */

typedef struct cache_entry {
    char                *pattern;
    npe_regex_flag_t     flags;
    npe_regex_t         *regex;
    struct cache_entry  *prev;
    struct cache_entry  *next;
} cache_entry_t;

static struct {
    bool            enabled;
    size_t          capacity;
    size_t          size;
    size_t          hits;
    size_t          misses;
    size_t          evictions;
    cache_entry_t  *head;   /* MRU */
    cache_entry_t  *tail;   /* LRU */
    pthread_mutex_t mutex;
} g_cache = {
    .enabled  = false,
    .capacity = 0,
    .size     = 0,
    .hits     = 0,
    .misses   = 0,
    .evictions= 0,
    .head     = NULL,
    .tail     = NULL,
    .mutex    = PTHREAD_MUTEX_INITIALIZER,
};

/* ── Lua metatable name ──────────────────────────────────────────────────── */

#define NPE_REGEX_META "npe.regex"

/* ── Timing helper ───────────────────────────────────────────────────────── */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FLAG CONVERSION
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint32_t to_pcre2_compile_flags(npe_regex_flag_t f) {
    uint32_t out = 0;
    if (f & NPE_REGEX_CASELESS)         out |= PCRE2_CASELESS;
    if (f & NPE_REGEX_MULTILINE)        out |= PCRE2_MULTILINE;
    if (f & NPE_REGEX_DOTALL)           out |= PCRE2_DOTALL;
    if (f & NPE_REGEX_EXTENDED)         out |= PCRE2_EXTENDED;
    if (f & NPE_REGEX_ANCHORED)         out |= PCRE2_ANCHORED;
    if (f & NPE_REGEX_UNGREEDY)         out |= PCRE2_UNGREEDY;
    if (f & NPE_REGEX_UTF)              out |= PCRE2_UTF;
    if (f & NPE_REGEX_NO_AUTO_CAPTURE)  out |= PCRE2_NO_AUTO_CAPTURE;
    return out;
}

static uint32_t to_pcre2_match_flags(npe_regex_match_flag_t f) {
    uint32_t out = 0;
    if (f & NPE_REGEX_MATCH_NOTBOL)   out |= PCRE2_NOTBOL;
    if (f & NPE_REGEX_MATCH_NOTEOL)   out |= PCRE2_NOTEOL;
    if (f & NPE_REGEX_MATCH_NOTEMPTY) out |= PCRE2_NOTEMPTY;
    if (f & NPE_REGEX_MATCH_PARTIAL)  out |= PCRE2_PARTIAL_SOFT;
    return out;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CACHE HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

static void cache_detach(cache_entry_t *e) {
    if (e->prev) e->prev->next = e->next;
    else         g_cache.head   = e->next;
    if (e->next) e->next->prev = e->prev;
    else         g_cache.tail   = e->prev;
    e->prev = e->next = NULL;
}

static void cache_push_front(cache_entry_t *e) {
    e->prev = NULL;
    e->next = g_cache.head;
    if (g_cache.head) g_cache.head->prev = e;
    g_cache.head = e;
    if (!g_cache.tail) g_cache.tail = e;
}

static void cache_entry_free(cache_entry_t *e) {
    if (!e) return;
    free(e->pattern);
    /* NOTE: we do NOT call npe_regex_destroy here because cached regex
       objects may still be referenced. The cache owns the npe_regex_t. */
    if (e->regex) {
        if (e->regex->code)        pcre2_code_free(e->regex->code);
        if (e->regex->pattern_str) free(e->regex->pattern_str);
        free(e->regex);
    }
    free(e);
}

static npe_regex_t *cache_lookup(const char *pattern, npe_regex_flag_t flags) {
    if (!g_cache.enabled) return NULL;

    pthread_mutex_lock(&g_cache.mutex);
    for (cache_entry_t *e = g_cache.head; e; e = e->next) {
        if (e->flags == flags && strcmp(e->pattern, pattern) == 0) {
            /* move to front (MRU) */
            cache_detach(e);
            cache_push_front(e);
            g_cache.hits++;
            pthread_mutex_unlock(&g_cache.mutex);

            pthread_mutex_lock(&g_stats_mutex);
            g_stats.cache_hits++;
            pthread_mutex_unlock(&g_stats_mutex);

            return e->regex;
        }
    }
    g_cache.misses++;
    pthread_mutex_unlock(&g_cache.mutex);

    pthread_mutex_lock(&g_stats_mutex);
    g_stats.cache_misses++;
    pthread_mutex_unlock(&g_stats_mutex);

    return NULL;
}

static void cache_insert(const char *pattern, npe_regex_flag_t flags,
                          npe_regex_t *re) {
    if (!g_cache.enabled) return;

    pthread_mutex_lock(&g_cache.mutex);

    /* evict LRU if at capacity */
    while (g_cache.size >= g_cache.capacity && g_cache.tail) {
        cache_entry_t *victim = g_cache.tail;
        cache_detach(victim);
        cache_entry_free(victim);
        g_cache.size--;
        g_cache.evictions++;
    }

    cache_entry_t *e = calloc(1, sizeof(*e));
    if (!e) {
        pthread_mutex_unlock(&g_cache.mutex);
        return;
    }
    e->pattern = strdup(pattern);
    e->flags   = flags;
    e->regex   = re;
    cache_push_front(e);
    g_cache.size++;

    pthread_mutex_unlock(&g_cache.mutex);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  COMPILATION
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_regex_compile(const char              *pattern,
                              npe_regex_flag_t         flags,
                              const npe_regex_limits_t *limits,
                              npe_regex_t            **out) {
    if (!pattern || !out) return NPE_ERROR_INVALID_ARG;
    return npe_regex_compile_n(pattern, strlen(pattern), flags, limits, out);
}

npe_error_t npe_regex_compile_n(const char              *pattern,
                                size_t                   pattern_len,
                                npe_regex_flag_t         flags,
                                const npe_regex_limits_t *limits,
                                npe_regex_t            **out) {
    if (!pattern || !out) return NPE_ERROR_INVALID_ARG;

    /* check cache (NUL-terminated copy for lookup) */
    char *pat_z = malloc(pattern_len + 1);
    if (!pat_z) return NPE_ERROR_MEMORY;
    memcpy(pat_z, pattern, pattern_len);
    pat_z[pattern_len] = '\0';

    npe_regex_t *cached = cache_lookup(pat_z, flags);
    if (cached) {
        free(pat_z);
        *out = cached;
        return NPE_OK;
    }

    npe_regex_t *re = calloc(1, sizeof(*re));
    if (!re) {
        free(pat_z);
        return NPE_ERROR_MEMORY;
    }

    re->pattern_str = pat_z;
    re->flags       = flags;

    int errcode;
    PCRE2_SIZE erroffset;
    uint32_t pcre2_flags = to_pcre2_compile_flags(flags);

    pcre2_compile_context *cctx = NULL;
    if (limits) {
        cctx = pcre2_compile_context_create(NULL);
        /* compile context doesn't directly take match/depth limits,
           those are set on match context. We store them for later. */
    }

    re->code = pcre2_compile((PCRE2_SPTR)pattern,
                             (PCRE2_SIZE)pattern_len,
                             pcre2_flags,
                             &errcode,
                             &erroffset,
                             cctx);

    if (cctx) pcre2_compile_context_free(cctx);

    if (!re->code) {
        re->compile_error        = errcode;
        re->compile_error_offset = erroffset;
        /* keep re alive so caller can query error */
        *out = re;
        return NPE_ERR_REGEX_COMPILE;
    }

    /* capture count */
    uint32_t cap = 0;
    pcre2_pattern_info(re->code, PCRE2_INFO_CAPTURECOUNT, &cap);
    re->capture_count = (size_t)cap;

    /* JIT compile if enabled */
    if (g_jit_enabled) {
        int jrc = pcre2_jit_compile(re->code, PCRE2_JIT_COMPLETE);
        re->jit_compiled = (jrc == 0);
    }

    pthread_mutex_lock(&g_stats_mutex);
    g_stats.total_compiles++;
    pthread_mutex_unlock(&g_stats_mutex);

    /* insert into cache (cache takes ownership if enabled) */
    cache_insert(re->pattern_str, flags, re);

    *out = re;
    return NPE_OK;
}

void npe_regex_destroy(npe_regex_t *re) {
    if (!re) return;

    /* If the cache is enabled, the cache owns this object.
       We only free if the cache is disabled or the entry isn't cached.
       For simplicity, if cache is disabled we always free. */
    if (g_cache.enabled) {
        /* Check if it's in the cache; if so, remove it first */
        pthread_mutex_lock(&g_cache.mutex);
        for (cache_entry_t *e = g_cache.head; e; e = e->next) {
            if (e->regex == re) {
                cache_detach(e);
                g_cache.size--;
                /* set regex to NULL so cache_entry_free doesn't double-free */
                e->regex = NULL;
                cache_entry_free(e);
                break;
            }
        }
        pthread_mutex_unlock(&g_cache.mutex);
    }

    if (re->code)        pcre2_code_free(re->code);
    if (re->pattern_str) free(re->pattern_str);
    free(re);
}

const char *npe_regex_pattern(const npe_regex_t *re) {
    return re ? re->pattern_str : NULL;
}

size_t npe_regex_capture_count(const npe_regex_t *re) {
    return re ? re->capture_count : 0;
}

int npe_regex_name_to_index(const npe_regex_t *re, const char *name) {
    if (!re || !re->code || !name) return -1;
    int idx = pcre2_substring_number_from_name(re->code, (PCRE2_SPTR)name);
    return (idx >= 0) ? idx : -1;
}

npe_error_t npe_regex_get_compile_error(const npe_regex_t *re,
                                        char              *buf,
                                        size_t             buf_size,
                                        size_t            *error_offset) {
    if (!re) return NPE_ERROR_INVALID_ARG;
    if (re->code) return NPE_ERROR_INVALID_ARG; /* no error */

    if (buf && buf_size > 0) {
        pcre2_get_error_message(re->compile_error, (PCRE2_UCHAR *)buf,
                                buf_size);
    }
    if (error_offset) *error_offset = (size_t)re->compile_error_offset;
    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL: build match result from pcre2 match data
 * ═══════════════════════════════════════════════════════════════════════════ */

static npe_error_t build_match_result(const npe_regex_t *re,
                                      pcre2_match_data  *md,
                                      const char        *subject,
                                      int                rc,
                                      npe_regex_match_t *match) {
    memset(match, 0, sizeof(*match));

    if (rc < 0) {
        match->matched = false;
        return (rc == PCRE2_ERROR_NOMATCH) ? NPE_ERROR_NOT_FOUND : NPE_ERR_REGEX;
    }

    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(md);
    uint32_t count = (uint32_t)rc;
    if (count == 0) {
        /* ovector too small, use capture_count + 1 */
        count = (uint32_t)(re->capture_count + 1);
    }

    match->matched       = true;
    match->offset        = (size_t)ovector[0];
    match->length        = (size_t)(ovector[1] - ovector[0]);
    match->capture_count = (size_t)count;

    match->captures = calloc(count, sizeof(npe_regex_capture_t));
    if (!match->captures) return NPE_ERROR_MEMORY;

    /* name table for named groups */
    PCRE2_SPTR name_table = NULL;
    uint32_t name_count   = 0;
    uint32_t name_entry_size = 0;
    pcre2_pattern_info(re->code, PCRE2_INFO_NAMECOUNT, &name_count);
    pcre2_pattern_info(re->code, PCRE2_INFO_NAMETABLE, &name_table);
    pcre2_pattern_info(re->code, PCRE2_INFO_NAMEENTRYSIZE, &name_entry_size);

    for (uint32_t i = 0; i < count; i++) {
        npe_regex_capture_t *cap = &match->captures[i];
        cap->group = (int)i;

        if (ovector[2 * i] == PCRE2_UNSET) {
            cap->matched = false;
            cap->start   = NULL;
            cap->length  = 0;
        } else {
            cap->matched = true;
            cap->start   = subject + ovector[2 * i];
            cap->length  = (size_t)(ovector[2 * i + 1] - ovector[2 * i]);
        }

        cap->name[0] = '\0';

        /* look up name */
        if (name_table && i > 0) {
            PCRE2_SPTR entry = name_table;
            for (uint32_t n = 0; n < name_count; n++) {
                uint16_t num = (uint16_t)((entry[0] << 8) | entry[1]);
                if (num == i) {
                    const char *nm = (const char *)(entry + 2);
                    snprintf(cap->name, sizeof(cap->name), "%s", nm);
                    break;
                }
                entry += name_entry_size;
            }
        }
    }

    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MATCHING
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_regex_exec(const npe_regex_t     *re,
                           const char            *subject,
                           size_t                 length,
                           size_t                 offset,
                           npe_regex_match_flag_t flags,
                           npe_regex_match_t     *match) {
    if (!re || !re->code || !subject || !match)
        return NPE_ERROR_INVALID_ARG;

    if (length == 0) length = strlen(subject);

    pcre2_match_context *mctx = pcre2_match_context_create(NULL);
    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re->code, NULL);
    if (!md) {
        if (mctx) pcre2_match_context_free(mctx);
        return NPE_ERROR_MEMORY;
    }

    uint32_t mflags = to_pcre2_match_flags(flags);

    uint64_t t0 = now_ns();

    int rc;
    if (re->jit_compiled) {
        rc = pcre2_jit_match(re->code,
                             (PCRE2_SPTR)subject,
                             (PCRE2_SIZE)length,
                             (PCRE2_SIZE)offset,
                             mflags,
                             md,
                             mctx);
    } else {
        rc = pcre2_match(re->code,
                         (PCRE2_SPTR)subject,
                         (PCRE2_SIZE)length,
                         (PCRE2_SIZE)offset,
                         mflags,
                         md,
                         mctx);
    }

    uint64_t elapsed = now_ns() - t0;

    pthread_mutex_lock(&g_stats_mutex);
    g_stats.total_matches++;
    g_stats.total_match_time_ns += elapsed;
    pthread_mutex_unlock(&g_stats_mutex);

    npe_error_t err = build_match_result(re, md, subject, rc, match);

    pcre2_match_data_free(md);
    if (mctx) pcre2_match_context_free(mctx);

    return err;
}

void npe_regex_match_free(npe_regex_match_t *match) {
    if (!match) return;
    free(match->captures);
    match->captures      = NULL;
    match->capture_count = 0;
    match->matched       = false;
}

bool npe_regex_test(const npe_regex_t *re,
                    const char        *subject,
                    size_t             length) {
    npe_regex_match_t m = {0};
    npe_error_t err = npe_regex_exec(re, subject, length, 0,
                                     NPE_REGEX_MATCH_NONE, &m);
    bool result = (err == NPE_OK && m.matched);
    npe_regex_match_free(&m);
    return result;
}

npe_error_t npe_regex_find(const npe_regex_t *re,
                           const char        *subject,
                           size_t             length,
                           size_t             offset,
                           size_t            *start_out,
                           size_t            *end_out) {
    npe_regex_match_t m = {0};
    npe_error_t err = npe_regex_exec(re, subject, length, offset,
                                     NPE_REGEX_MATCH_NONE, &m);
    if (err == NPE_OK && m.matched) {
        if (start_out) *start_out = m.offset;
        if (end_out)   *end_out   = m.offset + m.length;
    }
    npe_regex_match_free(&m);
    return err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  GLOBAL MATCHING
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_regex_find_all(const npe_regex_t  *re,
                               const char         *subject,
                               size_t              length,
                               size_t              max,
                               npe_regex_match_t **matches,
                               size_t             *count) {
    if (!re || !subject || !matches || !count)
        return NPE_ERROR_INVALID_ARG;

    if (length == 0) length = strlen(subject);

    size_t cap      = 16;
    size_t n        = 0;
    size_t offset   = 0;
    npe_regex_match_t *arr = calloc(cap, sizeof(*arr));
    if (!arr) return NPE_ERROR_MEMORY;

    while (offset <= length) {
        if (max > 0 && n >= max) break;

        npe_regex_match_t m = {0};
        npe_error_t err = npe_regex_exec(re, subject, length, offset,
                                         NPE_REGEX_MATCH_NONE, &m);
        if (err != NPE_OK || !m.matched) {
            npe_regex_match_free(&m);
            break;
        }

        /* grow array if needed */
        if (n >= cap) {
            cap *= 2;
            npe_regex_match_t *tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) {
                npe_regex_match_free(&m);
                npe_regex_match_array_free(arr, n);
                return NPE_ERROR_MEMORY;
            }
            arr = tmp;
        }

        arr[n++] = m;

        /* advance past match; handle zero-length matches */
        size_t new_offset = m.offset + m.length;
        if (new_offset == offset) {
            new_offset++;
        }
        offset = new_offset;
    }

    *matches = arr;
    *count   = n;
    return NPE_OK;
}

void npe_regex_match_array_free(npe_regex_match_t *matches, size_t count) {
    if (!matches) return;
    for (size_t i = 0; i < count; i++) {
        npe_regex_match_free(&matches[i]);
    }
    free(matches);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SPLIT
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_regex_split(const npe_regex_t  *re,
                            const char         *subject,
                            size_t              length,
                            size_t              max,
                            char             ***parts,
                            size_t             *count) {
    if (!re || !subject || !parts || !count)
        return NPE_ERROR_INVALID_ARG;

    if (length == 0) length = strlen(subject);

    size_t cap  = 16;
    size_t n    = 0;
    char **arr  = calloc(cap, sizeof(char *));
    if (!arr) return NPE_ERROR_MEMORY;

    size_t offset = 0;

    while (offset <= length) {
        /* if max is set and we've reached max-1 parts, take the rest */
        if (max > 0 && n >= max - 1) break;

        npe_regex_match_t m = {0};
        npe_error_t err = npe_regex_exec(re, subject, length, offset,
                                         NPE_REGEX_MATCH_NONE, &m);
        if (err != NPE_OK || !m.matched) {
            npe_regex_match_free(&m);
            break;
        }

        /* part before the match */
        size_t part_len = m.offset - offset;
        if (n >= cap) {
            cap *= 2;
            char **tmp = realloc(arr, cap * sizeof(char *));
            if (!tmp) {
                npe_regex_match_free(&m);
                npe_regex_split_free(arr, n);
                return NPE_ERROR_MEMORY;
            }
            arr = tmp;
        }

        arr[n] = malloc(part_len + 1);
        if (!arr[n]) {
            npe_regex_match_free(&m);
            npe_regex_split_free(arr, n);
            return NPE_ERROR_MEMORY;
        }
        memcpy(arr[n], subject + offset, part_len);
        arr[n][part_len] = '\0';
        n++;

        size_t new_offset = m.offset + m.length;
        if (new_offset == offset) new_offset++;
        offset = new_offset;

        npe_regex_match_free(&m);
    }

    /* remaining part */
    if (offset <= length) {
        if (n >= cap) {
            cap++;
            char **tmp = realloc(arr, cap * sizeof(char *));
            if (!tmp) {
                npe_regex_split_free(arr, n);
                return NPE_ERROR_MEMORY;
            }
            arr = tmp;
        }
        size_t rem = length - offset;
        arr[n] = malloc(rem + 1);
        if (!arr[n]) {
            npe_regex_split_free(arr, n);
            return NPE_ERROR_MEMORY;
        }
        memcpy(arr[n], subject + offset, rem);
        arr[n][rem] = '\0';
        n++;
    }

    /* NULL-terminate the array */
    if (n >= cap) {
        char **tmp = realloc(arr, (n + 1) * sizeof(char *));
        if (!tmp) {
            npe_regex_split_free(arr, n);
            return NPE_ERROR_MEMORY;
        }
        arr = tmp;
    }
    arr[n] = NULL;

    *parts = arr;
    *count = n;
    return NPE_OK;
}

void npe_regex_split_free(char **parts, size_t count) {
    if (!parts) return;
    for (size_t i = 0; i < count; i++) {
        free(parts[i]);
    }
    free(parts);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  REPLACE — backreference expansion
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Expand backreferences in replacement string:
 *   $0 or $& — full match
 *   $1..$9   — numbered group
 *   ${name}  — named group
 *   $$       — literal $
 */
static npe_error_t expand_replacement(const char              *repl,
                                      const npe_regex_t       *re,
                                      const npe_regex_match_t *match,
                                      char                   **out,
                                      size_t                  *out_len) {
    size_t rlen = strlen(repl);
    size_t cap  = rlen * 2 + 64;
    size_t pos  = 0;
    char  *buf  = malloc(cap);
    if (!buf) return NPE_ERROR_MEMORY;

#define ENSURE(need) do {                       \
    while (pos + (need) >= cap) {               \
        cap *= 2;                               \
        char *tmp = realloc(buf, cap);          \
        if (!tmp) { free(buf); return NPE_ERROR_MEMORY; } \
        buf = tmp;                              \
    }                                           \
} while(0)

    for (size_t i = 0; i < rlen; i++) {
        if (repl[i] == '$' && i + 1 < rlen) {
            if (repl[i + 1] == '$') {
                /* literal $ */
                ENSURE(1);
                buf[pos++] = '$';
                i++;
            } else if (repl[i + 1] == '&') {
                /* full match ($0) */
                if (match->capture_count > 0 && match->captures[0].matched) {
                    ENSURE(match->captures[0].length);
                    memcpy(buf + pos, match->captures[0].start,
                           match->captures[0].length);
                    pos += match->captures[0].length;
                }
                i++;
            } else if (repl[i + 1] >= '0' && repl[i + 1] <= '9') {
                /* numbered group $0..$9 */
                int grp = repl[i + 1] - '0';
                if ((size_t)grp < match->capture_count &&
                    match->captures[grp].matched) {
                    ENSURE(match->captures[grp].length);
                    memcpy(buf + pos, match->captures[grp].start,
                           match->captures[grp].length);
                    pos += match->captures[grp].length;
                }
                i++;
            } else if (repl[i + 1] == '{') {
                /* named group ${name} */
                size_t start = i + 2;
                size_t end   = start;
                while (end < rlen && repl[end] != '}') end++;
                if (end < rlen) {
                    char name[64];
                    size_t nlen = end - start;
                    if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
                    memcpy(name, repl + start, nlen);
                    name[nlen] = '\0';

                    int idx = npe_regex_name_to_index(re, name);
                    if (idx >= 0 && (size_t)idx < match->capture_count &&
                        match->captures[idx].matched) {
                        ENSURE(match->captures[idx].length);
                        memcpy(buf + pos, match->captures[idx].start,
                               match->captures[idx].length);
                        pos += match->captures[idx].length;
                    }
                    i = end; /* skip past '}' */
                } else {
                    /* malformed, copy literally */
                    ENSURE(1);
                    buf[pos++] = repl[i];
                }
            } else {
                /* unknown $ sequence, copy literally */
                ENSURE(1);
                buf[pos++] = repl[i];
            }
        } else {
            ENSURE(1);
            buf[pos++] = repl[i];
        }
    }

#undef ENSURE

    buf[pos] = '\0';
    *out     = buf;
    *out_len = pos;
    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  REPLACE
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_regex_replace(const npe_regex_t  *re,
                              const char         *subject,
                              size_t              length,
                              const char         *replacement,
                              size_t              max,
                              char              **result,
                              size_t             *result_len,
                              size_t             *replace_count) {
    if (!re || !subject || !replacement || !result)
        return NPE_ERROR_INVALID_ARG;

    if (length == 0) length = strlen(subject);

    size_t cap  = length * 2 + 64;
    size_t pos  = 0;
    char  *buf  = malloc(cap);
    if (!buf) return NPE_ERROR_MEMORY;

    size_t offset = 0;
    size_t rcount = 0;

#define OUT_ENSURE(need) do {                       \
    while (pos + (need) >= cap) {                   \
        cap *= 2;                                   \
        char *tmp = realloc(buf, cap);              \
        if (!tmp) { free(buf); return NPE_ERROR_MEMORY; } \
        buf = tmp;                                  \
    }                                               \
} while(0)

    while (offset <= length) {
        if (max > 0 && rcount >= max) break;

        npe_regex_match_t m = {0};
        npe_error_t err = npe_regex_exec(re, subject, length, offset,
                                         NPE_REGEX_MATCH_NONE, &m);
        if (err != NPE_OK || !m.matched) {
            npe_regex_match_free(&m);
            break;
        }

        /* copy text before match */
        size_t pre = m.offset - offset;
        if (pre > 0) {
            OUT_ENSURE(pre);
            memcpy(buf + pos, subject + offset, pre);
            pos += pre;
        }

        /* expand replacement */
        char  *expanded     = NULL;
        size_t expanded_len = 0;
        err = expand_replacement(replacement, re, &m, &expanded, &expanded_len);
        if (err != NPE_OK) {
            npe_regex_match_free(&m);
            free(buf);
            return err;
        }

        OUT_ENSURE(expanded_len);
        memcpy(buf + pos, expanded, expanded_len);
        pos += expanded_len;
        free(expanded);

        rcount++;

        size_t new_offset = m.offset + m.length;
        if (new_offset == offset) new_offset++;
        offset = new_offset;

        npe_regex_match_free(&m);
    }

#undef OUT_ENSURE

    /* copy remaining subject */
    if (offset < length) {
        size_t rem = length - offset;
        while (pos + rem >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return NPE_ERROR_MEMORY; }
            buf = tmp;
        }
        memcpy(buf + pos, subject + offset, rem);
        pos += rem;
    }

    buf[pos] = '\0';

    *result = buf;
    if (result_len)    *result_len    = pos;
    if (replace_count) *replace_count = rcount;

    pthread_mutex_lock(&g_stats_mutex);
    g_stats.total_replacements += rcount;
    pthread_mutex_unlock(&g_stats_mutex);

    return NPE_OK;
}

npe_error_t npe_regex_replace_func(const npe_regex_t    *re,
                                   const char           *subject,
                                   size_t                length,
                                   npe_regex_replace_fn  callback,
                                   void                 *userdata,
                                   size_t                max,
                                   char                **result,
                                   size_t               *result_len,
                                   size_t               *replace_count) {
    if (!re || !subject || !callback || !result)
        return NPE_ERROR_INVALID_ARG;

    if (length == 0) length = strlen(subject);

    size_t cap  = length * 2 + 64;
    size_t pos  = 0;
    char  *buf  = malloc(cap);
    if (!buf) return NPE_ERROR_MEMORY;

    /* temporary buffer for callback output */
    size_t cb_cap = 4096;
    char  *cb_buf = malloc(cb_cap);
    if (!cb_buf) { free(buf); return NPE_ERROR_MEMORY; }

    size_t offset = 0;
    size_t rcount = 0;

    while (offset <= length) {
        if (max > 0 && rcount >= max) break;

        npe_regex_match_t m = {0};
        npe_error_t err = npe_regex_exec(re, subject, length, offset,
                                         NPE_REGEX_MATCH_NONE, &m);
        if (err != NPE_OK || !m.matched) {
            npe_regex_match_free(&m);
            break;
        }

        /* copy text before match */
        size_t pre = m.offset - offset;
        if (pre > 0) {
            while (pos + pre >= cap) {
                cap *= 2;
                char *tmp = realloc(buf, cap);
                if (!tmp) { free(buf); free(cb_buf); npe_regex_match_free(&m); return NPE_ERROR_MEMORY; }
                buf = tmp;
            }
            memcpy(buf + pos, subject + offset, pre);
            pos += pre;
        }

        /* invoke callback */
        int cb_written = callback(&m, userdata, cb_buf, cb_cap);
        if (cb_written < 0) {
            npe_regex_match_free(&m);
            free(buf);
            free(cb_buf);
            return NPE_ERR_REGEX;
        }

        while (pos + (size_t)cb_written >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); free(cb_buf); npe_regex_match_free(&m); return NPE_ERROR_MEMORY; }
            buf = tmp;
        }
        memcpy(buf + pos, cb_buf, (size_t)cb_written);
        pos += (size_t)cb_written;

        rcount++;

        size_t new_offset = m.offset + m.length;
        if (new_offset == offset) new_offset++;
        offset = new_offset;

        npe_regex_match_free(&m);
    }

    free(cb_buf);

    /* copy remaining */
    if (offset < length) {
        size_t rem = length - offset;
        while (pos + rem >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return NPE_ERROR_MEMORY; }
            buf = tmp;
        }
        memcpy(buf + pos, subject + offset, rem);
        pos += rem;
    }

    buf[pos] = '\0';

    *result = buf;
    if (result_len)    *result_len    = pos;
    if (replace_count) *replace_count = rcount;

    pthread_mutex_lock(&g_stats_mutex);
    g_stats.total_replacements += rcount;
    pthread_mutex_unlock(&g_stats_mutex);

    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char REGEX_META_CHARS[] = "\\.^$|()[]{}*+?";

npe_error_t npe_regex_escape(const char  *input,
                             size_t       length,
                             char       **output,
                             size_t      *out_len) {
    if (!input || !output) return NPE_ERROR_INVALID_ARG;
    if (length == 0) length = strlen(input);

    /* worst case: every char is escaped */
    size_t cap = length * 2 + 1;
    char *buf  = malloc(cap);
    if (!buf) return NPE_ERROR_MEMORY;

    size_t pos = 0;
    for (size_t i = 0; i < length; i++) {
        if (strchr(REGEX_META_CHARS, input[i])) {
            buf[pos++] = '\\';
        }
        buf[pos++] = input[i];
    }
    buf[pos] = '\0';

    *output = buf;
    if (out_len) *out_len = pos;
    return NPE_OK;
}

bool npe_regex_quick_test(const char       *pattern,
                          npe_regex_flag_t  flags,
                          const char       *subject,
                          size_t            length) {
    npe_regex_t *re = NULL;
    npe_error_t err = npe_regex_compile(pattern, flags, NULL, &re);
    if (err != NPE_OK) return false;

    bool result = npe_regex_test(re, subject, length);

    /* only destroy if not cached */
    if (!g_cache.enabled) {
        npe_regex_destroy(re);
    }

    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATISTICS & DIAGNOSTICS
 * ═══════════════════════════════════════════════════════════════════════════ */

void npe_regex_get_stats(npe_regex_stats_t *stats) {
    if (!stats) return;
    pthread_mutex_lock(&g_stats_mutex);
    *stats = g_stats;
    pthread_mutex_unlock(&g_stats_mutex);
}

void npe_regex_reset_stats(void) {
    pthread_mutex_lock(&g_stats_mutex);
    memset(&g_stats, 0, sizeof(g_stats));
    pthread_mutex_unlock(&g_stats_mutex);
}

npe_error_t npe_regex_set_jit(bool enable) {
    uint32_t has_jit = 0;
    pcre2_config(PCRE2_CONFIG_JIT, &has_jit);
    if (enable && !has_jit) return NPE_ERR_NOT_SUPPORTED;
    g_jit_enabled = enable;
    return NPE_OK;
}

bool npe_regex_jit_enabled(void) {
    return g_jit_enabled;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PATTERN CACHE PUBLIC API
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_regex_cache_enable(size_t max_size) {
    pthread_mutex_lock(&g_cache.mutex);
    g_cache.enabled  = true;
    g_cache.capacity = max_size;
    pthread_mutex_unlock(&g_cache.mutex);
    return NPE_OK;
}

void npe_regex_cache_disable(void) {
    npe_regex_cache_clear();
    pthread_mutex_lock(&g_cache.mutex);
    g_cache.enabled  = false;
    g_cache.capacity = 0;
    pthread_mutex_unlock(&g_cache.mutex);
}

void npe_regex_cache_clear(void) {
    pthread_mutex_lock(&g_cache.mutex);
    cache_entry_t *e = g_cache.head;
    while (e) {
        cache_entry_t *next = e->next;
        cache_entry_free(e);
        e = next;
    }
    g_cache.head = NULL;
    g_cache.tail = NULL;
    g_cache.size = 0;
    pthread_mutex_unlock(&g_cache.mutex);
}

void npe_regex_cache_stats(npe_regex_cache_stats_t *stats) {
    if (!stats) return;
    pthread_mutex_lock(&g_cache.mutex);
    stats->size      = g_cache.size;
    stats->capacity  = g_cache.capacity;
    stats->hits      = g_cache.hits;
    stats->misses    = g_cache.misses;
    stats->evictions = g_cache.evictions;
    pthread_mutex_unlock(&g_cache.mutex);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_regex_flag_t npe_regex_flags_from_table(npe_vm_t *vm, int idx) {
    lua_State *L = (lua_State *)vm;
    npe_regex_flag_t flags = NPE_REGEX_NONE;

    if (!lua_istable(L, idx)) {
        /* if it's a string, parse flag characters */
        if (lua_isstring(L, idx)) {
            const char *s = lua_tostring(L, idx);
            for (; *s; s++) {
                switch (*s) {
                    case 'i': flags |= NPE_REGEX_CASELESS;  break;
                    case 'm': flags |= NPE_REGEX_MULTILINE; break;
                    case 's': flags |= NPE_REGEX_DOTALL;    break;
                    case 'x': flags |= NPE_REGEX_EXTENDED;  break;
                    case 'u': flags |= NPE_REGEX_UTF;       break;
                    case 'U': flags |= NPE_REGEX_UNGREEDY;  break;
                    case 'a': flags |= NPE_REGEX_ANCHORED;  break;
                    default: break;
                }
            }
        }
        return flags;
    }

    lua_getfield(L, idx, "caseless");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_CASELESS;
    lua_pop(L, 1);

    lua_getfield(L, idx, "multiline");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_MULTILINE;
    lua_pop(L, 1);

    lua_getfield(L, idx, "dotall");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_DOTALL;
    lua_pop(L, 1);

    lua_getfield(L, idx, "extended");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_EXTENDED;
    lua_pop(L, 1);

    lua_getfield(L, idx, "anchored");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_ANCHORED;
    lua_pop(L, 1);

    lua_getfield(L, idx, "ungreedy");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_UNGREEDY;
    lua_pop(L, 1);

    lua_getfield(L, idx, "utf");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_UTF;
    lua_pop(L, 1);

    lua_getfield(L, idx, "no_auto_capture");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_NO_AUTO_CAPTURE;
    lua_pop(L, 1);

    return flags;
}

npe_regex_match_flag_t npe_regex_match_flags_from_table(npe_vm_t *vm, int idx) {
    lua_State *L = (lua_State *)vm;
    npe_regex_match_flag_t flags = NPE_REGEX_MATCH_NONE;

    if (!lua_istable(L, idx)) return flags;

    lua_getfield(L, idx, "notbol");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_MATCH_NOTBOL;
    lua_pop(L, 1);

    lua_getfield(L, idx, "noteol");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_MATCH_NOTEOL;
    lua_pop(L, 1);

    lua_getfield(L, idx, "notempty");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_MATCH_NOTEMPTY;
    lua_pop(L, 1);

    lua_getfield(L, idx, "partial");
    if (lua_toboolean(L, -1)) flags |= NPE_REGEX_MATCH_PARTIAL;
    lua_pop(L, 1);

    return flags;
}

void npe_regex_push_match(npe_vm_t *vm, const npe_regex_match_t *match) {
    lua_State *L = (lua_State *)vm;

    if (!match || !match->matched) {
        lua_pushnil(L);
        return;
    }

    lua_createtable(L, 0, 5);

    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "matched");

    lua_pushinteger(L, (lua_Integer)(match->offset + 1)); /* 1-based */
    lua_setfield(L, -2, "offset");

    lua_pushinteger(L, (lua_Integer)match->length);
    lua_setfield(L, -2, "length");

    /* full match text */
    if (match->capture_count > 0 && match->captures[0].matched) {
        lua_pushlstring(L, match->captures[0].start,
                        match->captures[0].length);
        lua_setfield(L, -2, "text");
    }

    /* captures array */
    if (match->capture_count > 1) {
        lua_createtable(L, (int)(match->capture_count - 1), 0);
        for (size_t i = 1; i < match->capture_count; i++) {
            const npe_regex_capture_t *cap = &match->captures[i];
            if (cap->matched) {
                lua_createtable(L, 0, 4);

                lua_pushlstring(L, cap->start, cap->length);
                lua_setfield(L, -2, "text");

                lua_pushinteger(L, (lua_Integer)(cap->start -
                    match->captures[0].start + match->offset + 1));
                lua_setfield(L, -2, "offset");

                lua_pushinteger(L, (lua_Integer)cap->length);
                lua_setfield(L, -2, "length");

                if (cap->name[0] != '\0') {
                    lua_pushstring(L, cap->name);
                    lua_setfield(L, -2, "name");
                }

                lua_rawseti(L, -2, (int)i);
            } else {
                lua_pushboolean(L, 0);
                lua_rawseti(L, -2, (int)i);
            }
        }
        lua_setfield(L, -2, "captures");
    }
}

void npe_regex_push_match_array(npe_vm_t *vm,
                                const npe_regex_match_t *matches,
                                size_t count) {
    lua_State *L = (lua_State *)vm;
    lua_createtable(L, (int)count, 0);
    for (size_t i = 0; i < count; i++) {
        npe_regex_push_match(vm, &matches[i]);
        lua_rawseti(L, -2, (int)(i + 1));
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA REGEX OBJECT METHODS
 * ═══════════════════════════════════════════════════════════════════════════ */

static npe_regex_t **check_regex(lua_State *L, int idx) {
    return (npe_regex_t **)luaL_checkudata(L, idx, NPE_REGEX_META);
}

static int l_regex_gc(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (*rep) {
        npe_regex_destroy(*rep);
        *rep = NULL;
    }
    return 0;
}

static int l_regex_tostring(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (*rep && (*rep)->pattern_str) {
        lua_pushfstring(L, "regex(%s)", (*rep)->pattern_str);
    } else {
        lua_pushstring(L, "regex(destroyed)");
    }
    return 1;
}

static int l_regex_exec(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");

    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);
    size_t offset = (size_t)luaL_optinteger(L, 3, 1) - 1; /* 1-based to 0-based */

    npe_regex_match_flag_t mflags = NPE_REGEX_MATCH_NONE;
    if (lua_istable(L, 4)) {
        mflags = npe_regex_match_flags_from_table((npe_vm_t *)L, 4);
    }

    npe_regex_match_t m = {0};
    npe_error_t err = npe_regex_exec(*rep, subject, slen, offset, mflags, &m);

    if (err == NPE_OK && m.matched) {
        npe_regex_push_match((npe_vm_t *)L, &m);
    } else {
        lua_pushnil(L);
    }
    npe_regex_match_free(&m);
    return 1;
}

static int l_regex_test(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");

    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);

    lua_pushboolean(L, npe_regex_test(*rep, subject, slen));
    return 1;
}

static int l_regex_find(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");

    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);
    size_t offset = (size_t)luaL_optinteger(L, 3, 1) - 1;

    size_t start_out, end_out;
    npe_error_t err = npe_regex_find(*rep, subject, slen, offset,
                                     &start_out, &end_out);
    if (err == NPE_OK) {
        lua_pushinteger(L, (lua_Integer)(start_out + 1)); /* 1-based */
        lua_pushinteger(L, (lua_Integer)end_out);         /* inclusive end */
        return 2;
    }
    lua_pushnil(L);
    return 1;
}

static int l_regex_findall(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");

    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);
    size_t max = (size_t)luaL_optinteger(L, 3, 0);

    npe_regex_match_t *matches = NULL;
    size_t count = 0;
    npe_error_t err = npe_regex_find_all(*rep, subject, slen, max,
                                         &matches, &count);
    if (err != NPE_OK) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    npe_regex_push_match_array((npe_vm_t *)L, matches, count);
    npe_regex_match_array_free(matches, count);
    return 1;
}

static int l_regex_split(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");

    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);
    size_t max = (size_t)luaL_optinteger(L, 3, 0);

    char **parts = NULL;
    size_t count = 0;
    npe_error_t err = npe_regex_split(*rep, subject, slen, max,
                                      &parts, &count);
    if (err != NPE_OK) {
        lua_createtable(L, 0, 0);
        return 1;
    }

    lua_createtable(L, (int)count, 0);
    for (size_t i = 0; i < count; i++) {
        lua_pushstring(L, parts[i]);
        lua_rawseti(L, -2, (int)(i + 1));
    }
    npe_regex_split_free(parts, count);
    return 1;
}

static int l_regex_replace(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");

    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);
    const char *repl    = luaL_checkstring(L, 3);
    size_t max = (size_t)luaL_optinteger(L, 4, 0);

    char  *result     = NULL;
    size_t result_len = 0;
    size_t rcount     = 0;

    npe_error_t err = npe_regex_replace(*rep, subject, slen, repl, max,
                                        &result, &result_len, &rcount);
    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushinteger(L, 0);
        return 2;
    }

    lua_pushlstring(L, result, result_len);
    lua_pushinteger(L, (lua_Integer)rcount);
    free(result);
    return 2;
}

static int l_regex_pattern(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");
    lua_pushstring(L, npe_regex_pattern(*rep));
    return 1;
}

static int l_regex_groups(lua_State *L) {
    npe_regex_t **rep = check_regex(L, 1);
    if (!*rep) return luaL_error(L, "regex object is destroyed");
    lua_pushinteger(L, (lua_Integer)npe_regex_capture_count(*rep));
    return 1;
}

static const luaL_Reg regex_methods[] = {
    {"exec",    l_regex_exec},
    {"test",    l_regex_test},
    {"find",    l_regex_find},
    {"findall", l_regex_findall},
    {"split",   l_regex_split},
    {"replace", l_regex_replace},
    {"pattern", l_regex_pattern},
    {"groups",  l_regex_groups},
    {NULL, NULL}
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA MODULE FUNCTIONS (npe.regex.*)
 * ═══════════════════════════════════════════════════════════════════════════ */
static int l_mod_compile(lua_State *L) {
    const char *pattern = luaL_checkstring(L, 1);

    npe_regex_flag_t flags = NPE_REGEX_NONE;
    if (lua_gettop(L) >= 2) {
        flags = npe_regex_flags_from_table((npe_vm_t *)L, 2);
    }

    npe_regex_t *re = NULL;
    npe_error_t err = npe_regex_compile(pattern, flags, NULL, &re);

    if (err == NPE_ERR_REGEX_COMPILE) {
        /* push nil + error message */
        char errbuf[256];
        size_t erroff = 0;
        npe_regex_get_compile_error(re, errbuf, sizeof(errbuf), &erroff);
        npe_regex_destroy(re);
        lua_pushnil(L);
        lua_pushfstring(L, "regex compile error at offset %d: %s",
                        (int)erroff, errbuf);
        return 2;
    }

    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "regex compilation failed");
        return 2;
    }

    npe_regex_t **ud = (npe_regex_t **)lua_newuserdata(L, sizeof(npe_regex_t *));
    *ud = re;
    luaL_getmetatable(L, NPE_REGEX_META);
    lua_setmetatable(L, -2);
    return 1;
}

static int l_mod_test(lua_State *L) {
    const char *pattern = luaL_checkstring(L, 1);
    size_t slen;
    const char *subject = luaL_checklstring(L, 2, &slen);

    npe_regex_flag_t flags = NPE_REGEX_NONE;
    if (lua_gettop(L) >= 3) {
        flags = npe_regex_flags_from_table((npe_vm_t *)L, 3);
    }

    lua_pushboolean(L, npe_regex_quick_test(pattern, flags, subject, slen));
    return 1;
}

static int l_mod_escape(lua_State *L) {
    size_t len;
    const char *input = luaL_checklstring(L, 1, &len);

    char  *output   = NULL;
    size_t out_len  = 0;
    npe_error_t err = npe_regex_escape(input, len, &output, &out_len);
    if (err != NPE_OK) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlstring(L, output, out_len);
    free(output);
    return 1;
}

static int l_mod_set_jit(lua_State *L) {
    int enable = lua_toboolean(L, 1);
    npe_error_t err = npe_regex_set_jit((bool)enable);
    lua_pushboolean(L, err == NPE_OK);
    return 1;
}

static int l_mod_jit_enabled(lua_State *L) {
    lua_pushboolean(L, npe_regex_jit_enabled());
    return 1;
}

static int l_mod_cache_enable(lua_State *L) {
    size_t max_size = (size_t)luaL_optinteger(L, 1, 64);
    npe_error_t err = npe_regex_cache_enable(max_size);
    lua_pushboolean(L, err == NPE_OK);
    return 1;
}

static int l_mod_cache_disable(lua_State *L) {
    (void)L;
    npe_regex_cache_disable();
    return 0;
}

static int l_mod_cache_clear(lua_State *L) {
    (void)L;
    npe_regex_cache_clear();
    return 0;
}

static int l_mod_cache_stats(lua_State *L) {
    npe_regex_cache_stats_t stats;
    npe_regex_cache_stats(&stats);

    lua_createtable(L, 0, 5);

    lua_pushinteger(L, (lua_Integer)stats.size);
    lua_setfield(L, -2, "size");

    lua_pushinteger(L, (lua_Integer)stats.capacity);
    lua_setfield(L, -2, "capacity");

    lua_pushinteger(L, (lua_Integer)stats.hits);
    lua_setfield(L, -2, "hits");

    lua_pushinteger(L, (lua_Integer)stats.misses);
    lua_setfield(L, -2, "misses");

    lua_pushinteger(L, (lua_Integer)stats.evictions);
    lua_setfield(L, -2, "evictions");

    return 1;
}

static int l_mod_stats(lua_State *L) {
    npe_regex_stats_t stats;
    npe_regex_get_stats(&stats);

    lua_createtable(L, 0, 6);

    lua_pushinteger(L, (lua_Integer)stats.total_compiles);
    lua_setfield(L, -2, "total_compiles");

    lua_pushinteger(L, (lua_Integer)stats.total_matches);
    lua_setfield(L, -2, "total_matches");

    lua_pushinteger(L, (lua_Integer)stats.total_replacements);
    lua_setfield(L, -2, "total_replacements");

    lua_pushnumber(L, (lua_Number)stats.total_match_time_ns / 1e6);
    lua_setfield(L, -2, "total_match_time_ms");

    lua_pushinteger(L, (lua_Integer)stats.cache_hits);
    lua_setfield(L, -2, "cache_hits");

    lua_pushinteger(L, (lua_Integer)stats.cache_misses);
    lua_setfield(L, -2, "cache_misses");

    return 1;
}

static int l_mod_reset_stats(lua_State *L) {
    (void)L;
    npe_regex_reset_stats();
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MODULE FUNCTION TABLE
 * ═══════════════════════════════════════════════════════════════════════════ */

static const luaL_Reg regex_module_funcs[] = {
    {"compile",       l_mod_compile},
    {"test",          l_mod_test},
    {"escape",        l_mod_escape},
    {"set_jit",       l_mod_set_jit},
    {"jit_enabled",   l_mod_jit_enabled},
    {"cache_enable",  l_mod_cache_enable},
    {"cache_disable", l_mod_cache_disable},
    {"cache_clear",   l_mod_cache_clear},
    {"cache_stats",   l_mod_cache_stats},
    {"stats",         l_mod_stats},
    {"reset_stats",   l_mod_reset_stats},
    {NULL, NULL}
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  LIBRARY REGISTRATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static int npe_regex_lua_register(lua_State *L) {
    /* Create the regex object metatable */
    luaL_newmetatable(L, NPE_REGEX_META);

    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);

    lua_pushstring(L, "__gc");
    lua_pushcfunction(L, l_regex_gc);
    lua_settable(L, -3);

    lua_pushstring(L, "__tostring");
    lua_pushcfunction(L, l_regex_tostring);
    lua_settable(L, -3);

    /* Instance methods */
    luaL_setfuncs(L, regex_methods, 0);
    lua_pop(L, 1); /* pop metatable */

    /* Create module table: npe.regex */
    luaL_newlib(L, regex_module_funcs);

    /* Export flags */
    lua_pushinteger(L, NPE_REGEX_NONE);
    lua_setfield(L, -2, "NONE");

    lua_pushinteger(L, NPE_REGEX_CASELESS);
    lua_setfield(L, -2, "CASELESS");

    lua_pushinteger(L, NPE_REGEX_MULTILINE);
    lua_setfield(L, -2, "MULTILINE");

    lua_pushinteger(L, NPE_REGEX_DOTALL);
    lua_setfield(L, -2, "DOTALL");

    lua_pushinteger(L, NPE_REGEX_EXTENDED);
    lua_setfield(L, -2, "EXTENDED");

    lua_pushinteger(L, NPE_REGEX_ANCHORED);
    lua_setfield(L, -2, "ANCHORED");

    lua_pushinteger(L, NPE_REGEX_UNGREEDY);
    lua_setfield(L, -2, "UNGREEDY");

    lua_pushinteger(L, NPE_REGEX_UTF);
    lua_setfield(L, -2, "UTF");

    lua_pushinteger(L, NPE_REGEX_NO_AUTO_CAPTURE);
    lua_setfield(L, -2, "NO_AUTO_CAPTURE");

    return 1; /* Lua module on stack */
}

npe_error_t npe_lib_regex_register(npe_vm_t *vm)
{
    if (!vm)
        return NPE_ERROR_INVALID_ARG;

    lua_State *L = npe_vm_lua(vm);
    if (!L)
        return NPE_ERROR_INVALID_ARG;

    /* Create npe namespace if missing */
    lua_getglobal(L, "npe");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_setglobal(L, "npe");
        lua_getglobal(L, "npe");
    }

    /* Register regex module */
    npe_regex_lua_register(L);
    lua_setfield(L, -2, "regex");

    lua_pop(L, 1); /* pop npe */

    return NPE_OK;
}