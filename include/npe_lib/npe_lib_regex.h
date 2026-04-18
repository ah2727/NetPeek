/*****************************************************************************
 * npe_lib_regex.h — Regular expression matching library
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Provides PCRE2-compatible regular expression support for .npe scripts.
 * This library exposes both a C API (for internal engine use) and
 * registers Lua bindings under the `npe.regex` namespace.
 *
 * Features:
 *   • Compile-once, match-many pattern objects
 *   • Named and numbered capture groups
 *   • Global matching (find all)
 *   • Search, match, split, replace operations
 *   • Configurable match limits for DoS protection
 *
 * Lua API:
 *   npe.regex.compile(pattern, flags?)      → regex object
 *   npe.regex.match(pattern, subject)       → captures or nil
 *   npe.regex.find(pattern, subject, start?) → start, end or nil
 *   npe.regex.findall(pattern, subject)     → array of matches
 *   npe.regex.split(pattern, subject, max?) → array of parts
 *   npe.regex.replace(pattern, subject, repl, max?) → string, count
 *   npe.regex.escape(string)                → escaped pattern string
 *
 * Thread-safety: compiled regex objects are immutable and can be shared.
 *                Match state is per-call and thread-safe.
 *****************************************************************************/

#ifndef NPE_LIB_REGEX_H
#define NPE_LIB_REGEX_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_vm       npe_vm_t;
typedef struct npe_context  npe_context_t;

/* ── Opaque regex handle ─────────────────────────────────────────────────── */
typedef struct npe_regex    npe_regex_t;

/* ── Compile flags ───────────────────────────────────────────────────────── */
typedef enum npe_regex_flag {
    NPE_REGEX_NONE          = 0,
    NPE_REGEX_CASELESS      = (1 << 0),   /* case-insensitive matching       */
    NPE_REGEX_MULTILINE     = (1 << 1),   /* ^ and $ match line boundaries   */
    NPE_REGEX_DOTALL        = (1 << 2),   /* . matches newlines              */
    NPE_REGEX_EXTENDED      = (1 << 3),   /* ignore whitespace, allow #comments */
    NPE_REGEX_ANCHORED      = (1 << 4),   /* anchor at start of subject      */
    NPE_REGEX_UNGREEDY      = (1 << 5),   /* invert greediness of quantifiers */
    NPE_REGEX_UTF           = (1 << 6),   /* treat pattern/subject as UTF-8  */
    NPE_REGEX_NO_AUTO_CAPTURE = (1 << 7), /* disable numbered captures       */
} npe_regex_flag_t;

/* ── Match flags (runtime) ───────────────────────────────────────────────── */
typedef enum npe_regex_match_flag {
    NPE_REGEX_MATCH_NONE       = 0,
    NPE_REGEX_MATCH_NOTBOL     = (1 << 0),  /* subject not at beginning of line */
    NPE_REGEX_MATCH_NOTEOL     = (1 << 1),  /* subject not at end of line       */
    NPE_REGEX_MATCH_NOTEMPTY   = (1 << 2),  /* empty string is not a valid match */
    NPE_REGEX_MATCH_PARTIAL    = (1 << 3),  /* enable partial matching          */
} npe_regex_match_flag_t;

/* ── Capture group ───────────────────────────────────────────────────────── */
typedef struct npe_regex_capture {
    const char   *start;       /* pointer into original subject           */
    size_t        length;      /* length of capture                       */
    int           group;       /* group number (0 = full match)           */
    char          name[64];    /* named group name, or empty              */
    bool          matched;     /* false if group did not participate      */
} npe_regex_capture_t;

/* ── Match result ────────────────────────────────────────────────────────── */
typedef struct npe_regex_match {
    bool                  matched;        /* true if pattern matched         */
    size_t                offset;         /* byte offset in subject          */
    size_t                length;         /* length of full match            */
    npe_regex_capture_t  *captures;       /* array of capture groups         */
    size_t                capture_count;  /* number of captures (incl. group 0) */
} npe_regex_match_t;

/* ── Resource limits ─────────────────────────────────────────────────────── */
typedef struct npe_regex_limits {
    uint32_t  match_limit;           /* max backtracking steps (0 = default)  */
    uint32_t  depth_limit;           /* max recursion depth    (0 = default)  */
    size_t    heap_limit;            /* max heap for JIT       (0 = default)  */
} npe_regex_limits_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  COMPILATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Compile a regular expression pattern.
 *
 * @param pattern   pattern string (NUL-terminated)
 * @param flags     compile-time flags
 * @param limits    resource limits (NULL for defaults)
 * @param out       receives compiled regex on success
 * @return NPE_OK or error code (NPE_ERR_REGEX_COMPILE on syntax error)
 */
npe_error_t npe_regex_compile(const char              *pattern,
                              npe_regex_flag_t         flags,
                              const npe_regex_limits_t *limits,
                              npe_regex_t            **out);

/**
 * Compile with explicit pattern length (allows embedded NULs).
 */
npe_error_t npe_regex_compile_n(const char              *pattern,
                                size_t                   pattern_len,
                                npe_regex_flag_t         flags,
                                const npe_regex_limits_t *limits,
                                npe_regex_t            **out);

/**
 * Destroy a compiled regex and free resources.
 */
void npe_regex_destroy(npe_regex_t *re);

/**
 * Get the original pattern string.
 */
const char *npe_regex_pattern(const npe_regex_t *re);

/**
 * Get the number of capture groups (excluding group 0).
 */
size_t npe_regex_capture_count(const npe_regex_t *re);

/**
 * Get the index of a named capture group.
 * Returns -1 if the name does not exist.
 */
int npe_regex_name_to_index(const npe_regex_t *re, const char *name);

/**
 * Get compile error details (valid after NPE_ERR_REGEX_COMPILE).
 */
npe_error_t npe_regex_get_compile_error(const npe_regex_t *re,
                                        char              *buf,
                                        size_t             buf_size,
                                        size_t            *error_offset);

/* ═══════════════════════════════════════════════════════════════════════════
 *  MATCHING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Execute a single match against a subject string.
 *
 * @param re        compiled regex
 * @param subject   subject string
 * @param length    subject length (0 = strlen)
 * @param offset    starting offset in subject
 * @param flags     match-time flags
 * @param match     receives match result (caller provides storage)
 * @return NPE_OK if matched, NPE_ERROR_NOT_FOUND if no match, or error
 */
npe_error_t npe_regex_exec(const npe_regex_t     *re,
                           const char            *subject,
                           size_t                 length,
                           size_t                 offset,
                           npe_regex_match_flag_t flags,
                           npe_regex_match_t     *match);

/**
 * Free memory allocated within a match result.
 */
void npe_regex_match_free(npe_regex_match_t *match);

/**
 * Simple boolean test: does the pattern match anywhere in subject?
 */
bool npe_regex_test(const npe_regex_t *re,
                    const char        *subject,
                    size_t             length);

/**
 * Find first occurrence and return offsets.
 *
 * @param re        compiled regex
 * @param subject   subject string
 * @param length    subject length (0 = strlen)
 * @param offset    starting offset
 * @param start_out receives start offset of match (may be NULL)
 * @param end_out   receives end offset of match (may be NULL)
 * @return NPE_OK if found, NPE_ERROR_NOT_FOUND otherwise
 */
npe_error_t npe_regex_find(const npe_regex_t *re,
                           const char        *subject,
                           size_t             length,
                           size_t             offset,
                           size_t            *start_out,
                           size_t            *end_out);

/* ═══════════════════════════════════════════════════════════════════════════
 *  GLOBAL MATCHING (find all)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Find all non-overlapping matches.
 *
 * @param re        compiled regex
 * @param subject   subject string
 * @param length    subject length (0 = strlen)
 * @param max       maximum matches to return (0 = unlimited)
 * @param matches   receives array of match results (heap-allocated)
 * @param count     receives number of matches
 * @return NPE_OK on success
 *
 * Caller must free `*matches` with npe_regex_match_array_free().
 */
npe_error_t npe_regex_find_all(const npe_regex_t  *re,
                               const char         *subject,
                               size_t              length,
                               size_t              max,
                               npe_regex_match_t **matches,
                               size_t             *count);

void npe_regex_match_array_free(npe_regex_match_t *matches, size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SPLIT
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Split a string by a regex pattern.
 *
 * @param re        compiled regex (the delimiter)
 * @param subject   subject string
 * @param length    subject length (0 = strlen)
 * @param max       maximum parts (0 = unlimited)
 * @param parts     receives NULL-terminated array of strings
 * @param count     receives number of parts
 * @return NPE_OK on success
 *
 * Caller must free with npe_regex_split_free().
 */
npe_error_t npe_regex_split(const npe_regex_t  *re,
                            const char         *subject,
                            size_t              length,
                            size_t              max,
                            char             ***parts,
                            size_t             *count);

void npe_regex_split_free(char **parts, size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 *  REPLACE
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Replace callback signature.
 *
 * @param match     the current match
 * @param userdata  opaque pointer
 * @param out       buffer to write replacement text
 * @param out_size  size of output buffer
 * @return number of bytes written, or negative on error
 */
typedef int (*npe_regex_replace_fn)(const npe_regex_match_t *match,
                                    void                    *userdata,
                                    char                    *out,
                                    size_t                   out_size);

/**
 * Replace matches with a literal string.
 *
 * @param re           compiled regex
 * @param subject      subject string
 * @param length       subject length (0 = strlen)
 * @param replacement  replacement string (supports $1, $2, $name backrefs)
 * @param max          max replacements (0 = all)
 * @param result       receives heap-allocated result string
 * @param result_len   receives result length
 * @param replace_count receives number of replacements made (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_regex_replace(const npe_regex_t  *re,
                              const char         *subject,
                              size_t              length,
                              const char         *replacement,
                              size_t              max,
                              char              **result,
                              size_t             *result_len,
                              size_t             *replace_count);

/**
 * Replace matches using a callback function.
 */
npe_error_t npe_regex_replace_func(const npe_regex_t    *re,
                                   const char           *subject,
                                   size_t                length,
                                   npe_regex_replace_fn  callback,
                                   void                 *userdata,
                                   size_t                max,
                                   char                **result,
                                   size_t               *result_len,
                                   size_t               *replace_count);

/* ═══════════════════════════════════════════════════════════════════════════
 *  UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Escape a string so it can be used as a literal in a regex pattern.
 *
 * @param input     raw string
 * @param length    input length (0 = strlen)
 * @param output    receives heap-allocated escaped string
 * @param out_len   receives output length
 * @return NPE_OK on success
 */
npe_error_t npe_regex_escape(const char  *input,
                             size_t       length,
                             char       **output,
                             size_t      *out_len);

/**
 * Quick match using a pattern string (compiles, matches, frees).
 * Convenience function for one-off matches.
 */
bool npe_regex_quick_test(const char       *pattern,
                          npe_regex_flag_t  flags,
                          const char       *subject,
                          size_t            length);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING REGISTRATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register the npe.regex library with a Lua VM.
 * Called automatically during VM initialization.
 *
 * Creates the following Lua namespace:
 *   npe.regex.compile(pattern [, flags]) → regex object
 *   npe.regex.match(pattern, subject)    → table of captures or nil
 *   npe.regex.find(pattern, subject [, start]) → start_pos, end_pos or nil
 *   npe.regex.findall(pattern, subject)  → array of match tables
 *   npe.regex.split(pattern, subject [, max]) → array of strings
 *   npe.regex.replace(pattern, subject, replacement [, max]) → string, count
 *   npe.regex.escape(string)             → escaped string
 *
 * Regex objects are userdata with the following methods:
 *   regex:exec(subject [, offset [, flags]]) → match table or nil
 *   regex:test(subject)                       → boolean
 *   regex:find(subject [, offset])            → start, end or nil
 *   regex:findall(subject [, max])            → array of matches
 *   regex:split(subject [, max])              → array of parts
 *   regex:replace(subject, repl [, max])      → string, count
 *   regex:pattern()                           → pattern string
 *   regex:groups()                            → number of capture groups
 *
 * @param vm  the Lua VM to register with
 * @return NPE_OK on success
 */
npe_error_t npe_lib_regex_register(npe_vm_t *vm);

/**
 * Unregister the regex library and clean up resources.
 */
void npe_lib_regex_unregister(npe_vm_t *vm);

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL HELPERS (used by the Lua binding layer)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Convert a Lua table to compile flags.
 * Table can contain: caseless, multiline, dotall, extended, etc.
 * @internal
 */
npe_regex_flag_t npe_regex_flags_from_table(npe_vm_t *vm, int idx);

/**
 * Convert a Lua table to match flags.
 * @internal
 */
npe_regex_match_flag_t npe_regex_match_flags_from_table(npe_vm_t *vm, int idx);

/**
 * Push a match result onto the Lua stack as a table.
 * @internal
 */
void npe_regex_push_match(npe_vm_t *vm, const npe_regex_match_t *match);

/**
 * Push an array of match results as a Lua array.
 * @internal
 */
void npe_regex_push_match_array(npe_vm_t *vm,
                                const npe_regex_match_t *matches,
                                size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATISTICS & DIAGNOSTICS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Regex engine statistics (for debugging/profiling).
 */
typedef struct npe_regex_stats {
    size_t   total_compiles;      /* total patterns compiled              */
    size_t   total_matches;       /* total match operations               */
    size_t   total_replacements;  /* total replacement operations         */
    size_t   cache_hits;          /* pattern cache hits (if implemented)  */
    size_t   cache_misses;        /* pattern cache misses                 */
    uint64_t total_match_time_ns; /* cumulative match time in nanoseconds */
} npe_regex_stats_t;

/**
 * Get global regex engine statistics.
 */
void npe_regex_get_stats(npe_regex_stats_t *stats);

/**
 * Reset statistics counters.
 */
void npe_regex_reset_stats(void);

/**
 * Enable/disable internal JIT compilation (if PCRE2 JIT is available).
 * @param enable  true to enable JIT, false to disable
 * @return NPE_OK if JIT is available, NPE_ERR_NOT_SUPPORTED otherwise
 */
npe_error_t npe_regex_set_jit(bool enable);

/**
 * Check if JIT compilation is available and enabled.
 */
bool npe_regex_jit_enabled(void);

/* ═══════════════════════════════════════════════════════════════════════════
 *  PATTERN CACHE (optional optimization)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Enable pattern caching to avoid recompiling frequently-used patterns.
 *
 * @param max_size  maximum number of patterns to cache (0 = disable cache)
 * @return NPE_OK on success
 *
 * When enabled, npe_regex_compile() will check the cache first.
 * Cache uses LRU eviction policy.
 */
npe_error_t npe_regex_cache_enable(size_t max_size);

/**
 * Disable pattern caching and clear the cache.
 */
void npe_regex_cache_disable(void);

/**
 * Clear all cached patterns.
 */
void npe_regex_cache_clear(void);

/**
 * Get cache statistics.
 */
typedef struct {
    size_t size;        /* current cache size       */
    size_t capacity;    /* maximum cache size       */
    size_t hits;        /* cache hit count          */
    size_t misses;      /* cache miss count         */
    size_t evictions;   /* number of evicted entries */
} npe_regex_cache_stats_t;

void npe_regex_cache_stats(npe_regex_cache_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_REGEX_H */
