/*****************************************************************************
 * npe_result.c — Script result collection and formatting
 *
 * Thread-safe accumulator for script execution results with multiple
 * output format support (plain text, JSON, CSV).
 *****************************************************************************/

#include "npe_result.h"
#include "npe_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <time.h>

/*============================================================================
 * Internal: Result Collector Structure
 *============================================================================*/

struct npe_result_collector {
    npe_result_entry_t  *head;
    npe_result_entry_t  *tail;
    size_t               count;
    pthread_mutex_t      lock;
};

/*============================================================================
 * Internal Helpers
 *============================================================================*/

/*
 * Deep-copy a result entry.
 *
 * script_name (char[256]) and host_ip (char[64]) are fixed-size arrays
 * embedded in the struct, so the initial shallow copy handles them.
 * Only the heap-allocated output string needs an explicit strdup.
 */
static npe_error_t
result_entry_deep_copy(npe_result_entry_t *dst, const npe_result_entry_t *src)
{
    *dst = *src;      /* shallow copy — handles all fixed-size arrays */
    dst->next = NULL;

    /* Deep copy only the heap-allocated string output */
    if (src->result.output.type == NPE_VAL_STRING && src->result.output.v.s) {
        dst->result.output.v.s = strdup(src->result.output.v.s);
        if (!dst->result.output.v.s)
            return NPE_ERROR_MEMORY;
    }

    return NPE_OK;
}

static void
result_entry_free_members(npe_result_entry_t *entry)
{
    if (!entry)
        return;

    /* script_name and host_ip are char[] arrays — nothing to free */

    npe_result_free_members(&entry->result);
}

/*----------------------------------------------------------------------------
 * Formatting utilities
 *----------------------------------------------------------------------------*/

static const char *
protocol_to_string(npe_protocol_t proto)
{
    switch (proto) {
    case NPE_PROTO_TCP:  return "tcp";
    case NPE_PROTO_UDP:  return "udp";
    case NPE_PROTO_SCTP: return "sctp";
    default:             return "unknown";
    }
}

static const char *
phase_to_string(npe_phase_t phase)
{
    switch (phase) {
    case NPE_PHASE_PRERULE:   return "prerule";
    case NPE_PHASE_HOSTRULE:  return "hostrule";
    case NPE_PHASE_PORTRULE:  return "portrule";
    case NPE_PHASE_POSTRULE:  return "postrule";
    default:                  return "unknown";
    }
}

static const char *
status_to_string(npe_error_t status)
{
    if (status == NPE_OK) return "success";
    return "error";
}

/*
 * JSON-escape a string.  Returns a heap-allocated escaped string
 * (without surrounding quotes).  For NULL input returns the literal
 * four-character string "null" (unquoted) — callers that wrap in
 * \"%s\" will produce the JSON string "null"; callers that need a
 * real JSON null must check for NULL before calling.
 */
static char *
json_escape(const char *src)
{
    if (!src)
        return strdup("null");

    size_t  srclen = strlen(src);
    size_t  bufsz  = srclen * 6 + 1;
    char   *buf    = malloc(bufsz);
    if (!buf)
        return NULL;

    char       *wp        = buf;
    const char *rp        = src;
    size_t      remaining = bufsz;

    while (*rp && remaining > 1) {
        switch (*rp) {
        case '"':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = '"';
            remaining -= 2;
            break;
        case '\\':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = '\\';
            remaining -= 2;
            break;
        case '\b':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = 'b';
            remaining -= 2;
            break;
        case '\f':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = 'f';
            remaining -= 2;
            break;
        case '\n':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = 'n';
            remaining -= 2;
            break;
        case '\r':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = 'r';
            remaining -= 2;
            break;
        case '\t':
            if (remaining < 3) goto done;
            *wp++ = '\\'; *wp++ = 't';
            remaining -= 2;
            break;
        default:
            if ((unsigned char)*rp < 0x20) {
                if (remaining < 7) goto done;
                int written = snprintf(wp, remaining, "\\u%04x",
                                       (unsigned char)*rp);
                if (written < 0 || (size_t)written >= remaining)
                    goto done;
                wp        += written;
                remaining -= (size_t)written;
            } else {
                *wp++ = *rp;
                remaining--;
            }
            break;
        }
        rp++;
    }

done:
    *wp = '\0';
    return buf;
}

static char *
csv_escape(const char *src)
{
    if (!src)
        return strdup("");

    bool needs_quoting = false;
    size_t extra = 0;

    for (const char *p = src; *p; p++) {
        if (*p == '"') {
            needs_quoting = true;
            extra++;
        } else if (*p == ',' || *p == '\n' || *p == '\r') {
            needs_quoting = true;
        }
    }

    if (!needs_quoting)
        return strdup(src);

    size_t srclen = strlen(src);
    size_t bufsz  = srclen + extra + 3;
    char  *buf    = malloc(bufsz);
    if (!buf)
        return NULL;

    char *wp = buf;
    *wp++ = '"';
    for (const char *rp = src; *rp; rp++) {
        if (*rp == '"')
            *wp++ = '"';
        *wp++ = *rp;
    }
    *wp++ = '"';
    *wp   = '\0';
    return buf;
}

/*============================================================================
 * Result Lifecycle Helpers
 *============================================================================*/

void
npe_result_init(npe_result_t *result)
{
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    result->status = NPE_ERROR_GENERIC;
}

void
npe_result_free_members(npe_result_t *result)
{
    if (!result)
        return;

    if (result->output.type == NPE_VAL_STRING && result->output.v.s) {
        free(result->output.v.s);
        result->output.v.s = NULL;
    }
}

/*============================================================================
 * Result Collector — Create / Destroy
 *============================================================================*/

npe_error_t
npe_result_collector_create(npe_result_collector_t **out)
{
    if (!out)
        return NPE_ERROR_INVALID_ARG;

    npe_result_collector_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NPE_ERROR_MEMORY;

    int rc = pthread_mutex_init(&c->lock, NULL);
    if (rc != 0) {
        free(c);
        return NPE_ERROR_GENERIC;
    }

    c->head  = NULL;
    c->tail  = NULL;
    c->count = 0;

    *out = c;
    return NPE_OK;
}

void
npe_result_collector_destroy(npe_result_collector_t **collector)
{
    if (!collector || !*collector)
        return;

    npe_result_collector_t *c = *collector;

    npe_result_entry_t *cur = c->head;
    while (cur) {
        npe_result_entry_t *next = cur->next;
        result_entry_free_members(cur);
        free(cur);
        cur = next;
    }

    pthread_mutex_destroy(&c->lock);
    free(c);
    *collector = NULL;
}

/*============================================================================
 * Result Collector — Add (thread-safe)
 *============================================================================*/

npe_error_t
npe_result_collector_add(npe_result_collector_t   *collector,
                         const npe_result_entry_t *entry)
{
    if (!collector || !entry)
        return NPE_ERROR_INVALID_ARG;

    npe_result_entry_t *node = calloc(1, sizeof(*node));
    if (!node)
        return NPE_ERROR_MEMORY;

    npe_error_t err = result_entry_deep_copy(node, entry);
    if (err != NPE_OK) {
        free(node);
        return err;
    }

    pthread_mutex_lock(&collector->lock);

    if (collector->tail) {
        collector->tail->next = node;
    } else {
        collector->head = node;
    }
    collector->tail = node;
    collector->count++;

    pthread_mutex_unlock(&collector->lock);

    return NPE_OK;
}

/*============================================================================
 * Result Collector — Get All
 *
 * The header declares `const npe_result_collector_t *`.  We cast away const
 * only for the mutex lock/unlock — the logical contents are not modified.
 *============================================================================*/

npe_error_t
npe_result_collector_get_all(const npe_result_collector_t *collector,
                             npe_result_entry_t          **out,
                             size_t                       *count)
{
    if (!collector || !out || !count)
        return NPE_ERROR_INVALID_ARG;

    /* Cast away const only for the mutex — logical state is unchanged */
    npe_result_collector_t *mut =
        (npe_result_collector_t *)(uintptr_t)collector;

    pthread_mutex_lock(&mut->lock);

    size_t n = mut->count;
    if (n == 0) {
        pthread_mutex_unlock(&mut->lock);
        *out   = NULL;
        *count = 0;
        return NPE_OK;
    }

    npe_result_entry_t *arr = calloc(n, sizeof(*arr));
    if (!arr) {
        pthread_mutex_unlock(&mut->lock);
        return NPE_ERROR_MEMORY;
    }

    npe_result_entry_t *cur = mut->head;
    for (size_t i = 0; i < n && cur; i++, cur = cur->next) {
        npe_error_t err = result_entry_deep_copy(&arr[i], cur);
        if (err != NPE_OK) {
            for (size_t j = 0; j < i; j++)
                result_entry_free_members(&arr[j]);
            free(arr);
            pthread_mutex_unlock(&mut->lock);
            return err;
        }
    }

    pthread_mutex_unlock(&mut->lock);

    *out   = arr;
    *count = n;
    return NPE_OK;
}

/*============================================================================
 * Result Collector — Count
 *============================================================================*/

size_t
npe_result_collector_count(const npe_result_collector_t *collector)
{
    if (!collector)
        return 0;

    npe_result_collector_t *mut =
        (npe_result_collector_t *)(uintptr_t)collector;

    pthread_mutex_lock(&mut->lock);
    size_t n = mut->count;
    pthread_mutex_unlock(&mut->lock);

    return n;
}

/*============================================================================
 * Formatting — Plain Text
 *============================================================================*/

char *
npe_result_format_text(const npe_result_entry_t *entry)
{
    if (!entry)
        return NULL;

    const char *phase_str  = phase_to_string(entry->phase);
    const char *proto_str  = protocol_to_string(entry->protocol);
    const char *status_str = status_to_string(entry->result.status);

    /*
     * script_name and host_ip are char[] arrays — always valid,
     * but guard against an empty string for display purposes.
     */
    const char *script = entry->script_name[0] ? entry->script_name
                                                : "(unknown)";
    const char *host   = entry->host_ip[0]     ? entry->host_ip
                                                : "(unknown)";

    const char *output = (entry->result.output.type == NPE_VAL_STRING
                          && entry->result.output.v.s)
                         ? entry->result.output.v.s : "";

    int needed;
    if (entry->port_number != 0) {
        needed = snprintf(NULL, 0,
            "[%s] %s on %s:%" PRIu16 "/%s\n"
            "Status : %s (%.2f ms)\n"
            "Output :\n"
            "  %s\n",
            phase_str,
            script,
            host,
            entry->port_number,
            proto_str,
            status_str,
            entry->result.elapsed_ms,
            output);
    } else {
        needed = snprintf(NULL, 0,
            "[%s] %s on %s\n"
            "Status : %s (%.2f ms)\n"
            "Output :\n"
            "  %s\n",
            phase_str,
            script,
            host,
            status_str,
            entry->result.elapsed_ms,
            output);
    }

    if (needed < 0)
        return NULL;

    size_t bufsz = (size_t)needed + 1;
    char  *buf   = malloc(bufsz);
    if (!buf)
        return NULL;

    if (entry->port_number != 0) {
        snprintf(buf, bufsz,
            "[%s] %s on %s:%" PRIu16 "/%s\n"
            "Status : %s (%.2f ms)\n"
            "Output :\n"
            "  %s\n",
            phase_str,
            script,
            host,
            entry->port_number,
            proto_str,
            status_str,
            entry->result.elapsed_ms,
            output);
    } else {
        snprintf(buf, bufsz,
            "[%s] %s on %s\n"
            "Status : %s (%.2f ms)\n"
            "Output :\n"
            "  %s\n",
            phase_str,
            script,
            host,
            status_str,
            entry->result.elapsed_ms,
            output);
    }

    return buf;
}

/*============================================================================
 * Formatting — JSON
 *============================================================================*/

char *
npe_result_format_json(const npe_result_entry_t *entry)
{
    if (!entry)
        return NULL;

    const char *script = entry->script_name[0] ? entry->script_name
                                                : "(unknown)";
    const char *host   = entry->host_ip[0]     ? entry->host_ip
                                                : "(unknown)";

    /*
     * Build the output value portion.  For string types we JSON-escape
     * and wrap in quotes.  For numeric / bool / nil we emit bare JSON
     * literals so the output is type-correct.
     */
    char  *output_fragment = NULL;   /* heap-allocated JSON fragment */

    switch (entry->result.output.type) {
    case NPE_VAL_STRING: {
        const char *raw = entry->result.output.v.s
                          ? entry->result.output.v.s : "";
        char *esc = json_escape(raw);
        if (!esc)
            return NULL;
        /* Build:  "escaped_value"  (with surrounding quotes) */
        size_t len = strlen(esc) + 3; /* quote + esc + quote + NUL */
        output_fragment = malloc(len);
        if (!output_fragment) { free(esc); return NULL; }
        snprintf(output_fragment, len, "\"%s\"", esc);
        free(esc);
        break;
    }
    case NPE_VAL_INT: {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%" PRId64, entry->result.output.v.i);
        output_fragment = strdup(tmp);
        break;
    }
    case NPE_VAL_FLOAT: {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%g", entry->result.output.v.f);
        output_fragment = strdup(tmp);
        break;
    }
    case NPE_VAL_BOOL:
        output_fragment = strdup(entry->result.output.v.b ? "true" : "false");
        break;
    default:
        output_fragment = strdup("null");
        break;
    }

    if (!output_fragment)
        return NULL;

    char *escaped_script = json_escape(script);
    char *escaped_host   = json_escape(host);

    if (!escaped_script || !escaped_host) {
        free(escaped_script);
        free(escaped_host);
        free(output_fragment);
        return NULL;
    }

    const char *phase_str  = phase_to_string(entry->phase);
    const char *proto_str  = protocol_to_string(entry->protocol);
    const char *status_str = status_to_string(entry->result.status);

    /*
     * Note: output uses %s WITHOUT surrounding quotes — the
     * output_fragment already contains quotes for strings, or
     * is a bare literal for numbers/bool/null.
     */
    static const char fmt[] =
        "{"
        "\"script\":\"%s\","
        "\"host\":\"%s\","
        "\"port\":%" PRIu16 ","
        "\"protocol\":\"%s\","
        "\"phase\":\"%s\","
        "\"status\":\"%s\","
        "\"elapsed_ms\":%.2f,"
        "\"output\":%s"
        "}";

    int needed = snprintf(NULL, 0, fmt,
        escaped_script,
        escaped_host,
        entry->port_number,
        proto_str,
        phase_str,
        status_str,
        entry->result.elapsed_ms,
        output_fragment);

    char *buf = NULL;
    if (needed >= 0) {
        size_t bufsz = (size_t)needed + 1;
        buf = malloc(bufsz);
        if (buf) {
            snprintf(buf, bufsz, fmt,
                escaped_script,
                escaped_host,
                entry->port_number,
                proto_str,
                phase_str,
                status_str,
                entry->result.elapsed_ms,
                output_fragment);
        }
    }

    free(escaped_script);
    free(escaped_host);
    free(output_fragment);

    return buf;
}

/*============================================================================
 * Formatting — CSV
 *============================================================================*/

char *
npe_result_format_csv(const npe_result_entry_t *entry)
{
    if (!entry)
        return NULL;

    const char *output_str = (entry->result.output.type == NPE_VAL_STRING
                              && entry->result.output.v.s)
                             ? entry->result.output.v.s : "";

    const char *script = entry->script_name[0] ? entry->script_name
                                                : "(unknown)";
    const char *host   = entry->host_ip[0]     ? entry->host_ip
                                                : "(unknown)";

    char *esc_script = csv_escape(script);
    char *esc_host   = csv_escape(host);
    char *esc_output = csv_escape(output_str);

    if (!esc_script || !esc_host || !esc_output) {
        free(esc_script);
        free(esc_host);
        free(esc_output);
        return NULL;
    }

    const char *phase_str  = phase_to_string(entry->phase);
    const char *proto_str  = protocol_to_string(entry->protocol);
    const char *status_str = status_to_string(entry->result.status);

    static const char fmt[] = "%s,%s,%" PRIu16 ",%s,%s,%s,%.2f,%s";

    int needed = snprintf(NULL, 0, fmt,
        esc_script,
        esc_host,
        entry->port_number,
        proto_str,
        phase_str,
        status_str,
        entry->result.elapsed_ms,
        esc_output);

    if (needed < 0) {
        free(esc_script);
        free(esc_host);
        free(esc_output);
        return NULL;
    }

    size_t bufsz = (size_t)needed + 1;
    char  *buf   = malloc(bufsz);
    if (!buf) {
        free(esc_script);
        free(esc_host);
        free(esc_output);
        return NULL;
    }

    snprintf(buf, bufsz, fmt,
        esc_script,
        esc_host,
        entry->port_number,
        proto_str,
        phase_str,
        status_str,
        entry->result.elapsed_ms,
        esc_output);

    free(esc_script);
    free(esc_host);
    free(esc_output);

    return buf;
}
