// src/npe/npe_script.c
#include "npe/npe_script.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*============================================================================
 * Script Lifecycle
 *============================================================================*/

npe_error_t npe_script_create(npe_script_t **out) {
    if (!out) return NPE_ERROR_INVALID_ARG;
    npe_script_t *script = calloc(1, sizeof(npe_script_t));
    if (!script) return NPE_ERROR_MEMORY;
    script->state    = NPE_SCRIPT_IDLE;
    script->priority = 50;  /* default priority */
    *out = script;
    return NPE_OK;
}

npe_error_t npe_script_clone(npe_script_t **dst, const npe_script_t *src) {
    if (!dst || !src) return NPE_ERROR_INVALID_ARG;
    npe_script_t *copy = calloc(1, sizeof(npe_script_t));
    if (!copy) return NPE_ERROR_MEMORY;
    memcpy(copy, src, sizeof(npe_script_t));
    /* Deep-copy heap-allocated source fields */
    if (src->source.path) {
        copy->source.path = strdup(src->source.path);
        if (!copy->source.path) { free(copy); return NPE_ERROR_MEMORY; }
    }
    if (src->source.text) {
        copy->source.text = strdup(src->source.text);
        if (!copy->source.text) { free(copy->source.path); free(copy); return NPE_ERROR_MEMORY; }
    }
    copy->next = NULL;
    *dst = copy;
    return NPE_OK;
}

void npe_script_destroy(npe_script_t **script) {
    if (!script || !*script) return;
    free((*script)->source.path);
    free((*script)->source.text);
    free(*script);
    *script = NULL;
}

/*============================================================================
 * Metadata Queries
 *============================================================================*/

bool npe_script_matches_category(const npe_script_t *script, uint32_t mask) {
    if (!script) return false;
    return (script->meta.categories & mask) != 0;
}

bool npe_script_has_phase(const npe_script_t *script, npe_phase_t phase) {
    if (!script) return false;
    switch (phase) {
        case NPE_PHASE_PRERULE:  return script->meta.has_prerule;
        case NPE_PHASE_HOSTRULE: return script->meta.has_hostrule;
        case NPE_PHASE_PORTRULE: return script->meta.has_portrule;
        case NPE_PHASE_POSTRULE: return script->meta.has_postrule;
    }
    return false;
}

bool npe_script_depends_on(const npe_script_t *script, const char *dep_name) {
    if (!script || !dep_name) return false;
    for (size_t i = 0; i < script->meta.dependency_count; i++) {
        if (strcmp(script->meta.dependencies[i], dep_name) == 0)
            return true;
    }
    return false;
}

size_t npe_script_categories_str(const npe_script_t *script, char *buf, size_t bufsz) {
    if (!script || !buf || bufsz == 0) return 0;
    buf[0] = '\0';
    size_t written = 0;
    static const struct { uint32_t bit; const char *name; } cats[] = {
        { NPE_CAT_AUTH,      "auth"      },
        { NPE_CAT_BROADCAST, "broadcast" },
        { NPE_CAT_BRUTE,     "brute"     },
        { NPE_CAT_DEFAULT,   "default"   },
        { NPE_CAT_DISCOVERY, "discovery" },
        { NPE_CAT_DOS,       "dos"       },
        { NPE_CAT_EXPLOIT,   "exploit"   },
        { NPE_CAT_EXTERNAL,  "external"  },
        { NPE_CAT_FUZZER,    "fuzzer"    },
        { NPE_CAT_INTRUSIVE, "intrusive" },
        { NPE_CAT_MALWARE,   "malware"   },
        { NPE_CAT_SAFE,      "safe"      },
        { NPE_CAT_VERSION,   "version"   },
        { NPE_CAT_VULN,      "vuln"      },
    };
    for (size_t i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
        if (!(script->meta.categories & cats[i].bit)) continue;
        int n = snprintf(buf + written, bufsz - written,
                         "%s%s", (written > 0) ? "," : "", cats[i].name);
        if (n < 0 || (size_t)n >= bufsz - written) break;
        written += (size_t)n;
    }
    return written;
}

/*============================================================================
 * Port Interest Matching
 *============================================================================*/

bool npe_script_port_interest(const npe_script_t *script, uint16_t port, npe_protocol_t proto) {
    if (!script) return false;
    /* No interest list means wildcard — match everything */
    if (script->meta.interest_port_count == 0) return true;

    bool port_match = false;
    for (size_t i = 0; i < script->meta.interest_port_count; i++) {
        if (script->meta.interest_ports[i] == port) {
            port_match = true;
            break;
        }
    }
    if (!port_match) return false;

    /* If no protocol filter, port match is enough */
    if (script->meta.interest_protocol_count == 0) return true;

    for (size_t i = 0; i < script->meta.interest_protocol_count; i++) {
        if (script->meta.interest_protocols[i] == proto)
            return true;
    }
    return false;
}

/*============================================================================
 * Sorting / Comparison
 *============================================================================*/

int npe_script_compare(const void *a, const void *b) {
    const npe_script_t *sa = *(const npe_script_t *const *)a;
    const npe_script_t *sb = *(const npe_script_t *const *)b;
    if (sa->priority != sb->priority)
        return (sa->priority < sb->priority) ? -1 : 1;
    return strcmp(sa->filename, sb->filename);
}

/*============================================================================
 * Debug Dump
 *============================================================================*/

void npe_script_dump(const npe_script_t *script, void *fp) {
    FILE *f = fp ? (FILE *)fp : stderr;
    if (!script) {
        fprintf(f, "(null script)\n");
        return;
    }
    char catbuf[512];
    npe_script_categories_str(script, catbuf, sizeof(catbuf));
    fprintf(f, "Script: %s (id=%u, priority=%d)\n", script->filename, script->id, script->priority);
    fprintf(f, "  Author:     %s\n", script->meta.author);
    fprintf(f, "  Categories: %s\n", catbuf);
    fprintf(f, "  Phases:     %s%s%s%s\n",
            script->meta.has_prerule  ? "prerule "  : "",
            script->meta.has_hostrule ? "hostrule " : "",
            script->meta.has_portrule ? "portrule " : "",
            script->meta.has_postrule ? "postrule " : "");
    fprintf(f, "  State:      %d\n", script->state);
}
