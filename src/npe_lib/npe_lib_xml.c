/*****************************************************************************
 * npe_lib_xml.c — XML parsing and generation library
 *
 * Implements a lightweight XML parser, serializer, simplified XPath search,
 * attribute lookup, and Lua bindings exposed as npe.xml.*
 *
 * Lua API:
 *   npe.xml.parse(xml_string)       -> doc userdata
 *   npe.xml.stringify(doc)           -> string
 *   npe.xml.find(doc, xpath)         -> table of node userdata
 *   npe.xml.attr(node, attr_name)   -> string or nil
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include "npe_lib_xml.h"

#include "npe_types.h"
#include "npe_error_compat.h"
#include "lua_compat.h"
#include "npe_vm_compat.h"

/* ========================================================================= */
/*  Forward declarations (internal helpers)                                  */
/* ========================================================================= */

static npe_xml_node_t *xml_node_new(const char *name);
static void            xml_node_free(npe_xml_node_t *node);
static npe_error_t     xml_node_add_child(npe_xml_node_t *parent,
                                          npe_xml_node_t *child);
static npe_error_t     xml_node_add_attr(npe_xml_node_t *node,
                                         const char *name,
                                         const char *value);

/* Parser context */
typedef struct {
    const char *src;
    size_t      len;
    size_t      pos;
} xml_parser_t;

static void            parser_skip_ws(xml_parser_t *p);
static int             parser_eof(const xml_parser_t *p);
static char            parser_peek(const xml_parser_t *p);
static char            parser_advance(xml_parser_t *p);
static int             parser_match(xml_parser_t *p, const char *str);
static char           *parser_read_name(xml_parser_t *p);
static char           *parser_read_attr_value(xml_parser_t *p);
static char           *parser_read_text(xml_parser_t *p);
static npe_error_t     parser_parse_node(xml_parser_t *p,
                                         npe_xml_node_t **out);
static npe_error_t     parser_parse_prolog(xml_parser_t *p);

/* Serializer helpers */
static npe_error_t     xml_stringify_node(const npe_xml_node_t *node,
                                          char **buf,
                                          size_t *buf_len,
                                          size_t *buf_cap,
                                          int depth);
static npe_error_t     buf_append(char **buf, size_t *len, size_t *cap,
                                  const char *data, size_t data_len);
static npe_error_t     buf_appendf(char **buf, size_t *len, size_t *cap,
                                   const char *fmt, ...);

/* XPath helpers */
static void            xpath_collect(npe_xml_node_t *node,
                                     const char *segment,
                                     npe_xml_node_t ***results,
                                     size_t *count,
                                     size_t *cap);

/* Lua binding helpers */
static int             l_xml_parse(lua_State *L);
static int             l_xml_stringify(lua_State *L);
static int             l_xml_find(lua_State *L);
static int             l_xml_attr(lua_State *L);
static int             l_xml_doc_gc(lua_State *L);
static int             l_xml_node_gc(lua_State *L);

#define XML_DOC_META  "npe.xml.doc"
#define XML_NODE_META "npe.xml.node"

/* ========================================================================= */
/*  Node allocation / deallocation                                           */
/* ========================================================================= */

static npe_xml_node_t *xml_node_new(const char *name)
{
    npe_xml_node_t *node = calloc(1, sizeof(*node));
    if (!node) return NULL;

    if (name) {
        node->name = strdup(name);
        if (!node->name) {
            free(node);
            return NULL;
        }
    }
    return node;
}

static void xml_node_free(npe_xml_node_t *node)
{
    if (!node) return;

    free(node->name);
    free(node->text);

    for (size_t i = 0; i < node->attr_count; i++) {
        free(node->attributes[i].name);
        free(node->attributes[i].value);
    }
    free(node->attributes);

    for (size_t i = 0; i < node->child_count; i++) {
        xml_node_free(node->children[i]);
    }
    free(node->children);

    free(node);
}

static npe_error_t xml_node_add_child(npe_xml_node_t *parent,
                                      npe_xml_node_t *child)
{
    size_t new_cap = parent->child_count + 1;
    npe_xml_node_t **tmp = realloc(parent->children,
                                   new_cap * sizeof(*tmp));
    if (!tmp) return NPE_ERROR_MEMORY;

    parent->children = tmp;
    parent->children[parent->child_count++] = child;
    child->parent = parent;
    return NPE_OK;
}

static npe_error_t xml_node_add_attr(npe_xml_node_t *node,
                                     const char *name,
                                     const char *value)
{
    size_t new_cap = node->attr_count + 1;
    npe_xml_attr_t *tmp = realloc(node->attributes,
                                  new_cap * sizeof(*tmp));
    if (!tmp) return NPE_ERROR_MEMORY;

    node->attributes = tmp;
    npe_xml_attr_t *a = &node->attributes[node->attr_count++];
    a->name  = strdup(name  ? name  : "");
    a->value = strdup(value ? value : "");
    if (!a->name || !a->value) return NPE_ERROR_MEMORY;

    return NPE_OK;
}

/* ========================================================================= */
/*  Low-level parser primitives                                              */
/* ========================================================================= */

static void parser_skip_ws(xml_parser_t *p)
{
    while (p->pos < p->len && isspace((unsigned char)p->src[p->pos]))
        p->pos++;
}

static int parser_eof(const xml_parser_t *p)
{
    return p->pos >= p->len;
}

static char parser_peek(const xml_parser_t *p)
{
    if (p->pos >= p->len) return '\0';
    return p->src[p->pos];
}

static char parser_advance(xml_parser_t *p)
{
    if (p->pos >= p->len) return '\0';
    return p->src[p->pos++];
}

static int parser_match(xml_parser_t *p, const char *str)
{
    size_t slen = strlen(str);
    if (p->pos + slen > p->len) return 0;
    if (memcmp(p->src + p->pos, str, slen) != 0) return 0;
    p->pos += slen;
    return 1;
}

/* Read an XML name token (tag name, attribute name).
 * Returns a heap-allocated string or NULL on failure. */
static char *parser_read_name(xml_parser_t *p)
{
    size_t start = p->pos;

    /* First char: letter, underscore, or colon */
    if (parser_eof(p)) return NULL;
    char c = parser_peek(p);
    if (!isalpha((unsigned char)c) && c != '_' && c != ':') return NULL;
    parser_advance(p);

    /* Subsequent: letter, digit, underscore, colon, hyphen, dot */
    while (!parser_eof(p)) {
        c = parser_peek(p);
        if (isalnum((unsigned char)c) || c == '_' || c == ':' ||
            c == '-' || c == '.') {
            parser_advance(p);
        } else {
            break;
        }
    }

    size_t name_len = p->pos - start;
    if (name_len == 0) return NULL;

    char *name = malloc(name_len + 1);
    if (!name) return NULL;
    memcpy(name, p->src + start, name_len);
    name[name_len] = '\0';
    return name;
}

/* Read a quoted attribute value (handles both ' and "). */
static char *parser_read_attr_value(xml_parser_t *p)
{
    parser_skip_ws(p);
    if (parser_eof(p)) return NULL;

    char quote = parser_peek(p);
    if (quote != '"' && quote != '\'') return NULL;
    parser_advance(p); /* consume opening quote */

    size_t start = p->pos;
    while (!parser_eof(p) && parser_peek(p) != quote)
        parser_advance(p);

    size_t val_len = p->pos - start;
    if (parser_eof(p)) return NULL; /* unterminated */
    parser_advance(p); /* consume closing quote */

    char *val = malloc(val_len + 1);
    if (!val) return NULL;
    memcpy(val, p->src + start, val_len);
    val[val_len] = '\0';

    return val;
}

/* Read text content between tags (stops at '<'). */
static char *parser_read_text(xml_parser_t *p)
{
    size_t start = p->pos;
    while (!parser_eof(p) && parser_peek(p) != '<')
        parser_advance(p);

    size_t text_len = p->pos - start;
    if (text_len == 0) return NULL;

    char *text = malloc(text_len + 1);
    if (!text) return NULL;
    memcpy(text, p->src + start, text_len);
    text[text_len] = '\0';

    /* Trim leading/trailing whitespace */
    size_t lo = 0, hi = text_len;
    while (lo < hi && isspace((unsigned char)text[lo])) lo++;
    while (hi > lo && isspace((unsigned char)text[hi - 1])) hi--;

    if (lo == hi) {
        free(text);
        return NULL;
    }

    if (lo > 0 || hi < text_len) {
        size_t trimmed_len = hi - lo;
        memmove(text, text + lo, trimmed_len);
        text[trimmed_len] = '\0';
    }

    return text;
}

/* ========================================================================= */
/*  XML prolog / comment / CDATA skipping                                    */
/* ========================================================================= */

static npe_error_t parser_parse_prolog(xml_parser_t *p)
{
    parser_skip_ws(p);

    /* Skip <?xml ... ?> processing instructions */
    while (!parser_eof(p) && p->pos + 1 < p->len &&
           p->src[p->pos] == '<' && p->src[p->pos + 1] == '?') {
        p->pos += 2;
        while (!parser_eof(p)) {
            if (p->pos + 1 < p->len &&
                p->src[p->pos] == '?' && p->src[p->pos + 1] == '>') {
                p->pos += 2;
                break;
            }
            p->pos++;
        }
        parser_skip_ws(p);
    }

    /* Skip <!-- comments --> */
    while (!parser_eof(p) && p->pos + 3 < p->len &&
           memcmp(p->src + p->pos, "<!--", 4) == 0) {
        p->pos += 4;
        while (!parser_eof(p)) {
            if (p->pos + 2 < p->len &&
                memcmp(p->src + p->pos, "-->", 3) == 0) {
                p->pos += 3;
                break;
            }
            p->pos++;
        }
        parser_skip_ws(p);
    }

    /* Skip <!DOCTYPE ...> */
    while (!parser_eof(p) && p->pos + 8 < p->len &&
           memcmp(p->src + p->pos, "<!DOCTYPE", 9) == 0) {
        p->pos += 9;
        int depth = 1;
        while (!parser_eof(p) && depth > 0) {
            char c = parser_advance(p);
            if (c == '<') depth++;
            else if (c == '>') depth--;
        }
        parser_skip_ws(p);
    }

    return NPE_OK;
}

/* Skip a comment at current position if present. Returns 1 if skipped. */
static int parser_skip_comment(xml_parser_t *p)
{
    if (p->pos + 3 < p->len && memcmp(p->src + p->pos, "<!--", 4) == 0) {
        p->pos += 4;
        while (!parser_eof(p)) {
            if (p->pos + 2 < p->len &&
                memcmp(p->src + p->pos, "-->", 3) == 0) {
                p->pos += 3;
                return 1;
            }
            p->pos++;
        }
        return 1; /* unterminated comment, still consumed */
    }
    return 0;
}

/* ========================================================================= */
/*  Recursive descent XML element parser                                     */
/* ========================================================================= */

static npe_error_t parser_parse_node(xml_parser_t *p, npe_xml_node_t **out)
{
    parser_skip_ws(p);

    /* Skip comments */
    while (parser_skip_comment(p))
        parser_skip_ws(p);

    if (parser_eof(p) || parser_peek(p) != '<')
        return NPE_ERROR_PARSE;

    parser_advance(p); /* consume '<' */

    /* Check for closing tag (shouldn't happen here) */
    if (parser_peek(p) == '/')
        return NPE_ERROR_PARSE;

    /* Read tag name */
    char *tag_name = parser_read_name(p);
    if (!tag_name) return NPE_ERROR_PARSE;

    npe_xml_node_t *node = xml_node_new(tag_name);
    free(tag_name);
    if (!node) return NPE_ERROR_MEMORY;

    /* Parse attributes */
    for (;;) {
        parser_skip_ws(p);
        if (parser_eof(p)) {
            xml_node_free(node);
            return NPE_ERROR_PARSE;
        }

        char c = parser_peek(p);

        /* Self-closing tag: /> */
        if (c == '/') {
            parser_advance(p);
            if (parser_eof(p) || parser_peek(p) != '>') {
                xml_node_free(node);
                return NPE_ERROR_PARSE;
            }
            parser_advance(p); /* consume '>' */
            *out = node;
            return NPE_OK;
        }

        /* End of opening tag */
        if (c == '>') {
            parser_advance(p);
            break;
        }

        /* Attribute name */
        char *attr_name = parser_read_name(p);
        if (!attr_name) {
            xml_node_free(node);
            return NPE_ERROR_PARSE;
        }

        parser_skip_ws(p);
        if (parser_eof(p) || parser_peek(p) != '=') {
            /* Attribute without value (HTML-style) — treat as empty */
            npe_error_t err = xml_node_add_attr(node, attr_name, "");
            free(attr_name);
            if (err != NPE_OK) {
                xml_node_free(node);
                return err;
            }
            continue;
        }
        parser_advance(p); /* consume '=' */

        char *attr_val = parser_read_attr_value(p);
        if (!attr_val) {
            free(attr_name);
            xml_node_free(node);
            return NPE_ERROR_PARSE;
        }

        npe_error_t err = xml_node_add_attr(node, attr_name, attr_val);
        free(attr_name);
        free(attr_val);
        if (err != NPE_OK) {
            xml_node_free(node);
            return err;
        }
    }

    /* Parse children and text content */
    for (;;) {
        /* Read any text before the next tag */
        char *text = parser_read_text(p);
        if (text) {
            if (!node->text) {
                node->text = text;
            } else {
                /* Append text (mixed content) */
                size_t old_len = strlen(node->text);
                size_t new_len = strlen(text);
                char *merged = realloc(node->text, old_len + new_len + 2);
                if (!merged) {
                    free(text);
                    xml_node_free(node);
                    return NPE_ERROR_MEMORY;
                }
                merged[old_len] = ' ';
                memcpy(merged + old_len + 1, text, new_len + 1);
                node->text = merged;
                free(text);
            }
        }

        parser_skip_ws(p);
        if (parser_eof(p)) {
            xml_node_free(node);
            return NPE_ERROR_PARSE;
        }

        /* Skip comments in body */
        if (parser_skip_comment(p)) continue;

        if (parser_peek(p) != '<') {
            /* More text content */
            continue;
        }

        /* Check for closing tag </name> */
        if (p->pos + 1 < p->len && p->src[p->pos + 1] == '/') {
            parser_advance(p); /* '<' */
            parser_advance(p); /* '/' */

            char *close_name = parser_read_name(p);
            if (!close_name || strcmp(close_name, node->name) != 0) {
                free(close_name);
                xml_node_free(node);
                return NPE_ERROR_PARSE;
            }
            free(close_name);

            parser_skip_ws(p);
            if (parser_eof(p) || parser_peek(p) != '>') {
                xml_node_free(node);
                return NPE_ERROR_PARSE;
            }
            parser_advance(p); /* consume '>' */
            break;
        }

        /* Child element */
        npe_xml_node_t *child = NULL;
        npe_error_t err = parser_parse_node(p, &child);
        if (err != NPE_OK) {
            xml_node_free(node);
            return err;
        }

        err = xml_node_add_child(node, child);
        if (err != NPE_OK) {
            xml_node_free(child);
            xml_node_free(node);
            return err;
        }
    }

    *out = node;
    return NPE_OK;
}

/* ========================================================================= */
/*  Public API: npe_xml_parse                                                */
/* ========================================================================= */

npe_error_t npe_xml_parse(const char *input, size_t length,
                          npe_xml_doc_t **doc)
{
    if (!input || !doc) return NPE_ERR_INVALID;

    xml_parser_t parser;
    parser.src = input;
    parser.len = (length > 0) ? length : strlen(input);
    parser.pos = 0;

    npe_error_t err = parser_parse_prolog(&parser);
    if (err != NPE_OK) return err;

    npe_xml_node_t *root = NULL;
    err = parser_parse_node(&parser, &root);
    if (err != NPE_OK) return err;

    npe_xml_doc_t *d = calloc(1, sizeof(*d));
    if (!d) {
        xml_node_free(root);
        return NPE_ERROR_MEMORY;
    }
    d->root = root;
    *doc = d;

    return NPE_OK;
}

/* ========================================================================= */
/*  Dynamic buffer helpers for serialization                                 */
/* ========================================================================= */

static npe_error_t buf_append(char **buf, size_t *len, size_t *cap,
                              const char *data, size_t data_len)
{
    while (*len + data_len + 1 > *cap) {
        size_t new_cap = (*cap == 0) ? 256 : (*cap * 2);
        char *tmp = realloc(*buf, new_cap);
        if (!tmp) return NPE_ERROR_MEMORY;
        *buf = tmp;
        *cap = new_cap;
    }
    memcpy(*buf + *len, data, data_len);
    *len += data_len;
    (*buf)[*len] = '\0';
    return NPE_OK;
}

static npe_error_t buf_appendf(char **buf, size_t *len, size_t *cap,
                               const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n < 0) return NPE_ERROR_GENERIC;
    if ((size_t)n >= sizeof(tmp)) {
        /* Large format — allocate dynamically */
        size_t needed = (size_t)n + 1;
        char *big = malloc(needed);
        if (!big) return NPE_ERROR_MEMORY;
        va_start(ap, fmt);
        vsnprintf(big, needed, fmt, ap);
        va_end(ap);
        npe_error_t err = buf_append(buf, len, cap, big, (size_t)n);
        free(big);
        return err;
    }

    return buf_append(buf, len, cap, tmp, (size_t)n);
}

/* ========================================================================= */
/*  Serializer: node -> XML string                                           */
/* ========================================================================= */

/* Escape special XML characters in text/attribute values */
static npe_error_t xml_escape(char **buf, size_t *len, size_t *cap,
                              const char *str)
{
    if (!str) return NPE_OK;

    for (const char *s = str; *s; s++) {
        npe_error_t err;
        switch (*s) {
            case '&':  err = buf_append(buf, len, cap, "&amp;",  5); break;
            case '<':  err = buf_append(buf, len, cap, "&lt;",   4); break;
            case '>':  err = buf_append(buf, len, cap, "&gt;",   4); break;
            case '"':  err = buf_append(buf, len, cap, "&quot;", 6); break;
            case '\'': err = buf_append(buf, len, cap, "&apos;", 6); break;
            default:   err = buf_append(buf, len, cap, s, 1);       break;
        }
        if (err != NPE_OK) return err;
    }
    return NPE_OK;
}

static npe_error_t xml_stringify_node(const npe_xml_node_t *node,
                                      char **buf, size_t *buf_len,
                                      size_t *buf_cap, int depth)
{
    npe_error_t err;

    if (!node || !node->name) return NPE_ERR_INVALID;

    /* Indentation */
    for (int i = 0; i < depth; i++) {
        err = buf_append(buf, buf_len, buf_cap, "  ", 2);
        if (err != NPE_OK) return err;
    }

    /* Opening tag */
    err = buf_appendf(buf, buf_len, buf_cap, "<%s", node->name);
    if (err != NPE_OK) return err;

    /* Attributes */
    for (size_t i = 0; i < node->attr_count; i++) {
        err = buf_appendf(buf, buf_len, buf_cap, " %s=\"",
                          node->attributes[i].name);
        if (err != NPE_OK) return err;

        err = xml_escape(buf, buf_len, buf_cap,
                         node->attributes[i].value);
        if (err != NPE_OK) return err;

        err = buf_append(buf, buf_len, buf_cap, "\"", 1);
        if (err != NPE_OK) return err;
    }

    /* Self-closing if no children and no text */
    if (node->child_count == 0 && !node->text) {
        err = buf_append(buf, buf_len, buf_cap, "/>\n", 3);
        return err;
    }

    err = buf_append(buf, buf_len, buf_cap, ">", 1);
    if (err != NPE_OK) return err;

    /* Text-only node (no children): inline text */
    if (node->child_count == 0 && node->text) {
        err = xml_escape(buf, buf_len, buf_cap, node->text);
        if (err != NPE_OK) return err;

        err = buf_appendf(buf, buf_len, buf_cap, "</%s>\n", node->name);
        return err;
    }

    /* Has children */
    err = buf_append(buf, buf_len, buf_cap, "\n", 1);
    if (err != NPE_OK) return err;

    /* Text before children (mixed content) */
    if (node->text) {
        for (int i = 0; i < depth + 1; i++) {
            err = buf_append(buf, buf_len, buf_cap, "  ", 2);
            if (err != NPE_OK) return err;
        }
        err = xml_escape(buf, buf_len, buf_cap, node->text);
        if (err != NPE_OK) return err;
        err = buf_append(buf, buf_len, buf_cap, "\n", 1);
        if (err != NPE_OK) return err;
    }

    for (size_t i = 0; i < node->child_count; i++) {
        err = xml_stringify_node(node->children[i], buf, buf_len,
                                 buf_cap, depth + 1);
        if (err != NPE_OK) return err;
    }

    /* Closing tag with indentation */
    for (int i = 0; i < depth; i++) {
        err = buf_append(buf, buf_len, buf_cap, "  ", 2);
        if (err != NPE_OK) return err;
    }
    err = buf_appendf(buf, buf_len, buf_cap, "</%s>\n", node->name);
    return err;
}

/* ========================================================================= */
/*  Public API: npe_xml_stringify                                            */
/* ========================================================================= */

npe_error_t npe_xml_stringify(const npe_xml_doc_t *doc,
                              char **out, size_t *len)
{
    if (!doc || !doc->root || !out) return NPE_ERR_INVALID;

    char  *buf     = NULL;
    size_t buf_len = 0;
    size_t buf_cap = 0;

    /* XML declaration */
    npe_error_t err = buf_append(&buf, &buf_len, &buf_cap,
                                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                                 39);
    if (err != NPE_OK) {
        free(buf);
        return err;
    }

    err = xml_stringify_node(doc->root, &buf, &buf_len, &buf_cap, 0);
    if (err != NPE_OK) {
        free(buf);
        return err;
    }

    *out = buf;
    if (len) *len = buf_len;
    return NPE_OK;
}

/* ========================================================================= */
/*  Public API: npe_xml_find (simplified XPath)                              */
/*                                                                           */
/*  Supports paths like:                                                     */
/*    "root/child/grandchild"   — absolute path from node                    */
/*    "//tagname"               — recursive descendant search                */
/*    "*"                       — wildcard (all children)                     */
/* ========================================================================= */

static void xpath_collect(npe_xml_node_t *node, const char *segment,
                          npe_xml_node_t ***results, size_t *count,
                          size_t *cap)
{
    if (!node) return;

    int match = 0;
    if (strcmp(segment, "*") == 0) {
        match = 1;
    } else if (node->name && strcmp(node->name, segment) == 0) {
        match = 1;
    }

    if (match) {
        if (*count >= *cap) {
            size_t new_cap = (*cap == 0) ? 8 : (*cap * 2);
            npe_xml_node_t **tmp = realloc(*results,
                                           new_cap * sizeof(**results));
            if (!tmp) return; /* silently fail on OOM */
            *results = tmp;
            *cap = new_cap;
        }
        (*results)[(*count)++] = node;
    }
}

static void xpath_recursive(npe_xml_node_t *node, const char *segment,
                             npe_xml_node_t ***results, size_t *count,
                             size_t *cap)
{
    xpath_collect(node, segment, results, count, cap);
    for (size_t i = 0; i < node->child_count; i++) {
        xpath_recursive(node->children[i], segment, results, count, cap);
    }
}

npe_error_t npe_xml_find(npe_xml_node_t *node, const char *path,
                         npe_xml_node_t ***results, size_t *count)
{
    if (!node || !path || !results || !count)
        return NPE_ERR_INVALID;

    *results = NULL;
    *count   = 0;
    size_t cap = 0;

    /* Handle "//" prefix — recursive descendant search */
    if (path[0] == '/' && path[1] == '/') {
        const char *segment = path + 2;
        xpath_recursive(node, segment, results, count, &cap);
        return NPE_OK;
    }

    /* Tokenize path by '/' and walk the tree */
    char *path_copy = strdup(path);
    if (!path_copy) return NPE_ERROR_MEMORY;

    /* Collect starting set: just the root node passed in */
    npe_xml_node_t **current_set = NULL;
    size_t current_count = 0;
    size_t current_cap   = 0;

    /* If path starts with the node's own name, consume it */
    char *saveptr = NULL;
    char *token = strtok_r(path_copy, "/", &saveptr);

    if (!token) {
        free(path_copy);
        return NPE_OK;
    }

    /* Check if the first segment matches the node itself */
    if (node->name && strcmp(node->name, token) == 0) {
        /* Start from this node, advance to next segment */
        current_set = malloc(sizeof(*current_set));
        if (!current_set) {
            free(path_copy);
            return NPE_ERROR_MEMORY;
        }
        current_set[0] = node;
        current_count = 1;
        current_cap   = 1;

        token = strtok_r(NULL, "/", &saveptr);
    } else {
        /* First segment doesn't match node — search children */
        current_set = malloc(sizeof(*current_set));
        if (!current_set) {
            free(path_copy);
            return NPE_ERROR_MEMORY;
        }
        current_set[0] = node;
        current_count = 1;
        current_cap   = 1;
    }

    /* Walk each path segment */
    while (token) {
        npe_xml_node_t **next_set = NULL;
        size_t next_count = 0;
        size_t next_cap   = 0;

        for (size_t i = 0; i < current_count; i++) {
            npe_xml_node_t *cur = current_set[i];
            for (size_t j = 0; j < cur->child_count; j++) {
                xpath_collect(cur->children[j], token,
                              &next_set, &next_count, &next_cap);
            }
        }

        free(current_set);
        current_set   = next_set;
        current_count = next_count;
        current_cap   = next_cap;

        token = strtok_r(NULL, "/", &saveptr);
    }

    free(path_copy);

    *results = current_set;
    *count   = current_count;
    return NPE_OK;
}

/* ========================================================================= */
/*  Public API: npe_xml_attr                                                 */
/* ========================================================================= */

const char *npe_xml_attr(npe_xml_node_t *node, const char *name)
{
    if (!node || !name) return NULL;

    for (size_t i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attributes[i].name, name) == 0)
            return node->attributes[i].value;
    }
    return NULL;
}

/* ========================================================================= */
/*  Public API: npe_xml_free                                                 */
/* ========================================================================= */

void npe_xml_free(npe_xml_doc_t *doc)
{
    if (!doc) return;
    xml_node_free(doc->root);
    free(doc);
}

/* ========================================================================= */
/*  Lua bindings                                                             */
/* ========================================================================= */

/* Push an npe_xml_node_t* as a full userdata with metatable */
static void l_push_xml_node(lua_State *L, npe_xml_node_t *node)
{
    npe_xml_node_t **udata = (npe_xml_node_t **)lua_newuserdata(
        L, sizeof(npe_xml_node_t *));
    *udata = node;
    luaL_getmetatable(L, XML_NODE_META);
    lua_setmetatable(L, -2);
}

/* Push an npe_xml_doc_t* as a full userdata with metatable */
static void l_push_xml_doc(lua_State *L, npe_xml_doc_t *doc)
{
    npe_xml_doc_t **udata = (npe_xml_doc_t **)lua_newuserdata(
        L, sizeof(npe_xml_doc_t *));
    *udata = doc;
    luaL_getmetatable(L, XML_DOC_META);
    lua_setmetatable(L, -2);
}

/* ---- npe.xml.parse(xml_string) -> doc userdata ---- */
static int l_xml_parse(lua_State *L)
{
    size_t len = 0;
    const char *input = luaL_checklstring(L, 1, &len);

    npe_xml_doc_t *doc = NULL;
    npe_error_t err = npe_xml_parse(input, len, &doc);
    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "XML parse error");
        return 2;
    }

    l_push_xml_doc(L, doc);
    return 1;
}

/* ---- npe.xml.stringify(doc) -> string ---- */
static int l_xml_stringify(lua_State *L)
{
    npe_xml_doc_t **udata = (npe_xml_doc_t **)luaL_checkudata(
        L, 1, XML_DOC_META);
    if (!udata || !*udata) {
        lua_pushnil(L);
        lua_pushstring(L, "invalid XML document");
        return 2;
    }

    char  *out = NULL;
    size_t out_len = 0;
    npe_error_t err = npe_xml_stringify(*udata, &out, &out_len);
    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "XML stringify error");
        return 2;
    }

    lua_pushlstring(L, out, out_len);
    free(out);
    return 1;
}

/* ---- npe.xml.find(doc_or_node, xpath) -> table of node userdata ---- */
static int l_xml_find(lua_State *L)
{
    npe_xml_node_t *start = NULL;

    /* Accept either a doc or a node as the first argument */
    if (luaL_testudata(L, 1, XML_DOC_META)) {
        npe_xml_doc_t **doc_ud = (npe_xml_doc_t **)lua_touserdata(L, 1);
        if (doc_ud && *doc_ud) start = (*doc_ud)->root;
    } else if (luaL_testudata(L, 1, XML_NODE_META)) {
        npe_xml_node_t **node_ud = (npe_xml_node_t **)lua_touserdata(L, 1);
        if (node_ud) start = *node_ud;
    }

    if (!start) {
        lua_pushnil(L);
        lua_pushstring(L, "expected XML doc or node as first argument");
        return 2;
    }

    const char *path = luaL_checkstring(L, 2);

    npe_xml_node_t **found = NULL;
    size_t found_count = 0;
    npe_error_t err = npe_xml_find(start, path, &found, &found_count);
    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "XPath search error");
        return 2;
    }

    /* Return as a Lua table of node userdata */
    lua_createtable(L, (int)found_count, 0);
    for (size_t i = 0; i < found_count; i++) {
        l_push_xml_node(L, found[i]);
        lua_rawseti(L, -2, (int)(i + 1));
    }

    free(found);
    return 1;
}

/* ---- npe.xml.attr(node, name) -> string or nil ---- */
static int l_xml_attr(lua_State *L)
{
    npe_xml_node_t **udata = (npe_xml_node_t **)luaL_checkudata(
        L, 1, XML_NODE_META);
    if (!udata || !*udata) {
        lua_pushnil(L);
        return 1;
    }

    const char *name = luaL_checkstring(L, 2);
    const char *val  = npe_xml_attr(*udata, name);

    if (val) {
        lua_pushstring(L, val);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/* ---- __gc for doc userdata ---- */
static int l_xml_doc_gc(lua_State *L)
{
    npe_xml_doc_t **udata = (npe_xml_doc_t **)luaL_checkudata(
        L, 1, XML_DOC_META);
    if (udata && *udata) {
        npe_xml_free(*udata);
        *udata = NULL;
    }
    return 0;
}

/* ---- __gc for node userdata (nodes are owned by the doc, no-op) ---- */
static int l_xml_node_gc(lua_State *L)
{
    (void)L;
    /* Nodes are freed when the parent document is collected.
     * This is intentionally a no-op. */
    return 0;
}

/* ---- __index for node: allow node.name, node.text, node.children ---- */
static int l_xml_node_index(lua_State *L)
{
    npe_xml_node_t **udata = (npe_xml_node_t **)luaL_checkudata(
        L, 1, XML_NODE_META);
    if (!udata || !*udata) {
        lua_pushnil(L);
        return 1;
    }

    npe_xml_node_t *node = *udata;
    const char *key = luaL_checkstring(L, 2);

    if (strcmp(key, "name") == 0) {
        lua_pushstring(L, node->name ? node->name : "");
        return 1;
    }

    if (strcmp(key, "text") == 0) {
        if (node->text) {
            lua_pushstring(L, node->text);
        } else {
            lua_pushnil(L);
        }
        return 1;
    }

    if (strcmp(key, "children") == 0) {
        lua_createtable(L, (int)node->child_count, 0);
        for (size_t i = 0; i < node->child_count; i++) {
            l_push_xml_node(L, node->children[i]);
            lua_rawseti(L, -2, (int)(i + 1));
        }
        return 1;
    }

    if (strcmp(key, "parent") == 0) {
        if (node->parent) {
            l_push_xml_node(L, node->parent);
        } else {
            lua_pushnil(L);
        }
        return 1;
    }

    if (strcmp(key, "attr_count") == 0) {
        lua_pushinteger(L, (lua_Integer)node->attr_count);
        return 1;
    }

    if (strcmp(key, "child_count") == 0) {
        lua_pushinteger(L, (lua_Integer)node->child_count);
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

/* ---- __index for doc: allow doc.root ---- */
static int l_xml_doc_index(lua_State *L)
{
    npe_xml_doc_t **udata = (npe_xml_doc_t **)luaL_checkudata(
        L, 1, XML_DOC_META);
    if (!udata || !*udata) {
        lua_pushnil(L);
        return 1;
    }

    const char *key = luaL_checkstring(L, 2);

    if (strcmp(key, "root") == 0) {
        if ((*udata)->root) {
            l_push_xml_node(L, (*udata)->root);
        } else {
            lua_pushnil(L);
        }
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

/* ---- __tostring for node ---- */
static int l_xml_node_tostring(lua_State *L)
{
    npe_xml_node_t **udata = (npe_xml_node_t **)luaL_checkudata(
        L, 1, XML_NODE_META);
    if (!udata || !*udata || !(*udata)->name) {
        lua_pushstring(L, "xml.node(nil)");
        return 1;
    }
    lua_pushfstring(L, "xml.node(%s)", (*udata)->name);
    return 1;
}

/* ---- __tostring for doc ---- */
static int l_xml_doc_tostring(lua_State *L)
{
    npe_xml_doc_t **udata = (npe_xml_doc_t **)luaL_checkudata(
        L, 1, XML_DOC_META);
    if (!udata || !*udata || !(*udata)->root) {
        lua_pushstring(L, "xml.doc(empty)");
        return 1;
    }
    lua_pushfstring(L, "xml.doc(root=%s)",
                    (*udata)->root->name ? (*udata)->root->name : "?");
    return 1;
}

/* ========================================================================= */
/*  Lua registration table                                                   */
/* ========================================================================= */

static const luaL_Reg xml_funcs[] = {
    { "parse",     l_xml_parse     },
    { "stringify", l_xml_stringify  },
    { "find",      l_xml_find      },
    { "attr",      l_xml_attr      },
    { NULL,        NULL             }
};

npe_error_t npe_lib_xml_register(npe_vm_t *vm)
{
    if (!vm) return NPE_ERR_INVALID;

    lua_State *L = npe_vm_get_lua(vm);
    if (!L) return NPE_ERROR_GENERIC;

    /* Create doc metatable */
    luaL_newmetatable(L, XML_DOC_META);
    lua_pushcfunction(L, l_xml_doc_gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, l_xml_doc_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_xml_doc_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pop(L, 1);

    /* Create node metatable */
    luaL_newmetatable(L, XML_NODE_META);
    lua_pushcfunction(L, l_xml_node_gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, l_xml_node_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_xml_node_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pop(L, 1);

    /* Register npe.xml table */
    luaL_newlib(L, xml_funcs);

    /* Place it at npe.xml — assumes "npe" table is at global scope */
    lua_getglobal(L, "npe");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setglobal(L, "npe");
    }
    lua_pushvalue(L, -2);   /* push the xml_funcs table */
    lua_setfield(L, -2, "xml");
    lua_pop(L, 2);          /* pop npe table and xml_funcs table */

    return NPE_OK;
}
