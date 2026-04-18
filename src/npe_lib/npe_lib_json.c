/*****************************************************************************
 * npe_lib_json.c — JSON encoding/decoding library implementation
 *
 * Hand-rolled recursive-descent JSON parser and generator.
 * No external dependencies beyond libc.
 *****************************************************************************/

#include "npe_lib_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <float.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL PARSER STATE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *input;
    size_t      length;
    size_t      pos;
    int         depth;
    char        error[256];
} json_parser_t;

#define JSON_MAX_DEPTH 512

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL STRING BUILDER
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} json_buf_t;

static void json_buf_init(json_buf_t *b)
{
    b->cap = 256;
    b->len = 0;
    b->buf = (char *)malloc(b->cap);
    if (b->buf)
        b->buf[0] = '\0';
}

static void json_buf_ensure(json_buf_t *b, size_t extra)
{
    if (!b->buf) return;
    while (b->len + extra + 1 > b->cap) {
        b->cap *= 2;
        char *tmp = (char *)realloc(b->buf, b->cap);
        if (!tmp) { free(b->buf); b->buf = NULL; return; }
        b->buf = tmp;
    }
}

static void json_buf_append(json_buf_t *b, const char *s, size_t n)
{
    json_buf_ensure(b, n);
    if (!b->buf) return;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void json_buf_append_str(json_buf_t *b, const char *s)
{
    json_buf_append(b, s, strlen(s));
}

static void json_buf_append_char(json_buf_t *b, char c)
{
    json_buf_append(b, &c, 1);
}

static void json_buf_append_indent(json_buf_t *b, int level, int indent)
{
    if (indent <= 0) return;
    int total = level * indent;
    for (int i = 0; i < total; i++)
        json_buf_append_char(b, ' ');
}

static void json_buf_free(json_buf_t *b)
{
    free(b->buf);
    b->buf = NULL;
    b->len = 0;
    b->cap = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  VALUE ALLOCATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static npe_json_value_t *json_value_new(npe_json_type_t type)
{
    npe_json_value_t *v = (npe_json_value_t *)calloc(1, sizeof(*v));
    if (v) v->type = type;
    return v;
}

void npe_json_free(npe_json_value_t *value)
{
    if (!value) return;

    switch (value->type) {
    case NPE_JSON_STRING:
        free(value->string);
        break;

    case NPE_JSON_ARRAY:
        for (size_t i = 0; i < value->array.count; i++)
            npe_json_free(value->array.items[i]);
        free(value->array.items);
        break;

    case NPE_JSON_OBJECT:
        for (size_t i = 0; i < value->object.count; i++) {
            free(value->object.keys[i]);
            npe_json_free(value->object.values[i]);
        }
        free(value->object.keys);
        free(value->object.values);
        break;

    default:
        break;
    }

    free(value);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PARSER HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline char json_peek(json_parser_t *p)
{
    if (p->pos >= p->length) return '\0';
    return p->input[p->pos];
}

static inline char json_advance(json_parser_t *p)
{
    if (p->pos >= p->length) return '\0';
    return p->input[p->pos++];
}

static void json_skip_ws(json_parser_t *p)
{
    while (p->pos < p->length) {
        char c = p->input[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            p->pos++;
        else
            break;
    }
}

static bool json_expect(json_parser_t *p, const char *literal)
{
    size_t len = strlen(literal);
    if (p->pos + len > p->length)
        return false;
    if (memcmp(p->input + p->pos, literal, len) != 0)
        return false;
    p->pos += len;
    return true;
}

static void json_set_error(json_parser_t *p, const char *msg)
{
    snprintf(p->error, sizeof(p->error), "JSON parse error at position %zu: %s",
             p->pos, msg);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PARSE STRING
 * ═══════════════════════════════════════════════════════════════════════════ */

static int json_hex4(json_parser_t *p, uint16_t *out)
{
    *out = 0;
    for (int i = 0; i < 4; i++) {
        if (p->pos >= p->length) return -1;
        char c = json_advance(p);
        *out <<= 4;
        if (c >= '0' && c <= '9')      *out |= (uint16_t)(c - '0');
        else if (c >= 'a' && c <= 'f') *out |= (uint16_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') *out |= (uint16_t)(c - 'A' + 10);
        else return -1;
    }
    return 0;
}

/* Encode a Unicode codepoint as UTF-8 into buf, return bytes written */
static int json_utf8_encode(uint32_t cp, char *buf)
{
    if (cp < 0x80) {
        buf[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        buf[0] = (char)(0xC0 | (cp >> 6));
        buf[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        buf[0] = (char)(0xE0 | (cp >> 12));
        buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else if (cp < 0x110000) {
        buf[0] = (char)(0xF0 | (cp >> 18));
        buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0;
}

static char *json_parse_string_value(json_parser_t *p)
{
    if (json_advance(p) != '"') {
        json_set_error(p, "expected '\"'");
        return NULL;
    }

    json_buf_t sb;
    json_buf_init(&sb);

    while (p->pos < p->length) {
        char c = json_advance(p);

        if (c == '"') {
            char *result = sb.buf;
            /* don't free, caller owns it */
            return result;
        }

        if (c == '\\') {
            if (p->pos >= p->length) {
                json_set_error(p, "unexpected end in string escape");
                json_buf_free(&sb);
                return NULL;
            }
            char esc = json_advance(p);
            switch (esc) {
            case '"':  json_buf_append_char(&sb, '"');  break;
            case '\\': json_buf_append_char(&sb, '\\'); break;
            case '/':  json_buf_append_char(&sb, '/');  break;
            case 'b':  json_buf_append_char(&sb, '\b'); break;
            case 'f':  json_buf_append_char(&sb, '\f'); break;
            case 'n':  json_buf_append_char(&sb, '\n'); break;
            case 'r':  json_buf_append_char(&sb, '\r'); break;
            case 't':  json_buf_append_char(&sb, '\t'); break;
            case 'u': {
                uint16_t hi;
                if (json_hex4(p, &hi) < 0) {
                    json_set_error(p, "invalid \\uXXXX escape");
                    json_buf_free(&sb);
                    return NULL;
                }
                uint32_t cp = hi;
                /* Handle surrogate pairs */
                if (hi >= 0xD800 && hi <= 0xDBFF) {
                    if (p->pos + 1 < p->length &&
                        p->input[p->pos] == '\\' &&
                        p->input[p->pos + 1] == 'u') {
                        p->pos += 2; /* skip \u */
                        uint16_t lo;
                        if (json_hex4(p, &lo) < 0 || lo < 0xDC00 || lo > 0xDFFF) {
                            json_set_error(p, "invalid surrogate pair");
                            json_buf_free(&sb);
                            return NULL;
                        }
                        cp = 0x10000 + ((uint32_t)(hi - 0xD800) << 10) + (lo - 0xDC00);
                    } else {
                        json_set_error(p, "lone high surrogate");
                        json_buf_free(&sb);
                        return NULL;
                    }
                }
                char utf8[4];
                int n = json_utf8_encode(cp, utf8);
                json_buf_append(&sb, utf8, (size_t)n);
                break;
            }
            default:
                json_set_error(p, "invalid escape character");
                json_buf_free(&sb);
                return NULL;
            }
        } else if ((unsigned char)c < 0x20) {
            json_set_error(p, "control character in string");
            json_buf_free(&sb);
            return NULL;
        } else {
            json_buf_append_char(&sb, c);
        }
    }

    json_set_error(p, "unterminated string");
    json_buf_free(&sb);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PARSE NUMBER
 * ═══════════════════════════════════════════════════════════════════════════ */

static npe_json_value_t *json_parse_number(json_parser_t *p)
{
    size_t start = p->pos;

    if (json_peek(p) == '-') json_advance(p);

    if (json_peek(p) == '0') {
        json_advance(p);
    } else if (json_peek(p) >= '1' && json_peek(p) <= '9') {
        while (json_peek(p) >= '0' && json_peek(p) <= '9')
            json_advance(p);
    } else {
        json_set_error(p, "invalid number");
        return NULL;
    }

    if (json_peek(p) == '.') {
        json_advance(p);
        if (json_peek(p) < '0' || json_peek(p) > '9') {
            json_set_error(p, "expected digit after decimal point");
            return NULL;
        }
        while (json_peek(p) >= '0' && json_peek(p) <= '9')
            json_advance(p);
    }

    if (json_peek(p) == 'e' || json_peek(p) == 'E') {
        json_advance(p);
        if (json_peek(p) == '+' || json_peek(p) == '-')
            json_advance(p);
        if (json_peek(p) < '0' || json_peek(p) > '9') {
            json_set_error(p, "expected digit in exponent");
            return NULL;
        }
        while (json_peek(p) >= '0' && json_peek(p) <= '9')
            json_advance(p);
    }

    size_t num_len = p->pos - start;
    char *tmp = (char *)malloc(num_len + 1);
    if (!tmp) return NULL;
    memcpy(tmp, p->input + start, num_len);
    tmp[num_len] = '\0';

    char *endptr;
    double val = strtod(tmp, &endptr);
    free(tmp);

    if (endptr == tmp) {
        json_set_error(p, "invalid number format");
        return NULL;
    }

    npe_json_value_t *v = json_value_new(NPE_JSON_NUMBER);
    if (v) v->number = val;
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  RECURSIVE DESCENT PARSER
 * ═══════════════════════════════════════════════════════════════════════════ */

static npe_json_value_t *json_parse_value(json_parser_t *p);

static npe_json_value_t *json_parse_array(json_parser_t *p)
{
    json_advance(p); /* consume '[' */

    if (++p->depth > JSON_MAX_DEPTH) {
        json_set_error(p, "maximum nesting depth exceeded");
        return NULL;
    }

    npe_json_value_t *arr = json_value_new(NPE_JSON_ARRAY);
    if (!arr) return NULL;

    arr->array.items = NULL;
    arr->array.count = 0;
    size_t cap = 0;

    json_skip_ws(p);
    if (json_peek(p) == ']') {
        json_advance(p);
        p->depth--;
        return arr;
    }

    for (;;) {
        json_skip_ws(p);
        npe_json_value_t *item = json_parse_value(p);
        if (!item) {
            npe_json_free(arr);
            return NULL;
        }

        /* grow array */
        if (arr->array.count >= cap) {
            cap = cap == 0 ? 8 : cap * 2;
            npe_json_value_t **tmp = (npe_json_value_t **)realloc(
                arr->array.items, cap * sizeof(*tmp));
            if (!tmp) {
                npe_json_free(item);
                npe_json_free(arr);
                return NULL;
            }
            arr->array.items = tmp;
        }
        arr->array.items[arr->array.count++] = item;

        json_skip_ws(p);
        if (json_peek(p) == ',') {
            json_advance(p);
            continue;
        }
        if (json_peek(p) == ']') {
            json_advance(p);
            break;
        }

        json_set_error(p, "expected ',' or ']' in array");
        npe_json_free(arr);
        return NULL;
    }

    p->depth--;
    return arr;
}

static npe_json_value_t *json_parse_object(json_parser_t *p)
{
    json_advance(p); /* consume '{' */

    if (++p->depth > JSON_MAX_DEPTH) {
        json_set_error(p, "maximum nesting depth exceeded");
        return NULL;
    }

    npe_json_value_t *obj = json_value_new(NPE_JSON_OBJECT);
    if (!obj) return NULL;

    obj->object.keys   = NULL;
    obj->object.values = NULL;
    obj->object.count  = 0;
    size_t cap = 0;

    json_skip_ws(p);
    if (json_peek(p) == '}') {
        json_advance(p);
        p->depth--;
        return obj;
    }

    for (;;) {
        json_skip_ws(p);
        if (json_peek(p) != '"') {
            json_set_error(p, "expected string key in object");
            npe_json_free(obj);
            return NULL;
        }

        char *key = json_parse_string_value(p);
        if (!key) {
            npe_json_free(obj);
            return NULL;
        }

        json_skip_ws(p);
        if (json_advance(p) != ':') {
            json_set_error(p, "expected ':' after object key");
            free(key);
            npe_json_free(obj);
            return NULL;
        }

        json_skip_ws(p);
        npe_json_value_t *val = json_parse_value(p);
        if (!val) {
            free(key);
            npe_json_free(obj);
            return NULL;
        }

        /* grow object */
        if (obj->object.count >= cap) {
            cap = cap == 0 ? 8 : cap * 2;
            char **ktmp = (char **)realloc(obj->object.keys, cap * sizeof(char *));
            npe_json_value_t **vtmp = (npe_json_value_t **)realloc(
                obj->object.values, cap * sizeof(npe_json_value_t *));
            if (!ktmp || !vtmp) {
                free(key);
                npe_json_free(val);
                npe_json_free(obj);
                return NULL;
            }
            obj->object.keys   = ktmp;
            obj->object.values = vtmp;
        }
        obj->object.keys[obj->object.count]   = key;
        obj->object.values[obj->object.count]  = val;
        obj->object.count++;

        json_skip_ws(p);
        if (json_peek(p) == ',') {
            json_advance(p);
            continue;
        }
        if (json_peek(p) == '}') {
            json_advance(p);
            break;
        }

        json_set_error(p, "expected ',' or '}' in object");
        npe_json_free(obj);
        return NULL;
    }

    p->depth--;
    return obj;
}

static npe_json_value_t *json_parse_value(json_parser_t *p)
{
    json_skip_ws(p);

    char c = json_peek(p);

    switch (c) {
    case '"': {
        char *s = json_parse_string_value(p);
        if (!s) return NULL;
        npe_json_value_t *v = json_value_new(NPE_JSON_STRING);
        if (!v) { free(s); return NULL; }
        v->string = s;
        return v;
    }

    case '{':
        return json_parse_object(p);

    case '[':
        return json_parse_array(p);

    case 't':
        if (!json_expect(p, "true")) {
            json_set_error(p, "invalid literal (expected 'true')");
            return NULL;
        }
        {
            npe_json_value_t *v = json_value_new(NPE_JSON_BOOL);
            if (v) v->boolean = true;
            return v;
        }

    case 'f':
        if (!json_expect(p, "false")) {
            json_set_error(p, "invalid literal (expected 'false')");
            return NULL;
        }
        {
            npe_json_value_t *v = json_value_new(NPE_JSON_BOOL);
            if (v) v->boolean = false;
            return v;
        }

    case 'n':
        if (!json_expect(p, "null")) {
            json_set_error(p, "invalid literal (expected 'null')");
            return NULL;
        }
        return json_value_new(NPE_JSON_NULL);

    default:
        if (c == '-' || (c >= '0' && c <= '9'))
            return json_parse_number(p);

        json_set_error(p, "unexpected character");
        return NULL;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PUBLIC PARSE API
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t npe_json_parse(const char *input, size_t length, npe_json_value_t **out)
{
    if (!input || !out) return NPE_ERROR_INVALID_ARG;

    if (length == 0) length = strlen(input);

    json_parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.input  = input;
    parser.length = length;
    parser.pos    = 0;
    parser.depth  = 0;

    npe_json_value_t *val = json_parse_value(&parser);
    if (!val) return NPE_ERROR_PARSE;

    /* Ensure no trailing garbage (except whitespace) */
    json_skip_ws(&parser);
    if (parser.pos < parser.length) {
        npe_json_free(val);
        return NPE_ERROR_PARSE;
    }

    *out = val;
    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  STRINGIFY
 * ═══════════════════════════════════════════════════════════════════════════ */

static void json_stringify_string(json_buf_t *b, const char *s,
                                  bool escape_unicode)
{
    json_buf_append_char(b, '"');

    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"':  json_buf_append_str(b, "\\\""); break;
        case '\\': json_buf_append_str(b, "\\\\"); break;
        case '\b': json_buf_append_str(b, "\\b");  break;
        case '\f': json_buf_append_str(b, "\\f");  break;
        case '\n': json_buf_append_str(b, "\\n");  break;
        case '\r': json_buf_append_str(b, "\\r");  break;
        case '\t': json_buf_append_str(b, "\\t");  break;
        default:
            if (c < 0x20) {
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", c);
                json_buf_append_str(b, esc);
            } else if (escape_unicode && c > 0x7F) {
                /* Encode as \uXXXX */
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", c);
                json_buf_append_str(b, esc);
            } else {
                json_buf_append_char(b, (char)c);
            }
            break;
        }
    }

    json_buf_append_char(b, '"');
}

static void json_stringify_value(json_buf_t *b, const npe_json_value_t *v,
                                 const npe_json_encode_opts_t *opts,
                                 int depth)
{
    if (!v) {
        json_buf_append_str(b, "null");
        return;
    }

    bool pretty = opts && opts->pretty;
    int indent  = (opts && opts->indent > 0) ? opts->indent : 2;
    bool esc_u  = opts ? opts->escape_unicode : false;

    switch (v->type) {
    case NPE_JSON_NULL:
        json_buf_append_str(b, "null");
        break;

    case NPE_JSON_BOOL:
        json_buf_append_str(b, v->boolean ? "true" : "false");
        break;

    case NPE_JSON_NUMBER: {
        char num[64];
        if (v->number == (double)(long long)v->number &&
            fabs(v->number) < 1e15) {
            snprintf(num, sizeof(num), "%lld", (long long)v->number);
        } else {
            snprintf(num, sizeof(num), "%.17g", v->number);
        }
        json_buf_append_str(b, num);
        break;
    }

    case NPE_JSON_STRING:
        json_stringify_string(b, v->string ? v->string : "", esc_u);
        break;

    case NPE_JSON_ARRAY:
        json_buf_append_char(b, '[');
        for (size_t i = 0; i < v->array.count; i++) {
            if (i > 0) json_buf_append_char(b, ',');
            if (pretty) {
                json_buf_append_char(b, '\n');
                json_buf_append_indent(b, depth + 1, indent);
            }
            json_stringify_value(b, v->array.items[i], opts, depth + 1);
        }
        if (pretty && v->array.count > 0) {
            json_buf_append_char(b, '\n');
            json_buf_append_indent(b, depth, indent);
        }
        json_buf_append_char(b, ']');
        break;

    case NPE_JSON_OBJECT:
        json_buf_append_char(b, '{');
        for (size_t i = 0; i < v->object.count; i++) {
            if (i > 0) json_buf_append_char(b, ',');
            if (pretty) {
                json_buf_append_char(b, '\n');
                json_buf_append_indent(b, depth + 1, indent);
            }
            json_stringify_string(b, v->object.keys[i], esc_u);
            json_buf_append_char(b, ':');
            if (pretty) json_buf_append_char(b, ' ');
            json_stringify_value(b, v->object.values[i], opts, depth + 1);
        }
        if (pretty && v->object.count > 0) {
            json_buf_append_char(b, '\n');
            json_buf_append_indent(b, depth, indent);
        }
        json_buf_append_char(b, '}');
        break;
    }
}

npe_error_t npe_json_stringify(const npe_json_value_t *value,
                               const npe_json_encode_opts_t *opts,
                               char **out, size_t *out_len)
{
    if (!value || !out) return NPE_ERROR_INVALID_ARG;

    json_buf_t b;
    json_buf_init(&b);
    if (!b.buf) return NPE_ERROR_MEMORY;

    json_stringify_value(&b, value, opts, 0);

    if (!b.buf) return NPE_ERROR_MEMORY;

    *out = b.buf;
    if (out_len) *out_len = b.len;
    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  VALIDATION
 * ═══════════════════════════════════════════════════════════════════════════ */

bool npe_json_validate(const char *input, size_t length)
{
    npe_json_value_t *val = NULL;
    npe_error_t err = npe_json_parse(input, length, &val);
    if (err == NPE_OK) {
        npe_json_free(val);
        return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDINGS
 * ═══════════════════════════════════════════════════════════════════════════ */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Forward declarations */
static void json_push_value_to_lua(lua_State *L, const npe_json_value_t *v);
static npe_json_value_t *json_lua_to_value(lua_State *L, int idx, int depth);

static void json_push_value_to_lua(lua_State *L, const npe_json_value_t *v)
{
    if (!v) {
        lua_pushnil(L);
        return;
    }

    switch (v->type) {
    case NPE_JSON_NULL:
        lua_pushnil(L);
        break;

    case NPE_JSON_BOOL:
        lua_pushboolean(L, v->boolean ? 1 : 0);
        break;

    case NPE_JSON_NUMBER:
        lua_pushnumber(L, v->number);
        break;

    case NPE_JSON_STRING:
        lua_pushstring(L, v->string ? v->string : "");
        break;
    case NPE_JSON_ARRAY:
        lua_createtable(L, (int)v->array.count, 0);
        for (size_t i = 0; i < v->array.count; i++) {
            json_push_value_to_lua(L, v->array.items[i]);
            lua_rawseti(L, -2, (int)(i + 1));
        }
        break;

    case NPE_JSON_OBJECT:
        lua_createtable(L, 0, (int)v->object.count);
        for (size_t i = 0; i < v->object.count; i++) {
            lua_pushstring(L, v->object.keys[i]);
            json_push_value_to_lua(L, v->object.values[i]);
            lua_rawset(L, -3);
        }
        break;
    }
}

/* ── Lua table → npe_json_value_t ──────────────────────────────────────── */

static bool json_lua_is_array(lua_State *L, int idx)
{
    /* Heuristic: if the table has a positive integer key 1, treat as array.
     * Also check that #tbl > 0 or the table is empty. */
    idx = lua_absindex(L, idx);
    lua_rawgeti(L, idx, 1);
    bool has_one = !lua_isnil(L, -1);
    lua_pop(L, 1);

    if (!has_one) {
        /* Check if table is completely empty */
        lua_pushnil(L);
        if (lua_next(L, idx) == 0) {
            return true; /* empty table → treat as array */
        }
        lua_pop(L, 2);
        return false; /* has keys but no [1] → object */
    }
    return true;
}

static npe_json_value_t *json_lua_to_value(lua_State *L, int idx, int depth)
{
    if (depth > JSON_MAX_DEPTH) {
        luaL_error(L, "json.encode: maximum nesting depth exceeded");
        return NULL;
    }

    idx = lua_absindex(L, idx);
    int t = lua_type(L, idx);

    switch (t) {
    case LUA_TNIL:
    case LUA_TNONE:
        return json_value_new(NPE_JSON_NULL);

    case LUA_TBOOLEAN: {
        npe_json_value_t *v = json_value_new(NPE_JSON_BOOL);
        if (v) v->boolean = lua_toboolean(L, idx) ? true : false;
        return v;
    }

    case LUA_TNUMBER: {
        npe_json_value_t *v = json_value_new(NPE_JSON_NUMBER);
        if (v) v->number = lua_tonumber(L, idx);
        return v;
    }

    case LUA_TSTRING: {
        npe_json_value_t *v = json_value_new(NPE_JSON_STRING);
        if (v) {
            size_t len;
            const char *s = lua_tolstring(L, idx, &len);
            v->string = (char *)malloc(len + 1);
            if (v->string) {
                memcpy(v->string, s, len);
                v->string[len] = '\0';
            }
        }
        return v;
    }

    case LUA_TTABLE: {
        if (json_lua_is_array(L, idx)) {
            /* Array */
            size_t count = (size_t)lua_rawlen(L, idx);
            npe_json_value_t *arr = json_value_new(NPE_JSON_ARRAY);
            if (!arr) return NULL;

            arr->array.count = count;
            arr->array.items = NULL;
            if (count > 0) {
                arr->array.items = (npe_json_value_t **)calloc(
                    count, sizeof(npe_json_value_t *));
                if (!arr->array.items) {
                    npe_json_free(arr);
                    return NULL;
                }
                for (size_t i = 0; i < count; i++) {
                    lua_rawgeti(L, idx, (int)(i + 1));
                    arr->array.items[i] = json_lua_to_value(L, -1, depth + 1);
                    lua_pop(L, 1);
                    if (!arr->array.items[i]) {
                        npe_json_free(arr);
                        return NULL;
                    }
                }
            }
            return arr;
        } else {
            /* Object — first pass: count keys */
            size_t count = 0;
            lua_pushnil(L);
            while (lua_next(L, idx) != 0) {
                count++;
                lua_pop(L, 1);
            }

            npe_json_value_t *obj = json_value_new(NPE_JSON_OBJECT);
            if (!obj) return NULL;

            obj->object.count  = count;
            obj->object.keys   = NULL;
            obj->object.values = NULL;

            if (count > 0) {
                obj->object.keys = (char **)calloc(count, sizeof(char *));
                obj->object.values = (npe_json_value_t **)calloc(
                    count, sizeof(npe_json_value_t *));
                if (!obj->object.keys || !obj->object.values) {
                    npe_json_free(obj);
                    return NULL;
                }

                size_t i = 0;
                lua_pushnil(L);
                while (lua_next(L, idx) != 0) {
                    /* key at -2, value at -1 */
                    const char *key;
                    if (lua_type(L, -2) == LUA_TSTRING) {
                        key = lua_tostring(L, -2);
                    } else {
                        /* Convert non-string keys to string */
                        lua_pushvalue(L, -2);
                        key = lua_tostring(L, -1);
                        lua_pop(L, 1);
                    }

                    obj->object.keys[i] = strdup(key ? key : "");
                    obj->object.values[i] = json_lua_to_value(L, -1, depth + 1);
                    lua_pop(L, 1); /* pop value, keep key for next iteration */

                    if (!obj->object.keys[i] || !obj->object.values[i]) {
                        obj->object.count = i + 1;
                        npe_json_free(obj);
                        return NULL;
                    }
                    i++;
                }
            }
            return obj;
        }
    }

    default:
        /* Unsupported types (function, userdata, thread) → null */
        return json_value_new(NPE_JSON_NULL);
    }
}

/* ── Lua C functions ───────────────────────────────────────────────────── */

/* npe.json.decode(str) → value */
static int lua_json_decode(lua_State *L)
{
    size_t len;
    const char *str = luaL_checklstring(L, 1, &len);

    npe_json_value_t *val = NULL;
    npe_error_t err = npe_json_parse(str, len, &val);
    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "JSON parse error");
        return 2;
    }

    json_push_value_to_lua(L, val);
    npe_json_free(val);
    return 1;
}

/* npe.json.encode(value [, options]) → string */
static int lua_json_encode(lua_State *L)
{
    npe_json_encode_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.indent = 2;

    /* Parse options table if provided */
    if (lua_istable(L, 2)) {
        lua_getfield(L, 2, "pretty");
        if (!lua_isnil(L, -1)) opts.pretty = lua_toboolean(L, -1) ? true : false;
        lua_pop(L, 1);

        lua_getfield(L, 2, "indent");
        if (lua_isnumber(L, -1)) opts.indent = (int)lua_tointeger(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, 2, "escape_unicode");
        if (!lua_isnil(L, -1)) opts.escape_unicode = lua_toboolean(L, -1) ? true : false;
        lua_pop(L, 1);
    }

    npe_json_value_t *val = json_lua_to_value(L, 1, 0);
    if (!val) {
        lua_pushnil(L);
        lua_pushstring(L, "failed to convert Lua value to JSON");
        return 2;
    }

    char *out = NULL;
    size_t out_len = 0;
    npe_error_t err = npe_json_stringify(val, &opts, &out, &out_len);
    npe_json_free(val);

    if (err != NPE_OK || !out) {
        lua_pushnil(L);
        lua_pushstring(L, "JSON encode error");
        return 2;
    }

    lua_pushlstring(L, out, out_len);
    free(out);
    return 1;
}

/* npe.json.pretty(value) → string */
static int lua_json_pretty(lua_State *L)
{
    npe_json_encode_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pretty = true;
    opts.indent = 2;

    npe_json_value_t *val = json_lua_to_value(L, 1, 0);
    if (!val) {
        lua_pushnil(L);
        lua_pushstring(L, "failed to convert Lua value to JSON");
        return 2;
    }

    char *out = NULL;
    size_t out_len = 0;
    npe_error_t err = npe_json_stringify(val, &opts, &out, &out_len);
    npe_json_free(val);

    if (err != NPE_OK || !out) {
        lua_pushnil(L);
        lua_pushstring(L, "JSON encode error");
        return 2;
    }

    lua_pushlstring(L, out, out_len);
    free(out);
    return 1;
}

/* npe.json.validate(str) → boolean */
static int lua_json_validate(lua_State *L)
{
    size_t len;
    const char *str = luaL_checklstring(L, 1, &len);
    lua_pushboolean(L, npe_json_validate(str, len) ? 1 : 0);
    return 1;
}

/* ── Registration ──────────────────────────────────────────────────────── */

static const luaL_Reg json_funcs[] = {
    { "decode",   lua_json_decode   },
    { "encode",   lua_json_encode   },
    { "pretty",   lua_json_pretty   },
    { "validate", lua_json_validate },
    { NULL, NULL }
};

npe_error_t npe_lib_json_register(npe_vm_t *vm)
{
    if (!vm) return NPE_ERROR_INVALID_ARG;

    lua_State *L = (lua_State *)vm; /* vm wraps lua_State internally */

    /* Get or create npe global table */
    lua_getglobal(L, "npe");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_setglobal(L, "npe");
        lua_getglobal(L, "npe");
    }

    /* Create npe.json subtable */
    lua_newtable(L);
    luaL_setfuncs(L, json_funcs, 0);
    lua_setfield(L, -2, "json");

    lua_pop(L, 1); /* pop npe table */
    return NPE_OK;
}
