/*****************************************************************************
 * npe_lib_base64.c — Base64 encoding/decoding utilities
 *
 * NPE (NetPeek Extension Engine)
 *
 * Implements standard Base64 (RFC 4648 §4) and URL-safe Base64 (RFC 4648 §5)
 * encoding and decoding, with Lua bindings exposed as npe.base64.*
 *
 * Lua API:
 *   npe.base64.encode(data)       → standard Base64 string
 *   npe.base64.decode(str)        → decoded binary data
 *   npe.base64.url_encode(data)   → URL-safe Base64 string
 *   npe.base64.url_decode(str)    → decoded binary data (URL-safe)
 *   npe.base64.validate(str)      → boolean
 *****************************************************************************/

#include "npe_lib_base64.h"
#include "npe_lib_hash.h"   /* for npe_hash_format if needed */
#include "npe_types.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL: ALPHABET TABLES
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Standard Base64 alphabet (RFC 4648 §4) */
static const char b64_std_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* URL-safe Base64 alphabet (RFC 4648 §5) */
static const char b64_url_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
 * Decoding lookup table: 256 entries.
 *   -1 = invalid character
 *   -2 = padding '='
 *   0..63 = valid Base64 value
 *
 * We build two tables: one for standard, one for URL-safe.
 */
static int8_t b64_std_dec[256];
static int8_t b64_url_dec[256];
static bool   b64_tables_initialized = false;

#define B64_INVALID  ((int8_t)-1)
#define B64_PADDING  ((int8_t)-2)

/* ── Build decode tables (called once) ───────────────────────────────────── */
static void
b64_init_tables(void)
{
    if (b64_tables_initialized)
        return;

    /* Fill both tables with invalid marker */
    memset(b64_std_dec, B64_INVALID, sizeof(b64_std_dec));
    memset(b64_url_dec, B64_INVALID, sizeof(b64_url_dec));

    /* Populate standard table */
    for (int i = 0; i < 64; i++) {
        b64_std_dec[(unsigned char)b64_std_enc[i]] = (int8_t)i;
    }
    b64_std_dec[(unsigned char)'='] = B64_PADDING;

    /* Populate URL-safe table */
    for (int i = 0; i < 64; i++) {
        b64_url_dec[(unsigned char)b64_url_enc[i]] = (int8_t)i;
    }
    b64_url_dec[(unsigned char)'='] = B64_PADDING;

    b64_tables_initialized = true;
}

/* ── Select alphabet and decode table by variant ─────────────────────────── */
static const char *
b64_get_enc_table(npe_base64_variant_t variant)
{
    return (variant == NPE_BASE64_URLSAFE) ? b64_url_enc : b64_std_enc;
}

static const int8_t *
b64_get_dec_table(npe_base64_variant_t variant)
{
    return (variant == NPE_BASE64_URLSAFE) ? b64_url_dec : b64_std_dec;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENCODING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Calculate the encoded output length for a given input length.
 * Standard Base64 uses padding to a multiple of 4.
 * URL-safe variant also pads here; callers can strip if desired.
 */
static size_t
b64_encoded_length(size_t input_len)
{
    /* Each 3 bytes of input produce 4 characters of output.
     * Pad to the next multiple of 3, then multiply by 4/3. */
    return ((input_len + 2) / 3) * 4;
}

npe_error_t
npe_base64_encode(const uint8_t        *input,
                  size_t                length,
                  npe_base64_variant_t  variant,
                  char                **output,
                  size_t               *out_len)
{
    if (!output)
        return NPE_ERROR_INVALID_ARG;

    b64_init_tables();

    const char *alphabet = b64_get_enc_table(variant);

    /* Handle empty input */
    if (!input || length == 0) {
        *output = (char *)calloc(1, sizeof(char));
        if (!*output)
            return NPE_ERROR_MEMORY;
        if (out_len)
            *out_len = 0;
        return NPE_OK;
    }

    size_t enc_len = b64_encoded_length(length);
    char  *buf     = (char *)malloc(enc_len + 1);  /* +1 for NUL */
    if (!buf)
        return NPE_ERROR_MEMORY;

    size_t i = 0;   /* input index  */
    size_t j = 0;   /* output index */

    /* Process full 3-byte groups */
    while (i + 2 < length) {
        uint32_t triplet = ((uint32_t)input[i]     << 16) |
                           ((uint32_t)input[i + 1]  << 8)  |
                           ((uint32_t)input[i + 2]);

        buf[j++] = alphabet[(triplet >> 18) & 0x3F];
        buf[j++] = alphabet[(triplet >> 12) & 0x3F];
        buf[j++] = alphabet[(triplet >>  6) & 0x3F];
        buf[j++] = alphabet[(triplet      ) & 0x3F];

        i += 3;
    }

    /* Handle remaining 1 or 2 bytes */
    size_t remaining = length - i;

    if (remaining == 1) {
        uint32_t val = (uint32_t)input[i] << 16;

        buf[j++] = alphabet[(val >> 18) & 0x3F];
        buf[j++] = alphabet[(val >> 12) & 0x3F];
        buf[j++] = '=';
        buf[j++] = '=';
    } else if (remaining == 2) {
        uint32_t val = ((uint32_t)input[i] << 16) |
                       ((uint32_t)input[i + 1] << 8);

        buf[j++] = alphabet[(val >> 18) & 0x3F];
        buf[j++] = alphabet[(val >> 12) & 0x3F];
        buf[j++] = alphabet[(val >>  6) & 0x3F];
        buf[j++] = '=';
    }

    buf[j] = '\0';

    *output = buf;
    if (out_len)
        *out_len = j;

    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DECODING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Calculate the maximum decoded output length.
 * Actual length may be 1-2 bytes shorter due to padding.
 */
static size_t
b64_decoded_max_length(size_t input_len)
{
    return (input_len / 4) * 3 + 3;  /* generous upper bound */
}

/**
 * Skip whitespace characters (CR, LF, space, tab) commonly found
 * in PEM-encoded data and multi-line Base64.
 */
static inline bool
b64_is_whitespace(char c)
{
    return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

npe_error_t
npe_base64_decode(const char           *input,
                  size_t                length,
                  npe_base64_variant_t  variant,
                  uint8_t             **output,
                  size_t               *out_len)
{
    if (!output)
        return NPE_ERROR_INVALID_ARG;

    b64_init_tables();

    const int8_t *dec_table = b64_get_dec_table(variant);

    /* Handle empty input */
    if (!input || length == 0) {
        *output = (uint8_t *)calloc(1, sizeof(uint8_t));
        if (!*output)
            return NPE_ERROR_MEMORY;
        if (out_len)
            *out_len = 0;
        return NPE_OK;
    }

    /*
     * First pass: strip whitespace and count valid characters.
     * We allocate a clean buffer to simplify the decode loop.
     */
    char  *clean     = (char *)malloc(length + 1);
    if (!clean)
        return NPE_ERROR_MEMORY;

    size_t clean_len = 0;

    for (size_t i = 0; i < length; i++) {
        char c = input[i];
        if (b64_is_whitespace(c))
            continue;
        clean[clean_len++] = c;
    }
    clean[clean_len] = '\0';

    /* URL-safe variant may omit padding — add it back */
    size_t padded_len = clean_len;
    size_t pad_needed = 0;
    if (clean_len % 4 != 0) {
        pad_needed  = 4 - (clean_len % 4);
        padded_len  = clean_len + pad_needed;

        char *padded = (char *)realloc(clean, padded_len + 1);
        if (!padded) {
            free(clean);
            return NPE_ERROR_MEMORY;
        }
        clean = padded;

        for (size_t p = 0; p < pad_needed; p++)
            clean[clean_len + p] = '=';
        clean[padded_len] = '\0';
        clean_len = padded_len;
    }

    /* Validate: length must now be a multiple of 4 */
    if (clean_len % 4 != 0) {
        free(clean);
        return NPE_ERROR_INVALID_ARG;
    }

    /* Allocate output buffer */
    size_t   max_out = b64_decoded_max_length(clean_len);
    uint8_t *buf     = (uint8_t *)malloc(max_out);
    if (!buf) {
        free(clean);
        return NPE_ERROR_MEMORY;
    }

    size_t oi = 0;  /* output index */

    for (size_t i = 0; i < clean_len; i += 4) {
        int8_t a = dec_table[(unsigned char)clean[i]];
        int8_t b = dec_table[(unsigned char)clean[i + 1]];
        int8_t c = dec_table[(unsigned char)clean[i + 2]];
        int8_t d = dec_table[(unsigned char)clean[i + 3]];

        /* First two characters must always be valid (not padding, not invalid) */
        if (a == B64_INVALID || a == B64_PADDING ||
            b == B64_INVALID || b == B64_PADDING) {
            free(clean);
            free(buf);
            return NPE_ERROR_INVALID_ARG;
        }

        /* Third character: valid or padding */
        if (c == B64_INVALID) {
            free(clean);
            free(buf);
            return NPE_ERROR_INVALID_ARG;
        }

        /* Fourth character: valid or padding */
        if (d == B64_INVALID) {
            free(clean);
            free(buf);
            return NPE_ERROR_INVALID_ARG;
        }

        /* Decode the 4 characters into up to 3 bytes */
        if (c == B64_PADDING && d == B64_PADDING) {
            /* Two padding chars: only 1 output byte */
            uint32_t val = ((uint32_t)a << 18) | ((uint32_t)b << 12);
            buf[oi++] = (uint8_t)((val >> 16) & 0xFF);
        } else if (d == B64_PADDING) {
            /* One padding char: 2 output bytes */
            uint32_t val = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                           ((uint32_t)c << 6);
            buf[oi++] = (uint8_t)((val >> 16) & 0xFF);
            buf[oi++] = (uint8_t)((val >>  8) & 0xFF);
        } else {
            /* No padding: 3 output bytes */
            uint32_t val = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                           ((uint32_t)c << 6)  | ((uint32_t)d);
            buf[oi++] = (uint8_t)((val >> 16) & 0xFF);
            buf[oi++] = (uint8_t)((val >>  8) & 0xFF);
            buf[oi++] = (uint8_t)((val      ) & 0xFF);
        }
    }

    free(clean);

    *output = buf;
    if (out_len)
        *out_len = oi;

    return NPE_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  QUICK HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

char *
npe_base64_encode_str(const char *input)
{
    if (!input)
        return NULL;

    char  *output  = NULL;
    size_t out_len = 0;

    npe_error_t err = npe_base64_encode(
        (const uint8_t *)input,
        strlen(input),
        NPE_BASE64_STANDARD,
        &output,
        &out_len);

    if (err != NPE_OK) {
        return NULL;
    }

    return output;
}

char *
npe_base64_decode_str(const char *input)
{
    if (!input)
        return NULL;

    uint8_t *output  = NULL;
    size_t   out_len = 0;

    npe_error_t err = npe_base64_decode(
        input,
        strlen(input),
        NPE_BASE64_STANDARD,
        &output,
        &out_len);

    if (err != NPE_OK) {
        return NULL;
    }

    /*
     * Ensure NUL termination for string usage.
     * The decode buffer was allocated with enough room, but let's be safe.
     */
    uint8_t *result = (uint8_t *)realloc(output, out_len + 1);
    if (!result) {
        free(output);
        return NULL;
    }
    result[out_len] = '\0';

    return (char *)result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  VALIDATION
 * ═══════════════════════════════════════════════════════════════════════════ */

bool
npe_base64_validate(const char *input, size_t length)
{
    if (!input || length == 0)
        return true;  /* empty string is trivially valid */

    b64_init_tables();

    /*
     * We accept both standard and URL-safe characters.
     * Also allow whitespace and padding.
     * The structural rules:
     *   - After stripping whitespace, length must be a multiple of 4
     *     (or valid without padding for URL-safe).
     *   - Padding '=' may only appear at the end (max 2).
     *   - No invalid characters.
     */

    size_t clean_count  = 0;
    size_t pad_count    = 0;
    bool   seen_padding = false;

    for (size_t i = 0; i < length; i++) {
        char c = input[i];

        if (b64_is_whitespace(c))
            continue;

        if (c == '=') {
            seen_padding = true;
            pad_count++;
            clean_count++;

            /* More than 2 padding characters is invalid */
            if (pad_count > 2)
                return false;

            continue;
        }

        /* No data characters allowed after padding */
        if (seen_padding)
            return false;

        /* Check if character is in standard or URL-safe alphabet */
        if (b64_std_dec[(unsigned char)c] == B64_INVALID &&
            b64_url_dec[(unsigned char)c] == B64_INVALID) {
            return false;
        }

        clean_count++;
    }

    /* After stripping whitespace, length should be a multiple of 4,
     * or (for URL-safe without padding) mod 4 should be 2 or 3. */
    size_t mod = clean_count % 4;
    if (mod == 1)
        return false;  /* 1 character is never valid */

    /* If there's padding, total must be multiple of 4 */
    if (pad_count > 0 && mod != 0)
        return false;

    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDINGS
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * We assume the Lua VM interface provides:
 *   - npe_vm_push_string_l(vm, str, len)  — push string with length
 *   - npe_vm_push_nil(vm)                 — push nil
 *   - npe_vm_push_boolean(vm, val)        — push boolean
 *   - npe_vm_push_cfunction(vm, fn)       — push C function
 *   - npe_vm_get_string_l(vm, idx, &len)  — get string at stack index
 *   - npe_vm_set_field(vm, idx, name)     — set table field
 *   - npe_vm_new_table(vm)                — push new table
 *   - npe_vm_set_global(vm, name)         — set global
 *   - npe_vm_get_global(vm, name)         — get global
 *   - npe_vm_get_field(vm, idx, name)     — get table field
 *
 * The actual Lua C API calls depend on the npe_vm abstraction layer.
 * Below we use a thin wrapper style consistent with the NPE codebase.
 */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* ── Helper: get the lua_State from npe_vm_t ─────────────────────────────── */
/* Assumes npe_vm_t has a member `L` of type lua_State* or a getter function.
 * Adjust to match your actual npe_vm_t definition. */
static lua_State *
npe_vm_get_lua(npe_vm_t *vm)
{
    /* Common pattern: vm->L or npe_vm_lua_state(vm) */
    extern lua_State *npe_vm_lua_state(npe_vm_t *vm);
    return npe_vm_lua_state(vm);
}

/* ── npe.base64.encode(data) ─────────────────────────────────────────────── */
static int
l_base64_encode(lua_State *L)
{
    size_t      input_len = 0;
    const char *input     = luaL_checklstring(L, 1, &input_len);

    char  *output  = NULL;
    size_t out_len = 0;

    npe_error_t err = npe_base64_encode(
        (const uint8_t *)input,
        input_len,
        NPE_BASE64_STANDARD,
        &output,
        &out_len);

    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "base64 encode failed");
        return 2;
    }

    lua_pushlstring(L, output, out_len);
    free(output);
    return 1;
}

/* ── npe.base64.decode(str) ──────────────────────────────────────────────── */
static int
l_base64_decode(lua_State *L)
{
    size_t      input_len = 0;
    const char *input     = luaL_checklstring(L, 1, &input_len);

    uint8_t *output  = NULL;
    size_t   out_len = 0;

    npe_error_t err = npe_base64_decode(
        input,
        input_len,
        NPE_BASE64_STANDARD,
        &output,
        &out_len);

    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "base64 decode failed: invalid input");
        return 2;
    }

    lua_pushlstring(L, (const char *)output, out_len);
    free(output);
    return 1;
}

/* ── npe.base64.url_encode(data) ─────────────────────────────────────────── */
static int
l_base64_url_encode(lua_State *L)
{
    size_t      input_len = 0;
    const char *input     = luaL_checklstring(L, 1, &input_len);

    char  *output  = NULL;
    size_t out_len = 0;

    npe_error_t err = npe_base64_encode(
        (const uint8_t *)input,
        input_len,
        NPE_BASE64_URLSAFE,
        &output,
        &out_len);

    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "base64 url_encode failed");
        return 2;
    }

    /*
     * URL-safe Base64 conventionally strips trailing '=' padding.
     * Strip it here for maximum compatibility with web APIs.
     */
    while (out_len > 0 && output[out_len - 1] == '=') {
        out_len--;
    }

    lua_pushlstring(L, output, out_len);
    free(output);
    return 1;
}

/* ── npe.base64.url_decode(str) ──────────────────────────────────────────── */
static int
l_base64_url_decode(lua_State *L)
{
    size_t      input_len = 0;
    const char *input     = luaL_checklstring(L, 1, &input_len);

    uint8_t *output  = NULL;
    size_t   out_len = 0;

    npe_error_t err = npe_base64_decode(
        input,
        input_len,
        NPE_BASE64_URLSAFE,
        &output,
        &out_len);

    if (err != NPE_OK) {
        lua_pushnil(L);
        lua_pushstring(L, "base64 url_decode failed: invalid input");
        return 2;
    }

    lua_pushlstring(L, (const char *)output, out_len);
    free(output);
    return 1;
}

/* ── npe.base64.validate(str) ────────────────────────────────────────────── */
static int
l_base64_validate(lua_State *L)
{
    size_t      input_len = 0;
    const char *input     = luaL_checklstring(L, 1, &input_len);

    bool valid = npe_base64_validate(input, input_len);
    lua_pushboolean(L, valid);
    return 1;
}

/* ── Function registration table ─────────────────────────────────────────── */
static const luaL_Reg base64_funcs[] = {
    { "encode",     l_base64_encode     },
    { "decode",     l_base64_decode     },
    { "url_encode", l_base64_url_encode },
    { "url_decode", l_base64_url_decode },
    { "validate",   l_base64_validate   },
    { NULL,         NULL                }
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  REGISTRATION
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_error_t
npe_lib_base64_register(npe_vm_t *vm)
{
    if (!vm)
        return NPE_ERROR_INVALID_ARG;

    lua_State *L = npe_vm_get_lua(vm);
    if (!L)
        return NPE_ERROR_GENERIC;

    /* Ensure the global "npe" table exists */
    lua_getglobal(L, "npe");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setglobal(L, "npe");
    }

    /* Create npe.base64 = { ... } */
    lua_newtable(L);

    /* Register all functions into the table */
    for (const luaL_Reg *f = base64_funcs; f->name != NULL; f++) {
        lua_pushcfunction(L, f->func);
        lua_setfield(L, -2, f->name);
    }

    /* npe.base64 = <table on top of stack> */
    lua_setfield(L, -2, "base64");

    /* Pop the "npe" table */
    lua_pop(L, 1);

    /* Initialize decode tables eagerly */
    b64_init_tables();

    return NPE_OK;
}
