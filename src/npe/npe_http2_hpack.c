/*
 * npe_http2_hpack.c — Complete HPACK Implementation (RFC 7541)
 *
 * NetPeek Engine — HTTP/2 Header Compression
 */

#include "npe_http2_hpack.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  Forward Declarations (internal helpers)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int hpack_dyn_table_add(npe_h2_dyn_table_t *dt,
                               const char *name, uint32_t name_len,
                               const char *value, uint32_t value_len);
static void hpack_dyn_table_evict_one(npe_h2_dyn_table_t *dt);
static void hpack_dyn_table_evict_to_fit(npe_h2_dyn_table_t *dt, uint32_t needed);
static int hpack_lookup_index(npe_h2_dyn_table_t *dt, uint32_t index,
                              const char **name, uint32_t *name_len,
                              const char **value, uint32_t *value_len);
static int hpack_lookup_name_by_index(npe_h2_dyn_table_t *dt, uint32_t index,
                                      const char **name, uint32_t *name_len);
static int hpack_read_string(const uint8_t *buf, size_t buf_len, size_t *pos,
                             char **out_str, uint32_t *out_len);
static void hpack_ensure_header_capacity(char ***names, char ***values,
                                         uint32_t **n_lens, uint32_t **v_lens,
                                         uint32_t *cap, uint32_t needed);

/* ═══════════════════════════════════════════════════════════════════════════
 *  Static Table (RFC 7541 Appendix A) — 0-indexed sentinel, entries 1..61
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct
{
    const char *name;
    const char *value;
} hpack_static_entry_t;

static const hpack_static_entry_t hpack_static_table[62] = {
    /* 0  */ {"", ""},
    /* 1  */ {":authority", ""},
    /* 2  */ {":method", "GET"},
    /* 3  */ {":method", "POST"},
    /* 4  */ {":path", "/"},
    /* 5  */ {":path", "/index.html"},
    /* 6  */ {":scheme", "http"},
    /* 7  */ {":scheme", "https"},
    /* 8  */ {":status", "200"},
    /* 9  */ {":status", "204"},
    /* 10 */ {":status", "206"},
    /* 11 */ {":status", "304"},
    /* 12 */ {":status", "400"},
    /* 13 */ {":status", "404"},
    /* 14 */ {":status", "500"},
    /* 15 */ {"accept-charset", ""},
    /* 16 */ {"accept-encoding", "gzip, deflate"},
    /* 17 */ {"accept-language", ""},
    /* 18 */ {"accept-ranges", ""},
    /* 19 */ {"accept", ""},
    /* 20 */ {"access-control-allow-origin", ""},
    /* 21 */ {"age", ""},
    /* 22 */ {"allow", ""},
    /* 23 */ {"authorization", ""},
    /* 24 */ {"cache-control", ""},
    /* 25 */ {"content-disposition", ""},
    /* 26 */ {"content-encoding", ""},
    /* 27 */ {"content-language", ""},
    /* 28 */ {"content-length", ""},
    /* 29 */ {"content-location", ""},
    /* 30 */ {"content-range", ""},
    /* 31 */ {"content-type", ""},
    /* 32 */ {"cookie", ""},
    /* 33 */ {"date", ""},
    /* 34 */ {"etag", ""},
    /* 35 */ {"expect", ""},
    /* 36 */ {"expires", ""},
    /* 37 */ {"from", ""},
    /* 38 */ {"host", ""},
    /* 39 */ {"if-match", ""},
    /* 40 */ {"if-modified-since", ""},
    /* 41 */ {"if-none-match", ""},
    /* 42 */ {"if-range", ""},
    /* 43 */ {"if-unmodified-since", ""},
    /* 44 */ {"last-modified", ""},
    /* 45 */ {"link", ""},
    /* 46 */ {"location", ""},
    /* 47 */ {"max-forwards", ""},
    /* 48 */ {"proxy-authenticate", ""},
    /* 49 */ {"proxy-authorization", ""},
    /* 50 */ {"range", ""},
    /* 51 */ {"referer", ""},
    /* 52 */ {"refresh", ""},
    /* 53 */ {"retry-after", ""},
    /* 54 */ {"server", ""},
    /* 55 */ {"set-cookie", ""},
    /* 56 */ {"strict-transport-security", ""},
    /* 57 */ {"transfer-encoding", ""},
    /* 58 */ {"user-agent", ""},
    /* 59 */ {"vary", ""},
    /* 60 */ {"via", ""},
    /* 61 */ {"www-authenticate", ""}};

#define HPACK_STATIC_TABLE_LEN 61

/* ═══════════════════════════════════════════════════════════════════════════
 *  Huffman Code Table (RFC 7541 Appendix B) — 257 entries
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct
{
    uint32_t code;
    uint8_t bits;
} hpack_huff_sym_t;

static const hpack_huff_sym_t hpack_huff_table[257] = {
    {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28}, {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28}, {0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28}, {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28}, {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12}, {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11}, {0x3fa, 10}, {0x3fb, 10}, {0xf9, 8}, {0x7fb, 11}, {0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6}, {0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6}, {0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8}, {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6}, {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7}, {0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7}, {0x69, 7}, {0x6a, 7}, {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7}, {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7}, {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6}, {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5}, {0x25, 6}, {0x26, 6}, {0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7}, {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7}, {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7}, {0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14}, {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20}, {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23}, {0x3fffd6, 22}, {0x7fffda, 23}, {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23}, {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23}, {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23}, {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24}, {0x3fffda, 22}, {0x1fffdd, 21}, {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21}, {0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22}, {0x7fffeb, 23}, {0x7fffec, 23}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21}, {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23}, {0xfffea, 20}, {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23}, {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23}, {0x3fffe8, 22}, {0x1ffffec, 25}, {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27}, {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25}, {0x7fff2, 19}, {0x1fffe3, 21}, {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24}, {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27}, {0x7ffffe4, 27}, {0x7ffffe5, 27}, {0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21}, {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23}, {0x3fffea, 22}, {0x3fffeb, 22}, {0x1ffffee, 25}, {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23}, {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27}, {0x7ffffe9, 27}, {0x7ffffea, 27}, {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27}, {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26}, {0x3fffffff, 30}};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Huffman Decode Tree (bit-by-bit)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define HPACK_HUFF_DECODE_NODE_MAX 1024

typedef struct
{
    int16_t children[2];
} hpack_huff_node_t;

static hpack_huff_node_t huff_tree[HPACK_HUFF_DECODE_NODE_MAX];
static int huff_tree_count = 0;
static bool hpack_tables_ready = false;

static int huff_tree_alloc_node(void)
{
    if (huff_tree_count >= HPACK_HUFF_DECODE_NODE_MAX)
        return -1;
    int idx = huff_tree_count++;
    huff_tree[idx].children[0] = -1;
    huff_tree[idx].children[1] = -1;
    return idx;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Initialization
 * ═══════════════════════════════════════════════════════════════════════════ */

void npe_hpack_init(void)
{
    if (hpack_tables_ready)
        return;

    huff_tree_count = 0;
    huff_tree_alloc_node(); /* root = node 0 */

    for (int sym = 0; sym <= 256; sym++)
    {
        uint32_t code = hpack_huff_table[sym].code;
        uint8_t bits = hpack_huff_table[sym].bits;
        int node = 0;

        for (int b = bits - 1; b >= 0; b--)
        {
            int bit = (code >> b) & 1;
            if (b == 0)
            {
                huff_tree[node].children[bit] = -(sym + 2);
            }
            else
            {
                int next = huff_tree[node].children[bit];
                if (next < 0)
                {
                    next = huff_tree_alloc_node();
                    if (next < 0)
                        return;
                    huff_tree[node].children[bit] = next;
                }
                node = next;
            }
        }
    }

    hpack_tables_ready = true;
}

/* ═══════════Integer Encoding/Decoding (RFC 7541 §5.1) ══════════════════ */

size_t npe_hpack_encode_int(uint8_t *out, size_t out_len, uint32_t value, uint8_t prefix_bits)

{

    if (!out || out_len == 0 || prefix_bits == 0 || prefix_bits > 8)

        return 0;

    uint8_t max_prefix = (1u << prefix_bits) - 1;

    size_t pos = 0;

    if (value < max_prefix)
    {

        out[pos] = (out[pos] & ~max_prefix) | (uint8_t)value;

        return 1;
    }

    out[pos] = (out[pos] & ~max_prefix) | max_prefix;

    pos++;

    value -= max_prefix;

    while (value >= 128)
    {

        if (pos >= out_len)
            return 0;

        out[pos++] = (uint8_t)((value & 0x7F) | 0x80);

        value >>= 7;
    }

    if (pos >= out_len)
        return 0;

    out[pos++] = (uint8_t)(value & 0x7F);

    return pos;
}

int npe_hpack_decode_int(const uint8_t *buf, size_t buf_len, size_t *idx, uint32_t prefix_bits, uint32_t *val)

{

    if (!buf || !idx || !val || *idx >= buf_len || prefix_bits == 0 || prefix_bits > 8)

        return -1;

    uint8_t max_prefix = (1u << prefix_bits) - 1;

    uint32_t value = buf[*idx] & max_prefix;

    (*idx)++;

    if (value < max_prefix)
    {

        *val = value;

        return 0;
    }

    uint32_t shift = 0;

    for (;;)
    {

        if (*idx >= buf_len)
            return -2;

        uint8_t byte = buf[*idx];

        (*idx)++;

        value += (uint32_t)(byte & 0x7F) << shift;

        shift += 7;

        if (!(byte & 0x80))
            break;
    }

    *val = value;

    return 0;
}

/* ════════════════════ Huffman Decoding ════════════════════ */

int npe_hpack_huffman_decode(const uint8_t *in, size_t in_len, char **out, size_t *out_len)

{

    if (!hpack_tables_ready || !in || in_len == 0)
        return -1;

    size_t cap = in_len * 2 + 1;

    char *dst = malloc(cap);

    if (!dst)
        return -1;

    int node = 0;

    size_t out_pos = 0;

    for (size_t i = 0; i < in_len; ++i)
    {

        uint8_t byte = in[i];

        for (int bit = 7; bit >= 0; --bit)
        {

            int b = (byte >> bit) & 1;

            int child = huff_tree[node].children[b];

            if (child < -1)
            {

                int sym = -(child + 2);

                if (sym == 256)
                { /* EOS */

                    dst[out_pos] = '\0';

                    *out_len = out_pos;

                    *out = dst;

                    return 0;
                }

                if (out_pos + 1 >= cap)
                {

                    cap *= 2;

                    dst = realloc(dst, cap);

                    if (!dst)
                        return -1;
                }

                dst[out_pos++] = (char)sym;

                node = 0;
            }
            else if (child >= 0)
            {

                node = child;
            }
            else
            {

                free(dst);

                return -2;
            }
        }
    }

    dst[out_pos] = '\0';

    *out_len = out_pos;

    *out = dst;

    return 0;
}

/* ══════════════ Dynamic Table Management ══════════════════ */

int npe_hpack_dyn_table_init(npe_h2_dyn_table_t *dt, uint32_t max_size)

{

    memset(dt, 0, sizeof(*dt));

    dt->max_size = max_size ? max_size : NPE_HPACK_DEFAULT_SIZE;

    return 0;
}

void npe_hpack_dyn_table_free(npe_h2_dyn_table_t *dt)

{

    for (uint32_t i = 0; i < dt->count; i++)
    {

        free(dt->entries[i].name);

        free(dt->entries[i].value);
    }

    dt->count = 0;

    dt->current_size = 0;
}

static int hpack_dyn_table_add(npe_h2_dyn_table_t *dt,

                               const char *name, uint32_t name_len,

                               const char *value, uint32_t value_len)

{

    uint32_t entry_size = name_len + value_len + 32;

    hpack_dyn_table_evict_to_fit(dt, entry_size);

    if (dt->count >= HPACK_DYNAMIC_TABLE_MAX)

        hpack_dyn_table_evict_one(dt);

    /* Indexing in HPACK: newest is at index 1 in the dynamic region (total index 62) */

    /* So we shift our internal array to accommodate a new entry at position 0 */

    memmove(&dt->entries[1], &dt->entries[0], sizeof(npe_h2_header_entry_t) * dt->count);

    npe_h2_header_entry_t *e = &dt->entries[0];

    e->name = strndup(name, name_len);

    e->value = strndup(value, value_len);

    e->name_len = name_len;

    e->value_len = value_len;

    dt->count++;

    dt->current_size += entry_size;

    return 0;
}

static void hpack_dyn_table_evict_one(npe_h2_dyn_table_t *dt)

{

    if (dt->count == 0)
        return;

    uint32_t last = dt->count - 1;

    dt->current_size -= dt->entries[last].name_len + dt->entries[last].value_len + 32;

    free(dt->entries[last].name);

    free(dt->entries[last].value);

    dt->count--;
}

static void hpack_dyn_table_evict_to_fit(npe_h2_dyn_table_t *dt, uint32_t needed)

{

    while (dt->current_size + needed > dt->max_size && dt->count > 0)

        hpack_dyn_table_evict_one(dt);
}

/* ══════════════ Lookup Helpers ══════════════════════════ */

static int hpack_lookup_index(npe_h2_dyn_table_t *dt, uint32_t index,

                              const char **name, uint32_t *name_len,

                              const char **value, uint32_t *value_len)

{

    if (index == 0)
        return -1;

    if (index <= 61)
    {

        *name = hpack_static_table[index].name;

        *value = hpack_static_table[index].value;

        *name_len = (uint32_t)strlen(*name);

        *value_len = (uint32_t)strlen(*value);

        return 0;
    }

    uint32_t d_idx = index - 62;

    if (d_idx >= dt->count)
        return -1;

    *name = dt->entries[d_idx].name;

    *value = dt->entries[d_idx].value;

    *name_len = dt->entries[d_idx].name_len;

    *value_len = dt->entries[d_idx].value_len;

    return 0;
}

static int hpack_lookup_name_by_index(npe_h2_dyn_table_t *dt, uint32_t index,

                                      const char **name, uint32_t *name_len)

{

    const char *v;
    uint32_t vl;

    return hpack_lookup_index(dt, index, name, name_len, &v, &vl);
}

static void hpack_ensure_header_capacity(char ***names, char ***values,

                                         uint32_t **n_lens, uint32_t **v_lens,

                                         uint32_t *cap, uint32_t needed)

{

    if (needed <= *cap)
        return;

    uint32_t new_cap = *cap * 2;

    if (new_cap < needed)
        new_cap = needed;

    *names = realloc(names, sizeof(char) * new_cap);

    *values = realloc(values, sizeof(char) * new_cap);

    *n_lens = realloc(*n_lens, sizeof(uint32_t) * new_cap);

    *v_lens = realloc(*v_lens, sizeof(uint32_t) * new_cap);

    *cap = new_cap;
}

/* ══════════════ Header Block Decoding ══════════════════ */

int npe_hpack_decode_block(const uint8_t *in, size_t in_len,

                           npe_h2_dyn_table_t *dt,

                           char ***names, char ***values,

                           uint32_t **name_lens, uint32_t **value_lens,

                           uint32_t *header_count)

{

    if (!in || !dt || !names || !values || !header_count)
        return -1;

    size_t pos = 0;

    uint32_t cap = 8;

    names = malloc(sizeof(char) * cap);

    values = malloc(sizeof(char) * cap);

    *name_lens = malloc(sizeof(uint32_t) * cap);

    *value_lens = malloc(sizeof(uint32_t) * cap);

    *header_count = 0;

    while (pos < in_len)
    {

        uint8_t b = in[pos];

        if (b & 0x80)
        { /* 1. Indexed Header Field */

            uint32_t index;

            if (npe_hpack_decode_int(in, in_len, &pos, 7, &index) != 0)
                break;

            const char *n, *v;
            uint32_t nl, vl;

            if (hpack_lookup_index(dt, index, &n, &nl, &v, &vl) != 0)
                goto err;

            hpack_ensure_header_capacity(names, values, name_lens, value_lens, &cap, *header_count + 1);

            (*names)[*header_count] = strndup(n, nl);

            (*values)[*header_count] = strndup(v, vl);

            (*name_lens)[*header_count] = nl;

            (*value_lens)[*header_count] = vl;

            (*header_count)++;
        }

        else if ((b & 0xC0) == 0x40)
        { /* 2. Literal Header Field with Incremental Indexing */

            uint32_t index;

            if (npe_hpack_decode_int(in, in_len, &pos, 6, &index) != 0)
                break;

            const char *n;
            uint32_t nl;

            char *n_own = NULL, *v_own = NULL;
            uint32_t vl;

            if (index > 0)
            {

                if (hpack_lookup_name_by_index(dt, index, &n, &nl) != 0)
                    goto err;
            }
            else
            {

                if (hpack_read_string(in, in_len, &pos, &n_own, &nl) != 0)
                    goto err;

                n = n_own;
            }

            if (hpack_read_string(in, in_len, &pos, &v_own, &vl) != 0)
            {
                free(n_own);
                goto err;
            }

            hpack_dyn_table_add(dt, n, nl, v_own, vl);

            hpack_ensure_header_capacity(names, values, name_lens, value_lens, &cap, *header_count + 1);

            (*names)[*header_count] = strndup(n, nl);

            (*values)[*header_count] = v_own;
            /* transfer ownership */

            (*name_lens)[*header_count] = nl;

            (*value_lens)[*header_count] = vl;

            (*header_count)++;

            if (n_own)
                free(n_own);
        }

        else
        { /* 3. Other literals (not indexed) - treat similarly but don’t add to dyn table */

            uint8_t prefix = (b & 0xF0) == 0x10 ? 4 : 4; /* either 0x00 or 0x10 prefix */

            uint32_t index;

            if (npe_hpack_decode_int(in, in_len, &pos, prefix, &index) != 0)
                break;

            const char *n;
            uint32_t nl;

            char *n_own = NULL, *v_own = NULL;
            uint32_t vl;

            if (index > 0)
            {

                if (hpack_lookup_name_by_index(dt, index, &n, &nl) != 0)
                    goto err;
            }
            else
            {

                if (hpack_read_string(in, in_len, &pos, &n_own, &nl) != 0)
                    goto err;

                n = n_own;
            }

            if (hpack_read_string(in, in_len, &pos, &v_own, &vl) != 0)
            {
                free(n_own);
                goto err;
            }

            hpack_ensure_header_capacity(names, values, name_lens, value_lens, &cap, *header_count + 1);

            (*names)[*header_count] = strndup(n, nl);

            (*values)[*header_count] = v_own;

            (*name_lens)[*header_count] = nl;

            (*value_lens)[*header_count] = vl;

            (*header_count)++;

            if (n_own)
                free(n_own);
        }
    }

    return 0;

err:

    return -1;
}

/* ══════════════ String Reader ══════════════════════════ */

static int hpack_read_string(const uint8_t *buf, size_t buf_len, size_t *pos,

                             char **out_str, uint32_t *out_len)

{

    if (*pos >= buf_len)
        return -1;

    bool huffman = buf[*pos] & 0x80;

    uint32_t length;

    if (npe_hpack_decode_int(buf, buf_len, pos, 7, &length) != 0)
        return -2;

    if (*pos + length > buf_len)
        return -3;

    if (!huffman)
    {

        *out_str = malloc(length + 1);

        memcpy(*out_str, buf + *pos, length);

        (*out_str)[length] = '\0';

        *out_len = length;

        *pos += length;

        return 0;
    }

    size_t outl;

    int res = npe_hpack_huffman_decode(buf + *pos, length, out_str, &outl);

    if (res == 0)
    {

        *out_len = (uint32_t)outl;

        *pos += length;
    }

    return res;
}