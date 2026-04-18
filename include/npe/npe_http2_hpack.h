#ifndef NPE_HTTP2_HPACK_H
#define NPE_HTTP2_HPACK_H

#include "npe_http2.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  HPACK Compressed Table Entry (RLE)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint16_t count;
    int32_t  delta;
} hpack_rle_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  HPACK API
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Call once to expand Huffman tables */
void npe_hpack_init(void);

/* Dynamic table lifecycle */
int  npe_hpack_dyn_table_init(npe_h2_dyn_table_t *dt, uint32_t max_size);
void npe_hpack_dyn_table_free(npe_h2_dyn_table_t *dt);
void npe_hpack_dyn_table_resize(npe_h2_dyn_table_t *dt, uint32_t new_max);

/* Decode a complete HPACK header block */
int npe_hpack_decode_block(const uint8_t *in, size_t in_len,
                           npe_h2_dyn_table_t *dt,
                           char ***out_names, char ***out_values,
                           uint32_t **out_name_lens, uint32_t **out_value_lens,
                           uint32_t *out_count);

/* Encode headers into an HPACK block */
int npe_hpack_encode_block(const char **names, const char **values,
                           const uint32_t *name_lens, const uint32_t *value_lens,
                           uint32_t count,
                           npe_h2_dyn_table_t *dt,
                           uint8_t *out, size_t out_cap, size_t *out_len);

/* Integer prefix coding */
size_t npe_hpack_encode_int(uint8_t *out, size_t out_len,
                            uint32_t value, uint8_t prefix_bits);
int    npe_hpack_decode_int(const uint8_t *buf, size_t buf_len,
                            size_t *idx, uint32_t mask, uint32_t *val);

/* Huffman */
int  npe_hpack_huff_decode(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);
size_t npe_hpack_huff_encode(const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap);
size_t npe_hpack_huff_encoded_len(const uint8_t *in, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif /* NPE_HTTP2_HPACK_H */
