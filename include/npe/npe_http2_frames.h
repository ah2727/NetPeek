#ifndef NPE_HTTP2_FRAMES_H
#define NPE_HTTP2_FRAMES_H

#include <stdint.h>
#include <stddef.h>

/* ============================================
 * HTTP/2 Frame Types (RFC 7540 §6)
 * ============================================ */
typedef enum {
    NPE_H2_FRAME_DATA          = 0x0,
    NPE_H2_FRAME_HEADERS       = 0x1,
    NPE_H2_FRAME_PRIORITY      = 0x2,
    NPE_H2_FRAME_RST_STREAM    = 0x3,
    NPE_H2_FRAME_SETTINGS      = 0x4,
    NPE_H2_FRAME_PUSH_PROMISE  = 0x5,
    NPE_H2_FRAME_PING          = 0x6,
    NPE_H2_FRAME_GOAWAY        = 0x7,
    NPE_H2_FRAME_WINDOW_UPDATE = 0x8,
    NPE_H2_FRAME_CONTINUATION  = 0x9
} npe_h2_frame_type_t;

/* ============================================
 * HTTP/2 Flags
 * ============================================ */
#define NPE_H2_FLAG_END_STREAM   0x01
#define NPE_H2_FLAG_END_HEADERS  0x04
#define NPE_H2_FLAG_PADDED       0x08
#define NPE_H2_FLAG_PRIORITY     0x20
#define NPE_H2_FLAG_ACK          0x01

/* ============================================
 * Error Codes (RFC 7540 §7)
 * ============================================ */
typedef enum {
    NPE_H2_NO_ERROR            = 0x0,
    NPE_H2_PROTOCOL_ERROR      = 0x1,
    NPE_H2_INTERNAL_ERROR      = 0x2,
    NPE_H2_FLOW_CONTROL_ERROR  = 0x3,
    NPE_H2_SETTINGS_TIMEOUT    = 0x4,
    NPE_H2_STREAM_CLOSED       = 0x5,
    NPE_H2_FRAME_SIZE_ERROR    = 0x6,
    NPE_H2_REFUSED_STREAM      = 0x7,
    NPE_H2_CANCEL              = 0x8,
    NPE_H2_COMPRESSION_ERROR   = 0x9,
    NPE_H2_CONNECT_ERROR       = 0xa,
    NPE_H2_ENHANCE_YOUR_CALM   = 0xb,
    NPE_H2_INADEQUATE_SECURITY = 0xc,
    NPE_H2_HTTP_1_1_REQUIRED   = 0xd
} npe_h2_error_t;

/* ============================================
 * Frame Header (9 bytes)
 * ============================================ */
typedef struct {
    uint32_t length;   /* 24 bits */
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id; /* 31 bits */
} npe_h2_frame_header_t;

/* ============================================
 * Generic Frame Container
 * ============================================ */
typedef struct {
    npe_h2_frame_header_t hdr;
    uint8_t *payload;
} npe_h2_frame_t;

/* ============================================
 * API
 * ============================================ */

/* Encode frame header into buffer (must be >=9 bytes) */
void npe_h2_frame_encode_header(uint8_t *dst,
                                const npe_h2_frame_header_t *hdr);

/* Decode frame header from buffer */
int npe_h2_frame_decode_header(npe_h2_frame_header_t *hdr,
                               const uint8_t *src,
                               size_t len);

/* Validate header (frame size, stream id, flags) */
int npe_h2_frame_validate_header(const npe_h2_frame_header_t *hdr,
                                 uint32_t max_frame_size);

/* Allocate frame payload */
int npe_h2_frame_alloc(npe_h2_frame_t *f);

/* Free frame */
void npe_h2_frame_free(npe_h2_frame_t *f);

/* Debug helper */
const char *npe_h2_frame_type_str(uint8_t type);

#endif /* NPE_HTTP2_FRAMES_H */
