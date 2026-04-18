#ifndef NPE_LIB_HTTP2_FRAME_H
#define NPE_LIB_HTTP2_FRAME_H

#include "npe_lib_net.h"
#include "npe_lib_http2.h"
#include <stdint.h>
#include <stddef.h>

/* HTTP/2 frame types (RFC 7540 §11.2) */
#define NPE_HTTP2_FRAME_DATA       0x0
#define NPE_HTTP2_FRAME_HEADERS    0x1
#define NPE_HTTP2_FRAME_SETTINGS   0x4

typedef struct {
    uint32_t length;    /* 24‑bit in spec, but kept 32 for alignment */
    uint8_t  type;
    uint8_t  flags;
    uint32_t stream_id; /* lower 31 bits are valid */
} npe_http2_frame_hdr_t;

/* Write frame header + payload */
int npe_http2_frame_send(npe_net_socket_t *sock,
                         const npe_http2_frame_hdr_t *hdr,
                         const uint8_t *payload);

/* Read frame header (payload must be read separately) */
int npe_http2_frame_recv_hdr(npe_net_socket_t *sock,
                             npe_http2_frame_hdr_t *hdr);

#endif
