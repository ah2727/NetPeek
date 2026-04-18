#include "npe_http2_frames.h"

#include <stdlib.h>
#include <string.h>

void npe_h2_frame_encode_header(uint8_t *dst,
                                const npe_h2_frame_header_t *hdr)
{
    if (!dst || !hdr) return;

    uint32_t len = hdr->length & 0x00ffffffu;
    uint32_t sid = hdr->stream_id & 0x7fffffffu;

    dst[0] = (uint8_t)((len >> 16) & 0xff);
    dst[1] = (uint8_t)((len >> 8) & 0xff);
    dst[2] = (uint8_t)(len & 0xff);
    dst[3] = hdr->type;
    dst[4] = hdr->flags;
    dst[5] = (uint8_t)((sid >> 24) & 0x7f);
    dst[6] = (uint8_t)((sid >> 16) & 0xff);
    dst[7] = (uint8_t)((sid >> 8) & 0xff);
    dst[8] = (uint8_t)(sid & 0xff);
}

int npe_h2_frame_decode_header(npe_h2_frame_header_t *hdr,
                               const uint8_t *src,
                               size_t len)
{
    if (!hdr || !src || len < 9) return -1;

    hdr->length = ((uint32_t)src[0] << 16) |
                  ((uint32_t)src[1] << 8) |
                  (uint32_t)src[2];
    hdr->type = src[3];
    hdr->flags = src[4];
    hdr->stream_id = (((uint32_t)src[5] & 0x7fu) << 24) |
                     ((uint32_t)src[6] << 16) |
                     ((uint32_t)src[7] << 8) |
                     (uint32_t)src[8];
    return 0;
}

int npe_h2_frame_validate_header(const npe_h2_frame_header_t *hdr,
                                 uint32_t max_frame_size)
{
    if (!hdr) return -1;
    if (hdr->length > max_frame_size) return -1;
    if (hdr->stream_id > 0x7fffffffu) return -1;
    return 0;
}

int npe_h2_frame_alloc(npe_h2_frame_t *f)
{
    if (!f) return -1;
    if (f->hdr.length == 0)
    {
        f->payload = NULL;
        return 0;
    }

    f->payload = (uint8_t *)malloc(f->hdr.length);
    if (!f->payload) return -1;
    memset(f->payload, 0, f->hdr.length);
    return 0;
}

void npe_h2_frame_free(npe_h2_frame_t *f)
{
    if (!f) return;
    free(f->payload);
    f->payload = NULL;
}

const char *npe_h2_frame_type_str(uint8_t type)
{
    switch (type)
    {
    case NPE_H2_FRAME_DATA: return "DATA";
    case NPE_H2_FRAME_HEADERS: return "HEADERS";
    case NPE_H2_FRAME_PRIORITY: return "PRIORITY";
    case NPE_H2_FRAME_RST_STREAM: return "RST_STREAM";
    case NPE_H2_FRAME_SETTINGS: return "SETTINGS";
    case NPE_H2_FRAME_PUSH_PROMISE: return "PUSH_PROMISE";
    case NPE_H2_FRAME_PING: return "PING";
    case NPE_H2_FRAME_GOAWAY: return "GOAWAY";
    case NPE_H2_FRAME_WINDOW_UPDATE: return "WINDOW_UPDATE";
    case NPE_H2_FRAME_CONTINUATION: return "CONTINUATION";
    default: return "UNKNOWN";
    }
}
