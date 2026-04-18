#ifndef NPE_LIB_HTTP2_H
#define NPE_LIB_HTTP2_H

#include <stdint.h>
#include <stddef.h>
#include "npe_lib_net.h"
#include "npe_lib_http.h"
#include "npe_lib_http2_frame.h"
#ifdef __cplusplus
extern "C"
{
#endif

/* ─────────────────────────────────────────────
    *  HTTP/2 Frame Types (RFC 7540)
    * ───────────────────────────────────────────── */

#define NPE_HTTP2_FRAME_DATA 0x0
#define NPE_HTTP2_FRAME_HEADERS 0x1
#define NPE_HTTP2_FRAME_PRIORITY 0x2
#define NPE_HTTP2_FRAME_RST_STREAM 0x3
#define NPE_HTTP2_FRAME_SETTINGS 0x4
#define NPE_HTTP2_FRAME_PUSH_PROMISE 0x5
#define NPE_HTTP2_FRAME_PING 0x6
#define NPE_HTTP2_FRAME_GOAWAY 0x7
#define NPE_HTTP2_FRAME_WINDOW_UPDATE 0x8
#define NPE_HTTP2_FRAME_CONTINUATION 0x9

/* ─────────────────────────────────────────────
    *  Connection Setup
    * ───────────────────────────────────────────── */

/* Send client connection preface */
int npe_http2_send_preface(npe_net_socket_t *sock);

/* Called once after TLS setup */
int npe_http2_init_connection(npe_net_socket_t *sock);

/* ─────────────────────────────────────────────
    *  Frame I/O
    * ───────────────────────────────────────────── */

int npe_http2_send_frame(npe_net_socket_t *sock,
                            uint8_t type,
                            uint8_t flags,
                            uint32_t stream_id,
                            const uint8_t *payload,
                            int payload_len);


int npe_http2_read_frame(
    npe_net_socket_t *sock,
    npe_http2_frame_hdr_t *hdr_out,
    uint8_t *payload,
    uint32_t max_payload
);
/* ─────────────────────────────────────────────
    *  High‑level HTTP API
    * ───────────────────────────────────────────── */

/* Minimal blocking GET (single stream, id = 1) */
int npe_http2_send_get(npe_net_socket_t *sock,
                        const char *host,
                        const char *path,
                        npe_http_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_HTTP2_H */
