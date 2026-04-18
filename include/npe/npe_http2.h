#ifndef NPE_HTTP2_H
#define NPE_HTTP2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "npe_lib_net.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  HTTP/2 Constants (RFC 7540 / RFC 9113)
 * ═══════════════════════════════════════════ */

#define NPE_H2_CONNECTION_PREFACE       "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define NPE_H2_CONNECTION_PREFACE_LEN   24

#define NPE_H2_DEFAULT_HEADER_TABLE_SIZE     4096
#define NPE_H2_DEFAULT_MAX_CONCURRENT        100
#define NPE_H2_DEFAULT_INITIAL_WINDOW_SIZE   65535
#define NPE_H2_DEFAULT_MAX_FRAME_SIZE        16384
#define NPE_H2_DEFAULT_MAX_HEADER_LIST_SIZE  UINT32_MAX
#define NPE_H2_MAX_FRAME_SIZE_LIMIT          16777215  /* 2^24 - 1 */
#define NPE_H2_FRAME_HEADER_SIZE             9

/* HPACK constants */
#define NPE_HPACK_DEFAULT_SIZE          4096
#define HPACK_DYNAMIC_TABLE_MAX         256

/* ═══════════════════════════════════════════════════════════════════════════
 *  Frame Types (RFC 7540 §6)
 * ═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
 *  Frame Flags
 * ═══════════════════════════════════════════════════════════════════════════ */

#define NPE_H2_FLAG_END_STREAM   0x01
#define NPE_H2_FLAG_END_HEADERS  0x04
#define NPE_H2_FLAG_PADDED       0x08
#define NPE_H2_FLAG_PRIORITY     0x20
#define NPE_H2_FLAG_ACK          0x01  /* SETTINGS & PING */

/* ═══════════════════════════════════════════
 *  Error Codes (RFC 7540 §7)
 * ═══════════════════════════════════════════ */

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
} npe_h2_error_code_t;

/* ═══════════════════════════════════════════
 *  Settings IDs (RFC 7540 §6.5.2)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    NPE_H2_SETTINGS_HEADER_TABLE_SIZE      = 0x1,
    NPE_H2_SETTINGS_ENABLE_PUSH            = 0x2,
    NPE_H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    NPE_H2_SETTINGS_INITIAL_WINDOW_SIZE    = 0x4,
    NPE_H2_SETTINGS_MAX_FRAME_SIZE         = 0x5,
    NPE_H2_SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6
} npe_h2_settings_id_t;

/* ═══════════════════════════════════════════
 *  Frame Header (wire format)
 * ═══════════════════════════════════════════ */

typedef struct {
    uint32_t length;             /* 24-bit payload length */
    uint8_t  type;               /* frame type */
    uint8_t  flags;              /* frame flags */
    uint32_t stream_id;          /* 31-bit stream identifier */
} npe_h2_frame_header_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Settings
 * ═══════════════════════════════════════════ */

typedef struct {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
} npe_h2_settings_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  HPACK Dynamic Table Entry
 * ═══════════════════════════════════════════ */

typedef struct {
    char     *name;
    char     *value;
    uint32_t  name_len;
    uint32_t  value_len;
} npe_h2_header_entry_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  HPACK Dynamic Table
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    npe_h2_header_entry_t entries[HPACK_DYNAMIC_TABLE_MAX];
    uint32_t              count;
    uint32_t              current_size;
    uint32_t              max_size;
} npe_h2_dyn_table_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Stream States (RFC 7540 §5.1)
 * ═══════════════════════════════════════════ */

typedef enum {
    NPE_H2_STREAM_IDLE          = 0,
    NPE_H2_STREAM_OPEN          = 1,
    NPE_H2_STREAM_RESERVED_LOCAL  = 2,
    NPE_H2_STREAM_RESERVED_REMOTE = 3,
    NPE_H2_STREAM_HALF_CLOSED_LOCAL  = 4,
    NPE_H2_STREAM_HALF_CLOSED_REMOTE = 5,
    NPE_H2_STREAM_CLOSED_STATE  = 6
} npe_h2_stream_state_t;

/* ═══════════════════════════════════════════
 *  Single Stream
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t               id;
    npe_h2_stream_state_t  state;
    int32_t                window_size;

    /* Accumulated response headers */
    char   **header_names;
    char   **header_values;
    uint32_t header_count;
    uint32_t header_capacity;

    /* Accumulated response body */
    uint8_t *body;
    size_t   body_len;
    size_t   body_cap;

    /* Parsed pseudo-headers */
    int      status_code;
    char     content_type[128];

    /* Flags */
    bool     headers_done;
    bool     end_stream;
    uint32_t error_code;
} npe_h2_stream_t;

/* ═══════════════════════════════════════════
 *  Connection
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    int          fd;
    SSL         *ssl;
    SSL_CTX     *ssl_ctx;

    /* Our settings (what we advertise) */
    npe_h2_settings_t local_settings;
    /* Peer's settings (what they advertise) */
    npe_h2_settings_t peer_settings;
    bool              peer_settings_acked;

    /* Flow control */
    int32_t      conn_window_send;    /* our send window */
    int32_t      conn_window_recv;    /* our recv window */

    /* Stream table */
    npe_h2_stream_t *streams;
    uint32_t         stream_count;
    uint32_t         stream_capacity;
    uint32_t         next_stream_id;   /* always odd for client */
    uint32_t         last_peer_stream;

    /* HPACK */
    npe_h2_dyn_table_t hpack_dec;      /* decoder table */
    npe_h2_dyn_table_t hpack_enc;      /* encoder table */

    /* Receive buffer (raw bytes from TLS) */
    uint8_t *recv_buf;
    size_t   recv_buf_len;
    size_t   recv_buf_cap;

    /* GOAWAY state */
    bool     goaway_received;
    uint32_t goaway_last_stream;
    uint32_t goaway_error;

    /* Timeout */
    uint32_t timeout_ms;

    /* Error string */
    char     errmsg[256];
} npe_h2_conn_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════ */

/* --- Initialization (call once at program start) --- */
void npe_h2_global_init(void);

/* --- Connection lifecycle --- */
npe_h2_conn_t *npe_h2_conn_create(npe_net_socket_t *sock);
int  npe_h2_conn_handshake(npe_h2_conn_t *conn);
void npe_h2_conn_destroy(npe_h2_conn_t *conn);

/* --- Simple request (blocking, single stream) --- */
int npe_h2_request(npe_h2_conn_t *conn,
                   const char *method,
                   const char *authority,
                   const char *path,
                   const char **header_names,
                   const char **header_values,
                   size_t header_count,
                   const uint8_t *body,
                   size_t body_len,
                   npe_h2_stream_t **out_stream);

/* --- Process incoming frames until stream is complete --- */
int npe_h2_await_response(npe_h2_conn_t *conn, npe_h2_stream_t *stream);

/* --- ALPN negotiation helper --- */
bool npe_h2_alpn_is_h2(const char *alpn, size_t len);

int  npe_h2_ssl_ctx_setup_alpn(SSL_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NPE_HTTP2_H */
