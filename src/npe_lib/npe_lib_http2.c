#include "npe_lib_http2.h"
#include "npe_lib_http2_frame.h"
#include "logger.h"
#include "npe_lib_net.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* RFC 7540 §3.5 — exactly 24 bytes, no extra spaces */
static const char http2_preface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* Maximum frame payload we accept (RFC 7540 default) */
#define NPE_HTTP2_MAX_FRAME_PAYLOAD  16384

/* Initial connection-level flow-control window (RFC 7540 §6.9.2) */
#define NPE_HTTP2_INITIAL_WINDOW     65535

/* Maximum frames to read during any single wait-loop */
#define NPE_HTTP2_MAX_HANDSHAKE_FRAMES  64
#define NPE_HTTP2_MAX_RESPONSE_FRAMES   4096

/* ─────────────────────────────────────────────
   FORWARD DECLARATIONS (static helpers)
   ───────────────────────────────────────────── */
static int  npe_http2_send_settings(npe_net_socket_t *sock);
static int  npe_http2_send_settings_ack(npe_net_socket_t *sock);
static int  npe_http2_send_ping_ack(npe_net_socket_t *sock,
                                    const uint8_t *opaque_data);
static int  npe_http2_send_window_update(npe_net_socket_t *sock,
                                         uint32_t stream_id,
                                         uint32_t increment);
static int  hpack_encode_string(const char *s,
                                uint8_t *out, int max);
static int  npe_http2_encode_headers(const char *host,
                                     const char *path,
                                     uint8_t *out, int maxlen);

/* ─────────────────────────────────────────────
   CONNECTION SETUP
   ───────────────────────────────────────────── */
int npe_http2_send_preface(npe_net_socket_t *sock)
{
    int n = npe_net_send(sock,
                         http2_preface,
                         sizeof(http2_preface) - 1);
    if (n != (int)(sizeof(http2_preface) - 1))
    {
        LOGE("HTTP/2 preface send failed: sent %d / %d",
             n, (int)(sizeof(http2_preface) - 1));
        return -1;
    }
    return 0;
}

static int npe_http2_send_settings(npe_net_socket_t *sock)
{
    /*
     * Send our client SETTINGS.
     * Each setting is 6 bytes: 2-byte id + 4-byte value.
     *
     * SETTINGS_MAX_FRAME_SIZE       (0x05) = 16384  (default, explicit)
     * SETTINGS_INITIAL_WINDOW_SIZE  (0x04) = 65535  (default, explicit)
     * SETTINGS_ENABLE_PUSH          (0x02) = 0      (we don't support push)
     */
    uint8_t settings_payload[] = {
        /* SETTINGS_ENABLE_PUSH = 0 */
        0x00, 0x02,   0x00, 0x00, 0x00, 0x00,
        /* SETTINGS_INITIAL_WINDOW_SIZE = 65535 */
        0x00, 0x04,   0x00, 0x00, 0xFF, 0xFF,
        /* SETTINGS_MAX_FRAME_SIZE = 16384 */
        0x00, 0x05,   0x00, 0x00, 0x40, 0x00,
    };

    return npe_http2_send_frame(sock,
                                NPE_HTTP2_FRAME_SETTINGS,
                                0x00,
                                0,
                                settings_payload,
                                sizeof(settings_payload));
}

static int npe_http2_send_settings_ack(npe_net_socket_t *sock)
{
    return npe_http2_send_frame(sock,
                                NPE_HTTP2_FRAME_SETTINGS,
                                0x01,   /* ACK flag */
                                0,
                                NULL,
                                0);
}

int npe_http2_init_connection(npe_net_socket_t *sock)
{
    if (!sock || !sock->is_http2)
        return -1;

    /* ── 1. Send client connection preface ── */
    LOGD("HTTP/2 preface");
    if (npe_http2_send_preface(sock) < 0)
    {
        LOGE("Failed to send HTTP/2 preface");
        return -1;
    }

    /* ── 2. Send our SETTINGS ── */
    LOGD("HTTP/2 SETTINGS");
    if (npe_http2_send_settings(sock) < 0)
    {
        LOGE("Failed to send HTTP/2 SETTINGS");
        return -1;
    }

    /* ── 3. Read server preface (SETTINGS) + our SETTINGS ACK ── */
    npe_http2_frame_hdr_t hdr;
    uint8_t payload[NPE_HTTP2_MAX_FRAME_PAYLOAD];   /* ← FIX: real stack buffer */
    int settings_received   = 0;
    int settings_ack_received = 0;
    int attempts = 0;

    while ((!settings_received || !settings_ack_received)
           && attempts < NPE_HTTP2_MAX_HANDSHAKE_FRAMES)
    {
        ++attempts;

        LOGD("Waiting for frame: settings_recv=%d, settings_ack=%d (attempt %d)",
             settings_received, settings_ack_received, attempts);

        int rc = npe_http2_read_frame(sock, &hdr,
                                      payload, sizeof(payload));   /* ← FIX */
        if (rc < 0)
        {
            LOGE("Failed to read frame during handshake");
            return -1;
        }

        LOGD("Received frame: type=%d, flags=0x%02x, stream=%u, len=%u",
             hdr.type, hdr.flags, hdr.stream_id, hdr.length);

        switch (hdr.type)
        {
        case NPE_HTTP2_FRAME_SETTINGS:
            if (hdr.flags & 0x01)
            {
                LOGD("Received SETTINGS ACK");
                settings_ack_received = 1;
            }
            else
            {
                LOGD("Received peer SETTINGS (%u bytes), sending ACK",
                     hdr.length);
                settings_received = 1;
                if (npe_http2_send_settings_ack(sock) < 0)
                {
                    LOGE("Failed to send SETTINGS ACK");
                    return -1;
                }
            }
            break;

        case NPE_HTTP2_FRAME_WINDOW_UPDATE:
            LOGD("Ignoring WINDOW_UPDATE during handshake (stream %u)",
                 hdr.stream_id);
            break;

        case NPE_HTTP2_FRAME_PING:
            LOGD("Received PING during handshake, sending PONG");
            if (!(hdr.flags & 0x01))
            {
                if (npe_http2_send_ping_ack(sock, payload) < 0)
                {
                    LOGE("Failed to send PING ACK");
                    return -1;
                }
            }
            break;

        case NPE_HTTP2_FRAME_GOAWAY:
            LOGE("Received GOAWAY during handshake (last_stream=%u)",
                 hdr.stream_id);
            return -1;

        default:
            LOGD("Ignoring frame type %d during handshake", hdr.type);
            break;
        }
    }

    if (!settings_received || !settings_ack_received)
    {
        LOGE("HTTP/2 handshake timed out after %d frames", attempts);
        return -1;
    }

    LOGD("HTTP/2 handshake complete");
    return 0;
}

/* ─────────────────────────────────────────────
   HPACK – MINIMAL ENCODER (NO HUFFMAN)
   ───────────────────────────────────────────── */
static int hpack_encode_string(const char *s,
                               uint8_t *out,
                               int max)
{
    size_t len = strlen(s);
    if (len > 127)
        return -1;   /* 1-byte length only */
    if ((int)len + 1 > max)
        return -1;
    out[0] = (uint8_t)len;   /* H=0, no Huffman */
    memcpy(out + 1, s, len);
    return (int)len + 1;
}

static int npe_http2_encode_headers(const char *host,
                                    const char *path,
                                    uint8_t *out,
                                    int maxlen)
{
    uint8_t *p = out;
    if (maxlen < 64)
        return -1;

    /*
     * RFC 7541 static table indexed representations (§6.1)
     *   0x82 → index 2  → :method GET
     *   0x87 → index 7  → :scheme https
     *   0x44 → literal with incremental indexing, name index 4 → :path
     *   0x41 → literal with incremental indexing, name index 1 → :authority
     */
    *p++ = 0x82;   /* :method  GET   */
    *p++ = 0x87;   /* :scheme  https */

    /* :path */
    *p++ = 0x44;
    int n = hpack_encode_string(path, p, maxlen - (int)(p - out));
    if (n < 0)
        return -1;
    p += n;

    /* :authority */
    *p++ = 0x41;
    n = hpack_encode_string(host, p, maxlen - (int)(p - out));
    if (n < 0)
        return -1;
    p += n;

    return (int)(p - out);
}

/* ─────────────────────────────────────────────
   FRAME SEND
   ───────────────────────────────────────────── */
int npe_http2_send_frame(npe_net_socket_t *sock,
                         uint8_t type,
                         uint8_t flags,
                         uint32_t stream_id,
                         const uint8_t *payload,
                         int payload_len)
{
    if (payload_len < 0)
        return -1;

    uint8_t hdr[9];
    hdr[0] = (uint8_t)((payload_len >> 16) & 0xFF);
    hdr[1] = (uint8_t)((payload_len >>  8) & 0xFF);
    hdr[2] = (uint8_t)((payload_len      ) & 0xFF);
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = (uint8_t)((stream_id >> 24) & 0x7F);   /* R bit = 0 */
    hdr[6] = (uint8_t)((stream_id >> 16) & 0xFF);
    hdr[7] = (uint8_t)((stream_id >>  8) & 0xFF);
    hdr[8] = (uint8_t)((stream_id      ) & 0xFF);

    if (npe_net_send(sock, hdr, 9) != 9)
    {
        LOGE("Failed to send frame header");
        return -1;
    }

    if (payload_len > 0 && payload != NULL)
    {
        if (npe_net_send(sock, payload, payload_len) != payload_len)
        {
            LOGE("Failed to send frame payload (%d bytes)", payload_len);
            return -1;
        }
    }

    return 0;
}

/* ─────────────────────────────────────────────
   FRAME READ
   ───────────────────────────────────────────── */
int npe_http2_read_frame(npe_net_socket_t *sock,
                         npe_http2_frame_hdr_t *hdr_out,
                         uint8_t *payload,
                         uint32_t max_payload)
{
    if (!sock || !hdr_out)
        return -1;

    uint8_t hdr[9];
    int n = npe_net_recv(sock, hdr, 9, sock->timeout_ms);
    if (n != 9)
    {
        LOGE("Frame header read failed: expected 9, got %d", n);
        return -1;
    }

    hdr_out->length =
        ((uint32_t)hdr[0] << 16) |
        ((uint32_t)hdr[1] <<  8) |
        (uint32_t)hdr[2];
    hdr_out->type  = hdr[3];
    hdr_out->flags = hdr[4];
    hdr_out->stream_id =
        ((uint32_t)(hdr[5] & 0x7F) << 24) |
        ((uint32_t)hdr[6] << 16) |
        ((uint32_t)hdr[7] <<  8) |
        (uint32_t)hdr[8];

    if (hdr_out->length == 0)
        return 0;

    if (hdr_out->length > max_payload)
    {
        LOGE("Frame payload too large: %u > %u (type=%d, stream=%u)",
             hdr_out->length, max_payload, hdr_out->type, hdr_out->stream_id);

        uint8_t drain[1024];
        uint32_t remaining = hdr_out->length;
        while (remaining > 0)
        {
            uint32_t chunk = remaining > sizeof(drain)
                             ? (uint32_t)sizeof(drain) : remaining;
            int r = npe_net_recv(sock, drain, chunk, sock->timeout_ms);
            if (r <= 0)
            {
                LOGE("Failed to drain oversized frame payload");
                return -1;
            }
            remaining -= (uint32_t)r;
        }

        LOGD("Drained %u bytes of oversized frame", hdr_out->length);
        return -1;
    }

    if (payload == NULL)
    {
        LOGE("Payload buffer is NULL but frame has %u bytes", hdr_out->length);
        return -1;
    }

    size_t total = 0;
    while (total < hdr_out->length)
    {
        int r = npe_net_recv(sock, payload + total, 
                             hdr_out->length - total, 
                             sock->timeout_ms);
        if (r > 0)
        {
            total += r;
        }
        else if (r == 0)
        {
            LOGE("Connection closed while reading frame payload");
            return -1;
        }
        else if (errno != EAGAIN && errno != EINTR)
        {
            LOGE("Frame payload read failed: expected %u, got %zu",
                 hdr_out->length, total);
            return -1;
        }
    }

    return (int)hdr_out->length;
}

/* ─────────────────────────────────────────────
   SEND PING ACK
   ───────────────────────────────────────────── */
static int npe_http2_send_ping_ack(npe_net_socket_t *sock,
                                   const uint8_t *opaque_data)
{
    return npe_http2_send_frame(sock,
                                NPE_HTTP2_FRAME_PING,
                                0x01,   /* ACK */
                                0,
                                opaque_data,
                                8);
}

/* ─────────────────────────────────────────────
   SEND WINDOW_UPDATE
   ───────────────────────────────────────────── */
static int npe_http2_send_window_update(npe_net_socket_t *sock,
                                        uint32_t stream_id,
                                        uint32_t increment)
{
    uint8_t buf[4];
    buf[0] = (uint8_t)((increment >> 24) & 0x7F);   /* R bit = 0 */
    buf[1] = (uint8_t)((increment >> 16) & 0xFF);
    buf[2] = (uint8_t)((increment >>  8) & 0xFF);
    buf[3] = (uint8_t)((increment      ) & 0xFF);

    return npe_http2_send_frame(sock,
                                NPE_HTTP2_FRAME_WINDOW_UPDATE,
                                0x00,
                                stream_id,
                                buf,
                                4);
}

/* ─────────────────────────────────────────────
   HTTP/2 GET
   ───────────────────────────────────────────── */
int npe_http2_send_get(npe_net_socket_t *sock,
                       const char *host,
                       const char *path,
                       npe_http_response_t *resp)
{
    if (!sock || !host || !path || !resp)
        return -1;

    uint8_t headers[512];
    int hlen = npe_http2_encode_headers(host, path,
                                        headers, sizeof(headers));
    if (hlen < 0)
    {
        LOGE("Failed to encode HPACK headers");
        return -1;
    }

    /* END_STREAM (0x01) | END_HEADERS (0x04) = 0x05 */
    if (npe_http2_send_frame(sock,
                             NPE_HTTP2_FRAME_HEADERS,
                             0x05,
                             1,          /* stream 1 */
                             headers,
                             hlen) < 0)
    {
        LOGE("Failed to send HEADERS frame");
        return -1;
    }

    LOGD("HTTP/2 HEADERS sent on stream 1 (%d bytes)", hlen);

    memset(resp, 0, sizeof(*resp));

    uint8_t payload[NPE_HTTP2_MAX_FRAME_PAYLOAD];
    npe_http2_frame_hdr_t hdr;
    int stream_ended = 0;
    int frames_read  = 0;

    /* Track how many DATA bytes we've consumed so we can
       send WINDOW_UPDATE before the window is exhausted.      */
    uint32_t data_consumed_conn   = 0;
    uint32_t data_consumed_stream = 0;

    while (!stream_ended && frames_read < NPE_HTTP2_MAX_RESPONSE_FRAMES)
    {
        ++frames_read;

        int rc = npe_http2_read_frame(sock, &hdr,
                                      payload, sizeof(payload));
        if (rc < 0)
        {
            LOGE("Failed to read frame during response (frame #%d)",
                 frames_read);
            return -1;
        }

        LOGD("Response frame #%d: type=%d, flags=0x%02x, stream=%u, len=%u",
             frames_read, hdr.type, hdr.flags, hdr.stream_id, hdr.length);

        /* ── connection-level frames (stream 0) ── */
        if (hdr.stream_id == 0)
        {
            switch (hdr.type)
            {
            case NPE_HTTP2_FRAME_SETTINGS:
                if (!(hdr.flags & 0x01))
                {
                    LOGD("Late SETTINGS from server, sending ACK");
                    if (npe_http2_send_settings_ack(sock) < 0)
                        return -1;
                }
                break;

            case NPE_HTTP2_FRAME_PING:
                if (!(hdr.flags & 0x01))
                {
                    LOGD("PING received, sending PONG");
                    if (npe_http2_send_ping_ack(sock, payload) < 0)
                        return -1;
                }
                break;

            case NPE_HTTP2_FRAME_GOAWAY:
            {
                uint32_t last_stream = 0;
                uint32_t error_code  = 0;
                if (hdr.length >= 8)
                {
                    last_stream =
                        ((uint32_t)(payload[0] & 0x7F) << 24) |
                        ((uint32_t)payload[1] << 16) |
                        ((uint32_t)payload[2] <<  8) |
                        (uint32_t)payload[3];
                    error_code =
                        ((uint32_t)payload[4] << 24) |
                        ((uint32_t)payload[5] << 16) |
                        ((uint32_t)payload[6] <<  8) |
                        (uint32_t)payload[7];
                }
                LOGE("GOAWAY: last_stream=%u, error=0x%08x",
                     last_stream, error_code);
                return -1;
            }

            case NPE_HTTP2_FRAME_WINDOW_UPDATE:
                LOGD("Connection-level WINDOW_UPDATE");
                break;

            default:
                LOGD("Ignoring connection frame type %d", hdr.type);
                break;
            }
            continue;
        }

        /* ── only process our stream ── */
        if (hdr.stream_id != 1)
        {
            LOGD("Ignoring frame on unexpected stream %u", hdr.stream_id);
            continue;
        }

        /* ── stream 1 frames ── */
        switch (hdr.type)
        {
        case NPE_HTTP2_FRAME_RST_STREAM:
        {
            uint32_t err = 0;
            if (hdr.length >= 4)
            {
                err = ((uint32_t)payload[0] << 24) |
                      ((uint32_t)payload[1] << 16) |
                      ((uint32_t)payload[2] <<  8) |
                      (uint32_t)payload[3];
            }
            LOGE("RST_STREAM on stream 1: error=0x%08x", err);
            return -1;
        }

        case NPE_HTTP2_FRAME_HEADERS:
        {
            /*
             * Minimal HPACK decode: look for indexed :status
             * RFC 7541 static table entries 8–14
             *   index  8 → :status 200  → 0x88
             *   index  9 → :status 204  → 0x89
             *   index 10 → :status 206  → 0x8A
             *   index 11 → :status 304  → 0x8B
             *   index 12 → :status 400  → 0x8C
             *   index 13 → :status 404  → 0x8D
             *   index 14 → :status 500  → 0x8E
             */
            for (uint32_t i = 0; i < hdr.length; i++)
            {
                switch (payload[i])
                {
                case 0x88: resp->status_code = 200; break;
                case 0x89: resp->status_code = 204; break;
                case 0x8A: resp->status_code = 206; break;
                case 0x8B: resp->status_code = 304; break;
                case 0x8C: resp->status_code = 400; break;
                case 0x8D: resp->status_code = 404; break;
                case 0x8E: resp->status_code = 500; break;
                default: break;
                }
            }

            LOGD("HTTP/2 status_code=%d", resp->status_code);

            if (hdr.flags & 0x01)   /* END_STREAM */
                stream_ended = 1;
            break;
        }

        case NPE_HTTP2_FRAME_DATA:
        {
            if (hdr.length > 0)
            {
                char *newbuf = realloc(resp->body,
                                       resp->body_len + hdr.length + 1);
                if (!newbuf)
                {
                    LOGE("realloc failed for body (%zu + %u)",
                         resp->body_len, hdr.length);
                    return -1;
                }

                resp->body = newbuf;
                memcpy(resp->body + resp->body_len, payload, hdr.length);
                resp->body_len     += hdr.length;
                resp->content_length = resp->body_len;
                resp->body[resp->body_len] = '\0';

                /* Track consumed bytes for flow control */
                data_consumed_conn   += hdr.length;
                data_consumed_stream += hdr.length;

                /*
                 * RFC 7540 §6.9: Send WINDOW_UPDATE when we've
                 * consumed more than half the initial window so
                 * the server doesn't stall.
                 */
                if (data_consumed_conn > NPE_HTTP2_INITIAL_WINDOW / 2)
                {
                    LOGD("Sending connection WINDOW_UPDATE: %u",
                         data_consumed_conn);
                    if (npe_http2_send_window_update(sock, 0,
                                                     data_consumed_conn) < 0)
                        return -1;
                    data_consumed_conn = 0;
                }

                if (data_consumed_stream > NPE_HTTP2_INITIAL_WINDOW / 2)
                {
                    LOGD("Sending stream 1 WINDOW_UPDATE: %u",
                         data_consumed_stream);
                    if (npe_http2_send_window_update(sock, 1,
                                                     data_consumed_stream) < 0)
                        return -1;
                    data_consumed_stream = 0;
                }
            }

            if (hdr.flags & 0x01)   /* END_STREAM */
                stream_ended = 1;
            break;
        }

        case NPE_HTTP2_FRAME_WINDOW_UPDATE:
            LOGD("Stream-level WINDOW_UPDATE");
            break;

        default:
            LOGD("Ignoring stream frame type %d", hdr.type);
            break;
        }
    }

    if (!stream_ended)
    {
        LOGE("Response not completed after %d frames", frames_read);
        return -1;
    }

    LOGD("HTTP/2 response complete: status=%d, body_len=%zu",
         resp->status_code, resp->body_len);
    return 0;
}
