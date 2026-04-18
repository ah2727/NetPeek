#include "npe_http2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void npe_h2_global_init(void)
{
}

npe_h2_conn_t *npe_h2_conn_create(npe_net_socket_t *sock)
{
    if (!sock) return NULL;

    npe_h2_conn_t *conn = (npe_h2_conn_t *)calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->fd = sock->fd;
    conn->ssl = (SSL *)sock->ssl_handle;
    conn->timeout_ms = sock->timeout_ms;
    conn->next_stream_id = 1;
    return conn;
}

int npe_h2_conn_handshake(npe_h2_conn_t *conn)
{
    if (!conn) return -1;
    snprintf(conn->errmsg, sizeof(conn->errmsg), "http2_handshake_not_available");
    return -1;
}

void npe_h2_conn_destroy(npe_h2_conn_t *conn)
{
    if (!conn) return;

    if (conn->streams)
    {
        for (uint32_t i = 0; i < conn->stream_count; i++)
        {
            npe_h2_stream_t *s = &conn->streams[i];
            for (uint32_t h = 0; h < s->header_count; h++)
            {
                free(s->header_names ? s->header_names[h] : NULL);
                free(s->header_values ? s->header_values[h] : NULL);
            }
            free(s->header_names);
            free(s->header_values);
            free(s->body);
        }
        free(conn->streams);
    }

    free(conn->recv_buf);
    conn->recv_buf = NULL;
    free(conn);
}

int npe_h2_request(npe_h2_conn_t *conn,
                   const char *method,
                   const char *authority,
                   const char *path,
                   const char **header_names,
                   const char **header_values,
                   size_t header_count,
                   const uint8_t *body,
                   size_t body_len,
                   npe_h2_stream_t **out_stream)
{
    (void)method;
    (void)authority;
    (void)path;
    (void)header_names;
    (void)header_values;
    (void)header_count;
    (void)body;
    (void)body_len;

    if (!conn) return -1;

    if (out_stream)
    {
        *out_stream = (npe_h2_stream_t *)calloc(1, sizeof(npe_h2_stream_t));
        if (!*out_stream)
            return -1;
    }

    snprintf(conn->errmsg, sizeof(conn->errmsg), "http2_request_not_available");
    return -1;
}

int npe_h2_await_response(npe_h2_conn_t *conn, npe_h2_stream_t *stream)
{
    (void)stream;
    if (!conn) return -1;
    snprintf(conn->errmsg, sizeof(conn->errmsg), "http2_response_not_available");
    return -1;
}

bool npe_h2_alpn_is_h2(const char *alpn, size_t len)
{
    (void)alpn;
    (void)len;
    return false;
}

int npe_h2_ssl_ctx_setup_alpn(SSL_CTX *ctx)
{
    (void)ctx;
    return 0;
}
