#include "npe_lib_http.h"
#include "npe_http2.h"
#include <string.h>
#include <stdlib.h>

void npe_http__h2_stream_to_response(npe_h2_stream_t *s,
                                     npe_http_response_t *resp)
{
    memset(resp, 0, sizeof(*resp));

    /* Status */
    resp->status_code = s->status_code;
    snprintf(resp->status_line, sizeof(resp->status_line),
             "HTTP/2 %d", s->status_code);

    /* Headers */
    resp->header_count = s->header_count;
    resp->headers = calloc(resp->header_count, sizeof(npe_http_header_t));

    for (size_t i = 0; i < resp->header_count; i++)
    {
        /* COPY into fixed arrays (no strdup) */
        strncpy(resp->headers[i].name,
                s->header_names[i],
                sizeof(resp->headers[i].name) - 1);

        strncpy(resp->headers[i].value,
                s->header_values[i],
                sizeof(resp->headers[i].value) - 1);
    }

    /* Body → resp->body */
    if (s->body_len > 0)
    {
        resp->body = malloc(s->body_len);
        memcpy(resp->body, s->body, s->body_len);

        resp->body_len = s->body_len;
        resp->content_length = s->body_len;
    }

    /* HTTP/2 payload copy (optional but consistent) */
    resp->http2.body = malloc(s->body_len);
    memcpy(resp->http2.body, s->body, s->body_len);
    resp->http2.length = s->body_len;
    resp->http2.status_code = s->status_code;
}
