#ifndef NPE_HTTP2_ADAPTER_H
#define NPE_HTTP2_ADAPTER_H

#include "npe_lib_http.h"
#include "npe_http2.h"

void npe_http__h2_stream_to_response(npe_h2_stream_t *s,
                                     npe_http_response_t *resp);

#endif
