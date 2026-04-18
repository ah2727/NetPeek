/*****************************************************************************
 * npe_lib_http.c — HTTP Client Library for NPE Lua scripts
 *
 * Full HTTP/1.1 client: GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH.
 * Handles chunked transfer-encoding, redirects, and basic authentication.
 * Operates over npe_lib_net sockets; SSL is handled via npe_lib_ssl when
 * the scheme is "https".
 *****************************************************************************/

#include "npe_lib_http.h"
#include "npe_lib_net.h"
#include "npe_lib_http2.h"
#include "npe_http2.h"
#include "logger.h"
#include "npe_error.h"
#include "npe_ssl.h"
#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp */
#include <ctype.h>
#include <time.h>
#include <errno.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static double
http_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int
http_connect_socket(const npe_http_url_t *url,
                    const npe_http_request_opts_t *eff,
                    npe_net_socket_t *sock)
{
    if (!url || !sock)
        return -1;

    memset(sock, 0, sizeof(*sock));

    if (eff && eff->proxy && eff->proxy[0])
    {
        np_proxy_t proxy;
        if (np_proxy_parse(eff->proxy, &proxy) != NP_OK)
            return -1;

        int fd = np_proxy_connect(&proxy, url->host, url->port, eff->timeout_ms);
        if (fd < 0)
            return -1;

        sock->fd = fd;
        sock->type = NPE_NET_SOCK_TCP;
        sock->state = NPE_NET_STATE_CONNECTED;
        sock->timeout_ms = eff->timeout_ms;
        snprintf(sock->peer_host, sizeof(sock->peer_host), "%s", url->host);
        sock->peer_port = url->port;

        if (url->is_ssl)
        {
            if (npe_ssl_wrap(sock, url->host, eff->verify_ssl) != NPE_OK)
            {
                npe_net_tcp_disconnect(sock);
                memset(sock, 0, sizeof(*sock));
                return -1;
            }
        }

        return 0;
    }

    if (url->is_ssl)
        return npe_net_tcp_connect_ssl(url->host,
                                       url->port,
                                       eff->timeout_ms,
                                       eff->verify_ssl,
                                       sock);

    return npe_net_tcp_connect(url->host,
                               url->port,
                               eff->timeout_ms,
                               sock);
}

/* ─── Method string conversion ─── */

static const struct
{
    npe_http_method_t method;
    const char *name;
} method_table[] = {
    {NPE_HTTP_GET, "GET"},
    {NPE_HTTP_POST, "POST"},
    {NPE_HTTP_HEAD, "HEAD"},
    {NPE_HTTP_PUT, "PUT"},
    {NPE_HTTP_DELETE, "DELETE"},
    {NPE_HTTP_OPTIONS, "OPTIONS"},
    {NPE_HTTP_PATCH, "PATCH"},
    {NPE_HTTP_TRACE, "TRACE"},
    {NPE_HTTP_CONNECT, "CONNECT"},
};

#define METHOD_TABLE_SIZE (sizeof(method_table) / sizeof(method_table[0]))

const char *
npe_http_method_to_string(npe_http_method_t method)
{
    for (size_t i = 0; i < METHOD_TABLE_SIZE; i++)
    {
        if (method_table[i].method == method)
            return method_table[i].name;
    }
    return "GET";
}

int npe_http_method_from_string(const char *str, npe_http_method_t *out)
{
    if (!str || !out)
        return -1;
    for (size_t i = 0; i < METHOD_TABLE_SIZE; i++)
    {
        if (strcasecmp(str, method_table[i].name) == 0)
        {
            *out = method_table[i].method;
            return 0;
        }
    }
    return -1;
}

/* ─── URL Parsing ─── */

int npe_http_parse_url(const char *url, npe_http_url_t *out)
{
    if (!url || !out)
        return -1;
    memset(out, 0, sizeof(*out));

    const char *p = url;

    /* Scheme. */
    const char *scheme_end = strstr(p, "://");
    if (scheme_end)
    {
        size_t slen = (size_t)(scheme_end - p);
        if (slen >= sizeof(out->scheme))
            slen = sizeof(out->scheme) - 1;
        memcpy(out->scheme, p, slen);
        out->scheme[slen] = '\0';
        p = scheme_end + 3;
    }
    else
    {
        strncpy(out->scheme, "http", sizeof(out->scheme) - 1);
    }

    out->is_ssl = (strcasecmp(out->scheme, "https") == 0);

    /* Userinfo (user:pass@). */
    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    if (at && (!slash || at < slash))
    {
        size_t ulen = (size_t)(at - p);
        if (ulen >= sizeof(out->userinfo))
            ulen = sizeof(out->userinfo) - 1;
        memcpy(out->userinfo, p, ulen);
        out->userinfo[ulen] = '\0';
        p = at + 1;
    }

    /* Host (and optional :port). */
    const char *host_start = p;
    const char *host_end = p;

    if (*p == '[')
    {
        /* IPv6 literal: [::1]:port */
        const char *bracket = strchr(p, ']');
        if (!bracket)
            return -1;
        host_end = bracket + 1;
        size_t hlen = (size_t)(host_end - host_start);
        if (hlen >= sizeof(out->host))
            hlen = sizeof(out->host) - 1;
        memcpy(out->host, host_start, hlen);
        out->host[hlen] = '\0';
        p = host_end;
    }
    else
    {
        while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#')
            p++;
        host_end = p;
        size_t hlen = (size_t)(host_end - host_start);
        if (hlen >= sizeof(out->host))
            hlen = sizeof(out->host) - 1;
        memcpy(out->host, host_start, hlen);
        out->host[hlen] = '\0';
    }

    /* Port. */
    if (*p == ':')
    {
        p++;
        out->port = (uint16_t)strtoul(p, (char **)&p, 10);
    }
    else
    {
        out->port = out->is_ssl ? 443 : 80;
    }

    /* Path. */
    if (*p == '/')
    {
        const char *path_start = p;
        while (*p && *p != '?' && *p != '#')
            p++;
        size_t plen = (size_t)(p - path_start);
        if (plen >= sizeof(out->path))
            plen = sizeof(out->path) - 1;
        memcpy(out->path, path_start, plen);
        out->path[plen] = '\0';
    }
    else
    {
        strncpy(out->path, "/", sizeof(out->path) - 1);
    }

    /* Query. */
    if (*p == '?')
    {
        p++;
        const char *q_start = p;
        while (*p && *p != '#')
            p++;
        size_t qlen = (size_t)(p - q_start);
        if (qlen >= sizeof(out->query))
            qlen = sizeof(out->query) - 1;
        memcpy(out->query, q_start, qlen);
        out->query[qlen] = '\0';
    }

    /* Fragment. */
    if (*p == '#')
    {
        p++;
        strncpy(out->fragment, p, sizeof(out->fragment) - 1);
    }

    return 0;
}

int npe_http_build_url(const npe_http_url_t *parts, char *out_buf, size_t buf_size)
{
    if (!parts || !out_buf || buf_size == 0)
        return -1;

    int n;
    bool default_port = (parts->is_ssl && parts->port == 443) ||
                        (!parts->is_ssl && parts->port == 80);

    if (default_port)
    {
        n = snprintf(out_buf, buf_size, "%s://%s%s%s%s%s%s",
                     parts->scheme,
                     parts->host,
                     parts->path,
                     parts->query[0] ? "?" : "",
                     parts->query,
                     parts->fragment[0] ? "#" : "",
                     parts->fragment);
    }
    else
    {
        n = snprintf(out_buf, buf_size, "%s://%s:%u%s%s%s%s%s",
                     parts->scheme,
                     parts->host,
                     (unsigned)parts->port,
                     parts->path,
                     parts->query[0] ? "?" : "",
                     parts->query,
                     parts->fragment[0] ? "#" : "",
                     parts->fragment);
    }

    return (n >= 0 && (size_t)n < buf_size) ? n : -1;
}

/* ─── URL Encode/Decode ─── */

int npe_http_url_encode(const char *input, char *out_buf, size_t buf_size)
{
    if (!input || !out_buf || buf_size == 0)
        return -1;

    size_t j = 0;
    for (size_t i = 0; input[i] && j < buf_size - 1; i++)
    {
        unsigned char c = (unsigned char)input[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            out_buf[j++] = (char)c;
        }
        else
        {
            if (j + 3 >= buf_size)
                break;
            snprintf(out_buf + j, 4, "%%%02X", c);
            j += 3;
        }
    }
    out_buf[j] = '\0';
    return (int)j;
}

int npe_http_url_decode(const char *input, char *out_buf, size_t buf_size)
{
    if (!input || !out_buf || buf_size == 0)
        return -1;

    size_t j = 0;
    for (size_t i = 0; input[i] && j < buf_size - 1; i++)
    {
        if (input[i] == '%' && isxdigit((unsigned char)input[i + 1]) && isxdigit((unsigned char)input[i + 2]))
        {
            char hex[3] = {input[i + 1], input[i + 2], '\0'};
            out_buf[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        }
        else if (input[i] == '+')
        {
            out_buf[j++] = ' ';
        }
        else
        {
            out_buf[j++] = input[i];
        }
    }
    out_buf[j] = '\0';
    return (int)j;
}

/* ─── Response init / free ─── */

void npe_http_response_init(npe_http_response_t *resp)
{
    if (!resp)
        return;
    memset(resp, 0, sizeof(*resp));
}

void npe_lib_http_response_free(npe_http_response_t *resp)
{
    if (!resp)
        return;
    free(resp->body);
    resp->body = NULL;
    free(resp->headers);
    resp->headers = NULL;
    free(resp->cookies);
    resp->cookies = NULL;
    free(resp->raw_response);
    resp->raw_response = NULL;
}

/* ─── Request opts init / free ─── */

void npe_http_opts_init(npe_http_request_opts_t *opts)
{
    if (!opts)
        return;
    memset(opts, 0, sizeof(*opts));
    opts->timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;
    opts->max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;
    opts->verify_ssl = false;
    opts->follow_redirects = true;
}

void npe_http_opts_free(npe_http_request_opts_t *opts)
{
    if (!opts)
        return;
    free(opts->custom_headers);
    opts->custom_headers = NULL;
    opts->custom_header_count = 0;
}

/* ─── Header lookup ─── */

const char *
npe_http_get_header(const npe_http_response_t *resp, const char *name)
{
    if (!resp || !name)
        return NULL;
    for (size_t i = 0; i < resp->header_count; i++)
    {
        if (strcasecmp(resp->headers[i].name, name) == 0)
            return resp->headers[i].value;
    }
    return NULL;
}

bool npe_http_has_header(const npe_http_response_t *resp, const char *name)
{
    return npe_http_get_header(resp, name) != NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal: Build the raw HTTP request
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Simple Base64 encoder for Basic auth (no padding requirement for short inputs).
 */
static void
base64_encode_basic(const char *input, size_t len, char *out, size_t out_size)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t j = 0;
    for (size_t i = 0; i < len && j + 4 < out_size; i += 3)
    {
        uint32_t n = ((uint32_t)(unsigned char)input[i]) << 16;
        if (i + 1 < len)
            n |= ((uint32_t)(unsigned char)input[i + 1]) << 8;
        if (i + 2 < len)
            n |= ((uint32_t)(unsigned char)input[i + 2]);

        out[j++] = b64[(n >> 18) & 0x3F];
        out[j++] = b64[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64[n & 0x3F] : '=';
    }
    out[j] = '\0';
}

/**
 * Build the raw request string.
 * Returns a heap-allocated string; caller must free().
 */
static char *
build_request(npe_http_method_t method,
              const npe_http_url_t *url,
              const npe_http_request_opts_t *opts,
              size_t *out_len)
{
    const char *method_str = npe_http_method_to_string(method);
    const char *user_agent = (opts && opts->user_agent)
                                 ? opts->user_agent
                                 : NPE_HTTP_DEFAULT_USER_AGENT;

    /* Build the request URI (path + query). */
    char uri[NPE_HTTP_MAX_URL_LENGTH];
    if (url->query[0])
        snprintf(uri, sizeof(uri), "%s?%s", url->path, url->query);
    else
        snprintf(uri, sizeof(uri), "%s", url->path);

    /* Estimate total size generously. */
    size_t est_size = 4096;
    if (opts && opts->body_len > 0)
        est_size += opts->body_len;
    if (opts)
    {
        for (size_t i = 0; i < opts->custom_header_count; i++)
            est_size += 512;
    }

    char *req = malloc(est_size);
    if (!req)
        return NULL;

    int pos = 0;

    /* Request line. */
    pos += snprintf(req + pos, est_size - (size_t)pos,
                    "%s %s %s\r\n", method_str, uri, NPE_HTTP_DEFAULT_HTTP_VERSION);

    /* Host header. */
    bool default_port = (url->is_ssl && url->port == 443) ||
                        (!url->is_ssl && url->port == 80);
    if (default_port)
        pos += snprintf(req + pos, est_size - (size_t)pos,
                        "Host: %s\r\n", url->host);
    else
        pos += snprintf(req + pos, est_size - (size_t)pos,
                        "Host: %s:%u\r\n", url->host, (unsigned)url->port);

    /* User-Agent. */
    pos += snprintf(req + pos, est_size - (size_t)pos,
                    "User-Agent: %s\r\n", user_agent);

    /* Connection. */
    pos += snprintf(req + pos, est_size - (size_t)pos,
                    "Connection: close\r\n");

    /* Accept. */
    pos += snprintf(req + pos, est_size - (size_t)pos,
                    "Accept: */*\r\n");

    /* Content-Type and Content-Length. */
    if (opts && opts->body && opts->body_len > 0)
    {
        const char *ct = opts->content_type ? opts->content_type
                                            : "application/x-www-form-urlencoded";
        pos += snprintf(req + pos, est_size - (size_t)pos,
                        "Content-Type: %s\r\n", ct);
        pos += snprintf(req + pos, est_size - (size_t)pos,
                        "Content-Length: %zu\r\n", opts->body_len);
    }

    /* Basic authentication. */
    if (opts && opts->auth_username && opts->auth_password)
    {
        char cred[512];
        snprintf(cred, sizeof(cred), "%s:%s",
                 opts->auth_username, opts->auth_password);
        char b64[700];
        base64_encode_basic(cred, strlen(cred), b64, sizeof(b64));
        pos += snprintf(req + pos, est_size - (size_t)pos,
                        "Authorization: Basic %s\r\n", b64);
    }

    /* Custom headers. */
    if (opts)
    {
        for (size_t i = 0; i < opts->custom_header_count; i++)
        {
            pos += snprintf(req + pos, est_size - (size_t)pos,
                            "%s: %s\r\n",
                            opts->custom_headers[i].name,
                            opts->custom_headers[i].value);
        }
    }

    /* End of headers. */
    pos += snprintf(req + pos, est_size - (size_t)pos, "\r\n");

    /* Body. */
    if (opts && opts->body && opts->body_len > 0)
    {
        if ((size_t)pos + opts->body_len >= est_size)
        {
            est_size = (size_t)pos + opts->body_len + 1;
            char *tmp = realloc(req, est_size);
            if (!tmp)
            {
                free(req);
                return NULL;
            }
            req = tmp;
        }
        memcpy(req + pos, opts->body, opts->body_len);
        pos += (int)opts->body_len;
    }

    req[pos] = '\0';
    if (out_len)
        *out_len = (size_t)pos;
    return req;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal: Parse HTTP Response
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Parse the status line: "HTTP/1.1 200 OK\r\n"
 */
static int
parse_status_line(const char *data, npe_http_response_t *resp)
{
    /* Copy status line. */
    const char *eol = strstr(data, "\r\n");
    if (!eol)
        return -1;

    size_t line_len = (size_t)(eol - data);
    if (line_len >= sizeof(resp->status_line))
        line_len = sizeof(resp->status_line) - 1;
    memcpy(resp->status_line, data, line_len);
    resp->status_line[line_len] = '\0';

    /* Extract status code. */
    const char *sp = strchr(data, ' ');
    if (!sp)
        return -1;
    resp->status_code = (int)strtol(sp + 1, NULL, 10);

    return 0;
}

/**
 * Parse response headers.
 * `header_block` points to the first line after the status line.
 */
static int
parse_headers(const char *header_block, npe_http_response_t *resp)
{
    /* Count headers. */
    size_t count = 0;
    const char *p = header_block;
    while (p && *p && !(p[0] == '\r' && p[1] == '\n'))
    {
        const char *eol = strstr(p, "\r\n");
        if (!eol)
            break;
        count++;
        p = eol + 2;
    }

    if (count == 0)
        return 0;
    if (count > NPE_HTTP_MAX_HEADERS)
        count = NPE_HTTP_MAX_HEADERS;

    resp->headers = calloc(count, sizeof(npe_http_header_t));
    if (!resp->headers)
        return -1;

    p = header_block;
    size_t idx = 0;
    while (p && *p && !(p[0] == '\r' && p[1] == '\n') && idx < count)
    {
        const char *eol = strstr(p, "\r\n");
        if (!eol)
            break;

        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (colon)
        {
            size_t nlen = (size_t)(colon - p);
            if (nlen >= sizeof(resp->headers[idx].name))
                nlen = sizeof(resp->headers[idx].name) - 1;
            memcpy(resp->headers[idx].name, p, nlen);
            resp->headers[idx].name[nlen] = '\0';

            /* Skip ": " before value. */
            const char *val = colon + 1;
            while (val < eol && *val == ' ')
                val++;
            size_t vlen = (size_t)(eol - val);
            if (vlen >= sizeof(resp->headers[idx].value))
                vlen = sizeof(resp->headers[idx].value) - 1;
            memcpy(resp->headers[idx].value, val, vlen);
            resp->headers[idx].value[vlen] = '\0';

            idx++;
        }

        p = eol + 2;
    }

    resp->header_count = idx;
    return 0;
}

/**
 * Decode chunked transfer-encoding body.
 * Returns heap-allocated decoded body; sets *out_len.
 */
static char *
decode_chunked(const char *data, size_t data_len, size_t *out_len)
{
    size_t cap = data_len;
    char *out = malloc(cap + 1);
    if (!out)
        return NULL;

    size_t total = 0;
    const char *p = data;
    const char *end = data + data_len;

    while (p < end)
    {
        /* Read chunk size (hex). */
        char *size_end = NULL;
        unsigned long chunk_size = strtoul(p, &size_end, 16);
        if (size_end == p)
            break;

        /* Skip to the data (past \r\n after size). */
        const char *crlf = strstr(p, "\r\n");
        if (!crlf)
            break;
        p = crlf + 2;

        if (chunk_size == 0)
            break; /* last chunk */

        if (p + chunk_size > end)
            chunk_size = (unsigned long)(end - p);

        if (total + chunk_size > cap)
        {
            cap = (total + chunk_size) * 2;
            char *tmp = realloc(out, cap + 1);
            if (!tmp)
            {
                free(out);
                return NULL;
            }
            out = tmp;
        }

        memcpy(out + total, p, chunk_size);
        total += chunk_size;
        p += chunk_size;

        /* Skip trailing \r\n after chunk data. */
        if (p + 2 <= end && p[0] == '\r' && p[1] == '\n')
            p += 2;
    }

    out[total] = '\0';
    *out_len = total;
    return out;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Core: npe_http_request
 * ═══════════════════════════════════════════════════════════════════════════ */
int npe_http_request(npe_http_method_t method,
                     const char *url_str,
                     const npe_http_request_opts_t *opts,
                     npe_http_response_t *out_resp)
{
    if (!url_str || !url_str[0] || !out_resp)
        return -1;

    npe_http_request_opts_t eff;
    if (opts)
        memcpy(&eff, opts, sizeof(eff));
    else
        npe_http_opts_init(&eff);

    if (eff.timeout_ms == 0)
        eff.timeout_ms = NPE_HTTP_DEFAULT_TIMEOUT_MS;
    if (eff.max_redirects == 0)
        eff.max_redirects = NPE_HTTP_DEFAULT_MAX_REDIRECTS;

    npe_http_response_init(out_resp);

    char current_url[NPE_HTTP_MAX_URL_LENGTH];
    strncpy(current_url, url_str, sizeof(current_url) - 1);
    current_url[sizeof(current_url) - 1] = '\0';

    uint32_t redirects = 0;
    double start_time = http_now_ms();

    for (;;)
    {
        npe_http_url_t url;
        if (npe_http_parse_url(current_url, &url) < 0)
        {
            npe_error_log(NPE_ERROR_INVALID_ARG, "http",
                          "Failed to parse URL: %s", current_url);
            return -1;
        }

        /* ── CONNECT (TCP or TCP+TLS+ALPN) ── */
        npe_net_socket_t sock;
        int rc;

        rc = http_connect_socket(&url, &eff, &sock);

        if (rc < 0)
        {
            npe_error_log(NPE_ERROR_IO, "http",
                          "Connection to %s:%u failed", url.host, url.port);
            return -1;
        }

        /* ───────────────────────────────
           HTTP/2 PATH
           ─────────────────────────────── */
        if (sock.is_http2)
        {
            if (npe_http2_init_connection(&sock) < 0)
            {
                npe_net_tcp_disconnect(&sock);
                return -1;
            }

            if (method != NPE_HTTP_GET)
            {
                npe_net_tcp_disconnect(&sock);
                return -1;
            }

            const char *path = url.path[0] ? url.path : "/";

            if (npe_http2_send_get(&sock, url.host, path, out_resp) < 0)
            {
                npe_net_tcp_disconnect(&sock);
                return -1;
            }

            out_resp->is_ssl = true;
            out_resp->elapsed_ms = http_now_ms() - start_time;

            strncpy(out_resp->redirect_url,
                    current_url,
                    sizeof(out_resp->redirect_url) - 1);
            out_resp->redirect_url[sizeof(out_resp->redirect_url) - 1] = '\0';

            npe_net_tcp_disconnect(&sock);
            return 0;
        }

        /* ───────────────────────────────
           HTTP/1.1 PATH
           ─────────────────────────────── */

        size_t req_len = 0;
        char *raw_req = build_request(method, &url, &eff, &req_len);
        if (!raw_req)
        {
            npe_net_tcp_disconnect(&sock);
            return -1;
        }

        ssize_t sent = npe_net_send(&sock, raw_req, req_len);
        free(raw_req);

        if (sent < 0 || (size_t)sent != req_len)
        {
            npe_net_tcp_disconnect(&sock);
            return -1;
        }

        size_t resp_cap = 16384;
        size_t resp_len = 0;

        char *resp_buf = malloc(resp_cap + 1);
        if (!resp_buf)
        {
            npe_net_tcp_disconnect(&sock);
            return -1;
        }

        for (;;)
        {
            if (resp_len + 4096 + 1 > resp_cap)
            {
                size_t new_cap = resp_cap * 2;
                if (new_cap > NPE_HTTP_MAX_BODY_SIZE + NPE_HTTP_MAX_HEADER_SIZE)
                {
                    free(resp_buf);
                    npe_net_tcp_disconnect(&sock);
                    return -1;
                }

                char *tmp = realloc(resp_buf, new_cap + 1);
                if (!tmp)
                {
                    free(resp_buf);
                    npe_net_tcp_disconnect(&sock);
                    return -1;
                }

                resp_buf = tmp;
                resp_cap = new_cap;
            }

            ssize_t n = npe_net_recv(&sock,
                                     resp_buf + resp_len,
                                     resp_cap - resp_len,
                                     eff.timeout_ms);

            if (n <= 0)
                break;

            resp_len += (size_t)n;
        }

        resp_buf[resp_len] = '\0';

        npe_net_tcp_disconnect(&sock);

        /* ── PARSE RESPONSE ── */

        const char *header_end = strstr(resp_buf, "\r\n\r\n");
        if (!header_end)
        {
            free(resp_buf);
            return -1;
        }

        const char *body_start = header_end + 4;
        size_t body_raw_len = resp_len - (size_t)(body_start - resp_buf);

        if (parse_status_line(resp_buf, out_resp) < 0)
        {
            free(resp_buf);
            return -1;
        }

        const char *first_header = strstr(resp_buf, "\r\n");
        if (first_header)
            parse_headers(first_header + 2, out_resp);

        /* ── REDIRECT HANDLING ── */

        if (eff.follow_redirects &&
            (out_resp->status_code == 301 ||
             out_resp->status_code == 302 ||
             out_resp->status_code == 303 ||
             out_resp->status_code == 307 ||
             out_resp->status_code == 308))
        {
            if (redirects >= eff.max_redirects)
            {
                free(resp_buf);
                return -1;
            }

            const char *location = npe_http_get_header(out_resp, "Location");
            if (!location)
            {
                free(resp_buf);
                return -1;
            }

            if (location[0] == '/')
            {
                snprintf(current_url, sizeof(current_url),
                         "%s://%s:%u%s",
                         url.scheme, url.host, url.port, location);
            }
            else
            {
                strncpy(current_url, location, sizeof(current_url) - 1);
                current_url[sizeof(current_url) - 1] = '\0';
            }

            redirects++;
            out_resp->redirect_count = redirects;

            free(resp_buf);
            free(out_resp->headers);

            out_resp->headers = NULL;
            out_resp->header_count = 0;

            if (out_resp->status_code == 303)
                method = NPE_HTTP_GET;

            continue;
        }

        /* ── BODY ── */

        if (!eff.no_body && method != NPE_HTTP_HEAD && body_raw_len > 0)
        {
            const char *te = npe_http_get_header(out_resp, "Transfer-Encoding");

            if (te && strstr(te, "chunked"))
            {
                out_resp->body = decode_chunked(body_start,
                                                body_raw_len,
                                                &out_resp->body_len);
            }
            else
            {
                out_resp->body = malloc(body_raw_len + 1);

                if (out_resp->body)
                {
                    memcpy(out_resp->body, body_start, body_raw_len);
                    out_resp->body[body_raw_len] = '\0';
                    out_resp->body_len = body_raw_len;
                }
            }
        }

        const char *cl = npe_http_get_header(out_resp, "Content-Length");

        out_resp->content_length =
            cl ? (size_t)strtoul(cl, NULL, 10)
               : out_resp->body_len;

        strncpy(out_resp->redirect_url,
                current_url,
                sizeof(out_resp->redirect_url) - 1);

        out_resp->redirect_url[sizeof(out_resp->redirect_url) - 1] = '\0';

        out_resp->is_ssl = url.is_ssl;
        out_resp->elapsed_ms = http_now_ms() - start_time;

        if (eff.raw_response)
        {
            out_resp->raw_response = resp_buf;
            out_resp->raw_response_len = resp_len;
        }
        else
        {
            free(resp_buf);
        }

        return 0;
    }
}


/* ── Convenience wrappers ── */

int npe_http_get(const char *url, const npe_http_request_opts_t *opts,
                 npe_http_response_t *out)
{
    return npe_http_request(NPE_HTTP_GET, url, opts, out);
}

int npe_http_post(const char *url, const char *body, size_t body_len,
                  const npe_http_request_opts_t *opts, npe_http_response_t *out)
{
    npe_http_request_opts_t eff;
    if (opts)
        memcpy(&eff, opts, sizeof(eff));
    else
        npe_http_opts_init(&eff);
    eff.body = body;
    eff.body_len = body_len;
    return npe_http_request(NPE_HTTP_POST, url, &eff, out);
}

int npe_http_head(const char *url, const npe_http_request_opts_t *opts,
                  npe_http_response_t *out)
{
    return npe_http_request(NPE_HTTP_HEAD, url, opts, out);
}

int npe_http_put(const char *url, const char *body, size_t body_len,
                 const npe_http_request_opts_t *opts, npe_http_response_t *out)
{
    npe_http_request_opts_t eff;
    if (opts)
        memcpy(&eff, opts, sizeof(eff));
    else
        npe_http_opts_init(&eff);
    eff.body = body;
    eff.body_len = body_len;
    return npe_http_request(NPE_HTTP_PUT, url, &eff, out);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua Helpers: Push Response / Parse Options
 * ═══════════════════════════════════════════════════════════════════════════ */

int npe_http_push_response(lua_State *L, const npe_http_response_t *resp)
{
    lua_newtable(L);

    lua_pushinteger(L, resp->status_code);
    lua_setfield(L, -2, "status");

    lua_pushstring(L, resp->status_line);
    lua_setfield(L, -2, "status_line");

    /* Headers as a table. */
    lua_newtable(L);
    for (size_t i = 0; i < resp->header_count; i++)
    {
        lua_pushstring(L, resp->headers[i].value);
        lua_setfield(L, -2, resp->headers[i].name);
    }
    lua_setfield(L, -2, "headers");

    /* Body. */
    if (resp->body && resp->body_len > 0)
        lua_pushlstring(L, resp->body, resp->body_len);
    else
        lua_pushstring(L, "");
    lua_setfield(L, -2, "body");

    lua_pushinteger(L, (lua_Integer)resp->content_length);
    lua_setfield(L, -2, "content_length");

    lua_pushstring(L, resp->redirect_url);
    lua_setfield(L, -2, "redirect_url");

    lua_pushnumber(L, resp->elapsed_ms);
    lua_setfield(L, -2, "elapsed_ms");

    lua_pushboolean(L, resp->is_ssl);
    lua_setfield(L, -2, "ssl");

    return 1;
}

int npe_http_parse_lua_opts(lua_State *L, int idx, npe_http_request_opts_t *opts)
{
    npe_http_opts_init(opts);

    if (!lua_istable(L, idx))
        return 0;

    /* timeout_ms */
    lua_getfield(L, idx, "timeout_ms");
    if (lua_isinteger(L, -1))
        opts->timeout_ms = (uint32_t)lua_tointeger(L, -1);
    lua_pop(L, 1);

    /* max_redirects */
    lua_getfield(L, idx, "max_redirects");
    if (lua_isinteger(L, -1))
        opts->max_redirects = (uint32_t)lua_tointeger(L, -1);
    lua_pop(L, 1);

    /* content_type */
    lua_getfield(L, idx, "content_type");
    if (lua_isstring(L, -1))
        opts->content_type = lua_tostring(L, -1);
    lua_pop(L, 1);

    /* user_agent */
    lua_getfield(L, idx, "user_agent");
    if (lua_isstring(L, -1))
        opts->user_agent = lua_tostring(L, -1);
    lua_pop(L, 1);

    /* body */
    lua_getfield(L, idx, "body");
    if (lua_isstring(L, -1))
        opts->body = lua_tolstring(L, -1, &opts->body_len);
    lua_pop(L, 1);

    /* no_body */
    lua_getfield(L, idx, "no_body");
    if (lua_isboolean(L, -1))
        opts->no_body = lua_toboolean(L, -1);
    lua_pop(L, 1);

    /* raw */
    lua_getfield(L, idx, "raw");
    if (lua_isboolean(L, -1))
        opts->raw_response = lua_toboolean(L, -1);
    lua_pop(L, 1);

    /* verify_ssl */
    lua_getfield(L, idx, "verify_ssl");
    if (lua_isboolean(L, -1))
        opts->verify_ssl = lua_toboolean(L, -1);
    lua_pop(L, 1);

    /* proxy */
    lua_getfield(L, idx, "proxy");
    if (lua_isstring(L, -1))
        opts->proxy = lua_tostring(L, -1);
    lua_pop(L, 1);

    /* auth */
    lua_getfield(L, idx, "auth");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "username");
        if (lua_isstring(L, -1))
            opts->auth_username = lua_tostring(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "password");
        if (lua_isstring(L, -1))
            opts->auth_password = lua_tostring(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    /* headers (table of key=value) */
    lua_getfield(L, idx, "headers");
    if (lua_istable(L, -1))
    {
        /* Count entries. */
        size_t hcount = 0;
        lua_pushnil(L);
        while (lua_next(L, -2))
        {
            hcount++;
            lua_pop(L, 1);
        }

        if (hcount > 0)
        {
            opts->custom_headers = calloc(hcount, sizeof(npe_http_header_t));
            if (opts->custom_headers)
            {
                size_t hi = 0;
                lua_pushnil(L);
                while (lua_next(L, -2) && hi < hcount)
                {
                    if (lua_isstring(L, -2) && lua_isstring(L, -1))
                    {
                        strncpy(opts->custom_headers[hi].name,
                                lua_tostring(L, -2),
                                sizeof(opts->custom_headers[hi].name) - 1);
                        strncpy(opts->custom_headers[hi].value,
                                lua_tostring(L, -1),
                                sizeof(opts->custom_headers[hi].value) - 1);
                        hi++;
                    }
                    lua_pop(L, 1);
                }
                opts->custom_header_count = hi;
            }
        }
    }
    lua_pop(L, 1);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Lua-C Bindings
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Generic Lua request helper.
 * Stack: method_enum is passed by the caller wrapper; the Lua stack has:
 *   (url [, body] [, options])
 */
static int
http_lua_do_request(lua_State *L, npe_http_method_t method, bool has_body_arg)
{
    const char *url = luaL_checkstring(L, 1);
    int opts_idx = 2;

    npe_http_request_opts_t opts;
    npe_http_opts_init(&opts);

    if (has_body_arg && lua_isstring(L, 2))
    {
        opts.body = lua_tolstring(L, 2, &opts.body_len);
        opts_idx = 3;
    }

    if (lua_istable(L, opts_idx))
        npe_http_parse_lua_opts(L, opts_idx, &opts);

    npe_http_response_t resp;
    npe_http_response_init(&resp);

    int rc = npe_http_request(method, url, &opts, &resp);
    npe_http_opts_free(&opts);
    LOGD("DEBUG: rc=%d, status_code=%d, status_line='%s'\n",
         rc, resp.status_code, resp.status_line);
    if (rc < 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line : "HTTP request failed");
        npe_lib_http_response_free(&resp);
        return 2;
    }

    npe_http_push_response(L, &resp);
    npe_lib_http_response_free(&resp);
    return 1;
}

int npe_http_l_get(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_GET, false); }
int npe_http_l_post(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_POST, true); }
int npe_http_l_head(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_HEAD, false); }
int npe_http_l_put(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_PUT, true); }
int npe_http_l_delete(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_DELETE, false); }
int npe_http_l_options(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_OPTIONS, false); }
int npe_http_l_patch(lua_State *L) { return http_lua_do_request(L, NPE_HTTP_PATCH, true); }

int npe_http_l_request(lua_State *L)
{
    const char *method_str = luaL_checkstring(L, 1);
    npe_http_method_t method;
    if (npe_http_method_from_string(method_str, &method) < 0)
        return luaL_error(L, "Unknown HTTP method: %s", method_str);

    /* Shift arguments: url is at 2, body/opts at 3+ */
    const char *url = luaL_checkstring(L, 2);

    npe_http_request_opts_t opts;
    npe_http_opts_init(&opts);

    /* Check for body at position 3 and options at 3 or 4. */
    int opts_idx = 3;
    if (lua_isstring(L, 3))
    {
        opts.body = lua_tolstring(L, 3, &opts.body_len);
        opts_idx = 4;
    }

    if (lua_istable(L, opts_idx))
        npe_http_parse_lua_opts(L, opts_idx, &opts);

    npe_http_response_t resp;
    npe_http_response_init(&resp);

    int rc = npe_http_request(method, url, &opts, &resp);
    npe_http_opts_free(&opts);
    LOGD("DEBUG: rc=%d, status_code=%d, status_line='%s'\n",
         rc, resp.status_code, resp.status_line);
    if (rc < 0)
    {
        lua_pushnil(L);
        lua_pushstring(L, resp.status_line[0] ? resp.status_line : "HTTP request failed");
        npe_lib_http_response_free(&resp);
        return 2;
    }

    npe_http_push_response(L, &resp);
    npe_lib_http_response_free(&resp);
    return 1;
}

int npe_http_l_parse_url(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);
    npe_http_url_t parts;
    if (npe_http_parse_url(url, &parts) < 0)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "Failed to parse URL");
        return 2;
    }

    lua_newtable(L);
    lua_pushstring(L, parts.scheme);
    lua_setfield(L, -2, "scheme");
    lua_pushstring(L, parts.host);
    lua_setfield(L, -2, "host");
    lua_pushinteger(L, parts.port);
    lua_setfield(L, -2, "port");
    lua_pushstring(L, parts.path);
    lua_setfield(L, -2, "path");
    lua_pushstring(L, parts.query);
    lua_setfield(L, -2, "query");
    lua_pushstring(L, parts.fragment);
    lua_setfield(L, -2, "fragment");
    lua_pushstring(L, parts.userinfo);
    lua_setfield(L, -2, "userinfo");
    lua_pushboolean(L, parts.is_ssl);
    lua_setfield(L, -2, "is_ssl");

    return 1;
}

int npe_http_l_build_url(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);

    npe_http_url_t parts;
    memset(&parts, 0, sizeof(parts));

    lua_getfield(L, 1, "scheme");
    if (lua_isstring(L, -1))
        strncpy(parts.scheme, lua_tostring(L, -1), sizeof(parts.scheme) - 1);
    else
        strcpy(parts.scheme, "http");
    lua_pop(L, 1);

    lua_getfield(L, 1, "host");
    if (lua_isstring(L, -1))
        strncpy(parts.host, lua_tostring(L, -1), sizeof(parts.host) - 1);
    lua_pop(L, 1);

    lua_getfield(L, 1, "port");
    if (lua_isinteger(L, -1))
        parts.port = (uint16_t)lua_tointeger(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, 1, "path");
    if (lua_isstring(L, -1))
        strncpy(parts.path, lua_tostring(L, -1), sizeof(parts.path) - 1);
    else
        strcpy(parts.path, "/");
    lua_pop(L, 1);

    lua_getfield(L, 1, "query");
    if (lua_isstring(L, -1))
        strncpy(parts.query, lua_tostring(L, -1), sizeof(parts.query) - 1);
    lua_pop(L, 1);

    lua_getfield(L, 1, "fragment");
    if (lua_isstring(L, -1))
        strncpy(parts.fragment, lua_tostring(L, -1), sizeof(parts.fragment) - 1);
    lua_pop(L, 1);

    parts.is_ssl = (strcasecmp(parts.scheme, "https") == 0);
    if (parts.port == 0)
        parts.port = parts.is_ssl ? 443 : 80;

    char buf[NPE_HTTP_MAX_URL_LENGTH];
    if (npe_http_build_url(&parts, buf, sizeof(buf)) < 0)
    {
        lua_pushnil(L);
        return 1;
    }

    lua_pushstring(L, buf);
    return 1;
}

int npe_http_l_url_encode(lua_State *L)
{
    const char *input = luaL_checkstring(L, 1);
    char buf[NPE_HTTP_MAX_URL_LENGTH * 3];
    int len = npe_http_url_encode(input, buf, sizeof(buf));
    if (len < 0)
    {
        lua_pushnil(L);
        return 1;
    }
    lua_pushlstring(L, buf, (size_t)len);
    return 1;
}

int npe_http_l_url_decode(lua_State *L)
{
    const char *input = luaL_checkstring(L, 1);
    char buf[NPE_HTTP_MAX_URL_LENGTH];
    int len = npe_http_url_decode(input, buf, sizeof(buf));
    if (len < 0)
    {
        lua_pushnil(L);
        return 1;
    }
    lua_pushlstring(L, buf, (size_t)len);
    return 1;
}

int npe_http_l_build_query(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);

    luaL_Buffer B;
    luaL_buffinit(L, &B);

    bool first = true;
    lua_pushnil(L);
    while (lua_next(L, 1))
    {
        if (lua_isstring(L, -2))
        {
            if (!first)
                luaL_addchar(&B, '&');
            first = false;

            const char *key = lua_tostring(L, -2);
            const char *val = lua_tostring(L, -1);

            char enc_key[1024], enc_val[4096];
            npe_http_url_encode(key, enc_key, sizeof(enc_key));
            if (val)
                npe_http_url_encode(val, enc_val, sizeof(enc_val));
            else
                enc_val[0] = '\0';

            luaL_addstring(&B, enc_key);
            luaL_addchar(&B, '=');
            luaL_addstring(&B, enc_val);
        }
        lua_pop(L, 1);
    }

    luaL_pushresult(&B);
    return 1;
}

int npe_http_l_get_header(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);
    const char *name = luaL_checkstring(L, 2);

    lua_getfield(L, 1, "headers");
    if (!lua_istable(L, -1))
    {
        lua_pushnil(L);
        return 1;
    }

    /* Case-insensitive search. */
    lua_pushnil(L);
    while (lua_next(L, -2))
    {
        if (lua_isstring(L, -2))
        {
            const char *key = lua_tostring(L, -2);
            if (strcasecmp(key, name) == 0)
                return 1; /* value is on top */
        }
        lua_pop(L, 1);
    }

    lua_pushnil(L);
    return 1;
}

int npe_http_l_has_header(lua_State *L)
{
    int n = npe_http_l_get_header(L);
    (void)n;
    lua_pushboolean(L, !lua_isnil(L, -1));
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Module Registration
 * ═══════════════════════════════════════════════════════════════════════════ */

static const luaL_Reg http_funcs[] = {
    {"get", npe_http_l_get},
    {"post", npe_http_l_post},
    {"head", npe_http_l_head},
    {"put", npe_http_l_put},
    {"delete", npe_http_l_delete},
    {"options", npe_http_l_options},
    {"patch", npe_http_l_patch},
    {"request", npe_http_l_request},
    {"parse_url", npe_http_l_parse_url},
    {"build_url", npe_http_l_build_url},
    {"url_encode", npe_http_l_url_encode},
    {"url_decode", npe_http_l_url_decode},
    {"build_query", npe_http_l_build_query},
    {"get_header", npe_http_l_get_header},
    {"has_header", npe_http_l_has_header},
    {NULL, NULL}};

int luaopen_npe_http_lib(lua_State *L)
{
    luaL_newlib(L, http_funcs);
    return 1;
}
