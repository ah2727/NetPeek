#define _POSIX_C_SOURCE 200809L

#include "proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* ── URL Parsing ─────────────────────────────────────── */

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t olen = ((in_len + 2) / 3) * 4;
    if (!out || out_cap <= olen)
        return -1;

    size_t i = 0;
    size_t j = 0;
    while (i < in_len)
    {
        uint32_t octet_a = i < in_len ? in[i++] : 0;
        uint32_t octet_b = i < in_len ? in[i++] : 0;
        uint32_t octet_c = i < in_len ? in[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = tbl[(triple >> 18) & 0x3F];
        out[j++] = tbl[(triple >> 12) & 0x3F];
        out[j++] = tbl[(triple >> 6) & 0x3F];
        out[j++] = tbl[triple & 0x3F];
    }

    size_t mod = in_len % 3;
    if (mod > 0)
    {
        out[olen - 1] = '=';
        if (mod == 1)
            out[olen - 2] = '=';
    }

    out[olen] = '\0';
    return (int)olen;
}

np_status_t np_proxy_parse(const char *url, np_proxy_t *proxy)
{
    memset(proxy, 0, sizeof(*proxy));

    const char *rest = url;

    if (strncmp(url, "socks5://", 9) == 0) {
        proxy->type = NP_PROXY_SOCKS5;
        rest = url + 9;
    } else if (strncmp(url, "http://", 7) == 0) {
        proxy->type = NP_PROXY_HTTP_CONNECT;
        rest = url + 7;
    } else {
        /* default to socks5 if no scheme */
        proxy->type = NP_PROXY_SOCKS5;
    }

    /* check for user:pass@ */
    const char *at = strchr(rest, '@');
    if (at) {
        const char *colon = memchr(rest, ':', (size_t)(at - rest));
        if (!colon)
            return NP_ERR_ARGS;

        size_t ulen = (size_t)(colon - rest);
        size_t plen = (size_t)(at - colon - 1);

        if (ulen >= sizeof(proxy->username) || plen >= sizeof(proxy->password))
            return NP_ERR_ARGS;

        memcpy(proxy->username, rest, ulen);
        proxy->username[ulen] = '\0';

        memcpy(proxy->password, colon + 1, plen);
        proxy->password[plen] = '\0';

        proxy->has_auth = true;
        rest = at + 1;
    }

    /* host:port */
    const char *colon = strrchr(rest, ':');
    if (!colon)
        return NP_ERR_ARGS;

    size_t hlen = (size_t)(colon - rest);
    if (hlen == 0 || hlen >= sizeof(proxy->host))
        return NP_ERR_ARGS;

    memcpy(proxy->host, rest, hlen);
    proxy->host[hlen] = '\0';

    int p = atoi(colon + 1);
    if (p < 1 || p > 65535)
        return NP_ERR_ARGS;

    proxy->port = (uint16_t)p;
    return NP_OK;
}

/* ── Blocking connect to proxy host ──────────────────── */

static int connect_to_proxy(const np_proxy_t *proxy, uint32_t timeout_ms)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", proxy->port);

    if (getaddrinfo(proxy->host, port_str, &hints, &res) != 0)
        return -1;

    int fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* non-blocking connect with timeout */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (ret < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, (int)timeout_ms);

        if (pr <= 0) {
            close(fd);
            return -1;
        }

        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);

        if (err != 0) {
            close(fd);
            return -1;
        }
    }

    /* back to blocking for handshake */
    fcntl(fd, F_SETFL, flags);
    return fd;
}

/* ── Timed send/recv helpers ─────────────────────────── */

static bool send_all(int fd, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    size_t sent = 0;

    while (sent < len) {
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0)
            return false;

        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0)
            return false;

        sent += (size_t)n;
    }

    return true;
}

static ssize_t recv_exact(int fd, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    size_t got = 0;

    while (got < len) {
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0)
            return -1;

        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0)
            return -1;

        got += (size_t)n;
    }

    return (ssize_t)got;
}

/* ── SOCKS5 Handshake ────────────────────────────────── */

static int socks5_handshake(int fd, const np_proxy_t *proxy,
                            const char *target_host, uint16_t target_port,
                            uint32_t timeout_ms)
{
    uint8_t buf[512];

    /* greeting: version, nmethods, methods */
    if (proxy->has_auth) {
        uint8_t greet[] = { 0x05, 0x02, 0x00, 0x02 };
        if (!send_all(fd, greet, sizeof(greet), timeout_ms))
            return -1;
    } else {
        uint8_t greet[] = { 0x05, 0x01, 0x00 };
        if (!send_all(fd, greet, sizeof(greet), timeout_ms))
            return -1;
    }

    /* server method selection */
    if (recv_exact(fd, buf, 2, timeout_ms) < 0)
        return -1;

    if (buf[0] != 0x05)
        return -1;

    uint8_t method = buf[1];

    if (method == 0xFF)
        return -1; /* no acceptable method */

    /* username/password auth (RFC 1929) */
    if (method == 0x02) {
        if (!proxy->has_auth)
            return -1;

        uint8_t ulen = (uint8_t)strlen(proxy->username);
        uint8_t plen = (uint8_t)strlen(proxy->password);

        uint8_t auth[515];
        size_t off = 0;

        auth[off++] = 0x01;           /* subnegotiation version */
        auth[off++] = ulen;
        memcpy(auth + off, proxy->username, ulen);
        off += ulen;
        auth[off++] = plen;
        memcpy(auth + off, proxy->password, plen);
        off += plen;

        if (!send_all(fd, auth, off, timeout_ms))
            return -1;

        if (recv_exact(fd, buf, 2, timeout_ms) < 0)
            return -1;

        if (buf[1] != 0x00)
            return -1; /* auth failed */

    } else if (method != 0x00) {
        return -1; /* unsupported method */
    }

    /* CONNECT request using domain name (ATYP=0x03) */
    size_t hlen = strlen(target_host);
    if (hlen > 255)
        return -1;

    uint8_t req[512];
    size_t off = 0;

    req[off++] = 0x05;       /* version */
    req[off++] = 0x01;       /* CMD: CONNECT */
    req[off++] = 0x00;       /* reserved */
    req[off++] = 0x03;       /* ATYP: domain */
    req[off++] = (uint8_t)hlen;
    memcpy(req + off, target_host, hlen);
    off += hlen;
    req[off++] = (uint8_t)(target_port >> 8);
    req[off++] = (uint8_t)(target_port & 0xFF);

    if (!send_all(fd, req, off, timeout_ms))
        return -1;

    /* read reply header: VER, REP, RSV, ATYP */
    if (recv_exact(fd, buf, 4, timeout_ms) < 0)
        return -1;

    if (buf[0] != 0x05 || buf[1] != 0x00)
        return -1; /* connection failed or denied */

    /* consume the BND.ADDR + BND.PORT based on ATYP */
    uint8_t atyp = buf[3];

    if (atyp == 0x01) {
        /* IPv4: 4 bytes addr + 2 bytes port */
        if (recv_exact(fd, buf, 6, timeout_ms) < 0)
            return -1;
    } else if (atyp == 0x04) {
        /* IPv6: 16 bytes addr + 2 bytes port */
        if (recv_exact(fd, buf, 18, timeout_ms) < 0)
            return -1;
    } else if (atyp == 0x03) {
        /* domain: 1 byte len + domain + 2 bytes port */
        if (recv_exact(fd, buf, 1, timeout_ms) < 0)
            return -1;
        if (recv_exact(fd, buf + 1, buf[0] + 2, timeout_ms) < 0)
            return -1;
    } else {
        return -1;
    }

    return 0; /* success — fd is now tunneled */
}

/* ── HTTP CONNECT Handshake ──────────────────────────── */

static int http_connect_handshake(int fd, const np_proxy_t *proxy,
                                  const char *target_host, uint16_t target_port,
                                  uint32_t timeout_ms)
{
    char req[1536];
    int reqlen = 0;

    if (proxy && proxy->has_auth)
    {
        char auth_plain[320];
        int plain_len = snprintf(auth_plain, sizeof(auth_plain), "%s:%s",
                                 proxy->username,
                                 proxy->password);
        if (plain_len < 0 || (size_t)plain_len >= sizeof(auth_plain))
            return -1;

        char auth_b64[512];
        if (base64_encode((const uint8_t *)auth_plain,
                          (size_t)plain_len,
                          auth_b64,
                          sizeof(auth_b64)) < 0)
            return -1;

        reqlen = snprintf(req, sizeof(req),
                          "CONNECT %s:%u HTTP/1.1\r\n"
                          "Host: %s:%u\r\n"
                          "Proxy-Authorization: Basic %s\r\n"
                          "\r\n",
                          target_host, target_port,
                          target_host, target_port,
                          auth_b64);
    }
    else
    {
        reqlen = snprintf(req, sizeof(req),
                          "CONNECT %s:%u HTTP/1.1\r\n"
                          "Host: %s:%u\r\n"
                          "\r\n",
                          target_host, target_port,
                          target_host, target_port);
    }

    if (reqlen < 0 || (size_t)reqlen >= sizeof(req))
        return -1;

    if (!send_all(fd, (uint8_t *)req, (size_t)reqlen, timeout_ms))
        return -1;

    /* read response line by line until we hit \r\n\r\n */
    char resp[2048];
    size_t rlen = 0;

    struct pollfd pfd = { .fd = fd, .events = POLLIN };

    while (rlen < sizeof(resp) - 1) {
        int pr = poll(&pfd, 1, (int)timeout_ms);
        if (pr <= 0)
            return -1;

        ssize_t n = recv(fd, resp + rlen, 1, 0);
        if (n <= 0)
            return -1;

        rlen++;

        if (rlen >= 4 &&
            resp[rlen - 4] == '\r' && resp[rlen - 3] == '\n' &&
            resp[rlen - 2] == '\r' && resp[rlen - 1] == '\n')
            break;
    }

    resp[rlen] = '\0';

    /* check for "HTTP/1.x 200" */
    if (strncmp(resp, "HTTP/1.", 7) != 0)
        return -1;

    if (strstr(resp, " 200 ") == NULL)
        return -1;

    return 0;
}

/* ── Public API ──────────────────────────────────────── */

int np_proxy_connect(const np_proxy_t *proxy,
                     const char *target_host,
                     uint16_t target_port,
                     uint32_t timeout_ms)
{
    int fd = connect_to_proxy(proxy, timeout_ms);
    if (fd < 0)
        return -1;

    int rc;

    if (proxy->type == NP_PROXY_SOCKS5) {
        rc = socks5_handshake(fd, proxy, target_host, target_port, timeout_ms);
    } else if (proxy->type == NP_PROXY_HTTP_CONNECT) {
        rc = http_connect_handshake(fd, proxy, target_host, target_port, timeout_ms);
    } else {
        close(fd);
        return -1;
    }

    if (rc < 0) {
        close(fd);
        return -1;
    }

    return fd;
}
