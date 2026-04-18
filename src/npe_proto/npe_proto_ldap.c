#include "npe_proto_ldap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int ldap_connect_socket(const char *host, int port)
{
    if (!host || port <= 0 || port > 65535)
        return -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portbuf, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *it = res; it; it = it->ai_next)
    {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;

        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int ldap_send_all(int fd, const uint8_t *buf, size_t len, int timeout_ms)
{
    size_t sent = 0;
    while (sent < len)
    {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0)
            return -1;

        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0)
            return -1;

        sent += (size_t)n;
    }

    return 0;
}

static int ldap_recv_all(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
    size_t got = 0;
    while (got < len)
    {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0)
            return -1;

        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0)
            return -1;

        got += (size_t)n;
    }

    return 0;
}

static size_t ber_write_len(uint8_t *out, size_t out_cap, size_t len)
{
    if (!out || out_cap == 0)
        return 0;

    if (len < 128)
    {
        out[0] = (uint8_t)len;
        return 1;
    }

    size_t bytes = 0;
    size_t n = len;
    while (n > 0)
    {
        bytes++;
        n >>= 8;
    }

    if (1 + bytes > out_cap || bytes > 4)
        return 0;

    out[0] = (uint8_t)(0x80 | bytes);
    for (size_t i = 0; i < bytes; i++)
        out[bytes - i] = (uint8_t)((len >> (i * 8)) & 0xFF);

    return 1 + bytes;
}

static bool ber_read_len(const uint8_t *buf, size_t buf_len, size_t *len_out, size_t *len_bytes)
{
    if (!buf || buf_len == 0 || !len_out || !len_bytes)
        return false;

    if ((buf[0] & 0x80) == 0)
    {
        *len_out = (size_t)buf[0];
        *len_bytes = 1;
        return true;
    }

    size_t bytes = (size_t)(buf[0] & 0x7F);
    if (bytes == 0 || bytes > 4 || 1 + bytes > buf_len)
        return false;

    size_t len = 0;
    for (size_t i = 0; i < bytes; i++)
        len = (len << 8) | buf[1 + i];

    *len_out = len;
    *len_bytes = 1 + bytes;
    return true;
}

static int ldap_recv_ber_message(int fd, uint8_t **out_buf, size_t *out_len, int timeout_ms)
{
    if (!out_buf || !out_len)
        return -1;

    *out_buf = NULL;
    *out_len = 0;

    uint8_t hdr[8];
    if (ldap_recv_all(fd, hdr, 2, timeout_ms) != 0)
        return -1;

    size_t len = 0;
    size_t len_bytes = 0;
    if (!ber_read_len(hdr + 1, 1, &len, &len_bytes))
    {
        if (ldap_recv_all(fd, hdr + 2, sizeof(hdr) - 2, timeout_ms) != 0)
            return -1;
        if (!ber_read_len(hdr + 1, sizeof(hdr) - 1, &len, &len_bytes))
            return -1;
    }

    size_t head_len = 1 + len_bytes;
    uint8_t *msg = calloc(1, head_len + len);
    if (!msg)
        return -1;

    msg[0] = hdr[0];
    memcpy(msg + 1, hdr + 1, len_bytes);

    size_t already = 0;
    if (len_bytes > 1)
    {
        size_t have = len_bytes - 1;
        if (have > 0)
            memcpy(msg + 2, hdr + 2, have);
    }

    if (ldap_recv_all(fd, msg + head_len + already, len - already, timeout_ms) != 0)
    {
        free(msg);
        return -1;
    }

    *out_buf = msg;
    *out_len = head_len + len;
    return 0;
}

static int ldap_send_bind_anonymous(npe_ldap_connection_t *c)
{
    uint8_t bind_req[64];
    size_t off = 0;

    uint8_t bind_body[32];
    size_t b = 0;
    bind_body[b++] = 0x02;
    bind_body[b++] = 0x01;
    bind_body[b++] = (uint8_t)c->ldap_version;
    bind_body[b++] = 0x04;
    bind_body[b++] = 0x00;
    bind_body[b++] = 0x80;
    bind_body[b++] = 0x00;

    bind_req[off++] = 0x30;
    uint8_t inner[48];
    size_t in = 0;
    inner[in++] = 0x02;
    inner[in++] = 0x01;
    inner[in++] = (uint8_t)c->next_message_id;
    inner[in++] = 0x60;
    in += ber_write_len(inner + in, sizeof(inner) - in, b);
    memcpy(inner + in, bind_body, b);
    in += b;

    off += ber_write_len(bind_req + off, sizeof(bind_req) - off, in);
    memcpy(bind_req + off, inner, in);
    off += in;

    if (ldap_send_all(c->socket_fd, bind_req, off, c->write_timeout_ms) != 0)
        return -1;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (ldap_recv_ber_message(c->socket_fd, &resp, &resp_len, c->read_timeout_ms) != 0)
        return -1;

    int rc = -1;
    if (resp_len > 16)
    {
        for (size_t i = 0; i + 2 < resp_len; i++)
        {
            if (resp[i] == 0x0A && resp[i + 1] == 0x01)
            {
                rc = resp[i + 2] == 0x00 ? 0 : -1;
                break;
            }
        }
    }

    free(resp);
    return rc;
}

static bool parse_search_result_entry(const uint8_t *msg,
                                      size_t msg_len,
                                      npe_ldap_message_t *out)
{
    if (!msg || msg_len < 2 || !out)
        return false;

    for (size_t i = 0; i + 2 < msg_len; i++)
    {
        if (msg[i] != 0x64)
            continue;

        size_t op_len = 0;
        size_t op_len_bytes = 0;
        if (!ber_read_len(msg + i + 1, msg_len - (i + 1), &op_len, &op_len_bytes))
            return false;

        size_t dn_pos = i + 1 + op_len_bytes;
        if (dn_pos + 2 > msg_len || msg[dn_pos] != 0x04)
            return false;

        size_t dn_len = 0;
        size_t dn_len_bytes = 0;
        if (!ber_read_len(msg + dn_pos + 1, msg_len - (dn_pos + 1), &dn_len, &dn_len_bytes))
            return false;

        size_t dn_data = dn_pos + 1 + dn_len_bytes;
        if (dn_data + dn_len > msg_len)
            return false;

        npe_ldap_entry_t *next = realloc(out->entries,
                                         (out->entry_count + 1) * sizeof(*out->entries));
        if (!next)
            return false;

        out->entries = next;
        npe_ldap_entry_t *entry = &out->entries[out->entry_count++];
        memset(entry, 0, sizeof(*entry));

        size_t cp = dn_len;
        if (cp >= sizeof(entry->dn))
            cp = sizeof(entry->dn) - 1;

        memcpy(entry->dn, msg + dn_data, cp);
        entry->dn[cp] = '\0';
        return true;
    }

    return false;
}

static bool parse_search_done(const uint8_t *msg, size_t msg_len, npe_ldap_message_t *out)
{
    if (!msg || !out)
        return false;

    for (size_t i = 0; i + 2 < msg_len; i++)
    {
        if (msg[i] != 0x65)
            continue;

        for (size_t j = i + 1; j + 2 < msg_len; j++)
        {
            if (msg[j] == 0x0A && msg[j + 1] == 0x01)
            {
                out->result_code = (npe_ldap_result_code_t)msg[j + 2];
                return true;
            }
        }
    }

    return false;
}

static int encode_filter_simple(const char *filter, uint8_t *out, size_t out_cap)
{
    if (!out || out_cap < 4)
        return -1;

    if (!filter || strcmp(filter, "(objectClass=*)") == 0)
    {
        const char *attr = "objectClass";
        size_t attr_len = strlen(attr);
        if (2 + attr_len > out_cap)
            return -1;

        out[0] = 0x87;
        out[1] = (uint8_t)attr_len;
        memcpy(out + 2, attr, attr_len);
        return (int)(2 + attr_len);
    }

    const char *eq = strchr(filter, '=');
    const char *lp = strchr(filter, '(');
    const char *rp = strrchr(filter, ')');
    if (!eq || !lp || !rp || lp >= eq || eq >= rp)
        return -1;

    size_t attr_len = (size_t)(eq - (lp + 1));
    size_t val_len = (size_t)(rp - (eq + 1));
    if (attr_len == 0 || val_len == 0)
        return -1;

    if (val_len == 1 && eq[1] == '*')
    {
        if (2 + attr_len > out_cap)
            return -1;
        out[0] = 0x87;
        out[1] = (uint8_t)attr_len;
        memcpy(out + 2, lp + 1, attr_len);
        return (int)(2 + attr_len);
    }

    uint8_t inner[256];
    size_t off = 0;
    if (off + 2 + attr_len > sizeof(inner))
        return -1;
    inner[off++] = 0x04;
    inner[off++] = (uint8_t)attr_len;
    memcpy(inner + off, lp + 1, attr_len);
    off += attr_len;

    if (off + 2 + val_len > sizeof(inner))
        return -1;
    inner[off++] = 0x04;
    inner[off++] = (uint8_t)val_len;
    memcpy(inner + off, eq + 1, val_len);
    off += val_len;

    if (off + 2 > out_cap)
        return -1;
    out[0] = 0xA3;
    out[1] = (uint8_t)off;
    memcpy(out + 2, inner, off);
    return (int)(2 + off);
}

npe_ldap_connection_t *
npe_ldap_connect(const char *host, int port)
{
    if (!host || host[0] == '\0')
        return NULL;

    npe_ldap_connection_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;

    snprintf(c->host, sizeof(c->host), "%s", host);
    c->port = port > 0 ? port : NPE_LDAP_PORT_DEFAULT;
    c->connect_timeout_ms = NPE_LDAP_CONNECT_TIMEOUT_MS;
    c->read_timeout_ms = NPE_LDAP_READ_TIMEOUT_MS;
    c->write_timeout_ms = NPE_LDAP_READ_TIMEOUT_MS;
    c->ldap_version = NPE_LDAP_VERSION_3;
    c->next_message_id = 1;

    c->socket_fd = ldap_connect_socket(c->host, c->port);
    if (c->socket_fd < 0)
    {
        free(c);
        return NULL;
    }

    c->connected = true;
    return c;
}

int npe_ldap_bind_anonymous(npe_ldap_connection_t *c)
{
    if (!c || !c->connected)
        return NPE_LDAP_ERROR_CONNECTION;

    if (ldap_send_bind_anonymous(c) != 0)
        return NPE_LDAP_INVALID_CREDENTIALS;

    c->bound = true;
    c->auth_method = NPE_LDAP_AUTH_ANONYMOUS;
    c->next_message_id++;
    return NPE_LDAP_SUCCESS;
}

npe_ldap_message_t *
npe_ldap_search(npe_ldap_connection_t *c,
                const char *base_dn,
                npe_ldap_scope_t scope,
                const char *filter,
                const char **attrs,
                size_t attr_count)
{
    (void)attrs;
    (void)attr_count;

    npe_ldap_message_t *msg = calloc(1, sizeof(*msg));
    if (!msg)
        return NULL;

    msg->result_code = NPE_LDAP_OTHER;
    if (!c || !c->connected || !c->bound)
    {
        msg->result_code = NPE_LDAP_ERROR_NOT_BOUND;
        snprintf(msg->error_message, sizeof(msg->error_message), "not bound");
        return msg;
    }

    const char *base = base_dn ? base_dn : "";
    uint8_t filter_tlv[260];
    int filter_len = encode_filter_simple(filter, filter_tlv, sizeof(filter_tlv));
    if (filter_len < 0)
    {
        msg->result_code = NPE_LDAP_ERROR_INVALID_PARAM;
        snprintf(msg->error_message, sizeof(msg->error_message), "unsupported filter");
        return msg;
    }

    uint8_t search_body[1024];
    size_t sb = 0;
    size_t base_len = strlen(base);
    if (base_len > 255)
    {
        msg->result_code = NPE_LDAP_ERROR_INVALID_PARAM;
        snprintf(msg->error_message, sizeof(msg->error_message), "base DN too long");
        return msg;
    }

    search_body[sb++] = 0x04;
    search_body[sb++] = (uint8_t)base_len;
    memcpy(search_body + sb, base, base_len);
    sb += base_len;

    search_body[sb++] = 0x0A; search_body[sb++] = 0x01; search_body[sb++] = (uint8_t)scope;
    search_body[sb++] = 0x0A; search_body[sb++] = 0x01; search_body[sb++] = 0x00;
    search_body[sb++] = 0x02; search_body[sb++] = 0x01; search_body[sb++] = 0x00;
    search_body[sb++] = 0x02; search_body[sb++] = 0x01; search_body[sb++] = 0x1E;
    search_body[sb++] = 0x01; search_body[sb++] = 0x01; search_body[sb++] = 0x00;

    memcpy(search_body + sb, filter_tlv, (size_t)filter_len);
    sb += (size_t)filter_len;

    search_body[sb++] = 0x30;
    search_body[sb++] = 0x00;

    uint8_t ldap_msg[1400];
    size_t lm = 0;
    uint8_t inner[1200];
    size_t in = 0;

    inner[in++] = 0x02;
    inner[in++] = 0x01;
    inner[in++] = (uint8_t)c->next_message_id;
    inner[in++] = 0x63;
    in += ber_write_len(inner + in, sizeof(inner) - in, sb);
    memcpy(inner + in, search_body, sb);
    in += sb;

    ldap_msg[lm++] = 0x30;
    lm += ber_write_len(ldap_msg + lm, sizeof(ldap_msg) - lm, in);
    memcpy(ldap_msg + lm, inner, in);
    lm += in;

    if (ldap_send_all(c->socket_fd, ldap_msg, lm, c->write_timeout_ms) != 0)
    {
        msg->result_code = NPE_LDAP_ERROR_CONNECTION;
        snprintf(msg->error_message, sizeof(msg->error_message), "send failed");
        return msg;
    }

    bool done = false;
    while (!done)
    {
        uint8_t *resp = NULL;
        size_t resp_len = 0;
        if (ldap_recv_ber_message(c->socket_fd, &resp, &resp_len, c->read_timeout_ms) != 0)
        {
            msg->result_code = NPE_LDAP_ERROR_TIMEOUT;
            snprintf(msg->error_message, sizeof(msg->error_message), "recv timeout");
            break;
        }

        (void)parse_search_result_entry(resp, resp_len, msg);
        if (parse_search_done(resp, resp_len, msg))
            done = true;

        free(resp);
    }

    c->next_message_id++;
    if (msg->result_code == NPE_LDAP_SUCCESS)
        msg->message_id = c->next_message_id - 1;

    return msg;
}

void npe_ldap_close(npe_ldap_connection_t *c)
{
    if (!c)
        return;

    if (c->socket_fd >= 0)
        close(c->socket_fd);

    free(c);
}
