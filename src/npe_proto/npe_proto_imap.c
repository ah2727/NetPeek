#include "npe_proto_imap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

static int imap_connect_socket(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *res;
    char portbuf[16];
    int fd;

    snprintf(portbuf, sizeof(portbuf), "%u", port);
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo(host, portbuf, &hints, &res);
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return fd;
}

static int imap_readline(int fd, char *buf, size_t max) {
    size_t i = 0;
    while (i < max - 1) {
        if (read(fd, &buf[i], 1) != 1) break;
        if (buf[i++] == '\n') break;
    }
    buf[i] = 0;
    return (int)i;
}

npe_imap_connection_t *
npe_imap_connect(const char *host, uint16_t port, bool ssl, uint32_t timeout_ms) {
    npe_imap_connection_t *c = calloc(1, sizeof(*c));
    c->sockfd = imap_connect_socket(host, port);
    strncpy(c->hostname, host, sizeof(c->hostname) - 1);
    c->port = port;
    c->timeout_ms = timeout_ms;
    c->state = NPE_IMAP_STATE_NOT_AUTHENTICATED;
    c->is_connected = true;

    char banner[NPE_IMAP_MAX_LINE_LENGTH];
    imap_readline(c->sockfd, banner, sizeof(banner));
    return c;
}

int npe_imap_capability(npe_imap_connection_t *c,
                        npe_imap_capabilities_t *caps) {
    char buf[NPE_IMAP_MAX_LINE_LENGTH];
    write(c->sockfd, "a001 CAPABILITY\r\n", 17);

    memset(caps, 0, sizeof(*caps));
    while (imap_readline(c->sockfd, buf, sizeof(buf)) > 0) {
        if (buf[0] == '*' && strstr(buf, "CAPABILITY")) {
            if (strstr(buf, "IMAP4rev1")) caps->imap4rev1 = true;
            if (strstr(buf, "STARTTLS")) caps->starttls = true;
            if (strstr(buf, "IDLE")) caps->idle = true;
            if (strstr(buf, "NAMESPACE")) caps->namespace = true;
            if (strstr(buf, "UIDPLUS")) caps->uidplus = true;
        }
        if (!strncmp(buf, "a001", 4)) break;
    }
    return 0;
}

void npe_imap_disconnect(npe_imap_connection_t *c) {
    if (!c) return;
    write(c->sockfd, "a999 LOGOUT\r\n", 13);
    close(c->sockfd);
    free(c);
}