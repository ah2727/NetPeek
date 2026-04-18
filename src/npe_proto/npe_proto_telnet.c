#include "npe_proto_telnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

npe_telnet_session_t* npe_telnet_create(void) {
    return calloc(1, sizeof(npe_telnet_session_t));
}

int npe_telnet_connect(npe_telnet_session_t *s,
                       const char *host,
                       uint16_t port) {
    struct addrinfo hints = {0}, *res;
    char portbuf[16];

    snprintf(portbuf, sizeof(portbuf), "%u", port);
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo(host, portbuf, &hints, &res);
    s->socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(s->socket_fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    strncpy(s->host, host, sizeof(s->host)-1);
    s->port = port;
    s->state = NPE_TELNET_STATE_CONNECTED;

    /* Read banner */
    read(s->socket_fd, s->banner, sizeof(s->banner)-1);
    return NPE_TELNET_OK;
}

int npe_telnet_handle_negotiation(npe_telnet_session_t *s,
                                  const uint8_t *data,
                                  size_t len) {
    /* Respond WONT to all options */
    for (size_t i = 0; i + 2 < len; i++) {
        if (data[i] == NPE_TELNET_IAC &&
            (data[i+1] == NPE_TELNET_DO ||
             data[i+1] == NPE_TELNET_WILL)) {
            uint8_t resp[3] = {
                NPE_TELNET_IAC,
                (data[i+1] == NPE_TELNET_DO) ? NPE_TELNET_WONT : NPE_TELNET_DONT,
                data[i+2]
            };
            write(s->socket_fd, resp, 3);
        }
    }
    return 0;
}

int npe_telnet_get_banner(npe_telnet_session_t *s,
                          char *buf,
                          size_t sz) {
    strncpy(buf, s->banner, sz - 1);
    return 0;
}

int npe_telnet_disconnect(npe_telnet_session_t *s) {
    if (!s) return 0;
    close(s->socket_fd);
    free(s);
    return 0;
}