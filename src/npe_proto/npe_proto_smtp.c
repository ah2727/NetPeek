/*****************************************************************************
 * npe_proto_smtp.c — SMTP protocol implementation
 *****************************************************************************/

#include "npe_proto_smtp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define SMTP_BUFSZ 4096

struct npe_smtp_conn {
    int                 fd;
    char               *host;
    uint16_t            port;
    npe_proto_state_t   state;
    bool                authenticated;
    char                banner[SMTP_BUFSZ];
};

/* ───────────────────────────────────────────────────────────── */

static int smtp_read(int fd, char *buf) {
    size_t i = 0;
    while (i < SMTP_BUFSZ - 1) {
        if (read(fd, &buf[i], 1) != 1) break;
        if (buf[i++] == '\n') break;
    }
    buf[i] = 0;
    return (int)i;
}

static void smtp_cmd(int fd, const char *cmd, char *resp) {
    write(fd, cmd, strlen(cmd));
    write(fd, "\r\n", 2);
    smtp_read(fd, resp);
}

static const char b64_tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t smtp_base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    size_t i = 0, o = 0;
    while (i < in_len) {
        unsigned int octet_a = i < in_len ? in[i++] : 0;
        unsigned int octet_b = i < in_len ? in[i++] : 0;
        unsigned int octet_c = i < in_len ? in[i++] : 0;
        unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        if (o + 4 >= out_len) return 0;

        out[o++] = b64_tbl[(triple >> 18) & 0x3F];
        out[o++] = b64_tbl[(triple >> 12) & 0x3F];
        out[o++] = b64_tbl[(triple >> 6) & 0x3F];
        out[o++] = b64_tbl[triple & 0x3F];
    }

    if (in_len % 3 == 1) {
        out[o - 1] = '=';
        out[o - 2] = '=';
    } else if (in_len % 3 == 2) {
        out[o - 1] = '=';
    }

    if (o >= out_len) return 0;
    out[o] = '\0';
    return o;
}

/* ───────────────────────────────────────────────────────────── */

void npe_smtp_options_init(npe_smtp_options_t *o) {
    memset(o, 0, sizeof(*o));
    o->helo_domain = "localhost";
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_smtp_connect(const char *host,
                             uint16_t port,
                             const npe_smtp_options_t *opts,
                             npe_smtp_conn_t **out) {
    if (!port) port = 25;

    npe_smtp_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NPE_ERROR_MEMORY;

    struct addrinfo hints = {0}, *res;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%u", port);

    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo(host, portbuf, &hints, &res);

    c->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(c->fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    smtp_read(c->fd, c->banner);

    c->host = strdup(host);
    c->port = port;
    c->state = NPE_PROTO_STATE_CONNECTED;

    *out = c;
    return NPE_OK;
}

npe_proto_state_t npe_smtp_state(const npe_smtp_conn_t *c) {
    return c ? c->state : NPE_PROTO_STATE_DISCONNECTED;
}

npe_error_t npe_smtp_get_banner(npe_smtp_conn_t *c,
                                npe_proto_banner_t *b) {
    b->raw_banner = strdup(c->banner);
    return NPE_OK;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_smtp_ehlo(npe_smtp_conn_t *c,
                          const char *domain,
                          npe_smtp_capabilities_t *caps) {
    char buf[SMTP_BUFSZ];
    char cmd[SMTP_BUFSZ];

    snprintf(cmd, sizeof(cmd), "EHLO %s", domain);
    smtp_cmd(c->fd, cmd, buf);

    if (caps) {
        caps->starttls = strstr(buf, "STARTTLS") != NULL;
        caps->pipelining = strstr(buf, "PIPELINING") != NULL;
    }
    return NPE_OK;
}

npe_error_t npe_smtp_helo(npe_smtp_conn_t *c,
                          const char *domain,
                          npe_smtp_response_t *r) {
    char buf[SMTP_BUFSZ];
    char cmd[SMTP_BUFSZ];

    snprintf(cmd, sizeof(cmd), "HELO %s", domain);
    smtp_cmd(c->fd, cmd, buf);

    if (r) {
        r->code = atoi(buf);
        r->message = strdup(buf);
    }
    return NPE_OK;
}

npe_error_t npe_smtp_auth(npe_smtp_conn_t        *c,
                          const char             *username,
                          const char             *password,
                          npe_smtp_auth_method_t  method,
                          npe_smtp_response_t    *r)
{
    char buf[SMTP_BUFSZ] = {0};
    char out[SMTP_BUFSZ] = {0};
    char plain[SMTP_BUFSZ] = {0};

    if (!c || !username || !password) {
        return NPE_ERROR_INVALID_ARG;
    }

    if (method != NPE_SMTP_AUTH_PLAIN && method != NPE_SMTP_AUTH_LOGIN) {
        method = NPE_SMTP_AUTH_LOGIN;
    }

    if (method == NPE_SMTP_AUTH_PLAIN) {
        size_t user_len = strlen(username);
        size_t pass_len = strlen(password);
        size_t plain_len = user_len + pass_len + 2;
        if (plain_len >= sizeof(plain)) {
            return NPE_ERROR_MEMORY;
        }

        plain[0] = '\0';
        memcpy(plain + 1, username, user_len);
        plain[1 + user_len] = '\0';
        memcpy(plain + 2 + user_len, password, pass_len);

        if (smtp_base64_encode((const unsigned char *)plain, plain_len, out, sizeof(out)) == 0) {
            return NPE_ERROR_MEMORY;
        }

        snprintf(buf, sizeof(buf), "AUTH PLAIN %s", out);
        smtp_cmd(c->fd, buf, buf);
    } else {
        smtp_cmd(c->fd, "AUTH LOGIN", buf);
        if (atoi(buf) != 334) {
            if (r) {
                r->code = (uint32_t)atoi(buf);
                r->message = strdup(buf);
            }
            return NPE_ERROR_PROTOCOL;
        }

        if (smtp_base64_encode((const unsigned char *)username, strlen(username), out, sizeof(out)) == 0) {
            return NPE_ERROR_MEMORY;
        }
        smtp_cmd(c->fd, out, buf);
        if (atoi(buf) != 334) {
            if (r) {
                r->code = (uint32_t)atoi(buf);
                r->message = strdup(buf);
            }
            return NPE_ERROR_PROTOCOL;
        }

        if (smtp_base64_encode((const unsigned char *)password, strlen(password), out, sizeof(out)) == 0) {
            return NPE_ERROR_MEMORY;
        }
        smtp_cmd(c->fd, out, buf);
    }

    if (r) {
        r->code = (uint32_t)atoi(buf);
        r->message = strdup(buf);
    }

    if ((atoi(buf) / 100) == 2) {
        c->authenticated = true;
        c->state = NPE_PROTO_STATE_AUTHENTICATED;
        return NPE_OK;
    }

    return NPE_ERROR_PROTOCOL;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_smtp_vrfy(npe_smtp_conn_t *c,
                          const char *addr,
                          bool *exists,
                          char **real,
                          npe_smtp_response_t *r) {
    char buf[SMTP_BUFSZ];
    char cmd[SMTP_BUFSZ];

    snprintf(cmd, sizeof(cmd), "VRFY %s", addr);
    smtp_cmd(c->fd, cmd, buf);

    int code = atoi(buf);
    if (exists) *exists = (code == 250 || code == 252);
    if (real) *real = strdup(buf);

    if (r) {
        r->code = code;
        r->message = strdup(buf);
    }
    return NPE_OK;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_smtp_noop(npe_smtp_conn_t *c,
                          npe_smtp_response_t *r) {
    char buf[SMTP_BUFSZ];
    smtp_cmd(c->fd, "NOOP", buf);
    if (r) {
        r->code = atoi(buf);
        r->message = strdup(buf);
    }
    return NPE_OK;
}

npe_error_t npe_smtp_quit(npe_smtp_conn_t *c,
                          npe_smtp_response_t *r) {
    char buf[SMTP_BUFSZ];
    smtp_cmd(c->fd, "QUIT", buf);
    if (r) {
        r->code = atoi(buf);
        r->message = strdup(buf);
    }
    return NPE_OK;
}

/* ───────────────────────────────────────────────────────────── */

void npe_smtp_response_free(npe_smtp_response_t *r) {
    if (!r) return;
    free((void *)r->message);
}

bool npe_smtp_response_ok(const npe_smtp_response_t *r) {
    return r && (r->code / 100) == 2;
}

uint32_t npe_smtp_response_category(uint32_t code) {
    return code / 100;
}

void npe_smtp_disconnect(npe_smtp_conn_t *c) {
    if (!c) return;
    write(c->fd, "QUIT\r\n", 6);
    close(c->fd);
    free(c->host);
    free(c);
}

npe_error_t npe_smtp_register(npe_vm_t *vm) {
    (void)vm;
    return NPE_OK;
}

static int lua_smtp_banner(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 25);
    npe_smtp_conn_t *conn = NULL;
    npe_proto_banner_t banner = {0};

    if (npe_smtp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "SMTP connection failed");
        return 2;
    }

    npe_smtp_get_banner(conn, &banner);
    lua_pushstring(L, banner.raw_banner ? banner.raw_banner : "");

    free((void *)banner.raw_banner);
    npe_smtp_disconnect(conn);
    return 1;
}

static int lua_smtp_ehlo(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 25);
    const char *domain = luaL_optstring(L, 3, "localhost");
    npe_smtp_conn_t *conn = NULL;
    npe_smtp_capabilities_t caps;
    memset(&caps, 0, sizeof(caps));

    if (npe_smtp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "SMTP connection failed");
        return 2;
    }

    npe_smtp_ehlo(conn, domain, &caps);
    lua_newtable(L);
    lua_pushboolean(L, caps.starttls);
    lua_setfield(L, -2, "starttls");
    lua_pushboolean(L, caps.pipelining);
    lua_setfield(L, -2, "pipelining");

    npe_smtp_disconnect(conn);
    return 1;
}

static int lua_smtp_noop(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 25);
    npe_smtp_conn_t *conn = NULL;
    npe_smtp_response_t resp = {0};

    if (npe_smtp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "SMTP connection failed");
        return 2;
    }

    npe_smtp_noop(conn, &resp);
    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)resp.code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, resp.message ? resp.message : "");
    lua_setfield(L, -2, "message");

    npe_smtp_response_free(&resp);
    npe_smtp_disconnect(conn);
    return 1;
}

static int lua_smtp_auth(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 25);
    const char *domain = luaL_optstring(L, 3, "localhost");
    const char *user = luaL_checkstring(L, 4);
    const char *pass = luaL_checkstring(L, 5);
    const char *method_str = luaL_optstring(L, 6, "login");
    npe_smtp_auth_method_t method = NPE_SMTP_AUTH_LOGIN;
    npe_smtp_conn_t *conn = NULL;
    npe_smtp_response_t resp = {0};

    if (strcasecmp(method_str, "plain") == 0) {
        method = NPE_SMTP_AUTH_PLAIN;
    }

    if (npe_smtp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "SMTP connection failed");
        return 2;
    }

    npe_smtp_ehlo(conn, domain, NULL);
    npe_error_t rc = npe_smtp_auth(conn, user, pass, method, &resp);

    lua_newtable(L);
    lua_pushboolean(L, rc == NPE_OK);
    lua_setfield(L, -2, "success");
    lua_pushinteger(L, (lua_Integer)resp.code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, resp.message ? resp.message : "");
    lua_setfield(L, -2, "message");
    lua_pushstring(L, method == NPE_SMTP_AUTH_PLAIN ? "plain" : "login");
    lua_setfield(L, -2, "method");

    npe_smtp_response_free(&resp);
    npe_smtp_disconnect(conn);
    return 1;
}

int luaopen_npe_smtp(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"banner", lua_smtp_banner},
        {"ehlo", lua_smtp_ehlo},
        {"noop", lua_smtp_noop},
        {"auth", lua_smtp_auth},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
