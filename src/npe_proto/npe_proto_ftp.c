/*****************************************************************************
 * npe_proto_ftp.c — FTP protocol implementation
 *****************************************************************************/

#include "npe_proto_ftp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define FTP_BUFSZ 4096

struct npe_ftp_conn {
    int                 ctrl_fd;
    char               *host;
    uint16_t            port;
    npe_proto_state_t   state;
    bool                authenticated;
    npe_ftp_mode_t      mode;
    npe_ftp_type_t      type;
    char                banner[FTP_BUFSZ];
};

/* ───────────────────────────────────────────────────────────── */

static int tcp_connect(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *res, *rp;
    char portbuf[16];
    int fd = -1;

    snprintf(portbuf, sizeof(portbuf), "%u", port);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(host, portbuf, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int ftp_readline(int fd, char *buf, size_t max) {
    size_t i = 0;
    while (i < max - 1) {
        if (read(fd, &buf[i], 1) != 1) break;
        if (buf[i++] == '\n') break;
    }
    buf[i] = 0;
    return (int)i;
}

static int ftp_cmd(int fd, const char *cmd, char *resp) {
    char buf[FTP_BUFSZ];
    snprintf(buf, sizeof(buf), "%s\r\n", cmd);
    write(fd, buf, strlen(buf));
    return ftp_readline(fd, resp, FTP_BUFSZ);
}

static int ftp_cmd_split(int fd, const char *cmd, const char *arg, char *resp)
{
    char line[FTP_BUFSZ];
    if (arg && arg[0] != '\0') {
        snprintf(line, sizeof(line), "%s %s", cmd, arg);
    } else {
        snprintf(line, sizeof(line), "%s", cmd);
    }
    return ftp_cmd(fd, line, resp);
}

/* ───────────────────────────────────────────────────────────── */

void npe_ftp_options_init(npe_ftp_options_t *o) {
    memset(o, 0, sizeof(*o));
    o->mode = NPE_FTP_MODE_PASSIVE;
    o->type = NPE_FTP_TYPE_BINARY;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_ftp_connect(const char *host,
                            uint16_t port,
                            const npe_ftp_options_t *opts,
                            npe_ftp_conn_t **out) {
    if (!port) port = 21;

    npe_ftp_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NPE_ERROR_MEMORY;

    c->ctrl_fd = tcp_connect(host, port);
    if (c->ctrl_fd < 0) {
        free(c);
        return NPE_ERROR_CONNECTION;
    }

    ftp_readline(c->ctrl_fd, c->banner, sizeof(c->banner));

    c->host = strdup(host);
    c->port = port;
    c->mode = opts ? opts->mode : NPE_FTP_MODE_PASSIVE;
    c->type = opts ? opts->type : NPE_FTP_TYPE_BINARY;
    c->state = NPE_PROTO_STATE_CONNECTED;

    *out = c;
    return NPE_OK;
}

npe_proto_state_t npe_ftp_state(const npe_ftp_conn_t *c) {
    return c ? c->state : NPE_PROTO_STATE_DISCONNECTED;
}

npe_error_t npe_ftp_get_banner(npe_ftp_conn_t *c,
                               npe_proto_banner_t *b) {
    b->raw_banner = strdup(c->banner);
    return NPE_OK;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_ftp_login(npe_ftp_conn_t *c,
                          const char *u,
                          const char *p,
                          npe_ftp_response_t *r) {
    char buf[FTP_BUFSZ];

    ftp_cmd_split(c->ctrl_fd, "USER", u, buf);
    ftp_cmd_split(c->ctrl_fd, "PASS", p, buf);

    int code = atoi(buf);
    c->authenticated = (code / 100) == 2;
    if (c->authenticated) {
        c->state = NPE_PROTO_STATE_AUTHENTICATED;
    }

    if (r) {
        r->code = (uint32_t)code;
        r->message = strdup(buf);
    }

    return c->authenticated ? NPE_OK : NPE_ERROR_PROTOCOL;
}

npe_error_t npe_ftp_login_anonymous(npe_ftp_conn_t *c,
                                    npe_ftp_response_t *r) {
    return npe_ftp_login(c, "anonymous", "anonymous@", r);
}

bool npe_ftp_is_authenticated(const npe_ftp_conn_t *c) {
    return c && c->authenticated;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_ftp_pwd(npe_ftp_conn_t *c, char **path) {
    char buf[FTP_BUFSZ];
    ftp_cmd(c->ctrl_fd, "PWD", buf);
    *path = strdup(buf);
    return NPE_OK;
}

npe_error_t npe_ftp_cwd(npe_ftp_conn_t *c, const char *path) {
    char cmd[FTP_BUFSZ];
    char buf[FTP_BUFSZ];
    snprintf(cmd, sizeof(cmd), "CWD %s", path);
    ftp_cmd(c->ctrl_fd, cmd, buf);
    return NPE_OK;
}

/* ───────────────────────────────────────────────────────────── */

npe_error_t npe_ftp_raw_command(npe_ftp_conn_t *c,
                                const char *cmd,
                                npe_ftp_response_t *r) {
    char buf[FTP_BUFSZ];
    ftp_cmd(c->ctrl_fd, cmd, buf);
    if (r) {
        r->code = atoi(buf);
        r->message = strdup(buf);
    }
    return NPE_OK;
}

/* ───────────────────────────────────────────────────────────── */

void npe_ftp_response_free(npe_ftp_response_t *r) {
    if (!r) return;
    free((void *)r->message);
}

bool npe_ftp_response_ok(const npe_ftp_response_t *r) {
    return r && (r->code / 100) == 2;
}

uint32_t npe_ftp_response_category(uint32_t code) {
    return code / 100;
}

/* ───────────────────────────────────────────────────────────── */

void npe_ftp_disconnect(npe_ftp_conn_t *c) {
    if (!c) return;
    write(c->ctrl_fd, "QUIT\r\n", 6);
    close(c->ctrl_fd);
    free(c->host);
    free(c);
}

npe_error_t npe_ftp_register(npe_vm_t *vm) {
    (void)vm;
    return NPE_OK;
}

static int lua_ftp_banner(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 21);
    npe_ftp_conn_t *conn = NULL;
    npe_proto_banner_t banner = {0};

    if (npe_ftp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "FTP connection failed");
        return 2;
    }

    npe_ftp_get_banner(conn, &banner);
    lua_pushstring(L, banner.raw_banner ? banner.raw_banner : "");

    free((void *)banner.raw_banner);
    npe_ftp_disconnect(conn);
    return 1;
}

static int lua_ftp_anonymous(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 21);
    const char *user = luaL_optstring(L, 3, "anonymous");
    const char *pass = luaL_optstring(L, 4, "anonymous@");
    npe_ftp_conn_t *conn = NULL;
    npe_ftp_response_t resp = {0};

    if (npe_ftp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "FTP connection failed");
        return 2;
    }

    npe_error_t rc = npe_ftp_login(conn, user, pass, &resp);
    lua_newtable(L);
    lua_pushboolean(L, rc == NPE_OK);
    lua_setfield(L, -2, "success");
    lua_pushinteger(L, (lua_Integer)resp.code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, resp.message ? resp.message : "");
    lua_setfield(L, -2, "message");

    npe_ftp_response_free(&resp);
    npe_ftp_disconnect(conn);
    return 1;
}

static int lua_ftp_login(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 21);
    const char *user = luaL_checkstring(L, 3);
    const char *pass = luaL_checkstring(L, 4);
    npe_ftp_conn_t *conn = NULL;
    npe_ftp_response_t resp = {0};

    if (npe_ftp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "FTP connection failed");
        return 2;
    }

    npe_error_t rc = npe_ftp_login(conn, user, pass, &resp);
    lua_newtable(L);
    lua_pushboolean(L, rc == NPE_OK);
    lua_setfield(L, -2, "success");
    lua_pushinteger(L, (lua_Integer)resp.code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, resp.message ? resp.message : "");
    lua_setfield(L, -2, "message");

    npe_ftp_response_free(&resp);
    npe_ftp_disconnect(conn);
    return 1;
}

static int lua_ftp_raw_command(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 21);
    const char *cmd = luaL_checkstring(L, 3);
    npe_ftp_conn_t *conn = NULL;
    npe_ftp_response_t resp = {0};

    if (npe_ftp_connect(host, port, NULL, &conn) != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "FTP connection failed");
        return 2;
    }

    npe_ftp_raw_command(conn, cmd, &resp);
    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)resp.code);
    lua_setfield(L, -2, "code");
    lua_pushstring(L, resp.message ? resp.message : "");
    lua_setfield(L, -2, "message");

    npe_ftp_response_free(&resp);
    npe_ftp_disconnect(conn);
    return 1;
}

int luaopen_npe_ftp(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"banner", lua_ftp_banner},
        {"anonymous", lua_ftp_anonymous},
        {"login", lua_ftp_login},
        {"raw_command", lua_ftp_raw_command},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
