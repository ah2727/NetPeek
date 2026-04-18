/*****************************************************************************
 * npe_proto_ssh.c — SSH protocol implementation
 * NPE (NetPeek Extension Engine)
 *
 * Backend: libssh2
 *****************************************************************************/

#include "npe_proto_ssh.h"

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* ────────────────────────────────────────────────────────────────────────── */
/* Internal structures                                                        */
/* ────────────────────────────────────────── */

struct npe_ssh_conn {
    int                 sock;
    LIBSSH2_SESSION    *session;
    LIBSSH2_SFTP       *sftp;
    npe_proto_state_t   state;
    char               *host;
    uint16_t            port;
};

struct npe_ssh_shell {
    LIBSSH2_CHANNEL *channel;
};

struct npe_ssh_sftp {
    LIBSSH2_SFTP *sftp;
};

struct npe_ssh_forward {
    LIBSSH2_LISTENER *listener;
};

/* ────────────────────────────────────────────────────────────────────────── */
/* Utilities                                                                  */
/* ────────────────────────────────────────────────────────────────────────── */

static int tcp_connect(const char *host, uint16_t port) {
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;

    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

static uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ────────────────────────────────────────── */
/* OPTIONS                                                                    */
/* ────────────────────────────────────────────────────────────────────────── */

void npe_ssh_options_init(npe_ssh_options_t *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->strict_hostkey = false;
    opts->compress       = false;
    opts->max_auth_tries = 3;
}

/* ────────────────────────────────────────────────────────────────────────── */
/* CONNECTION                                                                 */
/* ────────────────────────────────────────────────────────────────────────── */

npe_error_t npe_ssh_connect(const char *host,
                            uint16_t port,
                            const npe_ssh_options_t *opts,
                            npe_ssh_conn_t **out) {
    npe_ssh_conn_t *c;

    if (!port)
        port = 22;

    if (libssh2_init(0) != 0)
        return NPE_ERROR_GENERIC;

    c = calloc(1, sizeof(*c));
    if (!c)
        return NPE_ERROR_MEMORY;

    c->sock = tcp_connect(host, port);
    if (c->sock < 0) {
        free(c);
        return NPE_ERROR_CONNECTION;
    }

    c->session = libssh2_session_init();
    if (!c->session) {
        close(c->sock);
        free(c);
        return NPE_ERROR_GENERIC;
    }

    if (opts && opts->compress)
        libssh2_session_flag(c->session, LIBSSH2_FLAG_COMPRESS, 1);

    if (libssh2_session_handshake(c->session, c->sock)) {
        libssh2_session_free(c->session);
        close(c->sock);
        free(c);
        return NPE_ERROR_PROTOCOL;
    }

    c->host = strdup(host);
    c->port = port;
    c->state = NPE_PROTO_STATE_CONNECTED;

    *out = c;
    return NPE_OK;
}

npe_proto_state_t npe_ssh_state(const npe_ssh_conn_t *conn) {
    return conn ? conn->state : NPE_PROTO_STATE_DISCONNECTED;
}

npe_error_t npe_ssh_get_banner(npe_ssh_conn_t *conn,
                               npe_proto_banner_t *banner) {
    const char *s = libssh2_session_banner_get(conn->session);
    if (!s)
        return NPE_ERROR_GENERIC;

    banner->raw_banner = strdup(s);
    return NPE_OK;
}

npe_error_t npe_ssh_get_algorithms(npe_ssh_conn_t *conn,
                                   npe_ssh_algorithms_t *a) {
    a->kex        = libssh2_session_methods(conn->session, LIBSSH2_METHOD_KEX);
    a->hostkey    = libssh2_session_methods(conn->session, LIBSSH2_METHOD_HOSTKEY);
    a->cipher_c2s = libssh2_session_methods(conn->session, LIBSSH2_METHOD_CRYPT_CS);
    a->cipher_s2c = libssh2_session_methods(conn->session, LIBSSH2_METHOD_CRYPT_SC);
    a->mac_c2s    = libssh2_session_methods(conn->session, LIBSSH2_METHOD_MAC_CS);
    a->mac_s2c    = libssh2_session_methods(conn->session, LIBSSH2_METHOD_MAC_SC);
    a->comp_c2s   = libssh2_session_methods(conn->session, LIBSSH2_METHOD_COMP_CS);
    a->comp_s2c   = libssh2_session_methods(conn->session, LIBSSH2_METHOD_COMP_SC);
    return NPE_OK;
}

void npe_ssh_disconnect(npe_ssh_conn_t *conn) {
    if (!conn)
        return;

    if (conn->session) {
        libssh2_session_disconnect(conn->session, "bye");
        libssh2_session_free(conn->session);
    }
    if (conn->sock >= 0)
        close(conn->sock);

    free(conn->host);
    free(conn);
}

/* ────────────────────────────────────────────────────────────────────────── */
/* AUTH                                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

npe_error_t npe_ssh_auth_password(npe_ssh_conn_t *c,
                                  const char *u,
                                  const char *p) {
    if (libssh2_userauth_password(c->session, u, p))
        return NPE_ERROR_GENERIC;
    c->state = NPE_PROTO_STATE_AUTHENTICATED;
    return NPE_OK;
}

npe_error_t npe_ssh_auth_pubkey(npe_ssh_conn_t *c,
                                const char *u,
                                const char *key,
                                const char *pass,
                                const char *pub) {
    if (libssh2_userauth_publickey_fromfile(c->session, u, pub, key, pass))
        return NPE_ERROR_GENERIC;
    c->state = NPE_PROTO_STATE_AUTHENTICATED;
    return NPE_OK;
}

npe_error_t npe_ssh_auth_agent(npe_ssh_conn_t *c,
                               const char *u) {
    LIBSSH2_AGENT *a = libssh2_agent_init(c->session);
    if (!a)
        return NPE_ERROR_GENERIC;

    if (libssh2_agent_connect(a) ||
        libssh2_agent_list_identities(a)) {
        libssh2_agent_free(a);
        return NPE_ERROR_GENERIC;
    }

    struct libssh2_agent_publickey *id = NULL;
    struct libssh2_agent_publickey *prev = NULL;
    while (libssh2_agent_get_identity(a, &id, prev) == 0) {
        if (libssh2_agent_userauth(a, u, id) == 0) {
            libssh2_agent_disconnect(a);
            libssh2_agent_free(a);
            c->state = NPE_PROTO_STATE_AUTHENTICATED;
            return NPE_OK;
        }
        prev = id;
    }

    libssh2_agent_disconnect(a);
    libssh2_agent_free(a);
    return NPE_ERROR_GENERIC;
}

bool npe_ssh_authenticated(npe_ssh_conn_t *c) {
    return c && c->state == NPE_PROTO_STATE_AUTHENTICATED;
}

/* ────────────────────────────────────────── */
/* EXEC                                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

npe_error_t npe_ssh_exec(npe_ssh_conn_t *c,
                         const char *cmd,
                         npe_ssh_exec_result_t *r) {
    LIBSSH2_CHANNEL *ch;
    uint64_t start = now_us();
    char buf[4096];
    ssize_t n;

    memset(r, 0, sizeof(*r));
    ch = libssh2_channel_open_session(c->session);
    if (!ch)
        return NPE_ERROR_CONNECTION;

    if (libssh2_channel_exec(ch, cmd)) {
        libssh2_channel_free(ch);
        return NPE_ERROR_GENERIC;
    }

    while ((n = libssh2_channel_read(ch, buf, sizeof(buf))) > 0) {
        r->stdout_data = realloc(r->stdout_data, r->stdout_len + n + 1);
        memcpy(r->stdout_data + r->stdout_len, buf, n);
        r->stdout_len += n;
    }

    while ((n = libssh2_channel_read_stderr(ch, buf, sizeof(buf))) > 0) {
        r->stderr_data = realloc(r->stderr_data, r->stderr_len + n + 1);
        memcpy(r->stderr_data + r->stderr_len, buf, n);
        r->stderr_len += n;
    }

    if (r->stdout_data)
        r->stdout_data[r->stdout_len] = '\0';
    if (r->stderr_data)
        r->stderr_data[r->stderr_len] = '\0';

    r->exit_code = libssh2_channel_get_exit_status(ch);
    r->duration_us = now_us() - start;

    libssh2_channel_close(ch);
    libssh2_channel_free(ch);
    return NPE_OK;
}

void npe_ssh_exec_result_free(npe_ssh_exec_result_t *r) {
    free(r->stdout_data);
    free(r->stderr_data);
}

/* ────────────────────────────────────────── */
/* SHELL                                                                      */
/* ────────────────────────────────────────────────────────────────────────── */

npe_error_t npe_ssh_shell_open(npe_ssh_conn_t *c,
                               const char *term,
                               uint32_t w,
                               uint32_t h,
                               npe_ssh_shell_t **out) {
    npe_ssh_shell_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NPE_ERROR_MEMORY;

    s->channel = libssh2_channel_open_session(c->session);
    if (!s->channel) {
        free(s);
        return NPE_ERROR_CONNECTION;
    }

    libssh2_channel_request_pty_size(s->channel, (int)w, (int)h);
    libssh2_channel_request_pty(s->channel, term ? term : "xterm");
    libssh2_channel_shell(s->channel);
    *out = s;
    return NPE_OK;
}

npe_error_t npe_ssh_shell_read(npe_ssh_shell_t *s,
                               void *buf,
                               size_t len,
                               size_t *rd) {
    ssize_t n = libssh2_channel_read(s->channel, buf, len);
    if (n < 0)
        return NPE_ERROR_IO;
    *rd = (size_t)n;
    return NPE_OK;
}

npe_error_t npe_ssh_shell_write(npe_ssh_shell_t *s,
                                const void *buf,
                                size_t len,
                                size_t *wr) {
    ssize_t n = libssh2_channel_write(s->channel, buf, len);
    if (n < 0)
        return NPE_ERROR_IO;
    *wr = (size_t)n;
    return NPE_OK;
}

void npe_ssh_shell_close(npe_ssh_shell_t *s) {
    if (!s)
        return;
    libssh2_channel_close(s->channel);
    libssh2_channel_free(s->channel);
    free(s);
}

/* ────────────────────────────────────────────────────────────────────────── */
/* SFTP                                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

npe_error_t npe_ssh_sftp_open(npe_ssh_conn_t *c,
                              npe_ssh_sftp_t **out) {
    npe_ssh_sftp_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NPE_ERROR_MEMORY;

    s->sftp = libssh2_sftp_init(c->session);
    if (!s->sftp) {
        free(s);
        return NPE_ERROR_PROTOCOL;
    }
    *out = s;
    return NPE_OK;
}

void npe_ssh_sftp_close(npe_ssh_sftp_t *s) {
    if (!s)
        return;
    libssh2_sftp_shutdown(s->sftp);
    free(s);
}

/* ────────────────────────────────────────── */
/* MISC                                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

const char *npe_ssh_version(void) {
    return libssh2_version(0);
}

static int lua_ssh_banner(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 22);
    npe_ssh_conn_t *conn = NULL;
    npe_proto_banner_t banner = {0};
    npe_error_t rc;

    rc = npe_ssh_connect(host, port, NULL, &conn);
    if (rc != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "SSH connection failed");
        return 2;
    }

    rc = npe_ssh_get_banner(conn, &banner);
    if (rc != NPE_OK) {
        npe_ssh_disconnect(conn);
        lua_pushnil(L);
        lua_pushstring(L, "SSH banner read failed");
        return 2;
    }

    lua_pushstring(L, banner.raw_banner ? banner.raw_banner : "");

    free((void *)banner.raw_banner);
    npe_ssh_disconnect(conn);
    return 1;
}

static int lua_ssh_login(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = (uint16_t)luaL_optinteger(L, 2, 22);
    const char *user = luaL_checkstring(L, 3);
    const char *pass = luaL_checkstring(L, 4);
    npe_ssh_conn_t *conn = NULL;
    npe_error_t rc;

    rc = npe_ssh_connect(host, port, NULL, &conn);
    if (rc != NPE_OK || !conn) {
        lua_pushnil(L);
        lua_pushstring(L, "SSH connection failed");
        return 2;
    }

    rc = npe_ssh_auth_password(conn, user, pass);

    lua_newtable(L);
    lua_pushboolean(L, rc == NPE_OK);
    lua_setfield(L, -2, "success");
    lua_pushstring(L, rc == NPE_OK ? "authentication accepted" : "authentication failed");
    lua_setfield(L, -2, "message");

    npe_ssh_disconnect(conn);
    return 1;
}

int luaopen_npe_ssh(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"banner", lua_ssh_banner},
        {"login", lua_ssh_login},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    lua_pushstring(L, npe_ssh_version());
    lua_setfield(L, -2, "version");
    return 1;
}

npe_error_t npe_ssh_register(npe_vm_t *vm) {
    /* real Lua binding lives elsewhere */
    (void)vm;
    return NPE_OK;
}
