#include "npe_proto_redis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

static int redis_connect(const char *host, uint16_t port, int timeout_ms) {
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

static int redis_send(int fd, const char *buf, size_t len) {
    return write(fd, buf, len) == (ssize_t)len ? 0 : -1;
}

static int redis_readline(int fd, char *buf, size_t max) {
    size_t i = 0;
    while (i < max - 1) {
        if (read(fd, &buf[i], 1) != 1) break;
        if (buf[i++] == '\n') break;
    }
    buf[i] = 0;
    return (int)i;
}

static int redis_simple_cmd(const char *host, uint16_t port,
                            const char *cmd, char *out, size_t outlen) {
    int fd = redis_connect(host, port, NPE_REDIS_DEFAULT_TIMEOUT_MS);
    redis_send(fd, cmd, strlen(cmd));
    redis_readline(fd, out, outlen);
    close(fd);
    return 0;
}

int npe_lua_redis_ping(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_optinteger(L, 2, 6379);
    char resp[1024];

    redis_simple_cmd(host, port, "*1\r\n$4\r\nPING\r\n", resp, sizeof(resp));
    lua_pushstring(L, resp + 1);
    return 1;
}

int npe_lua_redis_info(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_optinteger(L, 2, 6379);
    char resp[NPE_REDIS_MAX_INFO_LEN];

    redis_simple_cmd(host, port, "*1\r\n$4\r\nINFO\r\n", resp, sizeof(resp));
    lua_newtable(L);

    char *line = strtok(resp, "\r\n");
    while (line) {
        if (line[0] != '#' && strchr(line, ':')) {
            char *sep = strchr(line, ':');
            *sep = 0;
            lua_pushstring(L, sep + 1);
            lua_setfield(L, -2, line);
        }
        line = strtok(NULL, "\r\n");
    }
    return 1;
}

int npe_lua_redis_auth(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);
    const char *pass = luaL_checkstring(L, 3);
    char cmd[512], resp[512];

    snprintf(cmd, sizeof(cmd),
             "*2\r\n$4\r\nAUTH\r\n$%zu\r\n%s\r\n",
             strlen(pass), pass);

    redis_simple_cmd(host, port, cmd, resp, sizeof(resp));
    if (resp[0] == '-') {
        lua_pushnil(L);
        lua_pushstring(L, resp);
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

int npe_lua_redis_auth_user(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);
    const char *user = luaL_checkstring(L, 3);
    const char *pass = luaL_checkstring(L, 4);
    char cmd[768], resp[512];

    snprintf(cmd, sizeof(cmd),
             "*3\r\n$4\r\nAUTH\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n",
             strlen(user), user, strlen(pass), pass);

    redis_simple_cmd(host, port, cmd, resp, sizeof(resp));
    if (resp[0] == '-') {
        lua_pushnil(L);
        lua_pushstring(L, resp);
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

int npe_lua_redis_close(lua_State *L) {
    lua_pushboolean(L, 1);
    return 1;
}

int luaopen_npe_redis(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"ping", npe_lua_redis_ping},
        {"info", npe_lua_redis_info},
        {"auth", npe_lua_redis_auth},
        {"auth_user", npe_lua_redis_auth_user},
        {"close", npe_lua_redis_close},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
