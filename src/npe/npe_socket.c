// src/npe/npe_socket.c
#include <lua.h>
#include <lauxlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

static int l_connect(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        lua_pushnil(L);
        return 1;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        close(sock);
        lua_pushnil(L);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS)
    {
        close(sock);
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, sock);
    return 1;
}

static int l_recv(lua_State *L)
{
    int sock = (int)luaL_checkinteger(L, 1);
    int max_bytes = (int)luaL_optinteger(L, 2, 4096);
    if (max_bytes <= 0)
        max_bytes = 4096;

    char *buf = (char *)malloc((size_t)max_bytes + 1);
    if (!buf)
    {
        lua_pushnil(L);
        return 1;
    }

    ssize_t n = recv(sock, buf, (size_t)max_bytes, 0);
    if (n <= 0)
    {
        free(buf);
        lua_pushnil(L);
        return 1;
    }

    buf[n] = '\0';
    lua_pushlstring(L, buf, n);
    free(buf);
    return 1;
}

static int l_close(lua_State *L)
{
    int sock = (int)luaL_checkinteger(L, 1);
    close(sock);
    return 0;
}

static int l_set_timeout(lua_State *L)
{
    // Stub - implement with setsockopt SO_RCVTIMEO if needed
    return 0;
}

static int l_send(lua_State *L)
{
    int sock = (int)luaL_checkinteger(L, 1);
    size_t len;
    const char *data = luaL_checklstring(L, 2, &len);

    ssize_t n = send(sock, data, len, 0);
    lua_pushboolean(L, n == (ssize_t)len);
    return 1;
}
int luaopen_npe_socket(lua_State *L)
{
    lua_newtable(L);

    lua_pushcfunction(L, l_connect);
    lua_setfield(L, -2, "connect");

    lua_pushcfunction(L, l_recv);
    lua_setfield(L, -2, "recv");

    lua_pushcfunction(L, l_close);
    lua_setfield(L, -2, "close");

    lua_pushcfunction(L, l_set_timeout);
    lua_setfield(L, -2, "set_timeout");

    lua_pushcfunction(L, l_send);
    lua_setfield(L, -2, "send");
    
    return 1;
}
