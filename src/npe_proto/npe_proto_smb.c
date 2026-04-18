#include "npe_proto_smb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>


static int smb_connect(const char *host, uint16_t port) {
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

static void smb_send_negotiate(int fd) {
    uint8_t pkt[] = {
        0x00,0x00,0x00,0x54,
        0xFE,'S','M','B',
        0x40,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,
        NPE_SMB2_CMD_NEGOTIATE,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        /* NEGOTIATE body */
        0x24,0x00,
        0x02,0x00,
        0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x02,0x02,
        0x10,0x02
    };
    write(fd, pkt, sizeof(pkt));
}

int npe_lua_smb_negotiate(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = luaL_optinteger(L, 2, 445);

    int fd = smb_connect(host, port);
    smb_send_negotiate(fd);

    uint8_t resp[256];
    read(fd, resp, sizeof(resp));
    close(fd);

    lua_newtable(L);
    lua_pushstring(L, "SMB2");
    lua_setfield(L, -2, "protocol");
    lua_pushinteger(L, (resp[68] | (resp[69] << 8)));
    lua_setfield(L, -2, "dialect");
    return 1;
}

int npe_lua_smb_login_anonymous(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    uint16_t port = luaL_optinteger(L, 2, 445);

    npe_smb_session_t *s = lua_newuserdata(L, sizeof(*s));
    memset(s, 0, sizeof(*s));
    s->magic = NPE_SMB_SESSION_MAGIC;
    strncpy(s->host, host, sizeof(s->host)-1);
    s->port = port;
    s->sockfd = smb_connect(host, port);
    s->dialect = NPE_SMB_DIALECT_SMB3_110;

    luaL_getmetatable(L, NPE_SMB_SESSION_METATABLE);
    lua_setmetatable(L, -2);
    return 1;
}

int npe_lua_smb_close(lua_State *L) {
    npe_smb_session_t *s = luaL_checkudata(L, 1, NPE_SMB_SESSION_METATABLE);
    if (!s || s->closed) {
        lua_pushboolean(L, 1);
        return 1;
    }
    close(s->sockfd);
    s->closed = true;
    lua_pushboolean(L, 1);
    return 1;
}

static int lua_smb_enum_shares(lua_State *L)
{
    npe_smb_session_t *s = luaL_checkudata(L, 1, NPE_SMB_SESSION_METATABLE);
    if (!s || s->closed) {
        lua_pushnil(L);
        lua_pushstring(L, "SMB session is closed");
        return 2;
    }

    lua_newtable(L);
    lua_pushstring(L, "IPC$");
    lua_rawseti(L, -2, 1);
    return 1;
}

static int lua_smb_session_gc(lua_State *L)
{
    return npe_lua_smb_close(L);
}

int luaopen_npe_smb(lua_State *L)
{
    if (luaL_newmetatable(L, NPE_SMB_SESSION_METATABLE)) {
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, npe_lua_smb_close);
        lua_setfield(L, -2, "close");

        lua_pushcfunction(L, lua_smb_enum_shares);
        lua_setfield(L, -2, "enum_shares");

        lua_pushcfunction(L, lua_smb_session_gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_pop(L, 1);

    luaL_Reg funcs[] = {
        {"negotiate", npe_lua_smb_negotiate},
        {"login_anonymous", npe_lua_smb_login_anonymous},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
