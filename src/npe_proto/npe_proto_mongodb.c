#include "npe_proto_mongodb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

static int mongo_connect(const char *host, uint16_t port) {
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

static void bson_simple_doc(uint8_t **out, size_t *len,
                            const char *key, int value) {
    *len = 4 + 1 + strlen(key) + 1 + 4 + 1;
    *out = calloc(1, *len);
    memcpy(*out, len, 4);
    (*out)[4] = 0x10;
    strcpy((char *)(*out + 5), key);
    memcpy(*out + 5 + strlen(key) + 1, &value, 4);
}

int npe_lua_mongodb_ismaster(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_optinteger(L, 2, 27017);

    int fd = mongo_connect(host, port);

    uint8_t *doc;
    size_t doclen;
    bson_simple_doc(&doc, &doclen, "isMaster", 1);

    uint8_t msg[128];
    memset(msg, 0, sizeof(msg));
    memcpy(msg + 16 + 5, doc, doclen);

    write(fd, msg, 16 + 5 + doclen);
    read(fd, msg, sizeof(msg));

    close(fd);
    free(doc);

    lua_newtable(L);
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "ok");
    return 1;
}

int npe_lua_mongodb_buildinfo(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_optinteger(L, 2, 27017);

    int fd = mongo_connect(host, port);

    uint8_t *doc;
    size_t doclen;
    bson_simple_doc(&doc, &doclen, "buildInfo", 1);

    uint8_t msg[128];
    memset(msg, 0, sizeof(msg));
    memcpy(msg + 16 + 5, doc, doclen);

    write(fd, msg, 16 + 5 + doclen);
    read(fd, msg, sizeof(msg));

    close(fd);
    free(doc);

    lua_newtable(L);
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "ok");
    return 1;
}