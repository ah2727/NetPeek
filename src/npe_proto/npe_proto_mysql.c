#include "npe_proto_mysql.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdint.h>
#include <openssl/sha.h>

static int mysql_connect(const char *host, uint16_t port) {
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

static int mysql_read_packet(int fd, uint8_t **buf, size_t *len) {
    uint8_t hdr[4];
    if (read(fd, hdr, 4) != 4) {
        return -1;
    }
    *len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
    *buf = malloc(*len);
    if (!*buf) {
        return -1;
    }
    if (read(fd, *buf, *len) != (ssize_t)*len) {
        free(*buf);
        *buf = NULL;
        return -1;
    }
    return 0;
}

static void mysql_native_token(const char *password,
                               const unsigned char *scramble,
                               size_t scramble_len,
                               unsigned char out[SHA_DIGEST_LENGTH])
{
    unsigned char s1[SHA_DIGEST_LENGTH];
    unsigned char s2[SHA_DIGEST_LENGTH];
    unsigned char s3[SHA_DIGEST_LENGTH];
    unsigned char tmp[SHA_DIGEST_LENGTH + 64];

    SHA1((const unsigned char *)password, strlen(password), s1);
    SHA1(s1, SHA_DIGEST_LENGTH, s2);

    memcpy(tmp, scramble, scramble_len);
    memcpy(tmp + scramble_len, s2, SHA_DIGEST_LENGTH);
    SHA1(tmp, scramble_len + SHA_DIGEST_LENGTH, s3);

    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
        out[i] = s1[i] ^ s3[i];
    }
}

int npe_lua_mysql_login(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_optinteger(L, 2, 3306);
    const char *user = luaL_checkstring(L, 3);
    const char *pass = luaL_checkstring(L, 4);

    int fd = mysql_connect(host, (uint16_t)port);
    uint8_t *pkt = NULL;
    size_t len = 0;

    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "MySQL connection failed");
        return 2;
    }

    if (mysql_read_packet(fd, &pkt, &len) != 0 || !pkt || len < 32) {
        if (pkt) free(pkt);
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, "MySQL handshake failed");
        return 2;
    }

    size_t idx = 0;
    idx++; /* protocol version */
    while (idx < len && pkt[idx] != 0) idx++;
    idx++; /* skip NUL */
    idx += 4; /* connection id */

    unsigned char scramble[32] = {0};
    size_t scramble_len = 0;
    if (idx + 8 >= len) {
        free(pkt);
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, "MySQL handshake parse failed");
        return 2;
    }
    memcpy(scramble, pkt + idx, 8);
    scramble_len = 8;
    idx += 8;
    idx++; /* filler */

    uint16_t cap_low = 0;
    if (idx + 1 < len) {
        cap_low = (uint16_t)(pkt[idx] | (pkt[idx + 1] << 8));
    }
    idx += 2;
    idx += 1; /* charset */
    idx += 2; /* status */

    uint16_t cap_high = 0;
    if (idx + 1 < len) {
        cap_high = (uint16_t)(pkt[idx] | (pkt[idx + 1] << 8));
    }
    idx += 2;
    uint32_t caps = ((uint32_t)cap_high << 16) | cap_low;

    uint8_t auth_data_len = 0;
    if (idx < len) auth_data_len = pkt[idx];
    idx += 1;
    idx += 10; /* reserved */

    size_t need_more = auth_data_len > 8 ? (size_t)(auth_data_len - 8) : 12;
    if (need_more > 13) need_more = 13;
    if (idx + need_more <= len) {
        memcpy(scramble + scramble_len, pkt + idx, need_more);
        scramble_len += need_more;
    }

    free(pkt);

    unsigned char token[SHA_DIGEST_LENGTH] = {0};
    mysql_native_token(pass, scramble, scramble_len, token);

    uint32_t client_flags = NPE_MYSQL_CAP_LONG_PASSWORD |
                            NPE_MYSQL_CAP_PROTOCOL_41 |
                            NPE_MYSQL_CAP_SECURE_CONNECTION |
                            NPE_MYSQL_CAP_PLUGIN_AUTH;
    if (!(caps & NPE_MYSQL_CAP_PLUGIN_AUTH)) {
        client_flags &= ~NPE_MYSQL_CAP_PLUGIN_AUTH;
    }

    unsigned char payload[1024] = {0};
    size_t p = 0;

    payload[p++] = (unsigned char)(client_flags & 0xFF);
    payload[p++] = (unsigned char)((client_flags >> 8) & 0xFF);
    payload[p++] = (unsigned char)((client_flags >> 16) & 0xFF);
    payload[p++] = (unsigned char)((client_flags >> 24) & 0xFF);

    payload[p++] = 0x00; payload[p++] = 0x00; payload[p++] = 0x00; payload[p++] = 0x01; /* max packet */
    payload[p++] = 33; /* utf8_general_ci */
    memset(payload + p, 0, 23);
    p += 23;

    size_t user_len = strlen(user);
    if (p + user_len + 1 >= sizeof(payload)) {
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, "MySQL login payload too large");
        return 2;
    }
    memcpy(payload + p, user, user_len);
    p += user_len;
    payload[p++] = 0x00;

    payload[p++] = SHA_DIGEST_LENGTH;
    memcpy(payload + p, token, SHA_DIGEST_LENGTH);
    p += SHA_DIGEST_LENGTH;

    if (client_flags & NPE_MYSQL_CAP_PLUGIN_AUTH) {
        const char *plugin = "mysql_native_password";
        size_t plugin_len = strlen(plugin);
        if (p + plugin_len + 1 >= sizeof(payload)) {
            close(fd);
            lua_pushnil(L);
            lua_pushstring(L, "MySQL plugin payload too large");
            return 2;
        }
        memcpy(payload + p, plugin, plugin_len);
        p += plugin_len;
        payload[p++] = 0x00;
    }

    unsigned char hdr[4];
    hdr[0] = (unsigned char)(p & 0xFF);
    hdr[1] = (unsigned char)((p >> 8) & 0xFF);
    hdr[2] = (unsigned char)((p >> 16) & 0xFF);
    hdr[3] = 0x01;

    if (write(fd, hdr, 4) != 4 || write(fd, payload, p) != (ssize_t)p) {
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, "MySQL login write failed");
        return 2;
    }

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (mysql_read_packet(fd, &resp, &resp_len) != 0 || !resp || resp_len == 0) {
        if (resp) free(resp);
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, "MySQL login response failed");
        return 2;
    }

    lua_newtable(L);
    if (resp[0] == 0x00) {
        lua_pushboolean(L, 1);
        lua_setfield(L, -2, "success");
        lua_pushinteger(L, 0);
        lua_setfield(L, -2, "code");
        lua_pushstring(L, "OK");
        lua_setfield(L, -2, "message");
    } else {
        uint16_t err_code = 0;
        const char *err_msg = "authentication failed";
        if (resp_len >= 3 && resp[0] == 0xFF) {
            err_code = (uint16_t)(resp[1] | (resp[2] << 8));
            if (resp_len > 9) {
                err_msg = (const char *)(resp + 9);
            } else if (resp_len > 3) {
                err_msg = (const char *)(resp + 3);
            }
        }
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, "success");
        lua_pushinteger(L, err_code);
        lua_setfield(L, -2, "code");
        lua_pushstring(L, err_msg);
        lua_setfield(L, -2, "message");
    }

    free(resp);
    close(fd);
    return 1;
}

int npe_lua_mysql_banner(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_optinteger(L, 2, 3306);

    int fd = mysql_connect(host, port);
    uint8_t *pkt;
    size_t len;

    mysql_read_packet(fd, &pkt, &len);
    close(fd);

    lua_newtable(L);
    lua_pushinteger(L, pkt[0]);
    lua_setfield(L, -2, "protocol_version");
    lua_pushstring(L, (char *)(pkt + 1));
    lua_setfield(L, -2, "server_version");

    free(pkt);
    return 1;
}

int npe_lua_mysql_version(lua_State *L) {
    npe_lua_mysql_banner(L);
    lua_getfield(L, -1, "server_version");
    return 1;
}

static int lua_mysql_info(lua_State *L)
{
    return npe_lua_mysql_banner(L);
}

int luaopen_npe_mysql(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"banner", npe_lua_mysql_banner},
        {"version", npe_lua_mysql_version},
        {"login", npe_lua_mysql_login},
        {"info", lua_mysql_info},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
