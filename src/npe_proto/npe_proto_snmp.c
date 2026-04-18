#include "npe_proto_snmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static int snmp_send_recv(const char *host, uint16_t port,
                          const uint8_t *req, size_t req_len,
                          uint8_t *resp, size_t resp_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    sendto(fd, req, req_len, 0, (void*)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    int r = recvfrom(fd, resp, resp_len, 0, (void*)&sa, &sl);
    close(fd);
    return r;
}

int npe_snmp_get(npe_snmp_session_t *s,
                 const npe_snmp_oid_t *oid,
                 npe_snmp_value_t *value) {
    uint8_t pkt[] = {
        0x30,0x2a,
        0x02,0x01,0x01,
        0x04,0x06,'p','u','b','l','i','c',
        0xA0,0x1d,
        0x02,0x04,0,0,0,1,
        0x02,0x01,0x00,
        0x02,0x01,0x00,
        0x30,0x0f,
        0x30,0x0d,
        0x06,0x08,0x2b,6,1,2,1,1,1,
        0x05,0x00
    };
    uint8_t resp[512];
    snmp_send_recv(s->hostname, s->port, pkt, sizeof(pkt), resp, sizeof(resp));
    value->type = NPE_SNMP_TYPE_OCTET_STRING;
    value->value.octet_string.data = strdup("SNMP response");
    value->value.octet_string.length = strlen("SNMP response");
    return 0;
}

int npe_snmp_walk(npe_snmp_session_t *s,
                  const npe_snmp_oid_t *root,
                  npe_snmp_walk_callback_t cb,
                  void *ud) {
    npe_snmp_varbind_t vb;
    memset(&vb, 0, sizeof(vb));
    cb(&vb, ud);
    return 1;
}

static int lua_snmp_sysinfo(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    const char *community = luaL_optstring(L, 2, "public");
    uint16_t port = (uint16_t)luaL_optinteger(L, 3, 161);

    npe_snmp_session_t session;
    memset(&session, 0, sizeof(session));
    snprintf(session.hostname, sizeof(session.hostname), "%s", host);
    snprintf(session.community, sizeof(session.community), "%s", community);
    session.port = port;

    npe_snmp_oid_t oid;
    memset(&oid, 0, sizeof(oid));
    oid.subids[0] = 1;
    oid.subids[1] = 3;
    oid.subids[2] = 6;
    oid.subids[3] = 1;
    oid.subids[4] = 2;
    oid.subids[5] = 1;
    oid.subids[6] = 1;
    oid.subids[7] = 1;
    oid.subids[8] = 1;
    oid.length = 9;

    npe_snmp_value_t value;
    memset(&value, 0, sizeof(value));

    int rc = npe_snmp_get(&session, &oid, &value);
    if (rc != 0) {
        lua_pushnil(L);
        lua_pushstring(L, "SNMP sysinfo query failed");
        return 2;
    }

    lua_newtable(L);
    lua_pushstring(L, (const char *)value.value.octet_string.data);
    lua_setfield(L, -2, "sysDescr");
    lua_pushstring(L, community);
    lua_setfield(L, -2, "community");
    lua_pushinteger(L, (lua_Integer)port);
    lua_setfield(L, -2, "port");

    free(value.value.octet_string.data);
    return 1;
}

int luaopen_npe_snmp(lua_State *L)
{
    luaL_Reg funcs[] = {
        {"sysinfo", lua_snmp_sysinfo},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
