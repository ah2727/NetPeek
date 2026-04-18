// src/npe/npe_packet.c
#include <lua.h>
#include <lauxlib.h>

int luaopen_npe_packet(lua_State *L) {
    lua_newtable(L);
    // Add packet manipulation functions here later
    return 1;
}
