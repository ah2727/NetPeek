// src/npe/npe_string.c
#include <lua.h>
#include <lauxlib.h>

int luaopen_npe_string(lua_State *L) {
    lua_newtable(L);
    // Add string utility functions here later
    return 1;
}
