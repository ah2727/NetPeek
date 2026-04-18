// src/npe/npe_json.c
#include <lua.h>
#include <lauxlib.h>
#include "npe_lib_json.h"

int luaopen_npe_json(lua_State *L) {
    if (npe_lib_json_register((npe_vm_t *)L) != NPE_OK)
    {
        lua_newtable(L);
        return 1;
    }

    lua_getglobal(L, "npe");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "json");
        lua_remove(L, -2);
        if (lua_istable(L, -1))
            return 1;
        lua_pop(L, 1);
    }
    else
    {
        lua_pop(L, 1);
    }

    lua_newtable(L);
    return 1;
}
