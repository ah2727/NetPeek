// src/npe/npe_crypto.c
#include <lua.h>
#include <lauxlib.h>
#include "npe_lib_crypto.h"

int luaopen_npe_crypto(lua_State *L) {
    return npe_lib_crypto_register(L);
}
