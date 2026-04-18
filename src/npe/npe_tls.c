#include <lua.h>
#include <lauxlib.h>

#include "npe_lib_ssl.h"

int luaopen_npe_tls(lua_State *L)
{
    return npe_lib_ssl_register(L);
}

