#ifndef NPE_LUA_COMPAT_H
#define NPE_LUA_COMPAT_H

/*
 * Lua compatibility layer
 * Supports Lua 5.1 → 5.4 (Homebrew, system Lua, embedded)
 */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* ============================
 * Lua 5.1 compatibility
 * ============================ */
#if LUA_VERSION_NUM < 502

/* luaL_testudata does not exist in 5.1 */
static inline void *luaL_testudata(lua_State *L, int idx, const char *tname)
{
    void *p = lua_touserdata(L, idx);
    if (p == NULL) return NULL;
    if (!lua_getmetatable(L, idx)) return NULL;
    luaL_getmetatable(L, tname);
    int equal = lua_rawequal(L, -1, -2);
    lua_pop(L, 2);
    return equal ? p : NULL;
}

#endif /* LUA_VERSION_NUM < 502 */

#endif /* NPE_LUA_COMPAT_H */