#ifndef NPE_LIB_STRING_H
#define NPE_LIB_STRING_H

#include <lua.h>
#include <lauxlib.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * STRING CONSTANTS
 * ============================================================================ */

#define NPE_STRING_MAX_LEN     8192
#define NPE_STRING_MAX_TOKENS  1024

/* ============================================================================
 * LUA API FUNCTIONS
 * ============================================================================ */

int npe_lua_str_split(lua_State *L);
int npe_lua_str_trim(lua_State *L);
int npe_lua_str_ltrim(lua_State *L);
int npe_lua_str_rtrim(lua_State *L);
int npe_lua_str_starts_with(lua_State *L);
int npe_lua_str_ends_with(lua_State *L);
int npe_lua_str_contains(lua_State *L);
int npe_lua_str_hex_encode(lua_State *L);
int npe_lua_str_hex_decode(lua_State *L);
int npe_lua_str_url_encode(lua_State *L);
int npe_lua_str_url_decode(lua_State *L);

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

int npe_lib_string_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_STRING_H */
