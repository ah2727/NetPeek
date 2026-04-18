#ifndef NPE_LIB_CRYPTO_H
#define NPE_LIB_CRYPTO_H

#include <lua.h>
#include <lauxlib.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CRYPTO CONSTANTS
 * ============================================================================ */

#define NPE_CRYPTO_MAX_KEY_LEN     64
#define NPE_CRYPTO_MAX_BLOCK_LEN  4096
#define NPE_CRYPTO_HASH_HEX_LEN   128

/* ============================================================================
 * LUA API FUNCTIONS
 * ============================================================================ */

/* Hashing */
int npe_lua_crypto_md5(lua_State *L);
int npe_lua_crypto_sha1(lua_State *L);
int npe_lua_crypto_sha256(lua_State *L);
int npe_lua_crypto_sha512(lua_State *L);

/* HMAC */
int npe_lua_crypto_hmac_sha256(lua_State *L);
int npe_lua_crypto_hmac_sha1(lua_State *L);

/* Random */
int npe_lua_crypto_random_bytes(lua_State *L);

/* Symmetric crypto */
int npe_lua_crypto_aes_encrypt(lua_State *L);
int npe_lua_crypto_aes_decrypt(lua_State *L);

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

int npe_lib_crypto_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_CRYPTO_H */
