#ifndef NPE_LIB_SSL_H
#define NPE_LIB_SSL_H

#include <lua.h>
#include <lauxlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SSL CONSTANTS
 * ============================================================================ */

#define NPE_SSL_MAX_CERT_LEN     8192
#define NPE_SSL_MAX_CIPHERS      256
#define NPE_SSL_DEFAULT_TIMEOUT  5000

/* ============================================================================
 * SSL CERTIFICATE STRUCTURE (INTERNAL)
 * ============================================================================ */

typedef struct {
    char subject[512];
    char issuer[512];
    char serial[128];
    char not_before[64];
    char not_after[64];
    char fingerprint_sha256[128];
    char public_key_type[32];
    int  public_key_bits;
} npe_ssl_cert_t;

/* ============================================================================
 * LUA API FUNCTIONS
 * ============================================================================ */

int npe_lua_ssl_connect(lua_State *L);
int npe_lua_ssl_get_cert(lua_State *L);
int npe_lua_ssl_get_cert_chain(lua_State *L);
int npe_lua_ssl_get_cipher(lua_State *L);
int npe_lua_ssl_get_protocol(lua_State *L);
int npe_lua_ssl_enum_ciphers(lua_State *L);
int npe_lua_ssl_check_protocol(lua_State *L);

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

int npe_lib_ssl_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_SSL_H */
