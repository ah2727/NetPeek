/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_lib.h — Master Include for All NPE Libraries
 * =============================================================================
 *
 *  Single-header gateway to every NPE Lua library module.
 *  Include this file in npe_runtime.c to register all libraries into
 *  a new Lua state in one call.
 *
 *  Each library module exposes:
 *    - A luaopen_npe_<name>() function for registration
 *    - C utility functions that can be called from other C modules
 *
 *  Libraries are registered into the global "npe" table in Lua:
 *    npe.net.*       Network sockets
 *    npe.http.*      HTTP client
 *    npe.dns.*       DNS resolution
 *    npe.ssl.*       SSL/TLS
 *    npe.crypto.*    Cryptographic utilities
 *    npe.string.*    String manipulation
 *    npe.regex.*     Regular expressions
 *    npe.json.*      JSON handling
 *    npe.xml.*       XML parsing
 *    npe.base64.*    Base64 encoding
 *    npe.hash.*      Hashing functions
 *    npe.brute.*     Brute-force framework
 *    npe.packet.*    Raw packet crafting
 *    npe.time.*      Timing utilities
 *    npe.fs.*        Sandboxed file access
 *
 * =============================================================================
 */

#ifndef NPE_LIB_H
#define NPE_LIB_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* ── Individual library headers ───────────────────────────────────────────── */

#include "npe_lib_net.h"
#include "npe_lib_http.h"
#include "npe_lib_dns.h"
#include "npe_lib_ssl.h"
#include "npe_lib_crypto.h"
#include "npe_lib_string.h"
#include "npe_lib_regex.h"
#include "npe_lib_json.h"
#include "npe_lib_xml.h"
#include "npe_lib_base64.h"
#include "npe_lib_hash.h"
#include "npe_lib_brute.h"
#include "npe_lib_packet.h"
#include "npe_lib_time.h"
#include "npe_lib_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Library Registration Table
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_lib_entry_t
 *
 * Associates a library name (used as the Lua sub-table key under "npe")
 * with its luaopen function pointer.
 */
typedef struct npe_lib_entry {
    const char        *name;        /* e.g., "net", "http", "dns"           */
    lua_CFunction      opener;      /* e.g., luaopen_npe_net                */
} npe_lib_entry_t;

/*
 * npe_lib_get_all()
 *
 * Returns a pointer to a static, NULL-terminated array of all library
 * entries.  Used by npe_runtime to iterate and register every library.
 *
 * @return  Pointer to array of npe_lib_entry_t (last entry has name=NULL).
 */
const npe_lib_entry_t *npe_lib_get_all(void);

/*
 * npe_lib_register_all()
 *
 * Convenience function: creates the global "npe" table in the given
 * Lua state and registers every library as a sub-table.
 *
 * After calling:
 *   npe.net.connect(...)
 *   npe.http.get(...)
 *   npe.json.parse(...)
 *   ... etc.
 *
 * This function respects sandbox capabilities — if a library's capability
 * is not granted, its functions are replaced with stubs that raise errors.
 *
 * @param L   The Lua state (should already have sandbox applied).
 * @return    0 on success, -1 on error.
 */
int npe_lib_register_all(lua_State *L);

/*
 * npe_lib_register_one()
 *
 * Register a single library by name.  Useful for selectively loading
 * only required libraries.
 *
 * @param L      The Lua state.
 * @param name   Library name (e.g., "http").
 * @return       0 on success, -1 if library not found.
 */
int npe_lib_register_one(lua_State *L, const char *name);


/* ─────────────────────────────────────────────────────────────────────────────
 * Version and Metadata
 * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_LIB_VERSION_MAJOR   1
#define NPE_LIB_VERSION_MINOR   0
#define NPE_LIB_VERSION_PATCH   0
#define NPE_LIB_VERSION_STRING  "1.0.0"

/*
 * npe_lib_version()
 *
 * Returns the NPE library suite version string.
 */
const char *npe_lib_version(void);

/*
 * npe_lib_count()
 *
 * Returns the number of registered libraries.
 */
size_t npe_lib_count(void);

/*
 * npe_lib_list_names()
 *
 * Fill a caller-provided array with library name strings.
 *
 * @param names     Array of const char* to fill.
 * @param max_count Maximum number of entries to write.
 * @return          Actual number of entries written.
 */
size_t npe_lib_list_names(const char **names, size_t max_count);


/* ─────────────────────────────────────────────────────────────────────────────
 * Lua Global Table Layout Constants
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * The top-level table name in Lua's global namespace.
 * All NPE libraries live under this table.
 */
#define NPE_LIB_GLOBAL_TABLE   "npe"

/*
 * Registry key where the npe table reference is stored for fast access.
 */
#define NPE_LIB_REGISTRY_KEY   "npe.lib.root"


#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_H */
