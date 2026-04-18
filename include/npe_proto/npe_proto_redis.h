/**
 * =============================================================================
 * @file npe_proto_redis.h
 * @brief NPE Redis Protocol Library
 * =============================================================================
 *
 * Implements client-side interactions with Redis servers using the RESP
 * (REdis Serialization Protocol) version 2. Supports information gathering,
 * authentication, and common key-value operations.
 *
 * Lua API exposed as global table "redis":
 *
 *   redis.ping(ip, port [, timeout_ms])               -> string | nil, errmsg
 *   redis.info(ip, port [, timeout_ms])               -> table | nil, errmsg
 *   redis.auth(ip, port, password [, timeout_ms])     -> session | nil, errmsg
 *   redis.auth_user(ip, port, user, pass [, timeout]) -> session | nil, errmsg
 *   redis.connect(ip, port [, timeout_ms])            -> session | nil, errmsg
 *   redis.command(session, ...)                        -> value | nil, errmsg
 *   redis.get(session, key)                            -> string | nil, errmsg
 *   redis.set(session, key, value)                     -> bool | nil, errmsg
 *   redis.del(session, key)                            -> number | nil, errmsg
 *   redis.keys(session, pattern)                       -> table | nil, errmsg
 *   redis.dbsize(session)                              -> number | nil, errmsg
 *   redis.config_get(session, parameter)               -> table | nil, errmsg
 *   redis.scan(session, cursor [, pattern] [, count])  -> cursor, table | nil, errmsg
 *   redis.type(session, key)                           -> string | nil, errmsg
 *   redis.ttl(session, key)                            -> number | nil, errmsg
 *   redis.select(session, db_index)                    -> bool | nil, errmsg
 *   redis.close(session)                               -> bool | nil, errmsg
 *
 * Session objects are Lua full-userdata with metatable "npe.redis.session".
 *
 * @author  NetPeek Team
 * @version 1.0.0
 * =============================================================================
 */

#ifndef NPE_PROTO_REDIS_H
#define NPE_PROTO_REDIS_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * CONSTANTS AND LIMITS
 * =============================================================================*/

/** Default Redis server port */
#define NPE_REDIS_DEFAULT_PORT          6379

/** Default connect/read/write timeout in milliseconds */
#define NPE_REDIS_DEFAULT_TIMEOUT_MS    5000

/** Maximum length for a single RESP simple string or error line */
#define NPE_REDIS_MAX_INLINE_LEN       (64 * 1024)

/** Maximum bulk string size we will accept (safety limit) */
#define NPE_REDIS_MAX_BULK_LEN         (16 * 1024 * 1024)  /* 16 MB */

/** Maximum number of elements in a RESP array (safety limit) */
#define NPE_REDIS_MAX_ARRAY_ELEMENTS   1000000

/** Maximum recursion depth for nested RESP arrays */
#define NPE_REDIS_MAX_NESTING_DEPTH    8

/** Maximum command string length */
#define NPE_REDIS_MAX_COMMAND_LEN      (64 * 1024)

/** Maximum key name length */
#define NPE_REDIS_MAX_KEY_LEN          512

/** Maximum hostname/IP length */
#define NPE_REDIS_MAX_HOST_LEN         256

/** Maximum INFO output size */
#define NPE_REDIS_MAX_INFO_LEN         (1 * 1024 * 1024)   /* 1 MB */

/** Session magic number for validation */
#define NPE_REDIS_SESSION_MAGIC        0x52454449U          /* "REDI" */

/** Lua metatable name for redis session userdata */
#define NPE_REDIS_SESSION_METATABLE    "npe.redis.session"

/* =============================================================================
 * ERROR CODES
 * =============================================================================*/

typedef enum {
    NPE_REDIS_OK                = 0,     /**< Success                        */
    NPE_REDIS_ERR_NETWORK       = -1,    /**< Network/socket error           */
    NPE_REDIS_ERR_PROTOCOL      = -2,    /**< RESP protocol violation        */
    NPE_REDIS_ERR_AUTH_FAILED   = -3,    /**< AUTH rejected by server        */
    NPE_REDIS_ERR_INVALID_ARG   = -4,    /**< Bad Lua argument               */
    NPE_REDIS_ERR_PARSE_FAILED  = -5,    /**< Reply parsing failure          */
    NPE_REDIS_ERR_NO_SESSION    = -6,    /**< Session NULL or invalid        */
    NPE_REDIS_ERR_TIMEOUT       = -7,    /**< Operation timed out            */
    NPE_REDIS_ERR_ALLOC_FAILED  = -8,    /**< Memory allocation failure      */
    NPE_REDIS_ERR_SERVER_ERROR  = -9,    /**< Server returned -ERR           */
    NPE_REDIS_ERR_SESSION_CLOSED = -10,  /**< Session already closed         */
    NPE_REDIS_ERR_LIMIT_REACHED = -11,   /**< Safety limit exceeded          */
    NPE_REDIS_ERR_NESTING       = -12,   /**< RESP nesting too deep          */
} npe_redis_error_t;

/* =============================================================================
 * RESP REPLY STRUCTURES
 * =============================================================================*/

/**
 * RESP reply type indicators (matches RESP2 wire bytes).
 */
typedef enum {
    NPE_REDIS_REPLY_STRING      = '+',   /**< Simple String "+OK\r\n"       */
    NPE_REDIS_REPLY_ERROR       = '-',   /**< Error "-ERR ...\r\n"          */
    NPE_REDIS_REPLY_INTEGER     = ':',   /**< Integer ":1000\r\n"           */
    NPE_REDIS_REPLY_BULK        = '$',   /**< Bulk String "$6\r\nfoobar\r\n"*/
    NPE_REDIS_REPLY_ARRAY       = '*',   /**< Array "*2\r\n..."             */
    NPE_REDIS_REPLY_NIL         = 0,     /**< NULL bulk string or array     */
} npe_redis_reply_type_t;

/**
 * Recursive RESP reply structure (mirrors hiredis design).
 */
typedef struct npe_redis_reply {
    npe_redis_reply_type_t type;          /**< Reply type indicator          */

    int64_t     integer;                  /**< Value for INTEGER replies     */

    char       *str;                      /**< String data (heap-allocated)  */
    size_t      str_len;                  /**< Length of str (excl. NUL)     */

    struct npe_redis_reply **elements;    /**< Array of child replies        */
    size_t      element_count;            /**< Number of children            */
} npe_redis_reply_t;

/* =============================================================================
 * SESSION STRUCTURE
 * =============================================================================*/

/**
 * Redis session handle, stored as Lua full-userdata.
 */
typedef struct npe_redis_session {
    uint32_t    magic;              /**< Must equal NPE_REDIS_SESSION_MAGIC  */
    int         sockfd;             /**< TCP socket (-1 = closed)            */
    char        host[NPE_REDIS_MAX_HOST_LEN]; /**< Server hostname/IP       */
    uint16_t    port;               /**< Server port                         */
    int         timeout_ms;         /**< I/O timeout in milliseconds         */

    bool        authenticated;      /**< True after successful AUTH          */
    bool        closed;             /**< True after explicit or GC close     */
    int         db_index;           /**< Currently selected database index   */

    char        redis_version[64];  /**< Server version (from INFO)          */
    char        redis_mode[16];     /**< "standalone", "sentinel", "cluster" */
    int         max_clients;        /**< max_clients from CONFIG             */

    /* Internal read buffer for pipelining / partial reads */
    uint8_t    *read_buf;           /**< Dynamically allocated read buffer   */
    size_t      read_buf_len;       /**< Bytes currently in read buffer      */
    size_t      read_buf_cap;       /**< Allocated capacity of read buffer   */
} npe_redis_session_t;

/* =============================================================================
 * LUA-FACING API FUNCTIONS
 * =============================================================================*/

/**
 * @brief redis.ping(ip, port [, timeout_ms]) -> string | nil, errmsg
 *
 * Sends PING to the server and returns the response (typically "PONG").
 * Does not require authentication on default configurations.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_redis_ping(lua_State *L);

/**
 * @brief redis.info(ip, port [, timeout_ms]) -> table | nil, errmsg
 *
 * Sends INFO and parses the response into a nested table.
 * Top-level keys are section names (e.g., "server", "clients", "memory").
 * Each section value is a table of key=value pairs.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_redis_info(lua_State *L);

/**
 * @brief redis.auth(ip, port, password [, timeout_ms]) -> session | nil, errmsg
 *
 * Connects and authenticates with a single password (Redis < 6 style).
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=password, [4]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_redis_auth(lua_State *L);

/**
 * @brief redis.auth_user(ip, port, user, pass [, timeout]) -> session | nil, errmsg
 *
 * Connects and authenticates with username + password (Redis >= 6 ACL).
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=user, [4]=pass, [5]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_redis_auth_user(lua_State *L);

/**
 * @brief redis.connect(ip, port [, timeout_ms]) -> session | nil, errmsg
 *
 * Establishes a connection without authentication. Useful for servers
 * running in no-auth mode.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_redis_connect(lua_State *L);

/**
 * @brief redis.command(session, arg1, arg2, ...) -> value | nil, errmsg
 *
 * Sends a raw Redis command assembled from the given arguments.
 * Each argument becomes one element in the RESP array command.
 *
 * Return type depends on the server response:
 *   - Simple String -> Lua string
 *   - Error         -> nil + error string
 *   - Integer       -> Lua number
 *   - Bulk String   -> Lua string (or nil for NULL bulk)
 *   - Array         -> Lua table (recursively converted)
 *
 * @param L  Lua state. Stack: [1]=session, [2..N]=command arguments (strings/numbers).
 * @return   Number of Lua return values.
 */
int npe_lua_redis_command(lua_State *L);

/**
 * @brief redis.get(session, key) -> string | nil, errmsg
 */
int npe_lua_redis_get(lua_State *L);

/**
 * @brief redis.set(session, key, value) -> bool | nil, errmsg
 */
int npe_lua_redis_set(lua_State *L);

/**
 * @brief redis.del(session, key) -> number | nil, errmsg
 *
 * Returns the number of keys removed (0 or 1).
 */
int npe_lua_redis_del(lua_State *L);

/**
 * @brief redis.keys(session, pattern) -> table | nil, errmsg
 */
int npe_lua_redis_keys(lua_State *L);

/**
 * @brief redis.dbsize(session) -> number | nil, errmsg
 */
int npe_lua_redis_dbsize(lua_State *L);

/**
 * @brief redis.config_get(session, parameter) -> table | nil, errmsg
 *
 * Executes CONFIG GET <parameter> and returns a table of matching
 * config key-value pairs.
 */
int npe_lua_redis_config_get(lua_State *L);

/**
 * @brief redis.scan(session, cursor [, pattern [, count]]) -> cursor, table | nil, errmsg
 *
 * Incrementally iterates the key space. Returns the new cursor and an
 * array of keys found in this iteration.
 */
int npe_lua_redis_scan(lua_State *L);

/**
 * @brief redis.type(session, key) -> string | nil, errmsg
 *
 * Returns the data type of the key: "string", "list", "set", "zset",
 * "hash", "stream", or "none".
 */
int npe_lua_redis_type(lua_State *L);

/**
 * @brief redis.ttl(session, key) -> number | nil, errmsg
 *
 * Returns the remaining TTL in seconds. -1 if no expiry, -2 if key missing.
 */
int npe_lua_redis_ttl(lua_State *L);

/**
 * @brief redis.select(session, db_index) -> bool | nil, errmsg
 *
 * Selects the specified database index (0–15 by default).
 */
int npe_lua_redis_select(lua_State *L);

/**
 * @brief redis.close(session) -> bool | nil, errmsg
 *
 * Sends QUIT and closes the connection. Safe to call multiple times.
 */
int npe_lua_redis_close(lua_State *L);

/* =============================================================================
 * SESSION LIFECYCLE (INTERNAL)
 * =============================================================================*/

/**
 * Validate that a Lua stack value is a live Redis session.
 */
npe_redis_session_t *npe_redis_check_session(lua_State *L, int idx);

/**
 * Lua __gc metamethod. Closes socket and frees read buffer.
 */
int npe_redis_session_gc(lua_State *L);

/**
 * Lua __tostring metamethod. Returns "redis.session(host:port/db)".
 */
int npe_redis_session_tostring(lua_State *L);

/* =============================================================================
 * RESP PROTOCOL HELPERS (INTERNAL)
 * =============================================================================*/

/**
 * Free a RESP reply tree recursively. Safe with NULL.
 */
void npe_redis_reply_free(npe_redis_reply_t *reply);

/**
 * Parse a RESP reply from a buffer.
 *
 * @param buf       Input buffer.
 * @param len       Available bytes in buf.
 * @param consumed  Set to the number of bytes consumed.
 * @param depth     Current recursion depth (pass 0 initially).
 * @return          Allocated reply on success, NULL on incomplete/error.
 */
npe_redis_reply_t *npe_redis_parse_reply(const uint8_t *buf,
                                         size_t len,
                                         size_t *consumed,
                                         int depth);

/**
 * Format a command as a RESP array.
 *
 * @param buf       Output buffer.
 * @param buflen    Output buffer capacity.
 * @param argc      Number of arguments.
 * @param argv      Array of argument strings.
 * @param argvlen   Array of argument lengths (or NULL for strlen).
 * @return          Bytes written, or -1 on error.
 */
int npe_redis_format_command(char *buf, size_t buflen,
                             int argc,
                             const char **argv,
                             const size_t *argvlen);

/**
 * Send a RESP command and read the reply.
 *
 * @param session   Active session.
 * @param argc      Number of command arguments.
 * @param argv      Argument strings.
 * @param argvlen   Argument lengths (NULL = use strlen).
 * @param out       Set to the parsed reply (caller must free).
 * @return          NPE_REDIS_OK on success.
 */
npe_redis_error_t npe_redis_execute(npe_redis_session_t *session,
                                    int argc,
                                    const char **argv,
                                    const size_t *argvlen,
                                    npe_redis_reply_t **out);

/**
 * Push a RESP reply onto the Lua stack as the appropriate Lua type.
 *
 * @param L      Lua state.
 * @param reply  Parsed RESP reply.
 * @return       Number of values pushed (1), or 0 for nil.
 */
int npe_redis_reply_to_lua(lua_State *L, const npe_redis_reply_t *reply);

/**
 * Return a human-readable error string.
 */
const char *npe_redis_strerror(npe_redis_error_t err);

/* =============================================================================
 * LIBRARY REGISTRATION
 * =============================================================================*/

/** Lua function table for the "redis" library. */
extern const luaL_Reg npe_proto_redis_funcs[];

/** Lua method table for the redis session metatable. */
extern const luaL_Reg npe_proto_redis_session_methods[];

/**
 * Register the "redis" library and session metatable into a Lua state.
 *
 * @param L  Lua state.
 * @return   1 (library table on stack).
 */
int npe_proto_redis_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_REDIS_H */
