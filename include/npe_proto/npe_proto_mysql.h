/**
 * =============================================================================
 * @file npe_proto_mysql.h
 * @brief NPE MySQL Protocol Library
 * =============================================================================
 *
 * Implements client-side interactions with MySQL/MariaDB servers, focusing on
 * information gathering, authentication, and query execution. This library is
 * intended for use within the NPE scripting environment and adheres to its
 * security and API guidelines.
 *
 * Lua API exposed as global table "mysql":
 *
 *   mysql.banner(ip, port [, timeout_ms])              -> table | nil, errmsg
 *   mysql.version(ip, port [, timeout_ms])             -> string | nil, errmsg
 *   mysql.login(ip, port, user, pass [, timeout_ms])   -> session | nil, errmsg
 *   mysql.databases(session)                           -> table | nil, errmsg
 *   mysql.tables(session, database)                    -> table | nil, errmsg
 *   mysql.users(session)                               -> table | nil, errmsg
 *   mysql.variables(session)                           -> table | nil, errmsg
 *   mysql.status(session)                              -> table | nil, errmsg
 *   mysql.query(session, sql)                          -> table | nil, errmsg
 *   mysql.close(session)                               -> bool | nil, errmsg
 *
 * Session objects are Lua full-userdata with metatable "npe.mysql.session".
 * They are automatically garbage-collected (sockets closed) when unreachable.
 *
 * @author  NetPeek Team
 * @version 1.0.0
 * =============================================================================
 */

#ifndef NPE_PROTO_MYSQL_H
#define NPE_PROTO_MYSQL_H

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

/** Default MySQL server port */
#define NPE_MYSQL_DEFAULT_PORT          3306

/** Default connect/read/write timeout in milliseconds */
#define NPE_MYSQL_DEFAULT_TIMEOUT_MS    5000

/** Maximum banner buffer length */
#define NPE_MYSQL_MAX_BANNER_LEN        1024

/** Maximum server version string length */
#define NPE_MYSQL_MAX_VERSION_LEN       256

/** Maximum hostname/IP length */
#define NPE_MYSQL_MAX_HOST_LEN          256

/** Maximum database name length */
#define NPE_MYSQL_MAX_DB_NAME_LEN       128

/** Maximum table name length */
#define NPE_MYSQL_MAX_TABLE_NAME_LEN    128

/** Maximum SQL query string length */
#define NPE_MYSQL_MAX_QUERY_LEN         (64 * 1024)    /* 64 KB */

/** Maximum single row data length */
#define NPE_MYSQL_MAX_ROW_LEN          (64 * 1024)     /* 64 KB */

/** Maximum column name length */
#define NPE_MYSQL_MAX_COL_NAME_LEN      128

/** Maximum column type string length */
#define NPE_MYSQL_MAX_COL_TYPE_LEN      32

/** Maximum MySQL packet size (protocol limit) */
#define NPE_MYSQL_MAX_PACKET_SIZE       (1 << 24)      /* 16 MB */

/** Maximum number of rows returned per query (safety limit) */
#define NPE_MYSQL_MAX_RESULT_ROWS       100000

/** Maximum number of columns per result set (safety limit) */
#define NPE_MYSQL_MAX_RESULT_COLS       1024

/** Maximum number of databases returned (safety limit) */
#define NPE_MYSQL_MAX_DATABASES         10000

/** Maximum number of tables returned per database (safety limit) */
#define NPE_MYSQL_MAX_TABLES            100000

/** Auth plugin data (scramble) buffer size */
#define NPE_MYSQL_SCRAMBLE_LEN          21

/** Session magic number for validation */
#define NPE_MYSQL_SESSION_MAGIC         0x4D595351U     /* "MYSQ" */

/** Lua metatable name for mysql session userdata */
#define NPE_MYSQL_SESSION_METATABLE     "npe.mysql.session"

/* ---------------------------------------------------------------------------
 * MySQL Protocol Constants
 * ---------------------------------------------------------------------------*/

/** MySQL protocol version we understand */
#define NPE_MYSQL_PROTOCOL_VERSION_10   10

/* MySQL capability flags (subset relevant to NPE) */
#define NPE_MYSQL_CAP_LONG_PASSWORD             (1UL << 0)
#define NPE_MYSQL_CAP_FOUND_ROWS                (1UL << 1)
#define NPE_MYSQL_CAP_LONG_FLAG                 (1UL << 2)
#define NPE_MYSQL_CAP_CONNECT_WITH_DB           (1UL << 3)
#define NPE_MYSQL_CAP_NO_SCHEMA                 (1UL << 4)
#define NPE_MYSQL_CAP_COMPRESS                  (1UL << 5)
#define NPE_MYSQL_CAP_ODBC                      (1UL << 6)
#define NPE_MYSQL_CAP_LOCAL_FILES               (1UL << 7)
#define NPE_MYSQL_CAP_IGNORE_SPACE              (1UL << 8)
#define NPE_MYSQL_CAP_PROTOCOL_41               (1UL << 9)
#define NPE_MYSQL_CAP_INTERACTIVE               (1UL << 10)
#define NPE_MYSQL_CAP_SSL                       (1UL << 11)
#define NPE_MYSQL_CAP_IGNORE_SIGPIPE            (1UL << 12)
#define NPE_MYSQL_CAP_TRANSACTIONS              (1UL << 13)
#define NPE_MYSQL_CAP_RESERVED                  (1UL << 14)
#define NPE_MYSQL_CAP_SECURE_CONNECTION         (1UL << 15)
#define NPE_MYSQL_CAP_MULTI_STATEMENTS          (1UL << 16)
#define NPE_MYSQL_CAP_MULTI_RESULTS             (1UL << 17)
#define NPE_MYSQL_CAP_PS_MULTI_RESULTS          (1UL << 18)
#define NPE_MYSQL_CAP_PLUGIN_AUTH               (1UL << 19)
#define NPE_MYSQL_CAP_CONNECT_ATTRS             (1UL << 20)
#define NPE_MYSQL_CAP_PLUGIN_AUTH_LENENC_DATA   (1UL << 21)
#define NPE_MYSQL_CAP_DEPRECATE_EOF             (1UL << 24)

/* MySQL command bytes */
#define NPE_MYSQL_COM_QUIT              0x01
#define NPE_MYSQL_COM_INIT_DB           0x02
#define NPE_MYSQL_COM_QUERY             0x03
#define NPE_MYSQL_COM_FIELD_LIST        0x04
#define NPE_MYSQL_COM_PING             0x0E
#define NPE_MYSQL_COM_CHANGE_USER       0x11

/* MySQL response packet types */
#define NPE_MYSQL_PACKET_OK             0x00
#define NPE_MYSQL_PACKET_EOF            0xFE
#define NPE_MYSQL_PACKET_ERR            0xFF
#define NPE_MYSQL_PACKET_LOCAL_INFILE   0xFB

/* MySQL character sets */
#define NPE_MYSQL_CHARSET_UTF8          33
#define NPE_MYSQL_CHARSET_UTF8MB4       45
#define NPE_MYSQL_CHARSET_BINARY        63
#define NPE_MYSQL_CHARSET_LATIN1        8

/* =============================================================================
 * ERROR CODES
 * =============================================================================*/

/**
 * Error codes returned by internal C functions.
 * Lua-facing functions translate these into nil + human-readable messages.
 */
typedef enum {
    NPE_MYSQL_OK                = 0,     /**< Success                        */
    NPE_MYSQL_ERR_NETWORK       = -1,    /**< Network/socket error           */
    NPE_MYSQL_ERR_PROTOCOL      = -2,    /**< Protocol violation             */
    NPE_MYSQL_ERR_AUTH_FAILED   = -3,    /**< Authentication rejected        */
    NPE_MYSQL_ERR_INVALID_ARG   = -4,    /**< Bad Lua argument               */
    NPE_MYSQL_ERR_PARSE_FAILED  = -5,    /**< Response parsing failure       */
    NPE_MYSQL_ERR_QUERY_FAILED  = -6,    /**< Server returned query error    */
    NPE_MYSQL_ERR_NO_SESSION    = -7,    /**< Session is NULL or invalid     */
    NPE_MYSQL_ERR_TIMEOUT       = -8,    /**< Operation timed out            */
    NPE_MYSQL_ERR_ALLOC_FAILED  = -9,    /**< Memory allocation failure      */
    NPE_MYSQL_ERR_SESSION_CLOSED = -10,  /**< Session already closed         */
    NPE_MYSQL_ERR_LIMIT_REACHED = -11,   /**< Safety limit exceeded          */
    NPE_MYSQL_ERR_SSL_FAILED    = -12,   /**< TLS/SSL handshake failure      */
    NPE_MYSQL_ERR_UNSUPPORTED   = -13,   /**< Unsupported feature/version    */
} npe_mysql_error_t;

/* =============================================================================
 * STRUCTURES
 * =============================================================================*/

/**
 * Represents a single column definition in a result set.
 */
typedef struct npe_mysql_column {
    char        name[NPE_MYSQL_MAX_COL_NAME_LEN];    /**< Column name       */
    char        type_name[NPE_MYSQL_MAX_COL_TYPE_LEN];/**< Human-readable type */
    uint8_t     type;           /**< MySQL column type enum value              */
    uint16_t    flags;          /**< Column flags (NOT_NULL, PRI_KEY, etc.)    */
    uint32_t    max_length;     /**< Maximum display length                    */
    uint8_t     decimals;       /**< Number of decimal places                  */
} npe_mysql_column_t;

/**
 * Represents a single field value in a row.
 */
typedef struct npe_mysql_field {
    char       *value;          /**< Field value as string (NULL for SQL NULL) */
    size_t      length;         /**< Length of value in bytes                  */
    bool        is_null;        /**< True if the field is SQL NULL             */
} npe_mysql_field_t;

/**
 * Represents a single row of results.
 */
typedef struct npe_mysql_row {
    npe_mysql_field_t  *fields;       /**< Array of field values             */
    size_t              field_count;  /**< Number of fields in this row      */
} npe_mysql_row_t;

/**
 * Complete query result set.
 */
typedef struct npe_mysql_result {
    bool                success;        /**< True if query executed without error */
    int                 error_code;     /**< MySQL server error code (0 = none) */
    char               *error_message;  /**< MySQL server error message (NULL if none) */

    uint64_t            affected_rows;  /**< Rows affected (UPDATE/DELETE/INSERT) */
    uint64_t            insert_id;      /**< Last AUTO_INCREMENT insert ID     */

    npe_mysql_column_t *columns;        /**< Array of column definitions       */
    size_t              column_count;   /**< Number of columns                 */

    npe_mysql_row_t    *rows;           /**< Array of result rows              */
    size_t              row_count;      /**< Number of rows returned           */
} npe_mysql_result_t;

/**
 * Parsed MySQL initial handshake packet fields.
 */
typedef struct npe_mysql_handshake {
    uint8_t     protocol_version;   /**< Protocol version byte (usually 10)  */
    char        server_version[NPE_MYSQL_MAX_VERSION_LEN]; /**< Version string */
    uint32_t    connection_id;      /**< Server-assigned connection ID        */
    uint32_t    capabilities;       /**< Server capability flags (lower 32)   */
    uint32_t    ext_capabilities;   /**< Extended capability flags            */
    uint8_t     charset;            /**< Default server character set         */
    uint16_t    status_flags;       /**< Server status flags                  */
    char        scramble[NPE_MYSQL_SCRAMBLE_LEN]; /**< Auth plugin data      */
    char        auth_plugin[64];    /**< Auth plugin name (e.g. mysql_native) */
} npe_mysql_handshake_t;

/**
 * Session handle representing an authenticated MySQL connection.
 *
 * Stored as Lua full-userdata with metatable NPE_MYSQL_SESSION_METATABLE.
 * The __gc metamethod ensures sockets are closed when the session is
 * garbage-collected.
 */
typedef struct npe_mysql_session {
    uint32_t    magic;              /**< Must equal NPE_MYSQL_SESSION_MAGIC  */
    int         sockfd;             /**< Underlying TCP socket fd (-1 = closed) */
    char        host[NPE_MYSQL_MAX_HOST_LEN]; /**< Server hostname/IP       */
    uint16_t    port;               /**< Server port                         */
    int         timeout_ms;         /**< I/O timeout in milliseconds         */

    /* Handshake data */
    npe_mysql_handshake_t handshake; /**< Parsed handshake info              */

    /* Connection state */
    uint8_t     sequence_id;        /**< Current packet sequence number      */
    bool        authenticated;      /**< True after successful login         */
    bool        closed;             /**< True after explicit or GC close     */

    /* Current database (if USE db was issued) */
    char        current_db[NPE_MYSQL_MAX_DB_NAME_LEN];
} npe_mysql_session_t;

/* =============================================================================
 * LUA-FACING API FUNCTIONS
 * =============================================================================*/

/**
 * @brief mysql.banner(ip, port [, timeout_ms]) -> table | nil, errmsg
 *
 * Connects to the MySQL server and parses the initial handshake packet.
 *
 * Returned table fields:
 *   - protocol_version  (number)   Protocol version byte
 *   - server_version    (string)   Server version string (e.g. "8.0.32")
 *   - connection_id     (number)   Connection thread ID
 *   - capabilities      (number)   Server capability flags
 *   - charset           (number)   Default character set
 *   - status_flags      (number)   Server status flags
 *   - auth_plugin       (string)   Authentication plugin name
 *
 * @param L  Lua state. Stack: [1]=ip (string), [2]=port (number), [3]=timeout (number, opt).
 * @return   Number of Lua return values (1 on success, 2 on error).
 */
int npe_lua_mysql_banner(lua_State *L);

/**
 * @brief mysql.version(ip, port [, timeout_ms]) -> string | nil, errmsg
 *
 * Convenience: connects and returns only the server version string.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_version(lua_State *L);

/**
 * @brief mysql.login(ip, port, user, pass [, timeout_ms]) -> session | nil, errmsg
 *
 * Performs full handshake + authentication. On success returns an opaque
 * session userdata that must be passed to subsequent calls.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=user, [4]=pass, [5]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_login(lua_State *L);

/**
 * @brief mysql.databases(session) -> table | nil, errmsg
 *
 * Executes SHOW DATABASES and returns an array of database name strings.
 *
 * @param L  Lua state. Stack: [1]=session userdata.
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_databases(lua_State *L);

/**
 * @brief mysql.tables(session, database) -> table | nil, errmsg
 *
 * Executes SHOW TABLES FROM <database> and returns an array of table names.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=database name (string).
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_tables(lua_State *L);

/**
 * @brief mysql.users(session) -> table | nil, errmsg
 *
 * Retrieves MySQL user accounts (SELECT user, host FROM mysql.user).
 * Returns an array of tables, each with "user" and "host" fields.
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_users(lua_State *L);

/**
 * @brief mysql.variables(session) -> table | nil, errmsg
 *
 * Executes SHOW VARIABLES and returns a table keyed by variable name.
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_variables(lua_State *L);

/**
 * @brief mysql.status(session) -> table | nil, errmsg
 *
 * Executes SHOW STATUS and returns a table keyed by status variable name.
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_status(lua_State *L);

/**
 * @brief mysql.query(session, sql) -> table | nil, errmsg
 *
 * Executes an arbitrary SQL statement.
 *
 * Returned table fields:
 *   - success        (boolean)   True if no error
 *   - affected_rows  (number)    For INSERT/UPDATE/DELETE
 *   - insert_id      (number)    For INSERT with AUTO_INCREMENT
 *   - column_names   (table)     Array of column name strings
 *   - rows           (table)     Array of row tables (each row is array of strings)
 *
 * @param L  Lua state. Stack: [1]=session, [2]=sql (string).
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_query(lua_State *L);

/**
 * @brief mysql.close(session) -> bool | nil, errmsg
 *
 * Sends COM_QUIT and closes the session. Safe to call multiple times.
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mysql_close(lua_State *L);

/* =============================================================================
 * SESSION LIFECYCLE (INTERNAL)
 * =============================================================================*/

/**
 * Validate that a Lua stack value is a live MySQL session.
 * Raises a Lua error if the session is invalid, closed, or corrupted.
 *
 * @param L    Lua state.
 * @param idx  Stack index of the session argument.
 * @return     Pointer to the validated session.
 */
npe_mysql_session_t *npe_mysql_check_session(lua_State *L, int idx);

/**
 * Lua __gc metamethod for MySQL session userdata.
 * Sends COM_QUIT if the connection is still open and closes the socket.
 *
 * @param L  Lua state.
 * @return   0 (no Lua return values).
 */
int npe_mysql_session_gc(lua_State *L);

/**
 * Lua __tostring metamethod for MySQL session userdata.
 * Returns a human-readable description: "mysql.session(host:port)".
 *
 * @param L  Lua state.
 * @return   1 (the string).
 */
int npe_mysql_session_tostring(lua_State *L);

/* =============================================================================
 * RESULT MEMORY MANAGEMENT (INTERNAL)
 * =============================================================================*/

/**
 * Free all memory associated with a result set.
 * Safe to call with NULL.
 *
 * @param result  Pointer to the result to free.
 */
void npe_mysql_result_free(npe_mysql_result_t *result);

/* =============================================================================
 * PROTOCOL HELPERS (INTERNAL — NOT EXPOSED TO LUA)
 * =============================================================================*/

/**
 * Read a complete MySQL packet from the socket.
 *
 * @param session    Active session with a valid socket.
 * @param out_buf    Pointer set to allocated buffer (caller must free).
 * @param out_len    Set to the payload length.
 * @param out_seq    Set to the packet sequence number.
 * @return           NPE_MYSQL_OK on success, error code otherwise.
 */
npe_mysql_error_t npe_mysql_read_packet(npe_mysql_session_t *session,
                                        uint8_t **out_buf,
                                        size_t *out_len,
                                        uint8_t *out_seq);

/**
 * Write a MySQL packet to the socket.
 *
 * @param session    Active session.
 * @param payload    Packet payload bytes.
 * @param length     Payload length.
 * @param seq        Sequence number to use.
 * @return           NPE_MYSQL_OK on success, error code otherwise.
 */
npe_mysql_error_t npe_mysql_write_packet(npe_mysql_session_t *session,
                                         const uint8_t *payload,
                                         size_t length,
                                         uint8_t seq);

/**
 * Parse the initial handshake packet from the server.
 *
 * @param data       Raw handshake packet payload.
 * @param len        Payload length.
 * @param out        Parsed handshake structure.
 * @return           NPE_MYSQL_OK on success, error code otherwise.
 */
npe_mysql_error_t npe_mysql_parse_handshake(const uint8_t *data,
                                            size_t len,
                                            npe_mysql_handshake_t *out);

/**
 * Build and send the client authentication response packet.
 *
 * @param session    Session (with handshake already parsed).
 * @param user       Username.
 * @param password   Password (plaintext — will be hashed per protocol).
 * @return           NPE_MYSQL_OK on success, error code otherwise.
 */
npe_mysql_error_t npe_mysql_authenticate(npe_mysql_session_t *session,
                                         const char *user,
                                         const char *password);

/**
 * Parse a text result set from a COM_QUERY response.
 *
 * @param session    Active session (for reading additional packets).
 * @param first_pkt  First response packet (column count).
 * @param first_len  Length of first packet.
 * @param out        Allocated result structure.
 * @return           NPE_MYSQL_OK on success, error code otherwise.
 */
npe_mysql_error_t npe_mysql_parse_resultset(npe_mysql_session_t *session,
                                            const uint8_t *first_pkt,
                                            size_t first_len,
                                            npe_mysql_result_t *out);

/**
 * Compute MySQL native password hash: SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
 *
 * @param password   Plaintext password.
 * @param scramble   20-byte scramble from handshake.
 * @param out        20-byte output buffer.
 */
void npe_mysql_native_password_hash(const char *password,
                                    const uint8_t *scramble,
                                    uint8_t *out);

/**
 * Return a human-readable error string for an error code.
 *
 * @param err  Error code.
 * @return     Static string describing the error.
 */
const char *npe_mysql_strerror(npe_mysql_error_t err);

/* =============================================================================
 * LIBRARY REGISTRATION
 * =============================================================================*/

/**
 * Lua function table for the "mysql" library.
 * Terminated by a {NULL, NULL} sentinel entry.
 */
extern const luaL_Reg npe_proto_mysql_funcs[];

/**
 * Lua method table for the mysql session metatable.
 */
extern const luaL_Reg npe_proto_mysql_session_methods[];

/**
 * Register the "mysql" library and session metatable into a Lua state.
 *
 * Creates:
 *   - Global table "mysql" with all library functions.
 *   - Metatable "npe.mysql.session" with __gc, __tostring, and index methods.
 *
 * @param L  Lua state.
 * @return   1 (the library table is left on the stack).
 */
int npe_proto_mysql_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_MYSQL_H */