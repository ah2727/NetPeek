/**
 * =============================================================================
 * @file npe_proto_mongodb.h
 * @brief NPE MongoDB Protocol Library
 * =============================================================================
 *
 * Implements client-side interactions with MongoDB servers using the MongoDB
 * Wire Protocol (OP_MSG / OP_QUERY). Supports server information gathering,
 * SCRAM-SHA-1/SCRAM-SHA-256 authentication, and basic CRUD operations.
 *
 * Lua API exposed as global table "mongodb":
 *
 *   mongodb.serverinfo(ip, port [, timeout_ms])               -> table | nil, errmsg
 *   mongodb.buildinfo(ip, port [, timeout_ms])                -> table | nil, errmsg
 *   mongodb.ismaster(ip, port [, timeout_ms])                 -> table | nil, errmsg
 *   mongodb.login(ip, port, user, pass [, db [, timeout_ms]]) -> session | nil, errmsg
 *   mongodb.connect(ip, port [, timeout_ms])                  -> session | nil, errmsg
 *   mongodb.databases(session)                                -> table | nil, errmsg
 *   mongodb.collections(session, database)                    -> table | nil, errmsg
 *   mongodb.find(session, db, collection, filter [, opts])    -> table | nil, errmsg
 *   mongodb.count(session, db, collection [, filter])         -> number | nil, errmsg
 *   mongodb.insert(session, db, collection, document)         -> table | nil, errmsg
 *   mongodb.aggregate(session, db, collection, pipeline)      -> table | nil, errmsg
 *   mongodb.command(session, db, cmd_table)                   -> table | nil, errmsg
 *   mongodb.server_status(session)                            -> table | nil, errmsg
 *   mongodb.list_users(session, db)                           -> table | nil, errmsg
 *   mongodb.close(session)                                    -> bool | nil, errmsg
 *
 * Session objects are Lua full-userdata with metatable "npe.mongodb.session".
 *
 * MongoDB documents are represented as Lua tables. The library handles
 * BSON serialization/deserialization transparently.
 *
 * @author  NetPeek Team
 * @version 1.0.0
 * =============================================================================
 */

#ifndef NPE_PROTO_MONGODB_H
#define NPE_PROTO_MONGODB_H

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

/** Default MongoDB server port */
#define NPE_MONGODB_DEFAULT_PORT        27017

/** Default connect/read/write timeout in milliseconds */
#define NPE_MONGODB_DEFAULT_TIMEOUT_MS  5000

/** Maximum BSON document size (MongoDB hard limit) */
#define NPE_MONGODB_MAX_BSON_SIZE       (16 * 1024 * 1024)     /* 16 MB */

/** Maximum wire protocol message size */
#define NPE_MONGODB_MAX_MESSAGE_SIZE    (48 * 1024 * 1024)     /* 48 MB */

/** Maximum namespace (db.collection) length */
#define NPE_MONGODB_MAX_NAMESPACE_LEN   255

/** Maximum database name length */
#define NPE_MONGODB_MAX_DB_NAME_LEN     64

/** Maximum collection name length */
#define NPE_MONGODB_MAX_COLL_NAME_LEN   255

/** Maximum hostname/IP length */
#define NPE_MONGODB_MAX_HOST_LEN        256

/** Maximum number of documents returned per query (safety limit) */
#define NPE_MONGODB_MAX_QUERY_RESULTS   100000

/** Default batch size for find operations */
#define NPE_MONGODB_DEFAULT_BATCH_SIZE  101

/** Maximum BSON nesting depth (safety limit) */
#define NPE_MONGODB_MAX_BSON_DEPTH      32

/** Maximum number of pipeline stages for aggregate (safety limit) */
#define NPE_MONGODB_MAX_PIPELINE_STAGES 100

/** Session magic number for validation */
#define NPE_MONGODB_SESSION_MAGIC       0x4D4F4E47U             /* "MONG" */

/** Lua metatable name for mongodb session userdata */
#define NPE_MONGODB_SESSION_METATABLE   "npe.mongodb.session"

/* ---------------------------------------------------------------------------
 * MongoDB Wire Protocol Opcodes
 * ---------------------------------------------------------------------------*/

/** Reply from server (deprecated but still used for OP_QUERY responses) */
#define NPE_MONGODB_OP_REPLY           1

/** Legacy opcodes (deprecated in MongoDB 5.1+, but widely supported) */
#define NPE_MONGODB_OP_UPDATE          2001
#define NPE_MONGODB_OP_INSERT          2002
#define NPE_MONGODB_OP_QUERY           2004
#define NPE_MONGODB_OP_GET_MORE        2005
#define NPE_MONGODB_OP_DELETE          2006
#define NPE_MONGODB_OP_KILL_CURSORS    2007

/** Modern opcode (MongoDB 3.6+) */
#define NPE_MONGODB_OP_MSG             2013

/** Compressed opcode (MongoDB 3.4+) */
#define NPE_MONGODB_OP_COMPRESSED      2012

/* ---------------------------------------------------------------------------
 * MongoDB Wire Protocol Message Header
 * ---------------------------------------------------------------------------*/

/** Standard message header size in bytes */
#define NPE_MONGODB_HEADER_SIZE        16

/* ---------------------------------------------------------------------------
 * OP_MSG Flag Bits
 * ---------------------------------------------------------------------------*/

#define NPE_MONGODB_MSG_CHECKSUM_PRESENT   (1U << 0)
#define NPE_MONGODB_MSG_MORE_TO_COME       (1U << 1)
#define NPE_MONGODB_MSG_EXHAUST_ALLOWED    (1U << 16)

/* ---------------------------------------------------------------------------
 * OP_MSG Section Kinds
 * ---------------------------------------------------------------------------*/

#define NPE_MONGODB_SECTION_BODY           0    /**< Single BSON document   */
#define NPE_MONGODB_SECTION_DOC_SEQUENCE   1    /**< Document sequence      */

/* ---------------------------------------------------------------------------
 * BSON Type Tags
 * ---------------------------------------------------------------------------*/

#define NPE_BSON_TYPE_DOUBLE           0x01
#define NPE_BSON_TYPE_STRING           0x02
#define NPE_BSON_TYPE_DOCUMENT         0x03
#define NPE_BSON_TYPE_ARRAY            0x04
#define NPE_BSON_TYPE_BINARY           0x05
#define NPE_BSON_TYPE_UNDEFINED        0x06     /* deprecated */
#define NPE_BSON_TYPE_OBJECTID         0x07
#define NPE_BSON_TYPE_BOOL             0x08
#define NPE_BSON_TYPE_DATETIME         0x09
#define NPE_BSON_TYPE_NULL             0x0A
#define NPE_BSON_TYPE_REGEX            0x0B
#define NPE_BSON_TYPE_DBPOINTER        0x0C     /* deprecated */
#define NPE_BSON_TYPE_CODE             0x0D
#define NPE_BSON_TYPE_SYMBOL           0x0E     /* deprecated */
#define NPE_BSON_TYPE_CODEWSCOPE       0x0F
#define NPE_BSON_TYPE_INT32            0x10
#define NPE_BSON_TYPE_TIMESTAMP        0x11
#define NPE_BSON_TYPE_INT64            0x12
#define NPE_BSON_TYPE_DECIMAL128       0x13
#define NPE_BSON_TYPE_MINKEY           0xFF
#define NPE_BSON_TYPE_MAXKEY           0x7F

/* =============================================================================
 * ERROR CODES
 * =============================================================================*/

typedef enum {
    NPE_MONGODB_OK                  = 0,     /**< Success                    */
    NPE_MONGODB_ERR_NETWORK         = -1,    /**< Network/socket error       */
    NPE_MONGODB_ERR_PROTOCOL        = -2,    /**< Wire protocol violation    */
    NPE_MONGODB_ERR_AUTH_FAILED     = -3,    /**< Authentication rejected    */
    NPE_MONGODB_ERR_INVALID_ARG     = -4,    /**< Bad Lua argument           */
    NPE_MONGODB_ERR_PARSE_FAILED    = -5,    /**< BSON/response parse error  */
    NPE_MONGODB_ERR_COMMAND_FAILED  = -6,    /**< Server returned cmd error  */
    NPE_MONGODB_ERR_NO_SESSION      = -7,    /**< Session NULL or invalid    */
    NPE_MONGODB_ERR_TIMEOUT         = -8,    /**< Operation timed out        */
    NPE_MONGODB_ERR_ALLOC_FAILED    = -9,    /**< Memory allocation failure  */
    NPE_MONGODB_ERR_SESSION_CLOSED  = -10,   /**< Session already closed     */
    NPE_MONGODB_ERR_LIMIT_REACHED   = -11,   /**< Safety limit exceeded      */
    NPE_MONGODB_ERR_BSON_OVERFLOW   = -12,   /**< BSON document too large    */
    NPE_MONGODB_ERR_BSON_DEPTH      = -13,   /**< BSON nesting too deep      */
    NPE_MONGODB_ERR_CURSOR_EXPIRED  = -14,   /**< Server cursor expired      */
    NPE_MONGODB_ERR_UNSUPPORTED     = -15,   /**< Unsupported server feature */
} npe_mongodb_error_t;

/* =============================================================================
 * STRUCTURES
 * =============================================================================*/

/**
 * MongoDB wire protocol message header.
 */
typedef struct npe_mongodb_msg_header {
    int32_t     message_length;     /**< Total message size (incl. header)   */
    int32_t     request_id;         /**< Client-generated request identifier */
    int32_t     response_to;        /**< request_id this is a response to    */
    int32_t     op_code;            /**< Operation code                      */
} npe_mongodb_msg_header_t;

/**
 * Parsed OP_REPLY response.
 */
typedef struct npe_mongodb_op_reply {
    int32_t     response_flags;     /**< Bit vector of response flags        */
    int64_t     cursor_id;          /**< Cursor ID (0 = closed)              */
    int32_t     starting_from;      /**< Position in cursor                  */
    int32_t     number_returned;    /**< Number of documents in reply        */
    uint8_t   **documents;          /**< Array of raw BSON documents         */
    size_t     *doc_sizes;          /**< Sizes of each BSON document         */
} npe_mongodb_op_reply_t;

/**
 * BSON document builder for constructing commands.
 */
typedef struct npe_bson_buffer {
    uint8_t    *data;               /**< Allocated buffer                    */
    size_t      length;             /**< Current data length                 */
    size_t      capacity;           /**< Allocated capacity                  */
    int         depth;              /**< Current nesting depth               */
    bool        error;              /**< True if any operation failed        */
} npe_bson_buffer_t;

/**
 * Server information gathered from isMaster/hello response.
 */
typedef struct npe_mongodb_server_info {
    bool        is_master;          /**< True if this is a primary           */
    bool        is_secondary;       /**< True if this is a secondary         */
    int32_t     max_bson_size;      /**< Max BSON document size              */
    int32_t     max_message_size;   /**< Max wire message size               */
    int32_t     max_write_batch;    /**< Max write batch size                */
    char        set_name[64];       /**< Replica set name (empty if none)    */
    int32_t     min_wire_version;   /**< Minimum wire protocol version       */
    int32_t     max_wire_version;   /**< Maximum wire protocol version       */
    bool        read_only;          /**< True if server is read-only         */
} npe_mongodb_server_info_t;

/**
 * MongoDB session handle, stored as Lua full-userdata.
 */
typedef struct npe_mongodb_session {
    uint32_t    magic;              /**< Must equal NPE_MONGODB_SESSION_MAGIC */
    int         sockfd;             /**< TCP socket (-1 = closed)            */
    char        host[NPE_MONGODB_MAX_HOST_LEN]; /**< Server hostname/IP     */
    uint16_t    port;               /**< Server port                         */
    int         timeout_ms;         /**< I/O timeout in milliseconds         */

    bool        authenticated;      /**< True after successful auth          */
    bool        closed;             /**< True after explicit or GC close     */
    int32_t     request_id_counter; /**< Monotonically increasing request ID */

    /* Server info from isMaster/hello */
    npe_mongodb_server_info_t server_info;

    /* Authentication database (default "admin") */
    char        auth_db[NPE_MONGODB_MAX_DB_NAME_LEN];

    /* Negotiated wire version */
    int32_t     wire_version;       /**< Negotiated wire protocol version    */

    /* Whether to use OP_MSG (wire >= 6) or OP_QUERY (legacy) */
    bool        use_op_msg;         /**< True if server supports OP_MSG      */
} npe_mongodb_session_t;

/* =============================================================================
 * LUA-FACING API FUNCTIONS
 * =============================================================================*/

/**
 * @brief mongodb.serverinfo(ip, port [, timeout_ms]) -> table | nil, errmsg
 *
 * Connects and sends an isMaster/hello command. Returns server metadata
 * including version, replica set info, and wire protocol versions.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_serverinfo(lua_State *L);

/**
 * @brief mongodb.buildinfo(ip, port [, timeout_ms]) -> table | nil, errmsg
 *
 * Retrieves the buildInfo command output: version, git hash, OpenSSL info, etc.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_buildinfo(lua_State *L);

/**
 * @brief mongodb.ismaster(ip, port [, timeout_ms]) -> table | nil, errmsg
 *
 * Alias/wrapper for the isMaster command. Useful for cluster topology discovery.
 *
 * @param L  Lua state.
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_ismaster(lua_State *L);

/**
 * @brief mongodb.login(ip, port, user, pass [, db [, timeout_ms]]) -> session | nil, errmsg
 *
 * Connects and authenticates using SCRAM-SHA-256 (preferred) or SCRAM-SHA-1.
 * Default auth database is "admin" if not specified.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=user, [4]=pass,
 *           [5]=db (opt, default "admin"), [6]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_login(lua_State *L);

/**
 * @brief mongodb.connect(ip, port [, timeout_ms]) -> session | nil, errmsg
 *
 * Establishes a connection without authentication. Works when the server
 * has no authentication enabled.
 *
 * @param L  Lua state. Stack: [1]=ip, [2]=port, [3]=timeout (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_connect(lua_State *L);

/**
 * @brief mongodb.databases(session) -> table | nil, errmsg
 *
 * Executes listDatabases and returns an array of tables, each with:
 *   - name       (string)
 *   - sizeOnDisk (number)
 *   - empty      (boolean)
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_databases(lua_State *L);

/**
 * @brief mongodb.collections(session, database) -> table | nil, errmsg
 *
 * Lists all collections in the specified database. Returns an array of
 * tables with "name" and "type" fields.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=database (string).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_collections(lua_State *L);

/**
 * @brief mongodb.find(session, db, collection, filter [, opts]) -> table | nil, errmsg
 *
 * Executes a find query. Filter is a Lua table representing a BSON query document.
 * Options table may include:
 *   - limit       (number)    Maximum documents to return
 *   - skip        (number)    Documents to skip
 *   - sort        (table)     Sort specification
 *   - projection  (table)     Field projection
 *   - batch_size  (number)    Cursor batch size
 *
 * Returns an array of document tables.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=db, [3]=coll, [4]=filter, [5]=opts (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_find(lua_State *L);

/**
 * @brief mongodb.count(session, db, collection [, filter]) -> number | nil, errmsg
 *
 * Returns the count of documents matching the optional filter.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=db, [3]=coll, [4]=filter (opt).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_count(lua_State *L);

/**
 * @brief mongodb.insert(session, db, collection, document) -> table | nil, errmsg
 *
 * Inserts a single document. Returns a table with "inserted_id" and "acknowledged".
 *
 * @param L  Lua state. Stack: [1]=session, [2]=db, [3]=coll, [4]=document (table).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_insert(lua_State *L);

/**
 * @brief mongodb.aggregate(session, db, collection, pipeline) -> table | nil, errmsg
 *
 * Executes an aggregation pipeline. Pipeline is a Lua array of stage tables.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=db, [3]=coll, [4]=pipeline (table).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_aggregate(lua_State *L);

/**
 * @brief mongodb.command(session, db, cmd_table) -> table | nil, errmsg
 *
 * Executes an arbitrary database command. The cmd_table is a Lua table
 * representing the command BSON document.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=db (string), [3]=cmd_table (table).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_command(lua_State *L);

/**
 * @brief mongodb.server_status(session) -> table | nil, errmsg
 *
 * Executes the serverStatus command and returns comprehensive server metrics.
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_server_status(lua_State *L);

/**
 * @brief mongodb.list_users(session, db) -> table | nil, errmsg
 *
 * Lists all users in the specified database. Returns an array of user info tables.
 *
 * @param L  Lua state. Stack: [1]=session, [2]=db (string).
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_list_users(lua_State *L);

/**
 * @brief mongodb.close(session) -> bool | nil, errmsg
 *
 * Closes the MongoDB connection. Safe to call multiple times.
 *
 * @param L  Lua state. Stack: [1]=session.
 * @return   Number of Lua return values.
 */
int npe_lua_mongodb_close(lua_State *L);

/* =============================================================================
 * SESSION LIFECYCLE (INTERNAL)
 * =============================================================================*/

/**
 * Validate that a Lua stack value is a live MongoDB session.
 */
npe_mongodb_session_t *npe_mongodb_check_session(lua_State *L, int idx);

/**
 * Lua __gc metamethod for MongoDB session userdata.
 */
int npe_mongodb_session_gc(lua_State *L);

/**
 * Lua __tostring metamethod. Returns "mongodb.session(host:port)".
 */
int npe_mongodb_session_tostring(lua_State *L);

/**
 * Generate the next request ID for the session.
 */
int32_t npe_mongodb_next_request_id(npe_mongodb_session_t *session);

/* =============================================================================
 * BSON HELPERS (INTERNAL)
 * =============================================================================*/

/**
 * Initialize a BSON buffer with initial capacity.
 *
 * @param buf       Buffer to initialize.
 * @param capacity  Initial allocation size.
 * @return          NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_bson_init(npe_bson_buffer_t *buf, size_t capacity);

/**
 * Free a BSON buffer.
 */
void npe_bson_destroy(npe_bson_buffer_t *buf);

/**
 * Convert a Lua table at the given stack index to a BSON document.
 *
 * @param L     Lua state.
 * @param idx   Stack index of the table.
 * @param buf   BSON buffer to write into.
 * @param depth Current nesting depth (pass 0 initially).
 * @return      NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_bson_from_lua(lua_State *L, int idx,
                                      npe_bson_buffer_t *buf,
                                      int depth);

/**
 * Parse a BSON document and push it onto the Lua stack as a table.
 *
 * @param L     Lua state.
 * @param data  Raw BSON document bytes.
 * @param len   Length of BSON data.
 * @param depth Current nesting depth (pass 0 initially).
 * @return      NPE_MONGODB_OK on success (table is on Lua stack).
 */
npe_mongodb_error_t npe_bson_to_lua(lua_State *L, const uint8_t *data,
                                    size_t len, int depth);

/**
 * Append a key-value pair to a BSON buffer.
 */
npe_mongodb_error_t npe_bson_append_int32(npe_bson_buffer_t *buf,
                                          const char *key, int32_t value);

npe_mongodb_error_t npe_bson_append_int64(npe_bson_buffer_t *buf,
                                          const char *key, int64_t value);

npe_mongodb_error_t npe_bson_append_double(npe_bson_buffer_t *buf,
                                           const char *key, double value);

npe_mongodb_error_t npe_bson_append_string(npe_bson_buffer_t *buf,
                                           const char *key, const char *value,
                                           int32_t length);

npe_mongodb_error_t npe_bson_append_bool(npe_bson_buffer_t *buf,
                                         const char *key, bool value);

npe_mongodb_error_t npe_bson_append_null(npe_bson_buffer_t *buf,
                                         const char *key);

npe_mongodb_error_t npe_bson_append_document(npe_bson_buffer_t *buf,
                                             const char *key,
                                             const uint8_t *doc,
                                             size_t doc_len);

npe_mongodb_error_t npe_bson_append_array(npe_bson_buffer_t *buf,
                                          const char *key,
                                          const uint8_t *arr,
                                          size_t arr_len);

/* =============================================================================
 * WIRE PROTOCOL HELPERS (INTERNAL)
 * =============================================================================*/

/**
 * Send an OP_MSG command and read the response.
 *
 * @param session     Active session.
 * @param db          Database name (for $db field).
 * @param cmd_bson    BSON command document.
 * @param cmd_len     BSON document length.
 * @param reply_bson  Set to allocated reply BSON (caller must free).
 * @param reply_len   Set to reply BSON length.
 * @return            NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_mongodb_send_op_msg(npe_mongodb_session_t *session,
                                            const char *db,
                                            const uint8_t *cmd_bson,
                                            size_t cmd_len,
                                            uint8_t **reply_bson,
                                            size_t *reply_len);

/**
 * Send an OP_QUERY command and read the OP_REPLY (legacy path).
 *
 * @param session     Active session.
 * @param ns          Full namespace (e.g. "admin.$cmd").
 * @param query_bson  BSON query document.
 * @param query_len   BSON document length.
 * @param reply       Set to parsed OP_REPLY (caller must free).
 * @return            NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_mongodb_send_op_query(npe_mongodb_session_t *session,
                                              const char *ns,
                                              const uint8_t *query_bson,
                                              size_t query_len,
                                              npe_mongodb_op_reply_t *reply);

/**
 * Free an OP_REPLY structure.
 */
void npe_mongodb_op_reply_free(npe_mongodb_op_reply_t *reply);

/**
 * Read a complete wire protocol message from the socket.
 *
 * @param session   Active session.
 * @param header    Set to the parsed message header.
 * @param body      Set to allocated body bytes (caller must free).
 * @param body_len  Set to body length.
 * @return          NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_mongodb_read_message(npe_mongodb_session_t *session,
                                             npe_mongodb_msg_header_t *header,
                                             uint8_t **body,
                                             size_t *body_len);

/**
 * Write a complete wire protocol message to the socket.
 *
 * @param session   Active session.
 * @param op_code   Wire protocol opcode.
 * @param body      Message body bytes.
 * @param body_len  Body length.
 * @return          NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_mongodb_write_message(npe_mongodb_session_t *session,
                                              int32_t op_code,
                                              const uint8_t *body,
                                              size_t body_len);

/* =============================================================================
 * AUTHENTICATION HELPERS (INTERNAL)
 * =============================================================================*/

/**
 * Perform SCRAM-SHA-256 authentication (preferred for MongoDB 4.0+).
 *
 * @param session   Active session.
 * @param user      Username.
 * @param password  Password.
 * @param db        Auth database name.
 * @return          NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_mongodb_auth_scram_sha256(npe_mongodb_session_t *session,
                                                  const char *user,
                                                  const char *password,
                                                  const char *db);

/**
 * Perform SCRAM-SHA-1 authentication (fallback for older servers).
 *
 * @param session   Active session.
 * @param user      Username.
 * @param password  Password.
 * @param db        Auth database name.
 * @return          NPE_MONGODB_OK on success.
 */
npe_mongodb_error_t npe_mongodb_auth_scram_sha1(npe_mongodb_session_t *session,
                                                const char *user,
                                                const char *password,
                                                const char *db);

/**
 * Return a human-readable error string.
 */
const char *npe_mongodb_strerror(npe_mongodb_error_t err);

/* =============================================================================
 * LIBRARY REGISTRATION
 * =============================================================================*/

/** Lua function table for the "mongodb" library. */
extern const luaL_Reg npe_proto_mongodb_funcs[];

/** Lua method table for the mongodb session metatable. */
extern const luaL_Reg npe_proto_mongodb_session_methods[];

/**
 * Register the "mongodb" library and session metatable into a Lua state.
 *
 * @param L  Lua state.
 * @return   1 (library table on stack).
 */
int npe_proto_mongodb_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_MONGODB_H */
