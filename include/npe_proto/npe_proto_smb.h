/**
 * =============================================================================
 * @file npe_proto_smb.h
 * @brief NPE SMB Protocol Library
 * =============================================================================
 *
 * Implements client-side interactions with SMB/CIFS servers (SMB1 and SMB2/3).
 * Focuses on protocol negotiation, session setup, share enumeration, and
 * basic file operations for network reconnaissance.
 *
 * Lua API exposed as global table "smb":
 *
 *   smb.negotiate(ip, port [, timeout_ms])                -> table | nil, errmsg
 *   smb.os_discovery(ip, port [, timeout_ms])             -> table | nil, errmsg
 *   smb.login(ip, port, user, pass [, domain [, timeout]])-> session | nil, errmsg
 *   smb.login_guest(ip, port [, timeout_ms])              -> session | nil, errmsg
 *   smb.login_anonymous(ip, port [, timeout_ms])          -> session | nil, errmsg
 *   smb.shares(session)                                   -> table | nil, errmsg
 *   smb.share_connect(session, share_name)                -> tree_id | nil, errmsg
 *   smb.share_disconnect(session, tree_id)                -> bool | nil, errmsg
 *   smb.ls(session, tree_id, path)                        -> table | nil, errmsg
 *   smb.read(session, tree_id, path [, offset [, len]])   -> string | nil, errmsg
 *   smb.stat(session, tree_id, path)                      -> table | nil, errmsg
 *   smb.security(session)                                 -> table | nil, errmsg
 *   smb.sessions(session)                                 -> table | nil, errmsg
 *   smb.close(session)                                    -> bool | nil, errmsg
 *
 * Session objects are Lua full-userdata with metatable "npe.smb.session".
 *
 * @author  NetPeek Team
 * @version 1.0.0
 * =============================================================================
 */

#ifndef NPE_PROTO_SMB_H
#define NPE_PROTO_SMB_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* =============================================================================
 * CONSTANTS AND LIMITS
 * =============================================================================*/

/** Default SMB port (Direct TCP) */
#define NPE_SMB_DEFAULT_PORT 445

/** Legacy NetBIOS SSN port */
#define NPE_SMB_NETBIOS_PORT 139

/** Default connect/read/write timeout in milliseconds */
#define NPE_SMB_DEFAULT_TIMEOUT_MS 5000

/** Maximum hostname/IP length */
#define NPE_SMB_MAX_HOST_LEN 256

/** Maximum share name length */
#define NPE_SMB_MAX_SHARE_NAME_LEN 256

/** Maximum path length */
#define NPE_SMB_MAX_PATH_LEN 1024

/** Maximum file name length */
#define NPE_SMB_MAX_FILENAME_LEN 255

/** Maximum domain/workgroup name length */
#define NPE_SMB_MAX_DOMAIN_LEN 256

/** Maximum username length */
#define NPE_SMB_MAX_USERNAME_LEN 256

/** Maximum password length */
#define NPE_SMB_MAX_PASSWORD_LEN 256

/** Maximum OS name string length */
#define NPE_SMB_MAX_OS_LEN 256

/** Maximum LAN Manager string length */
#define NPE_SMB_MAX_LANMAN_LEN 256

/** Maximum number of shares returned (safety limit) */
#define NPE_SMB_MAX_SHARES 10000

/** Maximum number of directory entries returned (safety limit) */
#define NPE_SMB_MAX_DIR_ENTRIES 100000

/** Maximum file read size per operation */
#define NPE_SMB_MAX_READ_SIZE (1 * 1024 * 1024) /* 1 MB */

/** Maximum SMB message size */
#define NPE_SMB_MAX_MESSAGE_SIZE (8 * 1024 * 1024) /* 8 MB */

/** NetBIOS session header size */
#define NPE_SMB_NETBIOS_HEADER_SIZE 4

/** Session magic number for validation */
#define NPE_SMB_SESSION_MAGIC 0x534D4253U /* "SMBS" */

/** Lua metatable name for SMB session userdata */
#define NPE_SMB_SESSION_METATABLE "npe.smb.session"

/* ---------------------------------------------------------------------------
 * SMB Protocol Magic Bytes
 * ---------------------------------------------------------------------------*/

/** SMB1 magic: 0xFF 'S' 'M' 'B' */
#define NPE_SMB1_MAGIC 0x424D53FFU

/** SMB2/3 magic: 0xFE 'S' 'M' 'B' */
#define NPE_SMB2_MAGIC 0x424D53FEU

    /* ---------------------------------------------------------------------------
     * SMB Version Dialects
     * ---------------------------------------------------------------------------*/

#define NPE_SMB_DIALECT_SMB1 0x0000     /**< "NT LM 0.12"       */
#define NPE_SMB_DIALECT_SMB2_002 0x0202 /**< SMB 2.0.2          */
#define NPE_SMB_DIALECT_SMB2_100 0x0210 /**< SMB 2.1            */
#define NPE_SMB_DIALECT_SMB3_000 0x0300 /**< SMB 3.0            */
#define NPE_SMB_DIALECT_SMB3_002 0x0302 /**< SMB 3.0.2          */
#define NPE_SMB_DIALECT_SMB3_100 0x0310 /**< SMB 3.1.0 (Win10+) */
#define NPE_SMB_DIALECT_SMB3_110 0x0311 /**< SMB 3.1.1          */
#define NPE_SMB_DIALECT_WILDCARD 0x02FF /**< SMB2 wildcard      */

    /* ---------------------------------------------------------------------------
     * SMB2 Command Codes
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_CMD_NEGOTIATE 0x0000
#define NPE_SMB2_CMD_SESSION_SETUP 0x0001
#define NPE_SMB2_CMD_LOGOFF 0x0002
#define NPE_SMB2_CMD_TREE_CONNECT 0x0003
#define NPE_SMB2_CMD_TREE_DISCONNECT 0x0004
#define NPE_SMB2_CMD_CREATE 0x0005
#define NPE_SMB2_CMD_CLOSE 0x0006
#define NPE_SMB2_CMD_FLUSH 0x0007
#define NPE_SMB2_CMD_READ 0x0008
#define NPE_SMB2_CMD_WRITE 0x0009
#define NPE_SMB2_CMD_LOCK 0x000A
#define NPE_SMB2_CMD_IOCTL 0x000B
#define NPE_SMB2_CMD_CANCEL 0x000C
#define NPE_SMB2_CMD_ECHO 0x000D
#define NPE_SMB2_CMD_QUERY_DIRECTORY 0x000E
#define NPE_SMB2_CMD_CHANGE_NOTIFY 0x000F
#define NPE_SMB2_CMD_QUERY_INFO 0x0010
#define NPE_SMB2_CMD_SET_INFO 0x0011
#define NPE_SMB2_CMD_OPLOCK_BREAK 0x0012

    /* ---------------------------------------------------------------------------
     * SMB2 Header Flags
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_FLAGS_SERVER_TO_REDIR 0x00000001U
#define NPE_SMB2_FLAGS_ASYNC_COMMAND 0x00000002U
#define NPE_SMB2_FLAGS_RELATED_OPS 0x00000004U
#define NPE_SMB2_FLAGS_SIGNED 0x00000008U
#define NPE_SMB2_FLAGS_PRIORITY_MASK 0x00000070U
#define NPE_SMB2_FLAGS_DFS_OPERATIONS 0x10000000U
#define NPE_SMB2_FLAGS_REPLAY_OPERATION 0x20000000U

    /* ---------------------------------------------------------------------------
     * SMB2 Share Types
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_SHARE_TYPE_DISK 0x01
#define NPE_SMB2_SHARE_TYPE_PIPE 0x02
#define NPE_SMB2_SHARE_TYPE_PRINT 0x03

    /* ---------------------------------------------------------------------------
     * SMB2 Share Capabilities
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_SHARE_CAP_DFS 0x00000008U
#define NPE_SMB2_SHARE_CAP_CONTINUOUS_AVAIL 0x00000010U
#define NPE_SMB2_SHARE_CAP_SCALEOUT 0x00000020U
#define NPE_SMB2_SHARE_CAP_CLUSTER 0x00000040U
#define NPE_SMB2_SHARE_CAP_ASYMMETRIC 0x00000080U
#define NPE_SMB2_SHARE_CAP_REDIRECT_TO_OWNER 0x00000100U

    /* ---------------------------------------------------------------------------
     * SMB2 File Attributes
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_FILE_ATTR_READONLY 0x00000001U
#define NPE_SMB2_FILE_ATTR_HIDDEN 0x00000002U
#define NPE_SMB2_FILE_ATTR_SYSTEM 0x00000004U
#define NPE_SMB2_FILE_ATTR_DIRECTORY 0x00000010U
#define NPE_SMB2_FILE_ATTR_ARCHIVE 0x00000020U
#define NPE_SMB2_FILE_ATTR_NORMAL 0x00000080U
#define NPE_SMB2_FILE_ATTR_TEMPORARY 0x00000100U
#define NPE_SMB2_FILE_ATTR_COMPRESSED 0x00000800U
#define NPE_SMB2_FILE_ATTR_ENCRYPTED 0x00004000U

    /* ---------------------------------------------------------------------------
     * SMB2 Security Modes
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_NEGOTIATE_SIGNING_ENABLED 0x0001
#define NPE_SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002

    /* ---------------------------------------------------------------------------
     * SMB2 Capabilities
     * ---------------------------------------------------------------------------*/

#define NPE_SMB2_GLOBAL_CAP_DFS 0x00000001U
#define NPE_SMB2_GLOBAL_CAP_LEASING 0x00000002U
#define NPE_SMB2_GLOBAL_CAP_LARGE_MTU 0x00000004U
#define NPE_SMB2_GLOBAL_CAP_MULTI_CHANNEL 0x00000008U
#define NPE_SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010U
#define NPE_SMB2_GLOBAL_CAP_DIRECTORY_LEASING 0x00000020U
#define NPE_SMB2_GLOBAL_CAP_ENCRYPTION 0x00000040U

    /* ---------------------------------------------------------------------------
     * NT STATUS Codes (common subset)
     * ---------------------------------------------------------------------------*/

#define NPE_NT_STATUS_SUCCESS 0x00000000U
#define NPE_NT_STATUS_MORE_PROCESSING_REQUIRED 0xC0000016U
#define NPE_NT_STATUS_LOGON_FAILURE 0xC000006DU
#define NPE_NT_STATUS_ACCOUNT_DISABLED 0xC0000072U
#define NPE_NT_STATUS_INVALID_PARAMETER 0xC000000DU
#define NPE_NT_STATUS_NO_SUCH_FILE 0xC000000FU
#define NPE_NT_STATUS_ACCESS_DENIED 0xC0000022U
#define NPE_NT_STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034U
#define NPE_NT_STATUS_OBJECT_NAME_COLLISION 0xC0000035U
#define NPE_NT_STATUS_SHARING_VIOLATION 0xC0000043U
#define NPE_NT_STATUS_ACCOUNT_RESTRICTION 0xC000006EU
#define NPE_NT_STATUS_PASSWORD_EXPIRED 0xC0000071U
#define NPE_NT_STATUS_INSUFF_SERVER_RESOURCES 0xC0000205U
#define NPE_NT_STATUS_NOT_FOUND 0xC0000225U
#define NPE_NT_STATUS_PATH_NOT_COVERED 0xC0000257U
#define NPE_NT_STATUS_NO_MORE_FILES 0x80000006U
#define NPE_NT_STATUS_BUFFER_OVERFLOW 0x80000005U
#define NPE_NT_STATUS_PENDING 0x00000103U

    /* =============================================================================
     * ERROR CODES
     * =============================================================================*/

    typedef enum
    {
        NPE_SMB_OK = 0,                     /**< Success                        */
        NPE_SMB_ERR_NETWORK = -1,           /**< Network/socket error           */
        NPE_SMB_ERR_PROTOCOL = -2,          /**< SMB protocol violation         */
        NPE_SMB_ERR_AUTH_FAILED = -3,       /**< Authentication rejected        */
        NPE_SMB_ERR_INVALID_ARG = -4,       /**< Bad Lua argument               */
        NPE_SMB_ERR_PARSE_FAILED = -5,      /**< Response parsing failure       */
        NPE_SMB_ERR_ACCESS_DENIED = -6,     /**< Server returned ACCESS_DENIED  */
        NPE_SMB_ERR_NO_SESSION = -7,        /**< Session NULL or invalid        */
        NPE_SMB_ERR_TIMEOUT = -8,           /**< Operation timed out            */
        NPE_SMB_ERR_ALLOC_FAILED = -9,      /**< Memory allocation failure      */
        NPE_SMB_ERR_SESSION_CLOSED = -10,   /**< Session already closed         */
        NPE_SMB_ERR_LIMIT_REACHED = -11,    /**< Safety limit exceeded          */
        NPE_SMB_ERR_NOT_FOUND = -12,        /**< File/share not found           */
        NPE_SMB_ERR_SIGNING_REQUIRED = -13, /**< Server requires signing        */
        NPE_SMB_ERR_NEGOTIATE_FAILED = -14, /**< Dialect negotiation failed     */
        NPE_SMB_ERR_NT_STATUS = -15,        /**< Server returned NT_STATUS err  */
        NPE_SMB_ERR_TREE_CONNECT = -16,     /**< Tree connect failed            */
        NPE_SMB_ERR_UNSUPPORTED = -17,      /**< Unsupported SMB dialect/feature*/
    } npe_smb_error_t;

    /* =============================================================================
     * STRUCTURES
     * =============================================================================*/

    /**
     * SMB2 message header (64 bytes).
     */
    typedef struct npe_smb2_header
    {
        uint8_t protocol_id[4];    /**< 0xFE 'S' 'M' 'B'                   */
        uint16_t structure_size;   /**< Must be 64                          */
        uint16_t credit_charge;    /**< Credit charge for this request      */
        uint32_t status;           /**< NT_STATUS code (responses only)     */
        uint16_t command;          /**< SMB2 command code                   */
        uint16_t credit_req_grant; /**< Credits requested/granted           */
        uint32_t flags;            /**< Header flags                        */
        uint32_t next_command;     /**< Offset to next command (compound)   */
        uint64_t message_id;       /**< Unique message ID                   */
        uint32_t reserved;         /**< Reserved / AsyncId high             */
        uint32_t tree_id;          /**< Tree connect identifier             */
        uint64_t session_id;       /**< Session identifier                  */
        uint8_t signature[16];     /**< Message signature (if signed)       */
    } npe_smb2_header_t;

    /**
     * Negotiation result from the server.
     */
    typedef struct npe_smb_negotiate_result
    {
        uint16_t dialect;           /**< Negotiated dialect (e.g., 0x0311)   */
        uint16_t security_mode;     /**< Server security mode flags          */
        uint32_t capabilities;      /**< Server global capabilities          */
        uint32_t max_transact_size; /**< Maximum transaction size            */
        uint32_t max_read_size;     /**< Maximum read size                   */
        uint32_t max_write_size;    /**< Maximum write size                  */
        uint64_t system_time;       /**< Server system time (FILETIME)       */
        uint64_t server_start_time; /**< Server boot time (FILETIME)         */
        uint8_t server_guid[16];    /**< Server GUID                         */

        /* Security buffer (for SPNEGO/NTLMSSP) */
        uint8_t *security_blob;   /**< Security buffer data (allocated)    */
        size_t security_blob_len; /**< Security buffer length              */

        /* SMB1 specific (if SMB1 was negotiated) */
        bool is_smb1;                                /**< True if server chose SMB1           */
        char native_os[NPE_SMB_MAX_OS_LEN];          /**< SMB1 OS string    */
        char native_lanman[NPE_SMB_MAX_LANMAN_LEN];  /**< SMB1 LAN manager */
        char primary_domain[NPE_SMB_MAX_DOMAIN_LEN]; /**< SMB1 domain     */
    } npe_smb_negotiate_result_t;

    /**
     * Represents a network share.
     */
    typedef struct npe_smb_share_info
    {
        char name[NPE_SMB_MAX_SHARE_NAME_LEN]; /**< Share name        */
        uint8_t type;                          /**< Share type (DISK, PIPE, PRINT)      */
        char comment[256];                     /**< Share comment/description           */

        /* Extended info (from QueryInfo if available) */
        uint32_t capabilities; /**< Share capabilities flags            */
        uint32_t access_mask;  /**< Granted access mask                 */
        bool is_hidden;        /**< True if share name ends with '$'    */
    } npe_smb_share_info_t;

    /**
     * Represents a directory entry.
     */
    typedef struct npe_smb_dir_entry
    {
        char name[NPE_SMB_MAX_FILENAME_LEN]; /**< File/directory name   */
        uint32_t attributes;                 /**< FILE_ATTRIBUTE_xxx flags            */
        uint64_t size;                       /**< File size in bytes                  */
        uint64_t alloc_size;                 /**< Allocation size                     */
        uint64_t creation_time;              /**< Creation time (FILETIME)            */
        uint64_t last_access_time;           /**< Last access time (FILETIME)         */
        uint64_t last_write_time;            /**< Last write time (FILETIME)          */
        uint64_t change_time;                /**< Last change time (FILETIME)         */
        bool is_directory;                   /**< True if this is a directory         */
    } npe_smb_dir_entry_t;

    /**
     * Represents file/path stat information.
     */
    typedef struct npe_smb_file_info
    {
        uint32_t attributes;       /**< FILE_ATTRIBUTE_xxx flags            */
        uint64_t size;             /**< File size in bytes                  */
        uint64_t alloc_size;       /**< Allocation size                     */
        uint64_t creation_time;    /**< Creation time (FILETIME)            */
        uint64_t last_access_time; /**< Last access time                    */
        uint64_t last_write_time;  /**< Last write time                     */
        uint64_t change_time;      /**< Last change time                    */
        bool is_directory;         /**< True if directory                   */
        bool is_readonly;          /**< True if read-only                   */
        bool is_hidden;            /**< True if hidden                      */
        bool is_system;            /**< True if system file                 */
    } npe_smb_file_info_t;

    /**
     * OS discovery information extracted from negotiate + session setup.
     */
    typedef struct npe_smb_os_info
    {
        char os_name[NPE_SMB_MAX_OS_LEN]; /**< OS name           */
        char os_version[128];             /**< OS version string                   */
        uint8_t os_major;                 /**< OS major version                    */
        uint8_t os_minor;                 /**< OS minor version                    */
        uint16_t os_build;                /**< OS build number                     */
        char netbios_name[64];            /**< NetBIOS computer name               */
        char netbios_domain[64];          /**< NetBIOS domain name                 */
        char dns_name[256];               /**< DNS computer name                   */
        char dns_domain[256];             /**< DNS domain name                     */
        char dns_forest[256];             /**< DNS forest name                     */
        uint16_t smb_dialect;             /**< Negotiated SMB dialect              */
        bool signing_enabled;             /**< True if signing is enabled          */
        bool signing_required;            /**< True if signing is required         */
        bool encryption_supported;        /**< True if encryption is supported   */
    } npe_smb_os_info_t;

    /**
     * Security information about the server.
     */
    typedef struct npe_smb_security_info
    {
        bool signing_enabled;                /**< Message signing enabled             */
        bool signing_required;               /**< Message signing required            */
        bool encryption_capable;             /**< Server supports encryption          */
        uint16_t dialect;                    /**< Negotiated dialect                   */
        uint32_t capabilities;               /**< Server capabilities                 */
        char domain[NPE_SMB_MAX_DOMAIN_LEN]; /**< Domain name       */
        char server_name[256];               /**< Server name                         */
        uint64_t server_time;                /**< Server time (FILETIME)              */
    } npe_smb_security_info_t;

    /**
     * SMB session handle, stored as Lua full-userdata.
     */
    typedef struct npe_smb_session
    {
        uint32_t magic;                  /**< Must equal NPE_SMB_SESSION_MAGIC    */
        int sockfd;                      /**< TCP socket (-1 = closed)            */
        char host[NPE_SMB_MAX_HOST_LEN]; /**< Server hostname/IP         */
        uint16_t port;                   /**< Server port                         */
        int timeout_ms;                  /**< I/O timeout in milliseconds         */

        bool authenticated; /**< True after successful auth          */
        bool closed;        /**< True after explicit or GC close     */
        bool is_guest;      /**< True if logged in as guest          */
        bool is_anonymous;  /**< True if anonymous (null session)    */

        /* Negotiation state */
        npe_smb_negotiate_result_t negotiate; /**< Cached negotiate result       */
        uint16_t dialect;                     /**< Negotiated dialect                   */
        bool signing_required;                /**< True if signing is mandatory        */

        /* Session state */
        uint64_t session_id;         /**< SMB2 session ID                     */
        uint64_t message_id_counter; /**< Monotonically increasing msg ID     */
        uint16_t credit_balance;     /**< Available credits                   */

        /* Session key for signing/encryption */
        uint8_t session_key[16]; /**< Derived session key                 */
        size_t session_key_len;      /**< Session key length                  */
    } npe_smb_session_t;

    /* =============================================================================
     * LUA-FACING FUNCTIONS
     * =============================================================================*/

    /**
     * smb.negotiate(host, port) → table
     */
    int npe_lua_smb_negotiate(lua_State *L);

    /**
     * smb.login_anonymous(host, port) → session userdata
     */
    int npe_lua_smb_login_anonymous(lua_State *L);

    /**
     * smb.close(session) → bool
     */
    int npe_lua_smb_close(lua_State *L);

    /**
     * Register SMB library with Lua VM.
     */
    int npe_smb_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_SMB_H */
