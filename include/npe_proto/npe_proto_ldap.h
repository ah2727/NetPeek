/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_proto_ldap.h — LDAP Protocol Interactions
 * =============================================================================
 *
 *  Comprehensive LDAP (Lightweight Directory Access Protocol) client library
 *  for NPE Lua scripts. Supports LDAPv3 with STARTTLS, SASL authentication,
 *  search operations, directory enumeration, and Active Directory integration.
 *
 *  Features:
 *    - Full LDAPv3 protocol support (RFC 4511)
 *    - Anonymous, simple, and SASL authentication
 *    - STARTTLS and LDAPS (SSL/TLS) connections
 *    - Search, compare, add, modify, delete, rename operations
 *    - Paged results for large directories
 *    - Active Directory specific queries (users, groups, GPOs, trusts)
 *    - Schema and RootDSE enumeration
 *    - Password policy detection
 *    - Kerberos integration support
 *
 *  Lua API:
 *
 *    -- Connection
 *    local ldap = npe.ldap.connect(host, port)              -- Plain LDAP
 *    local ldap = npe.ldap.connect_ssl(host, port)          -- LDAPS
 *    local ldap = npe.ldap.connect(host, port, options)     -- With options
 *    ldap:starttls()                                        -- Upgrade to TLS
 *    ldap:close()
 *
 *    -- Authentication
 *    local ok, err = ldap:bind_simple(dn, password)         -- Simple bind
 *    local ok, err = ldap:bind_anonymous()                  -- Anonymous bind
 *    local ok, err = ldap:bind_sasl(mechanism, credentials) -- SASL bind
 *    local ok, err = ldap:bind_ntlm(domain, user, password) -- NTLM (AD)
 *    local ok, err = ldap:bind_gssapi(principal)            -- Kerberos
 *    ldap:unbind()
 *
 *    -- Search operations
 *    local results = ldap:search(base_dn, scope, filter, attributes)
 *    local results = ldap:search_paged(base_dn, scope, filter, attrs, page_size)
 *    local entry   = ldap:read(dn, attributes)              -- Read single entry
 *
 *    -- Scopes: "base", "one", "sub" (subtree)
 *    -- Filters: RFC 4515 filter syntax "(objectClass=user)"
 *
 *    -- Modify operations (requires write permissions)
 *    local ok, err = ldap:add(dn, attributes)
 *    local ok, err = ldap:modify(dn, modifications)
 *    local ok, err = ldap:delete(dn)
 *    local ok, err = ldap:rename(dn, new_rdn, new_parent, delete_old)
 *    local ok, err = ldap:compare(dn, attribute, value)
 *
 *    -- Directory enumeration
 *    local rootdse   = ldap:rootdse()                       -- RootDSE info
 *    local schema    = ldap:schema()                        -- Schema info
 *    local naming    = ldap:naming_contexts()               -- Base DNs
 *    local controls  = ldap:supported_controls()            -- Supported controls
 *
 *    -- Active Directory specific
 *    local users     = ldap:ad_users(base_dn)               -- Enumerate users
 *    local groups    = ldap:ad_groups(base_dn)              -- Enumerate groups
 *    local computers = ldap:ad_computers(base_dn)           -- Enumerate machines
 *    local gpos      = ldap:ad_gpos(base_dn)                -- Group policies
 *    local trusts    = ldap:ad_trusts()                     -- Domain trusts
 *    local admins    = ldap:ad_admins(base_dn)              -- Admin accounts
 *    local spns      = ldap:ad_spns(base_dn)                -- Service principals
 *    local info      = ldap:ad_domain_info()                -- Domain metadata
 *    local policy    = ldap:ad_password_policy()            -- Password policy
 *    local locked    = ldap:ad_locked_accounts(base_dn)     -- Locked accounts
 *    local disabled  = ldap:ad_disabled_accounts(base_dn)   -- Disabled accounts
 *    local expiring  = ldap:ad_expiring_passwords(base_dn, days)
 *
 *    -- Utilities
 *    local escaped   = npe.ldap.escape_filter(value)        -- Escape filter chars
 *    local escaped   = npe.ldap.escape_dn(value)            -- Escape DN chars
 *    local parsed    = npe.ldap.parse_dn(dn_string)         -- Parse DN to table
 *    local dn_str    = npe.ldap.build_dn(components)        -- Build DN string
 *    local sid_str   = npe.ldap.decode_sid(binary_sid)      -- Decode Windows SID
 *    local guid_str  = npe.ldap.decode_guid(binary_guid)    -- Decode GUID
 *    local time      = npe.ldap.decode_filetime(filetime)   -- Windows FILETIME
 *    local time      = npe.ldap.decode_gentime(gentime)     -- Generalized time
 *
 * =============================================================================
 */

#ifndef NPE_PROTO_LDAP_H
#define NPE_PROTO_LDAP_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


/* ═══════════════════════════════════════════════════════════════════════════
 * Constants and Limits
 * ═══════════════════════════════════════════════════════════════════════════ */

/* LDAP Protocol Versions */
#define NPE_LDAP_VERSION_2                  2
#define NPE_LDAP_VERSION_3                  3
#define NPE_LDAP_VERSION_DEFAULT            NPE_LDAP_VERSION_3

/* Default Ports */
#define NPE_LDAP_PORT_DEFAULT               389
#define NPE_LDAP_PORT_SSL                   636
#define NPE_LDAP_PORT_GC                    3268    /* Global Catalog        */
#define NPE_LDAP_PORT_GC_SSL                3269    /* Global Catalog SSL    */

/* Timeouts (milliseconds) */
#define NPE_LDAP_CONNECT_TIMEOUT_MS         10000
#define NPE_LDAP_READ_TIMEOUT_MS            30000
#define NPE_LDAP_WRITE_TIMEOUT_MS           10000
#define NPE_LDAP_BIND_TIMEOUT_MS            15000
#define NPE_LDAP_SEARCH_TIMEOUT_MS          60000

/* Size Limits */
#define NPE_LDAP_MAX_DN_LENGTH              2048
#define NPE_LDAP_MAX_FILTER_LENGTH          4096
#define NPE_LDAP_MAX_ATTRIBUTE_NAME         256
#define NPE_LDAP_MAX_ATTRIBUTE_VALUE        (10 * 1024 * 1024)  /* 10 MB     */
#define NPE_LDAP_MAX_ATTRIBUTES             256
#define NPE_LDAP_MAX_VALUES_PER_ATTR        1024
#define NPE_LDAP_MAX_ENTRIES                100000
#define NPE_LDAP_MAX_MESSAGE_SIZE           (16 * 1024 * 1024)  /* 16 MB     */
#define NPE_LDAP_DEFAULT_PAGE_SIZE          1000
#define NPE_LDAP_MAX_PAGE_SIZE              10000
#define NPE_LDAP_MAX_REFERRAL_HOPS          10

/* Buffer Sizes */
#define NPE_LDAP_RECV_BUFFER_SIZE           65536
#define NPE_LDAP_SEND_BUFFER_SIZE           65536
#define NPE_LDAP_SASL_BUFFER_SIZE           4096


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Result Codes (RFC 4511)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum npe_ldap_result_code {
    /* Success codes */
    NPE_LDAP_SUCCESS                        = 0,
    NPE_LDAP_COMPARE_FALSE                  = 5,
    NPE_LDAP_COMPARE_TRUE                   = 6,
    NPE_LDAP_REFERRAL                       = 10,
    NPE_LDAP_SASL_BIND_IN_PROGRESS          = 14,

    /* Error codes - Name/DN related */
    NPE_LDAP_OPERATIONS_ERROR               = 1,
    NPE_LDAP_PROTOCOL_ERROR                 = 2,
    NPE_LDAP_TIMELIMIT_EXCEEDED             = 3,
    NPE_LDAP_SIZELIMIT_EXCEEDED             = 4,
    NPE_LDAP_AUTH_METHOD_NOT_SUPPORTED      = 7,
    NPE_LDAP_STRONGER_AUTH_REQUIRED         = 8,
    NPE_LDAP_PARTIAL_RESULTS                = 9,
    NPE_LDAP_ADMIN_LIMIT_EXCEEDED           = 11,
    NPE_LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 12,
    NPE_LDAP_CONFIDENTIALITY_REQUIRED       = 13,
    
    /* Attribute errors */
    NPE_LDAP_NO_SUCH_ATTRIBUTE              = 16,
    NPE_LDAP_UNDEFINED_ATTRIBUTE_TYPE       = 17,
    NPE_LDAP_INAPPROPRIATE_MATCHING         = 18,
    NPE_LDAP_CONSTRAINT_VIOLATION           = 19,
    NPE_LDAP_ATTRIBUTE_OR_VALUE_EXISTS      = 20,
    NPE_LDAP_INVALID_ATTRIBUTE_SYNTAX       = 21,
    
    /* Name/DN errors */
    NPE_LDAP_NO_SUCH_OBJECT                 = 32,
    NPE_LDAP_ALIAS_PROBLEM                  = 33,
    NPE_LDAP_INVALID_DN_SYNTAX              = 34,
    NPE_LDAP_IS_LEAF                        = 35,
    NPE_LDAP_ALIAS_DEREFERENCING_PROBLEM    = 36,
    
    /* Security errors */
    NPE_LDAP_INAPPROPRIATE_AUTH             = 48,
    NPE_LDAP_INVALID_CREDENTIALS            = 49,
    NPE_LDAP_INSUFFICIENT_ACCESS_RIGHTS     = 50,
    NPE_LDAP_BUSY                           = 51,
    NPE_LDAP_UNAVAILABLE                    = 52,
    NPE_LDAP_UNWILLING_TO_PERFORM           = 53,
    NPE_LDAP_LOOP_DETECT                    = 54,
    
    /* Update errors */
    NPE_LDAP_NAMING_VIOLATION               = 64,
    NPE_LDAP_OBJECT_CLASS_VIOLATION         = 65,
    NPE_LDAP_NOT_ALLOWED_ON_NON_LEAF        = 66,
    NPE_LDAP_NOT_ALLOWED_ON_RDN             = 67,
    NPE_LDAP_ENTRY_ALREADY_EXISTS           = 68,
    NPE_LDAP_OBJECT_CLASS_MODS_PROHIBITED   = 69,
    NPE_LDAP_RESULTS_TOO_LARGE              = 70,
    NPE_LDAP_AFFECTS_MULTIPLE_DSAS          = 71,
    
    /* Other */
    NPE_LDAP_OTHER                          = 80,

    /* Local/API errors (negative values) */
    NPE_LDAP_ERROR_CONNECTION               = -1,
    NPE_LDAP_ERROR_TIMEOUT                  = -2,
    NPE_LDAP_ERROR_MEMORY                   = -3,
    NPE_LDAP_ERROR_ENCODING                 = -4,
    NPE_LDAP_ERROR_DECODING                 = -5,
    NPE_LDAP_ERROR_TLS                      = -6,
    NPE_LDAP_ERROR_SASL                     = -7,
    NPE_LDAP_ERROR_CANCELLED                = -8,
    NPE_LDAP_ERROR_INVALID_PARAM            = -9,
    NPE_LDAP_ERROR_NOT_CONNECTED            = -10,
    NPE_LDAP_ERROR_ALREADY_CONNECTED        = -11,
    NPE_LDAP_ERROR_NOT_BOUND                = -12,
    NPE_LDAP_ERROR_REFERRAL_LIMIT           = -13,
    NPE_LDAP_ERROR_FILTER_PARSE             = -14,
    NPE_LDAP_ERROR_BUFFER_OVERFLOW          = -15
} npe_ldap_result_code_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Search Scope
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum npe_ldap_scope {
    NPE_LDAP_SCOPE_BASE                     = 0,    /* Base object only      */
    NPE_LDAP_SCOPE_ONELEVEL                 = 1,    /* One level below base  */
    NPE_LDAP_SCOPE_SUBTREE                  = 2,    /* Entire subtree        */
    NPE_LDAP_SCOPE_SUBORDINATE              = 3     /* Subordinate subtree   */
} npe_ldap_scope_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Alias Dereferencing Options
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum npe_ldap_deref {
    NPE_LDAP_DEREF_NEVER                    = 0,    /* Never dereference     */
    NPE_LDAP_DEREF_SEARCHING                = 1,    /* Deref during search   */
    NPE_LDAP_DEREF_FINDING                  = 2,    /* Deref finding base    */
    NPE_LDAP_DEREF_ALWAYS                   = 3     /* Always dereference    */
} npe_ldap_deref_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Modification Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum npe_ldap_mod_op {
    NPE_LDAP_MOD_ADD                        = 0,    /* Add attribute value   */
    NPE_LDAP_MOD_DELETE                     = 1,    /* Delete attribute      */
    NPE_LDAP_MOD_REPLACE                    = 2,    /* Replace attribute     */
    NPE_LDAP_MOD_INCREMENT                  = 3     /* Increment numeric     */
} npe_ldap_mod_op_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Authentication Methods
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum npe_ldap_auth_method {
    NPE_LDAP_AUTH_ANONYMOUS                 = 0,
    NPE_LDAP_AUTH_SIMPLE                    = 1,
    NPE_LDAP_AUTH_SASL                      = 2,
    NPE_LDAP_AUTH_NTLM                      = 3,
    NPE_LDAP_AUTH_GSSAPI                    = 4
} npe_ldap_auth_method_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Forward Declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct npe_ldap_connection npe_ldap_connection_t;
typedef struct npe_ldap_entry      npe_ldap_entry_t;
typedef struct npe_ldap_attribute  npe_ldap_attribute_t;
typedef struct npe_ldap_message    npe_ldap_message_t;
typedef struct npe_ldap_control    npe_ldap_control_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Attribute
 * ═══════════════════════════════════════════════════════════════════════════ */

struct npe_ldap_attribute {
    char   name[NPE_LDAP_MAX_ATTRIBUTE_NAME];
    char **values;
    size_t value_count;
};


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Entry
 * ═══════════════════════════════════════════════════════════════════════════ */

struct npe_ldap_entry {
    char dn[NPE_LDAP_MAX_DN_LENGTH];

    npe_ldap_attribute_t *attributes;
    size_t attribute_count;
};


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Control (RFC 4511)
 * ═══════════════════════════════════════════════════════════════════════════ */

struct npe_ldap_control {
    char    oid[128];
    bool    critical;
    uint8_t *value;
    size_t  value_len;
};


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Message
 * ═══════════════════════════════════════════════════════════════════════════ */

struct npe_ldap_message {
    int message_id;

    npe_ldap_result_code_t result_code;

    char matched_dn[NPE_LDAP_MAX_DN_LENGTH];
    char error_message[512];

    npe_ldap_entry_t *entries;
    size_t entry_count;
};


/* ═══════════════════════════════════════════════════════════════════════════
 * LDAP Connection
 * ═══════════════════════════════════════════════════════════════════════════ */

struct npe_ldap_connection {

    /* Connection info */
    char host[256];
    int  port;

    bool connected;
    bool tls_active;
    bool bound;

    int ldap_version;

    /* Authentication */
    npe_ldap_auth_method_t auth_method;
    char bind_dn[NPE_LDAP_MAX_DN_LENGTH];

    /* Network */
    int socket_fd;

    /* TLS context pointer (opaque for SSL module) */
    void *ssl_ctx;
    void *ssl_session;

    /* Timeouts */
    int connect_timeout_ms;
    int read_timeout_ms;
    int write_timeout_ms;

    /* Search configuration */
    size_t size_limit;
    int time_limit_sec;

    /* Paging */
    size_t page_size;

    /* Message tracking */
    int next_message_id;

    /* Lua state reference */
    lua_State *L;
};


/* ═══════════════════════════════════════════════════════════════════════════
 * Connection Management
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_ldap_connection_t *
npe_ldap_connect(const char *host, int port);

npe_ldap_connection_t *
npe_ldap_connect_ssl(const char *host, int port);

int
npe_ldap_starttls(npe_ldap_connection_t *conn);

void
npe_ldap_close(npe_ldap_connection_t *conn);


/* ═══════════════════════════════════════════════════════════════════════════
 * Authentication
 * ═══════════════════════════════════════════════════════════════════════════ */

int
npe_ldap_bind_anonymous(npe_ldap_connection_t *conn);

int
npe_ldap_bind_simple(
    npe_ldap_connection_t *conn,
    const char *bind_dn,
    const char *password
);

int
npe_ldap_bind_sasl(
    npe_ldap_connection_t *conn,
    const char *mechanism,
    const uint8_t *credentials,
    size_t cred_len
);

int
npe_ldap_bind_ntlm(
    npe_ldap_connection_t *conn,
    const char *domain,
    const char *username,
    const char *password
);

int
npe_ldap_bind_gssapi(
    npe_ldap_connection_t *conn,
    const char *principal
);

int
npe_ldap_unbind(npe_ldap_connection_t *conn);


/* ═══════════════════════════════════════════════════════════════════════════
 * Search Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_ldap_message_t *
npe_ldap_search(
    npe_ldap_connection_t *conn,
    const char *base_dn,
    npe_ldap_scope_t scope,
    const char *filter,
    const char **attributes,
    size_t attr_count
);

npe_ldap_message_t *
npe_ldap_search_paged(
    npe_ldap_connection_t *conn,
    const char *base_dn,
    npe_ldap_scope_t scope,
    const char *filter,
    const char **attributes,
    size_t attr_count,
    size_t page_size
);

npe_ldap_entry_t *
npe_ldap_read(
    npe_ldap_connection_t *conn,
    const char *dn,
    const char **attributes,
    size_t attr_count
);


/* ═══════════════════════════════════════════════════════════════════════════
 * Modify Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

int
npe_ldap_add(
    npe_ldap_connection_t *conn,
    const char *dn,
    npe_ldap_attribute_t *attributes,
    size_t attr_count
);

int
npe_ldap_modify(
    npe_ldap_connection_t *conn,
    const char *dn,
    npe_ldap_mod_op_t *operations,
    npe_ldap_attribute_t *attributes,
    size_t mod_count
);

int
npe_ldap_delete(
    npe_ldap_connection_t *conn,
    const char *dn
);

int
npe_ldap_rename(
    npe_ldap_connection_t *conn,
    const char *dn,
    const char *new_rdn,
    const char *new_parent_dn,
    bool delete_old_rdn
);

int
npe_ldap_compare(
    npe_ldap_connection_t *conn,
    const char *dn,
    const char *attribute,
    const char *value
);


/* ═══════════════════════════════════════════════════════════════════════════
 * Directory Enumeration
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_ldap_entry_t *
npe_ldap_rootdse(npe_ldap_connection_t *conn);

npe_ldap_message_t *
npe_ldap_schema(npe_ldap_connection_t *conn);

npe_ldap_message_t *
npe_ldap_naming_contexts(npe_ldap_connection_t *conn);

npe_ldap_message_t *
npe_ldap_supported_controls(npe_ldap_connection_t *conn);


/* ═══════════════════════════════════════════════════════════════════════════
 * Active Directory Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

npe_ldap_message_t *
npe_ldap_ad_users(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_groups(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_computers(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_admins(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_spns(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_gpos(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_trusts(npe_ldap_connection_t *conn);

npe_ldap_entry_t *
npe_ldap_ad_domain_info(npe_ldap_connection_t *conn);

npe_ldap_entry_t *
npe_ldap_ad_password_policy(npe_ldap_connection_t *conn);

npe_ldap_message_t *
npe_ldap_ad_locked_accounts(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_disabled_accounts(
    npe_ldap_connection_t *conn,
    const char *base_dn
);

npe_ldap_message_t *
npe_ldap_ad_expiring_passwords(
    npe_ldap_connection_t *conn,
    const char *base_dn,
    int days
);


/* ═══════════════════════════════════════════════════════════════════════════
 * Utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

char *
npe_ldap_escape_filter(const char *input);

char *
npe_ldap_escape_dn(const char *input);

int
npe_ldap_parse_dn(
    const char *dn,
    char ***components,
    size_t *count
);

char *
npe_ldap_build_dn(
    char **components,
    size_t count
);

char *
npe_ldap_decode_sid(const uint8_t *binary_sid, size_t len);

char *
npe_ldap_decode_guid(const uint8_t *binary_guid, size_t len);

time_t
npe_ldap_decode_filetime(uint64_t filetime);

time_t
npe_ldap_decode_gentime(const char *gentime);


/* ═══════════════════════════════════════════════════════════════════════════
 * Memory Management
 * ═══════════════════════════════════════════════════════════════════════════ */

void
npe_ldap_entry_free(npe_ldap_entry_t *entry);

void
npe_ldap_message_free(npe_ldap_message_t *message);

void
npe_ldap_attribute_free(npe_ldap_attribute_t *attr);


/* ═══════════════════════════════════════════════════════════════════════════
 * Lua Binding
 * ═══════════════════════════════════════════════════════════════════════════ */

int luaopen_npe_ldap(lua_State *L);


#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_LDAP_H */
