/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_proto_snmp.h — SNMP Protocol Interaction Library
 * =============================================================================
 *
 *  Comprehensive SNMP (Simple Network Management Protocol) implementation
 *  supporting SNMPv1, SNMPv2c, and SNMPv3 with authentication and encryption.
 *
 *  Lua API:
 *
 *    -- SNMPv1/v2c Basic Operations
 *    local session = npe.snmp.open(host, {
 *        version    = "2c",           -- "1", "2c", or "3"
 *        community  = "public",       -- Community string (v1/v2c)
 *        port       = 161,
 *        timeout_ms = 5000,
 *        retries    = 2,
 *    })
 *
 *    -- GET operation
 *    local value = session:get("1.3.6.1.2.1.1.1.0")  -- sysDescr.0
 *    local values = session:get({
 *        "1.3.6.1.2.1.1.1.0",     -- sysDescr.0
 *        "1.3.6.1.2.1.1.3.0",     -- sysUpTime.0
 *        "1.3.6.1.2.1.1.5.0"      -- sysName.0
 *    })
 *
 *    -- GET-NEXT operation
 *    local oid, value = session:get_next("1.3.6.1.2.1.1")
 *
 *    -- WALK operation (iterate through MIB tree)
 *    for oid, value, type in session:walk("1.3.6.1.2.1.2.2.1") do
 *        print(oid, value, type)
 *    end
 *
 *    -- BULK-GET operation (SNMPv2c/v3)
 *    local results = session:get_bulk({
 *        non_repeaters = 0,
 *        max_repetitions = 10,
 *        oids = {"1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.2"}
 *    })
 *
 *    -- SET operation
 *    session:set("1.3.6.1.2.1.1.5.0", "NewHostName", "string")
 *    session:set("1.3.6.1.2.1.1.6.0", "192.168.1.1", "ipaddress")
 *
 *    -- SNMPv3 with authentication
 *    local session = npe.snmp.open(host, {
 *        version         = "3",
 *        security_level  = "authPriv",  -- "noAuthNoPriv", "authNoPriv", "authPriv"
 *        username        = "admin",
 *        auth_protocol   = "SHA",       -- "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"
 *        auth_password   = "authpass",
 *        priv_protocol   = "AES",       -- "DES", "AES", "AES192", "AES256"
 *        priv_password   = "privpass",
 *        engine_id       = nil,         -- Auto-discover or specify
 *        context_name    = "",
 *    })
 *
 *    -- TRAP receiver
 *    local trap_handler = npe.snmp.trap_receiver({
 *        port = 162,
 *        community = "public",
 *        callback = function(trap)
 *            print(trap.source_ip, trap.enterprise_oid, trap.generic_trap)
 *            for _, varbind in ipairs(trap.varbinds) do
 *                print(varbind.oid, varbind.value, varbind.type)
 *            end
 *        end
 *    })
 *    trap_handler:start()
 *
 *    -- MIB utilities
 *    local name = npe.snmp.oid_to_name("1.3.6.1.2.1.1.1.0")  -- "sysDescr.0"
 *    local oid  = npe.snmp.name_to_oid("sysDescr.0")         -- "1.3.6.1.2.1.1.1.0"
 *
 *    session:close()
 *
 * =============================================================================
 */

#ifndef NPE_PROTO_SNMP_H
#define NPE_PROTO_SNMP_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_SNMP_DEFAULT_PORT           161
#define NPE_SNMP_TRAP_DEFAULT_PORT      162
#define NPE_SNMP_DEFAULT_TIMEOUT_MS     5000
#define NPE_SNMP_DEFAULT_RETRIES        2
#define NPE_SNMP_MAX_OID_LENGTH         128
#define NPE_SNMP_MAX_MESSAGE_SIZE       65507   /* UDP max payload            */
#define NPE_SNMP_MAX_VARBINDS           256
#define NPE_SNMP_MAX_COMMUNITY_LENGTH   256
#define NPE_SNMP_MAX_USERNAME_LENGTH    64
#define NPE_SNMP_MAX_PASSWORD_LENGTH    64
#define NPE_SNMP_MAX_ENGINE_ID_LENGTH   32
#define NPE_SNMP_MAX_CONTEXT_LENGTH     256
#define NPE_SNMP_MAX_VALUE_LENGTH       65535

/*
 * SNMP Versions
 */
typedef enum npe_snmp_version {
    NPE_SNMP_VERSION_1      = 0,        /* SNMPv1                             */
    NPE_SNMP_VERSION_2C     = 1,        /* SNMPv2c                            */
    NPE_SNMP_VERSION_3      = 3         /* SNMPv3                             */
} npe_snmp_version_t;

/*
 * SNMP PDU Types
 */
typedef enum npe_snmp_pdu_type {
    NPE_SNMP_PDU_GET                = 0xA0,
    NPE_SNMP_PDU_GET_NEXT           = 0xA1,
    NPE_SNMP_PDU_GET_RESPONSE       = 0xA2,
    NPE_SNMP_PDU_SET                = 0xA3,
    NPE_SNMP_PDU_TRAP_V1            = 0xA4,
    NPE_SNMP_PDU_GET_BULK           = 0xA5,     /* SNMPv2c/v3                 */
    NPE_SNMP_PDU_INFORM             = 0xA6,     /* SNMPv2c/v3                 */
    NPE_SNMP_PDU_TRAP_V2            = 0xA7,     /* SNMPv2c/v3                 */
    NPE_SNMP_PDU_REPORT             = 0xA8      /* SNMPv3                     */
} npe_snmp_pdu_type_t;

/*
 * SNMP Error Status
 */
typedef enum npe_snmp_error {
    NPE_SNMP_ERROR_NOERROR          = 0,
    NPE_SNMP_ERROR_TOOBIG           = 1,
    NPE_SNMP_ERROR_NOSUCHNAME       = 2,
    NPE_SNMP_ERROR_BADVALUE         = 3,
    NPE_SNMP_ERROR_READONLY         = 4,
    NPE_SNMP_ERROR_GENERR           = 5,
    NPE_SNMP_ERROR_NOACCESS         = 6,        /* SNMPv2c/v3                 */
    NPE_SNMP_ERROR_WRONGTYPE        = 7,
    NPE_SNMP_ERROR_WRONGLENGTH      = 8,
    NPE_SNMP_ERROR_WRONGENCODING    = 9,
    NPE_SNMP_ERROR_WRONGVALUE       = 10,
    NPE_SNMP_ERROR_NOCREATION       = 11,
    NPE_SNMP_ERROR_INCONSISTENTVALUE = 12,
    NPE_SNMP_ERROR_RESOURCEUNAVAILABLE = 13,
    NPE_SNMP_ERROR_COMMITFAILED     = 14,
    NPE_SNMP_ERROR_UNDOFAILED       = 15,
    NPE_SNMP_ERROR_AUTHORIZATIONERROR = 16,
    NPE_SNMP_ERROR_NOTWRITABLE      = 17,
    NPE_SNMP_ERROR_INCONSISTENTNAME = 18
} npe_snmp_error_t;

/*
 * SNMP Data Types (ASN.1 BER Tags)
 */
typedef enum npe_snmp_type {
    NPE_SNMP_TYPE_INTEGER           = 0x02,
    NPE_SNMP_TYPE_OCTET_STRING      = 0x04,
    NPE_SNMP_TYPE_NULL              = 0x05,
    NPE_SNMP_TYPE_OBJECT_ID         = 0x06,
    NPE_SNMP_TYPE_SEQUENCE          = 0x30,
    NPE_SNMP_TYPE_IPADDRESS         = 0x40,
    NPE_SNMP_TYPE_COUNTER32         = 0x41,
    NPE_SNMP_TYPE_GAUGE32           = 0x42,
    NPE_SNMP_TYPE_TIMETICKS         = 0x43,
    NPE_SNMP_TYPE_OPAQUE            = 0x44,
    NPE_SNMP_TYPE_COUNTER64         = 0x46,     /* SNMPv2c/v3                 */
    NPE_SNMP_TYPE_NOSUCHOBJECT      = 0x80,     /* SNMPv2c/v3 exception       */
    NPE_SNMP_TYPE_NOSUCHINSTANCE    = 0x81,     /* SNMPv2c/v3 exception       */
    NPE_SNMP_TYPE_ENDOFMIBVIEW      = 0x82      /* SNMPv2c/v3 exception       */
} npe_snmp_type_t;

/*
 * SNMPv3 Security Levels
 */
typedef enum npe_snmp_security_level {
    NPE_SNMP_SEC_NOAUTH_NOPRIV      = 0,        /* No authentication or encryption */
    NPE_SNMP_SEC_AUTH_NOPRIV        = 1,        /* Authentication, no encryption   */
    NPE_SNMP_SEC_AUTH_PRIV          = 2         /* Authentication and encryption   */
} npe_snmp_security_level_t;

/*
 * SNMPv3 Authentication Protocols
 */
typedef enum npe_snmp_auth_protocol {
    NPE_SNMP_AUTH_NONE              = 0,
    NPE_SNMP_AUTH_MD5               = 1,
    NPE_SNMP_AUTH_SHA               = 2,
    NPE_SNMP_AUTH_SHA224            = 3,
    NPE_SNMP_AUTH_SHA256            = 4,
    NPE_SNMP_AUTH_SHA384            = 5,
    NPE_SNMP_AUTH_SHA512            = 6
} npe_snmp_auth_protocol_t;

/*
 * SNMPv3 Privacy (Encryption) Protocols
 */
typedef enum npe_snmp_priv_protocol {
    NPE_SNMP_PRIV_NONE              = 0,
    NPE_SNMP_PRIV_DES               = 1,
    NPE_SNMP_PRIV_AES               = 2,
    NPE_SNMP_PRIV_AES192            = 3,
    NPE_SNMP_PRIV_AES256            = 4
} npe_snmp_priv_protocol_t;

/*
 * SNMPv1 Generic Trap Types
 */
typedef enum npe_snmp_trap_generic {
    NPE_SNMP_TRAP_COLDSTART         = 0,
    NPE_SNMP_TRAP_WARMSTART         = 1,
    NPE_SNMP_TRAP_LINKDOWN          = 2,
    NPE_SNMP_TRAP_LINKUP            = 3,
    NPE_SNMP_TRAP_AUTHFAILURE       = 4,
    NPE_SNMP_TRAP_EGPNEIGHBORLOSS   = 5,
    NPE_SNMP_TRAP_ENTERPRISESPECIFIC = 6
} npe_snmp_trap_generic_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Data Structures
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_oid_t — Object Identifier
 */
typedef struct npe_snmp_oid {
    uint32_t    subids[NPE_SNMP_MAX_OID_LENGTH];
    size_t      length;                         /* Number of subidentifiers   */
} npe_snmp_oid_t;

/*
 * npe_snmp_value_t — Variable Binding Value
 */
typedef struct npe_snmp_value {
    npe_snmp_type_t type;                       /* Value type                 */
    union {
        int32_t         integer;
        uint32_t        unsigned32;             /* Counter32, Gauge32, TimeTicks */
        uint64_t        counter64;
        struct {
            uint8_t    *data;
            size_t      length;
        } octet_string;
        npe_snmp_oid_t  object_id;
        struct {
            uint8_t     octets[4];              /* IPv4 address               */
        } ipaddress;
        uint8_t        *opaque;
    } value;
} npe_snmp_value_t;

/*
 * npe_snmp_varbind_t — Variable Binding
 */
typedef struct npe_snmp_varbind {
    npe_snmp_oid_t      oid;
    npe_snmp_value_t    value;
} npe_snmp_varbind_t;

/*
 * npe_snmp_pdu_t — Protocol Data Unit
 */
typedef struct npe_snmp_pdu {
    npe_snmp_pdu_type_t pdu_type;
    int32_t             request_id;
    npe_snmp_error_t    error_status;
    int32_t             error_index;

    /* GET-BULK specific fields (SNMPv2c/v3) */
    int32_t             non_repeaters;
    int32_t             max_repetitions;

    /* Variable bindings */
    npe_snmp_varbind_t  varbinds[NPE_SNMP_MAX_VARBINDS];
    size_t              varbind_count;
} npe_snmp_pdu_t;

/*
 * npe_snmp_trap_v1_t — SNMPv1 Trap PDU
 */
typedef struct npe_snmp_trap_v1 {
    npe_snmp_oid_t          enterprise_oid;
    uint8_t                 agent_addr[4];      /* IPv4 address               */
    npe_snmp_trap_generic_t generic_trap;
    int32_t                 specific_trap;
    uint32_t                timestamp;          /* sysUpTime                  */
    npe_snmp_varbind_t      varbinds[NPE_SNMP_MAX_VARBINDS];
    size_t                  varbind_count;
} npe_snmp_trap_v1_t;

/*
 * npe_snmp_v3_usm_t — SNMPv3 User-based Security Model Parameters
 */
typedef struct npe_snmp_v3_usm {
    uint8_t                     engine_id[NPE_SNMP_MAX_ENGINE_ID_LENGTH];
    size_t                      engine_id_length;
    int32_t                     engine_boots;
    int32_t                     engine_time;
    char                        username[NPE_SNMP_MAX_USERNAME_LENGTH];
    uint8_t                     auth_params[32]; /* Authentication parameters */
    uint8_t                     priv_params[32]; /* Privacy parameters        */
} npe_snmp_v3_usm_t;

/*
 * npe_snmp_session_t — SNMP Session Handle
 */
typedef struct npe_snmp_session {
    /* Connection parameters */
    int                         sockfd;
    struct sockaddr_storage     peer_addr;
    socklen_t                   peer_addr_len;
    char                        hostname[256];
    uint16_t                    port;

    /* SNMP parameters */
    npe_snmp_version_t          version;
    char                        community[NPE_SNMP_MAX_COMMUNITY_LENGTH];

    /* Timing */
    uint32_t                    timeout_ms;
    uint32_t                    retries;
    int32_t                     request_id;     /* Auto-incrementing          */

    /* SNMPv3 specific */
    npe_snmp_security_level_t   security_level;
    npe_snmp_auth_protocol_t    auth_protocol;
    npe_snmp_priv_protocol_t    priv_protocol;
    char                        username[NPE_SNMP_MAX_USERNAME_LENGTH];
    uint8_t                     auth_key[64];   /* Derived key                */
    uint8_t                     priv_key[64];   /* Derived key                */
    npe_snmp_v3_usm_t           usm_params;
    char                        context_name[NPE_SNMP_MAX_CONTEXT_LENGTH];

    /* State */
    bool                        is_open;
} npe_snmp_session_t;

/*
 * npe_snmp_trap_receiver_t — TRAP/INFORM Receiver
 */
typedef struct npe_snmp_trap_receiver {
    int                         sockfd;
    uint16_t                    port;
    char                        community[NPE_SNMP_MAX_COMMUNITY_LENGTH];
    int                         lua_callback_ref;   /* Lua registry reference */
    bool                        is_running;
    pthread_t                   thread;
} npe_snmp_trap_receiver_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Core SNMP Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_session_open — Open SNMP session
 *
 * Creates and initializes an SNMP session with the specified parameters.
 *
 * Parameters:
 *   hostname     — Target host (hostname or IP address)
 *   options      — Session options (version, community, port, timeout, etc.)
 *
 * Returns:
 *   Pointer to session structure on success, NULL on failure
 */
npe_snmp_session_t *npe_snmp_session_open(
    const char *hostname,
    npe_snmp_version_t version,
    const char *community,
    uint16_t port,
    uint32_t timeout_ms,
    uint32_t retries
);

/*
 * npe_snmp_session_open_v3 — Open SNMPv3 session with authentication
 */
npe_snmp_session_t *npe_snmp_session_open_v3(
    const char *hostname,
    uint16_t port,
    npe_snmp_security_level_t security_level,
    const char *username,
    npe_snmp_auth_protocol_t auth_protocol,
    const char *auth_password,
    npe_snmp_priv_protocol_t priv_protocol,
    const char *priv_password,
    const uint8_t *engine_id,
    size_t engine_id_length,
    const char *context_name,
    uint32_t timeout_ms,
    uint32_t retries
);

/*
 * npe_snmp_session_close — Close SNMP session
 */
void npe_snmp_session_close(npe_snmp_session_t *session);

/*
 * npe_snmp_get — Perform SNMP GET operation
 *
 * Retrieves the value of a single OID.
 *
 * Parameters:
 *   session      — SNMP session
 *   oid          — Object identifier
 *   value        — [OUT] Retrieved value
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
int npe_snmp_get(
    npe_snmp_session_t *session,
    const npe_snmp_oid_t *oid,
    npe_snmp_value_t *value
);

/*
 * npe_snmp_get_multi — GET multiple OIDs in a single request
 */
int npe_snmp_get_multi(
    npe_snmp_session_t *session,
    const npe_snmp_oid_t *oids,
    size_t oid_count,
    npe_snmp_varbind_t *results,
    size_t *result_count
);

/*
 * npe_snmp_get_next — Perform SNMP GET-NEXT operation
 *
 * Retrieves the next OID in lexicographic order.
 */
int npe_snmp_get_next(
    npe_snmp_session_t *session,
    const npe_snmp_oid_t *oid,
    npe_snmp_oid_t *next_oid,
    npe_snmp_value_t *value
);

/*
 * npe_snmp_get_bulk — Perform SNMP GET-BULK operation (SNMPv2c/v3)
 *
 * Efficiently retrieves multiple rows from a table.
 */
int npe_snmp_get_bulk(
    npe_snmp_session_t *session,
    int32_t non_repeaters,
    int32_t max_repetitions,
    const npe_snmp_oid_t *oids,
    size_t oid_count,
    npe_snmp_varbind_t *results,
    size_t *result_count
);

/*
 * npe_snmp_set — Perform SNMP SET operation
 *
 * Sets the value of an OID.
 */
int npe_snmp_set(
    npe_snmp_session_t *session,
    const npe_snmp_oid_t *oid,
    const npe_snmp_value_t *value
);

/*
 * npe_snmp_set_multi — SET multiple OIDs in a single request
 */
int npe_snmp_set_multi(
    npe_snmp_session_t *session,
    const npe_snmp_varbind_t *varbinds,
    size_t varbind_count
);

/*
 * npe_snmp_walk — Walk an OID subtree
 *
 * Iterator function that calls a callback for each OID in the subtree.
 *
 * Parameters:
 *   session      — SNMP session
 *   root_oid     — Starting OID
 *   callback     — Function called for each varbind
 *   user_data    — User data passed to callback
 *
 * Returns:
 *   Number of OIDs walked, negative error code on failure
 */
typedef int (*npe_snmp_walk_callback_t)(
    const npe_snmp_varbind_t *varbind,
    void *user_data
);

int npe_snmp_walk(
    npe_snmp_session_t *session,
    const npe_snmp_oid_t *root_oid,
    npe_snmp_walk_callback_t callback,
    void *user_data
);


/* ─────────────────────────────────────────────────────────────────────────────
 * TRAP/INFORM Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_trap_receiver_create — Create TRAP receiver
 */
npe_snmp_trap_receiver_t *npe_snmp_trap_receiver_create(
    uint16_t port,
    const char *community
);

/*
 * npe_snmp_trap_receiver_start — Start receiving traps
 */
int npe_snmp_trap_receiver_start(npe_snmp_trap_receiver_t *receiver);

/*
 * npe_snmp_trap_receiver_stop — Stop receiving traps
 */
void npe_snmp_trap_receiver_stop(npe_snmp_trap_receiver_t *receiver);

/*
 * npe_snmp_trap_receiver_destroy — Destroy trap receiver
 */
void npe_snmp_trap_receiver_destroy(npe_snmp_trap_receiver_t *receiver);


/* ─────────────────────────────────────────────────────────────────────────────
 * OID Utilities
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_oid_from_string — Parse OID from string
 *
 * Example: "1.3.6.1.2.1.1.1.0" or ".iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0"
 */
int npe_snmp_oid_from_string(const char *oid_str, npe_snmp_oid_t *oid);

/*
 * npe_snmp_oid_to_string — Convert OID to string
 */
char *npe_snmp_oid_to_string(const npe_snmp_oid_t *oid);

/*
 * npe_snmp_oid_compare — Compare two OIDs
 *
 * Returns: <0 if oid1 < oid2, 0 if equal, >0 if oid1 > oid2
 */
int npe_snmp_oid_compare(const npe_snmp_oid_t *oid1, const npe_snmp_oid_t *oid2);

/*
 * npe_snmp_oid_is_subtree — Check if oid is within root subtree
 */
bool npe_snmp_oid_is_subtree(const npe_snmp_oid_t *oid, const npe_snmp_oid_t *root);

/*
 * npe_snmp_oid_copy — Copy OID
 */
void npe_snmp_oid_copy(npe_snmp_oid_t *dest, const npe_snmp_oid_t *src);


/* ─────────────────────────────────────────────────────────────────────────────
 * MIB Name Resolution
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_mib_load — Load MIB definition file
 *
 * Parses a MIB file and adds name-to-OID mappings.
 */
int npe_snmp_mib_load(const char *mib_file);

/*
 * npe_snmp_name_to_oid — Convert symbolic name to OID
 *
 * Example: "sysDescr.0" → "1.3.6.1.2.1.1.1.0"
 */
int npe_snmp_name_to_oid(const char *name, npe_snmp_oid_t *oid);

/*
 * npe_snmp_oid_to_name — Convert OID to symbolic name
 */
char *npe_snmp_oid_to_name(const npe_snmp_oid_t *oid);


/* ─────────────────────────────────────────────────────────────────────────────
 * ASN.1 BER Encoding/Decoding
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_encode_pdu — Encode PDU to BER bytes
 */
int npe_snmp_encode_pdu(
    const npe_snmp_pdu_t *pdu,
    npe_snmp_version_t version,
    const char *community,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *encoded_length
);

/*
 * npe_snmp_decode_pdu — Decode BER bytes to PDU
 */
int npe_snmp_decode_pdu(
    const uint8_t *buffer,
    size_t buffer_length,
    npe_snmp_pdu_t *pdu,
    npe_snmp_version_t *version,
    char *community,
    size_t community_size
);

/*
 * npe_snmp_encode_value — Encode SNMP value to BER
 */
int npe_snmp_encode_value(
    const npe_snmp_value_t *value,
    uint8_t *buffer,
    size_t buffer_size,
    size_t *encoded_length
);

/*
 * npe_snmp_decode_value — Decode BER to SNMP value
 */
int npe_snmp_decode_value(
    const uint8_t *buffer,
    size_t buffer_length,
    npe_snmp_value_t *value,
    size_t *consumed
);


/* ─────────────────────────────────────────────────────────────────────────────
 * SNMPv3 Cryptographic Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_snmp_v3_generate_engine_id — Generate SNMPv3 engine ID
 *
 * Creates a unique engine ID based on enterprise number and entropy.
 */
int npe_snmp_v3_generate_engine_id(
    uint32_t enterprise_number,
    uint8_t *engine_id,
    size_t *engine_id_length
);

/*
 * npe_snmp_v3_discover_engine — Discover remote engine ID and parameters
 *
 * Performs engine discovery handshake.
 */
int npe_snmp_v3_discover_engine(
    npe_snmp_session_t *session,
    npe_snmp_v3_usm_t *usm_params
);

/*
 * npe_snmp_v3_password_to_key — Convert password to localized key
 *
 * Implements password-to-key algorithm (RFC 3414).
 */
int npe_snmp_v3_password_to_key(
    npe_snmp_auth_protocol_t auth_protocol,
    const char *password,
    const uint8_t *engine_id,
    size_t engine_id_length,
    uint8_t *key,
    size_t *key_length
);

/*
 * npe_snmp_v3_authenticate — Generate authentication parameters
 */
int npe_snmp_v3_authenticate(
    npe_snmp_auth_protocol_t auth_protocol,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *message,
    size_t message_length,
    uint8_t *auth_params
);

/*
 * npe_snmp_v3_verify_auth — Verify authentication parameters
 */
int npe_snmp_v3_verify_auth(
    npe_snmp_auth_protocol_t auth_protocol,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *message,
    size_t message_length,
    const uint8_t *auth_params
);

/*
 * npe_snmp_v3_encrypt — Encrypt scoped PDU
 */
int npe_snmp_v3_encrypt(
    npe_snmp_priv_protocol_t priv_protocol,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *engine_boots,
    const uint8_t *engine_time,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t *ciphertext_length,
    uint8_t *priv_params
);

/*
 * npe_snmp_v3_decrypt — Decrypt scoped PDU
 */
int npe_snmp_v3_decrypt(
    npe_snmp_priv_protocol_t priv_protocol,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *priv_params,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t *plaintext_length
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Lua API Registration
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * luaopen_npe_snmp — Register SNMP library in Lua
 *
 * Registers the npe.snmp table with all functions and constants.
 */
int luaopen_npe_snmp(lua_State *L);


/* ─────────────────────────────────────────────────────────────────────────────
 * Common OID Constants (RFC 1213 MIB-II)
 * ───────────────────────────────────────────────────────────────────────────── */

/* System group (1.3.6.1.2.1.1) */
#define NPE_SNMP_OID_SYSDESCR       "1.3.6.1.2.1.1.1.0"
#define NPE_SNMP_OID_SYSOBJECTID    "1.3.6.1.2.1.1.2.0"
#define NPE_SNMP_OID_SYSUPTIME      "1.3.6.1.2.1.1.3.0"
#define NPE_SNMP_OID_SYSCONTACT     "1.3.6.1.2.1.1.4.0"
#define NPE_SNMP_OID_SYSNAME        "1.3.6.1.2.1.1.5.0"
#define NPE_SNMP_OID_SYSLOCATION    "1.3.6.1.2.1.1.6.0"
#define NPE_SNMP_OID_SYSSERVICES    "1.3.6.1.2.1.1.7.0"

/* Interfaces group (1.3.6.1.2.1.2) */
#define NPE_SNMP_OID_IFNUMBER       "1.3.6.1.2.1.2.1.0"
#define NPE_SNMP_OID_IFTABLE        "1.3.6.1.2.1.2.2"
#define NPE_SNMP_OID_IFINDEX        "1.3.6.1.2.1.2.2.1.1"
#define NPE_SNMP_OID_IFDESCR        "1.3.6.1.2.1.2.2.1.2"
#define NPE_SNMP_OID_IFTYPE         "1.3.6.1.2.1.2.2.1.3"
#define NPE_SNMP_OID_IFMTU          "1.3.6.1.2.1.2.2.1.4"
#define NPE_SNMP_OID_IFSPEED        "1.3.6.1.2.1.2.2.1.5"
#define NPE_SNMP_OID_IFPHYSADDRESS  "1.3.6.1.2.1.2.2.1.6"

/* IP group (1.3.6.1.2.1.4) */
#define NPE_SNMP_OID_IPFORWARDING   "1.3.6.1.2.1.4.1.0"
#define NPE_SNMP_OID_IPINRECEIVES   "1.3.6.1.2.1.4.3.0"

/* ICMP group (1.3.6.1.2.1.5) */
#define NPE_SNMP_OID_ICMPINMSGS     "1.3.6.1.2.1.5.1.0"

/* TCP group (1.3.6.1.2.1.6) */
#define NPE_SNMP_OID_TCPRTOALGORITHM "1.3.6.1.2.1.6.1.0"
#define NPE_SNMP_OID_TCPCONNTABLE   "1.3.6.1.2.1.6.13"

/* UDP group (1.3.6.1.2.1.7) */
#define NPE_SNMP_OID_UDPINDATAGRAMS "1.3.6.1.2.1.7.1.0"
#define NPE_SNMP_OID_UDPTABLE       "1.3.6.1.2.1.7.5"

/* SNMP group (1.3.6.1.2.1.11) */
#define NPE_SNMP_OID_SNMPINPKTS     "1.3.6.1.2.1.11.1.0"
#define NPE_SNMP_OID_SNMPOUTPKTS    "1.3.6.1.2.1.11.2.0"

/* Host Resources MIB (1.3.6.1.2.1.25) */
#define NPE_SNMP_OID_HRSYSTEMUPTIME     "1.3.6.1.2.1.25.1.1.0"
#define NPE_SNMP_OID_HRSYSTEMDATE       "1.3.6.1.2.1.25.1.2.0"
#define NPE_SNMP_OID_HRPROCESSORTABLE   "1.3.6.1.2.1.25.3.3"
#define NPE_SNMP_OID_HRSTORAGETABLE     "1.3.6.1.2.1.25.2.3"
#define NPE_SNMP_OID_HRDEVICETABLE      "1.3.6.1.2.1.25.3.2"

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_SNMP_H */
