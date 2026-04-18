/*****************************************************************************
 * npe_proto.h — Master protocol library include
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Master header for protocol-specific libraries. Provides a unified interface
 * for interacting with common network protocols including SSH, FTP, SMTP,
 * HTTP, SMB, RDP, VNC, Telnet, and more.
 *
 * Protocol libraries provide:
 *   • Connection establishment and management
 *   • Protocol-specific command execution
 *   • Authentication mechanism support
 *   • Response parsing and state tracking
 *   • Banner grabbing and version detection
 *   • Vulnerability-specific probes
 *
 * Architecture:
 *   Each protocol has its own header (npe_proto_*.h) that can be included
 *   independently. This master header provides common types, error codes,
 *   and convenience functions shared across all protocol implementations.
 *
 * Thread-safety: All protocol operations are thread-safe. Connection objects
 *                must not be shared between threads without synchronization.
 *****************************************************************************/

#ifndef NPE_PROTO_H
#define NPE_PROTO_H

#include "npe_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_vm      npe_vm_t;
typedef struct npe_context npe_context_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  COMMON PROTOCOL TYPES
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Protocol identifiers.
 */
#include "npe_types.h"  /* npe_protocol_t lives here */

/**
 * Connection state.
 */
typedef enum npe_proto_state {
    NPE_PROTO_STATE_DISCONNECTED = 0,
    NPE_PROTO_STATE_CONNECTING   = 1,
    NPE_PROTO_STATE_CONNECTED    = 2,
    NPE_PROTO_STATE_AUTHENTICATED= 3,
    NPE_PROTO_STATE_ERROR        = 4,
    NPE_PROTO_STATE_CLOSED       = 5
} npe_proto_state_t;

/**
 * Authentication method.
 */
typedef enum npe_proto_auth_method {
    NPE_AUTH_NONE         = 0,
    NPE_AUTH_PASSWORD     = 1,
    NPE_AUTH_PUBKEY       = 2,
    NPE_AUTH_KEYBOARD     = 3,
    NPE_AUTH_KERBEROS     = 4,
    NPE_AUTH_NTLM         = 5,
    NPE_AUTH_TOKEN        = 6,
    NPE_AUTH_CERTIFICATE  = 7,
    NPE_AUTH_ANONYMOUS    = 8
} npe_proto_auth_method_t;

/**
 * Protocol connection options (common across all protocols).
 */
typedef struct npe_proto_options {
    const char *host;                /* target hostname/IP                */
    uint16_t    port;                /* target port (0 = use default)     */
    uint32_t    timeout_ms;          /* connection timeout (ms)           */
    uint32_t    read_timeout_ms;     /* read timeout (ms)                 */
    uint32_t    write_timeout_ms;    /* write timeout (ms)                */
    bool        use_tls;             /* use TLS/SSL encryption            */
    bool        verify_cert;         /* verify TLS certificate            */
    const char *tls_version;         /* TLS version ("1.2", "1.3", NULL)  */
    const char *bind_address;        /* local bind address (NULL = any)   */
    uint16_t    bind_port;           /* local bind port (0 = any)         */
    const char *proxy;               /* SOCKS/HTTP proxy URL              */
    bool        keep_alive;          /* enable TCP keep-alive             */
    uint32_t    keep_alive_idle;     /* keep-alive idle time (sec)        */
    uint32_t    buffer_size;         /* I/O buffer size (0 = default)     */
    void       *user_data;           /* opaque user data pointer          */
} npe_proto_options_t;

/**
 * Protocol response structure (generic).
 */
typedef struct npe_proto_response {
    uint32_t    status_code;         /* numeric status/response code      */
    const char *status_text;         /* status message                    */
    const char *data;                /* response data/body                */
    size_t      data_len;            /* response data length              */
    time_t      timestamp;           /* response timestamp                */
    uint64_t    latency_us;          /* response latency (microseconds)   */
    void       *headers;             /* protocol-specific headers         */
    size_t      header_count;        /* number of headers                 */
} npe_proto_response_t;

/**
 * Banner/version information.
 */
typedef struct npe_proto_banner {
    npe_protocol_t protocol;         /* detected protocol                 */
    const char    *raw_banner;       /* raw banner string                 */
    const char    *product;          /* product name                      */
    const char    *version;          /* version string                    */
    const char    *os;               /* operating system (if detected)    */
    const char    *extra_info;       /* additional information            */
} npe_proto_banner_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  COMMON PROTOCOL FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Get protocol name from enum.
 */
const char *npe_proto_name(npe_protocol_t proto);

/**
 * Get protocol from name (case-insensitive).
 */
npe_error_t npe_proto_by_name(const char *name, npe_protocol_t *proto);

/**
 * Get default port for a protocol.
 */
uint16_t npe_proto_default_port(npe_protocol_t proto);

/**
 * Initialize protocol options with defaults.
 */
void npe_proto_options_init(npe_proto_options_t *opts);

/**
 * Free protocol response structure.
 */
void npe_proto_response_free(npe_proto_response_t *resp);

/**
 * Free banner structure.
 */
void npe_proto_banner_free(npe_proto_banner_t *banner);

/**
 * Clone protocol options.
 */
npe_error_t npe_proto_options_clone(const npe_proto_options_t *src,
                                    npe_proto_options_t       *dst);

/**
 * Parse connection string (e.g., "ssh://user@host:22").
 */
npe_error_t npe_proto_parse_url(const char              *url,
                                npe_protocol_t          *proto,
                                npe_proto_options_t     *opts,
                                char                   **username,
                                char                   **password);

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROTOCOL DETECTION & FINGERPRINTING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Detect protocol on a given host:port by sending probes.
 *
 * @param host     target host
 * @param port     target port
 * @param timeout  timeout in milliseconds
 * @param proto    receives detected protocol
 * @param banner   receives banner info (may be NULL)
 * @return NPE_OK if protocol detected
 */
npe_error_t npe_proto_detect(const char         *host,
                             uint16_t            port,
                             uint32_t            timeout,
                             npe_protocol_t     *proto,
                             npe_proto_banner_t *banner);

/**
 * Grab banner from a service.
 */
npe_error_t npe_proto_grab_banner(const char         *host,
                                  uint16_t            port,
                                  npe_protocol_t      proto,
                                  uint32_t            timeout,
                                  npe_proto_banner_t *banner);

/**
 * Test if a port is open (basic TCP connect).
 */
npe_error_t npe_proto_port_open(const char *host,
                                uint16_t    port,
                                uint32_t    timeout,
                                bool       *is_open);

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATISTICS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Protocol usage statistics.
 */
typedef struct npe_proto_stats {
    uint64_t total_connections;      /* total connection attempts         */
    uint64_t successful_connections; /* successful connections            */
    uint64_t failed_connections;     /* failed connections                */
    uint64_t total_auth_attempts;    /* total authentication attempts     */
    uint64_t successful_auths;       /* successful authentications        */
    uint64_t total_bytes_sent;       /* total bytes sent                  */
    uint64_t total_bytes_received;   /* total bytes received              */
    uint64_t total_commands;         /* total commands executed           */
    uint64_t avg_latency_us;         /* average latency (microseconds)    */
} npe_proto_stats_t;

/**
 * Get global protocol statistics.
 */
npe_error_t npe_proto_get_stats(npe_protocol_t proto, npe_proto_stats_t *stats);

/**
 * Reset protocol statistics.
 */
void npe_proto_reset_stats(npe_protocol_t proto);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register all protocol libraries with Lua VM.
 *
 * Creates npe.proto.* tables for each protocol.
 *
 * @param vm  Lua VM instance
 * @return NPE_OK on success
 */
npe_error_t npe_proto_register_all(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_H */
