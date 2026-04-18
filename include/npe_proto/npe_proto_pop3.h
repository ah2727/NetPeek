/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_proto_pop3.h — POP3 Protocol Interaction Library
 * =============================================================================
 *
 *  Post Office Protocol version 3 (RFC 1939) implementation with extensions
 *  including STARTTLS (RFC 2595), APOP, UIDL, and TOP.
 *
 *  Lua API:
 *
 *    -- Connect to POP3 server
 *    local pop3 = npe.pop3.connect(host, {
 *        port        = 110,           -- 110 for plain, 995 for SSL
 *        ssl         = false,         -- Use SSL/TLS from start
 *        starttls    = false,         -- Upgrade to TLS with STARTTLS
 *        timeout_ms  = 30000,
 *    })
 *
 *    -- Authentication
 *    pop3:login(username, password)                -- USER/PASS
 *    pop3:apop(username, secret)                   -- APOP (MD5 challenge)
 *
 *    -- Get mailbox statistics
 *    local msg_count, total_size = pop3:stat()
 *
 *    -- List messages
 *    local messages = pop3:list()                  -- All messages
 *    local size = pop3:list(msg_num)               -- Specific message
 *
 *    -- Get unique IDs
 *    local uids = pop3:uidl()                      -- All messages
 *    local uid = pop3:uidl(msg_num)                -- Specific message
 *
 *    -- Retrieve messages
 *    local message = pop3:retr(msg_num)            -- Full message
 *    local headers = pop3:top(msg_num, lines)      -- Headers + N lines
 *
 *    -- Mark for deletion
 *    pop3:dele(msg_num)
 *
 *    -- Reset deletion marks
 *    pop3:rset()
 *
 *    -- No-operation (keepalive)
 *    pop3:noop()
 *
 *    -- Close connection
 *    pop3:quit()
 *
 *    -- Capability detection
 *    local caps = pop3:capa()                      -- Get capabilities
 *    if caps["UIDL"] then
 *        print("Server supports UIDL")
 *    end
 *
 * =============================================================================
 */

#ifndef NPE_PROTO_POP3_H
#define NPE_PROTO_POP3_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_POP3_DEFAULT_PORT           110
#define NPE_POP3_SSL_PORT               995
#define NPE_POP3_DEFAULT_TIMEOUT_MS     30000
#define NPE_POP3_MAX_LINE_LENGTH        512
#define NPE_POP3_MAX_RESPONSE_SIZE      (16 * 1024 * 1024)  /* 16 MB      */
#define NPE_POP3_MAX_USERNAME_LENGTH    256
#define NPE_POP3_MAX_PASSWORD_LENGTH    256
#define NPE_POP3_MAX_COMMAND_LENGTH     512

/*
 * POP3 Response Status
 */
typedef enum npe_pop3_status {
    NPE_POP3_STATUS_OK      = 0,        /* +OK response                       */
    NPE_POP3_STATUS_ERR     = 1,        /* -ERR response                      */
    NPE_POP3_STATUS_TIMEOUT = 2,        /* Operation timed out                */
    NPE_POP3_STATUS_DISCONNECTED = 3,   /* Connection closed                  */
    NPE_POP3_STATUS_INVALID = 4         /* Invalid response format            */
} npe_pop3_status_t;

/*
 * POP3 Authentication State
 */
typedef enum npe_pop3_auth_state {
    NPE_POP3_AUTH_NONE      = 0,        /* Not authenticated                  */
    NPE_POP3_AUTH_USER      = 1,        /* USER/PASS authentication           */
    NPE_POP3_AUTH_APOP      = 2         /* APOP authentication                */
} npe_pop3_auth_state_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Data Structures
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_response_t — POP3 Server Response
 */
typedef struct npe_pop3_response {
    npe_pop3_status_t   status;         /* +OK or -ERR                        */
    char               *message;        /* Status message                     */
    char               *data;           /* Multi-line response data           */
    size_t              data_length;    /* Length of data                     */
} npe_pop3_response_t;

/*
 * npe_pop3_message_info_t — Message Metadata
 */
typedef struct npe_pop3_message_info {
    uint32_t    message_number;         /* Message number (1-based)           */
    uint32_t    size;                   /* Size in octets                     */
    char       *unique_id;              /* UIDL unique ID (optional)          */
} npe_pop3_message_info_t;

/*
 * npe_pop3_capabilities_t — Server Capabilities
 */
typedef struct npe_pop3_capabilities {
    bool    top;                        /* TOP command supported              */
    bool    uidl;                       /* UIDL command supported             */
    bool    sasl;                       /* SASL authentication                */
    bool    resp_codes;                 /* Response codes extension           */
    bool    pipelining;                 /* Command pipelining                 */
    bool    expire;                     /* EXPIRE extension                   */
    bool    login_delay;                /* LOGIN-DELAY extension              */
    bool    stls;                       /* STARTTLS supported                 */
    bool    user;                       /* USER/PASS supported                */
    bool    apop;                       /* APOP supported                     */
    char   *implementation;             /* Server implementation string       */
    uint32_t expire_days;               /* Message retention (if EXPIRE)      */
    uint32_t login_delay_seconds;       /* Login delay (if LOGIN-DELAY)       */
} npe_pop3_capabilities_t;

/*
 * npe_pop3_connection_t — POP3 Connection Handle
 */
typedef struct npe_pop3_connection {
    /* Network */
    int                         sockfd;
    char                        hostname[256];
    uint16_t                    port;
    bool                        use_ssl;
    void                       *ssl_ctx;    /* SSL/TLS context (opaque)       */
    void                       *ssl;        /* SSL connection (opaque)        */

    /* Timing */
    uint32_t                    timeout_ms;

    /* Protocol state */
    npe_pop3_auth_state_t       auth_state;
    char                        banner[NPE_POP3_MAX_LINE_LENGTH];
    char                        apop_timestamp[128];    /* APOP challenge     */
    npe_pop3_capabilities_t     capabilities;
    bool                        capabilities_fetched;

    /* Statistics */
    uint32_t                    message_count;
    uint64_t                    mailbox_size;

    /* Buffer */
    char                       *read_buffer;
    size_t                      read_buffer_size;
    size_t                      read_buffer_used;

    /* State */
    bool                        is_connected;
} npe_pop3_connection_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Core POP3 Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_connect — Connect to POP3 server
 *
 * Establishes connection and reads greeting banner.
 *
 * Parameters:
 *   hostname     — Server hostname or IP
 *   port         — Server port (110 for plain, 995 for SSL)
 *   use_ssl      — Use SSL/TLS from start
 *   timeout_ms   — Connection and operation timeout
 *
 * Returns:
 *   Pointer to connection structure on success, NULL on failure
 */
npe_pop3_connection_t *npe_pop3_connect(
    const char *hostname,
    uint16_t port,
    bool use_ssl,
    uint32_t timeout_ms
);

/*
 * npe_pop3_starttls — Upgrade connection to TLS
 *
 * Issues STLS command and performs TLS handshake.
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
int npe_pop3_starttls(npe_pop3_connection_t *conn);

/*
 * npe_pop3_disconnect — Close connection
 */
void npe_pop3_disconnect(npe_pop3_connection_t *conn);


/* ─────────────────────────────────────────────────────────────────────────────
 * Authentication Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_login — Authenticate with USER/PASS
 *
 * Sends USER and PASS commands sequentially.
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
int npe_pop3_login(
    npe_pop3_connection_t *conn,
    const char *username,
    const char *password
);

/*
 * npe_pop3_apop — Authenticate with APOP
 *
 * Uses MD5 challenge-response authentication.
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
int npe_pop3_apop(
    npe_pop3_connection_t *conn,
    const char *username,
    const char *secret
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Transaction Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_stat — Get mailbox statistics
 *
 * Returns:
 *   0 on success with message_count and mailbox_size filled
 */
int npe_pop3_stat(
    npe_pop3_connection_t *conn,
    uint32_t *message_count,
    uint64_t *mailbox_size
);

/*
 * npe_pop3_list — List messages
 *
 * If message_num is 0, lists all messages.
 * Otherwise, returns info for specific message.
 *
 * Returns:
 *   Number of messages returned, negative on error
 */
int npe_pop3_list(
    npe_pop3_connection_t *conn,
    uint32_t message_num,
    npe_pop3_message_info_t **messages,
    size_t *message_count
);

/*
 * npe_pop3_uidl — Get unique message IDs
 *
 * If message_num is 0, returns all UIDs.
 *
 * Returns:
 *   Number of UIDs returned, negative on error
 */
int npe_pop3_uidl(
    npe_pop3_connection_t *conn,
    uint32_t message_num,
    npe_pop3_message_info_t **messages,
    size_t *message_count
);

/*
 * npe_pop3_retr — Retrieve full message
 *
 * Downloads entire message including headers and body.
 *
 * Returns:
 *   0 on success with message stored in *data
 */
int npe_pop3_retr(
    npe_pop3_connection_t *conn,
    uint32_t message_num,
    char **data,
    size_t *data_length
);

/*
 * npe_pop3_top — Retrieve message headers and N body lines
 *
 * Useful for previewing messages without downloading entire body.
 *
 * Parameters:
 *   message_num  — Message number
 *   line_count   — Number of body lines to retrieve (0 for headers only)
 *
 * Returns:
 *   0 on success with data stored in *data
 */
int npe_pop3_top(
    npe_pop3_connection_t *conn,
    uint32_t message_num,
    uint32_t line_count,
    char **data,
    size_t *data_length
);

/*
 * npe_pop3_dele — Mark message for deletion
 *
 * Message is deleted when QUIT is issued.
 *
 * Returns:
 *   0 on success
 */
int npe_pop3_dele(
    npe_pop3_connection_t *conn,
    uint32_t message_num
);

/*
 * npe_pop3_rset — Reset deletion marks
 *
 * Unmarks all messages previously marked with DELE.
 *
 * Returns:
 *   0 on success
 */
int npe_pop3_rset(npe_pop3_connection_t *conn);

/*
 * npe_pop3_noop — No operation (keepalive)
 *
 * Returns:
 *   0 on success
 */
int npe_pop3_noop(npe_pop3_connection_t *conn);

/*
 * npe_pop3_quit — Close session and commit changes
 *
 * Deletes messages marked with DELE and closes connection.
 *
 * Returns:
 *   0 on success
 */
int npe_pop3_quit(npe_pop3_connection_t *conn);


/* ─────────────────────────────────────────────────────────────────────────────
 * Extension Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_capa — Get server capabilities
 *
 * Issues CAPA command and parses response.
 *
 * Returns:
 *   0 on success with capabilities filled
 */
int npe_pop3_capa(
    npe_pop3_connection_t *conn,
    npe_pop3_capabilities_t *capabilities
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Low-Level Protocol Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_send_command — Send command to server
 *
 * Automatically appends CRLF.
 *
 * Returns:
 *   0 on success
 */
int npe_pop3_send_command(
    npe_pop3_connection_t *conn,
    const char *command
);

/*
 * npe_pop3_read_response — Read single-line response
 *
 * Reads "+OK" or "-ERR" response.
 *
 * Returns:
 *   Response structure (must be freed with npe_pop3_response_free)
 */
npe_pop3_response_t *npe_pop3_read_response(npe_pop3_connection_t *conn);

/*
 * npe_pop3_read_multiline — Read multi-line response
 *
 * Reads lines until terminating "." line.
 *
 * Returns:
 *   Response structure with multi-line data
 */
npe_pop3_response_t *npe_pop3_read_multiline(npe_pop3_connection_t *conn);

/*
 * npe_pop3_response_free — Free response structure
 */
void npe_pop3_response_free(npe_pop3_response_t *response);


/* ─────────────────────────────────────────────────────────────────────────────
 * Utility Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_pop3_parse_banner — Parse greeting banner for APOP timestamp
 *
 * Extracts timestamp from banner like: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
 *
 * Returns:
 *   true if APOP timestamp found
 */
bool npe_pop3_parse_banner(
    const char *banner,
    char *timestamp,
    size_t timestamp_size
);

/*
 * npe_pop3_compute_apop_digest — Compute APOP MD5 digest
 *
 * Computes MD5(timestamp + secret) for APOP authentication.
 */
int npe_pop3_compute_apop_digest(
    const char *timestamp,
    const char *secret,
    char *digest,
    size_t digest_size
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Lua API Registration
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * luaopen_npe_pop3 — Register POP3 library in Lua
 */
int luaopen_npe_pop3(lua_State *L);


/* ─────────────────────────────────────────────────────────────────────────────
 * Error Codes
 * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_POP3_ERR_NONE           0
#define NPE_POP3_ERR_CONNECT        -1
#define NPE_POP3_ERR_AUTH           -2
#define NPE_POP3_ERR_TIMEOUT        -3
#define NPE_POP3_ERR_PROTOCOL       -4
#define NPE_POP3_ERR_NOTFOUND       -5
#define NPE_POP3_ERR_SSL            -6
#define NPE_POP3_ERR_MEMORY         -7
#define NPE_POP3_ERR_INVALID_STATE  -8
#define NPE_POP3_ERR_SERVER         -9

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_POP3_H */
