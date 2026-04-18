/*****************************************************************************
 * npe_proto_smtp.h — SMTP protocol library
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Provides SMTP (Simple Mail Transfer Protocol) support including:
 *   • Connection and EHLO/HELO negotiation
 *   • SMTP authentication (PLAIN, LOGIN, CRAM-MD5)
 *   • Email composition and sending
 *   • STARTTLS support
 *   • VRFY and EXPN commands (user enumeration)
 *   • Server capability detection
 *   • Support for SMTP submission (port 587) and SMTPS (port 465)
 *
 * Lua API:
 *   smtp = npe.proto.smtp.connect(host, port, options)
 *   smtp:ehlo(domain)                       → capabilities[]
 *   smtp:starttls()                         → success
 *   smtp:auth(user, pass, method)           → success
 *   smtp:mail_from(sender)                  → success
 *   smtp:rcpt_to(recipient)                 → success
 *   smtp:data(message)                      → success
 *   smtp:send_mail(from, to, subject, body) → success
 *   smtp:vrfy(address)                      → exists, real_address
 *   smtp:expn(mailing_list)                 → addresses[]
 *   smtp:noop()                             → success
 *   smtp:quit()                             → success
 *   smtp:close()
 *
 * Thread-safety: SMTP connections are not thread-safe.
 *****************************************************************************/

#ifndef NPE_PROTO_SMTP_H
#define NPE_PROTO_SMTP_H

#include "npe_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque SMTP connection handle ───────────────────────────────────────── */
typedef struct npe_smtp_conn npe_smtp_conn_t;

/* ── SMTP-specific types ─────────────────────────────────────────────────── */

/**
 * SMTP authentication mechanism.
 */
typedef enum npe_smtp_auth_method {
    NPE_SMTP_AUTH_NONE      = 0,
    NPE_SMTP_AUTH_PLAIN     = 1,     /* AUTH PLAIN                        */
    NPE_SMTP_AUTH_LOGIN     = 2,     /* AUTH LOGIN                        */
    NPE_SMTP_AUTH_CRAM_MD5  = 3,     /* AUTH CRAM-MD5                     */
    NPE_SMTP_AUTH_DIGEST_MD5= 4,     /* AUTH DIGEST-MD5                   */
    NPE_SMTP_AUTH_NTLM      = 5,     /* AUTH NTLM (Windows)               */
    NPE_SMTP_AUTH_XOAUTH2   = 6      /* AUTH XOAUTH2 (OAuth2)             */
} npe_smtp_auth_method_t;

/**
 * SMTP connection options.
 */
typedef struct npe_smtp_options {
    npe_proto_options_t      base;   /* common protocol options           */
    
    /* SMTP-specific options */
    bool                     use_starttls; /* use STARTTLS upgrade        */
    bool                     require_tls;  /* fail if TLS unavailable     */
    const char              *helo_domain;  /* HELO/EHLO domain name       */
    npe_smtp_auth_method_t   auth_method;  /* preferred auth method       */
    bool                     pipelining;   /* enable command pipelining   */
    bool                     vrfy_enabled; /* enable VRFY command         */
    bool                     expn_enabled; /* enable EXPN command         */
    uint32_t                 max_message_size; /* max message size hint   */
} npe_smtp_options_t;

/**
 * SMTP server response.
 */
typedef struct npe_smtp_response {
    uint32_t    code;                /* response code (e.g., 220, 250)    */
    const char *message;             /* response message                  */
    bool        enhanced;            /* enhanced status code present      */
    char        enhanced_code[12];   /* enhanced code (e.g., "5.7.1")     */
    bool        multiline;           /* multiline response                */
} npe_smtp_response_t;

/**
 * SMTP server capabilities.
 */
typedef struct npe_smtp_capabilities {
    char   **extensions;             /* array of extension names          */
    size_t   extension_count;        /* number of extensions              */
    bool     starttls;               /* STARTTLS supported                */
    bool     pipelining;             /* PIPELINING supported              */
    bool     dsn;                    /* DSN supported                     */
    bool     etrn;                   /* ETRN supported                    */
    bool     enhancedstatuscodes;    /* Enhanced Status Codes supported   */
    bool     size;                   /* SIZE supported                    */
    uint64_t max_size;               /* maximum message size (bytes)      */
    bool     vrfy;                   /* VRFY supported                    */
    bool     expn;                   /* EXPN supported                    */
    char   **auth_methods;           /* supported auth methods            */
    size_t   auth_count;             /* number of auth methods            */
} npe_smtp_capabilities_t;

/**
 * Email message structure.
 */
typedef struct npe_smtp_message {
    const char  *from;               /* sender address                    */
    const char **to;                 /* recipient addresses (array)       */
    size_t       to_count;           /* number of recipients              */
    const char **cc;                 /* CC addresses                      */
    size_t       cc_count;           /* number of CC recipients           */
    const char **bcc;                /* BCC addresses                     */
    size_t       bcc_count;          /* number of BCC recipients          */
    const char  *subject;            /* message subject                   */
    const char  *body;               /* message body (plain text)         */
    const char  *html_body;          /* HTML body (optional)              */
    
    /* Headers */
    const char **header_names;       /* custom header names               */
    const char **header_values;      /* custom header values              */
    size_t       header_count;       /* number of custom headers          */
    
    /* Attachments */
    const char **attach_paths;       /* attachment file paths             */
    const char **attach_names;       /* attachment names (display)        */
    const char **attach_types;       /* MIME types                        */
    size_t       attach_count;       /* number of attachments             */
} npe_smtp_message_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  CONNECTION MANAGEMENT
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialize SMTP options with defaults.
 */
void npe_smtp_options_init(npe_smtp_options_t *opts);

/**
 * Connect to SMTP server.
 *
 * @param host   target hostname/IP
 * @param port   target port (0 = use default: 25, 587, or 465)
 * @param opts   connection options (may be NULL)
 * @param conn   receives connection handle
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_connect(const char             *host,
                             uint16_t                port,
                             const npe_smtp_options_t *opts,
                             npe_smtp_conn_t       **conn);

/**
 * Get connection state.
 */
npe_proto_state_t npe_smtp_state(const npe_smtp_conn_t *conn);

/**
 * Get server banner.
 */
npe_error_t npe_smtp_get_banner(npe_smtp_conn_t    *conn,
                                npe_proto_banner_t *banner);

/**
 * Disconnect from SMTP server.
 */
void npe_smtp_disconnect(npe_smtp_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SMTP HANDSHAKE
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Send HELO command (simple handshake).
 *
 * @param conn   connection handle
 * @param domain client domain name
 * @param resp   receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_helo(npe_smtp_conn_t    *conn,
                          const char         *domain,
                          npe_smtp_response_t *resp);

/**
 * Send EHLO command (extended handshake).
 *
 * @param conn   connection handle
 * @param domain client domain name
 * @param caps   receives server capabilities (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_ehlo(npe_smtp_conn_t         *conn,
                          const char              *domain,
                          npe_smtp_capabilities_t *caps);

/**
 * Upgrade connection to TLS (STARTTLS).
 */
npe_error_t npe_smtp_starttls(npe_smtp_conn_t    *conn,
                              npe_smtp_response_t *resp);

/**
 * Free capabilities structure.
 */
void npe_smtp_capabilities_free(npe_smtp_capabilities_t *caps);

/* ═══════════════════════════════════════════════════════════════════════════
 *  AUTHENTICATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Authenticate with server.
 *
 * @param conn     connection handle
 * @param username username
 * @param password password
 * @param method   authentication method (0 = auto-select)
 * @param resp     receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_auth(npe_smtp_conn_t        *conn,
                          const char             *username,
                          const char             *password,
                          npe_smtp_auth_method_t  method,
                          npe_smtp_response_t    *resp);

/**
 * Check if authenticated.
 */
bool npe_smtp_is_authenticated(const npe_smtp_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIL OPERATIONS (Low-level)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Send MAIL FROM command.
 *
 * @param conn   connection handle
 * @param sender sender address
 * @param resp   receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_mail_from(npe_smtp_conn_t    *conn,
                               const char         *sender,
                               npe_smtp_response_t *resp);

/**
 * Send RCPT TO command.
 */
npe_error_t npe_smtp_rcpt_to(npe_smtp_conn_t    *conn,
                             const char         *recipient,
                             npe_smtp_response_t *resp);

/**
 * Send DATA command and message content.
 *
 * @param conn    connection handle
 * @param message raw message data (including headers)
 * @param msg_len message length
 * @param resp    receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_data(npe_smtp_conn_t    *conn,
                          const char         *message,
                          size_t              msg_len,
                          npe_smtp_response_t *resp);

/**
 * Reset transaction (RSET).
 */
npe_error_t npe_smtp_rset(npe_smtp_conn_t    *conn,
                          npe_smtp_response_t *resp);

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIL OPERATIONS (High-level)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialize message structure.
 */
void npe_smtp_message_init(npe_smtp_message_t *msg);

/**
 * Send complete email message.
 *
 * @param conn connection handle
 * @param msg  message structure
 * @param resp receives final response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_send_message(npe_smtp_conn_t        *conn,
                                  const npe_smtp_message_t *msg,
                                  npe_smtp_response_t    *resp);

/**
 * Send simple text email.
 */
npe_error_t npe_smtp_send_simple(npe_smtp_conn_t    *conn,
                                 const char         *from,
                                 const char         *to,
                                 const char         *subject,
                                 const char         *body,
                                 npe_smtp_response_t *resp);

/**
 * Free message structure.
 */
void npe_smtp_message_free(npe_smtp_message_t *msg);

/* ═══════════════════════════════════════════════════════════════════════════
 *  USER ENUMERATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Verify email address (VRFY command).
 *
 * @param conn      connection handle
 * @param address   email address to verify
 * @param exists    receives true if address exists
 * @param real_addr receives canonical address (may be NULL, caller must free)
 * @param resp      receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_vrfy(npe_smtp_conn_t    *conn,
                          const char         *address,
                          bool               *exists,
                          char              **real_addr,
                          npe_smtp_response_t *resp);

/**
 * Expand mailing list (EXPN command).
 *
 * @param conn      connection handle
 * @param list_name mailing list name
 * @param addresses receives array of addresses (caller must free)
 * @param count     receives number of addresses
 * @param resp      receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_expn(npe_smtp_conn_t    *conn,
                          const char         *list_name,
                          char             ***addresses,
                          size_t             *count,
                          npe_smtp_response_t *resp);

/* ═══════════════════════════════════════════════════════════════════════════
 *  OTHER COMMANDS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Send NOOP (keep-alive).
 */
npe_error_t npe_smtp_noop(npe_smtp_conn_t    *conn,
                          npe_smtp_response_t *resp);

/**
 * Send HELP command.
 */
npe_error_t npe_smtp_help(npe_smtp_conn_t    *conn,
                          const char         *command,
                          npe_smtp_response_t *resp);

/**
 * Send QUIT command.
 */
npe_error_t npe_smtp_quit(npe_smtp_conn_t    *conn,
                          npe_smtp_response_t *resp);

/**
 * Send raw SMTP command.
 *
 * @param conn    connection handle
 * @param command command string (without CRLF)
 * @param resp    receives response
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_raw_command(npe_smtp_conn_t    *conn,
                                 const char         *command,
                                 npe_smtp_response_t *resp);

/* ═══════════════════════════════════════════════════════════════════════════
 *  UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Free SMTP response structure.
 */
void npe_smtp_response_free(npe_smtp_response_t *resp);

/**
 * Check if response code indicates success (2xx).
 */
bool npe_smtp_response_ok(const npe_smtp_response_t *resp);

/**
 * Parse SMTP response code category.
 * Returns: 2=success, 3=intermediate, 4=transient error, 5=permanent error
 */
uint32_t npe_smtp_response_category(uint32_t code);

/**
 * Build RFC 5322 compliant message from structure.
 *
 * @param msg     message structure
 * @param output  receives formatted message (caller must free)
 * @param out_len receives message length
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_build_message(const npe_smtp_message_t *msg,
                                   char                    **output,
                                   size_t                   *out_len);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register SMTP library with Lua VM.
 *
 * Creates the 'npe.proto.smtp' table.
 *
 * @param vm  Lua VM instance
 * @return NPE_OK on success
 */
npe_error_t npe_smtp_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_SMTP_H */
