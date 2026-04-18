/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_proto_imap.h — IMAP Protocol Interaction Library
 * =============================================================================
 *
 *  Internet Message Access Protocol version 4rev1 (RFC 3501) implementation
 *  with extensions including IDLE, NAMESPACE, QUOTA, and ACL.
 *
 *  Lua API:
 *
 *    -- Connect to IMAP server
 *    local imap = npe.imap.connect(host, {
 *        port        = 143,           -- 143 for plain, 993 for SSL
 *        ssl         = false,
 *        starttls    = false,
 *        timeout_ms  = 30000,
 *    })
 *
 *    -- Authentication
 *    imap:login(username, password)
 *    imap:authenticate("PLAIN", credentials)
 *
 *    -- Mailbox operations
 *    local mailboxes = imap:list("", "*")        -- List all mailboxes
 *    imap:select("INBOX")                        -- Select mailbox
 *    imap:examine("INBOX")                       -- Read-only select
 *    imap:create("Archive/2024")                 -- Create mailbox
 *    imap:delete("OldFolder")                    -- Delete mailbox
 *    imap:rename("OldName", "NewName")           -- Rename mailbox
 *    imap:subscribe("INBOX")                     -- Subscribe
 *    imap:unsubscribe("Junk")                    -- Unsubscribe
 *
 *    -- Message operations
 *    local messages = imap:search("ALL")         -- Search messages
 *    local messages = imap:search("UNSEEN")      -- Unread messages
 *    local messages = imap:search('FROM "alice@example.com"')
 *
 *    -- Fetch message data
 *    local headers = imap:fetch(123, "BODY[HEADER]")
 *    local body = imap:fetch(123, "BODY[TEXT]")
 *    local full = imap:fetch(123, "RFC822")
 *    local flags = imap:fetch(123, "FLAGS")
 *
 *    -- Set flags
 *    imap:store(123, "+FLAGS", "\\Seen")         -- Mark as read
 *    imap:store(123, "-FLAGS", "\\Flagged")      -- Remove flag
 *
 *    -- Copy and move
 *    imap:copy(123, "Archive")                   -- Copy message
 *    imap:move(123, "Trash")                     -- Move message (RFC 6851)
 *
 *    -- Expunge deleted messages
 *    imap:expunge()
 *
 *    -- Close mailbox
 *    imap:close()
 *
 *    -- Logout
 *    imap:logout()
 *
 *    -- Capabilities
 *    local caps = imap:capability()
 *    if caps["IDLE"] then
 *        print("Server supports IDLE")
 *    end
 *
 *    -- IDLE (push notifications)
 *    imap:idle_start()
 *    local updates = imap:idle_wait(timeout_ms)
 *    imap:idle_done()
 *
 *    -- Namespace
 *    local ns = imap:namespace()
 *    print(ns.personal[1].prefix, ns.personal[1].delimiter)
 *
 *    -- Quota
 *    local quota = imap:getquota("INBOX")
 *    print(quota.used, quota.limit)
 *
 * =============================================================================
 */

#ifndef NPE_PROTO_IMAP_H
#define NPE_PROTO_IMAP_H

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

#define NPE_IMAP_DEFAULT_PORT           143
#define NPE_IMAP_SSL_PORT               993
#define NPE_IMAP_DEFAULT_TIMEOUT_MS     30000
#define NPE_IMAP_MAX_LINE_LENGTH        8192
#define NPE_IMAP_MAX_RESPONSE_SIZE      (64 * 1024 * 1024)  /* 64 MB      */
#define NPE_IMAP_MAX_TAG_LENGTH         16
#define NPE_IMAP_MAX_MAILBOX_NAME       256
#define NPE_IMAP_MAX_FLAGS              32
#define NPE_IMAP_MAX_SEARCH_RESULTS     100000

/*
 * IMAP Response Status
 */
typedef enum npe_imap_status {
    NPE_IMAP_STATUS_OK          = 0,    /* OK response                        */
    NPE_IMAP_STATUS_NO          = 1,    /* NO response (command failed)       */
    NPE_IMAP_STATUS_BAD         = 2,    /* BAD response (protocol error)      */
    NPE_IMAP_STATUS_PREAUTH     = 3,    /* PREAUTH (already authenticated)    */
    NPE_IMAP_STATUS_BYE         = 4,    /* BYE (server closing connection)    */
    NPE_IMAP_STATUS_CONTINUE    = 5,    /* + (continuation request)           */
    NPE_IMAP_STATUS_UNTAGGED    = 6,    /* * (untagged response)              */
    NPE_IMAP_STATUS_TIMEOUT     = 7,    /* Operation timed out                */
    NPE_IMAP_STATUS_DISCONNECTED = 8    /* Connection closed                  */
} npe_imap_status_t;

/*
 * IMAP Connection State
 */
typedef enum npe_imap_state {
    NPE_IMAP_STATE_NOT_AUTHENTICATED    = 0,
    NPE_IMAP_STATE_AUTHENTICATED        = 1,
    NPE_IMAP_STATE_SELECTED             = 2,
    NPE_IMAP_STATE_LOGOUT               = 3
} npe_imap_state_t;

/*
 * Mailbox Flags (RFC 3501 Section 7.2.2)
 */
typedef enum npe_imap_mailbox_flags {
    NPE_IMAP_MBOX_FLAG_NOINFERIORS  = (1 << 0),    /* \Noinferiors       */
    NPE_IMAP_MBOX_FLAG_NOSELECT     = (1 << 1),    /* \Noselect          */
    NPE_IMAP_MBOX_FLAG_MARKED       = (1 << 2),    /* \Marked            */
    NPE_IMAP_MBOX_FLAG_UNMARKED     = (1 << 3),    /* \Unmarked          */
    NPE_IMAP_MBOX_FLAG_HASCHILDREN  = (1 << 4),    /* \HasChildren       */
    NPE_IMAP_MBOX_FLAG_HASNOCHILDREN = (1 << 5),   /* \HasNoChildren     */
    NPE_IMAP_MBOX_FLAG_ALL          = (1 << 6),    /* \All               */
    NPE_IMAP_MBOX_FLAG_ARCHIVE      = (1 << 7),    /* \Archive           */
    NPE_IMAP_MBOX_FLAG_DRAFTS       = (1 << 8),    /* \Drafts            */
    NPE_IMAP_MBOX_FLAG_FLAGGED      = (1 << 9),    /* \Flagged           */
    NPE_IMAP_MBOX_FLAG_JUNK         = (1 << 10),   /* \Junk              */
    NPE_IMAP_MBOX_FLAG_SENT         = (1 << 11),   /* \Sent              */
    NPE_IMAP_MBOX_FLAG_TRASH        = (1 << 12)    /* \Trash             */
} npe_imap_mailbox_flags_t;

/*
 * Message Flags (RFC 3501 Section 2.3.2)
 */
typedef enum npe_imap_message_flags {
    NPE_IMAP_MSG_FLAG_SEEN      = (1 << 0),    /* \Seen                      */
    NPE_IMAP_MSG_FLAG_ANSWERED  = (1 << 1),    /* \Answered                  */
    NPE_IMAP_MSG_FLAG_FLAGGED   = (1 << 2),    /* \Flagged                   */
    NPE_IMAP_MSG_FLAG_DELETED   = (1 << 3),    /* \Deleted                   */
    NPE_IMAP_MSG_FLAG_DRAFT     = (1 << 4),    /* \Draft                     */
    NPE_IMAP_MSG_FLAG_RECENT    = (1 << 5)     /* \Recent                    */
} npe_imap_message_flags_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Data Structures
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_response_t — IMAP Server Response
 */
typedef struct npe_imap_response {
    npe_imap_status_t   status;         /* Response status                    */
    char                tag[NPE_IMAP_MAX_TAG_LENGTH];
    char               *status_text;    /* Status response text               */
    char              **untagged;       /* Array of untagged response lines   */
    size_t              untagged_count;
    char               *continuation;   /* Continuation data (for literals)   */
} npe_imap_response_t;

/*
 * npe_imap_mailbox_t — Mailbox Information
 */
typedef struct npe_imap_mailbox {
    char                name[NPE_IMAP_MAX_MAILBOX_NAME];
    char                delimiter;      /* Hierarchy delimiter                */
    uint32_t            flags;          /* Mailbox attribute flags            */
    uint32_t            exists;         /* Number of messages                 */
    uint32_t            recent;         /* Number of recent messages          */
    uint32_t            unseen;         /* Number of unseen messages          */
    uint32_t            uidnext;        /* Predicted next UID                 */
    uint32_t            uidvalidity;    /* UID validity value                 */
    bool                read_only;      /* Read-only access                   */
} npe_imap_mailbox_t;

/*
 * npe_imap_message_t — Message Metadata
 */
typedef struct npe_imap_message {
    uint32_t            sequence_num;   /* Message sequence number            */
    uint32_t            uid;            /* Unique identifier                  */
    uint32_t            flags;          /* Message flags bitmask              */
    uint32_t            size;           /* RFC822 size in octets              */
    char               *envelope;       /* ENVELOPE structure (heap)          */
    char               *body_structure; /* BODYSTRUCTURE (heap)               */
    char               *internal_date;  /* Internal date string               */
} npe_imap_message_t;

/*
 * npe_imap_namespace_t — Namespace Information (RFC 2342)
 */
typedef struct npe_imap_namespace_entry {
    char                prefix[256];    /* Namespace prefix                   */
    char                delimiter;      /* Hierarchy delimiter                */
} npe_imap_namespace_entry_t;

typedef struct npe_imap_namespace {
    npe_imap_namespace_entry_t *personal;
    size_t                      personal_count;
    npe_imap_namespace_entry_t *other_users;
    size_t                      other_users_count;
    npe_imap_namespace_entry_t *shared;
    size_t                      shared_count;
} npe_imap_namespace_t;

/*
 * npe_imap_quota_t — Quota Information (RFC 2087)
 */
typedef struct npe_imap_quota {
    char                root[256];      /* Quota root                         */
    uint64_t            storage_used;   /* Storage used (KB)                  */
    uint64_t            storage_limit;  /* Storage limit (KB)                 */
    uint32_t            message_used;   /* Message count used                 */
    uint32_t            message_limit;  /* Message count limit                */
} npe_imap_quota_t;

/*
 * npe_imap_capabilities_t — Server Capabilities
 */
typedef struct npe_imap_capabilities {
    bool    imap4rev1;                  /* IMAP4rev1 base                     */
    bool    starttls;                   /* STARTTLS extension                 */
    bool    idle;                       /* IDLE extension (RFC 2177)          */
    bool    namespace;                  /* NAMESPACE extension (RFC 2342)     */
    bool    quota;                      /* QUOTA extension (RFC 2087)         */
    bool    acl;                        /* ACL extension (RFC 4314)           */
    bool    rights;                     /* RIGHTS extension                   */
    bool    uidplus;                    /* UIDPLUS extension (RFC 4315)       */
    bool    move;                       /* MOVE extension (RFC 6851)          */
    bool    condstore;                  /* CONDSTORE extension (RFC 4551)     */
    bool    qresync;                    /* QRESYNC extension (RFC 5162)       */
    bool    compress_deflate;           /* COMPRESS=DEFLATE (RFC 4978)        */
    bool    children;                   /* CHILDREN extension (RFC 3348)      */
    bool    special_use;                /* SPECIAL-USE (RFC 6154)             */
    char  **auth_methods;               /* SASL auth methods                  */
    size_t  auth_methods_count;
} npe_imap_capabilities_t;

/*
 * npe_imap_connection_t — IMAP Connection Handle
 */
typedef struct npe_imap_connection {
    /* Network */
    int                         sockfd;
    char                        hostname[256];
    uint16_t                    port;
    bool                        use_ssl;
    void                       *ssl_ctx;    /* SSL/TLS context                */
    void                       *ssl;        /* SSL connection                 */

    /* Timing */
    uint32_t                    timeout_ms;

    /* Protocol state */
    npe_imap_state_t            state;
    uint32_t                    tag_counter;    /* Command tag counter        */
    npe_imap_capabilities_t     capabilities;
    bool                        capabilities_fetched;

    /* Selected mailbox */
    npe_imap_mailbox_t          selected_mailbox;
    bool                        mailbox_selected;

    /* IDLE state */
    bool                        idle_active;

    /* Buffer */
    char                       *read_buffer;
    size_t                      read_buffer_size;
    size_t                      read_buffer_used;

    /* State */
    bool                        is_connected;
} npe_imap_connection_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Core IMAP Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_connect — Connect to IMAP server
 */
npe_imap_connection_t *npe_imap_connect(
    const char *hostname,
    uint16_t port,
    bool use_ssl,
    uint32_t timeout_ms
);

/*
 * npe_imap_starttls — Upgrade connection to TLS
 */
int npe_imap_starttls(npe_imap_connection_t *conn);

/*
 * npe_imap_disconnect — Close connection
 */
void npe_imap_disconnect(npe_imap_connection_t *conn);


/* ─────────────────────────────────────────────────────────────────────────────
 * Authentication Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_login — Authenticate with LOGIN command
 */
int npe_imap_login(
    npe_imap_connection_t *conn,
    const char *username,
    const char *password
);

/*
 * npe_imap_authenticate — Authenticate with SASL
 *
 * Supported mechanisms: PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5
 */
int npe_imap_authenticate(
    npe_imap_connection_t *conn,
    const char *mechanism,
    const char *credentials
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Mailbox Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_list — List mailboxes
 *
 * Parameters:
 *   reference    — Reference name (usually "")
 *   pattern      — Mailbox pattern ("*" for all, "%" for top level)
 *
 * Returns:
 *   Number of mailboxes found, negative on error
 */
int npe_imap_list(
    npe_imap_connection_t *conn,
    const char *reference,
    const char *pattern,
    npe_imap_mailbox_t **mailboxes,
    size_t *mailbox_count
);

/*
 * npe_imap_lsub — List subscribed mailboxes
 */
int npe_imap_lsub(
    npe_imap_connection_t *conn,
    const char *reference,
    const char *pattern,
    npe_imap_mailbox_t **mailboxes,
    size_t *mailbox_count
);

/*
 * npe_imap_select — Select mailbox for read-write access
 */
int npe_imap_select(
    npe_imap_connection_t *conn,
    const char *mailbox
);

/*
 * npe_imap_examine — Select mailbox for read-only access
 */
int npe_imap_examine(
    npe_imap_connection_t *conn,
    const char *mailbox
);

/*
 * npe_imap_create — Create new mailbox
 */
int npe_imap_create(
    npe_imap_connection_t *conn,
    const char *mailbox
);

/*
 * npe_imap_delete — Delete mailbox
 */
int npe_imap_delete(
    npe_imap_connection_t *conn,
    const char *mailbox
);

/*
 * npe_imap_rename — Rename mailbox
 */
int npe_imap_rename(
    npe_imap_connection_t *conn,
    const char *old_name,
    const char *new_name
);

/*
 * npe_imap_subscribe — Subscribe to mailbox
 */
int npe_imap_subscribe(
    npe_imap_connection_t *conn,
    const char *mailbox
);

/*
 * npe_imap_unsubscribe — Unsubscribe from mailbox
 */
int npe_imap_unsubscribe(
    npe_imap_connection_t *conn,
    const char *mailbox
);

/*
 * npe_imap_status — Get mailbox status without selecting
 *
 * Parameters:
 *   mailbox      — Mailbox name
 *   items        — Status items (MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN)
 */
int npe_imap_status(
    npe_imap_connection_t *conn,
    const char *mailbox,
    const char *items,
    npe_imap_mailbox_t *status
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Message Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_search — Search for messages
 *
 * Examples:
 *   "ALL"
 *   "UNSEEN"
 *   "FROM alice@example.com"
 *   "SUBJECT \"important\""
 *   "SINCE 1-Jan-2024"
 *
 * Returns:
 *   Number of matching messages, negative on error
 */
int npe_imap_search(
    npe_imap_connection_t *conn,
    const char *criteria,
    uint32_t **sequence_nums,
    size_t *count
);

/*
 * npe_imap_uid_search — Search using UID
 */
int npe_imap_uid_search(
    npe_imap_connection_t *conn,
    const char *criteria,
    uint32_t **uids,
    size_t *count
);

/*
 * npe_imap_fetch — Fetch message data
 *
 * Parameters:
 *   sequence_set — Sequence numbers (e.g., "1", "1:5", "1,3,5")
 *   items        — Data items (e.g., "FLAGS", "RFC822", "BODY[HEADER]")
 *
 * Returns:
 *   0 on success with data in response
 */
int npe_imap_fetch(
    npe_imap_connection_t *conn,
    const char *sequence_set,
    const char *items,
    npe_imap_response_t **response
);

/*
 * npe_imap_uid_fetch — Fetch using UID
 */
int npe_imap_uid_fetch(
    npe_imap_connection_t *conn,
    const char *uid_set,
    const char *items,
    npe_imap_response_t **response
);

/*
 * npe_imap_store — Store message flags
 *
 * Parameters:
 *   sequence_set — Message sequence numbers
 *   operation    — "+FLAGS", "-FLAGS", "FLAGS"
 *   flags        — Flag list (e.g., "\\Seen \\Flagged")
 */
int npe_imap_store(
    npe_imap_connection_t *conn,
    const char *sequence_set,
    const char *operation,
    const char *flags
);

/*
 * npe_imap_uid_store — Store flags using UID
 */
int npe_imap_uid_store(
    npe_imap_connection_t *conn,
    const char *uid_set,
    const char *operation,
    const char *flags
);

/*
 * npe_imap_copy — Copy messages to another mailbox
 */
int npe_imap_copy(
    npe_imap_connection_t *conn,
    const char *sequence_set,
    const char *mailbox
);

/*
 * npe_imap_uid_copy — Copy using UID
 */
int npe_imap_uid_copy(
    npe_imap_connection_t *conn,
    const char *uid_set,
    const char *mailbox
);

/*
 * npe_imap_move — Move messages (RFC 6851)
 *
 * Requires MOVE capability.
 */
int npe_imap_move(
    npe_imap_connection_t *conn,
    const char *sequence_set,
    const char *mailbox
);

/*
 * npe_imap_uid_move — Move using UID
 */
int npe_imap_uid_move(
    npe_imap_connection_t *conn,
    const char *uid_set,
    const char *mailbox
);

/*
 * npe_imap_expunge — Permanently remove deleted messages
 */
int npe_imap_expunge(npe_imap_connection_t *conn);

/*
 * npe_imap_uid_expunge — Expunge specific UIDs (RFC 4315)
 *
 * Requires UIDPLUS capability.
 */
int npe_imap_uid_expunge(
    npe_imap_connection_t *conn,
    const char *uid_set
);


/* ─────────────────────────────────────────────────────────────────────────────
 * Extension Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_capability — Get server capabilities
 */
int npe_imap_capability(
    npe_imap_connection_t *conn,
    npe_imap_capabilities_t *capabilities
);

/*
 * npe_imap_namespace — Get namespace information (RFC 2342)
 */
int npe_imap_namespace(
    npe_imap_connection_t *conn,
    npe_imap_namespace_t *namespaces
);

/*
 * npe_imap_getquota — Get quota information (RFC 2087)
 */
int npe_imap_getquota(
    npe_imap_connection_t *conn,
    const char *quota_root,
    npe_imap_quota_t *quota
);

/*
 * npe_imap_getquotaroot — Get quota root for mailbox
 */
int npe_imap_getquotaroot(
    npe_imap_connection_t *conn,
    const char *mailbox,
    npe_imap_quota_t *quota
);

/*
 * npe_imap_idle_start — Start IDLE mode (RFC 2177)
 *
 * Server will send updates when mailbox changes.
 */
int npe_imap_idle_start(npe_imap_connection_t *conn);

/*
 * npe_imap_idle_wait — Wait for IDLE updates
 *
 * Returns when server sends update or timeout expires.
 */
int npe_imap_idle_wait(
    npe_imap_connection_t *conn,
    uint32_t timeout_ms,
    npe_imap_response_t **response
);

/*
 * npe_imap_idle_done — Stop IDLE mode
 */
int npe_imap_idle_done(npe_imap_connection_t *conn);


/* ─────────────────────────────────────────────────────────────────────────────
 * Session Commands
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_noop — No operation (keepalive)
 */
int npe_imap_noop(npe_imap_connection_t *conn);

/*
 * npe_imap_check — Checkpoint mailbox
 */
int npe_imap_check(npe_imap_connection_t *conn);

/*
 * npe_imap_close — Close selected mailbox
 */
int npe_imap_close(npe_imap_connection_t *conn);

/*
 * npe_imap_logout — Logout and close connection
 */
int npe_imap_logout(npe_imap_connection_t *conn);


/* ─────────────────────────────────────────────────────────────────────────────
 * Low-Level Protocol Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_generate_tag — Generate unique command tag
 */
void npe_imap_generate_tag(
    npe_imap_connection_t *conn,
    char *tag,
    size_t tag_size
);

/*
 * npe_imap_send_command — Send command to server
 */
int npe_imap_send_command(
    npe_imap_connection_t *conn,
    const char *command
);

/*
 * npe_imap_read_response — Read command response
 */
npe_imap_response_t *npe_imap_read_response(
    npe_imap_connection_t *conn,
    const char *expected_tag
);

/*
 * npe_imap_response_free — Free response structure
 */
void npe_imap_response_free(npe_imap_response_t *response);


/* ─────────────────────────────────────────────────────────────────────────────
 * Utility Functions
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_imap_parse_flags — Parse flag string to bitmask
 */
uint32_t npe_imap_parse_flags(const char *flags_str);

/*
 * npe_imap_flags_to_string — Convert bitmask to flag string
 */
char *npe_imap_flags_to_string(uint32_t flags);

/*
 * npe_imap_quote_string — Quote string for IMAP command
 */
char *npe_imap_quote_string(const char *str);


/* ─────────────────────────────────────────────────────────────────────────────
 * Lua API Registration
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * luaopen_npe_imap — Register IMAP library in Lua
 */
int luaopen_npe_imap(lua_State *L);


/* ─────────────────────────────────────────────────────────────────────────────
 * Error Codes
 * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_IMAP_ERR_NONE           0
#define NPE_IMAP_ERR_CONNECT        -1
#define NPE_IMAP_ERR_AUTH           -2
#define NPE_IMAP_ERR_TIMEOUT        -3
#define NPE_IMAP_ERR_PROTOCOL       -4
#define NPE_IMAP_ERR_NOTFOUND       -5
#define NPE_IMAP_ERR_SSL            -6
#define NPE_IMAP_ERR_MEMORY         -7
#define NPE_IMAP_ERR_INVALID_STATE  -8
#define NPE_IMAP_ERR_SERVER         -9
#define NPE_IMAP_ERR_NO_MAILBOX     -10
#define NPE_IMAP_ERR_READONLY       -11

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_IMAP_H */
