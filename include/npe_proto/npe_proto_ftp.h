/*****************************************************************************
 * npe_proto_ftp.h — FTP protocol library
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Provides FTP (File Transfer Protocol) support including:
 *   • Active and passive mode connections
 *   • Anonymous and authenticated login
 *   • File upload/download
 *   • Directory listing and navigation
 *   • FTP over TLS (FTPS - explicit and implicit)
 *   • Common FTP commands (SITE, FEAT, STAT, etc.)
 *   • Transfer resumption
 *
 * Lua API:
 *   ftp = npe.proto.ftp.connect(host, port, options)
 *   ftp:login(user, pass)                   → success, banner
 *   ftp:anonymous_login()                   → success, banner
 *   ftp:list(path)                          → entries[]
 *   ftp:cwd(path)                           → success
 *   ftp:pwd()                               → current_path
 *   ftp:download(remote, local)             → bytes_transferred
 *   ftp:upload(local, remote)               → bytes_transferred
 *   ftp:delete(path)                        → success
 *   ftp:mkdir(path)                         → success
 *   ftp:rmdir(path)                         → success
 *   ftp:rename(old, new)                    → success
 *   ftp:size(path)                          → file_size
 *   ftp:mdtm(path)                          → modification_time
 *   ftp:raw_command(cmd)                    → response
 *   ftp:close()
 *
 * Thread-safety: FTP connections are not thread-safe.
 *****************************************************************************/

#ifndef NPE_PROTO_FTP_H
#define NPE_PROTO_FTP_H

#include "npe_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque FTP connection handle ────────────────────────────────────────── */
typedef struct npe_ftp_conn npe_ftp_conn_t;

/* ── FTP-specific types ──────────────────────────────────────────────────── */

/**
 * FTP transfer mode.
 */
typedef enum npe_ftp_mode {
    NPE_FTP_MODE_ACTIVE  = 0,        /* active mode (server connects)     */
    NPE_FTP_MODE_PASSIVE = 1,        /* passive mode (client connects)    */
    NPE_FTP_MODE_EPSV    = 2         /* extended passive mode (IPv6)      */
} npe_ftp_mode_t;

/**
 * FTP transfer type.
 */
typedef enum npe_ftp_type {
    NPE_FTP_TYPE_ASCII  = 0,         /* ASCII text transfer               */
    NPE_FTP_TYPE_BINARY = 1          /* binary transfer                   */
} npe_ftp_type_t;

/**
 * FTP security mode.
 */
typedef enum npe_ftp_security {
    NPE_FTP_PLAIN       = 0,         /* no encryption                     */
    NPE_FTP_EXPLICIT_TLS= 1,         /* explicit FTPS (AUTH TLS)          */
    NPE_FTP_IMPLICIT_TLS= 2          /* implicit FTPS (port 990)          */
} npe_ftp_security_t;

/**
 * FTP connection options.
 */
typedef struct npe_ftp_options {
    npe_proto_options_t  base;       /* common protocol options           */
    
    /* FTP-specific options */
    npe_ftp_mode_t      mode;        /* transfer mode                     */
    npe_ftp_type_t      type;        /* transfer type                     */
    npe_ftp_security_t  security;    /* security mode                     */
    bool                use_utf8;    /* enable UTF-8 encoding             */
    bool                use_mlsd;    /* prefer MLSD over LIST             */
    uint32_t            data_timeout;/* data connection timeout (ms)      */
    const char         *encoding;    /* character encoding (e.g., "UTF-8")*/
} npe_ftp_options_t;

/**
 * FTP server response.
 */
typedef struct npe_ftp_response {
    uint32_t    code;                /* response code (e.g., 220, 530)    */
    const char *message;             /* response message                  */
    bool        multiline;           /* true if multiline response        */
} npe_ftp_response_t;

/**
 * FTP directory entry.
 */
typedef struct npe_ftp_entry {
    char    *name;                   /* entry name                        */
    char    *full_path;              /* full path                         */
    bool     is_dir;                 /* true if directory                 */
    bool     is_link;                /* true if symbolic link             */
    uint64_t size;                   /* file size in bytes                */
    time_t   mtime;                  /* modification time                 */
    char    *permissions;            /* permission string (e.g., "rwxr-xr-x") */
    char    *owner;                  /* owner name                        */
    char    *group;                  /* group name                        */
    char    *link_target;            /* link target (if is_link)          */
} npe_ftp_entry_t;

/**
 * FTP transfer progress callback.
 */
typedef void (*npe_ftp_progress_cb_t)(uint64_t bytes_transferred,
                                      uint64_t total_bytes,
                                      double   speed_bps,
                                      void    *user_data);

/* ═══════════════════════════════════════════════════════════════════════════
 *  CONNECTION MANAGEMENT
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialize FTP options with defaults.
 */
void npe_ftp_options_init(npe_ftp_options_t *opts);

/**
 * Connect to FTP server.
 *
 * @param host   target hostname/IP
 * @param port   target port (0 = use default 21 or 990 for implicit FTPS)
 * @param opts   connection options (may be NULL)
 * @param conn   receives connection handle
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_connect(const char            *host,
                            uint16_t               port,
                            const npe_ftp_options_t *opts,
                            npe_ftp_conn_t       **conn);

/**
 * Get connection state.
 */
npe_proto_state_t npe_ftp_state(const npe_ftp_conn_t *conn);

/**
 * Get server banner.
 */
npe_error_t npe_ftp_get_banner(npe_ftp_conn_t     *conn,
                               npe_proto_banner_t *banner);

/**
 * Disconnect from FTP server.
 */
void npe_ftp_disconnect(npe_ftp_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  AUTHENTICATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Login with username and password.
 *
 * @param conn     connection handle
 * @param username username
 * @param password password
 * @param resp     receives server response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_login(npe_ftp_conn_t     *conn,
                          const char         *username,
                          const char         *password,
                          npe_ftp_response_t *resp);

/**
 * Anonymous login.
 */
npe_error_t npe_ftp_login_anonymous(npe_ftp_conn_t     *conn,
                                    npe_ftp_response_t *resp);

/**
 * Check if logged in.
 */
bool npe_ftp_is_authenticated(const npe_ftp_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  DIRECTORY OPERATIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Get current working directory.
 */
npe_error_t npe_ftp_pwd(npe_ftp_conn_t *conn,
                        char          **path);

/**
 * Change working directory.
 */
npe_error_t npe_ftp_cwd(npe_ftp_conn_t *conn,
                        const char     *path);

/**
 * Change to parent directory.
 */
npe_error_t npe_ftp_cdup(npe_ftp_conn_t *conn);

/**
 * List directory contents.
 *
 * @param conn    connection handle
 * @param path    directory path (NULL = current directory)
 * @param entries receives array of entries (caller must free)
 * @param count   receives number of entries
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_list(npe_ftp_conn_t   *conn,
                         const char       *path,
                         npe_ftp_entry_t **entries,
                         size_t           *count);

/**
 * Create directory.
 */
npe_error_t npe_ftp_mkdir(npe_ftp_conn_t *conn,
                          const char     *path);

/**
 * Remove directory.
 */
npe_error_t npe_ftp_rmdir(npe_ftp_conn_t *conn,
                          const char     *path);

/**
 * Free directory entry array.
 */
void npe_ftp_entry_free(npe_ftp_entry_t *entries, size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 *  FILE OPERATIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Download file from server.
 *
 * @param conn        connection handle
 * @param remote_path remote file path
 * @param local_path  local destination path
 * @param resume      resume partial transfer if true
 * @param progress    progress callback (may be NULL)
 * @param user_data   opaque data passed to callback
 * @param transferred receives bytes transferred
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_download(npe_ftp_conn_t        *conn,
                             const char            *remote_path,
                             const char            *local_path,
                             bool                   resume,
                             npe_ftp_progress_cb_t  progress,
                             void                  *user_data,
                             uint64_t              *transferred);

/**
 * Upload file to server.
 */
npe_error_t npe_ftp_upload(npe_ftp_conn_t        *conn,
                           const char            *local_path,
                           const char            *remote_path,
                           bool                   resume,
                           npe_ftp_progress_cb_t  progress,
                           void                  *user_data,
                           uint64_t              *transferred);

/**
 * Download file to memory buffer.
 */
npe_error_t npe_ftp_download_buffer(npe_ftp_conn_t *conn,
                                    const char     *remote_path,
                                    void          **buffer,
                                    size_t         *buffer_len);

/**
 * Upload from memory buffer.
 */
npe_error_t npe_ftp_upload_buffer(npe_ftp_conn_t *conn,
                                  const void     *buffer,
                                  size_t          buffer_len,
                                  const char     *remote_path);

/**
 * Delete file.
 */
npe_error_t npe_ftp_delete(npe_ftp_conn_t *conn,
                           const char     *path);

/**
 * Rename/move file.
 */
npe_error_t npe_ftp_rename(npe_ftp_conn_t *conn,
                           const char     *old_path,
                           const char     *new_path);

/**
 * Get file size.
 */
npe_error_t npe_ftp_size(npe_ftp_conn_t *conn,
                         const char     *path,
                         uint64_t       *size);

/**
 * Get file modification time.
 */
npe_error_t npe_ftp_mdtm(npe_ftp_conn_t *conn,
                         const char     *path,
                         time_t         *mtime);

/* ═══════════════════════════════════════════════════════════════════════════
 *  ADVANCED COMMANDS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Send SITE command.
 *
 * @param conn     connection handle
 * @param command  SITE subcommand
 * @param resp     receives response (may be NULL)
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_site(npe_ftp_conn_t     *conn,
                         const char         *command,
                         npe_ftp_response_t *resp);

/**
 * Send FEAT command (get server features).
 */
npe_error_t npe_ftp_feat(npe_ftp_conn_t *conn,
                         char         ***features,
                         size_t         *count);

/**
 * Send STAT command.
 */
npe_error_t npe_ftp_stat(npe_ftp_conn_t     *conn,
                         const char         *path,
                         npe_ftp_response_t *resp);

/**
 * Send HELP command.
 */
npe_error_t npe_ftp_help(npe_ftp_conn_t     *conn,
                         const char         *command,
                         npe_ftp_response_t *resp);

/**
 * Send NOOP (keep-alive).
 */
npe_error_t npe_ftp_noop(npe_ftp_conn_t     *conn,
                         npe_ftp_response_t *resp);

/**
 * Send raw FTP command.
 *
 * @param conn    connection handle
 * @param command raw command string (without CRLF)
 * @param resp    receives response
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_raw_command(npe_ftp_conn_t     *conn,
                                const char         *command,
                                npe_ftp_response_t *resp);

/* ═══════════════════════════════════════════════════════════════════════════
 *  TRANSFER SETTINGS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Set transfer mode (active/passive).
 */
npe_error_t npe_ftp_set_mode(npe_ftp_conn_t *conn,
                             npe_ftp_mode_t  mode);

/**
 * Set transfer type (ASCII/binary).
 */
npe_error_t npe_ftp_set_type(npe_ftp_conn_t *conn,
                             npe_ftp_type_t  type);

/**
 * Get transfer mode.
 */
npe_ftp_mode_t npe_ftp_get_mode(const npe_ftp_conn_t *conn);

/**
 * Get transfer type.
 */
npe_ftp_type_t npe_ftp_get_type(const npe_ftp_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Free FTP response structure.
 */
void npe_ftp_response_free(npe_ftp_response_t *resp);

/**
 * Check if response code indicates success (2xx).
 */
bool npe_ftp_response_ok(const npe_ftp_response_t *resp);

/**
 * Parse FTP response code category.
 * Returns: 1=positive preliminary, 2=positive completion,
 *          3=positive intermediate, 4=transient error, 5=permanent error
 */
uint32_t npe_ftp_response_category(uint32_t code);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register FTP library with Lua VM.
 *
 * Creates the 'npe.proto.ftp' table.
 *
 * @param vm  Lua VM instance
 * @return NPE_OK on success
 */
npe_error_t npe_ftp_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_FTP_H */
