/*****************************************************************************
 * npe_proto_ssh.h — SSH protocol library
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Provides SSH v2 protocol support for .npe scripts including:
 *   • Connection and authentication
 *   • Command execution (shell and exec)
 *   • SFTP file operations
 *   • Port forwarding (local and remote)
 *   • Key exchange and algorithm negotiation
 *   • Known hosts verification
 *   • Agent forwarding
 *
 * Lua API:
 *   ssh = npe.proto.ssh.connect(host, port, options)
 *   ssh:auth_password(user, pass)           → success, error
 *   ssh:auth_pubkey(user, keyfile, pass)    → success, error
 *   ssh:auth_agent(user)                    → success, error
 *   ssh:exec(command)                       → stdout, stderr, exit_code
 *   ssh:shell()                             → shell_session
 *   ssh:sftp()                              → sftp_session
 *   ssh:forward_local(local_port, remote_host, remote_port)
 *   ssh:forward_remote(remote_port, local_host, local_port)
 *   ssh:get_banner()                        → banner_info
 *   ssh:get_algorithms()                    → kex, hostkey, cipher, mac, compression
 *   ssh:close()
 *
 * Based on libssh2 or similar SSH library.
 * Thread-safety: SSH connections are not thread-safe. Each thread should
 *                use separate connection objects.
 *****************************************************************************/

#ifndef NPE_PROTO_SSH_H
#define NPE_PROTO_SSH_H

#include "npe_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque SSH connection handle ────────────────────────────────────────── */
typedef struct npe_ssh_conn npe_ssh_conn_t;

/* ── SSH-specific structures ─────────────────────────────────────────────── */

/**
 * SSH authentication credentials.
 */
typedef struct npe_ssh_auth {
    npe_proto_auth_method_t method;  /* authentication method             */
    const char             *username;/* username                          */
    const char             *password;/* password (for password auth)      */
    const char             *keyfile; /* private key file path             */
    const char             *keypass; /* key passphrase                    */
    const char             *pubkey;  /* public key file path (optional)   */
    bool                    use_agent;/* use SSH agent                    */
} npe_ssh_auth_t;

/**
 * SSH connection options.
 */
typedef struct npe_ssh_options {
    npe_proto_options_t base;        /* common protocol options           */
    
    /* SSH-specific options */
    bool        strict_hostkey;      /* strict host key checking          */
    const char *known_hosts_file;    /* known_hosts file path             */
    const char *preferred_kex;       /* preferred key exchange algorithms */
    const char *preferred_hostkey;   /* preferred host key algorithms     */
    const char *preferred_cipher;    /* preferred ciphers                 */
    const char *preferred_mac;       /* preferred MAC algorithms          */
    const char *preferred_comp;      /* preferred compression             */
    bool        compress;            /* enable compression                */
    bool        agent_forward;       /* enable agent forwarding           */
    bool        x11_forward;         /* enable X11 forwarding             */
    uint32_t    max_auth_tries;      /* max authentication attempts       */
} npe_ssh_options_t;

/**
 * SSH algorithm negotiation result.
 */
typedef struct npe_ssh_algorithms {
    const char *kex;                 /* key exchange algorithm            */
    const char *hostkey;             /* host key algorithm                */
    const char *cipher_c2s;          /* client-to-server cipher           */
    const char *cipher_s2c;          /* server-to-client cipher           */
    const char *mac_c2s;             /* client-to-server MAC              */
    const char *mac_s2c;             /* server-to-client MAC              */
    const char *comp_c2s;            /* client-to-server compression      */
    const char *comp_s2c;            /* server-to-client compression      */
} npe_ssh_algorithms_t;

/**
 * SSH command execution result.
 */
typedef struct npe_ssh_exec_result {
    char    *stdout_data;            /* standard output                   */
    size_t   stdout_len;             /* stdout length                     */
    char    *stderr_data;            /* standard error                    */
    size_t   stderr_len;             /* stderr length                     */
    int32_t  exit_code;              /* command exit code                 */
    int32_t  exit_signal;            /* exit signal (if killed)           */
    uint64_t duration_us;            /* execution duration (microseconds) */
} npe_ssh_exec_result_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  CONNECTION MANAGEMENT
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialize SSH options with defaults.
 */
void npe_ssh_options_init(npe_ssh_options_t *opts);

/**
 * Connect to SSH server.
 *
 * @param host    target hostname/IP
 * @param port    target port (0 = use default 22)
 * @param opts    connection options (may be NULL for defaults)
 * @param conn    receives connection handle
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_connect(const char            *host,
                            uint16_t               port,
                            const npe_ssh_options_t *opts,
                            npe_ssh_conn_t       **conn);

/**
 * Get connection state.
 */
npe_proto_state_t npe_ssh_state(const npe_ssh_conn_t *conn);

/**
 * Get server banner/version.
 */
npe_error_t npe_ssh_get_banner(npe_ssh_conn_t     *conn,
                               npe_proto_banner_t *banner);

/**
 * Get negotiated algorithms.
 */
npe_error_t npe_ssh_get_algorithms(npe_ssh_conn_t       *conn,
                                   npe_ssh_algorithms_t *algos);

/**
 * Get server host key fingerprint.
 *
 * @param conn       connection handle
 * @param hash_type  hash algorithm (e.g., "md5", "sha256")
 * @param fingerprint receives fingerprint string (caller must free)
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_get_fingerprint(npe_ssh_conn_t *conn,
                                    const char     *hash_type,
                                    char          **fingerprint);

/**
 * Disconnect and close SSH connection.
 */
void npe_ssh_disconnect(npe_ssh_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  AUTHENTICATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Get list of supported authentication methods from server.
 *
 * @param conn     connection handle
 * @param username username to query
 * @param methods  receives NULL-terminated array of method names
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_auth_methods(npe_ssh_conn_t  *conn,
                                 const char      *username,
                                 char          ***methods);

/**
 * Authenticate with password.
 */
npe_error_t npe_ssh_auth_password(npe_ssh_conn_t *conn,
                                  const char     *username,
                                  const char     *password);

/**
 * Authenticate with public key.
 *
 * @param conn      connection handle
 * @param username  username
 * @param keyfile   private key file path
 * @param passphrase key passphrase (may be NULL)
 * @param pubkey    public key file path (may be NULL, auto-detected)
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_auth_pubkey(npe_ssh_conn_t *conn,
                                const char     *username,
                                const char     *keyfile,
                                const char     *passphrase,
                                const char     *pubkey);

/**
 * Authenticate using SSH agent.
 */
npe_error_t npe_ssh_auth_agent(npe_ssh_conn_t *conn,
                               const char     *username);

/**
 * Authenticate with keyboard-interactive.
 *
 * @param conn      connection handle
 * @param username  username
 * @param callback  callback function for prompts
 * @param user_data opaque data passed to callback
 * @return NPE_OK on success
 */
typedef void (*npe_ssh_kbd_callback_t)(const char *prompt,
                                       bool        echo,
                                       char       *response,
                                       size_t      max_len,
                                       void       *user_data);

npe_error_t npe_ssh_auth_keyboard(npe_ssh_conn_t        *conn,
                                  const char            *username,
                                  npe_ssh_kbd_callback_t callback,
                                  void                  *user_data);

/**
 * Check if authentication is required.
 */
bool npe_ssh_auth_required(npe_ssh_conn_t *conn);

/**
 * Check if authenticated.
 */
bool npe_ssh_authenticated(npe_ssh_conn_t *conn);

/* ═══════════════════════════════════════════════════════════════════════════
 *  COMMAND EXECUTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Execute a single command and wait for completion.
 *
 * @param conn    connection handle
 * @param command command to execute
 * @param result  receives execution result (caller must free)
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_exec(npe_ssh_conn_t       *conn,
                         const char           *command,
                         npe_ssh_exec_result_t *result);

/**
 * Execute command with timeout.
 */
npe_error_t npe_ssh_exec_timeout(npe_ssh_conn_t       *conn,
                                 const char           *command,
                                 uint32_t              timeout_ms,
                                 npe_ssh_exec_result_t *result);

/**
 * Free execution result.
 */
void npe_ssh_exec_result_free(npe_ssh_exec_result_t *result);

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERACTIVE SHELL
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Opaque shell session handle.
 */
typedef struct npe_ssh_shell npe_ssh_shell_t;

/**
 * Open an interactive shell session.
 *
 * @param conn   connection handle
 * @param term   terminal type (e.g., "xterm", "vt100", NULL = default)
 * @param width  terminal width in characters
 * @param height terminal height in characters
 * @param shell  receives shell session handle
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_shell_open(npe_ssh_conn_t   *conn,
                               const char       *term,
                               uint32_t          width,
                               uint32_t          height,
                               npe_ssh_shell_t **shell);

/**
 * Read from shell (non-blocking).
 */
npe_error_t npe_ssh_shell_read(npe_ssh_shell_t *shell,
                               void            *buffer,
                               size_t           buffer_len,
                               size_t          *bytes_read);

/**
 * Write to shell.
 */
npe_error_t npe_ssh_shell_write(npe_ssh_shell_t *shell,
                                const void      *data,
                                size_t           data_len,
                                size_t          *bytes_written);

/**
 * Resize shell terminal.
 */
npe_error_t npe_ssh_shell_resize(npe_ssh_shell_t *shell,
                                 uint32_t         width,
                                 uint32_t         height);

/**
 * Check if shell has data available.
 */
bool npe_ssh_shell_has_data(npe_ssh_shell_t *shell);

/**
 * Close shell session.
 */
void npe_ssh_shell_close(npe_ssh_shell_t *shell);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SFTP (SSH File Transfer Protocol)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Opaque SFTP session handle.
 */
typedef struct npe_ssh_sftp npe_ssh_sftp_t;

/**
 * SFTP file attributes.
 */
typedef struct npe_sftp_attrs {
    uint64_t    size;                /* file size in bytes                */
    uint32_t    uid;                 /* user ID                           */
    uint32_t    gid;                 /* group ID                          */
    uint32_t    permissions;         /* POSIX permissions                 */
    time_t      atime;               /* access time                       */
    time_t      mtime;               /* modification time                 */
    bool        is_dir;              /* true if directory                 */
    bool        is_link;             /* true if symbolic link             */
} npe_sftp_attrs_t;

/**
 * Open SFTP session.
 */
npe_error_t npe_ssh_sftp_open(npe_ssh_conn_t  *conn,
                              npe_ssh_sftp_t **sftp);

/**
 * Get file attributes.
 */
npe_error_t npe_sftp_stat(npe_ssh_sftp_t  *sftp,
                          const char      *path,
                          npe_sftp_attrs_t *attrs);

/**
 * List directory contents.
 */
typedef struct npe_sftp_direntry {
    char             *name;          /* entry name                        */
    npe_sftp_attrs_t  attrs;         /* entry attributes                  */
} npe_sftp_direntry_t;

npe_error_t npe_sftp_readdir(npe_ssh_sftp_t      *sftp,
                             const char          *path,
                             npe_sftp_direntry_t **entries,
                             size_t              *entry_count);

/**
 * Download file.
 */
npe_error_t npe_sftp_download(npe_ssh_sftp_t *sftp,
                              const char     *remote_path,
                              const char     *local_path);

/**
 * Upload file.
 */
npe_error_t npe_sftp_upload(npe_ssh_sftp_t *sftp,
                            const char     *local_path,
                            const char     *remote_path,
                            uint32_t        permissions);

/**
 * Read file contents.
 */
npe_error_t npe_sftp_read_file(npe_ssh_sftp_t *sftp,
                               const char     *path,
                               void          **data,
                               size_t         *data_len);

/**
 * Write file contents.
 */
npe_error_t npe_sftp_write_file(npe_ssh_sftp_t *sftp,
                                const char     *path,
                                const void     *data,
                                size_t          data_len,
                                uint32_t        permissions);

/**
 * Delete file.
 */
npe_error_t npe_sftp_unlink(npe_ssh_sftp_t *sftp,
                            const char     *path);

/**
 * Create directory.
 */
npe_error_t npe_sftp_mkdir(npe_ssh_sftp_t *sftp,
                           const char     *path,
                           uint32_t        permissions);

/**
 * Remove directory.
 */
npe_error_t npe_sftp_rmdir(npe_ssh_sftp_t *sftp,
                           const char     *path);

/**
 * Rename/move file.
 */
npe_error_t npe_sftp_rename(npe_ssh_sftp_t *sftp,
                            const char     *old_path,
                            const char     *new_path);

/**
 * Close SFTP session.
 */
void npe_ssh_sftp_close(npe_ssh_sftp_t *sftp);

/* ═══════════════════════════════════════════════════════════════════════════
 *  PORT FORWARDING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Opaque port forwarding handle.
 */
typedef struct npe_ssh_forward npe_ssh_forward_t;

/**
 * Create local port forward (local → remote).
 *
 * @param conn        connection handle
 * @param local_host  local bind address ("127.0.0.1", "0.0.0.0", etc.)
 * @param local_port  local port to listen on
 * @param remote_host remote destination host
 * @param remote_port remote destination port
 * @param forward     receives forward handle
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_forward_local(npe_ssh_conn_t     *conn,
                                  const char         *local_host,
                                  uint16_t            local_port,
                                  const char         *remote_host,
                                  uint16_t            remote_port,
                                  npe_ssh_forward_t **forward);

/**
 * Create remote port forward (remote → local).
 */
npe_error_t npe_ssh_forward_remote(npe_ssh_conn_t     *conn,
                                   const char         *remote_host,
                                   uint16_t            remote_port,
                                   const char         *local_host,
                                   uint16_t            local_port,
                                   npe_ssh_forward_t **forward);

/**
 * Stop port forwarding.
 */
void npe_ssh_forward_stop(npe_ssh_forward_t *forward);

/* ═══════════════════════════════════════════════════════════════════════════
 *  UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Generate SSH key pair.
 *
 * @param type       key type ("rsa", "dsa", "ecdsa", "ed25519")
 * @param bits       key size in bits (0 = use default)
 * @param comment    key comment (may be NULL)
 * @param passphrase passphrase to encrypt private key (may be NULL)
 * @param priv_path  output private key file path
 * @param pub_path   output public key file path
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_keygen(const char *type,
                           uint32_t    bits,
                           const char *comment,
                           const char *passphrase,
                           const char *priv_path,
                           const char *pub_path);

/**
 * Get SSH library version.
 */
const char *npe_ssh_version(void);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register SSH library with Lua VM.
 *
 * Creates the 'npe.proto.ssh' table.
 *
 * @param vm  Lua VM instance
 * @return NPE_OK on success
 */
npe_error_t npe_ssh_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_SSH_H */
