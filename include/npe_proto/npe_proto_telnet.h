/**
 * @file npe_proto_telnet.h
 * @brief Telnet protocol interactions for NPE framework
 * @author NPE Development Team
 * @date 2026-03-16
 * 
 * This header provides Telnet protocol functionality including:
 * - Telnet connection management
 * - Option negotiation (WILL/WONT/DO/DONT)
 * - Authentication handling
 * - Command execution
 * - Terminal emulation support
 * - Banner grabbing and fingerprinting
 */

#ifndef NPE_PROTO_TELNET_H
#define NPE_PROTO_TELNET_H

#include "npe_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * TELNET PROTOCOL CONSTANTS
 * ============================================================================ */

/**
 * @defgroup telnet_defaults Default Values
 * @{
 */
#define NPE_TELNET_DEFAULT_PORT          23
#define NPE_TELNET_DEFAULT_TIMEOUT       30000   /* 30 seconds in ms */
#define NPE_TELNET_CONNECT_TIMEOUT       10000   /* 10 seconds in ms */
#define NPE_TELNET_READ_TIMEOUT          5000    /* 5 seconds in ms */
#define NPE_TELNET_MAX_BUFFER_SIZE       8192
#define NPE_TELNET_MAX_LINE_LENGTH       1024
#define NPE_TELNET_MAX_USERNAME_LEN      256
#define NPE_TELNET_MAX_PASSWORD_LEN      256
#define NPE_TELNET_MAX_COMMAND_LEN       4096
#define NPE_TELNET_MAX_RESPONSE_LEN      65536
#define NPE_TELNET_MAX_PROMPT_LEN        256
#define NPE_TELNET_MAX_BANNER_LEN        4096
#define NPE_TELNET_MAX_OPTIONS           256
#define NPE_TELNET_MAX_SUBNEG_LEN        512
#define NPE_TELNET_MAX_TERM_TYPE_LEN     64
#define NPE_TELNET_MAX_ENV_VARS          32
#define NPE_TELNET_MAX_ENV_NAME_LEN      128
#define NPE_TELNET_MAX_ENV_VALUE_LEN     256
#define NPE_TELNET_DEFAULT_WINDOW_ROWS   24
#define NPE_TELNET_DEFAULT_WINDOW_COLS   80
/** @} */

/**
 * @defgroup telnet_commands Telnet Commands (RFC 854)
 * @{
 */
#define NPE_TELNET_IAC                   255     /* Interpret As Command */
#define NPE_TELNET_DONT                  254     /* Refuse to perform option */
#define NPE_TELNET_DO                    253     /* Request to perform option */
#define NPE_TELNET_WONT                  252     /* Refuse to perform option */
#define NPE_TELNET_WILL                  251     /* Agree to perform option */
#define NPE_TELNET_SB                    250     /* Subnegotiation Begin */
#define NPE_TELNET_GA                    249     /* Go Ahead */
#define NPE_TELNET_EL                    248     /* Erase Line */
#define NPE_TELNET_EC                    247     /* Erase Character */
#define NPE_TELNET_AYT                   246     /* Are You There */
#define NPE_TELNET_AO                    245     /* Abort Output */
#define NPE_TELNET_IP                    244     /* Interrupt Process */
#define NPE_TELNET_BRK                   243     /* Break */
#define NPE_TELNET_DM                    242     /* Data Mark */
#define NPE_TELNET_NOP                   241     /* No Operation */
#define NPE_TELNET_SE                    240     /* Subnegotiation End */
#define NPE_TELNET_EOR                   239     /* End of Record */
#define NPE_TELNET_ABORT                 238     /* Abort Process */
#define NPE_TELNET_SUSP                  237     /* Suspend Process */
#define NPE_TELNET_EOF                   236     /* End of File */
/** @} */

/**
 * @defgroup telnet_options Telnet Options (RFC 855+)
 * @{
 */
#define NPE_TELOPT_BINARY                0       /* Binary Transmission (RFC 856) */
#define NPE_TELOPT_ECHO                  1       /* Echo (RFC 857) */
#define NPE_TELOPT_RCP                   2       /* Reconnection */
#define NPE_TELOPT_SGA                   3       /* Suppress Go Ahead (RFC 858) */
#define NPE_TELOPT_NAMS                  4       /* Approx Message Size Negotiation */
#define NPE_TELOPT_STATUS                5       /* Status (RFC 859) */
#define NPE_TELOPT_TM                    6       /* Timing Mark (RFC 860) */
#define NPE_TELOPT_RCTE                  7       /* Remote Controlled Trans and Echo */
#define NPE_TELOPT_NAOL                  8       /* Output Line Width */
#define NPE_TELOPT_NAOP                  9       /* Output Page Size */
#define NPE_TELOPT_NAOCRD                10      /* Output Carriage-Return Disposition */
#define NPE_TELOPT_NAOHTS                11      /* Output Horizontal Tab Stops */
#define NPE_TELOPT_NAOHTD                12      /* Output Horizontal Tab Disposition */
#define NPE_TELOPT_NAOFFD                13      /* Output Formfeed Disposition */
#define NPE_TELOPT_NAOVTS                14      /* Output Vertical Tabstops */
#define NPE_TELOPT_NAOVTD                15      /* Output Vertical Tab Disposition */
#define NPE_TELOPT_NAOLFD                16      /* Output Linefeed Disposition */
#define NPE_TELOPT_XASCII                17      /* Extended ASCII */
#define NPE_TELOPT_LOGOUT                18      /* Logout (RFC 727) */
#define NPE_TELOPT_BM                    19      /* Byte Macro */
#define NPE_TELOPT_DET                   20      /* Data Entry Terminal */
#define NPE_TELOPT_SUPDUP                21      /* SUPDUP */
#define NPE_TELOPT_SUPDUPOUTPUT          22      /* SUPDUP Output */
#define NPE_TELOPT_SNDLOC                23      /* Send Location */
#define NPE_TELOPT_TTYPE                 24      /* Terminal Type (RFC 1091) */
#define NPE_TELOPT_EOR                   25      /* End of Record (RFC 885) */
#define NPE_TELOPT_TUID                  26      /* TACACS User Identification */
#define NPE_TELOPT_OUTMRK                27      /* Output Marking */
#define NPE_TELOPT_TTYLOC                28      /* Terminal Location Number */
#define NPE_TELOPT_3270REGIME            29      /* 3270 Regime */
#define NPE_TELOPT_X3PAD                 30      /* X.3 PAD */
#define NPE_TELOPT_NAWS                  31      /* Window Size (RFC 1073) */
#define NPE_TELOPT_TSPEED                32      /* Terminal Speed (RFC 1079) */
#define NPE_TELOPT_LFLOW                 33      /* Remote Flow Control (RFC 1372) */
#define NPE_TELOPT_LINEMODE              34      /* Linemode (RFC 1184) */
#define NPE_TELOPT_XDISPLOC              35      /* X Display Location (RFC 1096) */
#define NPE_TELOPT_OLD_ENVIRON           36      /* Old Environment Variables */
#define NPE_TELOPT_AUTHENTICATION        37      /* Authentication (RFC 2941) */
#define NPE_TELOPT_ENCRYPT               38      /* Encryption (RFC 2946) */
#define NPE_TELOPT_NEW_ENVIRON           39      /* New Environment Variables (RFC 1572) */
#define NPE_TELOPT_TN3270E               40      /* TN3270E (RFC 2355) */
#define NPE_TELOPT_XAUTH                 41      /* XAUTH */
#define NPE_TELOPT_CHARSET               42      /* CHARSET (RFC 2066) */
#define NPE_TELOPT_RSP                   43      /* Telnet Remote Serial Port */
#define NPE_TELOPT_COM_PORT_CONTROL      44      /* Com Port Control (RFC 2217) */
#define NPE_TELOPT_SUPPRESS_LOCAL_ECHO   45      /* Suppress Local Echo */
#define NPE_TELOPT_START_TLS             46      /* Start TLS */
#define NPE_TELOPT_KERMIT                47      /* KERMIT (RFC 2840) */
#define NPE_TELOPT_SEND_URL              48      /* SEND-URL */
#define NPE_TELOPT_FORWARD_X             49      /* FORWARD_X */
#define NPE_TELOPT_EXOPL                 255     /* Extended-Options-List (RFC 861) */
/** @} */

/**
 * @defgroup telnet_subneg Subnegotiation Constants
 * @{
 */
#define NPE_TELNET_SUBNEG_IS             0       /* IS (used in TTYPE, ENVIRON) */
#define NPE_TELNET_SUBNEG_SEND           1       /* SEND (used in TTYPE, ENVIRON) */
#define NPE_TELNET_SUBNEG_INFO           2       /* INFO (used in ENVIRON) */
#define NPE_TELNET_ENVIRON_VAR           0       /* VAR */
#define NPE_TELNET_ENVIRON_VALUE         1       /* VALUE */
#define NPE_TELNET_ENVIRON_ESC           2       /* ESC */
#define NPE_TELNET_ENVIRON_USERVAR       3       /* USERVAR */
/** @} */

/**
 * @defgroup telnet_special Special Characters
 * @{
 */
#define NPE_TELNET_CR                    '\r'    /* Carriage Return */
#define NPE_TELNET_LF                    '\n'    /* Line Feed */
#define NPE_TELNET_NUL                   '\0'    /* Null */
/** @} */

/* ============================================================================
 * TELNET ENUMERATIONS
 * ============================================================================ */

/**
 * @brief Telnet error codes
 */
typedef enum npe_telnet_error {
    NPE_TELNET_OK                        = 0,
    NPE_TELNET_ERROR_UNKNOWN             = -1,
    NPE_TELNET_ERROR_MEMORY              = -2,
    NPE_TELNET_ERROR_INVALID_PARAM       = -3,
    NPE_TELNET_ERROR_NOT_CONNECTED       = -4,
    NPE_TELNET_ERROR_ALREADY_CONNECTED   = -5,
    NPE_TELNET_ERROR_CONNECTION_FAILED   = -6,
    NPE_TELNET_ERROR_CONNECTION_REFUSED  = -7,
    NPE_TELNET_ERROR_CONNECTION_TIMEOUT  = -8,
    NPE_TELNET_ERROR_CONNECTION_RESET    = -9,
    NPE_TELNET_ERROR_HOST_UNREACHABLE    = -10,
    NPE_TELNET_ERROR_NETWORK_UNREACHABLE = -11,
    NPE_TELNET_ERROR_DNS_FAILED          = -12,
    NPE_TELNET_ERROR_SEND_FAILED         = -13,
    NPE_TELNET_ERROR_RECV_FAILED         = -14,
    NPE_TELNET_ERROR_TIMEOUT             = -15,
    NPE_TELNET_ERROR_AUTH_FAILED         = -16,
    NPE_TELNET_ERROR_AUTH_REQUIRED       = -17,
    NPE_TELNET_ERROR_PROMPT_NOT_FOUND    = -18,
    NPE_TELNET_ERROR_BUFFER_OVERFLOW     = -19,
    NPE_TELNET_ERROR_PROTOCOL            = -20,
    NPE_TELNET_ERROR_OPTION_REFUSED      = -21,
    NPE_TELNET_ERROR_CLOSED              = -22,
    NPE_TELNET_ERROR_SSL_INIT            = -23,
    NPE_TELNET_ERROR_SSL_HANDSHAKE       = -24,
    NPE_TELNET_ERROR_SSL_CERT            = -25,
    NPE_TELNET_ERROR_WOULD_BLOCK         = -26,
    NPE_TELNET_ERROR_IN_PROGRESS         = -27,
    NPE_TELNET_ERROR_INTERRUPTED         = -28
} npe_telnet_error_t;

/**
 * @brief Telnet connection state
 */
typedef enum npe_telnet_state {
    NPE_TELNET_STATE_DISCONNECTED        = 0,
    NPE_TELNET_STATE_CONNECTING          = 1,
    NPE_TELNET_STATE_CONNECTED           = 2,
    NPE_TELNET_STATE_NEGOTIATING         = 3,
    NPE_TELNET_STATE_AUTHENTICATING      = 4,
    NPE_TELNET_STATE_AUTHENTICATED       = 5,
    NPE_TELNET_STATE_READY               = 6,
    NPE_TELNET_STATE_EXECUTING           = 7,
    NPE_TELNET_STATE_CLOSING             = 8,
    NPE_TELNET_STATE_ERROR               = 9
} npe_telnet_state_t;

/**
 * @brief Telnet option negotiation state (Q-Method RFC 1143)
 */
typedef enum npe_telnet_opt_state {
    NPE_TELNET_OPT_NO                    = 0,    /* Option is disabled */
    NPE_TELNET_OPT_YES                   = 1,    /* Option is enabled */
    NPE_TELNET_OPT_WANTNO                = 2,    /* Sent WONT/DONT, waiting for response */
    NPE_TELNET_OPT_WANTYES               = 3,    /* Sent WILL/DO, waiting for response */
    NPE_TELNET_OPT_WANTNO_OPPOSITE       = 4,    /* WANTNO with opposite queued */
    NPE_TELNET_OPT_WANTYES_OPPOSITE      = 5     /* WANTYES with opposite queued */
} npe_telnet_opt_state_t;

/**
 * @brief Terminal type for TTYPE negotiation
 */
typedef enum npe_telnet_term_type {
    NPE_TELNET_TERM_UNKNOWN              = 0,
    NPE_TELNET_TERM_ANSI                 = 1,
    NPE_TELNET_TERM_VT100                = 2,
    NPE_TELNET_TERM_VT102                = 3,
    NPE_TELNET_TERM_VT220                = 4,
    NPE_TELNET_TERM_XTERM                = 5,
    NPE_TELNET_TERM_XTERM_256COLOR       = 6,
    NPE_TELNET_TERM_LINUX                = 7,
    NPE_TELNET_TERM_SCREEN               = 8,
    NPE_TELNET_TERM_DUMB                 = 9,
    NPE_TELNET_TERM_CUSTOM               = 10
} npe_telnet_term_type_t;

/**
 * @brief Authentication method
 */
typedef enum npe_telnet_auth_method {
    NPE_TELNET_AUTH_NONE                 = 0,
    NPE_TELNET_AUTH_PASSWORD             = 1,
    NPE_TELNET_AUTH_NTLM                 = 2,
    NPE_TELNET_AUTH_KERBEROS             = 3,
    NPE_TELNET_AUTH_SPX                  = 4,
    NPE_TELNET_AUTH_SRP                  = 5
} npe_telnet_auth_method_t;

/**
 * @brief Line ending mode
 */
typedef enum npe_telnet_line_mode {
    NPE_TELNET_LINE_CRLF                 = 0,
    NPE_TELNET_LINE_CR                   = 1,
    NPE_TELNET_LINE_LF                   = 2,
    NPE_TELNET_LINE_CRNUL                = 3
} npe_telnet_line_mode_t;

/**
 * @brief Logging level
 */
typedef enum npe_telnet_log_level {
    NPE_TELNET_LOG_NONE                  = 0,
    NPE_TELNET_LOG_ERROR                 = 1,
    NPE_TELNET_LOG_WARNING               = 2,
    NPE_TELNET_LOG_INFO                  = 3,
    NPE_TELNET_LOG_DEBUG                 = 4,
    NPE_TELNET_LOG_TRACE                 = 5
} npe_telnet_log_level_t;


/* ============================================================================
 * TELNET STRUCTURES
 * ============================================================================ */

/**
 * @brief Environment variable
 */
typedef struct npe_telnet_env_var {
    char name[NPE_TELNET_MAX_ENV_NAME_LEN];
    char value[NPE_TELNET_MAX_ENV_VALUE_LEN];
} npe_telnet_env_var_t;

/**
 * @brief Telnet option state
 */
typedef struct npe_telnet_option {
    uint8_t option;
    npe_telnet_opt_state_t local_state;
    npe_telnet_opt_state_t remote_state;
} npe_telnet_option_t;

/**
 * @brief Telnet session structure
 */
typedef struct npe_telnet_session {

    int socket_fd;
    char host[256];
    uint16_t port;

    npe_telnet_state_t state;

    int timeout_ms;
    int connect_timeout_ms;
    int read_timeout_ms;

    /* buffers */
    uint8_t read_buffer[NPE_TELNET_MAX_BUFFER_SIZE];
    size_t read_length;

    uint8_t write_buffer[NPE_TELNET_MAX_BUFFER_SIZE];
    size_t write_length;

    /* authentication */
    char username[NPE_TELNET_MAX_USERNAME_LEN];
    char password[NPE_TELNET_MAX_PASSWORD_LEN];
    npe_telnet_auth_method_t auth_method;

    /* terminal settings */
    npe_telnet_term_type_t terminal_type;
    char terminal_name[NPE_TELNET_MAX_TERM_TYPE_LEN];
    uint16_t window_rows;
    uint16_t window_cols;

    /* options */
    npe_telnet_option_t options[NPE_TELNET_MAX_OPTIONS];

    /* environment variables */
    npe_telnet_env_var_t env_vars[NPE_TELNET_MAX_ENV_VARS];
    size_t env_count;

    /* banner */
    char banner[NPE_TELNET_MAX_BANNER_LEN];

    /* logging */
    npe_telnet_log_level_t log_level;

    /* user data */
    void *user_data;

} npe_telnet_session_t;


/* ============================================================================
 * TELNET CALLBACKS
 * ============================================================================ */

typedef void (*npe_telnet_log_cb)(
    npe_telnet_log_level_t level,
    const char *message,
    void *user_data
);

typedef void (*npe_telnet_data_cb)(
    const uint8_t *data,
    size_t length,
    void *user_data
);


/* ============================================================================
 * TELNET CORE API
 * ============================================================================ */

/* session management */
npe_telnet_session_t* npe_telnet_create(void);
void npe_telnet_destroy(npe_telnet_session_t *session);

/* connection management */
int npe_telnet_connect(
    npe_telnet_session_t *session,
    const char *host,
    uint16_t port
);

int npe_telnet_disconnect(
    npe_telnet_session_t *session
);

/* authentication */
int npe_telnet_login(
    npe_telnet_session_t *session,
    const char *username,
    const char *password
);

/* communication */
int npe_telnet_send(
    npe_telnet_session_t *session,
    const uint8_t *data,
    size_t length
);

int npe_telnet_send_command(
    npe_telnet_session_t *session,
    const char *command
);

int npe_telnet_receive(
    npe_telnet_session_t *session,
    uint8_t *buffer,
    size_t size,
    size_t *received
);

/* option negotiation */
int npe_telnet_send_option(
    npe_telnet_session_t *session,
    uint8_t command,
    uint8_t option
);

int npe_telnet_handle_negotiation(
    npe_telnet_session_t *session,
    const uint8_t *data,
    size_t length
);

/* terminal configuration */
int npe_telnet_set_terminal(
    npe_telnet_session_t *session,
    npe_telnet_term_type_t type,
    const char *name
);

int npe_telnet_set_window_size(
    npe_telnet_session_t *session,
    uint16_t rows,
    uint16_t cols
);

/* environment variables */
int npe_telnet_set_env(
    npe_telnet_session_t *session,
    const char *name,
    const char *value
);

/* banner grabbing */
int npe_telnet_get_banner(
    npe_telnet_session_t *session,
    char *buffer,
    size_t size
);

/* timeout configuration */
void npe_telnet_set_timeout(
    npe_telnet_session_t *session,
    int timeout_ms
);

/* logging */
void npe_telnet_set_log_level(
    npe_telnet_session_t *session,
    npe_telnet_log_level_t level
);

void npe_telnet_set_log_callback(
    npe_telnet_session_t *session,
    npe_telnet_log_cb callback
);

/* error utilities */
const char* npe_telnet_strerror(
    npe_telnet_error_t error
);


/* ============================================================================
 * END
 * ============================================================================ */

#ifdef __cplusplus
}
#endif

#endif /* NPE_PROTO_TELNET_H */
