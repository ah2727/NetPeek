/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_lib_net.h — Network Socket Operations Library
 * =============================================================================
 *
 *  Provides TCP, UDP, and (optionally) raw socket operations to Lua scripts.
 *  All functions are exposed under the "npe.net" namespace in Lua.
 *
 *  Lua API:
 *    -- TCP
 *    local sock = npe.net.tcp_connect(host, port [, timeout_ms])
 *    npe.net.send(sock, data)
 *    local data = npe.net.recv(sock [, max_bytes [, timeout_ms]])
 *    local line = npe.net.recv_line(sock [, timeout_ms])
 *    local data = npe.net.recv_until(sock, pattern [, timeout_ms])
 *    npe.net.close(sock)
 *
 *    -- UDP
 *    local sock = npe.net.udp_connect(host, port)
 *    npe.net.udp_send(sock, data)
 *    local data, addr = npe.net.udp_recv(sock [, max_bytes [, timeout_ms]])
 *    npe.net.close(sock)
 *
 *    -- Utilities
 *    local ip = npe.net.resolve(hostname)
 *    local status = npe.net.is_port_open(host, port [, timeout_ms])
 *    npe.net.set_timeout(sock, timeout_ms)
 *    local info = npe.net.get_peer_info(sock)
 *
 * =============================================================================
 */

#ifndef NPE_LIB_NET_H
#define NPE_LIB_NET_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────────────────
 * Constants
 * ───────────────────────────────────────────────────────────────────────────── */

#define NPE_NET_DEFAULT_TIMEOUT_MS      5000        /* 5 seconds              */
#define NPE_NET_MAX_RECV_SIZE           (4 * 1024 * 1024)  /* 4 MiB           */
#define NPE_NET_DEFAULT_RECV_SIZE       4096        /* Default buffer size     */
#define NPE_NET_MAX_LINE_LENGTH         8192        /* Max line for recv_line  */
#define NPE_NET_CONNECT_RETRY_DELAY_MS  100         /* Between retries         */
#define NPE_NET_MAX_CONNECT_RETRIES     3           /* Connection attempts     */

/*
 * Lua metatable name for socket userdata objects.
 * Used for type checking when sockets are passed to library functions.
 */
#define NPE_NET_SOCKET_METATABLE        "npe.net.socket"

/*
 * Socket type identifiers.
 */
typedef enum npe_net_sock_type {
    NPE_NET_SOCK_TCP     = 0,
    NPE_NET_SOCK_UDP     = 1,
    NPE_NET_SOCK_RAW     = 2
} npe_net_sock_type_t;

/*
 * Socket state (lifecycle tracking).
 */
typedef enum npe_net_sock_state {
    NPE_NET_STATE_CLOSED      = 0,
    NPE_NET_STATE_CONNECTING  = 1,
    NPE_NET_STATE_CONNECTED   = 2,
    NPE_NET_STATE_ERROR       = 3
} npe_net_sock_state_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Socket Userdata Structure
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_net_socket_t
 *
 * Stored as a Lua full userdata with the NPE_NET_SOCKET_METATABLE metatable.
 * Every socket created by npe.net functions is represented by this struct.
 */
typedef struct npe_net_socket {
    int                     fd;             /* Underlying file descriptor      */
    npe_net_sock_type_t     type;           /* TCP, UDP, or RAW               */
    npe_net_sock_state_t    state;          /* Current lifecycle state         */
    uint32_t                timeout_ms;     /* Per-socket timeout              */

    /* Peer information (filled on connect) */
    char                    peer_host[256]; /* Peer hostname / IP string       */
    uint16_t                peer_port;      /* Peer port                       */
    struct sockaddr_storage peer_addr;      /* Binary peer address             */
    socklen_t               peer_addr_len;  /* Size of peer_addr               */

    /* Internal buffer for line-oriented reads */
    char                   *recv_buf;       /* Dynamic receive buffer          */
    size_t                  recv_buf_size;  /* Current buffer capacity         */
    size_t                  recv_buf_len;   /* Bytes currently in buffer       */

    /* SSL handle (opaque pointer, NULL if plaintext) */
    void                   *ssl_handle;     /* Points to npe_ssl_connection_t  */
    
    bool is_http2;
    /* Ownership tracking */
    bool                    owned_by_lua;   /* true = Lua GC manages lifetime  */
    uint64_t                socket_id;      /* Unique ID for logging/debugging */
} npe_net_socket_t;


/* ─────────────────────────────────────────────────────────────────────────────
 * Lua Module Registration
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * luaopen_npe_net()
 *
 * Lua module opener.  Registers all npe.net functions and the socket
 * metatable.  Called by npe_lib_register_all().
 *
 * @param L   The Lua state.
 * @return    1 (the module table is on the stack).
 */
int luaopen_npe_net(lua_State *L);


/* ─────────────────────────────────────────────────────────────────────────────
 * C-Level API (for use by other NPE C modules)
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_net_tcp_connect()
 *
 * Open a TCP connection to host:port with a timeout.
 * This is the C implementation backing npe.net.tcp_connect() in Lua.
 *
 * @param host          Target hostname or IP address.
 * @param port          Target port number.
 * @param timeout_ms    Connection timeout in milliseconds (0 = default).
 * @param out_sock      On success, receives the created socket struct.
 * @return              0 on success, -1 on error (errno set).
 */
int npe_net_tcp_connect(const char *host, uint16_t port,
                        uint32_t timeout_ms, npe_net_socket_t *out_sock);

/*
 * npe_net_udp_create()
 *
 * Create a UDP socket bound to the given target.
 *
 * @param host          Target hostname or IP address.
 * @param port          Target port number.
 * @param out_sock      On success, receives the created socket struct.
 * @return              0 on success, -1 on error.
 */
int npe_net_udp_create(const char *host, uint16_t port,
                       npe_net_socket_t *out_sock);

/*
 * npe_net_send()
 *
 * Send data through a connected socket.  Handles partial writes.
 *
 * @param sock    Pointer to the socket struct.
 * @param data    Data buffer to send.
 * @param len     Number of bytes to send.
 * @return        Number of bytes sent, or -1 on error.
 */
ssize_t npe_net_send(npe_net_socket_t *sock, const void *data, size_t len);

/*
 * npe_net_recv()
 *
 * Receive data from a connected socket.
 *
 * @param sock          Pointer to the socket struct.
 * @param buf           Buffer to receive into.
 * @param buf_size      Maximum bytes to read.
 * @param timeout_ms    Read timeout (0 = use socket's default timeout).
 * @return              Number of bytes received, 0 on EOF, -1 on error.
 */
ssize_t npe_net_recv(npe_net_socket_t *sock, void *buf, size_t buf_size,
                     uint32_t timeout_ms);

/*
 * npe_net_recv_line()
 *
 * Read data until a newline (\n or \r\n) is encountered.
 * The returned string includes the newline.
 *
 * @param sock          Pointer to the socket struct.
 * @param buf           Buffer to receive the line into.
 * @param buf_size      Buffer capacity.
 * @param timeout_ms    Read timeout.
 * @return              Length of the line, 0 on EOF, -1 on error.
 */
ssize_t npe_net_recv_line(npe_net_socket_t *sock, char *buf, size_t buf_size,
                          uint32_t timeout_ms);

/*
 * npe_net_recv_until()
 *
 * Read data until a specific byte pattern is found in the stream.
 *
 * @param sock          Pointer to the socket struct.
 * @param buf           Buffer to receive into.
 * @param buf_size      Buffer capacity.
 * @param pattern       Pattern string to match.
 * @param pattern_len   Length of the pattern.
 * @param timeout_ms    Read timeout.
 * @return              Total bytes received, -1 on error.
 */
ssize_t npe_net_recv_until(npe_net_socket_t *sock, char *buf, size_t buf_size,
                           const char *pattern, size_t pattern_len,
                           uint32_t timeout_ms);

/*
 * npe_net_recv_bytes()
 *
 * Read exactly `count` bytes from the socket (blocking until all
 * bytes are received or timeout/error).
 *
 * @param sock          Pointer to the socket struct.
 * @param buf           Buffer to receive into.
 * @param count         Exact number of bytes to read.
 * @param timeout_ms    Read timeout.
 * @return              `count` on success, -1 on error, partial count on EOF.
 */
ssize_t npe_net_recv_bytes(npe_net_socket_t *sock, void *buf, size_t count,
                           uint32_t timeout_ms);

/*
 * npe_net_close()
 *
 * Close a socket and release all associated resources.
 * The socket struct is zeroed after closing.
 *
 * @param sock    Pointer to the socket struct.
 */
void npe_net_close(npe_net_socket_t *sock);

/*
 * npe_net_set_timeout()
 *
 * Update the timeout for an existing socket.
 *
 * @param sock          Pointer to the socket struct.
 * @param timeout_ms    New timeout in milliseconds.
 * @return              0 on success, -1 on error.
 */
int npe_net_set_timeout(npe_net_socket_t *sock, uint32_t timeout_ms);

/*
 * npe_net_is_port_open()
 *
 * Quick TCP connect-and-close check to determine if a port is open.
 *
 * @param host          Target hostname or IP.
 * @param port          Target port.
 * @param timeout_ms    Connection timeout.
 * @return              true if port is open, false otherwise.
 */
bool npe_net_is_port_open(const char *host, uint16_t port, uint32_t timeout_ms);

/*
 * npe_net_resolve()
 *
 * Resolve a hostname to an IP address string.
 *
 * @param hostname      The hostname to resolve.
 * @param out_ip        Buffer to receive the IP string (at least INET6_ADDRSTRLEN).
 * @param out_ip_size   Size of the output buffer.
 * @return              0 on success, -1 on failure.
 */
int npe_net_resolve(const char *hostname, char *out_ip, size_t out_ip_size);


/* ─────────────────────────────────────────────────────────────────────────────
 * Socket Userdata Helpers (for Lua binding code)
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_net_push_socket()
 *
 * Create a new socket userdata on the Lua stack from an existing C socket.
 *
 * @param L       The Lua state.
 * @param sock    Source socket struct to copy into the userdata.
 * @return        Pointer to the userdata's npe_net_socket_t.
 */
npe_net_socket_t *npe_net_push_socket(lua_State *L,
                                      const npe_net_socket_t *sock);

/*
 * npe_net_check_socket()
 *
 * Retrieve and validate a socket userdata from the Lua stack at the
 * given index.  Raises a Lua error if the argument is not a valid socket.
 *
 * @param L      The Lua state.
 * @param idx    Stack index of the argument.
 * @return       Pointer to the socket struct.
 */
npe_net_socket_t *npe_net_check_socket(lua_State *L, int idx);

/*
 * npe_net_socket_gc()
 *
 * Garbage collection metamethod (__gc) for socket userdata.
 * Automatically closes the socket if still open.
 *
 * @param L    The Lua state.
 * @return     0 (no Lua return values).
 */
int npe_net_socket_gc(lua_State *L);

/*
 * npe_net_socket_tostring()
 *
 * String representation metamethod (__tostring) for socket userdata.
 * Returns a string like "npe.net.socket<TCP:192.168.1.1:80>".
 *
 * @param L    The Lua state.
 * @return     1 (string on stack).
 */
int npe_net_socket_tostring(lua_State *L);


/* ─────────────────────────────────────────────────────────────────────────────
 * Internal Lua-C Function Bindings (registered in luaopen_npe_net)
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * These are the actual C functions registered into the npe.net Lua table.
 * They validate arguments, check sandbox permissions, and delegate to
 * the C-level API above.
 */
int npe_net_l_tcp_connect(lua_State *L);
int npe_net_l_udp_connect(lua_State *L);
int npe_net_l_send(lua_State *L);
int npe_net_l_recv(lua_State *L);
int npe_net_l_recv_line(lua_State *L);
int npe_net_l_recv_until(lua_State *L);
int npe_net_l_recv_bytes(lua_State *L);
int npe_net_l_close(lua_State *L);
int npe_net_l_resolve(lua_State *L);
int npe_net_l_is_port_open(lua_State *L);
int npe_net_l_set_timeout(lua_State *L);
int npe_net_l_get_peer_info(lua_State *L);


/* ─────────────────────────────────────────────────────────────────────────────
 * Socket ID Generation
 * ───────────────────────────────────────────────────────────────────────────── */

/*
 * npe_net_next_socket_id()
 *
 * Thread-safe unique ID generator for socket tracking.
 *
 * @return  A monotonically increasing unique socket ID.
 */
uint64_t npe_net_next_socket_id(void);

/* ─────────────────────────────────────────────────────────
 *  npe_net_tcp_connect_ssl  —  TCP + TLS + ALPN in one call
 *
 *  This is what npe_http_request() should use for HTTPS.
 *  After this returns, sock->is_http2 is authoritative.
 * ───────────────────────────────────────────────────────── */

int npe_net_tcp_disconnect(npe_net_socket_t *sock);

/* ─────────────────────────────────────────────────────────
 *  npe_net_tcp_disconnect  —  clean teardown
 * ───────────────────────────────────────────────────────── */

int
npe_net_tcp_connect_ssl(const char *host, uint16_t port,
                        uint32_t timeout_ms, bool verify_ssl,
                        npe_net_socket_t *out_sock);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_NET_H */
