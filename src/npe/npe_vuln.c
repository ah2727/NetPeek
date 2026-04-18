// src/npe/npe_vuln.c
#include <lua.h>
#include <lauxlib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define VULN_DEFAULT_TIMEOUT_MS 4000
#define VULN_MAX_TIMEOUT_MS 15000
#define VULN_MAX_PROBE_BYTES (256 * 1024)

static int vuln_opt_timeout(lua_State *L, int idx) {
    if (!lua_istable(L, idx)) {
        return VULN_DEFAULT_TIMEOUT_MS;
    }

    lua_getfield(L, idx, "timeout_ms");
    int timeout = lua_isinteger(L, -1) ? (int)lua_tointeger(L, -1) : VULN_DEFAULT_TIMEOUT_MS;
    lua_pop(L, 1);

    if (timeout <= 0) {
        return VULN_DEFAULT_TIMEOUT_MS;
    }
    if (timeout > VULN_MAX_TIMEOUT_MS) {
        return VULN_MAX_TIMEOUT_MS;
    }
    return timeout;
}

static size_t vuln_opt_max_bytes(lua_State *L, int idx) {
    if (!lua_istable(L, idx)) {
        return 8192;
    }

    lua_getfield(L, idx, "max_bytes");
    size_t max_bytes = lua_isinteger(L, -1) ? (size_t)lua_tointeger(L, -1) : 8192;
    lua_pop(L, 1);

    if (max_bytes == 0) {
        return 8192;
    }
    if (max_bytes > VULN_MAX_PROBE_BYTES) {
        return VULN_MAX_PROBE_BYTES;
    }
    return max_bytes;
}

static int vuln_connect_timeout(const char *host, int port, int timeout_ms) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    char port_buf[16];
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_buf, sizeof(port_buf), "%d", port);

    if (getaddrinfo(host, port_buf, &hints, &res) != 0) {
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sock);
            sock = -1;
            continue;
        }

        int rc = connect(sock, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            fcntl(sock, F_SETFL, flags);
            break;
        }
        if (errno != EINPROGRESS) {
            close(sock);
            sock = -1;
            continue;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv = {
            .tv_sec = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000,
        };

        rc = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) {
            close(sock);
            sock = -1;
            continue;
        }

        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0 || so_err != 0) {
            close(sock);
            sock = -1;
            continue;
        }

        fcntl(sock, F_SETFL, flags);
        break;
    }

    if (res) {
        freeaddrinfo(res);
    }
    return sock;
}

static int vuln_send_all(int fd, const char *data, size_t len, int timeout_ms) {
    size_t off = 0;
    while (off < len) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = {
            .tv_sec = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000,
        };

        int ready = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (ready <= 0) {
            return -1;
        }

        ssize_t n = send(fd, data + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static ssize_t vuln_recv_some(int fd, char *buf, size_t cap, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };

    int ready = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ready <= 0) {
        return -1;
    }
    return recv(fd, buf, cap, 0);
}

static int l_tcp_probe(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    size_t payload_len = 0;
    const char *payload = luaL_optlstring(L, 3, "", &payload_len);
    int timeout_ms = vuln_opt_timeout(L, 4);
    size_t max_bytes = vuln_opt_max_bytes(L, 4);

    int sock = vuln_connect_timeout(host, port, timeout_ms);
    if (sock < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "connect_failed");
        return 2;
    }

    if (payload_len > 0 && vuln_send_all(sock, payload, payload_len, timeout_ms) < 0) {
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "send_failed");
        return 2;
    }

    char *buf = (char *)malloc(max_bytes);
    if (!buf) {
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "oom");
        return 2;
    }

    ssize_t n = vuln_recv_some(sock, buf, max_bytes, timeout_ms);
    close(sock);

    if (n <= 0) {
        free(buf);
        lua_pushnil(L);
        lua_pushstring(L, "recv_failed");
        return 2;
    }

    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    return 1;
}

static int l_tls_probe(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    size_t payload_len = 0;
    const char *payload = luaL_optlstring(L, 3, "", &payload_len);
    int timeout_ms = vuln_opt_timeout(L, 4);
    size_t max_bytes = vuln_opt_max_bytes(L, 4);

    int sock = vuln_connect_timeout(host, port, timeout_ms);
    if (sock < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "connect_failed");
        return 2;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "ssl_ctx_failed");
        return 2;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "ssl_new_failed");
        return 2;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "ssl_handshake_failed");
        return 2;
    }

    if (payload_len > 0 && SSL_write(ssl, payload, (int)payload_len) <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "ssl_write_failed");
        return 2;
    }

    char *buf = (char *)malloc(max_bytes);
    if (!buf) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        lua_pushnil(L);
        lua_pushstring(L, "oom");
        return 2;
    }

    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int n = SSL_read(ssl, buf, (int)max_bytes);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);

    if (n <= 0) {
        free(buf);
        lua_pushnil(L);
        lua_pushstring(L, "ssl_read_failed");
        return 2;
    }

    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    return 1;
}

static int l_http_probe(lua_State *L) {
    const char *url = luaL_checkstring(L, 1);
    const char *method = luaL_optstring(L, 2, "GET");

    lua_getglobal(L, "http");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushstring(L, "http_module_not_loaded");
        return 2;
    }

    lua_getfield(L, -1, "request");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        lua_pushnil(L);
        lua_pushstring(L, "http_request_missing");
        return 2;
    }

    lua_pushstring(L, method);
    lua_pushstring(L, url);
    if (!lua_isnoneornil(L, 3)) {
        lua_pushvalue(L, 3);
    } else {
        lua_newtable(L);
    }

    if (lua_pcall(L, 3, LUA_MULTRET, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        lua_pushnil(L);
        lua_pushstring(L, err ? err : "http_probe_failed");
        return 2;
    }

    if (lua_isnil(L, -2)) {
        const char *err = lua_tostring(L, -1);
        lua_pushnil(L);
        lua_pushstring(L, err ? err : "http_request_failed");
        return 2;
    }

    return 1;
}

static int l_banner_match(lua_State *L) {
    size_t text_len = 0;
    const char *text = luaL_checklstring(L, 1, &text_len);
    luaL_checktype(L, 2, LUA_TTABLE);

    size_t n = lua_rawlen(L, 2);
    for (size_t i = 1; i <= n; i++) {
        lua_rawgeti(L, 2, (int)i);
        if (lua_isstring(L, -1)) {
            size_t pat_len = 0;
            const char *pat = lua_tolstring(L, -1, &pat_len);
            if (pat && pat_len > 0 && text_len >= pat_len && strstr(text, pat) != NULL) {
                lua_pop(L, 1);
                lua_pushboolean(L, 1);
                return 1;
            }
        }
        lua_pop(L, 1);
    }

    lua_pushboolean(L, 0);
    return 1;
}

static int parse_semver3(const char *v, int out[3]) {
    if (!v || !out) {
        return -1;
    }
    out[0] = out[1] = out[2] = 0;
    int matched = sscanf(v, "%d.%d.%d", &out[0], &out[1], &out[2]);
    return (matched >= 1) ? 0 : -1;
}

static int cmp_semver3(const int a[3], const int b[3]) {
    for (int i = 0; i < 3; i++) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    return 0;
}

static int l_version_in_range(lua_State *L) {
    const char *version = luaL_checkstring(L, 1);
    const char *lower = luaL_optstring(L, 2, "0.0.0");
    const char *upper = luaL_optstring(L, 3, "9999.9999.9999");

    int v[3], lo[3], hi[3];
    if (parse_semver3(version, v) < 0 || parse_semver3(lower, lo) < 0 || parse_semver3(upper, hi) < 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    bool in_range = cmp_semver3(v, lo) >= 0 && cmp_semver3(v, hi) <= 0;
    lua_pushboolean(L, in_range ? 1 : 0);
    return 1;
}

static int l_result(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    static const char *ordered_keys[] = {
        "check", "cve", "vulnerable", "confidence", "severity", "target", "evidence", "notes", NULL};

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (int i = 0; ordered_keys[i] != NULL; i++) {
        const char *k = ordered_keys[i];
        lua_getfield(L, 1, k);
        if (!lua_isnil(L, -1)) {
            luaL_addstring(&b, k);
            luaL_addstring(&b, ": ");
            size_t vlen = 0;
            const char *v = luaL_tolstring(L, -1, &vlen);
            luaL_addlstring(&b, v ? v : "", vlen);
            luaL_addstring(&b, "\n");
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }

    luaL_pushresult(&b);
    return 1;
}

int luaopen_npe_vuln(lua_State *L) {
    static const luaL_Reg funcs[] = {
        {"tcp_probe", l_tcp_probe},
        {"tls_probe", l_tls_probe},
        {"http_probe", l_http_probe},
        {"banner_match", l_banner_match},
        {"version_in_range", l_version_in_range},
        {"result", l_result},
        {NULL, NULL},
    };

    luaL_newlib(L, funcs);
    return 1;
}
