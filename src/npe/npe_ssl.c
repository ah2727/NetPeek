#include "npe/npe_ssl.h"
#include "npe_lib_net.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* ALPN wire format: length-prefixed protocol names
 * "\x02h2"           = HTTP/2
 * "\x08http/1.1"     = HTTP/1.1
 */
static const unsigned char alpn_protos[] = {
    2, 'h', '2',
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

npe_error_t npe_ssl_wrap(npe_net_socket_t *sock, const char *hostname, bool verify_ssl) {
    if (!sock || sock->fd < 0) return NPE_ERROR_INVALID_ARG;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NPE_ERROR_SSL;

    SSL_CTX_set_verify(ctx, verify_ssl ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

    /* ── KEY FIX: Advertise h2 and http/1.1 via ALPN ── */
    if (SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos)) != 0) {
        /* Non-fatal: fall back to HTTP/1.1 silently */
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return NPE_ERROR_SSL;
    }

    /* Set blocking mode for the handshake */
    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(sock->fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    SSL_set_fd(ssl, sock->fd);
    if (hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }

    if (SSL_connect(ssl) <= 0) {
        unsigned long err = ERR_peek_last_error();
        (void)err; /* log if needed */
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NPE_ERROR_SSL;
    }

    /* ── KEY FIX: Check what the server negotiated ── */
    const unsigned char *alpn_selected = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn_selected, &alpn_len);

    if (alpn_selected && alpn_len == 2 && memcmp(alpn_selected, "h2", 2) == 0) {
        sock->is_http2 = true;
    } else {
        sock->is_http2 = false;
    }

    sock->ssl_handle = ssl;
    return NPE_OK;
}

npe_error_t npe_ssl_unwrap(npe_net_socket_t *sock) {
    if (!sock || !sock->ssl_handle) return NPE_ERROR_INVALID_ARG;

    SSL *ssl = (SSL *)sock->ssl_handle;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    sock->ssl_handle = NULL;
    sock->is_http2 = false;
    return NPE_OK;
}
