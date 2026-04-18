#ifndef NPE_SSL_H
#define NPE_SSL_H

#include "npe/npe_types.h"
#include "npe_lib_net.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct npe_net_socket npe_net_socket_t;

npe_error_t npe_ssl_wrap(npe_net_socket_t *sock, const char *hostname, bool verify_ssl);
npe_error_t npe_ssl_unwrap(npe_net_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif /* NPE_SSL_H */
