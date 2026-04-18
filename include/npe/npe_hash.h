// include/npe/npe_hash.h
#ifndef NPE_HASH_H
#define NPE_HASH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Format a binary hash into a hexadecimal string.
 *
 * @param hash     Binary hash data
 * @param len      Length of hash in bytes
 * @param buf      Output buffer for hex string
 * @param bufsize  Size of output buffer (must be at least len*2+1)
 * @return Pointer to buf on success, NULL on error
 */
char* npe_hash_format(const unsigned char *hash, size_t len, char *buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif /* NPE_HASH_H */
