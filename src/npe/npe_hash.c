// src/npe/npe_hash.c
#include "npe/npe_hash.h"
#include <stdio.h>
#include <string.h>

char* npe_hash_format(const unsigned char *hash, size_t len, char *buf, size_t bufsize) {
    if (!hash || !buf || bufsize < (len * 2 + 1)) return NULL;
    for (size_t i = 0; i < len; i++) {
        snprintf(buf + (i * 2), 3, "%02x", hash[i]);
    }
    return buf;
}
