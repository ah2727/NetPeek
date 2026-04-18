/*****************************************************************************
 * npe_lib_base64.h — Base64 encoding/decoding utilities
 *
 * Lua API exposed as: npe.base64.*
 *
 * Lua API:
 *   npe.base64.encode(data)
 *   npe.base64.decode(str)
 *   npe.base64.url_encode(data)
 *   npe.base64.url_decode(str)
 *****************************************************************************/

#ifndef NPE_LIB_BASE64_H
#define NPE_LIB_BASE64_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct npe_vm npe_vm_t;

/* Encoding variants */
typedef enum {
    NPE_BASE64_STANDARD,
    NPE_BASE64_URLSAFE
} npe_base64_variant_t;

/* Encode binary data */
npe_error_t npe_base64_encode(const uint8_t *input,
                              size_t length,
                              npe_base64_variant_t variant,
                              char **output,
                              size_t *out_len);

/* Decode base64 string */
npe_error_t npe_base64_decode(const char *input,
                              size_t length,
                              npe_base64_variant_t variant,
                              uint8_t **output,
                              size_t *out_len);

/* Quick helpers */
char *npe_base64_encode_str(const char *input);
char *npe_base64_decode_str(const char *input);

/* Validation */
bool npe_base64_validate(const char *input, size_t length);

/* Lua registration */
npe_error_t npe_lib_base64_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif
