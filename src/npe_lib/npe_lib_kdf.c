/*****************************************************************************
 * npe_lib_kdf.c — Key Derivation Functions (PBKDF2, scrypt)
 *****************************************************************************/

#include "npe_lib_hash.h"
#include "npe_types.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * PBKDF2
 * ========================================================================== */

npe_error_t
npe_pbkdf2(npe_hash_algo_t  algo,
           const void      *password,
           size_t           password_len,
           const void      *salt,
           size_t           salt_len,
           uint32_t         iterations,
           void            *derived_key,
           size_t           derived_key_len)
{
    if (!password || !salt || !derived_key)
        return NPE_ERROR_INVALID_ARG;
    if (iterations == 0 || derived_key_len == 0)
        return NPE_ERROR_INVALID_ARG;

    const EVP_MD *md = NULL;

    switch (algo) {
    case NPE_HASH_SHA1:   md = EVP_sha1();   break;
    case NPE_HASH_SHA224: md = EVP_sha224(); break;
    case NPE_HASH_SHA256: md = EVP_sha256(); break;
    case NPE_HASH_SHA384: md = EVP_sha384(); break;
    case NPE_HASH_SHA512: md = EVP_sha512(); break;
    default:
        return NPE_ERROR_INVALID_ARG;
    }

    if (!md)
        return NPE_ERROR_GENERIC;

    int rc = PKCS5_PBKDF2_HMAC(
        (const char *)password, (int)password_len,
        (const unsigned char *)salt, (int)salt_len,
        (int)iterations,
        md,
        (int)derived_key_len,
        (unsigned char *)derived_key
    );

    return (rc == 1) ? NPE_OK : NPE_ERROR_GENERIC;
}

npe_error_t
npe_pbkdf2_string(npe_hash_algo_t   algo,
                  const void       *password,
                  size_t            password_len,
                  const void       *salt,
                  size_t            salt_len,
                  uint32_t          iterations,
                  size_t            derived_key_len,
                  npe_hash_format_t format,
                  char            **output,
                  size_t           *out_len)
{
    if (!output || !out_len)
        return NPE_ERROR_INVALID_ARG;

    uint8_t *dk = (uint8_t *)malloc(derived_key_len);
    if (!dk)
        return NPE_ERROR_MEMORY;

    npe_error_t err = npe_pbkdf2(
        algo,
        password, password_len,
        salt, salt_len,
        iterations,
        dk, derived_key_len
    );

    if (err != NPE_OK) {
        free(dk);
        return err;
    }

    err = npe_hash_format(dk, derived_key_len, format, output, out_len);
    free(dk);
    return err;
}

/* ============================================================================
 * scrypt
 * ========================================================================== */

npe_error_t
npe_scrypt(const void *password,
           size_t      password_len,
           const void *salt,
           size_t      salt_len,
           uint64_t    N,
           uint32_t    r,
           uint32_t    p,
           void       *derived_key,
           size_t      derived_key_len)
{
    if (!password || !salt || !derived_key)
        return NPE_ERROR_INVALID_ARG;
    if (derived_key_len == 0)
        return NPE_ERROR_INVALID_ARG;

    if (N == 0 || (N & (N - 1)) != 0)
        return NPE_ERROR_INVALID_ARG;
    if (r == 0 || p == 0)
        return NPE_ERROR_INVALID_ARG;

    int rc = EVP_PBE_scrypt(
        (const char *)password, password_len,
        (const unsigned char *)salt, salt_len,
        N, r, p,
        0,
        (unsigned char *)derived_key, derived_key_len
    );

    return (rc == 1) ? NPE_OK : NPE_ERROR_GENERIC;
}

npe_error_t
npe_scrypt_string(const void       *password,
                  size_t            password_len,
                  const void       *salt,
                  size_t            salt_len,
                  uint64_t          N,
                  uint32_t          r,
                  uint32_t          p,
                  size_t            derived_key_len,
                  npe_hash_format_t format,
                  char            **output,
                  size_t           *out_len)
{
    if (!output || !out_len)
        return NPE_ERROR_INVALID_ARG;

    uint8_t *dk = (uint8_t *)malloc(derived_key_len);
    if (!dk)
        return NPE_ERROR_MEMORY;

    npe_error_t err = npe_scrypt(
        password, password_len,
        salt, salt_len,
        N, r, p,
        dk, derived_key_len
    );

    if (err != NPE_OK) {
        free(dk);
        return err;
    }

    err = npe_hash_format(dk, derived_key_len, format, output, out_len);
    free(dk);
    return err;
}