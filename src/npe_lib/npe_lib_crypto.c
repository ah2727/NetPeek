/*
 * =============================================================================
 *  NetPeek Extension Engine (NPE)
 *  npe_lib_crypto.c — Cryptographic Operations Library Implementation
 * =============================================================================
 */

#include "npe_lib_crypto.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static void bytes_to_hex(const unsigned char *bytes, int len, char *hex_out) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_out + i * 2, "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *bytes, int max_len) {
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) {
        return -1;
    }
    
    for (int i = 0; i < hex_len; i += 2) {
        unsigned int byte_val;
        if (sscanf(hex + i, "%2x", &byte_val) != 1) {
            return -1;
        }
        bytes[i / 2] = (unsigned char)byte_val;
    }
    
    return hex_len / 2;
}

/* ============================================================================
 * HASH FUNCTIONS
 * ============================================================================ */

int npe_lua_crypto_md5(lua_State *L) {
    size_t data_len;
    const char *data = luaL_checklstring(L, 1, &data_len);
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)data, data_len, digest);
    
    char hex_digest[MD5_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(digest, MD5_DIGEST_LENGTH, hex_digest);
    
    lua_pushstring(L, hex_digest);
    return 1;
}

int npe_lua_crypto_sha1(lua_State *L) {
    size_t data_len;
    const char *data = luaL_checklstring(L, 1, &data_len);
    
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)data, data_len, digest);
    
    char hex_digest[SHA_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(digest, SHA_DIGEST_LENGTH, hex_digest);
    
    lua_pushstring(L, hex_digest);
    return 1;
}

int npe_lua_crypto_sha256(lua_State *L) {
    size_t data_len;
    const char *data = luaL_checklstring(L, 1, &data_len);
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, data_len, digest);
    
    char hex_digest[SHA256_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, hex_digest);
    
    lua_pushstring(L, hex_digest);
    return 1;
}

int npe_lua_crypto_sha512(lua_State *L) {
    size_t data_len;
    const char *data = luaL_checklstring(L, 1, &data_len);
    
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char *)data, data_len, digest);
    
    char hex_digest[SHA512_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(digest, SHA512_DIGEST_LENGTH, hex_digest);
    
    lua_pushstring(L, hex_digest);
    return 1;
}

/* ============================================================================
 * HMAC FUNCTIONS
 * ============================================================================ */

int npe_lua_crypto_hmac_sha256(lua_State *L) {
    size_t key_len, data_len;
    const char *key = luaL_checklstring(L, 1, &key_len);
    const char *data = luaL_checklstring(L, 2, &data_len);
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len;
    
    HMAC(EVP_sha256(), key, key_len, (const unsigned char *)data, data_len, 
         digest, &digest_len);
    
    char hex_digest[SHA256_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(digest, digest_len, hex_digest);
    
    lua_pushstring(L, hex_digest);
    return 1;
}

int npe_lua_crypto_hmac_sha1(lua_State *L) {
    size_t key_len, data_len;
    const char *key = luaL_checklstring(L, 1, &key_len);
    const char *data = luaL_checklstring(L, 2, &data_len);
    
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len;
    
    HMAC(EVP_sha1(), key, key_len, (const unsigned char *)data, data_len, 
         digest, &digest_len);
    
    char hex_digest[SHA_DIGEST_LENGTH * 2 + 1];
    bytes_to_hex(digest, digest_len, hex_digest);
    
    lua_pushstring(L, hex_digest);
    return 1;
}

/* ============================================================================
 * RANDOM FUNCTIONS
 * ============================================================================ */

int npe_lua_crypto_random_bytes(lua_State *L) {
    int num_bytes = (int)luaL_checkinteger(L, 1);
    bool as_hex = lua_toboolean(L, 2);
    
    if (num_bytes <= 0 || num_bytes > NPE_CRYPTO_MAX_BLOCK_LEN) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid number of bytes requested");
        return 2;
    }
    
    unsigned char *random_data = malloc(num_bytes);
    if (!random_data) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    if (RAND_bytes(random_data, num_bytes) != 1) {
        free(random_data);
        lua_pushnil(L);
        lua_pushstring(L, "Failed to generate random bytes");
        return 2;
    }
    
    if (as_hex) {
        char *hex_data = malloc(num_bytes * 2 + 1);
        if (!hex_data) {
            free(random_data);
            lua_pushnil(L);
            lua_pushstring(L, "Memory allocation failed");
            return 2;
        }
        
        bytes_to_hex(random_data, num_bytes, hex_data);
        lua_pushstring(L, hex_data);
        free(hex_data);
    } else {
        lua_pushlstring(L, (const char *)random_data, num_bytes);
    }
    
    free(random_data);
    return 1;
}

/* ============================================================================
 * AES ENCRYPTION/DECRYPTION
 * ============================================================================ */

int npe_lua_crypto_aes_encrypt(lua_State *L) {
    size_t data_len, key_len, iv_len = 0;
    const char *data = luaL_checklstring(L, 1, &data_len);
    const char *key = luaL_checklstring(L, 2, &key_len);
    const char *iv = luaL_optlstring(L, 3, NULL, &iv_len);
    const char *mode = luaL_optstring(L, 4, "CBC");
    
    /* Validate key length */
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid key length (must be 16, 24, or 32 bytes)");
        return 2;
    }
    
    /* Determine cipher */
    const EVP_CIPHER *cipher = NULL;
    int expected_iv_len = 0;
    
    if (strcmp(mode, "CBC") == 0) {
        expected_iv_len = 16;
        if (key_len == 16) cipher = EVP_aes_128_cbc();
        else if (key_len == 24) cipher = EVP_aes_192_cbc();
        else if (key_len == 32) cipher = EVP_aes_256_cbc();
    } else if (strcmp(mode, "ECB") == 0) {
        expected_iv_len = 0;
        if (key_len == 16) cipher = EVP_aes_128_ecb();
        else if (key_len == 24) cipher = EVP_aes_192_ecb();
        else if (key_len == 32) cipher = EVP_aes_256_ecb();
    } else {
        lua_pushnil(L);
        lua_pushstring(L, "Unsupported mode (use CBC or ECB)");
        return 2;
    }
    
    if (!cipher) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to determine cipher");
        return 2;
    }
    
    /* Validate IV */
    unsigned char iv_bytes[16] = {0};
    if (expected_iv_len > 0) {
        if (!iv || iv_len != expected_iv_len) {
            lua_pushnil(L);
            lua_pushfstring(L, "IV required and must be %d bytes", expected_iv_len);
            return 2;
        }
        memcpy(iv_bytes, iv, expected_iv_len);
    }
    
    /* Set up encryption context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create cipher context");
        return 2;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char *)key, 
                          expected_iv_len > 0 ? iv_bytes : NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Failed to initialize encryption");
        return 2;
    }
    
    /* Allocate output buffer */
    int max_out_len = data_len + AES_BLOCK_SIZE;
    unsigned char *out_data = malloc(max_out_len);
    if (!out_data) {
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    /* Encrypt */
    int out_len, final_len;
    if (EVP_EncryptUpdate(ctx, out_data, &out_len, (const unsigned char *)data, data_len) != 1) {
        free(out_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Encryption failed");
        return 2;
    }
    
    if (EVP_EncryptFinal_ex(ctx, out_data + out_len, &final_len) != 1) {
        free(out_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Encryption finalization failed");
        return 2;
    }
    
    out_len += final_len;
    
    /* Return encrypted data as hex string */
    char *hex_data = malloc(out_len * 2 + 1);
    if (!hex_data) {
        free(out_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    bytes_to_hex(out_data, out_len, hex_data);
    lua_pushstring(L, hex_data);
    
    free(out_data);
    free(hex_data);
    EVP_CIPHER_CTX_free(ctx);
    
    return 1;
}

int npe_lua_crypto_aes_decrypt(lua_State *L) {
    size_t data_len, key_len, iv_len = 0;
    const char *hex_data = luaL_checklstring(L, 1, &data_len);
    const char *key = luaL_checklstring(L, 2, &key_len);
    const char *iv = luaL_optlstring(L, 3, NULL, &iv_len);
    const char *mode = luaL_optstring(L, 4, "CBC");
    
    /* Convert hex data to bytes */
    unsigned char *encrypted_data = malloc(data_len / 2);
    if (!encrypted_data) {
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    int encrypted_len = hex_to_bytes(hex_data, encrypted_data, data_len / 2);
    if (encrypted_len < 0) {
        free(encrypted_data);
        lua_pushnil(L);
        lua_pushstring(L, "Invalid hex input");
        return 2;
    }
    
    /* Validate key length */
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        free(encrypted_data);
        lua_pushnil(L);
        lua_pushstring(L, "Invalid key length (must be 16, 24, or 32 bytes)");
        return 2;
    }
    
    /* Determine cipher */
    const EVP_CIPHER *cipher = NULL;
    int expected_iv_len = 0;
    
    if (strcmp(mode, "CBC") == 0) {
        expected_iv_len = 16;
        if (key_len == 16) cipher = EVP_aes_128_cbc();
        else if (key_len == 24) cipher = EVP_aes_192_cbc();
        else if (key_len == 32) cipher = EVP_aes_256_cbc();
    } else if (strcmp(mode, "ECB") == 0) {
        expected_iv_len = 0;
        if (key_len == 16) cipher = EVP_aes_128_ecb();
        else if (key_len == 24) cipher = EVP_aes_192_ecb();
        else if (key_len == 32) cipher = EVP_aes_256_ecb();
    } else {
        free(encrypted_data);
        lua_pushnil(L);
        lua_pushstring(L, "Unsupported mode (use CBC or ECB)");
        return 2;
    }
    
    /* Validate IV */
    unsigned char iv_bytes[16] = {0};
    if (expected_iv_len > 0) {
        if (!iv || iv_len != expected_iv_len) {
            free(encrypted_data);
            lua_pushnil(L);
            lua_pushfstring(L, "IV required and must be %d bytes", expected_iv_len);
            return 2;
        }
        memcpy(iv_bytes, iv, expected_iv_len);
    }
    
    /* Set up decryption context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        lua_pushnil(L);
        lua_pushstring(L, "Failed to create cipher context");
        return 2;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char *)key, 
                          expected_iv_len > 0 ? iv_bytes : NULL) != 1) {
        free(encrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Failed to initialize decryption");
        return 2;
    }
    
    /* Allocate output buffer */
    unsigned char *out_data = malloc(encrypted_len + AES_BLOCK_SIZE);
    if (!out_data) {
        free(encrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Memory allocation failed");
        return 2;
    }
    
    /* Decrypt */
    int out_len, final_len;
    if (EVP_DecryptUpdate(ctx, out_data, &out_len, encrypted_data, encrypted_len) != 1) {
        free(encrypted_data);
        free(out_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Decryption failed");
        return 2;
    }
    
    if (EVP_DecryptFinal_ex(ctx, out_data + out_len, &final_len) != 1) {
        free(encrypted_data);
        free(out_data);
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "Decryption finalization failed");
        return 2;
    }
    
    out_len += final_len;
    
    lua_pushlstring(L, (const char *)out_data, out_len);
    
    free(encrypted_data);
    free(out_data);
    EVP_CIPHER_CTX_free(ctx);
    
    return 1;
}

/* ============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================ */

static const luaL_Reg crypto_functions[] = {
    /* Hashing */
    {"md5",              npe_lua_crypto_md5},
    {"sha1",             npe_lua_crypto_sha1},
    {"sha256",           npe_lua_crypto_sha256},
    {"sha512",           npe_lua_crypto_sha512},
    
    /* HMAC */
    {"hmac_sha256",      npe_lua_crypto_hmac_sha256},
    {"hmac_sha1",        npe_lua_crypto_hmac_sha1},
    
    /* Random */
    {"random_bytes",     npe_lua_crypto_random_bytes},
    
    /* Symmetric encryption */
    {"aes_encrypt",      npe_lua_crypto_aes_encrypt},
    {"aes_decrypt",      npe_lua_crypto_aes_decrypt},
    
    {NULL, NULL}
};

int npe_lib_crypto_register(lua_State *L) {
    /* Create crypto module table */
    luaL_newlib(L, crypto_functions);
    
    /* Add constants */
    lua_pushinteger(L, NPE_CRYPTO_MAX_KEY_LEN);
    lua_setfield(L, -2, "MAX_KEY_LEN");
    
    lua_pushinteger(L, NPE_CRYPTO_MAX_BLOCK_LEN);
    lua_setfield(L, -2, "MAX_BLOCK_LEN");
    
    return 1;
}
