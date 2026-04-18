#define NPE_BCRYPT_STRING_LEN 64

#define NPE_BCRYPT_STRING_LEN 64
/*****************************************************************************
 * npe_lib_hash.h — Cryptographic hashing library
 * ───────────────────────────────────────────────────────────────────────────
 * NPE (NetPeek Extension Engine)
 *
 * Provides cryptographic hash functions for .npe scripts including
 * MD5, SHA-1, SHA-256, SHA-384, SHA-512, and HMAC variants.
 *
 * Features:
 *   • One-shot hashing for strings and binary data
 *   • Incremental/streaming hash computation
 *   • HMAC support for all hash algorithms
 *   • Hex and Base64 output encoding
 *   • File hashing support
 *   • Password hashing utilities (bcrypt, PBKDF2)
 *
 * Lua API:
 *   npe.hash.md5(data)                    → hex string
 *   npe.hash.sha1(data)                   → hex string
 *   npe.hash.sha256(data)                 → hex string
 *   npe.hash.sha384(data)                 → hex string
 *   npe.hash.sha512(data)                 → hex string
 *   npe.hash.hmac(algo, key, data)        → hex string
 *   npe.hash.new(algo)                    → hasher object
 *   npe.hash.pbkdf2(algo, pass, salt, iterations, keylen) → derived key
 *   npe.hash.bcrypt(password, rounds)     → hash string
 *   npe.hash.bcrypt_verify(password, hash) → boolean
 *
 * Thread-safety: All functions are thread-safe. Hash context objects
 *                must not be shared between threads without synchronization.
 *****************************************************************************/

#ifndef NPE_LIB_HASH_H
#define NPE_LIB_HASH_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────────────────── */
typedef struct npe_vm       npe_vm_t;
typedef struct npe_context  npe_context_t;

/* ── Hash algorithm enumeration ──────────────────────────────────────────── */
typedef enum npe_hash_algo {
    NPE_HASH_MD5        = 0,    /* MD5 (128-bit, insecure, legacy only)     */
    NPE_HASH_SHA1       = 1,    /* SHA-1 (160-bit, deprecated)              */
    NPE_HASH_SHA224     = 2,    /* SHA-224 (224-bit)                        */
    NPE_HASH_SHA256     = 3,    /* SHA-256 (256-bit, recommended)           */
    NPE_HASH_SHA384     = 4,    /* SHA-384 (384-bit)                        */
    NPE_HASH_SHA512     = 5,    /* SHA-512 (512-bit)                        */
    NPE_HASH_SHA512_224 = 6,    /* SHA-512/224                              */
    NPE_HASH_SHA512_256 = 7,    /* SHA-512/256                              */
    NPE_HASH_SHA3_224   = 8,    /* SHA3-224                                 */
    NPE_HASH_SHA3_256   = 9,    /* SHA3-256                                 */
    NPE_HASH_SHA3_384   = 10,   /* SHA3-384                                 */
    NPE_HASH_SHA3_512   = 11,   /* SHA3-512                                 */
    NPE_HASH_BLAKE2B    = 12,   /* BLAKE2b (256-bit default)                */
    NPE_HASH_BLAKE2S    = 13,   /* BLAKE2s (256-bit default)                */
    NPE_HASH_CRC32      = 14,   /* CRC32 (non-cryptographic)                */
    NPE_HASH_XXH64      = 15,   /* xxHash64 (non-cryptographic, fast)       */
    NPE_HASH_ALGO_COUNT = 16
} npe_hash_algo_t;

/* ── Hash output format ──────────────────────────────────────────────────── */
typedef enum npe_hash_format {
    NPE_HASH_FMT_RAW    = 0,    /* raw binary bytes                         */
    NPE_HASH_FMT_HEX    = 1,    /* lowercase hexadecimal string             */
    NPE_HASH_FMT_HEX_UC = 2,    /* uppercase hexadecimal string             */
    NPE_HASH_FMT_BASE64 = 3,    /* Base64 encoded                           */
    NPE_HASH_FMT_BASE64_URL = 4 /* URL-safe Base64 encoded                  */
} npe_hash_format_t;

/* ── Opaque hash context ─────────────────────────────────────────────────── */
typedef struct npe_hash_ctx npe_hash_ctx_t;

/* ── Hash digest sizes (in bytes) ────────────────────────────────────────── */
#define NPE_HASH_MD5_SIZE        16
#define NPE_HASH_SHA1_SIZE       20
#define NPE_HASH_SHA224_SIZE     28
#define NPE_HASH_SHA256_SIZE     32
#define NPE_HASH_SHA384_SIZE     48
#define NPE_HASH_SHA512_SIZE     64
#define NPE_HASH_BLAKE2B_SIZE    64
#define NPE_HASH_BLAKE2S_SIZE    32
#define NPE_HASH_CRC32_SIZE      4
#define NPE_HASH_XXH64_SIZE      8
#define NPE_HASH_MAX_SIZE        64   /* maximum digest size                */

/* ── Hash block sizes (in bytes) ─────────────────────────────────────────── */
#define NPE_HASH_MD5_BLOCK       64
#define NPE_HASH_SHA1_BLOCK      64
#define NPE_HASH_SHA256_BLOCK    64
#define NPE_HASH_SHA512_BLOCK    128
#define NPE_HASH_MAX_BLOCK       128

/* ═══════════════════════════════════════════════════════════════════════════
 *  ALGORITHM INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Get algorithm information.
 */
typedef struct npe_hash_algo_info {
    npe_hash_algo_t  algo;           /* algorithm enum value               */
    const char      *name;           /* canonical name (e.g., "sha256")    */
    const char      *description;    /* human-readable description         */
    size_t           digest_size;    /* output size in bytes               */
    size_t           block_size;     /* internal block size in bytes       */
    bool             cryptographic;  /* true if cryptographically secure   */
    bool             deprecated;     /* true if considered weak            */
} npe_hash_algo_info_t;

/**
 * Get information about a hash algorithm.
 *
 * @param algo  the algorithm
 * @param info  receives algorithm information
 * @return NPE_OK on success, NPE_ERROR_INVALID_ARG if unknown algorithm
 */
npe_error_t npe_hash_algo_info(npe_hash_algo_t algo, npe_hash_algo_info_t *info);

/**
 * Get algorithm by name.
 *
 * @param name  algorithm name (case-insensitive)
 * @param algo  receives algorithm enum
 * @return NPE_OK on success, NPE_ERROR_NOT_FOUND if unknown name
 */
npe_error_t npe_hash_algo_by_name(const char *name, npe_hash_algo_t *algo);

/**
 * Get digest size for an algorithm.
 *
 * @param algo  the algorithm
 * @return digest size in bytes, or 0 if invalid algorithm
 */
size_t npe_hash_digest_size(npe_hash_algo_t algo);

/**
 * Get list of all supported algorithm names.
 * Returns NULL-terminated array of strings. Do not free.
 */
const char **npe_hash_algo_list(size_t *count);

/* ═══════════════════════════════════════════════════════════════════════════
 *  ONE-SHOT HASHING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Compute hash of data in a single call.
 *
 * @param algo      hash algorithm to use
 * @param data      input data
 * @param data_len  input data length
 * @param digest    output buffer (must be at least digest_size bytes)
 * @param digest_len receives actual digest length
 * @return NPE_OK on success
 */
npe_error_t npe_hash(npe_hash_algo_t  algo,
                     const void      *data,
                     size_t           data_len,
                     void            *digest,
                     size_t          *digest_len);

/**
 * Compute hash and return as formatted string.
 *
 * @param algo      hash algorithm to use
 * @param data      input data
 * @param data_len  input data length
 * @param format    output format (hex, base64, etc.)
 * @param output    receives heap-allocated output string
 * @param out_len   receives output length (excluding NUL)
 * @return NPE_OK on success
 *
 * Caller must free *output.
 */
npe_error_t npe_hash_string(npe_hash_algo_t   algo,
                            const void       *data,
                            size_t            data_len,
                            npe_hash_format_t format,
                            char            **output,
                            size_t           *out_len);

/**
 * Convenience macros for common hash algorithms.
 */
#define npe_md5(data, len, digest, dlen)    npe_hash(NPE_HASH_MD5, data, len, digest, dlen)
#define npe_sha1(data, len, digest, dlen)   npe_hash(NPE_HASH_SHA1, data, len, digest, dlen)
#define npe_sha256(data, len, digest, dlen) npe_hash(NPE_HASH_SHA256, data, len, digest, dlen)
#define npe_sha512(data, len, digest, dlen) npe_hash(NPE_HASH_SHA512, data, len, digest, dlen)

/* ═══════════════════════════════════════════════════════════════════════════
 *  INCREMENTAL (STREAMING) HASHING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Create a new hash context for incremental hashing.
 *
 * @param algo  hash algorithm to use
 * @param ctx   receives new context
 * @return NPE_OK on success
 */
npe_error_t npe_hash_ctx_create(npe_hash_algo_t algo, npe_hash_ctx_t **ctx);

/**
 * Reset a hash context to initial state (reuse without reallocating).
 *
 * @param ctx  hash context
 * @return NPE_OK on success
 */
npe_error_t npe_hash_ctx_reset(npe_hash_ctx_t *ctx);

/**
 * Clone a hash context (for computing intermediate digests).
 *
 * @param src   source context
 * @param dest  receives cloned context
 * @return NPE_OK on success
 */
npe_error_t npe_hash_ctx_clone(const npe_hash_ctx_t *src, npe_hash_ctx_t **dest);

/**
 * Feed data into the hash context.
 *
 * @param ctx       hash context
 * @param data      input data
 * @param data_len  input data length
 * @return NPE_OK on success
 */
npe_error_t npe_hash_ctx_update(npe_hash_ctx_t *ctx,
                                const void     *data,
                                size_t          data_len);

/**
 * Finalize and retrieve the digest.
 * After calling this, the context is reset and can be reused.
 *
 * @param ctx        hash context
 * @param digest     output buffer (must be at least digest_size bytes)
 * @param digest_len receives actual digest length
 * @return NPE_OK on success
 */
npe_error_t npe_hash_ctx_final(npe_hash_ctx_t *ctx,
                               void           *digest,
                               size_t         *digest_len);

/**
 * Finalize and return formatted string.
 *
 * @param ctx     hash context
 * @param format  output format
 * @param output  receives heap-allocated string
 * @param out_len receives string length
 * @return NPE_OK on success
 */
npe_error_t npe_hash_ctx_final_string(npe_hash_ctx_t   *ctx,
                                      npe_hash_format_t format,
                                      char            **output,
                                      size_t           *out_len);

/**
 * Destroy a hash context and free resources.
 *
 * @param ctx  hash context (may be NULL)
 */
void npe_hash_ctx_destroy(npe_hash_ctx_t *ctx);

/**
 * Get the algorithm used by a context.
 */
npe_hash_algo_t npe_hash_ctx_algo(const npe_hash_ctx_t *ctx);

/**
 * Get bytes processed so far.
 */
uint64_t npe_hash_ctx_bytes_processed(const npe_hash_ctx_t *ctx);

/* ═══════════════════════════════════════════════════════════════════════════
 *  HMAC (Hash-based Message Authentication Code)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Opaque HMAC context.
 */
typedef struct npe_hmac_ctx npe_hmac_ctx_t;

/**
 * Compute HMAC in a single call.
 *
 * @param algo       hash algorithm
 * @param key        secret key
 * @param key_len    key length
 * @param data       message data
 * @param data_len   message length
 * @param mac        output buffer (must be at least digest_size bytes)
 * @param mac_len    receives actual MAC length
 * @return NPE_OK on success
 */
npe_error_t npe_hmac(npe_hash_algo_t  algo,
                     const void      *key,
                     size_t           key_len,
                     const void      *data,
                     size_t           data_len,
                     void            *mac,
                     size_t          *mac_len);

/**
 * Compute HMAC and return as formatted string.
 */
npe_error_t npe_hmac_string(npe_hash_algo_t   algo,
                            const void       *key,
                            size_t            key_len,
                            const void       *data,
                            size_t            data_len,
                            npe_hash_format_t format,
                            char            **output,
                            size_t           *out_len);

/**
 * Create HMAC context for incremental computation.
 *
 * @param algo     hash algorithm
 * @param key      secret key
 * @param key_len  key length
 * @param ctx      receives new context
 * @return NPE_OK on success
 */
npe_error_t npe_hmac_ctx_create(npe_hash_algo_t  algo,
                                const void      *key,
                                size_t           key_len,
                                npe_hmac_ctx_t **ctx);

/**
 * Reset HMAC context with new key.
 */
npe_error_t npe_hmac_ctx_reset(npe_hmac_ctx_t *ctx,
                               const void     *key,
                               size_t          key_len);

/**
 * Feed data into HMAC context.
 */
npe_error_t npe_hmac_ctx_update(npe_hmac_ctx_t *ctx,
                                const void     *data,
                                size_t          data_len);

/**
 * Finalize HMAC computation.
 */
npe_error_t npe_hmac_ctx_final(npe_hmac_ctx_t *ctx,
                               void           *mac,
                               size_t         *mac_len);

/**
 * Finalize HMAC and return formatted string.
 */
npe_error_t npe_hmac_ctx_final_string(npe_hmac_ctx_t   *ctx,
                                      npe_hash_format_t format,
                                      char            **output,
                                      size_t           *out_len);

/**
 * Destroy HMAC context.
 */
void npe_hmac_ctx_destroy(npe_hmac_ctx_t *ctx);

/* ═══════════════════════════════════════════════════════════════════════════
 *  PASSWORD HASHING (PBKDF2, bcrypt, scrypt)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * PBKDF2 key derivation.
 *
 * @param algo        hash algorithm for PRF
 * @param password    password string
 * @param pass_len    password length
 * @param salt        salt bytes
 * @param salt_len    salt length
 * @param iterations  iteration count (recommend >= 100000)
 * @param key_len     desired output key length
 * @param key         output buffer
 * @return NPE_OK on success
 */

npe_error_t npe_pbkdf2(
    npe_hash_algo_t  algo,
    const void      *password,
    size_t           password_len,
    const void      *salt,
    size_t           salt_len,
    uint32_t         iterations,
    void            *derived_key,
    size_t           derived_key_len
);


/**
 * PBKDF2 with formatted output.
 */
npe_error_t npe_pbkdf2_string(npe_hash_algo_t   algo,
                              const void       *password,
                              size_t            pass_len,
                              const void       *salt,
                              size_t            salt_len,
                              uint32_t          iterations,
                              size_t            key_len,
                              npe_hash_format_t format,
                              char            **output,
                              size_t           *out_len);

/**
 * bcrypt password hashing.
 *
 * @param password  password string (NUL-terminated)
 * @param rounds    cost factor (4-31, recommend 12)
 * @param hash      output buffer (must be at least 61 bytes)
 * @return NPE_OK on success
 *
 * Output format: $2b$rounds$salt+hash (standard bcrypt format)
 */


npe_error_t npe_bcrypt_hash(const void *password,
                            size_t      password_len,
                            uint32_t    work_factor,
                            char       *output,
                            size_t      output_size);



/**
 * Verify password against bcrypt hash.
 *
 * @param password  password to verify
 * @param hash      bcrypt hash string
 * @param match     receives true if password matches
 * @return NPE_OK on success
 */


npe_error_t npe_bcrypt_verify(const void *password,
                              size_t      password_len,
                              const char *hash_string,
                              bool       *match);



/**
 * scrypt key derivation (memory-hard).
 *
 * @param password  password
 * @param pass_len  password length
 * @param salt      salt
 * @param salt_len  salt length
 * @param N         CPU/memory cost (power of 2, e.g., 16384)
 * @param r         block size (e.g., 8)
 * @param p         parallelization (e.g., 1)
 * @param key_len   output key length
 * @param key       output buffer
 * @return NPE_OK on success
 */

npe_error_t npe_scrypt(const void *password,
                       size_t      password_len,
                       const void *salt,
                       size_t      salt_len,
                       uint64_t    N,
                       uint32_t    r,
                       uint32_t    p,
                       void       *derived_key,
                       size_t      derived_key_len);


/* ═══════════════════════════════════════════════════════════════════════════
 *  FILE HASHING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Compute hash of a file.
 *
 * @param algo      hash algorithm
 * @param path      file path
 * @param digest    output buffer
 * @param digest_len receives digest length
 * @return NPE_OK on success
 */
npe_error_t npe_hash_file(npe_hash_algo_t  algo,
                          const char      *path,
                          void            *digest,
                          size_t          *digest_len);

/**
 * Compute hash of file and return formatted string.
 */
npe_error_t npe_hash_file_string(npe_hash_algo_t   algo,
                                 const char       *path,
                                 npe_hash_format_t format,
                                 char            **output,
                                 size_t           *out_len);

/* ═══════════════════════════════════════════════════════════════════════════
 *  UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Compare two digests in constant time (timing-attack resistant).
 *
 * @param a      first digest
 * @param b      second digest
 * @param len    length to compare
 * @return true if equal
 */
bool npe_hash_compare(const void *a, const void *b, size_t len);

/**
 * Format binary digest to string.
 *
 * @param digest    binary digest
 * @param digest_len digest length
 * @param format    output format
 * @param output    receives heap-allocated string
 * @param out_len   receives string length
 * @return NPE_OK on success
 */
npe_error_t npe_hash_format(const void       *digest,
                            size_t            digest_len,
                            npe_hash_format_t format,
                            char            **output,
                            size_t           *out_len);

/**
 * Parse formatted hash string back to binary.
 *
 * @param input     formatted string
 * @param format    input format
 * @param digest    output buffer
 * @param digest_len receives digest length
 * @return NPE_OK on success
 */
npe_error_t npe_hash_parse(const char       *input,
                           npe_hash_format_t format,
                           void             *digest,
                           size_t           *digest_len);

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATISTICS & DIAGNOSTICS
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Hash operation statistics.
 */
typedef struct npe_hash_stats {
    uint64_t total_hashes;       /* total hash operations                */
    uint64_t total_bytes;        /* total bytes hashed                   */
    uint64_t total_time_us;      /* total time in microseconds           */
    uint64_t hmac_operations;    /* HMAC operations                      */
    uint64_t pbkdf2_operations;  /* PBKDF2 operations                    */
    uint64_t bcrypt_operations;  /* bcrypt operations                    */
    uint64_t file_hashes;        /* file hash operations                 */
} npe_hash_stats_t;

/**
 * Get global hash statistics.
 */

npe_hash_stats_t npe_hash_get_stats(void);


/**
 * Reset global hash statistics.
 */
void npe_hash_reset_stats(void);

/**
 * Benchmark a hash algorithm.
 *
 * @param algo       algorithm to benchmark
 * @param data_size  test data size in bytes
 * @param iterations number of iterations
 * @param mbps       receives throughput in MB/s
 * @return NPE_OK on success
 */
npe_error_t npe_hash_benchmark(npe_hash_algo_t algo,
                               size_t          data_size,
                               uint32_t        iterations,
                               double         *mbps);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LUA BINDING
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Register hash library with Lua VM.
 *
 * Creates the 'npe.hash' table with all hash functions.
 *
 * @param vm  Lua VM instance
 * @return NPE_OK on success
 */
npe_error_t npe_hash_register(npe_vm_t *vm);

/**
 * Push a hash context as Lua userdata.
 * Used internally by Lua bindings.
 */
npe_error_t npe_hash_ctx_push_lua(npe_vm_t *vm, npe_hash_ctx_t *ctx);

/**
 * Get hash context from Lua stack.
 * Used internally by Lua bindings.
 */
npe_error_t npe_hash_ctx_from_lua(npe_vm_t *vm, int index, npe_hash_ctx_t **ctx);

#ifdef __cplusplus
}
#endif

#endif /* NPE_LIB_HASH_H */
