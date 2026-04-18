/*****************************************************************************
 * npe_lib_hash.c — Core cryptographic hash functions
 *****************************************************************************/

#include "npe_lib_hash.h"
#include "npe_types.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>

/* ============================================================================
 * Atomics
 * ========================================================================== */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#define ATOMIC_INC(x, v)  atomic_fetch_add(&(x), (v))
#define ATOMIC_LOAD(x)    atomic_load(&(x))
#define ATOMIC_STORE(x,v) atomic_store(&(x),(v))
typedef _Atomic uint64_t atomic_u64;
#else
#define ATOMIC_INC(x, v)  ((x) += (v))
#define ATOMIC_LOAD(x)    (x)
#define ATOMIC_STORE(x,v) ((x) = (v))
typedef uint64_t atomic_u64;
#endif

/* ============================================================================
 * Global statistics
 * ========================================================================== */

static struct {
    atomic_u64 total_hashes;
    atomic_u64 total_bytes;
    atomic_u64 total_time_us;
    atomic_u64 hmac_operations;
    atomic_u64 file_hashes;
} g_hash_stats;

/* ============================================================================
 * Time helper
 * ========================================================================== */

static uint64_t
now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/* ============================================================================
 * Algorithm metadata
 * ========================================================================== */

typedef struct {
    npe_hash_algo_t algo;
    const char     *name;
    size_t          digest_size;
    const EVP_MD *(*evp_md)(void);
} algo_entry_t;

static const algo_entry_t algos[] = {
    { NPE_HASH_MD5,        "md5",        16, EVP_md5        },
    { NPE_HASH_SHA1,       "sha1",       20, EVP_sha1       },
    { NPE_HASH_SHA224,     "sha224",     28, EVP_sha224     },
    { NPE_HASH_SHA256,     "sha256",     32, EVP_sha256     },
    { NPE_HASH_SHA384,     "sha384",     48, EVP_sha384     },
    { NPE_HASH_SHA512,     "sha512",     64, EVP_sha512     },
    { NPE_HASH_SHA512_224, "sha512-224", 28, EVP_sha512_224 },
    { NPE_HASH_SHA512_256, "sha512-256", 32, EVP_sha512_256 },
    { NPE_HASH_SHA3_224,   "sha3-224",   28, EVP_sha3_224   },
    { NPE_HASH_SHA3_256,   "sha3-256",   32, EVP_sha3_256   },
    { NPE_HASH_SHA3_384,   "sha3-384",   48, EVP_sha3_384   },
    { NPE_HASH_SHA3_512,   "sha3-512",   64, EVP_sha3_512   },
};

static const algo_entry_t *
algo_lookup(npe_hash_algo_t algo)
{
    for (size_t i = 0; i < sizeof(algos)/sizeof(algos[0]); i++) {
        if (algos[i].algo == algo)
            return &algos[i];
    }
    return NULL;
}

/* ============================================================================
 * One‑shot hashing
 * ========================================================================== */

npe_error_t
npe_hash(npe_hash_algo_t  algo,
         const void      *data,
         size_t           data_len,
         void            *digest,
         size_t          *digest_len)
{
    if (!data || !digest || !digest_len)
        return NPE_ERROR_INVALID_ARG;

    const algo_entry_t *e = algo_lookup(algo);
    if (!e || !e->evp_md)
        return NPE_ERROR_INVALID_ARG;

    uint64_t t0 = now_us();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return NPE_ERROR_MEMORY;

    unsigned int outlen = 0;
    int ok =
        EVP_DigestInit_ex(ctx, e->evp_md(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, data_len) == 1 &&
        EVP_DigestFinal_ex(ctx, (unsigned char *)digest, &outlen) == 1;

    EVP_MD_CTX_free(ctx);

    if (!ok)
        return NPE_ERROR_GENERIC;

    *digest_len = outlen;

    ATOMIC_INC(g_hash_stats.total_hashes, 1);
    ATOMIC_INC(g_hash_stats.total_bytes, data_len);
    ATOMIC_INC(g_hash_stats.total_time_us, now_us() - t0);

    return NPE_OK;
}

/* ============================================================================
 * Hash contexts (streaming)
 * ========================================================================== */

struct npe_hash_ctx {
    npe_hash_algo_t algo;
    EVP_MD_CTX     *ctx;
    uint64_t        bytes;
};

npe_error_t
npe_hash_ctx_create(npe_hash_algo_t algo, npe_hash_ctx_t **out)
{
    if (!out)
        return NPE_ERROR_INVALID_ARG;

    const algo_entry_t *e = algo_lookup(algo);
    if (!e || !e->evp_md)
        return NPE_ERROR_INVALID_ARG;

    npe_hash_ctx_t *h = calloc(1, sizeof(*h));
    if (!h)
        return NPE_ERROR_MEMORY;

    h->ctx = EVP_MD_CTX_new();
    if (!h->ctx) {
        free(h);
        return NPE_ERROR_MEMORY;
    }

    if (EVP_DigestInit_ex(h->ctx, e->evp_md(), NULL) != 1) {
        EVP_MD_CTX_free(h->ctx);
        free(h);
        return NPE_ERROR_GENERIC;
    }

    h->algo = algo;
    *out = h;
    return NPE_OK;
}

npe_error_t
npe_hash_ctx_update(npe_hash_ctx_t *ctx, const void *data, size_t len)
{
    if (!ctx || (!data && len))
        return NPE_ERROR_INVALID_ARG;

    if (len == 0)
        return NPE_OK;

    if (EVP_DigestUpdate(ctx->ctx, data, len) != 1)
        return NPE_ERROR_GENERIC;

    ctx->bytes += len;
    return NPE_OK;
}

npe_error_t
npe_hash_ctx_final(npe_hash_ctx_t *ctx, void *digest, size_t *digest_len)
{
    if (!ctx || !digest || !digest_len)
        return NPE_ERROR_INVALID_ARG;

    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(ctx->ctx, (unsigned char *)digest, &outlen) != 1)
        return NPE_ERROR_GENERIC;

    *digest_len = outlen;
    return NPE_OK;
}

void
npe_hash_ctx_destroy(npe_hash_ctx_t *ctx)
{
    if (!ctx)
        return;
    EVP_MD_CTX_free(ctx->ctx);
    free(ctx);
}

/* ============================================================================
 * HMAC
 * ========================================================================== */

npe_error_t
npe_hmac(npe_hash_algo_t  algo,
         const void      *key,
         size_t           key_len,
         const void      *data,
         size_t           data_len,
         void            *mac,
         size_t          *mac_len)
{
    if (!key || !data || !mac || !mac_len)
        return NPE_ERROR_INVALID_ARG;

    const algo_entry_t *e = algo_lookup(algo);
    if (!e || !e->evp_md)
        return NPE_ERROR_INVALID_ARG;

    uint64_t t0 = now_us();

    unsigned int outlen = 0;
    unsigned char *res = HMAC(
        e->evp_md(),
        key, (int)key_len,
        data, data_len,
        mac, &outlen
    );

    if (!res)
        return NPE_ERROR_GENERIC;

    *mac_len = outlen;

    ATOMIC_INC(g_hash_stats.hmac_operations, 1);
    ATOMIC_INC(g_hash_stats.total_bytes, data_len);
    ATOMIC_INC(g_hash_stats.total_time_us, now_us() - t0);

    return NPE_OK;
}

/* ============================================================================
 * Statistics
 * ========================================================================== */

npe_hash_stats_t
npe_hash_get_stats(void)
{
    npe_hash_stats_t s;
    s.total_hashes    = ATOMIC_LOAD(g_hash_stats.total_hashes);
    s.total_bytes     = ATOMIC_LOAD(g_hash_stats.total_bytes);
    s.total_time_us   = ATOMIC_LOAD(g_hash_stats.total_time_us);
    s.hmac_operations = ATOMIC_LOAD(g_hash_stats.hmac_operations);
    s.file_hashes     = ATOMIC_LOAD(g_hash_stats.file_hashes);
    s.pbkdf2_operations = 0;
    s.bcrypt_operations = 0;
    return s;
}

void
npe_hash_reset_stats(void)
{
    ATOMIC_STORE(g_hash_stats.total_hashes, 0);
    ATOMIC_STORE(g_hash_stats.total_bytes, 0);
    ATOMIC_STORE(g_hash_stats.total_time_us, 0);
    ATOMIC_STORE(g_hash_stats.hmac_operations, 0);
    ATOMIC_STORE(g_hash_stats.file_hashes, 0);
}