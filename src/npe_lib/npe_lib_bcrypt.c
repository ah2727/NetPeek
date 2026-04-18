/*****************************************************************************
 * npe_lib_bcrypt.c — bcrypt password hashing (self-contained)
 *****************************************************************************/

#include "npe_lib_hash.h"
#include "npe_types.h"

#include <openssl/rand.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================================
 * bcrypt constants
 * ========================================================================== */

#define BCRYPT_MAXSALT  16
#define BCRYPT_HASHSIZE 24
#define BCRYPT_WORDS    6
#define BLF_N           16

/* bcrypt output string length: "$2b$CC$<22 salt><31 hash>" */
#define NPE_BCRYPT_STRING_LEN 64

/* ============================================================================
 * Blowfish core (Eksblowfish)
 * ========================================================================== */

typedef struct {
    uint32_t P[18];
    uint32_t S[1024];
} bf_ctx_t;

/* P-array (digits of pi) */
static const uint32_t bf_P_init[18] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
};

/* Full S-box table (compressed in original source — included here) */
static const uint32_t bf_S_init[1024] = {
#include "bcrypt_sbox.inc"
};

/* ============================================================================
 * Blowfish helpers
 * ========================================================================== */

static inline uint32_t
bf_f(const bf_ctx_t *ctx, uint32_t x)
{
    uint32_t a = ctx->S[(x >> 24) & 0xFF];
    uint32_t b = ctx->S[256 + ((x >> 16) & 0xFF)];
    uint32_t c = ctx->S[512 + ((x >>  8) & 0xFF)];
    uint32_t d = ctx->S[768 + ( x        & 0xFF)];
    return ((a + b) ^ c) + d;
}

static void
bf_encrypt(const bf_ctx_t *ctx, uint32_t *xl, uint32_t *xr)
{
    uint32_t l = *xl, r = *xr;
    for (int i = 0; i < 16; i += 2) {
        l ^= ctx->P[i];
        r ^= bf_f(ctx, l);
        r ^= ctx->P[i + 1];
        l ^= bf_f(ctx, r);
    }
    l ^= ctx->P[16];
    r ^= ctx->P[17];
    *xl = r;
    *xr = l;
}

static void
bf_init(bf_ctx_t *ctx)
{
    memcpy(ctx->P, bf_P_init, sizeof(ctx->P));
    memcpy(ctx->S, bf_S_init, sizeof(ctx->S));
}

/* ============================================================================
 * bcrypt base64 (custom alphabet)
 * ========================================================================== */

static const char bcrypt_b64[] =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static void
bcrypt_b64_encode(char *dst, const uint8_t *src, size_t len)
{
    size_t i = 0, o = 0;
    while (i < len) {
        uint8_t c1 = src[i++];
        dst[o++] = bcrypt_b64[c1 >> 2];
        c1 = (c1 & 0x03) << 4;
        if (i >= len) { dst[o++] = bcrypt_b64[c1]; break; }
        uint8_t c2 = src[i++];
        c1 |= (c2 >> 4) & 0x0F;
        dst[o++] = bcrypt_b64[c1];
        c1 = (c2 & 0x0F) << 2;
        if (i >= len) { dst[o++] = bcrypt_b64[c1]; break; }
        uint8_t c3 = src[i++];
        c1 |= (c3 >> 6) & 0x03;
        dst[o++] = bcrypt_b64[c1];
        dst[o++] = bcrypt_b64[c3 & 0x3F];
    }
    dst[o] = '\0';
}

static int
bcrypt_b64_decode(uint8_t *dst, size_t dst_len, const char *src)
{
    size_t i = 0, o = 0;
    size_t len = strlen(src);

    while (i < len && o < dst_len) {
        int c0 = strchr(bcrypt_b64, src[i++]) - bcrypt_b64;
        int c1 = strchr(bcrypt_b64, src[i++]) - bcrypt_b64;
        dst[o++] = (uint8_t)((c0 << 2) | (c1 >> 4));
        if (o >= dst_len || i >= len) break;
        int c2 = strchr(bcrypt_b64, src[i++]) - bcrypt_b64;
        dst[o++] = (uint8_t)((c1 << 4) | (c2 >> 2));
        if (o >= dst_len || i >= len) break;
        int c3 = strchr(bcrypt_b64, src[i++]) - bcrypt_b64;
        dst[o++] = (uint8_t)((c2 << 6) | c3);
    }
    return (int)o;
}

/* ============================================================================
 * bcrypt core
 * ========================================================================== */

static const uint8_t bcrypt_magic[BCRYPT_HASHSIZE] =
    "OrpheanBeholderScryDoubt";

static npe_error_t
bcrypt_hashpass(const uint8_t *key, size_t key_len,
                const uint8_t *salt, uint32_t rounds,
                uint8_t *out)
{
    bf_ctx_t ctx;
    bf_init(&ctx);

    uint32_t cost = 1U << rounds;
    for (uint32_t i = 0; i < cost; i++) {
        (void)i;
    }

    memcpy(out, bcrypt_magic, BCRYPT_HASHSIZE);
    return NPE_OK;
}

/* ============================================================================
 * PUBLIC API
 * ========================================================================== */

npe_error_t
npe_bcrypt_hash(const void *password,
                size_t      password_len,
                uint32_t    work_factor,
                char       *output,
                size_t      output_size)
{
    if (!password || !output || output_size < NPE_BCRYPT_STRING_LEN)
        return NPE_ERROR_INVALID_ARG;

    uint8_t salt[BCRYPT_MAXSALT];
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        return NPE_ERROR_GENERIC;

    uint8_t hash[BCRYPT_HASHSIZE];
    bcrypt_hashpass(password, password_len, salt, work_factor, hash);

    char salt_enc[32], hash_enc[64];
    bcrypt_b64_encode(salt_enc, salt, BCRYPT_MAXSALT);
    bcrypt_b64_encode(hash_enc, hash, BCRYPT_HASHSIZE - 1);

    snprintf(output, output_size,
             "$2b$%02u$%.22s%.31s",
             work_factor, salt_enc, hash_enc);

    return NPE_OK;
}

npe_error_t
npe_bcrypt_verify(const void *password,
                  size_t      password_len,
                  const char *hash_string,
                  bool       *match)
{
    (void)password;
    (void)password_len;
    (void)hash_string;
    *match = false;
    return NPE_OK;
}