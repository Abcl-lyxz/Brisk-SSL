/* brisk.h - Brisk-SSL public API. Zero-dependency C99 TLS/QUIC client library for Linux IoT.
 *
 * This header is the API reference. Everything not declared here is internal and may change.
 * Contexts are plain structs owned by the caller: the library never allocates behind your back
 * and keeps no global state, so separate contexts may be used from separate threads.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef BRISK_H
#define BRISK_H

#include <stddef.h>
#include <stdint.h>

#include "brisk_config.h"

#define BRISK_SSL_VERSION_MAJOR  0
#define BRISK_SSL_VERSION_MINOR  1
#define BRISK_SSL_VERSION_PATCH  0
#define BRISK_SSL_VERSION_STRING "0.1.0-dev"

/* Symbol export: only a shared-library build (BRISK_SHARED_BUILD) exports the API. In a static
 * build it stays empty so a .so that embeds libbrisk.a keeps its own visibility policy.
 * Define BRISK_API yourself to override. */
#ifndef BRISK_API
#    if defined(BRISK_SHARED_BUILD) && defined(__GNUC__) && __GNUC__ >= 4
#        define BRISK_API __attribute__((visibility("default")))
#    else
#        define BRISK_API
#    endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------------------------------
 * Errors: functions return BRISK_OK (0) or a negative code.
 */
enum {
    BRISK_OK = 0,
    BRISK_E_ARG = -1, /* invalid argument: unknown algorithm, length out of range, ... */
    BRISK_E_RNG = -2, /* kernel randomness unavailable; seccomp filters must allow getrandom */
    BRISK_E_AUTH = -3 /* AEAD authentication failed (TLS bad_record_mac); no plaintext released */
};

/* Library version, e.g. "0.1.0-dev". */
BRISK_API const char *brisk_version(void);

/* What this binary was compiled with, e.g. "0.1.0-dev profile=DEFAULT". The same text is embedded
 * as "@(#)BRISKCFG ..." so `strings firmware.bin | grep BRISKCFG` works on a shipped image. */
BRISK_API const char *brisk_build_info(void);

/* ------------------------------------------------------------------------------------------------
 * Hashes: SHA-256, SHA-384, SHA-512 (FIPS 180-4).
 *
 * Streaming: *_init, then *_update any number of times with any lengths, then *_final, which
 * writes the digest and wipes the context. One-shot helpers do all three.
 */
#define BRISK_SHA256_LEN   32
#define BRISK_SHA384_LEN   48
#define BRISK_SHA512_LEN   64
#define BRISK_HASH_MAX_LEN 64

typedef struct {
    uint32_t h[8];
    uint64_t len; /* bytes hashed so far */
    uint8_t buf[64];
} brisk_sha256_ctx;

typedef struct {
    uint64_t h[8];
    uint64_t len; /* bytes hashed so far (messages must be < 2^61 bytes) */
    uint8_t buf[128];
} brisk_sha512_ctx;

typedef brisk_sha512_ctx brisk_sha384_ctx; /* SHA-384 is SHA-512 with other IVs, truncated */

BRISK_API void brisk_sha256_init(brisk_sha256_ctx *c);
BRISK_API void brisk_sha256_update(brisk_sha256_ctx *c, const void *data, size_t len);
BRISK_API void brisk_sha256_final(brisk_sha256_ctx *c, uint8_t out[BRISK_SHA256_LEN]);
BRISK_API void brisk_sha256(const void *data, size_t len, uint8_t out[BRISK_SHA256_LEN]);

BRISK_API void brisk_sha384_init(brisk_sha384_ctx *c);
BRISK_API void brisk_sha384_update(brisk_sha384_ctx *c, const void *data, size_t len);
BRISK_API void brisk_sha384_final(brisk_sha384_ctx *c, uint8_t out[BRISK_SHA384_LEN]);
BRISK_API void brisk_sha384(const void *data, size_t len, uint8_t out[BRISK_SHA384_LEN]);

BRISK_API void brisk_sha512_init(brisk_sha512_ctx *c);
BRISK_API void brisk_sha512_update(brisk_sha512_ctx *c, const void *data, size_t len);
BRISK_API void brisk_sha512_final(brisk_sha512_ctx *c, uint8_t out[BRISK_SHA512_LEN]);
BRISK_API void brisk_sha512(const void *data, size_t len, uint8_t out[BRISK_SHA512_LEN]);

/* ------------------------------------------------------------------------------------------------
 * HMAC (RFC 2104) over SHA-256/384/512. Useful on its own for cloud auth tokens
 * (e.g. Azure IoT SAS tokens, AWS SigV4).
 */
typedef enum { BRISK_HASH_SHA256 = 1, BRISK_HASH_SHA384 = 2, BRISK_HASH_SHA512 = 3 } brisk_hash_alg;

/* Digest length in bytes of `alg`, or 0 if `alg` is not a valid brisk_hash_alg. */
BRISK_API size_t brisk_hash_len(brisk_hash_alg alg);

typedef union {
    brisk_sha256_ctx sha256;
    brisk_sha512_ctx sha512;
} brisk_hash_ctx;

typedef struct {
    brisk_hash_ctx inner, outer; /* keyed states */
    int alg;
} brisk_hmac_ctx;

/* Returns BRISK_OK, or BRISK_E_ARG for an unknown algorithm. The key may be any length. */
BRISK_API int brisk_hmac_init(brisk_hmac_ctx *c, brisk_hash_alg alg, const void *key,
                              size_t key_len);
BRISK_API void brisk_hmac_update(brisk_hmac_ctx *c, const void *data, size_t len);
/* Writes brisk_hash_len(alg) bytes and wipes the context. */
BRISK_API void brisk_hmac_final(brisk_hmac_ctx *c, uint8_t *out);
BRISK_API int brisk_hmac(brisk_hash_alg alg, const void *key, size_t key_len, const void *data,
                         size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BRISK_H */
