/* brisk_int.h - internal declarations shared by the library sources. Not installed.
 * Internal symbols use the brisk__ prefix and are never part of the ABI.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef BRISK_INT_H
#define BRISK_INT_H

#include <string.h>

#include "brisk.h"

/* ---- byte order: explicit, alignment-free loads/stores (safe on MIPS/ARMv5, any endianness) ----
 */
static inline uint32_t brisk__load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline uint64_t brisk__load_be64(const uint8_t *p)
{
    return ((uint64_t)brisk__load_be32(p) << 32) | brisk__load_be32(p + 4);
}

static inline void brisk__store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void brisk__store_be64(uint8_t *p, uint64_t v)
{
    brisk__store_be32(p, (uint32_t)(v >> 32));
    brisk__store_be32(p + 4, (uint32_t)v);
}

/* ---- util.c ---- */
/* 1 if the n bytes at a and b are equal, else 0. Time depends only on n. */
int brisk__ct_memeq(const void *a, const void *b, size_t n);
/* memset(p, 0, n) that the optimizer cannot drop. Use for every key, secret and scratch buffer. */
void brisk__secure_zero(void *p, size_t n);

/* ---- crypto/sha2.c: generic dispatch over brisk_hash_alg ---- */
size_t brisk__hash_block_len(brisk_hash_alg alg);
void brisk__hash_init(brisk_hash_ctx *c, brisk_hash_alg alg); /* alg must be valid */
void brisk__hash_update(brisk_hash_ctx *c, brisk_hash_alg alg, const void *data, size_t len);
void brisk__hash_final(brisk_hash_ctx *c, brisk_hash_alg alg, uint8_t *out);

/* ---- crypto/hkdf.c: HKDF (RFC 5869) and TLS 1.3 HKDF-Expand-Label (RFC 9846 7.1) ---- */
/* prk receives brisk_hash_len(alg) bytes. An empty salt means HashLen zero bytes (RFC 5869 2.2). */
int brisk__hkdf_extract(brisk_hash_alg alg, const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
/* BRISK_E_ARG if out_len > 255 * HashLen. `out` may alias `prk`, but must not overlap `info`. */
int brisk__hkdf_expand(brisk_hash_alg alg, const uint8_t *prk, size_t prk_len, const uint8_t *info,
                       size_t info_len, uint8_t *out, size_t out_len);
/* HKDF-Expand(secret, HkdfLabel{out_len, "tls13 " + label, context}, out_len). `label` is the
 * bare label ("derived", "c hs traffic", "quic key", ...). Also used by QUIC (RFC 9001 5.1). */
int brisk__hkdf_expand_label(brisk_hash_alg alg, const uint8_t *secret, size_t secret_len,
                             const char *label, const uint8_t *context, size_t context_len,
                             uint8_t *out, size_t out_len);

/* ---- os/linux_rand.c (Linux builds only): the only randomness source, no userspace DRBG ---- */
/* len bytes from the kernel CSPRNG: getrandom(2), which blocks until the pool is initialised.
 * Only on kernels older than 4.8 that lack it (ENOSYS) or filter it (EPERM): wait once for
 * /dev/random to be readable, then read /dev/urandom. BRISK_E_RNG otherwise: abort, never use
 * the buffer. */
int brisk__os_random(uint8_t *out, size_t len);
/* The two sources on their own, for tests. brisk__os_getrandom returns BRISK__RAND_FALLBACK on
 * ENOSYS/EPERM; brisk__os_urandom (the waited-for /dev/urandom) never checks the kernel version. */
#define BRISK__RAND_FALLBACK 1
int brisk__os_getrandom(uint8_t *out, size_t len);
int brisk__os_urandom(uint8_t *out, size_t len);

#endif /* BRISK_INT_H */
