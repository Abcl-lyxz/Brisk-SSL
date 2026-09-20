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

static inline uint32_t brisk__load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void brisk__store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* ---- constant-time checking (`python tools/dev.py ct`) ----
 * With -DBRISK_CT_CHECK the test suite hands valgrind's memcheck the secrets marked as
 * "undefined", so every branch, memory index or division whose result depends on one is reported
 * (the ctgrind trick). Both macros compile to nothing in a normal build, so the library and the
 * tests are unchanged. BRISK__CT_PUBLIC declassifies a value that is public by design - a tag
 * comparison result, a decision the protocol reveals anyway - and is the only way to silence a
 * report: never "fix" one by declassifying a secret. */
#ifdef BRISK_CT_CHECK
#    include <valgrind/memcheck.h>
#    define BRISK__CT_SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#    define BRISK__CT_PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED(p, n)
#else
#    define BRISK__CT_SECRET(p, n) ((void)0)
#    define BRISK__CT_PUBLIC(p, n) ((void)0)
#endif

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

/* ---- crypto/chacha20_poly1305.c: ChaCha20, Poly1305, AEAD_CHACHA20_POLY1305 (RFC 8439) ----
 * Fixed sizes only (RFC 8439 2.8: K_LEN 32, nonce 12, tag 16). The per-record/per-packet nonce
 * (iv XOR left-padded sequence or packet number, RFC 9846 5.3 / RFC 9001 5.3) is built by the
 * caller; this module just takes the 12 bytes. */
#define BRISK__CHACHA20_KEY_LEN   32
#define BRISK__CHACHA20_NONCE_LEN 12
#define BRISK__POLY1305_TAG_LEN   16

/* out = in XOR ChaCha20 keystream(key, counter, nonce) (RFC 8439 2.4). in == out allowed; no
 * partial overlap. The caller guarantees counter + ceil(len/64) <= 2^32: the 32-bit block counter
 * is NOT checked for wrap, and a wrap would reuse keystream. Also QUIC header protection
 * (RFC 9001 5.4.4): brisk__chacha20(hp, brisk__load_le32(sample), sample + 4, zero5, mask, 5). */
void brisk__chacha20(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                     const uint8_t *in, uint8_t *out, size_t len);

/* One-shot Poly1305 (RFC 8439 2.5); key is a one-time key (r || s). */
void brisk__poly1305(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16]);

/* AEAD_CHACHA20_POLY1305 seal (RFC 8439 2.8): out gets len bytes of ciphertext, tag the 16-byte
 * tag, so the TLS layer can place the tag right after the ciphertext (RFC 9846 5.2). in == out
 * allowed. BRISK_OK, or BRISK_E_ARG if len > 274877906880 (P_MAX, before any access). */
int brisk__chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                                  uint8_t *out, uint8_t tag[16]);

/* Open: verifies the tag over (aad, in) with brisk__ct_memeq BEFORE decrypting anything.
 * BRISK_OK with len bytes of plaintext in out; BRISK_E_AUTH with out[0..len) zeroed (with
 * in == out that destroys the ciphertext, by design); or BRISK_E_ARG as for seal. */
int brisk__chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                                  uint8_t *out, const uint8_t tag[16]);

/* ---- crypto/aes_ct.c | aes_ct64.c: AES-128/256 forward cipher (FIPS 197), bitsliced, constant
 * time Only the forward cipher: GCM (SP 800-38D) and QUIC header protection (RFC 9001 5.4.3) never
 * decrypt with AES. AES-192 is not supported (no TLS 1.3 / TLS 1.2 AEAD / QUIC suite uses it).
 * One variant is compiled per target: ct64 (4 blocks per pass in uint64_t q[8]) where pointers are
 * 64-bit, ct (2 blocks per pass in uint32_t q[8]) elsewhere, including ILP32 ABIs (x32, n32).
 * Stack: about 0.6 KB (ct) / 1.1 KB (ct64) per call for the expanded schedule and state. */
#ifndef BRISK__AES_CT64 /* -DBRISK__AES_CT64=0 builds the 32-bit variant anywhere (dev.py ct) */
#    if UINTPTR_MAX > 0xFFFFFFFFu
#        define BRISK__AES_CT64 1
#    else
#        define BRISK__AES_CT64 0
#    endif
#endif

typedef struct {
    /* compressed bitsliced schedule, only ever accessed through the compiled variant's member */
    union {
        uint32_t w32[60];
        uint64_t w64[30];
    } sk;
    unsigned nr;  /* 10 or 14 */
    unsigned pad; /* sizeof is 248 on every arch (i386 aligns uint64_t to 4 only) */
} brisk__aes_key;

/* key_len 16 or 32, else BRISK_E_ARG before anything is written. The caller wipes k with
 * brisk__secure_zero(k, sizeof *k). */
int brisk__aes_init(brisk__aes_key *k, const uint8_t *key, size_t key_len);

/* One block, FIPS 197 5.1 Cipher(). in == out allowed; no alignment needed. QUIC HP mask
 * (RFC 9001 5.4.3), GCM H = E(K, 0^128) and E(K, J0). */
void brisk__aes_encrypt(const brisk__aes_key *k, const uint8_t in[16], uint8_t out[16]);

/* GCTR with inc32 (SP 800-38D 6.2/6.5): out = in XOR E(K, cb) || E(K, inc32(cb)) || ...
 * Only bytes 12..15 of cb (big-endian) count up, mod 2^32; cb itself is not modified. in == out
 * allowed (no partial overlap); any len including 0; a short last block uses the leading keystream
 * bytes. Stateless: a caller splitting a message advances cb itself. The 2^32 - 2 block limit is
 * the caller's (GCM's) job. */
void brisk__aes_ctr32(const brisk__aes_key *k, const uint8_t cb[16], const uint8_t *in, size_t len,
                      uint8_t *out);

/* ---- crypto/gcm.c: GHASH (SP 800-38D 6.4) and AES-GCM (SP 800-38D 7.1/7.2, RFC 5116 5.1/5.3)
 * 96-bit IV and 128-bit tag only. The per-record/packet nonce is built by the caller (RFC 9846
 * 5.3, RFC 9001 5.3); a nonce must never repeat under one key (RFC 5116 5.1.1) and this module is
 * stateless, so the TLS/QUIC counters own that. Sender limits (2^24.5 full records per key, RFC
 * 9846 5.5; 2^23 packets, RFC 9001 6.6) are enforced by the TLS/QUIC layers. */
#define BRISK__GCM_IV_LEN  12
#define BRISK__GCM_TAG_LEN 16

/* y = GHASH_H continued over data: for each 16-byte block X (a short last block is zero-padded),
 * y = (y ^ X) * H in GF(2^128). Constant time (ctmul32 on 32-bit, ctmul64 on 64-bit targets,
 * from BearSSL). len may be 0 (data may then be NULL). */
void brisk__ghash(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len);

typedef struct {
    brisk__aes_key aes; /* 248 B on every arch */
    uint8_t h[16];      /* H = E(K, 0^128) */
} brisk__gcm_key;       /* 264 B; the caller wipes it with brisk__secure_zero(k, sizeof *k) */

/* key_len 16 or 32; otherwise BRISK_E_ARG and nothing is written. */
int brisk__gcm_init(brisk__gcm_key *k, const uint8_t *key, size_t key_len);

/* Same shape as brisk__chacha20_poly1305_seal/open. in == out allowed (no partial overlap); NULL
 * allowed where the matching length is 0. BRISK_E_ARG, before any access, if len > 2^36 - 32
 * (SP 800-38D 5.2.1.1: beyond it inc32 would wrap into J0) or aad_len > 2^61 - 1 (64-bit size_t
 * only). */
int brisk__gcm_seal(const brisk__gcm_key *k, const uint8_t iv[12], const uint8_t *aad,
                    size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16]);
/* Tag over (aad, in) checked with brisk__ct_memeq BEFORE decrypting. On BRISK_E_AUTH, out[0..len)
 * is zeroed (in place, that destroys the ciphertext). */
int brisk__gcm_open(const brisk__gcm_key *k, const uint8_t iv[12], const uint8_t *aad,
                    size_t aad_len, const uint8_t *in, size_t len, uint8_t *out,
                    const uint8_t tag[16]);

/* ---- crypto/x25519.c: X25519 (RFC 7748) on vendored fiat-crypto field arithmetic ----
 * One TU: vendor/fiat/curve25519_{64,32}.c is #included (every fiat function is static).
 * Stateless, no key context: the scalar is 32 bytes and lives with the caller.
 * The _64 file needs unsigned __int128, so it is picked on 64-bit pointers AND __int128 support;
 * ILP32-on-64 ABIs (x32, mips n32) correctly take the 32-bit file, as they do for AES. */
#ifndef BRISK__FIAT_64 /* -DBRISK__FIAT_64=0 builds the 32-bit fiat variant anywhere (dev.py ct)   \
                        */
#    if UINTPTR_MAX > 0xFFFFFFFFu && defined(__SIZEOF_INT128__)
#        define BRISK__FIAT_64 1
#    else
#        define BRISK__FIAT_64 0
#    endif
#endif

#define BRISK__X25519_LEN 32

/* out = X25519(scalar, u) (RFC 7748 5). The scalar is clamped on a private copy
 * (decodeScalar25519) and the caller's bytes are untouched; bit 255 of u is masked (RFC 7748 5,
 * MUST) and non-canonical u (2^255-19 .. 2^255-1) is accepted and reduced (ditto). Every 32-byte
 * u is a legal input - there is no point validation. out may alias scalar and/or u.
 * Constant time in both inputs; the only value that ever reaches a branch is the all-zero test
 * below, which the protocol reveals anyway (BRISK__CT_PUBLIC on that one byte).
 * BRISK_OK, or BRISK_E_ARG with out wiped when the result is the all-zero value: the peer sent a
 * small-order point (RFC 7748 6.1, 7; RFC 9846 7.4.2 says MUST abort). The TLS layer maps that to
 * an illegal_parameter alert. */
int brisk__x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]);

/* Public key for a private key: X25519(scalar, 9), the KeyShareEntry.key_exchange bytes
 * (RFC 7748 6.1, RFC 9846 7.4.2). No status: a clamped scalar is never 0 mod the group order, so
 * the all-zero case cannot occur on the base point. The caller supplies the private key from
 * brisk__os_random - L1 crypto never calls the OS itself. */
void brisk__x25519_base(uint8_t out[32], const uint8_t scalar[32]);

/* ---- crypto/p256.c: P-256 (secp256r1) ECDHE and ECDSA verify ----
 * RFC 9846 4.3.8.2 (key_share encoding + the MUST to validate the peer point), 7.4.2 (the ECDHE
 * shared secret), 4.3.3 (ecdsa_secp256r1_sha256); FIPS 186-5 6.4.2 (verify); parameters from
 * RFC 5903 3.1 = SP 800-186 3.2.1.3. Both halves are mandatory-to-implement for a TLS 1.3 client
 * (RFC 9846 9.1), so neither sits behind a config knob.
 *
 * One TU: vendor/fiat/p256_{64,32}.c is #included (every fiat function is static), selected by
 * BRISK__FIAT_64 exactly as for x25519. Stateless, no key context; the caller owns all memory.
 * Stack: measured with -fstack-usage along the deepest call chain (gcc 10.3), 1504 B for a keygen
 * or an ECDH and 1856 B for a verify at -Os; budget 2 KB, which holds at -Os and -O2 only. The
 * figure is not optimisation-independent: -O3 reaches 2160 B and -O0 about 4 KB. Above
 * brisk__aes_key's 1.1 KB, and no VLA or malloc hides it - see src/crypto/p256.c for the
 * per-frame numbers and the full table. */
#define BRISK__P256_SCALAR_LEN 32
#define BRISK__P256_POINT_LEN  65 /* 0x04 || X || Y (RFC 9846 4.3.8.2) */
#define BRISK__P256_SIG_LEN    64 /* r || s; DER is the X.509 / handshake layer's job */

/* Public key for a private key: pub = 0x04 || X(d*G) || Y(d*G), ready for KeyShareEntry.
 * `priv` is 32 caller-supplied random bytes (brisk__os_random) read big-endian; BRISK_E_ARG with
 * pub untouched if d == 0 or d >= n, so the caller draws again (FIPS 186-5 A.2.2, p ~ 2^-32).
 * L1 crypto never calls the OS itself. Constant time in d. */
int brisk__p256_keygen(uint8_t pub[65], const uint8_t priv[32]);

/* out = X(d * Q): the 32-byte shared secret Z, leading zeros kept (RFC 9846 7.4.2).
 * `peer` is the peer's 65-byte uncompressed point, validated first (RFC 9846 4.3.8.2: first byte
 * 0x04, x and y both < p, y^2 == x^3 - 3x + b) - compressed and hybrid forms are rejected, never
 * decompressed, and the point at infinity fails the curve equation. Validation runs before any
 * field element is built, because fiat_p256_from_bytes does not reduce and every Montgomery
 * operation is only proved for inputs < p. BRISK_E_ARG with out wiped on a bad point or a bad d;
 * the TLS layer maps that to illegal_parameter. Constant time in d and in the shared secret; only
 * the validity verdict reaches a branch. out may alias priv and/or peer. */
int brisk__p256_ecdh(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[65]);

/* ECDSA verify (FIPS 186-5 6.4.2). `sig` is r || s, 64 bytes: the DER ECDSA-Sig-Value of
 * RFC 9846 4.3.3 is unwrapped by the caller (the M2 DER parser). `hash` is the message digest;
 * hash_len must be >= 32 and only the leftmost 32 bytes are used (FIPS 186-5's leftmost-bits
 * rule), so a P-256 key certified with SHA-384/512 works.
 *
 * Three outcomes, and the split is what the TLS layer needs to pick an alert:
 *   BRISK_OK     the signature verifies.
 *   BRISK_E_AUTH it does not - including r or s outside [1, n-1], which FIPS 186-5 6.4.2 calls
 *                INVALID rather than an error, and R turning out to be the point at infinity.
 *                A CertificateVerify caller MUST turn this into decrypt_error (RFC 9846 4.5.2).
 *   BRISK_E_ARG  `pub` is not a point on the curve (malformed key material -> bad_certificate,
 *                not a failed signature), or hash_len < 32, which is a caller bug.
 * Every input is public, so this path may branch on all of them. */
int brisk__p256_ecdsa_verify(const uint8_t pub[65], const uint8_t *hash, size_t hash_len,
                             const uint8_t sig[64]);

/* Scalar arithmetic modulo n, the group order: in-house constant-time Montgomery over 8 limbs of
 * 32 bits on every target - deliberately one width, since a 4x64 variant would need
 * unsigned __int128 and a second code path to buy about 2% of a verify (the rationale is written
 * out in src/crypto/p256.c). Big-endian 32-byte in and out, so the limb layout stays private and
 * the tests stay
 * byte-level. Operands are reduced mod n on the way in, so any 32 bytes are legal. n0' and
 * R^2 mod n are derived at run time, so no hand-typed Montgomery constant exists to be wrong.
 * ECDSA signing (the next roadmap line) reuses these unchanged; `add` is the one verify does not
 * need and is here so the generated vectors cover it too. r may alias a and/or b. */
int brisk__p256_scalar_valid(const uint8_t a[32]); /* 1 iff 1 <= a <= n-1, constant time */
void brisk__p256_scalar_reduce(uint8_t r[32], const uint8_t a[32]);
void brisk__p256_scalar_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void brisk__p256_scalar_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void brisk__p256_scalar_inv(uint8_t r[32], const uint8_t a[32]); /* a^(n-2) mod n; 0 -> 0 */

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
