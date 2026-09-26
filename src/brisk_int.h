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

static inline uint32_t brisk__load_be16(const uint8_t *p)
{
    return ((uint32_t)p[0] << 8) | p[1];
}

static inline uint32_t brisk__load_be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static inline void brisk__store_be16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void brisk__store_be24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
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
#    define BRISK__CT_SECRET(p, n) ((void)(p), (void)(n))
#    define BRISK__CT_PUBLIC(p, n) ((void)(p), (void)(n))
#endif

/* Value barrier: launders an integer lvalue through a register so the optimizer forgets what it
 * knows about it. Use on a 0/all-ones select mask right after computing it - otherwise a compiler
 * that can prove `flag` is 0 or 1 may turn the mask/XOR select back into a branch or a cmov on a
 * target where cmov is not constant time. The vendored fiat code is generated with the same
 * barrier, so this keeps our hand-written selects at its level. Takes an lvalue, modifies it in
 * place, works for any integer width (the "+r" constraint picks the register class).
 *
 * ponytail: no-op on a non-GNU compiler, which leaves that build exactly as it was before this
 * macro existed. Nothing in the support matrix (gcc, clang, mingw-gcc) lands there today. */
#if defined(__GNUC__) || defined(__clang__)
#    define BRISK__CT_BARRIER(x) __asm__ __volatile__("" : "+r"(x))
#else
#    define BRISK__CT_BARRIER(x) ((void)0)
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
#if BRISK_ENABLE_TLS12
/* RFC 5246 5: PRF(secret, label, seed1 || seed2)[0..out_len), P_<alg> over HMAC, the label and
 * seeds streamed (no concatenation buffer), any out_len. alg SHA-256/384 for TLS 1.2 (SHA-512
 * is accepted for the ACVP rows). BRISK_E_ARG (out untouched) on an unknown alg, out == NULL,
 * out_len == 0 or label == NULL; seed2 may be NULL/0. `out` must not overlap `secret`. Every
 * intermediate A(i) and HMAC state is wiped; the loop count depends only on out_len. */
int brisk__tls12_prf(brisk_hash_alg alg, const uint8_t *secret, size_t secret_len,
                     const char *label, const uint8_t *seed1, size_t seed1_len,
                     const uint8_t *seed2, size_t seed2_len, uint8_t *out, size_t out_len);
#endif

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
/* the multiply-free GHASH behind BRISK_GHASH_MULFREE; always built so every arch tests it */
void brisk__ghash_mulfree(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len);

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

/* ---- crypto/p256.c: P-256 (secp256r1) ECDHE, ECDSA verify and (BRISK_ENABLE_MTLS) ECDSA sign ---
 * RFC 9846 4.3.8.2 (key_share encoding + the MUST to validate the peer point), 7.4.2 (the ECDHE
 * shared secret), 4.3.3 (ecdsa_secp256r1_sha256); FIPS 186-5 6.4.2 (verify); parameters from
 * RFC 5903 3.1 = SP 800-186 3.2.1.3. Both halves are mandatory-to-implement for a TLS 1.3 client
 * (RFC 9846 9.1), so neither sits behind a config knob.
 *
 * One TU: vendor/fiat/p256_{64,32}.c is #included (every fiat function is static), selected by
 * BRISK__FIAT_64 exactly as for x25519. Stateless, no key context; the caller owns all memory.
 * Stack: measured with -fstack-usage along the deepest call chain (gcc 10.3), at -Os, 1504 B for
 * a keygen or an ECDH, 1856 B for a verify and 2688 B for a SIGN. Budget 3 KB, raised from 2 KB
 * when signing landed: the sign path runs its fault-check verify nested inside its own frame, so
 * the two add up and no reordering removes that - the countermeasure is worth the kilobyte (see
 * brisk__p256_ecdsa_sign). Verify and ECDH still fit the old 2 KB, so a TINY build without
 * BRISK_ENABLE_MTLS keeps the smaller number. The figures are not optimisation-independent and
 * only -Os holds on the 64-bit field: -O2 needs 2144 B for a verify and 3200 B for a sign, -O3
 * 3328 B for a sign - all over budget, which is why -Os is pinned PRIVATE in CMakeLists.txt.
 * Above brisk__aes_key's 1.1 KB, and no VLA or malloc hides it - see src/crypto/p256.c for the
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

#if BRISK_ENABLE_MTLS
/* ECDSA signature generation (FIPS 186-5 6.4.1) with a deterministic nonce (RFC 6979 3.2), hedged
 * with caller-supplied extra data (RFC 6979 3.6, bullet 2) when `extra` is non-NULL. The mTLS
 * device-key half of RFC 9846 4.3.3; gated by BRISK_ENABLE_MTLS because p256.c is linked into
 * every build for ECDHE and a TINY image never signs.
 *
 * `sig`   receives r || s, 64 bytes, fixed width. The DER ECDSA-Sig-Value of RFC 9846 4.3.3 is
 *         wrapped by the caller, mirroring brisk__p256_ecdsa_verify's input contract.
 * `priv`  the device key d, 32 bytes big-endian. BRISK_E_ARG with `sig` untouched if d == 0 or
 *         d >= n, so the caller can retry into the same buffer (as brisk__p256_keygen).
 * `hash`  the message digest. hash_len must be 32, 48 or 64: it is both the leftmost-bits input
 *         (only the first 32 bytes are read) and the selector for the RFC 6979 HMAC hash, which
 *         must be the same H that produced the digest (RFC 6979 3.2 b). Any other length is
 *         BRISK_E_ARG - a caller bug, not a signature failure. RFC 9846 4.3.3 forbids SHA-224 and
 *         leaves SHA-1 legacy-only, and brisk.h compiles no digest below SHA-256, so there is no
 *         shorter case to support.
 * `extra` k' (RFC 6979 3.6): 32 bytes from brisk__os_random in production, NULL/0 for pure
 *         RFC 6979. L1 crypto never calls the OS, so the caller owns that draw - which is also
 *         what makes the hedged path testable with a fixed k'. Any extra_len is legal; the bytes
 *         are appended after bits2octets(h1) in steps d and f, and nothing else changes. With
 *         `extra` absent the function is bit-exact RFC 6979, which is what lets the A.2.5 vectors
 *         serve as a self-test of the hedged code path.
 *
 * The HMAC_DRBG inside is nonce derivation, not a randomness source: it is per-signature, seeded
 * only from (d, h1, k'), never persisted and never reseeded, so it does not contradict the "no
 * userspace DRBG" rule in .claude/rules/crypto.md.
 *
 * No low-s normalisation. TLS 1.3 does not ask for it, RFC 6979 A.2.5 publishes the
 * non-normalised s, and normalising would break every official vector. Do not add it.
 *
 * Returns BRISK_OK, BRISK_E_ARG (bad d or bad hash_len), or BRISK_E_AUTH when the self-verify of
 * the produced signature fails - a fault or a bug, and `sig` is then zeroed rather than emitted.
 * That self-verify is deliberate and not in the RFC: a single glitched ECDSA signature leaks the
 * long-term device key, and this is the one place in the library where that risk is unbounded.
 * It costs one keygen plus one verify per signature. Do not simplify it away.
 *
 * Constant time in d, k and the DRBG state; the only value that reaches a branch is the one-bit
 * "this candidate was rejected" verdict, declassified exactly as in brisk__p256_keygen. `hash` is
 * public (the peer computes the same transcript hash).
 * `sig` may alias `hash` and/or `extra`: it is written only after both have been consumed. */
int brisk__p256_ecdsa_sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t *hash,
                           size_t hash_len, const uint8_t *extra, size_t extra_len);
#endif

/* Scalar arithmetic modulo n, the group order: in-house constant-time Montgomery over 8 limbs of
 * 32 bits on every target - deliberately one width, since a 4x64 variant would need
 * unsigned __int128 and a second code path to buy about 2% of a verify (the rationale is written
 * out in src/crypto/p256.c). Big-endian 32-byte in and out, so the limb layout stays private and
 * the tests stay
 * byte-level. Operands are reduced mod n on the way in, so any 32 bytes are legal. n0' and
 * R^2 mod n are derived at run time, so no hand-typed Montgomery constant exists to be wrong.
 * brisk__p256_ecdsa_sign reuses all five unchanged - `add` is the one verify does not need, and
 * signing is what needs it (e + r*d). r may alias a and/or b. */
int brisk__p256_scalar_valid(const uint8_t a[32]); /* 1 iff 1 <= a <= n-1, constant time */
void brisk__p256_scalar_reduce(uint8_t r[32], const uint8_t a[32]);
void brisk__p256_scalar_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void brisk__p256_scalar_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
void brisk__p256_scalar_inv(uint8_t r[32], const uint8_t a[32]); /* a^(n-2) mod n; 0 -> 0 */

#if BRISK_ENABLE_P384
/* ---- crypto/p384.c: P-384 (secp384r1) ECDSA VERIFY ONLY ---------------------------------------
 * RFC 9846 4.3.3 (ecdsa_secp384r1_sha384 = 0x0503), 4.3.8.2 (the uncompressed point encoding and
 * the validation rules); FIPS 186-5 6.4.2 (verify); parameters from RFC 5903 3.2 = SP 800-186
 * 3.2.1.4 = SEC 2 2.4.3. Behind BRISK_ENABLE_P384 because RFC 9846 9.1 makes only P-256
 * mandatory; what makes it worth compiling is X.509, since Let's Encrypt Generation Y
 * intermediates are P-384 (docs/ARCHITECTURE.md 121-122).
 *
 * VERIFY ONLY, forever: no keygen, no ECDH (docs/ARCHITECTURE.md locks "no P-384 ECDHE"), no
 * signing. Every input is public, and the ladder inside branches on the bits of its scalars, so
 * NOTHING SECRET MAY EVER BE PASSED TO THIS FILE. If a secret scalar is ever needed on P-384,
 * the ladder needs a fixed-step sibling with a mask select; it must not simply be reused.
 *
 * Runs on the generic i31 bignum of bn.c, which needs no change for it. A verify is about 12,000
 * 13-limb Montgomery multiplications and 2648 B of stack along the deepest chain (verify ->
 * pt_add -> fe_mul -> brisk__bn_mont_mul), measured with -fstack-usage, gcc 14.2 at -Os on
 * x86_64, against the 3 KB budget p256.c already carries. Other toolchains differ by a few
 * hundred bytes; the per-frame breakdown, and the only copy of these figures to update, is the
 * src/crypto/p384.c header. That accumulator is sized by BRISK_RSA_MAX_BITS - see
 * docs/CONFIG.md. */
#    define BRISK__P384_SCALAR_LEN 48
#    define BRISK__P384_POINT_LEN  97 /* 0x04 || X || Y (RFC 9846 4.3.8.2) */
#    define BRISK__P384_SIG_LEN    96 /* r || s; DER is the X.509 layer's job */

/* `sig` is r || s, 96 bytes: the DER ECDSA-Sig-Value of RFC 9846 4.3.3 is unwrapped by the caller
 * (the M2 DER parser). `pub` is the uncompressed 0x04 || X || Y point, which is also the
 * SubjectPublicKey bit-string body the M2 SPKI parser hands over. `hash` is the message digest;
 * hash_len must be >= 48 and only the leftmost 48 bytes are read (FIPS 186-5's leftmost-bits
 * rule), so a P-384 key certified with SHA-512 verifies.
 *
 * CONSEQUENCE, recorded rather than fixed here: a P-384 key certified with ecdsa-with-SHA256
 * exists in some private PKIs and cannot be verified through this API. RFC 9846 4.3.3 pairs the
 * curve with its own hash, so TLS never asks for that pairing; M2's certificate layer must
 * reject the mismatch with unsupported_certificate rather than call in with hash_len 32.
 *
 * Three outcomes, and the split is what the TLS/X.509 layer needs to pick an alert:
 *   BRISK_OK     the signature verifies.
 *   BRISK_E_AUTH it does not - including r or s outside [1, n-1], which FIPS 186-5 6.4.2 calls
 *                INVALID rather than an error, and R turning out to be the point at infinity.
 *                A CertificateVerify caller MUST turn this into decrypt_error (RFC 9846 4.5.2).
 *   BRISK_E_ARG  `pub` is not a point on the curve (malformed key material -> bad_certificate,
 *                not a failed signature), or hash_len < 48, which is a caller bug. */
int brisk__p384_ecdsa_verify(const uint8_t pub[97], const uint8_t *hash, size_t hash_len,
                             const uint8_t sig[96]);
#endif /* BRISK_ENABLE_P384 */

/* ---- crypto/bn.c: i31 big integers, constant-time Montgomery ---------------------------------
 * Representation (BearSSL's i31 layout): x[0] is the ANNOUNCED BIT LENGTH; x[1...] are 31-bit
 * limbs, least significant first, bit 31 of every limb always 0. A value of `bits` bits occupies
 * BRISK__BN_LIMBS(bits) uint32_t words INCLUDING the header word.
 *
 * THE ONE FOOTGUN, stated once and enforced by the API below: every operand in a computation
 * carries the MODULUS's announced length, not its own. Mixing widths silently produces a wrong
 * answer with no error, which is why there is no general brisk__bn_decode() - only the two
 * decoders below, one for a modulus and one for a value at a modulus's width.
 *
 * Why i31 rather than the fixed 8x32 core already in p256.c: 31-bit limbs leave bit 31 free, so
 * the add/sub carry chains need only uint32 arithmetic (an armv5/mips32 win), the 31x31 partial
 * products accumulate in a uint64 with headroom for the CIOS carries, and the announced-length
 * header makes a variable-width value self-describing. p256.c's scalar core stays exactly as it
 * is: it is shipped, tested, and faster at its one width.
 *
 * Constant time, honestly stated: nothing secret flows through this file today. RSA is verify
 * only and P-384 will be verify only, so every input - modulus, signature, digest, exponent - is
 * public. The kernel is nevertheless branch-free, index-free and division-free on its data, so
 * that a future secret-key consumer inherits safety by construction rather than by audit. The
 * ONE deliberate exception is brisk__bn_modpow_pub, which branches on the bits of its exponent;
 * see the warning there. */
#define BRISK__BN_LIMBS(bits) (((bits) + 30) / 31 + 1)
#define BRISK__BN_MAX_BITS    BRISK_RSA_MAX_BITS
#define BRISK__BN_MAX_LIMBS   BRISK__BN_LIMBS(BRISK__BN_MAX_BITS)

/* m <- OS2IP(src) (RFC 8017 4.2), header set to m's TRUE bit length. Leading zero octets are
 * accepted and dropped. BRISK_E_ARG if the value needs more than max_bits bits, if src_len is 0,
 * if the value is 0, or if m is even (no Montgomery inverse exists, and an even modulus would
 * silently produce garbage). m needs BRISK__BN_LIMBS(max_bits) words. On every failure path m[0]
 * is 0, so brisk__bn_decode_into on an unchecked m is a no-op rather than an overflow. */
int brisk__bn_decode_mod(uint32_t *m, uint32_t max_bits, const uint8_t *src, size_t src_len);

/* x <- OS2IP(src), zero-extended to m's ANNOUNCED width (x takes m's header word). BRISK_E_ARG
 * if the value does not fit that width. Does NOT check x < m: the caller does that with
 * brisk__bn_lt, because RFC 8017 5.2.2 step 1 wants that as a distinct outcome. */
int brisk__bn_decode_into(uint32_t *x, const uint32_t *m, const uint8_t *src, size_t src_len);

/* dst <- I2OSP(x, dst_len) (RFC 8017 4.1), left-padded with zeros. BRISK_E_ARG, with dst
 * untouched, if x does not fit in dst_len octets. Byte stores only - safe at any alignment and
 * on either endianness. */
int brisk__bn_encode(uint8_t *dst, size_t dst_len, const uint32_t *x);

/* 1 iff a < b, else 0. Both must carry the same announced length. Constant time. */
uint32_t brisk__bn_lt(const uint32_t *a, const uint32_t *b);

/* a <- a + b (ctl == 1) or a unchanged (ctl == 0); the carry out is returned either way, so a
 * caller can use the comparison without taking the result. sub is the same with the borrow. Both
 * operands carry the same announced length. Constant time in the limbs; `ctl` must be 0 or 1
 * and MAY be secret - brisk__bn_to_mont already passes a value derived from its operand - because
 * the mask goes through BRISK__CT_BARRIER and the select is branch-free. Never branch on it at
 * the call site. */
uint32_t brisk__bn_add(uint32_t *a, const uint32_t *b, uint32_t ctl);
uint32_t brisk__bn_sub(uint32_t *a, const uint32_t *b, uint32_t ctl);

/* n0 = -m^-1 mod 2^31, by Newton iteration from 1 (m is odd, so 1 is correct mod 2), five rounds,
 * masked to 31 bits. Derived at run time: no hand-typed Montgomery constant exists to be wrong,
 * the same rule sc_n0() follows in p256.c. Reads m[1] without consulting m[0], so unlike
 * brisk__bn_decode_into it is NOT harmless on a modulus whose decode failed: check that status. */
uint32_t brisk__bn_ninv31(const uint32_t *m);

/* d <- x * y * R^-1 mod m, R = 2^(31 * limbs), CIOS.
 * PRECONDITION, load-bearing and NOT checked (the same contract sc_mont_mul carries in p256.c):
 * m odd, m[0] the true bit length, x < m, y < m, all three the same announced width. Feed it an
 * unreduced operand and the result exceeds what one conditional subtraction can fix - it is then
 * silently wrong, and no mask trick rescues it. Every entry point in rsa.c establishes x < m by
 * the RFC 8017 5.2.2 step 1 range check before calling; p384.c must do the same.
 * d MAY alias x and/or y (the CIOS accumulator is internal); d must NOT alias m.
 * n0 comes from brisk__bn_ninv31(m). Constant time, branch-free, index-free, division-free. */
void brisk__bn_mont_mul(uint32_t *d, const uint32_t *x, const uint32_t *y, const uint32_t *m,
                        uint32_t n0);

/* x <- x * R mod m: 31*limbs modular doublings. Same precondition (x < m, m odd). No scratch and
 * no n0, which is why its signature differs from from_mont's.
 * ponytail: ~10 lines and no division helper, instead of BearSSL's muladd_small (which needs a
 * shift-based constant-time divrem). MEASURED COST, because the earlier "about a quarter" here
 * was wrong by 3x: at 4096 bits with e = 65537 (gcc 10.3, -Os, x86_64) this is 0.95 ms of a
 * 1.15 ms brisk__bn_modpow_pub - about 80%, not a quarter. The ratio is width-independent for
 * an F4 exponent: 31*limbs doublings of three full limb passes each, against ~18 mont_muls of
 * limbs^2 mul-accumulates. Upgrade path if a 4096-bit verify ever measures too slow on a real
 * target: bn_muladd_small + a CT divrem (BearSSL i31_muladd / i31_decode_reduce), which is one
 * pass and stays cheap when P-384 rides on this core. Nothing above this line changes. */
void brisk__bn_to_mont(uint32_t *x, const uint32_t *m);

/* x <- x * R^-1 mod m, i.e. brisk__bn_mont_mul(x, x, 1). `t` is scratch of
 * BRISK__BN_LIMBS(m bits) words, wiped on return - needed because the "1" has to live somewhere.
 */
void brisk__bn_from_mont(uint32_t *x, const uint32_t *m, uint32_t n0, uint32_t *t);

/* x <- x^e mod m, square-and-multiply over the big-endian octet string e, any e_len.
 * PRECONDITION x < m, m odd, x at m's announced width. `t` is scratch of
 * 2 * BRISK__BN_LIMBS(m bits) words, wiped on return. n0 is derived internally.
 *
 * THE EXPONENT IS PUBLIC AND ITS BITS REACH A BRANCH. That is deliberate and the only
 * non-constant-time thing in bn.c: e is the RSA public exponent, or the fixed constants p-2 and
 * n-2 for P-384 inversion. It is declassified with BRISK__CT_PUBLIC so `dev.py ct` stays
 * meaningful over the rest of the kernel instead of being silenced wholesale. Nothing secret may
 * ever be passed as e - hence the _pub suffix. If that ever changes, this function needs a
 * fixed-window sibling; it must not simply be reused.
 * BRISK_E_ARG if e is zero after stripping leading zero octets. */
int brisk__bn_modpow_pub(uint32_t *x, const uint8_t *e, size_t e_len, const uint32_t *m,
                         uint32_t *t);

/* ---- crypto/rsa.c: RSASSA-PKCS1-v1_5 and RSASSA-PSS verify (RFC 8017) ------------------------
 * Verify only (locked decision): no signing, no RSAES, no OAEP, no CRT, no key generation, no
 * primality testing, and this module consumes no randomness. Both halves are mandatory to
 * implement for a TLS 1.3 client (RFC 9846 9.1: rsa_pkcs1_sha256 for certificates,
 * rsa_pss_rsae_sha256 for CertificateVerify and certificates), so neither sits behind a config
 * knob - the same reasoning that keeps p256.c unconditional for ECDHE.
 *
 * `n` and `e` are the big-endian modulus and public exponent as the M2 SPKI parser hands them
 * over; leading zero octets are allowed. `hash` is the already-computed digest, as in
 * brisk__p256_ecdsa_verify - this library never hashes the message for you.
 *
 * Three outcomes, and the split is what the TLS layer needs in order to pick an alert:
 *   BRISK_OK     the signature verifies.
 *   BRISK_E_AUTH it does not: s >= n (RFC 8017 5.2.2 step 1), sig_len != k (8.2.2 step 1), bad
 *                padding, wrong DigestInfo, PSS inconsistency. RFC 9846 4.5.2 makes this
 *                decrypt_error for a CertificateVerify, and a chain failure for a certificate.
 *   BRISK_E_ARG  malformed key material or a caller bug -> bad_certificate, not a failed
 *                signature: modBits outside [2048, BRISK_RSA_MAX_BITS], n even, e even, e < 3,
 *                e >= n, unknown alg, hash_len != brisk_hash_len(alg).
 * Every input is public, so these paths may branch on all of them. */
#define BRISK__RSA_MIN_BITS 2048
#define BRISK__RSA_MAX_BITS BRISK__BN_MAX_BITS

/* RFC 8017 8.2.2 with the EMSA-PKCS1-v1_5 encoding of 9.2. Strict DER DigestInfo per 9.2 note 1;
 * the BER leniency of note 2 is NOT adopted, so absent NULL parameters, BER-encoded padding and
 * trailing octets after the digest are all rejected. `alg` is SHA-256, SHA-384 or SHA-512 - RFC
 * 9846 4.3.3 leaves SHA-1 legacy-only and brisk_hash_alg has no shorter digest.
 * Per RFC 9846 4.3.3 the rsa_pkcs1_* schemes "refer solely to signatures which appear in
 * certificates" and "are not defined for use in signed TLS handshake messages": this is an X.509
 * (M2) entry point only and a CertificateVerify caller must never reach it. */
int brisk__rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                            brisk_hash_alg alg, const uint8_t *hash, size_t hash_len,
                            const uint8_t *sig, size_t sig_len);

/* RFC 8017 8.1.2 + EMSA-PSS-VERIFY 9.1.2, MGF1 per B.2.1. emLen = ceil((modBits - 1)/8) from the
 * TRUE bit length of n, so it is k - 1 when modBits - 1 is a multiple of 8 and k otherwise.
 * `salt_len` is explicit rather than fixed to hLen: RFC 9846 4.3.3 requires sLen == hLen for
 * rsa_pss_rsae_* and rsa_pss_pss_* (the TLS caller passes hash_len), but an X.509 RSASSA-PSS
 * AlgorithmIdentifier (RFC 4055) carries an arbitrary saltLength and NIST's own vectors use sLen
 * in {0, 10, 20, 24, 28, 32, 48, 64}. A separate MGF hash is NOT supported: one `alg` covers
 * both, which is exactly what RFC 9846 4.3.3 mandates, and the M2 DER parser rejects a parameter
 * set whose mgfHash differs - as it must also reject a trailerField other than 1, the only value
 * 9.1.2 step 4's 0xbc encodes. sLen is NOT checked against hLen here (sLen = 0 verifies, and NIST
 * vectors need it), so the TLS entry point MUST pass hash_len and never a parsed saltLength.
 * BRISK_E_AUTH if emLen < hLen + salt_len + 2, which 9.1.2 step 3 calls "inconsistent" rather
 * than an error. */
int brisk__rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                          brisk_hash_alg alg, size_t salt_len, const uint8_t *hash, size_t hash_len,
                          const uint8_t *sig, size_t sig_len);

/* ---- x509/der.c: strict DER reader (ITU-T X.690) --------------------------------------------
 *
 * A cursor over a caller-owned buffer. Nothing is copied and nothing is allocated: every reader
 * hands back a pointer into the original bytes, so the certificate must outlive everything the
 * parser produced from it.
 *
 * Where DER is required: RFC 5280 4.1 encodes the to-be-signed data with DER and 4.1.1.3 signs
 * "the ASN.1 DER encoded tbsCertificate" - so DER is what the signature is computed over, which
 * is why a second reading of the same bytes must not be possible. RFC 9846 4.3.3 carries the
 * only flat MUST: an RSASSA-PSS AlgorithmIdentifier in a certificate signature "MUST be DER
 * encoded". Neither says every octet of a certificate is DER; this reader requires it anyway,
 * because a parser that accepts two encodings of one value is a parser other implementations
 * can be made to disagree with.
 *
 * STRICT means both halves are enforced: the plain BER content rules of clause 8, and the DER
 * restrictions of clauses 10 and 11 that pick one encoding where BER allows several. Rejected:
 * the indefinite length form (8.1.3.6, banned by 10.1); a long-form length that is not minimal
 * or that could have used the short form (10.1); a constructed universal type other than
 * SEQUENCE or SET (10.2 for the string types, 8.2.1 / 8.3.1 / 8.4 / 8.8.1 / 8.19.1 for the
 * rest, which are primitive-only in BER already); a primitive SEQUENCE or SET (8.9.1, 8.10.1);
 * the reserved tag 0 (8.1.2.2), which is BER's end-of-contents marker; an INTEGER or ENUMERATED
 * with no contents octet (8.3.1) or a redundant leading one (8.3.2, 8.4); a BOOLEAN that is not
 * one octet (8.2.1) of 00 (8.2.2) or FF (11.1); a NULL with contents (8.8.2); a BIT STRING with
 * no unused-bit count (8.6.2.1), a count above 7 (8.6.2.2), a non-zero count on an empty value
 * (8.6.2.3) or unused bits left set (11.2.1); and an OBJECT IDENTIFIER with a padded
 * subidentifier or an unterminated last one (8.19.2). Trailing bytes after a value are an error
 * the caller sees, never something quietly ignored. The high-tag-number form (8.1.2.4) is
 * rejected too, and that one is NOT an X.690 restriction - X.690 allows it; it is a local
 * profile decision, because no X.509 field has a tag number above 30.
 *
 * What this layer deliberately does NOT enforce, and who owns each rule instead. None of these
 * can be checked without knowing the ASN.1 type of the value, which implicit tagging has
 * erased by the time the bytes get here:
 *   - 11.2.2, a NamedBitList BIT STRING has its trailing zero bits removed: the extension code,
 *     for KeyUsage (RFC 5280 4.2.1.3).
 *   - 11.5, a component equal to its DEFAULT is omitted: the certificate code, for `version`,
 *     `critical` and `cA` (RFC 5280 4.1, 4.2, 4.2.1.9). NOT for RSASSA-PSS-params, where RFC
 *     4055 3.1 overrides it with an explicit instruction to validators to accept both forms.
 *   - 10.3 and 11.6, SET component and SET OF ordering: safe to skip only while distinguished
 *     names are compared as raw TLVs, as brisk__der_tlv intends. Re-audit it at the RFC 9525
 *     names item, and before anything compares a DN attribute by attribute.
 *   - 11.7 and 11.8, the DER forms of GeneralizedTime and UTCTime, together with the tighter
 *     profile of RFC 5280 4.1.2.5.1 / 4.1.2.5.2 (Zulu, seconds present, no fractional part):
 *     brisk__x509_time, which cert.c applies. This reader hands those values over unexamined,
 *     including empty ones.
 *   - the alphabets of PrintableString, IA5String and friends: X.680, not X.690, so there is
 *     nothing here to enforce. The names code owes the embedded-NUL and control-character
 *     checks before any hostname comparison.
 *
 * AND THE RULE THAT DECIDES WHERE THE CERTIFICATE PARSER STARTS: two of the checks above - the
 * constructed-universal-type ban and every leaf content rule - can only run on a value that is
 * actually read, and brisk__der_tlv / brisk__der_skip read only a header. So a parser built on
 * the cursor alone would let BER through wherever it skips, including over an AlgorithmIdentifier
 * whose parameters RFC 9846 4.3.3 requires to be DER. The certificate entry point therefore runs
 * brisk__der_walk over the whole encoding ONCE before it parses anything, and the cursor API
 * relies on that gate having passed. Walk first, then cursor.
 *
 * One limit of that gate, because it is easy to over-trust: an OCTET STRING is a leaf here,
 * so the walk does not descend into an X.509 extnValue, which holds a whole DER value of its
 * own. cert.c walks each recognised extnValue separately for exactly that reason.
 *
 * The error is STICKY: once a read fails the cursor stays failed and every later read is a
 * no-op, so a parser can run a whole chain of reads and check once at the end. Outputs of a
 * failed read are always cleared, never left holding a previous value, and brisk__der_enter
 * hands back a child cursor that is already failed - so even a caller who ignores every status
 * reads zeroes rather than garbage. Every error is BRISK_E_ARG: a malformed certificate is a
 * parse failure, never a cryptographic one.
 *
 * NOT constant time, and it does not need to be: a certificate is public, and so is every byte
 * of a TLS handshake message this reader ever sees. Nothing secret may be parsed with it.
 */

/* Maximum nesting. X.509 itself needs 9 (Certificate > TBSCertificate > extensions [3] >
 * Extensions > Extension > extnValue > the extension's own SEQUENCE > ...), so 16 leaves room
 * for the deeper policy and name structures while keeping brisk__der_walk's end stack at
 * 16 pointers. */
#define BRISK__DER_MAX_DEPTH 16

/* Identifier octets (tag class | constructed bit | tag number), i.e. the whole first byte. */
enum {
    BRISK__DER_BOOLEAN = 0x01,
    BRISK__DER_INTEGER = 0x02,
    BRISK__DER_BIT_STRING = 0x03,
    BRISK__DER_OCTET_STRING = 0x04,
    BRISK__DER_NULL = 0x05,
    BRISK__DER_OID = 0x06,
    BRISK__DER_ENUMERATED = 0x0a,
    BRISK__DER_UTF8_STRING = 0x0c,
    BRISK__DER_PRINTABLE_STRING = 0x13,
    BRISK__DER_TELETEX_STRING = 0x14,
    BRISK__DER_IA5_STRING = 0x16,
    BRISK__DER_UTC_TIME = 0x17,
    BRISK__DER_GENERALIZED_TIME = 0x18,
    BRISK__DER_SEQUENCE = 0x30,
    BRISK__DER_SET = 0x31,
    /* OR these into a tag number: BRISK__DER_CONTEXT | 2 is [2] IMPLICIT primitive (dNSName),
     * BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 3 is [3] EXPLICIT (extensions). */
    BRISK__DER_CONSTRUCTED = 0x20,
    BRISK__DER_CONTEXT = 0x80
};

typedef struct {
    const uint8_t *p;   /* next unread byte */
    const uint8_t *end; /* one past the last byte of this value */
    unsigned depth;     /* nesting level; brisk__der_enter refuses to pass BRISK__DER_MAX_DEPTH */
    int err;            /* sticky: BRISK_OK or BRISK_E_ARG */
} brisk__der;

/* A cursor over len bytes at der. len == 0 is legal and every read on it fails, but `der`
 * itself must not be NULL - pass a real pointer and a zero length for an empty value. */
static inline void brisk__der_init(brisk__der *c, const uint8_t *der, size_t len)
{
    c->p = der;
    c->end = der + len;
    c->depth = 0;
    c->err = BRISK_OK;
}

/* The sticky status: BRISK_OK if every read so far succeeded. */
static inline int brisk__der_err(const brisk__der *c)
{
    return c->err;
}

/* The next identifier octet without consuming it, or -1 at the end of the value or on a failed
 * cursor - which is how an OPTIONAL field is tested for:
 *     if (brisk__der_peek(&tbs) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0)) { ... } */
static inline int brisk__der_peek(const brisk__der *c)
{
    return (c->err != BRISK_OK || c->p == c->end) ? -1 : (int)*c->p;
}

/* BRISK_E_ARG unless the cursor sits exactly at the end of its value; fails it if not. Call it
 * on the top-level cursor to reject trailing bytes after a certificate. */
int brisk__der_end(brisk__der *c);

/* Mark the cursor failed from the caller's own semantic check (a wrong OID, a version this
 * client will not parse), so the one status check at the end covers those too. Returns
 * BRISK_E_ARG. */
int brisk__der_fail(brisk__der *c);

/* Enter a constructed value of exactly `tag`: `body` becomes a cursor over its contents at
 * depth + 1 and `c` is left positioned after it, so a forgotten read of the body cannot
 * desynchronise the parent. BRISK_E_ARG on a tag mismatch, on a primitive encoding, or at
 * BRISK__DER_MAX_DEPTH. On failure `body` is an empty, already-failed cursor. */
int brisk__der_enter(brisk__der *c, unsigned tag, brisk__der *body);

/* Finish with a child cursor: rejects bytes it left unread and folds its sticky error into the
 * parent, so only the parent has to be checked. Returns the parent's status. */
int brisk__der_close(brisk__der *c, brisk__der *body);

/* Contents of a primitive value of exactly `tag`, with that type's DER content rules applied
 * (see the list above). The pointer aims into the caller's buffer. */
int brisk__der_value(brisk__der *c, unsigned tag, const uint8_t **v, size_t *len);

/* The next value whatever it is, as a raw TLV *including* its header - the bytes to hash for
 * TBSCertificate, or to keep for a DN comparison. Only the header is validated (so the length
 * is in bounds); the contents are whatever they are, which is exactly right for an unknown
 * non-critical extension RFC 5280 4.2 says to ignore. brisk__der_skip is the same without the
 * output. */
int brisk__der_tlv(brisk__der *c, const uint8_t **tlv, size_t *len);
int brisk__der_skip(brisk__der *c);

/* BOOLEAN -> 0 or 1. NULL -> nothing, it is the check itself. */
int brisk__der_bool(brisk__der *c, int *out);
int brisk__der_null(brisk__der *c);

/* OBJECT IDENTIFIER contents, i.e. the value octets without tag or length. COMPARE them against
 * a stored encoding; do not decode them to dotted numbers. 8.19.2's no-padding rule makes the
 * encoding of any given OID unique, so memcmp is exact - while a decoder would need overflow
 * checks on subidentifiers that X.690 does not bound, and none exist here. */
int brisk__der_oid(brisk__der *c, const uint8_t **v, size_t *len);

/* INTEGER contents exactly as encoded, sign octet and all. For a serial number, which RFC 5280
 * 4.1.2.2 wants positive and at most 20 octets but which is handled as an opaque string because
 * non-conforming CAs issue negative and over-long ones. */
int brisk__der_int(brisk__der *c, const uint8_t **v, size_t *len);

/* A non-negative INTEGER as a magnitude: the 0x00 sign octet DER prepends when the top bit is
 * set is stripped, so an RSA modulus, an exponent or an ECDSA r/s arrives the way the crypto
 * layer wants it. Zero comes back as one 0x00 byte, never as an empty string. BRISK_E_ARG if
 * the value is negative. */
int brisk__der_unsigned(brisk__der *c, const uint8_t **v, size_t *len);

/* A small non-negative INTEGER: certificate version, pathLenConstraint. BRISK_E_ARG above
 * 2^32 - 1, which is far past anything those fields may hold - the caller range-checks the
 * rest. uint32_t rather than uint64_t on purpose: no 64-bit arithmetic on a 32-bit MIPS. */
int brisk__der_uint(brisk__der *c, uint32_t *out);

/* BIT STRING: *unused is the 0..7 unused trailing bits of the last octet, *v / *len are the
 * octets after that count. A keyUsage reads bit i as (v[i / 8] >> (7 - i % 8)) & 1 after
 * checking i / 8 < len; an ECDSA subjectPublicKey requires *unused == 0. */
int brisk__der_bitstring(brisk__der *c, const uint8_t **v, size_t *len, unsigned *unused);

/* Validate one complete DER value and everything inside it: every header in bounds, every
 * universal leaf's contents legal, nesting within BRISK__DER_MAX_DEPTH, no trailing bytes.
 * Iterative with an explicit end stack - attacker-controlled nesting never reaches the C stack.
 * This is the fuzz entry point (fuzz/fuzz_der.c) and the strictness oracle the tests drive.
 * BRISK_OK or BRISK_E_ARG. */
int brisk__der_walk(const uint8_t *der, size_t len);

/* ---- x509/cert.c: one certificate, parsed (RFC 5280) ----------------------------------------
 *
 * brisk__x509_parse turns a DER Certificate into a brisk__x509_cert: a plain struct of pointers
 * INTO the caller's buffer plus a handful of decoded scalars. Nothing is copied, nothing is
 * allocated, and the DER must outlive the struct. It is a parse, not a validation: the
 * signature is not checked, the dates are decoded but not compared against a clock, and no
 * chain is built - brisk__x509_signed_by, brisk__x509_time_ok and brisk__x509_chain_verify own
 * those three. What it does decide is whether the
 * certificate is well formed enough to be worth any of that.
 *
 * Every pointer/length pair aims at the ENCODED bytes, never at a decoded copy: issuer and
 * subject are whole Name TLVs so name chaining is a memcmp (RFC 5280 7.1 canonical comparison
 * is deliberately not implemented - an exact DER match is what the Web PKI does in practice and
 * a mismatch only costs a chain that fails to build), `tbs` is what the signature covers
 * (4.1.1.3), and `spki` is the whole SubjectPublicKeyInfo so an SPKI pin can hash it directly.
 *
 * FAIL CLOSED, and the list of what that rejects is the point of this module:
 *   - anything brisk__der_walk rejects: the whole encoding is walked once, before any field is
 *     read, because the cursor API validates only the headers it steps over (see the der
 *     block). Each recognised extension's extnValue is walked again on its own, since an
 *     OCTET STRING is a leaf to the first pass - without that, a subjectAltName entry could
 *     carry a BER length all the way to the hostname matcher.
 *   - a critical extension this client does not recognise (4.2). That includes ones RFC 5280
 *     says applications MUST recognise but this one does not implement - name constraints
 *     (4.2.1.10), policy constraints (4.2.1.11), certificate policies (4.2.1.4) and inhibit
 *     anyPolicy (4.2.1.14). A CA that marks them critical gets its certificate refused rather
 *     than half-processed. Deliberate: an IoT client that silently ignored a name constraint
 *     would be exactly the bug this rule exists to prevent.
 *   - a repeated keyUsage, basicConstraints, subjectAltName or extendedKeyUsage (4.2: "A
 *     certificate MUST NOT include more than one instance of a particular extension") - the
 *     classic way to get two parsers to read different values. Extensions this client ignores
 *     are NOT deduplicated: a second copy changes nothing it decides, and keeping every OID
 *     seen would cost more than it buys.
 *   - a unique identifier in a v1 certificate (4.1.2.8) or extensions outside v3 (4.1.2.9).
 *   - keyUsage with no bit set, or with a bit above decipherOnly(8). 4.2.1.3 defines nine bits
 *     and says "at least one of the bits MUST be set to 1"; bounding the LENGTH is what keeps
 *     `key_usage == 0` meaning "absent" instead of also meaning "present, but every bit it
 *     set is one I do not know about", which chain code would read as unrestricted.
 *   - keyCertSign asserted without cA (4.2.1.9: "If the cA boolean is not asserted, then the
 *     keyCertSign bit in the key usage extension MUST NOT be asserted").
 *   - pathLenConstraint present without cA, or negative (4.2.1.9).
 *   - an empty subjectAltName sequence (4.2.1.6 "the sequence MUST contain at least one
 *     entry"), an empty subject whose subjectAltName is not critical, and a cA certificate
 *     with an empty subject (both 4.1.2.6).
 *   - an empty extendedKeyUsage sequence (4.2.1.12 SIZE (1..MAX)).
 *   - signatureAlgorithm different from the `signature` field inside the TBS (4.1.1.2 "This
 *     field MUST contain the same algorithm identifier"), compared as raw DER so a re-encoding
 *     of the same algorithm does not pass either.
 *   - a key or signature algorithm this build cannot use, and any use of SHA-1 (RFC 9325 4.5:
 *     "SHA-1 or MD5 MUST NOT be used").
 *   - a date outside 1950..9999, not in Zulu, without seconds, or with a fractional part
 *     (4.1.2.5.1, 4.1.2.5.2), and notBefore after notAfter.
 *
 * Not checked here, on purpose: the signature (brisk__x509_signed_by), whether `now` is inside
 * the validity window (brisk__x509_time_ok owns the STRICT / FLOOR / INSECURE_NO_TIME
 * decision), hostname and IP matching (brisk__x509_match_host), and the alphabet of any string -
 * this module never looks inside a Name or a GeneralName, it only records where they are.
 *
 * One residual worth naming: a NON-critical nameConstraints, policyConstraints or
 * inhibitAnyPolicy is ignored, although RFC 5280 4.2 says conforming applications MUST
 * recognise them. 4.2.1.10 and 4.2.1.11 require those extensions to be critical, so a
 * conforming certificate is caught by the critical-unknown rule above; a non-conforming
 * non-critical one is a constraint bypass. Every mainstream implementation behaves this way.
 */

/* Public key algorithms this client can use. Anything else is BRISK_E_ARG at parse time, which
 * is bad_certificate rather than a chain failure. */
enum {
    BRISK__X509_KEY_RSA = 1,  /* rsaEncryption, 1.2.840.113549.1.1.1 */
    BRISK__X509_KEY_P256 = 2, /* id-ecPublicKey + prime256v1 */
    BRISK__X509_KEY_P384 = 3  /* id-ecPublicKey + secp384r1; needs BRISK_ENABLE_P384 */
};

/* Signature algorithm families. The digest is kept separately in `sig_hash` so the verifier
 * does not have to re-derive it, and `sig_salt_len` carries the saltLength an RSASSA-PSS
 * AlgorithmIdentifier declared (RFC 4055 3.1) - which is why PSS is one token and not three. */
enum {
    BRISK__X509_SIG_RSA_PKCS1 = 1, /* RFC 4055 5: sha256/384/512WithRSAEncryption */
    BRISK__X509_SIG_RSA_PSS = 2,   /* RFC 4055 3.1 id-RSASSA-PSS, MGF1 with the same hash */
    BRISK__X509_SIG_ECDSA = 3      /* RFC 5758 3.2: ecdsa-with-SHA256/384/512 */
};

/* extendedKeyUsage, as a bitmask. 0 means the extension was absent, which RFC 5280 4.2.1.12
 * leaves unconstrained - the chain code decides what to require. */
#define BRISK__X509_EKU_SERVER 0x01 /* id-kp-serverAuth  1.3.6.1.5.5.7.3.1 */
#define BRISK__X509_EKU_CLIENT 0x02 /* id-kp-clientAuth  1.3.6.1.5.5.7.3.2 */
#define BRISK__X509_EKU_ANY    0x04 /* anyExtendedKeyUsage 2.5.29.37.0 */
#define BRISK__X509_EKU_OTHER  0x08 /* some purpose this client does not name */

/* keyUsage bit i of RFC 5280 4.2.1.3 is 1 << i. A value of 0 means the extension was absent,
 * which is unambiguous because a present keyUsage is refused unless it sets a bit in 0..8 -
 * see the rejection list above. */
#define BRISK__X509_KU_DIGITAL_SIGNATURE 0x0001
#define BRISK__X509_KU_NON_REPUDIATION   0x0002
#define BRISK__X509_KU_KEY_ENCIPHERMENT  0x0004
#define BRISK__X509_KU_DATA_ENCIPHERMENT 0x0008
#define BRISK__X509_KU_KEY_AGREEMENT     0x0010
#define BRISK__X509_KU_KEY_CERT_SIGN     0x0020
#define BRISK__X509_KU_CRL_SIGN          0x0040
#define BRISK__X509_KU_ENCIPHER_ONLY     0x0080
#define BRISK__X509_KU_DECIPHER_ONLY     0x0100

typedef struct {
    /* Every pair below points into the DER the caller passed to brisk__x509_parse. */
    const uint8_t *raw; /* the whole Certificate TLV */
    size_t raw_len;
    const uint8_t *tbs; /* TBSCertificate TLV - the exact bytes the signature covers (4.1.1.3) */
    size_t tbs_len;
    const uint8_t *serial; /* INTEGER contents as encoded, sign octet included (4.1.2.2) */
    size_t serial_len;
    const uint8_t *issuer; /* Name TLVs; chaining is issuer == the parent's subject, byte-wise */
    size_t issuer_len;
    const uint8_t *subject;
    size_t subject_len;
    const uint8_t *spki; /* SubjectPublicKeyInfo TLV, the thing an SPKI sha256 pin covers */
    size_t spki_len;
    const uint8_t *key; /* subjectPublicKey BIT STRING contents: the RSAPublicKey TLV, or the */
    size_t key_len;     /* uncompressed EC point, 0x04 || X || Y */
    const uint8_t *san; /* GeneralNames CONTENTS (4.2.1.6), NULL when the extension is absent */
    size_t san_len;
    const uint8_t *sig; /* signatureValue BIT STRING contents */
    size_t sig_len;

    int64_t not_before, not_after; /* seconds since 1970-01-01T00:00:00Z, may be negative */

    uint16_t key_usage;   /* BRISK__X509_KU_*, 0 when the extension is absent */
    uint8_t version;      /* 1, 2 or 3 - the encoded value plus one */
    uint8_t key_alg;      /* BRISK__X509_KEY_* */
    uint8_t sig_alg;      /* BRISK__X509_SIG_* */
    uint8_t sig_hash;     /* a brisk_hash_alg */
    uint8_t sig_salt_len; /* RSASSA-PSS saltLength; 0 for the other families */
    uint8_t eku;          /* BRISK__X509_EKU_*, 0 when the extension is absent */
    uint8_t is_ca;        /* basicConstraints cA (4.2.1.9); 0 when the extension is absent */
    int16_t path_len;     /* pathLenConstraint, or -1 for absent / no limit */
} brisk__x509_cert;

/* Parse one DER Certificate. `der` must stay valid and unchanged for as long as `c` is used.
 * BRISK_OK, or BRISK_E_ARG for every rejection in the list above - a malformed or unusable
 * certificate is a parse failure, never BRISK_E_AUTH, which this layer reserves for a signature
 * that did not verify. `c` is fully overwritten on entry, so a failed parse leaves it zeroed
 * rather than half-filled. */
int brisk__x509_parse(brisk__x509_cert *c, const uint8_t *der, size_t len);

/* Seconds since the Unix epoch for a DER UTCTime or GeneralizedTime value (`tag` says which),
 * with the RFC 5280 4.1.2.5.1 / 4.1.2.5.2 profile applied: Zulu only, seconds mandatory, no
 * fractional part, and a two-digit year below 50 meaning 20YY. Exposed because the TLS layer
 * needs the same conversion and because it is where the calendar arithmetic is tested.
 * BRISK_E_ARG on anything else. */
int brisk__x509_time(unsigned tag, const uint8_t *v, size_t len, int64_t *out);

/* ---- x509/chain.c: build a path to a trust anchor and check every signature ----------------
 *
 * brisk__x509_chain_verify takes the certificates a server sent, in the order it sent them or
 * in any other, and answers one question: does certs[0] chain to something the caller trusts?
 * It is the RFC 5280 6.1 path validation algorithm with the parts this client does not
 * implement left out, and the parts it does implement are named below with their step letters.
 *
 * Nothing is copied or allocated here either: the certs stay where the caller parsed them and
 * the only state is loop variables, the BRISK__X509_MAX_CHAIN pointers of the search path, and
 * one brisk__x509_cert for the anchor under inspection.
 * STACK: this is the top of the deepest call chain in the library, because verifying one
 * certificate signature enters the RSA verifier from here. Measured with -fstack-usage at -Os,
 * gcc 14, BRISK_RSA_MAX_BITS 4096, summed along brisk__x509_chain_verify -> signed_by ->
 * brisk__rsa_pss_verify -> rsa_vp1 -> brisk__bn_modpow_pub -> brisk__bn_mont_mul:
 *   armv7hf 3824 = 208 + 408 + 2488 + 40 + 64 + 616
 *   mips    3928 = 240 + 416 + 2520 + 64 + 88 + 600
 *   x86_64  4240 = 352 + 496 + 2560 + 80 + 112 + 640
 * The first term grew by 40 (armv7hf), 56 (mips) and 64 (x86_64) bytes when the greedy walk
 * became a backtracking search. The path array - one pointer per level, so 32 or 64 bytes - is
 * most of that; the rest is the extra live ranges around it. Treat the figure below as a FLOOR
 * rather than a number: it is gcc 14 -Os on three of the ten archs, and the same six-frame sum
 * under gcc 10 on x86_64 is 4528. aarch64, mips64, riscv64 and ppc are unmeasured, and
 * aarch64's 16-byte frame alignment tends to inflate.
 * So a thread that runs a handshake wants 4.5 KB for this path alone at 4096-bit RSA, on top of
 * whatever the TLS layer holds. BRISK_RSA_MAX_BITS is the lever - at 2048 the RSA part roughly
 * halves - and the 3.5 KB budget in src/crypto/rsa.c is the subtree, not the total.
 *
 * WHAT IS CHECKED, per certificate of the path:
 *   - 6.1.3 (a)(2) `now` is inside the validity window, as brisk__x509_time_ok reads it under
 *     the configured time policy. For a parent this is a SELECTION predicate, checked exactly
 *     like (k)..(n) below and before any signature work: an expired candidate is skipped, not
 *     fatal, so a same-Name rollover pair with the dead certificate first still builds through
 *     the live one. Checking it after the walk committed would turn that into a chain that
 *     fails although an in-date path was sitting in the array.
 *     A TRUST ANCHOR is exempt, and here the exemption is not just the letter of 6.1.1 (d)
 *     (an anchor is a Name and a key, so 6.1.3 never runs on it): an expired root is the one
 *     failure that takes out working devices with no attacker anywhere near them. DST Root CA
 *     X3 expiring in 2021 broke every client that checked it and none of the ones that did not,
 *     while the intermediate below it - which IS checked here - still had to be current. This
 *     is the opposite call from cA and keyCertSign below, which the anchor does have to pass,
 *     and the difference is that those are properties an operator chose once and a date is an
 *     event that arrives on its own.
 *   - 6.1.3 (a)(4) the issuer Name of the child equals the subject Name of the parent, compared
 *     as raw DER (see the brisk__x509_cert block on why not RFC 5280 7.1).
 *   - 6.1.3 (a)(1) the child's signature verifies under the parent's public key.
 *   - 6.1.4 (k) a parent is a v3 certificate with basicConstraints cA TRUE. A v1 or v2
 *     intermediate is refused outright, which (k) explicitly allows.
 *     A TRUST ANCHOR is the one exception, and it cuts both ways. 6.1.1 (d) defines an anchor
 *     as a Name and a key, never as certificate i of 6.1.3, so (k) does not reach it: a v1 or
 *     v2 anchor is accepted, because the operator put it in the store on purpose and a private
 *     PKI older than RFC 2459 should not be unusable. The other three rules ARE applied to the
 *     anchor although the RFC does not ask for them - a v3 root still has to say cA TRUE, still
 *     has to allow keyCertSign, and its pathLenConstraint still counts.
 *   - 6.1.4 (n) if the parent has a keyUsage, keyCertSign is set in it.
 *   - 6.1.4 (l) and (m) pathLenConstraint: a parent that declares one must not sit further than
 *     that many non-self-issued certificates above the end entity. A self-issued certificate
 *     (issuer == subject) does not count, exactly as (l) says, so a CA that cross-signs itself
 *     during a key rollover does not consume its own budget.
 *
 * WHAT IS NOT, on purpose: hostname and IP matching (brisk__x509_match_host, which the caller
 * owns), EKU policy at the end entity, name constraints, certificate policies and revocation.
 * A caller that stops after this function has a chain that is well formed and cryptographically
 * intact, and nothing more than that.
 *
 * SEARCH STRATEGY: a depth-first search upward, one level at a time, WITH backtracking.
 * At each level the trust anchors are asked FIRST - which is what "stop at the first trust
 * anchor" means and what makes a cross-signed root work: when a chain arrives with the old
 * cross-certificate still attached, the intermediate's issuer is already in the store and the
 * useless tail is never looked at. Only then are the certificates the peer supplied searched,
 * and every candidate with a matching subject is tried until one verifies.
 *
 * If a level later turns out to lead nowhere, the search RETURNS to it and resumes one past the
 * candidate it gave up on. That matters because the case is not exotic: a CA rollover puts two
 * certificates with one subject Name and one key on the wire, differing only in who signed
 * them, and the useless one goes first because it is the legacy cross-certificate kept for old
 * clients. A greedy walk takes it and reports a chain that does not build, holding every
 * certificate it needed. SPKI pins made that reachable far more often - a pin miss sends the
 * search back down a level where it would otherwise have returned - which is what finally
 * bought the 64 bytes (32 on a 32-bit target) this costs: one pointer per level, doubling as
 * the path and as each level's resume position.
 *
 * Three bounds keep it finite on peer input, and none of them depends on the peer being
 * reasonable. BRISK__X509_MAX_CHAIN bounds the depth, so a cycle of self-issued certificates
 * ends in BRISK_E_AUTH rather than a hang. BRISK__X509_MAX_VERIFY bounds the total signature
 * verifications - and with them the number of paths explored, because every descent costs at
 * least one. BRISK__X509_MAX_LOOKUPS bounds how often the trust store is consulted, which is a
 * budget of its own precisely because the other two do not cover it: the store is asked once
 * per fresh descent rather than once per level, and a candidate refused on its Name or its CA
 * bits never reaches a signature, so it is free of the verify budget. BRISK__X509_MAX_ANCHORS
 * bounds what the store may offer per Name, and anchors are asked only on first arrival. */
/* Depth: end entity + 7; the Web PKI's deepest real chain is 4. It must stay <= 31, because
 * x509/chain.c packs one pin bit per level into a uint32_t whose bit 31 is the "no pins
 * configured" marker - at 32 the two would alias and a certificate committed at the top level
 * would make every anchor pass the pin test, which is the fail-OPEN direction. chain.c carries
 * the compile-time assertion; this is the note for whoever comes here to raise the number. */
#define BRISK__X509_MAX_CHAIN 8
/* Times the trust store may be consulted in ONE search, each consultation asking for up to
 * BRISK__X509_MAX_ANCHORS candidates. Its own budget because neither of the other two covers
 * it: the depth limit stopped bounding it when the walk gained backtracking (the store is asked
 * once per fresh descent, not once per level), and a lookup is not paid for out of
 * BRISK__X509_MAX_VERIFY, since a candidate refused on its Name or its CA bits never reaches a
 * signature. 2 * MAX_CHAIN: the straight path needs one per level, and the slack is what a real
 * rollover's dead branches cost. It bounds pre-auth I/O, which for the CA bundle store is a
 * ~200 KB pass per miss - the thing a peer would otherwise get 33 of per handshake. */
#define BRISK__X509_MAX_LOOKUPS 16
/* Candidates offered for ONE issuer Name by the trust store, i.e. how many roots may share a
 * subject during a key rollover. Its own constant and not MAX_CHAIN: trimming the depth limit
 * for flash must not quietly shrink what a CA bundle may hold. */
#define BRISK__X509_MAX_ANCHORS 4
/* Total signature verifications one walk may perform, anchors and peer candidates together.
 * A real chain needs at most one per level; this is the ceiling that keeps a peer from turning
 * a long Certificate message into minutes of CPU on a 200 MHz core. */
#define BRISK__X509_MAX_VERIFY 32

/* Trust anchor lookup, called with the issuer Name TLV the walk is looking for.
 *
 * `index` counts up from 0 for the SAME `dn` until the callback stops finding candidates, so a
 * store holding two roots with one subject Name - a key rollover, which the Web PKI does have -
 * can offer both, and at most BRISK__X509_MAX_ANCHORS of them are asked for per level, so a
 * store that never says "no more" cannot hang the walk. Fill `*out` with a parsed anchor and return
 * BRISK_OK, or return any negative code to say "no more"; the walk then moves on and never calls
 * the callback again for that level. The lookup is by Name alone, so it can stay lazy: the CA
 * bundle item scans its file for a matching subject instead of parsing every root into RAM. */
typedef int (*brisk__x509_anchor_fn)(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                                     brisk__x509_cert *out);

/* Everything the walk is told to trust: a store to look anchors up in, and an optional set of
 * SPKI pins. One struct and not four arguments because these are one decision - "what does this
 * connection trust" - and M3 keeps exactly one of them per client config.
 *
 * A PIN is sha256 over a certificate's whole SubjectPublicKeyInfo TLV (brisk__x509_cert.spki),
 * the same preimage as RFC 7469's Base64(SHA-256(SPKI)) without the base64, so a pin published
 * for HPKP or generated with `openssl x509 -pubkey | openssl dgst -sha256` transfers unchanged.
 *
 * Pins are ADDITIVE: with n_pins > 0 a path must both chain to an anchor AND carry at least one
 * pinned SubjectPublicKeyInfo. They can only ever REFUSE a connection an unpinned build would
 * have accepted - there is no code path where a pin supplies trust the chain did not, which is
 * what keeps "pinned" from quietly meaning "unverified but familiar".
 *
 * Only certificates the walk COMMITS to count: the end entity, each parent it chose, and the
 * anchor it stopped at. A peer that appends the real pinned root to its Certificate message
 * does not thereby satisfy the pin, because that copy is on no path.
 *
 * Pin ROOTS. A leaf or an intermediate is a moving target - Let's Encrypt rotates intermediates
 * and certificate lifetimes drop to 47 days by 2029 - and a pin that outlives its key is an
 * outage no server-side fix can reach. Pinning them is allowed here because a private PKI with
 * one long-lived leaf is a real IoT shape, not because it is the safe default. */
typedef struct {
    brisk__x509_anchor_fn find_anchor; /* NULL = an empty trust store, so nothing can verify */
    void *anchor_ctx;
    const uint8_t (*pins)[BRISK_SHA256_LEN]; /* n_pins sha256 digests; NULL = no pinning */
    size_t n_pins;
} brisk__x509_trust;

/* Is `now` inside this certificate's validity window, under the policy the build was configured
 * with? `now` is int64 seconds since the Unix epoch, straight from whatever clock the caller has
 * - a device that has never been told the time passes what it believes, usually something near
 * 0, and the policy is what turns that into an answer. WIDEN it, never truncate: a 32-bit
 * time_t stops in 2038, and a caller that narrowed one would report every certificate as
 * not-yet-valid the moment it wrapped. The three policies, the floor they compare
 * against and why the default is not "trust the clock" are documented on BRISK_X509_TIME_POLICY
 * in include/brisk_config.h; in short:
 *   now >= BRISK_X509_TIME_FLOOR   notBefore <= now <= notAfter, whatever the policy.
 *   now <  BRISK_X509_TIME_FLOOR   STRICT refuses, FLOOR demands only notAfter >= the floor,
 *                                  INSECURE_NO_TIME never got this far.
 * BRISK_OK, or BRISK_E_AUTH for a certificate that is expired, not yet valid, or unjudgeable -
 * one code, because the caller sends one alert and an attacker learns nothing from which.
 * BRISK_E_ARG only for a NULL certificate. With BRISK_X509_TIME_POLICY_INSECURE_NO_TIME the body
 * is a NULL test and `return BRISK_OK` - the dates are not read, but the call is still a call:
 * it is a cross-TU symbol and this project does not assume LTO.
 *
 * Exposed rather than static because the TLS layer needs the same question answered about a
 * certificate it did not put in a path (a pinned leaf), and because it is where the policy is
 * tested. brisk__x509_chain_verify already calls it for every certificate of the path. */
int brisk__x509_time_ok(const brisk__x509_cert *c, int64_t now);

/* Verify that `child` was signed by the key in `issuer`, and nothing else: the caller owns the
 * name chaining and the CA checks. The digest named by child->sig_hash is taken over
 * child->tbs, then the family in child->sig_alg decides the verifier - which is also where the
 * signature and the key stop being opaque, because the DER inside a BIT STRING is the one part
 * of a certificate brisk__der_walk cannot reach (an ECDSA-Sig-Value and an RSAPublicKey both
 * live there). Both are parsed with the strict cursor here, so neither reaches the crypto layer
 * unvalidated.
 *   BRISK_OK     the signature verifies.
 *   BRISK_E_AUTH it does not, or the issuer's key algorithm cannot produce this signature.
 *   BRISK_E_ARG  the signature or the public key is not well-formed DER, or this build cannot
 *                verify the pairing at all - P-384 with BRISK_ENABLE_P384 off, or a digest
 *                narrower than the issuer's field, which RFC 5480 4 does not pair and the M1
 *                verifiers refuse. A TLS caller turns that into unsupported_certificate, which
 *                is why it is not folded into BRISK_E_AUTH. */
int brisk__x509_signed_by(const brisk__x509_cert *child, const brisk__x509_cert *issuer);

/* certs[0] is the end entity; certs[1..] are whatever else the peer supplied, in any order, and
 * may include certificates that belong to no path at all. `now` is the caller's clock in
 * seconds since the Unix epoch, read by brisk__x509_time_ok under the configured time policy -
 * an unset clock is a value this function expects, not a caller mistake.
 * `trust` may be NULL, and so may trust->find_anchor, either of which
 * means an empty trust store and therefore always BRISK_E_AUTH. n_certs itself is not bounded
 * here - the TLS layer caps the Certificate message it builds the array from - but the WORK is:
 * BRISK__X509_MAX_VERIFY signature verifications in total, however many candidates the peer
 * supplies, so an oversized list costs a scan and not a stall.
 *   BRISK_OK     certs[0] chains to a trust anchor and every signature on the way verified.
 *   BRISK_E_AUTH no such path exists - no anchor was reached, a signature failed, a certificate
 *                was outside its validity window, a parent was
 *                not a usable CA, no certificate on the path matched a pin, or the walk hit
 *                BRISK__X509_MAX_CHAIN or BRISK__X509_MAX_VERIFY. They are
 *                deliberately one code: an attacker learns nothing from which one it was, and
 *                a TLS caller sends the same alert for all of them.
 *   BRISK_E_ARG  n_certs is 0. */
int brisk__x509_chain_verify(const brisk__x509_cert *certs, size_t n_certs, int64_t now,
                             const brisk__x509_trust *trust);

/* ---- x509/bundle.c: PEM certificates out of a byte stream, sans-I/O ------------------------
 *
 * A CA bundle is a 200 KB text file with ~140 roots in it, and an IoT gateway is not going to
 * hold that in RAM to answer one lookup. So this decodes ONE certificate at a time out of
 * whatever slice of the file the caller happens to have read: feed bytes in, take a certificate
 * out, feed the rest. All the state is in the struct, so a certificate may straddle any number
 * of read() boundaries - which is also what makes the decoder testable without a filesystem,
 * and why the syscalls live in os/linux_ca.c instead of here.
 *
 * WHAT IT ACCEPTS (RFC 7468 4, read leniently, because the file belongs to root and the
 * certificates in it are verified afterwards anyway):
 *   - "-----BEGIN CERTIFICATE-----" AT THE START OF A LINE (RFC 7468 3), then base64, then
 *     "-----END CERTIFICATE-----". The END line is not spelled out: the first '-' after the
 *     body ends it, which is also what recovers a block truncated mid-file. The line anchor is
 *     what keeps this from being a parser DIFFERENTIAL against OpenSSL's PEM_read_bio, which
 *     anchors too - an indented block that only Brisk could see would be a trust anchor no
 *     tooling an integrator audits the bundle with would ever show them.
 *   - anything between blocks, which is how the human-readable subject headers Debian's
 *     ca-certificates.crt and Mozilla's PEM export put above each certificate are skipped.
 *   - other PEM labels - a private key, a CRL, "TRUSTED CERTIFICATE" - are not certificates and
 *     never start a block, because the BEGIN line is matched whole.
 *   - '=', CR, LF, space and tab inside the body, ignored wherever they fall.
 *
 * A DELIBERATE deviation: RFC 7468 2 says parsers "SHOULD ignore whitespace and other
 * non-base64 characters", and this drops the whole block instead. RFC 4648 3.3 is the other
 * half of that tension ("MUST reject the encoded data if it contains characters outside the
 * base alphabet") and it is the right half for a trust store - a stray byte that silently
 * shifted a root's bytes is not a root anyone chose. The cost is availability, never trust:
 * a dropped block is a root that is not there.
 * A block whose base64 holds any other byte, or whose DER is longer than
 * BRISK__X509_ANCHOR_MAX, is DROPPED and the scan resumes at the next BEGIN - one unreadable
 * entry in a bundle must not cost the other 139. Nothing here judges the DER: a dropped block
 * and a block that decodes to garbage are both the caller's problem, and the caller is
 * brisk__x509_parse. */
#define BRISK__X509_ANCHOR_MAX 2048 /* a 4096-bit RSA root is ~1.4 KB (ISRG Root X1: 1391 B) */

typedef struct {
    uint8_t der[BRISK__X509_ANCHOR_MAX]; /* the certificate just decoded, der_len bytes */
    size_t der_len;
    uint32_t acc;  /* base64 bit accumulator; only its low `bits` + 6 bits ever matter */
    uint8_t bits;  /* bits held in acc, 0..6 */
    uint8_t tok;   /* how much of the BEGIN line has matched so far */
    uint8_t state; /* 0 = looking for a BEGIN line, 1 = decoding a body */
    uint8_t over;  /* this body has already outgrown der[], so drop it at the END line */
    uint8_t bol;   /* the next byte starts a line, so a BEGIN line may begin there */
} brisk__x509_pem;

void brisk__x509_pem_init(brisk__x509_pem *p);

/* Consume bytes from **in until a certificate is complete or the input runs out. On return *in
 * points at the first byte NOT consumed and *len is how many are left, so the same call is made
 * again to collect a second certificate from the same buffer.
 *   1  p->der[0..p->der_len) is a complete block, valid until the next call.
 *   0  the input is exhausted; hand over more, or stop.
 * There is no error return: a malformed block is skipped, not reported (see above). */
int brisk__x509_pem_feed(brisk__x509_pem *p, const uint8_t **in, size_t *len);

#if BRISK_ENABLE_MTLS
/* ---- x509/bundle.c: ONE PEM block out of a buffer, STRICT --------------------------------
 *
 * The other PEM reader, for the device's OWN configuration (cfg.client_chain as PEM, the PEM
 * forms of cfg.client_key), and deliberately NOT the lenient streaming one above. That one skips
 * bad blocks because one unreadable root in a 140-root third-party bundle must not cost the other
 * 139; here a bad block is the integrator's own file and must fail the connection setup loudly
 * rather than send a different chain or no key. Do not "unify" the two.
 *
 * Next block labelled `label` (no dashes: "CERTIFICATE", "EC PRIVATE KEY") in in[*off..len).
 * RFC 7468 2-3: the BEGIN line starts at a line start (the anchor the streaming reader and
 * OpenSSL use) and matches "-----BEGIN " label "-----" WHOLE; blocks with other labels and text
 * outside blocks are skipped. The block ends with "-----END " + the SAME label + "-----" at a
 * line start. RFC 4648 3.3 / 3.5 for the body: base64 plus SP / HTAB / CR / LF only, '=' only at
 * the end and at most two, a whole number of 4-character quanta (pads included), zero pad bits.
 * out == NULL: validate and count only (pass 1 of a size-then-write pair; cap is ignored).
 * Otherwise at most cap bytes are written, and on failure what was written is wiped.
 *   BRISK_OK, *out_len > 0   one block; *off is just past its END line.
 *   BRISK_OK, *out_len == 0  no more blocks; *off = len.
 *   BRISK_E_ARG              a malformed block (any rule above, a missing END, an empty body,
 *                            more than cap bytes).
 * Constant time in the body's characters (the device key's base64 is the secret): only the
 * byte class (data / pad / layout / newline / dash) and the final verdict are declassified. */
int brisk__x509_pem_block(const uint8_t *in, size_t len, size_t *off, const char *label,
                          uint8_t *out, size_t cap, size_t *out_len);

/* ---- x509/key.c: the device's P-256 private key (cfg.client_key) --------------------------
 *
 * d (SECRET) out of:
 *   len 32            the raw big-endian scalar (RFC 5915 3: I2OSP(d, 32)).
 *   first byte 0x30   DER: SEC1 ECPrivateKey (RFC 5915 3; version 1, a 32-octet privateKey,
 *                     [0] namedCurve prime256v1 REQUIRED, optional [1] publicKey) or PKCS#8
 *                     PrivateKeyInfo / OneAsymmetricKey (RFC 5958 2; version 0 or 1, algorithm
 *                     id-ecPublicKey + prime256v1, the privateKey an ECPrivateKey whose [0] may
 *                     be omitted, attributes skipped, [1] publicKey only in version 1).
 *   anything else     PEM text with exactly ONE "EC PRIVATE KEY" (SEC1) or "PRIVATE KEY"
 *                     (PKCS#8) block, RFC 7468 10, decoded with brisk__x509_pem_block.
 * prime256v1 only (RFC 5480 2.1.1: namedCurve, never implicit or specified), 1 <= d <= n-1, and
 * every embedded public key must be 0x04 || X || Y equal to keygen(d). DER only, never BER -
 * although RFC 5958 2 asks receivers to take BER: fail closed, one strict reader, and every
 * encoder in use emits DER. Encrypted keys (RFC 5958 3, legacy Proc-Type PEM) are refused, with
 * no decryption code: their outer structure or label never matches. BRISK_OK, or BRISK_E_ARG
 * with d wiped; every stack copy is wiped on every path. */
int brisk__x509_p256_key(uint8_t d[32], const uint8_t *in, size_t len);
#endif

/* ---- x509/name.c: service identity, i.e. does this certificate speak for this name --------
 *
 * RFC 9525 (which obsoletes RFC 6125), from the point of view of a client that has ONE
 * reference identifier: a host name or an IP literal, whatever the user configured. The
 * certificate chain says the peer holds a key some CA vouched for; this says the peer is the
 * host that was asked for. Both are required and neither implies the other.
 *
 * WHAT IS MATCHED:
 *   - a DNS-ID against every dNSName [2] in subjectAltName, case-insensitive ASCII (6.3). Both
 *     sides have passed the same shape check by then, so "each label MUST match" is one length
 *     test and one byte-wise fold, not a label walk.
 *   - a wildcard in a PRESENTED identifier, under 6.3's two requirements: one wildcard
 *     character, and only as the complete content of the left-most label. It consumes exactly
 *     one reference label, so *.a.example is x.a.example and is neither a.example nor
 *     x.y.a.example.
 *   - an IP-ID against every iPAddress [7], "octet-for-octet" (6.4), 4 octets for IPv4 and 16
 *     for IPv6. The reference identifier is classified ONCE, by brisk__x509_parse_ip: a string
 *     that parses as an address is an IP-ID and is never compared against a dNSName, and one
 *     that does not is a DNS-ID and is never compared against an iPAddress. 7.4 is a section
 *     about precisely the bug where two components classify the same string differently.
 *
 * WHAT IS REFUSED, and the first one is the reason this module exists:
 *   - the subject Common Name, always. 1.3: "Do not include or check strings that look like
 *     domain names in the subject's Common Name." A certificate with no subjectAltName has no
 *     identity here, whatever its subject says, and there is no opt-out knob.
 *   - a presented identifier outside the LDH alphabet plus '_' and the label separator, which
 *     is where the embedded NUL, the control character and the raw UTF-8 U-label are stopped.
 *     The rule is 2: "any characters outside the range described in [US-ASCII] are prohibited,
 *     and internationalized domain labels are represented as A-labels". An identifier this
 *     client will not compare is simply not a match and the search moves on to the next entry
 *     - which is also what 6.3 requires of an invalid WILDCARD ("the presented identifier is
 *     invalid and MUST be ignored"), and what the multi-entry vectors pin down.
 *   - a reference identifier whose right-most label is all digits - 010.0.0.1, 127.1,
 *     2130706433, 0x7f.0.0.1. RFC 1123 2.1 gives no real host name an all-numeric top label,
 *     while a resolver turns every one of those into an address: accepting them as DNS-IDs
 *     would be the split classification 7.4 warns about, with the socket on an address and the
 *     matcher on a name. BRISK_E_ARG, so the caller writes the address it means.
 *   - an empty label, a leading dot or a trailing root dot in a presented identifier, a label
 *     over 63 octets and a name over 255 (RFC 1035 2.3.4).
 *   - a wildcard that is not the whole left-most label (w*.a.example, *w.a.example,
 *     a.*.example), or that appears twice (*.*.a.example).
 *   - a wildcard in the REFERENCE identifier, with BRISK_E_ARG: 6.3 covers wildcards in
 *     presented identifiers only, so a caller that passes one is asking a question this
 *     document does not define.
 *   - a reference identifier that is not a usable one at all - empty, over 255 octets, outside
 *     the alphabet (a U-label included: A-labels are the caller's job, see below) - with
 *     BRISK_E_ARG, so a configuration mistake is not reported as an authentication failure.
 *
 * NOT IMPLEMENTED, on purpose, and each one fails closed:
 *   - SRV-IDs and URI-IDs (1.3, 7.2). An otherName or uniformResourceIdentifier entry is
 *     skipped like any other GeneralName, so a certificate that carries only those does not
 *     match. This is a TLS library for devices that connect to a configured host, not an XMPP
 *     or SIP stack; the day one needs an SRV-ID, it is a new entry tag in the same loop.
 *   - IDNA. 6.3 requires U-labels to be converted to A-labels BEFORE comparison, and a
 *     punycode encoder plus the IDNA 2008 tables is larger than this whole module. The caller
 *     owes an A-label; a reference identifier with a non-ASCII octet is BRISK_E_ARG rather
 *     than a comparison that would silently never match.
 *   - public suffix protection: a presented *.com or *.co.uk is accepted as a wildcard, and
 *     7.1 puts that "beyond the scope of this document". A list of suffixes does not belong in
 *     a 60 KB library, and name constraints are the mechanism a private PKI should use.
 *   - the application service type of 6.5, which needs an SRV-ID or a URI-ID to begin with.
 *
 * The caller owns the ORDER of the two checks, and both are required: brisk__x509_chain_verify
 * says the key is vouched for, this says the name is right. Neither reads the other's verdict.
 */
/* RFC 1035 2.3.4: 255 octets for a whole name, 63 for one label. A presentation-form name is
 * not quite the wire form these bound, but no real name comes near either, and a ceiling is
 * what keeps a pathological SAN entry from costing a long scan. */
#define BRISK__X509_MAX_NAME  255
#define BRISK__X509_MAX_LABEL 63

/* An IPv4 or IPv6 literal in presentation form as the octets an iPAddress SAN entry holds.
 * Returns 4, 16, or 0 when `s` is not an address - which is also how a caller asks "is this
 * string a host name?", and the ONLY place that question is answered (RFC 9525 7.4). `out`
 * needs room for 16 octets and holds nothing meaningful unless 4 or 16 comes back.
 *
 * Accepted: dotted-quad IPv4 with no leading zeros (010.0.0.1 is octal to some resolvers and
 * decimal to others, so it is refused rather than guessed), and the three RFC 4291 2.2 forms
 * of IPv6 including one "::" run and a dotted-quad tail. Refused: a scope identifier
 * (fe80::1%eth0), the URI bracket form ([2001:db8::1]), and any surrounding space - none of
 * them can appear in a certificate, so accepting them would only widen what counts as an
 * IP-ID. Not constant time and it does not need to be: a host name is public. */
size_t brisk__x509_parse_ip(const char *s, size_t len, uint8_t *out);

/* Does `c` speak for `host`? `host` is a reference identifier of exactly one kind - a host name
 * or an IP literal, in presentation form, NOT NUL-terminated (host_len decides), and one
 * trailing root dot is stripped from it before anything else. `c` must have come from
 * brisk__x509_parse, whose brisk__der_walk gate is what lets the SAN entries be read here
 * without re-validating their headers.
 *   BRISK_OK     some presented identifier matched.
 *   BRISK_E_AUTH none did, or the certificate has no subjectAltName at all. A TLS caller turns
 *                this into a fatal alert; it is the same code a failed chain gives, because
 *                the peer is not the host either way.
 *   BRISK_E_ARG  `host` is not a usable reference identifier - NULL, empty, over 255 octets, a
 *                label over 63 or an empty one (so a leading dot or "www..example" too),
 *                outside the DNS alphabet, a wildcard, or an all-digit right-most label. That
 *                is the caller's bug, not the peer's, which is why it is not folded into
 *                BRISK_E_AUTH. */
int brisk__x509_match_host(const brisk__x509_cert *c, const char *host, size_t host_len);

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

/* ---- os/linux_ca.c (Linux builds only): the system CA bundle as a trust store --------------
 *
 * The distribution's PEM bundle, used LAZILY: every lookup opens the file, scans it for a
 * subject Name and closes it again. That is one open() and one pass over ~200 KB per anchor
 * asked for, against ~350 KB of RAM to hold every root parsed - on the hardware this library
 * targets that trade is not close, and the walk asks for an anchor a handful of times per
 * handshake. The page cache does the rest.
 *
 * ponytail: the file is re-opened and re-scanned for every `index` of every lookup, so N roots
 * sharing one Name cost N passes. N is at most BRISK__X509_MAX_ANCHORS and in practice 1.
 * Cache the offset of the last hit if a profile ever shows this.
 *
 * HOW OFTEN the search asks is what makes that affordable, and it is a bound rather than a
 * hope: BRISK__X509_MAX_LOOKUPS consultations per search, each for up to
 * BRISK__X509_MAX_ANCHORS candidates. A straight chain spends one per level; the slack is what
 * a peer can force by sending certificates that chain plausibly and name an issuer nobody has.
 *
 * Re-opening per lookup also means a bundle REWRITTEN between two `index` values - which is
 * what update-ca-certificates does, by rename - can shift the numbering and make the search
 * skip a same-Name candidate. Transient and fail-closed (a chain that does not build), so it is
 * recorded rather than fixed; holding one fd open for the whole search is the fix if it ever
 * matters. */
typedef struct {
    /* The bundle to read. NULL means "find one", and the first lookup fills this in with the
     * first readable path of the list in linux_ca.c, so the search happens once. Set it
     * yourself to pin a private bundle and no autodetection runs at all. */
    const char *path;
    brisk__x509_pem pem; /* decode scratch; the anchor handed back points INTO it */
} brisk__x509_bundle;

/* The first readable well-known CA bundle path, or NULL when the device has none. The string is
 * static storage, never freed. Only the presence of the file is checked here - an unreadable or
 * empty bundle is indistinguishable from one that holds no matching root, and both end as
 * BRISK_E_AUTH from the walk. */
const char *brisk__os_ca_path(void);

/* A brisk__x509_anchor_fn over a brisk__x509_bundle (passed as `ctx`). `*out` stays valid until
 * the next call with the same ctx, which is exactly as long as brisk__x509_chain_verify uses
 * it. BRISK_OK, or BRISK_E_ARG for "no more" - including a bundle that could not be found or
 * opened at all. */
int brisk__os_ca_anchor(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                        brisk__x509_cert *out);

/* ---- tls/keyschedule.c: TLS 1.3 key schedule (RFC 9846 sect 7.1) --------------------------------
 *
 * Composition over brisk__hkdf_extract and brisk__hkdf_expand_label from M1a; nothing new is
 * measured against a KAT here that expand_label.inc + hkdf_extract.inc have not already
 * verified. The RFC 8448 sect 3 trace uses this cascade byte for byte, so every stage output is
 * the expected value in tests/kat/expand_label.inc; the test only wires the stages together.
 *
 * NOTHING SECRET REACHES A BRANCH here: branches are on the requested algorithm, a NULL PSK
 * pointer and the return codes of the primitives. Intermediate secrets are wiped on every path.
 *
 * The engine (tls/handshake.c) owns the transcript hash and hands it in; this module never
 * sees a handshake message. Same rule as picotls: the key schedule and the wire protocol are
 * separated so QUIC (RFC 9001 sect 5.1) reuses the same schedule unchanged. */
typedef struct {
    uint8_t secret[BRISK_HASH_MAX_LEN]; /* current stage secret (early / handshake / master) */
    brisk_hash_alg alg;                 /* SHA-256 for suites 0x1301/0x1303, SHA-384 for 0x1302 */
} brisk__tls_ks;

/* early_secret = HKDF-Extract(0^HashLen, PSK|0^HashLen). psk == NULL or psk_len == 0 means
 * the external-PSK case is absent, so IKM is HashLen zeros (RFC 9846 sect 7.1). BRISK_E_ARG on
 * an unknown alg; ks->secret is HashLen bytes on success. */
int brisk__tls_ks_init(brisk__tls_ks *ks, brisk_hash_alg alg, const uint8_t *psk, size_t psk_len);

/* Advance early -> handshake and derive the two handshake traffic secrets. `dhe` is the (EC)DHE
 * shared secret (X25519 or the X of P-256's shared point, kept with its leading zeros). `th_ch_sh`
 * is Transcript-Hash(ClientHello..ServerHello), HashLen bytes. Each output is HashLen bytes.
 * ks->secret is left holding the handshake_secret for the next stage. */
int brisk__tls_ks_derive_handshake(brisk__tls_ks *ks, const uint8_t *dhe, size_t dhe_len,
                                   const uint8_t *th_ch_sh, uint8_t *c_hs_ts, uint8_t *s_hs_ts);

/* Advance handshake -> master and derive the two application traffic secrets and the exporter
 * master secret. `th_ch_sf` is TH(CH..server Finished), HashLen bytes. Each output is HashLen
 * bytes. ks->secret is left holding the master_secret for the resumption stage. */
int brisk__tls_ks_derive_application(brisk__tls_ks *ks, const uint8_t *th_ch_sf, uint8_t *c_ap_ts,
                                     uint8_t *s_ap_ts, uint8_t *exporter_ms);

/* resumption_master_secret = Derive-Secret(master_secret, "res master", CH..client Finished).
 * Called by the handshake engine after emitting the client Finished. */
int brisk__tls_ks_derive_resumption(brisk__tls_ks *ks, const uint8_t *th_ch_cf, uint8_t *res_ms);

/* verify_data for a TLS 1.3 Finished (RFC 9846 sect 4.5.3):
 *     finished_key = HKDF-Expand-Label(base_key, "finished", "", HashLen)
 *     verify_data  = HMAC(finished_key, transcript_hash)
 * `base_key` is the client or server handshake traffic secret (HashLen bytes); `transcript_hash`
 * is HashLen bytes; `out` receives HashLen bytes. The finished_key is wiped before return; the
 * COMPARE against the peer's verify_data is the handshake engine's brisk__ct_memeq. */
int brisk__tls_finished_mac(brisk_hash_alg alg, const uint8_t *base_key,
                            const uint8_t *transcript_hash, uint8_t *out);

/* TLS 1.3 exporter (RFC 9846 sect 7.5): TLS-Exporter(label, ctx, L) =
 *     HKDF-Expand-Label(Derive-Secret(exporter_master, label, ""), "exporter", Hash(ctx), L).
 * `exporter_ms` is the exporter_master_secret produced by brisk__tls_ks_derive_application.
 * `ctx` may be NULL when ctx_len == 0. Required by QUIC (RFC 9001) transport-parameter export
 * and by application code that wants channel bindings. BRISK_E_ARG on an unknown alg or
 * out_len > 255 * HashLen (from HKDF-Expand). */
int brisk__tls_ks_exporter(brisk_hash_alg alg, const uint8_t *exporter_ms, const char *label,
                           const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len);

/* Wipe every secret in ks. Safe on NULL. */
void brisk__tls_ks_wipe(brisk__tls_ks *ks);

/* PSK binder (RFC 9846 4.3.11.2 + 7.1): binder_key = Derive-Secret(HKDF-Extract(0, psk),
 * "res binder", ""), then a Finished MAC (4.5.3) with binder_key as BaseKey over `th_trunc`, the
 * HashLen-byte Transcript-Hash(... || Truncate(ClientHello)). `out` gets HashLen bytes. The early
 * secret, binder_key and finished_key are wiped before return. BRISK_E_ARG on an unknown alg. */
int brisk__tls_psk_binder(brisk_hash_alg alg, const uint8_t *psk, size_t psk_len,
                          const uint8_t *th_trunc, uint8_t *out);

/* ---- tls/handshake.c: TLS 1.3 client handshake engine (RFC 9846 sect 4), sans-I/O -----------
 *
 * One engine for TCP and QUIC: it deals in HANDSHAKE MESSAGES tagged with an epoch (the RFC 9001
 * 4.1.3 encryption levels), never in records or packets, and it exports traffic SECRETS through
 * a callback, never keys - the record layer or QUIC derives key/iv/hp itself (picotls model).
 * No syscalls, no clock, no malloc: the caller supplies the ClientHello bytes (built with
 * brisk__tls13_ch_write from brisk__os_random output), the ECDHE private key, `now` for the
 * certificate check, and one scratch buffer.
 *
 * FLOW (RFC 9846 sect 4.1, Appendix A.1). START -> [hs_client_hello] -> WAIT_SH -> WAIT_EE ->
 * WAIT_CERT_CR -> [WAIT_CERT] -> WAIT_CV -> WAIT_FIN -> CONNECTED. A HelloRetryRequest turns
 * WAIT_SH into WAIT_CH2 once; the caller then builds CH2 from hs->hrr_group / hs->cookie and
 * absorbs it with hs_client_hello again. Anything out of order is unexpected_message. When the
 * ServerHello selected the offered PSK (hs_set_psk), WAIT_EE goes to WAIT_FIN (A.1): no
 * certificate is sent or checked on a resumed connection, so the ONLY binding to the original
 * server is the ticket's SNI match and its 7-day cap (ticket.c); SPKI pins are not re-checked.
 * With BRISK_ENABLE_TLS12 the same engine also offers TLS 1.2 (ch_params.tls12) and, when the
 * ServerHello has no supported_versions and passes the RFC 9846 4.2.3 sentinel test, hands the
 * rest of the handshake to tls/tls12.c (hs->version 0x0303; see that block below).
 *
 * PSK (RFC 9846 4.3.11): resumption only, psk_dhe_ke only, never 0-RTT. The caller builds the
 * ClientHello with brisk__tls13_ch_write (binder = HashLen zeros); hs_client_hello computes the
 * binder over Truncate(CH) (after an HRR: message_hash(CH1) || HRR || Truncate(CH2)), writes it
 * into ITS queued copy and the transcript - the caller's bytes stay const. The PSK is wiped once
 * the ServerHello is processed, selected or not; a declined PSK is a full handshake.
 *
 * ALPN (RFC 7301): the offer is read from the ClientHello; EE must answer with exactly one name
 * from it (else decode_error / illegal_parameter, over QUIC no_application_protocol - RFC 9001
 * 8.1, which also makes ALPN mandatory there). hs_alpn reports the answer, len 0 for none.
 *
 * mTLS (RFC 9846 4.5.1-4.5.2): a CertificateRequest is answered with cfg.client_chain and a
 * CertificateVerify (ecdsa_secp256r1_sha256, signed with cfg.client_key or cfg.sign) when the
 * request lists 0x0403, else with an empty Certificate.
 *
 * FAILURE is sticky: the first violation sets hs->alert (RFC 9846 6.2 AlertDescription), wipes
 * every secret, drops queued output and returns BRISK_E_AUTH (a certificate or signature
 * failure: alerts 42, 43, 48, 51), BRISK_E_ARG (internal_error, 80: a local fault - on_secret
 * or on_peer_tp refused, or the authenticator rejected its own ctx or reference host) or
 * BRISK_E_PROTO (everything else: the peer broke the protocol); every later call returns
 * the same code. There is no best-effort continuation anywhere.
 *
 * POST-HANDSHAKE (RFC 9846 4.7): in CONNECTED, hs_feed takes epoch APP. A NewSessionTicket is
 * parsed strictly and handed to cfg.on_ticket (NULL = silently ignored, the MUST for a client
 * without resumption; it is not added to the transcript). A KeyUpdate sets hs->ku for the record
 * layer (refused over QUIC, RFC 9001 6). Anything else, incl. a CertificateRequest (no
 * post_handshake_auth is ever offered), is unexpected_message. A ticket larger than
 * BRISK_TLS_MAX_HS_MSG fails closed with illegal_parameter (the local limit, as for any message).
 *
 * STACK: hs_feed is 512 B (-fstack-usage, gcc -Os, x86_64 host) and calls the authenticator
 * from inside it, so the deepest chain is hs_feed -> brisk__tls13_auth_x509 (128) ->
 * brisk__x509_chain_verify's RSA-4096 subtree (the chain.c block: 4240 on x86_64 gcc 14), about
 * 4.9 KB. The certificate array lives in the scratch buffer, never on the stack.
 */
/* Epochs = RFC 9001 4.1.3 encryption levels. 1 (0-RTT) is reserved and never used: no 0-RTT. */
enum { BRISK__EPOCH_INITIAL = 0, BRISK__EPOCH_HANDSHAKE = 2, BRISK__EPOCH_APP = 3 };

/* RFC 9846 6.2 AlertDescription values the engine emits. */
enum {
    BRISK__ALERT_CLOSE_NOTIFY = 0,
    BRISK__ALERT_UNEXPECTED_MESSAGE = 10,
    BRISK__ALERT_BAD_RECORD_MAC = 20,
    BRISK__ALERT_RECORD_OVERFLOW = 22,
    BRISK__ALERT_HANDSHAKE_FAILURE = 40,
    BRISK__ALERT_BAD_CERTIFICATE = 42,
    BRISK__ALERT_UNSUPPORTED_CERTIFICATE = 43,
    BRISK__ALERT_ILLEGAL_PARAMETER = 47,
    BRISK__ALERT_UNKNOWN_CA = 48,
    BRISK__ALERT_DECODE_ERROR = 50,
    BRISK__ALERT_DECRYPT_ERROR = 51,
    BRISK__ALERT_PROTOCOL_VERSION = 70,
    BRISK__ALERT_INTERNAL_ERROR = 80,
    BRISK__ALERT_USER_CANCELED = 90,
    BRISK__ALERT_MISSING_EXTENSION = 109,
    BRISK__ALERT_UNSUPPORTED_EXTENSION = 110,
    BRISK__ALERT_CERTIFICATE_REQUIRED = 116,    /* 4.5.1.3 / 6.2: only ever received */
    BRISK__ALERT_NO_APPLICATION_PROTOCOL = 120, /* RFC 7301 3.2; RFC 9001 8.1 over QUIC */
    /* never on the wire: over QUIC only, a violation RFC 9001 maps to PROTOCOL_VIOLATION rather
     * than CRYPTO_ERROR (4.6.1: NewSessionTicket early_data other than 0xffffffff) */
    BRISK__ALERT_QUIC_PROTOCOL_VIOLATION = 255
};

/* Local cap on the encoded ALPN ProtocolNameList body we offer (RFC 7301 3.1 allows 2^16-1). */
#define BRISK__TLS13_ALPN_MAX 256

/* One resumption PSK, from brisk__tls13_ticket_import (RFC 9846 4.3.11). */
typedef struct {
    const uint8_t *identity; /* the ticket; points into the caller's blob */
    size_t identity_len;
    uint8_t psk[BRISK_HASH_MAX_LEN]; /* SECRET */
    uint8_t psk_len;                 /* 32 or 48 = HashLen of `suite` */
    uint16_t suite;
    uint32_t obf_age; /* 4.3.11.1: (age_ms + ticket_age_add) mod 2^32, from import's now_ms */
} brisk__tls13_psk;

/* The HRR cookie is copied into CH2 (RFC 9846 4.3.2). The RFC allows 2^16-1 bytes; 256 is a
 * LOCAL limit that keeps the context small, and a bigger cookie fails with illegal_parameter.
 * Raise it (and make it a knob) if interop finds a stateless server that needs more. */
#define BRISK__TLS13_COOKIE_MAX 256
/* Room for a queued ClientHello pair and the client flight. brisk__tls13_ch_write output is
 * ~350 bytes with SNI and a P-256 share; a CH that does not fit is BRISK_E_ARG at absorb. With
 * mTLS the flight carries the device chain too (BRISK_TLS_MAX_CLIENT_CHAIN on top). */
#if BRISK_ENABLE_MTLS
#    define BRISK__TLS13_OUT_MAX (2048 + BRISK_TLS_MAX_CLIENT_CHAIN)
#else
#    define BRISK__TLS13_OUT_MAX 2048
#endif

/* Traffic secret hand-off: called synchronously from hs_feed, in the order s_hs(recv),
 * c_hs(send) after the ServerHello and s_ap(recv), c_ap(send) after the server Finished.
 * `len` is HashLen. A non-zero return aborts the handshake with internal_error. The c_ap send
 * secret protects only what the caller sends AFTER the bytes hs_pull tagged HANDSHAKE. */
typedef int (*brisk__tls13_secret_fn)(void *ctx, unsigned epoch, int is_send, uint16_t suite,
                                      const uint8_t *secret, size_t len);

/* Peer authentication: the server's certificates (certs[0] is the end entity), the signature
 * scheme and signature of its CertificateVerify, and `tbs`, the FULL RFC 9846 4.5.2 signed
 * content (not a digest). REQUIRED: a NULL auth is BRISK_E_ARG at init, never a silent skip.
 * Production always passes brisk__tls13_auth_x509; only the RFC 8448 trace test, whose server
 * key is RSA-1024 with no anchor, passes its own. Return BRISK_OK or a negative code with *alert
 * set; an *alert left at 0 becomes decrypt_error for BRISK_E_AUTH and bad_certificate
 * otherwise. The certificate structs point into the engine's scratch and die with the call.
 * `version` is the negotiated protocol: 0x0304 (the CertificateVerify above) or 0x0303 (a TLS
 * 1.2 ServerKeyExchange: tbs = client_random || server_random || ServerECDHParams, RFC 8422
 * 5.4, and the TLS 1.2 scheme rules of brisk__tls12_sig_verify). */
typedef int (*brisk__tls13_auth_fn)(void *ctx, uint16_t version, const brisk__x509_cert *certs,
                                    size_t n_certs, uint16_t scheme, const uint8_t *tbs,
                                    size_t tbs_len, const uint8_t *sig, size_t sig_len,
                                    uint8_t *alert);

typedef struct {
    const char *host; /* RFC 9525 reference identity, host_len bytes, not NUL-terminated */
    size_t host_len;
    const brisk__x509_trust *trust;
    int64_t now; /* seconds since the epoch, widened; never time_t */
} brisk__tls13_auth_x509_ctx;

/* The production brisk__tls13_auth_fn (ctx = brisk__tls13_auth_x509_ctx). In this order: the
 * scheme fits the leaf key (illegal_parameter, before any bignum work),
 * brisk__x509_chain_verify (bad_certificate - one alert for every chain failure, because chain.c
 * deliberately reports one code; its BRISK_E_ARG "cannot verify this pairing" is
 * unsupported_certificate), brisk__x509_match_host (bad_certificate), the leaf's keyUsage has
 * digitalSignature when present (RFC 9846 4.5.1.2) and its EKU includes serverAuth or
 * anyExtendedKeyUsage when present (RFC 5280 4.2.1.12) - chain.c checks neither -
 * (unsupported_certificate), then the signature through brisk__tls13_cv_verify - or, for
 * version 0x0303, brisk__tls12_sig_verify (the first check uses the same TLS 1.2 table). */
int brisk__tls13_auth_x509(void *ctx, uint16_t version, const brisk__x509_cert *certs,
                           size_t n_certs, uint16_t scheme, const uint8_t *tbs, size_t tbs_len,
                           const uint8_t *sig, size_t sig_len, uint8_t *alert);

/* The CertificateVerify signature alone (RFC 9846 4.5.2) against `leaf`'s key. Schemes: 0x0403
 * (P-256 key), 0x0503 (P-384 key, BRISK_ENABLE_P384), 0x0804/0805/0806 rsa_pss_rsae with
 * sLen = hLen, NEVER a parsed saltLength (RFC 9846 4.3.3). Anything else, or a key of the
 * wrong type, is illegal_parameter before any bignum work. ECDSA signatures are the DER
 * ECDSA-Sig-Value, strictly (decode_error otherwise). A signature that does not verify is
 * decrypt_error; malformed key material is bad_certificate.
 * BRISK_OK, or BRISK_E_AUTH / BRISK_E_ARG with *alert set. */
int brisk__tls13_cv_verify(const brisk__x509_cert *leaf, uint16_t scheme, const uint8_t *tbs,
                           size_t tbs_len, const uint8_t *sig, size_t sig_len, uint8_t *alert);
#if BRISK_ENABLE_TLS12
/* A TLS 1.2 ServerKeyExchange signature (RFC 5246 7.4.3, RFC 8422 5.4) under RFC 9846 4.3.3's
 * TLS 1.2 rules: the curve is not bound to the hash, so 0x0403 or 0x0503 with a P-256 key, 0x0503
 * with a P-384 key (BRISK_ENABLE_P384); rsa_pss_rsae 0x0804-0x0806 (sLen = hLen) and
 * rsa_pkcs1 0x0401/0x0501/0x0601 with an RSA key. Never SHA-1 / SHA-224 / MD5. 0x0403 with a
 * P-384 key is refused (the digest is narrower than the field). Same alert split as
 * brisk__tls13_cv_verify. */
int brisk__tls12_sig_verify(const brisk__x509_cert *leaf, uint16_t scheme, const uint8_t *tbs,
                            size_t tbs_len, const uint8_t *sig, size_t sig_len, uint8_t *alert);
#endif

/* RFC 9846 4.5.2 signed content: 64 x 0x20 || "TLS 1.3, server CertificateVerify" (or client)
 * || 0x00 || th. `out` needs 98 + hl bytes. Returns the length. */
size_t brisk__tls13_cv_content(int is_server, const uint8_t *th, size_t hl, uint8_t *out);

/* ClientHello parameters (RFC 9846 4.2.2). NULL lists take the library's offer, which is the
 * security-relevant default: suites 0x1303, 0x1301, 0x1302 (ChaCha20 first: this library has no
 * AES instructions); groups x25519, secp256r1; signature schemes 0x0403, 0x0503 (with
 * BRISK_ENABLE_P384), 0x0804-0x0806, then 0x0401/0x0501/0x0601 for certificates only. Never
 * SHA-1, never rsa_pss_pss (no RSASSA-PSS key type in x509), never a group without ECDHE. */
typedef struct {
    const uint8_t *random; /* 32 bytes from brisk__os_random */
    const uint8_t *session_id;
    size_t session_id_len; /* 32 over TCP (Appendix E.4), 0 over QUIC (RFC 9001 8.4) */
    const uint16_t *suites;
    size_t n_suites;
    const uint16_t *groups;
    size_t n_groups;
    uint16_t share_group; /* exactly one KeyShareEntry, and its group must be in `groups` */
    const uint8_t *share_pub;
    size_t share_pub_len; /* 32 (x25519) or 65 (secp256r1) */
    const uint16_t *sig_schemes;
    size_t n_sig_schemes;
    const char *sni; /* NULL/0 = omit; an IP literal is omitted too (RFC 6066 3) */
    size_t sni_len;
    const uint8_t *cookie; /* from the HRR (RFC 9846 4.3.2); NULL on CH1 */
    size_t cookie_len;
    const uint8_t *quic_tp; /* QUIC only: encoded transport parameters (RFC 9001 8.2); NULL over
                               TCP, where the extension MUST NOT be sent */
    size_t quic_tp_len;
    /* RFC 7301 3.1 ProtocolName entries (u8 length + name each), WITHOUT the outer uint16;
     * NULL/0 = no ALPN. Empty names, a truncated entry or more than BRISK__TLS13_ALPN_MAX
     * bytes are BRISK_E_ARG. Over QUIC it is mandatory (RFC 9001 8.1, checked at absorb). */
    const uint8_t *alpn;
    size_t alpn_len;
    uint8_t psk_modes; /* 1 = psk_key_exchange_modes [psk_dhe_ke] (4.3.9); needed with psk */
    /* NULL = no pre_shared_key. Else one identity + obf_age, and a binder of psk_len zero bytes
     * that hs_client_hello fills (4.3.11). The extension is written LAST, as 4.3.11 demands. */
    const brisk__tls13_psk *psk;
    /* 1 = also offer TLS 1.2 (M5): 0x0303 after 0x0304 in supported_versions (RFC 9846 4.3.1),
     * the six TLS 1.2 suites after `suites`, and ec_point_formats [uncompressed] (RFC 8422 5.1),
     * extended_main_secret (RFC 7627 5.1) and renegotiation_info {0x00} (RFC 5746 3.4) right
     * after supported_versions. BRISK_E_ARG with BRISK_ENABLE_TLS12 == 0 or over QUIC. */
    uint8_t tls12;
} brisk__tls13_ch_params;

/* Serialise a ClientHello handshake message, header included. Extension order: server_name,
 * supported_groups, signature_algorithms, ALPN, supported_versions, cookie,
 * psk_key_exchange_modes, key_share, quic_transport_parameters, pre_shared_key. The SNI must be
 * printable ASCII (0x21..0x7e; IDNs as A-labels) and at most 255 bytes; one trailing dot is
 * dropped. The same caller string MUST be the RFC 9525 reference host (auth ctx) and the ticket
 * SNI - brisk_connect wires all three from its `host`.
 * BRISK_E_ARG, with *out_len 0, on bad parameters or when cap is too small. */
int brisk__tls13_ch_write(const brisk__tls13_ch_params *p, uint8_t *out, size_t cap,
                          size_t *out_len);

/* The server's quic_transport_parameters extension_data (RFC 9001 8.2), called from hs_feed
 * while the EncryptedExtensions is processed, before CONNECTED; the bytes die with the call.
 * A non-zero return aborts the handshake with internal_error (BRISK_E_ARG). */
typedef int (*brisk__tls13_tp_fn)(void *ctx, const uint8_t *tp, size_t len);

/* A NewSessionTicket (RFC 9846 4.7.1), strictly parsed. nonce and ticket point into the engine's
 * scratch and die with the call. lifetime is passed through as sent (a value above 604800 is
 * not fatal; whoever stores the ticket MUST NOT use it beyond 7 days). max_early_data is 0
 * when the early_data extension is absent. psk = HKDF-Expand-Label(resumption_master_secret,
 * "resumption", ticket_nonce, HashLen) of the connection's suite: SECRET, and wiped as soon as
 * the callback returns - export it (brisk__tls13_ticket_export) inside the callback. */
typedef struct {
    uint32_t lifetime, age_add, max_early_data;
    const uint8_t *nonce, *ticket;
    size_t nonce_len, ticket_len;
    uint8_t psk[BRISK_HASH_MAX_LEN];
    size_t psk_len;
    uint16_t suite;
} brisk__tls13_ticket;
/* Non-zero return = internal_error (BRISK_E_ARG). */
typedef int (*brisk__tls13_ticket_fn)(void *ctx, const brisk__tls13_ticket *t);

typedef struct {
    brisk__tls13_secret_fn on_secret; /* may be NULL (nothing exported) */
    void *secret_ctx;
    brisk__tls13_auth_fn auth; /* REQUIRED */
    void *auth_ctx;
    /* RFC 9001 8.4: the ClientHello session id MUST be empty. 8.2: the ClientHello MUST carry
     * quic_transport_parameters when set and MUST NOT otherwise (BRISK_E_ARG at absorb), and an
     * EE without it is missing_extension. */
    uint8_t quic;
    brisk__tls13_tp_fn on_peer_tp; /* QUIC: may be NULL (the parameters are dropped) */
    void *tp_ctx;
    brisk__tls13_ticket_fn on_ticket; /* may be NULL: tickets are silently ignored */
    void *ticket_ctx;
    /* mTLS (RFC 9846 4.5.1, 4.5.2). Same layout in every profile; a chain with
     * BRISK_ENABLE_MTLS == 0 is BRISK_E_ARG at init. hs_init checks, as configuration bugs
     * (BRISK_E_ARG): exactly one of client_key / sign; sign_rand with client_key; every
     * certificate parses (DER, or one PEM CERTIFICATE block each - exactly one TLV per block);
     * the leaf is P-256 with digitalSignature when keyUsage is present (4.5.1.2);
     * keygen(client_key) is the leaf's point; the DER certificates total at most
     * BRISK_TLS_MAX_CLIENT_CHAIN, so the Certificate + CertificateVerify + Finished fit an
     * empty output queue (BRISK__TLS13_OUT_MAX) - it is empty in practice,
     * because the ClientHello is pulled before the server can answer it; if it is not, the
     * flight fails with internal_error, never truncated. Buffers are not copied: they must
     * outlive the handshake. */
    const uint8_t *client_chain; /* DER certificates, or PEM text (first byte != 0x30), leaf
                                    first; NULL = none. Decoded again at handshake time. */
    size_t client_chain_len;
    const uint8_t *client_key; /* 32-byte P-256 d (SECRET), or NULL when `sign` is used */
    const uint8_t *sign_rand;  /* 32 fresh bytes of brisk__os_random per handshake: the hedged
                                  RFC 6979 3.6 k'. Reuse is safe (6979 stays deterministic on
                                  the rest), only weaker against faults. */
    brisk_sign_fn sign;        /* e.g. a secure element; must return a raw 64-byte r || s */
    void *sign_ctx;
} brisk__tls13_hs_cfg;

enum {
    BRISK__HS_START,
    BRISK__HS_WAIT_SH,
    BRISK__HS_WAIT_CH2,
    BRISK__HS_WAIT_EE,
    BRISK__HS_WAIT_CERT_CR,
    BRISK__HS_WAIT_CERT,
    BRISK__HS_WAIT_CV,
    BRISK__HS_WAIT_FIN,
    /* TLS 1.2 (tls12.c, RFC 5246 7.3): Certificate, ServerKeyExchange, [CertificateRequest]
     * ServerHelloDone, then - the client flight queued - the server's CCS and Finished */
    BRISK__HS_WAIT12_CERT,
    BRISK__HS_WAIT12_SKE,
    BRISK__HS_WAIT12_CR_SHD,
    BRISK__HS_WAIT12_SHD,
    BRISK__HS_WAIT12_CCS,
    BRISK__HS_WAIT12_FIN,
    BRISK__HS_CONNECTED,
    BRISK__HS_FAILED
};

/* The offer, parsed from the ClientHello bytes the engine absorbed - what was sent is the only
 * source of truth for "did the client offer this" (RFC 9846 4.3 unsolicited extensions). */
#define BRISK__TLS13_MAX_OFFER_EXT 16
#if BRISK_ENABLE_TLS12
#    define BRISK__TLS13_MAX_OFFER_SUITES 16 /* 3 TLS 1.3 + 6 TLS 1.2 by default */
#else
#    define BRISK__TLS13_MAX_OFFER_SUITES 8
#endif
#define BRISK__TLS13_MAX_OFFER_GROUPS 16
#define BRISK__TLS13_MAX_OFFER_SIGS   24

typedef struct {
    brisk__tls13_hs_cfg cfg;
    brisk_hash_ctx th256, th384; /* transcript; both until the suite is known (RFC 9846 4.1) */
    brisk__tls_ks ks;
    uint8_t c_hs[BRISK_HASH_MAX_LEN], s_hs[BRISK_HASH_MAX_LEN]; /* wiped after the Finished pair */
    uint8_t exp_ms[BRISK_HASH_MAX_LEN], res_ms[BRISK_HASH_MAX_LEN];
    uint8_t priv[32]; /* ECDHE private key, wiped right after the shared secret */
    uint8_t session_id[32];
    uint8_t cookie[BRISK__TLS13_COOKIE_MAX];
    uint16_t offered_ext[BRISK__TLS13_MAX_OFFER_EXT];
    uint16_t offered_suites[BRISK__TLS13_MAX_OFFER_SUITES];
    uint16_t offered_groups[BRISK__TLS13_MAX_OFFER_GROUPS];
    uint16_t offered_sigs[BRISK__TLS13_MAX_OFFER_SIGS];
    uint16_t cookie_len;
    uint16_t share_group, suite, hrr_group; /* suite is 0 until the SH/HRR picks one */
    uint16_t peer_rsl; /* server's record_size_limit (RFC 8449 4) from EE; 0 = none sent */
    uint16_t own_rsl;  /* ours, from the ClientHello; 0 = not offered */
    uint8_t n_ext, n_suites, n_groups, n_sigs, session_id_len;
    uint8_t hrr_seen, cr_seen, state, alert, in_epoch;
    /* resumption (4.3.11): the PSK from hs_set_psk (wiped at the ServerHello), whether the last
     * ClientHello carried it, whether the ServerHello selected it */
    uint8_t psk[BRISK_HASH_MAX_LEN];
    uint8_t psk_len, psk_offered, psk_ok, cr_sig_ok; /* cr_sig_ok: the CR lists 0x0403 */
    uint16_t psk_suite;
    /* ALPN (RFC 7301): the offered ProtocolNameList body, and the server's pick inside it */
    uint8_t alpn[BRISK__TLS13_ALPN_MAX];
    uint16_t alpn_len, alpn_sel_off;
    uint8_t alpn_sel_len;
    /* KeyUpdate received in CONNECTED (RFC 9846 4.7.3), for the record layer, which clears it:
     * bit0 rotate the receive key after this record, bit1 the peer set update_requested */
    uint8_t ku;
    /* 0 until the ServerHello, then 0x0303 or 0x0304 (RFC 9846 4.3.1); tls12_offered: the
     * absorbed ClientHello listed 0x0303 (BRISK_ENABLE_TLS12 builds only) */
    uint16_t version;
    uint8_t tls12_offered;
#if BRISK_ENABLE_TLS12
    /* TLS 1.2 (tls12.c). SECRET: priv_p256 (the P-256 d a ServerKeyExchange may pick; the x25519
     * one is priv above), main (first the 32-byte ECDHE preliminary secret, then the 48-byte
     * extended main secret, RFC 7627 4) - wiped as soon as they are used and by hs_fail. crand /
     * srand are the hello randoms, kx_pub our ECDHE share for the ClientKeyExchange. */
    uint8_t priv_p256[32], main[48], crand[32], srand[32], kx_pub[65];
    uint8_t kx_pub_len, cr_send; /* cr_send: the CertificateRequest also lists ecdsa_sign(64) */
#endif
    int err; /* the sticky return code once FAILED */
    /* scratch carve-up: [message reassembly | certificate array | output queue] */
    uint8_t *scratch, *in, *out;
    brisk__x509_cert *certs;
    size_t scratch_len, in_cap, in_base, in_len, n_certs, out_len, out_off, out_split;
} brisk__tls13_hs;

/* Scratch bytes hs_init needs: BRISK_TLS_MAX_HS_MSG + 4 for the largest message (the
 * Certificate, kept while the CertificateVerify - or the TLS 1.2 ServerKeyExchange - is
 * reassembled after it, because the parsed certificates point into it), a CertificateVerify or
 * ServerKeyExchange at BRISK_RSA_MAX_BITS, BRISK__X509_MAX_CHAIN certificate structs
 * (sizeof-based, aligned in place), and BRISK__TLS13_OUT_MAX of output queue. */
size_t brisk__tls13_hs_scratch_size(void);

/* BRISK_E_ARG if cfg or cfg->auth is NULL or scratch is too small. */
int brisk__tls13_hs_init(brisk__tls13_hs *hs, const brisk__tls13_hs_cfg *cfg, uint8_t *scratch,
                         size_t scratch_len);

/* Absorb a ClientHello exactly as it goes on the wire (CH1 in START, CH2 in WAIT_CH2), queue it
 * at INITIAL, learn the offer from the bytes, and take the 32-byte private key of its single key
 * share. The bytes must be well formed, offer TLS 1.3 and only suites/groups the engine can
 * finish, carry exactly one share, no PSK/early_data, and - for CH2 - the HRR's group and
 * cookie (RFC 9846 4.2.2). BRISK_E_ARG (nothing changed) otherwise: a caller bug. */
int brisk__tls13_hs_client_hello(brisk__tls13_hs *hs, const uint8_t *ch, size_t ch_len,
                                 uint16_t share_group, const uint8_t *share_priv);

/* Feed handshake bytes received at `epoch`, in any split. BRISK_OK (maybe waiting for more),
 * else BRISK_E_PROTO / BRISK_E_AUTH with hs->alert set. Bytes at an epoch other than the current
 * receive epoch, or left over in the same call after the message that ends an epoch (the
 * ServerHello, the server Finished) are unexpected_message (RFC 9846 5.1). */
int brisk__tls13_hs_feed(brisk__tls13_hs *hs, unsigned epoch, const uint8_t *in, size_t len);

/* Drain queued output of ONE epoch per call into out[0..cap). Returns the byte count, 0 when
 * nothing is queued (always 0 once FAILED). *epoch is set when the count is non-zero. */
size_t brisk__tls13_hs_pull(brisk__tls13_hs *hs, unsigned *epoch, uint8_t *out, size_t cap);

/* Before hs_client_hello when the ClientHello carries pre_shared_key (START only). psk_len must
 * be the HashLen of a known suite. The PSK is copied (identity/obf_age are ch_write's business)
 * and wiped at the ServerHello, by hs_fail and by hs_wipe. BRISK_E_ARG otherwise. */
int brisk__tls13_hs_set_psk(brisk__tls13_hs *hs, const brisk__tls13_psk *psk);

/* After CONNECTED: the ALPN name the server selected (points into hs), *len 0 = none. BRISK_E_ARG
 * before CONNECTED. Whether "none" is acceptable is the caller's call (no protocol switching). */
int brisk__tls13_hs_alpn(const brisk__tls13_hs *hs, const uint8_t **name, size_t *len);

/* 1 if the ServerHello accepted the PSK: no certificate was checked on this connection. */
int brisk__tls13_hs_resumed(const brisk__tls13_hs *hs);

/* 0 before the ServerHello, then 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3). */
uint16_t brisk__tls13_hs_version(const brisk__tls13_hs *hs);

#if BRISK_ENABLE_TLS12
/* ---- tls/tls12.c: the TLS 1.2 client half of the engine (RFC 5246, RFC 9846 4.2.3 / 4.3.3 / E)
 *
 * Entered from hs_on_sh only when the ServerHello has no supported_versions AND passed the
 * downgrade-sentinel test (RFC 9846 4.2.3). Full handshakes only (RFC 5246 7.3): SH ->
 * Certificate -> ServerKeyExchange -> [CertificateRequest] -> ServerHelloDone, then the client
 * flight [Certificate] ClientKeyExchange [CertificateVerify] at INITIAL (plaintext) and the
 * Finished in the second output run (hs_pull tags it APP: it goes out under the new keys, after
 * the record layer's mandatory CCS); then the server's CCS (brisk__tls12_on_ccs) and Finished.
 * Keys go out through cfg.on_secret with epoch APP, suite = the TLS 1.2 code and secret =
 * key || fixed_iv (RFC 5246 6.3). extended_main_secret and renegotiation_info are REQUIRED; no
 * resumption, no renegotiation (a HelloRequest in CONNECTED sets hs->ku bit 2 for the record
 * layer's one no_renegotiation warning), no exporter. Same sticky failure contract as the rest
 * of the engine. */

/* Before hs_client_hello for CH1 when the ClientHello offers TLS 1.2: the P-256 d a
 * ServerKeyExchange may pick (the x25519 d is the key_share key). Copied; wiped at a HRR, a TLS
 * 1.3 ServerHello, right after the ECDH, by hs_fail and hs_wipe. BRISK_E_ARG unless state START
 * and brisk__p256_scalar_valid(d). */
int brisk__tls13_hs_set_tls12_key(brisk__tls13_hs *hs, const uint8_t p256_d[32]);
/* hs_on_sh after the sentinel test; m/n = the whole ServerHello, ext/ext_len its extensions. */
int brisk__tls12_on_sh(brisk__tls13_hs *hs, const uint8_t *m, size_t n, const uint8_t *ext,
                       size_t ext_len, int is_hrr);
/* hs_dispatch forwards every message here once hs->version == 0x0303. */
int brisk__tls12_dispatch(brisk__tls13_hs *hs, const uint8_t *m, size_t n);
/* The record layer's server ChangeCipherSpec {0x01}: BRISK_OK (state WAIT12_FIN, receive epoch
 * APP) only in WAIT12_CCS with no handshake fragment pending; else unexpected_message, sticky.
 * RFC 5246 7.1 / 7.4.9, and the CCS-injection class (CVE-2014-0224). */
int brisk__tls12_on_ccs(brisk__tls13_hs *hs);
/* 0xC02B/0xC02F: SHA-256, key 16, iv 4; 0xC02C/0xC030: SHA-384, 32, 4; 0xCCA8/0xCCA9: SHA-256,
 * 32, 12 (RFC 5288 3, RFC 5289 3.2, RFC 7905 2); *ecdsa = 1 for ECDHE_ECDSA. 0 for anything else
 * (outputs untouched), 1 for a TLS 1.2 suite; any output pointer may be NULL. */
int brisk__tls12_suite(uint16_t suite, brisk_hash_alg *prf, size_t *key_len, size_t *iv_len,
                       uint8_t *ecdsa);

/* handshake.c helpers shared with tls12.c (formerly static; see handshake.c for each) */
brisk_hash_alg brisk__hs_alg(uint16_t suite);
int brisk__hs_fail(brisk__tls13_hs *hs, uint8_t alert);
void brisk__hs_th_add(brisk__tls13_hs *hs, const uint8_t *m, size_t n);
void brisk__hs_th_snap(const brisk__tls13_hs *hs, uint8_t *out);
uint8_t *brisk__hs_reserve(brisk__tls13_hs *hs, unsigned epoch, size_t n);
int brisk__hs_queue(brisk__tls13_hs *hs, unsigned epoch, const uint8_t *m, size_t n);
int brisk__hs_ext_next(const uint8_t **p, const uint8_t *end, uint16_t *type, const uint8_t **data,
                       size_t *dlen);
int brisk__hs_in_list(const uint16_t *list, size_t n, uint16_t v);
uint8_t brisk__hs_alpn_check(brisk__tls13_hs *hs, const uint8_t *d, size_t dl);
#    if BRISK_ENABLE_MTLS
/* The CertificateEntry list of the device chain (DER or PEM): its length when out is NULL,
 * else written to out[cap]; 0 = refused (malformed, no certificate, or more than cap). */
size_t brisk__hs_chain_entries(const uint8_t *chain, size_t len, uint8_t *out, size_t cap, int ext);
#    endif
#endif

/* ---- tls/ticket.c: the resumption ticket blob, the ONE parser of caller-stored bytes
 * ------------- Blob v1, big-endian, byte-addressed (portable across archs): ver(1)=1 | suite(2) |
 * issued_ms(8, int64) | lifetime(4) | age_add(4) | psk_len(1) psk | sni_len(1) sni |
 * ticket_len(2) ticket, nothing after. KEY MATERIAL (the PSK). ALPN is per connection (RFC 7301
 * 3.1) and is not stored. The SNI stored and compared is the caller's host with one trailing dot
 * dropped, compared ASCII case-insensitively: 4.7.1 only lets a ticket be used for a server
 * the original certificate was valid for, and an exact host match is the cheap way to meet it.
 * Both return BRISK_OK or BRISK_E_ARG, and wipe out[0..cap) / *out on failure.
 *
 * export: lifetime 0 (discard, 4.7.1), a psk_len that is not the suite's HashLen, an empty
 * ticket, an SNI over 255 bytes, or a blob over min(cap, BRISK_TICKET_MAX) are refused.
 * import: anything malformed, an unknown suite, an SNI mismatch, now_ms < issued_ms (the clock
 * went back) or an age >= min(lifetime, 604800) s (4.7.1, 4.3.11.1) is refused, which just
 * means a full handshake. out->identity points into `blob`. Import does not consume: the caller
 * deletes the blob once it has been offered (C.4, clients SHOULD NOT reuse a ticket). */
int brisk__tls13_ticket_export(const brisk__tls13_ticket *t, int64_t now_ms, const char *sni,
                               size_t sni_len, uint8_t *out, size_t cap, size_t *out_len);
int brisk__tls13_ticket_import(const uint8_t *blob, size_t len, const char *sni, size_t sni_len,
                               int64_t now_ms, brisk__tls13_psk *out);

/* RFC 9846 7.5 exporter; CONNECTED only (BRISK_E_ARG otherwise). */
int brisk__tls13_hs_exporter(const brisk__tls13_hs *hs, const char *label, const uint8_t *ctx,
                             size_t ctx_len, uint8_t *out, size_t out_len);

/* Wipe everything: secrets, key, transcript, and the whole scratch buffer. Safe on NULL. */
void brisk__tls13_hs_wipe(brisk__tls13_hs *hs);

/* ---- tls/record.c: TLS 1.3 record layer over TCP (RFC 9846 sect 5), sans-I/O ---------------
 *
 * Two layers. brisk__tls_dir / rec_seal / rec_open protect ONE record in one direction: key and
 * iv from a traffic secret (7.3), nonce = iv XOR the 64-bit sequence number (5.3), AAD = the
 * 5-byte header as on the wire, TLSInnerPlaintext = content || type || zero padding (5.2, 5.4).
 * brisk__tls13_conn drives a brisk__tls13_hs over them: framing, the unprotected CCS rule,
 * alerts, close_notify, KeyUpdate, the send-key switch timing and record_size_limit.
 *
 * FAILURE is sticky: the first violation sets c->alert, wipes the receive key, the pending secret
 * and the engine, and every later call returns c->err (BRISK_E_AUTH for bad_record_mac,
 * BRISK_E_ARG for internal_error - a local fault - and BRISK_E_PROTO otherwise). conn_pull then
 * emits exactly one fatal alert {2, desc} under the then-current send key (plaintext before one
 * is installed, RFC 9846 7.3) and wipes the send key. A fatal alert FROM the peer is
 * BRISK_E_PEER_ALERT with the value in c->peer_alert; nothing is sent back (6.2) and every key
 * is wiped at once.
 *
 * LOCAL CHOICES the RFC leaves open: a receive sequence number at 2^64-1 (5.3 "MUST NOT wrap") is
 * unexpected_message - unreachable in practice; a second send secret while one is still pending
 * is internal_error (a caller bug: the ServerHello was fed before the ClientHello was pulled);
 * the send side at the 2^48-1 KeyUpdate cap terminates with internal_error at the 5.5 limit.
 *
 * CONSTANT TIME: keys, ivs and secrets never reach a branch or an index; the nonce XOR is
 * branch-free and the AEADs verify the tag before decrypting. The padding scan after a
 * successful open branches on the authenticated plaintext, which is declassified there: it is
 * the peer's message, handed to the caller anyway, and its padding length is not a key.
 *
 * GCM on the wire: armv5 and 32-bit MIPS use the multiply-free GHASH (BRISK_GHASH_MULFREE), so
 * an early-terminating multiplier cannot leak H there.
 */
#define BRISK__TLS_REC_HDR    5
#define BRISK__TLS_MAX_PLAIN  16384u              /* 2^14, 5.1 */
#define BRISK__TLS_MAX_INNER  (16384u + 1)        /* 5.4 */
#define BRISK__TLS_MAX_CIPHER (16384u + 256)      /* 5.2 */
#define BRISK__TLS_REC_IN_MAX (5 + 16384 + 256)   /* 16645: the receive buffer conn_init needs */
#define BRISK__TLS_REKEY_SEQ  ((uint64_t)1 << 24) /* 5.5: below 2^24.5 AES-GCM records */
enum { BRISK__CT_CCS = 20, BRISK__CT_ALERT = 21, BRISK__CT_HANDSHAKE = 22, BRISK__CT_APP = 23 };

typedef struct { /* one direction's protection state */
    union {
        brisk__gcm_key gcm;
        uint8_t chacha[32];
    } k;
    uint8_t iv[12];
    uint8_t secret[BRISK_HASH_MAX_LEN]; /* traffic secret N, kept for 7.2 "traffic upd" */
    uint64_t seq;
    uint64_t n_updates; /* KeyUpdates applied here (send side: the 2^48-1 cap of 4.7.3) */
    uint16_t suite;     /* 0 = unprotected */
    uint8_t epoch;      /* BRISK__EPOCH_* */
} brisk__tls_dir;

/* nonce = iv XOR (seq big-endian, left-padded to 12 bytes) (RFC 9846 5.3, RFC 9001 5.3). */
void brisk__tls_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12]);

/* 7.3 key/iv from `secret` (len must be the suite's HashLen), seq = 0, n_updates = 0, the
 * previous state wiped first. `secret` may point into d. BRISK_E_ARG on an unknown suite or a
 * wrong len (d wiped). */
int brisk__tls_dir_init(brisk__tls_dir *d, unsigned epoch, uint16_t suite, const uint8_t *secret,
                        size_t len);
#if BRISK_ENABLE_TLS12
/* RFC 5246 6.3 key and fixed IV straight from the key block (no HKDF): d wiped first, seq 0,
 * epoch APP. BRISK_E_ARG (d wiped) unless `suite` is a TLS 1.2 suite and the lengths are its. A
 * TLS 1.2 d makes brisk__tls_rec_seal / _open use RFC 5246 6.2.3.3 framing: the real content
 * type in the header, AAD = seq(8) || type || 0x0303 || plaintext length, GCM nonce = iv(4) ||
 * nonce_explicit(8) (= seq on seal, read from the wire on open, RFC 5288 3), ChaCha nonce = iv
 * XOR seq (RFC 7905 2); no inner type, pad must be 0. */
int brisk__tls12_dir_init(brisk__tls_dir *d, uint16_t suite, const uint8_t *key, size_t key_len,
                          const uint8_t *iv, size_t iv_len);
#endif
/* 7.2: secret = Expand-Label(secret, "traffic upd", "", HashLen), then dir_init; n_updates + 1.
 * The old secret, key and iv are gone afterwards. BRISK_E_ARG unless d is an APP epoch. */
int brisk__tls_dir_update(brisk__tls_dir *d);
void brisk__tls_dir_wipe(brisk__tls_dir *d); /* safe on NULL */

/* Seal ONE record into out: header || AEAD(content || type || zeros[pad]), or a plaintext
 * record when d->suite == 0 (pad must then be 0, len <= 2^14). `in` may equal out + 5 (no other
 * overlap). BRISK_E_ARG, nothing written and seq unchanged, if len + 1 + pad > 2^14 + 1 (checked
 * without overflow), cap is too small, or d->seq == UINT64_MAX. *out_len = 5 + len + 1 + pad + 16
 * (protected). seq++ on success. `legacy_ver` goes into plaintext headers only: 0x0301 for an
 * initial ClientHello, 0x0303 otherwise (5.1); protected records always carry 0x0303. */
int brisk__tls_rec_seal(brisk__tls_dir *d, uint8_t type, uint16_t legacy_ver, const uint8_t *in,
                        size_t len, size_t pad, uint8_t *out, size_t cap, size_t *out_len);

/* Open ONE complete record in place, rec[0..rec_len) with rec_len == 5 + the header length, any
 * alignment. The header's type and version are not checked (the version MUST be ignored, 5.1;
 * both are AAD). BRISK_OK: *type = the inner type 21..23 (or the plaintext type 20..23),
 * content at rec + 5, *len bytes; seq++ (protected only). BRISK_E_AUTH (*alert = bad_record_mac,
 * content wiped, seq unchanged), BRISK_E_PROTO (*alert = record_overflow / unexpected_message)
 * or BRISK_E_ARG (rec_len disagrees with the header). The CCS drop rule, alert parsing and
 * record ordering are the caller's (conn's) job. */
int brisk__tls_rec_open(brisk__tls_dir *d, uint8_t *rec, size_t rec_len, uint8_t *type, size_t *len,
                        uint8_t *alert);

/* The sans-I/O connection. conn_init hooks itself into hs->cfg.on_secret, so hs must be
 * hs_init'ed first, and hs_client_hello'd before the first conn_pull. */
typedef struct {
    brisk__tls13_hs *hs;
    brisk__tls_dir rd, wr;
    uint8_t pend[BRISK_HASH_MAX_LEN]; /* send secret waiting for the earlier epoch to drain */
    uint8_t *in;                      /* the caller's >= BRISK__TLS_REC_IN_MAX byte buffer */
    size_t in_cap, in_len, app_off, app_len;
    uint16_t pend_suite;
    uint8_t pend_epoch; /* 0 = no pending send secret */
    uint8_t ccs_sent;   /* Appendix E.4 compat CCS already emitted */
    uint8_t ku_owe;     /* a KeyUpdate(update_not_requested) must precede the next record */
    uint8_t close;      /* 1 close_notify queued, 2 sent */
    uint8_t eof;        /* close_notify received */
    uint8_t alert;      /* the fatal alert we send once failed */
    uint8_t alert_sent;
    uint8_t peer_alert; /* the peer's fatal alert (BRISK_E_PEER_ALERT) */
#if BRISK_ENABLE_TLS12
    /* TLS 1.2: the receive key || iv waits here for the server's CCS (RFC 5246 7.1); hr = 1 a
     * no_renegotiation warning is owed for the first HelloRequest, 2 it was sent (RFC 5746 4.2) */
    uint8_t rpend[32 + 12];
    uint16_t rpend_suite;
    uint8_t rpend_set, hr;
#endif
    int err; /* sticky once failed */
} brisk__tls13_conn;

/* BRISK_E_ARG if a pointer is NULL or cap < BRISK__TLS_REC_IN_MAX. */
int brisk__tls13_conn_init(brisk__tls13_conn *c, brisk__tls13_hs *hs, uint8_t *rec_in, size_t cap);
/* The brisk__tls13_secret_fn conn_init installs (ctx = c). Receive secrets install at once (the
 * record in hand is already open, and the engine refuses bytes after SH / server Finished in
 * it); a send secret waits until every hs_pull byte of the earlier epoch has been sealed, so
 * c_ap protects only what follows the client Finished (RFC 9846 4, handshake.c contract).
 * TLS 1.2 suites (secret = key || fixed_iv): the send key installs once the plaintext client
 * flight is sealed (it protects the Finished, after the mandatory CCS); the receive key waits
 * in rpend for the server's CCS (RFC 5246 7.1) - see brisk__tls12_on_ccs. */
int brisk__tls13_conn_on_secret(void *ctx, unsigned epoch, int is_send, uint16_t suite,
                                const uint8_t *secret, size_t len);
/* Absorb wire bytes in any split; *used = bytes taken. Stops early (short *used) while
 * decrypted application data is undrained: conn_read, then feed the rest. After close_notify
 * every byte is taken and ignored. BRISK_OK, BRISK_E_AUTH / E_PROTO / E_ARG (sticky, the alert
 * queued for conn_pull) or BRISK_E_PEER_ALERT. */
int brisk__tls13_conn_feed(brisk__tls13_conn *c, const uint8_t *in, size_t len, size_t *used);
/* Drain decrypted application data. *n = 0 with c->eof set after close_notify. */
int brisk__tls13_conn_read(brisk__tls13_conn *c, uint8_t *out, size_t cap, size_t *n);
/* Whole records of pending protocol output: the ClientHello (plaintext), the compat CCS, the
 * handshake flight, an owed KeyUpdate, close_notify, or - once failed - the one fatal alert.
 * Returns the bytes written; 0 when nothing is pending or the next record does not fit. */
size_t brisk__tls13_conn_pull(brisk__tls13_conn *c, uint8_t *out, size_t cap);
/* Seal application data: first whatever conn_pull would emit (the client Finished, an owed or
 * 5.5-threshold KeyUpdate), then records of at most min(peer record_size_limit, 2^14 + 1) - 1
 * content bytes (RFC 8449 4). *used = plaintext consumed, *out_len = wire bytes; a short *used
 * means out is full. BRISK_E_ARG before CONNECTED or after conn_close; the sticky code once
 * failed. */
int brisk__tls13_conn_write(brisk__tls13_conn *c, const uint8_t *data, size_t len, size_t *used,
                            uint8_t *out, size_t cap, size_t *out_len);
/* Queue close_notify {1, 0} (RFC 9846 6.1) for conn_pull; the write side is closed after it. */
int brisk__tls13_conn_close(brisk__tls13_conn *c);
/* Wipe both directions, the pending secret, the engine and the receive buffer. Safe on NULL. */
void brisk__tls13_conn_wipe(brisk__tls13_conn *c);
/* A LOCAL fatal condition found by the layer above (conn.c: a ClientHello2 it cannot build):
 * the same sticky path as the connection's own failures - `alert` queued for conn_pull, every
 * secret forgotten. Returns the sticky code (`err`, or an earlier one). */
int brisk__tls13_conn_abort(brisk__tls13_conn *c, uint8_t alert, int err);

/* x509/chain.c: an ECDSA-Sig-Value (strict DER, RFC 5480 A.1) as the fixed-width r || s of
 * 2 * flen bytes. BRISK_E_ARG on any encoding error, negative or over-wide integer, trailing
 * byte. Shared by certificate signatures and the CertificateVerify. */
int brisk__x509_ecdsa_raw(const uint8_t *sig, size_t sig_len, size_t flen, uint8_t *out);

#if BRISK_ENABLE_MTLS
/* x509/chain.c: the inverse for P-256 - r || s as a minimal DER ECDSA-Sig-Value (X.690 8.3.2:
 * leading zero octets stripped, 0x00 prepended when the top bit is set). Returns the length,
 * 8..72. The client CertificateVerify's encoder (RFC 9846 4.3.3). */
size_t brisk__x509_ecdsa_der(const uint8_t raw[64], uint8_t out[72]);
#endif

/* ---- tls/conn.c: the public connection (brisk_conn), sans-I/O ----------------------------------
 *
 * Glue, not protocol: one brisk__tls13_hs + brisk__tls13_conn wired to the caller's brisk_cfg -
 * the ClientHello pair (CH1 at setup, CH2 inside brisk_feed after an HRR), the X.509
 * authenticator with the in-memory + file trust store, ALPN, ticket import/export. No syscall,
 * no malloc, no clock: randomness and time come in through brisk__conn_setup, whose public
 * wrapper brisk_conn_init lives in src/os/linux_net.c.
 *
 * RANDOMNESS: BRISK__CONN_RAND bytes per connection, drawn once, in this order: client random
 * 32 | legacy_session_id 32 (TCP compatibility mode, RFC 9846 E.4) | x25519 d 32 | P-256 d 32
 * (must satisfy brisk__p256_scalar_valid - the OS layer redraws it) | sign_rand 32 (the RFC 6979
 * 3.6 k' of the client CertificateVerify). SECRET; the two key slices are wiped once CH2 is
 * queued or the ServerHello is processed, the rest at conn_wipe. The fixed layout is what lets
 * tests/test_conn.c replay tools/kat.py flows byte for byte.
 *
 * MEMORY: [align slack | struct brisk_conn | rec_in BRISK__TLS_REC_IN_MAX | hs scratch]. The hs
 * scratch lives as long as the connection: record.c feeds post-handshake NewSessionTicket and
 * KeyUpdate through the engine's reassembly buffer. The blocking layer appends BRISK__CONN_TX
 * (records to send) and BRISK__CONN_RX (received bytes, kept apart because brisk_feed stops
 * short while application data is unread) to the same single malloc.
 *
 * STACK (-fstack-usage, gcc -Os, x86_64): the ticket callback is 2160 B (its BRISK_TICKET_MAX
 * blob) under hs_feed's 512 and brisk_feed's 128 - about 2.9 KB with record.c in between, still
 * below the authenticator's ~4.9 KB chain (the handshake.c STACK note). conn_hello is 496,
 * brisk__conn_setup 320. Move the blob into the arena if an 8 KB thread budget ever needs it. */
#define BRISK__CONN_RAND 160
#define BRISK__CONN_TX   4096
#define BRISK__CONN_RX   2048

struct brisk_conn {
    brisk__tls13_hs hs;
    brisk__tls13_conn tc;
    brisk__tls13_auth_x509_ctx auth;
    brisk__x509_trust trust;
    brisk__x509_bundle bundle; /* the file store, and the PEM decode scratch for cfg.ca_mem */
    brisk_cfg cfg;
    brisk__x509_anchor_fn sys_anchor; /* the file / system store; NULL = memory anchors only */
    uint8_t rnd[BRISK__CONN_RAND];    /* SECRET, layout above */
    uint8_t key[32]; /* SECRET: cfg.client_key parsed once (RFC 5915 d); hs.cfg.client_key points
                        here; wiped with the rest of *c by brisk_conn_wipe and on setup failure */
    uint8_t alpn[BRISK__TLS13_ALPN_MAX];
    uint16_t alpn_len;
    char host[256]; /* NUL-terminated copy of the caller's host */
    size_t host_len;
    uint16_t port;  /* brisk_connect's port (0 = unknown: sans-I/O / test fd) - the h2 :authority */
    int64_t now_ms; /* wall clock: ticket age / stamp; auth.now holds the same in seconds */
    int64_t ch1_ms; /* now_ms when CH1 was built: CH2 re-imports its PSK at that time (4.2.2) */
    /* blocking layer (src/os/linux_net.c) only; fd = -1 and the rest 0 for sans-I/O */
    int fd, io_err;
    uint8_t fixed_now; /* test seam: never refresh now_ms from the clock */
    uint32_t timeout_ms;
    uint8_t *heap, *tx, *rx;
    size_t heap_len, rx_off, rx_len;
#if BRISK_ENABLE_QUIC
    /* QUIC mode (src/quic/api.c): no record layer (tc unused), the ClientHello is built with
     * no session id (RFC 9001 8.4), no TLS 1.2 offer (4.2) and these transport parameters
     * (8.2); suites NULL = the engine's default list */
    const uint8_t *quic_tp;
    size_t quic_tp_len;
    const uint16_t *suites;
    size_t n_suites;
    uint8_t quic;
#endif
};

/* brisk_conn_init without the OS: `rnd` as above, `now_ms` the wall clock in ms since the epoch
 * (int64, never time_t), `sys_anchor` the file / system store lookup (brisk__os_ca_anchor on
 * Linux, NULL where there is none: then only cfg.ca_mem anchors exist). */
int brisk__conn_setup(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                      int64_t now_ms, const uint8_t rnd[BRISK__CONN_RAND],
                      brisk__x509_anchor_fn sys_anchor, brisk_conn **out);
/* The per-connection randomness of brisk_conn_init: BRISK__CONN_RAND bytes, the P-256 slice
 * redrawn until valid. BRISK_OK or BRISK_E_RNG (rnd wiped). Linux (src/os/linux_net.c). */
int brisk__conn_rand(uint8_t rnd[BRISK__CONN_RAND]);
/* Refresh the wall clock (ms) used for the certificate check and ticket stamps. */
void brisk__conn_set_time(brisk_conn *c, int64_t now_ms);
/* The connection's brisk__x509_anchor_fn (ctx = the brisk_conn): cfg.ca_mem's certificates
 * with a matching subject first, then the file store, numbered on from there. */
int brisk__conn_anchor(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                       brisk__x509_cert *out);
/* "h2,http/1.1" -> RFC 7301 ProtocolName entries (u8 length + name each, no outer length).
 * BRISK_E_ARG on an empty name or more than cap bytes. NULL list = *out_len 0. */
int brisk__alpn_encode(const char *list, uint8_t *out, size_t cap, size_t *out_len);

#if BRISK_ENABLE_QUIC
/* ---- quic/packet.c: QUIC v1 packets and packet/header protection (RFC 9000 17, RFC 9001 5) ----
 * Stateless codecs: varints, packet numbers, header parsing, Initial secrets, per-level
 * key/iv/hp and seal/open. Internal only; the public brisk_quic_* surface comes with streams. */
#    define BRISK__QUIC_V1          0x00000001u
#    define BRISK__QUIC_MAX_CID     20   /* RFC 9000 17.2 */
#    define BRISK__QUIC_MIN_INITIAL 1200 /* RFC 9000 14.1 */
#    define BRISK__QUIC_VARINT_MAX  (((uint64_t)1 << 62) - 1)
#    define BRISK__QUIC_TOKEN_MAX   256 /* Retry token kept (policy: a longer one -> discarded) */
enum {
    BRISK__QPKT_INITIAL = 0,
    BRISK__QPKT_0RTT = 1,
    BRISK__QPKT_HANDSHAKE = 2,
    BRISK__QPKT_RETRY = 3,
    BRISK__QPKT_1RTT = 4,
    BRISK__QPKT_VN = 5
};
/* QUIC transport error codes (RFC 9000 20.1) + the CRYPTO_ERROR base (RFC 9001 4.8) */
enum {
    BRISK__QERR_NO_ERROR = 0x00,
    BRISK__QERR_INTERNAL = 0x01,
    BRISK__QERR_FLOW_CONTROL = 0x03,
    BRISK__QERR_STREAM_LIMIT = 0x04,
    BRISK__QERR_STREAM_STATE = 0x05,
    BRISK__QERR_FINAL_SIZE = 0x06,
    BRISK__QERR_FRAME_ENCODING = 0x07,
    BRISK__QERR_TRANSPORT_PARAMETER = 0x08,
    BRISK__QERR_CONNECTION_ID_LIMIT = 0x09,
    BRISK__QERR_PROTOCOL_VIOLATION = 0x0a,
    BRISK__QERR_APPLICATION = 0x0c,
    BRISK__QERR_CRYPTO_BUFFER_EXCEEDED = 0x0d,
    BRISK__QERR_KEY_UPDATE = 0x0e, /* RFC 9001 6.4 */
    BRISK__QERR_AEAD_LIMIT_REACHED = 0x0f,
    BRISK__QERR_VERSION_NEGOTIATION = 0x11, /* RFC 9368 10.2: local abandonment only, never sent */
    BRISK__QERR_CRYPTO = 0x0100
};

/* RFC 9000 16. put: minimal encoding, returns 1/2/4/8, or 0 if v > 2^62-1 or cap is too small.
 * get: 1 and advances *p, or 0 (truncated, *p unchanged). Never reads past end. */
size_t brisk__quic_varint_put(uint8_t *p, size_t cap, uint64_t v);
int brisk__quic_varint_get(const uint8_t **p, const uint8_t *end, uint64_t *v);

/* RFC 9000 A.3: the full PN from `truncated` of nbits (8/16/24/32) given the largest
 * authenticated PN (UINT64_MAX = none yet -> expected 0). Masks and compares only, no branch. */
uint64_t brisk__quic_pn_decode(uint64_t largest, uint64_t truncated, unsigned nbits);
/* RFC 9000 A.2 / 17.1: bytes (1..4) for `pn` given largest_acked (UINT64_MAX = nothing acked
 * -> 4, the full width until the space is acknowledged). */
unsigned brisk__quic_pn_len(uint64_t pn, uint64_t largest_acked);

/* One direction at one encryption level (RFC 9001 5.1). The hp key is its own member: it never
 * changes on a key update (5.4). */
typedef struct {
    union {
        brisk__gcm_key gcm;
        uint8_t chacha[32];
    } k;
    union {
        brisk__aes_key aes;
        uint8_t chacha[32];
    } hp;
    uint8_t iv[12];
    uint16_t suite;    /* 0x1301/0x1302/0x1303; 0 = not installed */
    uint8_t phase;     /* RFC 9001 6: the key phase these keys protect (keys_init: 0) */
    uint64_t n_sealed; /* RFC 9001 6.6 confidentiality counter */
    uint64_t next_pn;  /* seal refuses a lower PN: a nonce is never reused (5.3) */
} brisk__quic_keys;
/* RFC 9001 5.2: both Initial secrets (32 B each) from the client's DCID: 0..20 bytes (a Retry
 * SCID may be empty, 5.2 note; brisk__quic_conn_init still requires >= 8 for the first, 7.2). */
int brisk__quic_initial_secrets(const uint8_t *dcid, size_t dcid_len, uint8_t client[32],
                                uint8_t server[32]);
/* quic key/iv/hp (5.1) from a traffic secret of HashLen(suite) bytes. BRISK_E_ARG, nothing
 * written, on an unknown suite or a wrong length. */
int brisk__quic_keys_init(brisk__quic_keys *k, uint16_t suite, const uint8_t *secret, size_t len);
void brisk__quic_keys_wipe(brisk__quic_keys *k); /* safe on NULL */
/* RFC 9001 6.1: *secret = HKDF-Expand-Label(*secret, "quic ku", "", len) in place, then next =
 * key/iv from it with cur's hp (never re-derived, 6.1), suite, next_pn, phase = !cur->phase and
 * n_sealed = 0 (6.6: a new key, a new count). next == cur is allowed. BRISK_E_ARG, nothing
 * written, if cur has no suite or len != HashLen(suite). */
int brisk__quic_keys_next(brisk__quic_keys *next, const brisk__quic_keys *cur, uint8_t *secret,
                          size_t len);
/* RFC 9001 5.8: BRISK_OK if the last 16 bytes of the Retry (pkt, len) are the integrity tag over
 * odcid_len || odcid || pkt[0..len-16), BRISK_E_AUTH if not (brisk__gcm_open, constant-time
 * compare), BRISK_E_ARG if odcid_len > 20, len < 16 or len - 16 > 47 + BRISK__QUIC_TOKEN_MAX
 * (the pseudo-packet lives in a stack buffer). */
int brisk__quic_retry_verify(const uint8_t *odcid, size_t odcid_len, const uint8_t *pkt,
                             size_t len);

/* Header parse, no crypto (RFC 9000 17.2 / 17.3). A v1 Retry (17.2.5) takes the whole datagram:
 * token = the bytes between the SCID and the 16-byte tag, at least 1 (else BRISK_E_PROTO).
 * `short_dcid_len` = our SCID length. BRISK_OK with h filled and h->pkt_len = bytes of this packet
 * (coalesced: the next one starts there), or BRISK_E_PROTO = discard this packet and the rest of
 * the datagram (never a connection error). A version other than 1 (0 = Version Negotiation) parses
 * only the invariant fields (RFC 8999) and takes the whole datagram; a v1 long header needs Length
 * >= 20 (a full sample, RFC 9001 5.4.2). */
typedef struct {
    uint8_t type, first; /* first = byte 0, still HP-masked */
    uint32_t version;
    const uint8_t *dcid, *scid, *token;
    uint8_t dcid_len, scid_len;
    size_t token_len, pn_off, pkt_len;
} brisk__quic_hdr;
int brisk__quic_hdr_parse(const uint8_t *d, size_t len, size_t short_dcid_len, brisk__quic_hdr *h);

/* Seal in place: pkt[0..pn_off) is the header (Length already set for long headers),
 * pkt[pn_off..pn_off+pn_len) gets the truncated PN, the payload_len bytes after it are plaintext
 * and the 16 bytes after that take the tag. AEAD first, then HP (RFC 9001 5.4.1). BRISK_E_ARG if
 * pn_len + payload_len < 4 (no full sample, the caller pads), pn > 2^62-1, pn_len is not 1..4,
 * no key is installed, or the key reached its 6.6 limit. */
int brisk__quic_seal(brisk__quic_keys *k, uint8_t *pkt, size_t pn_off, unsigned pn_len, uint64_t pn,
                     size_t payload_len);
/* Open in place: remove HP, decode the PN against `largest`, AEAD open. BRISK_OK -> *pn,
 * *payload_off, *payload_len, and *first = unmasked byte 0 (reserved bits are the caller's
 * protocol check). BRISK_E_AUTH = drop (the payload is wiped). BRISK_E_PROTO = too short for a
 * sample, drop. RFC 9001 9.5: no branch on the PN or its length before the AEAD verdict. */
int brisk__quic_open(const brisk__quic_keys *k, uint8_t *pkt, size_t pn_off, size_t pkt_len,
                     uint64_t largest, uint8_t *first, uint64_t *pn, size_t *payload_off,
                     size_t *payload_len);
/* As brisk__quic_open, but a short header whose unmasked Key Phase bit != k->phase is opened
 * with alt (RFC 9001 6.3 / 6.5: the bit alone picks the key set), which must share k's hp;
 * alt == NULL: k always. The bit is declassified before the select (like the PN length); both
 * paths run one AEAD over the same bytes. *first carries the bit. */
int brisk__quic_open_kp(const brisk__quic_keys *k, const brisk__quic_keys *alt, uint8_t *pkt,
                        size_t pn_off, size_t pkt_len, uint64_t largest, uint8_t *first,
                        uint64_t *pn, size_t *payload_off, size_t *payload_len);

/* ---- quic/recovery.c: ACK ranges, RTT, loss detection, PTO, NewReno (RFC 9000 13, RFC 9002) --
 * Pure functions over plain structs: no callbacks, no clock (every call takes now in ms), no
 * division, no float, no variable 64-bit shift. Times are int64 ms; RTTs uint32 ms clamped to
 * 2^24. Levels = packet number spaces: 0 Initial, 1 Handshake, 2 Application. */
#    define BRISK__QUIC_SENT   32   /* sent-packet records, all spaces */
#    define BRISK__QUIC_RANGES 8    /* received-PN ranges per space */
#    define BRISK__QUIC_MDS    1200 /* max_datagram_size: we never send more (RFC 9002 7.2) */
#    define BRISK__QUIC_MINWIN 2400 /* kMinimumWindow = 2 * max_datagram_size (7.2) */

typedef struct {
    uint64_t lo, hi;
} brisk__quic_range;
/* The receive side of one space (RFC 9000 13.2): ranges highest first, r[0].hi = largest. */
typedef struct {
    brisk__quic_range r[BRISK__QUIC_RANGES];
    uint64_t floor;    /* PNs below it are treated as duplicates (13.2.3) */
    int64_t largest_t; /* receive time of the largest */
    int64_t ack_due;   /* INT64_MAX = no ACK owed */
    uint8_t n;         /* ranges used */
    uint8_t pending;   /* ack-eliciting packets not acknowledged yet */
} brisk__quic_rxack;
void brisk__quic_rxack_init(brisk__quic_rxack *a);
/* 1 = duplicate, below the floor, or no room to track it (the caller drops the packet unread).
 * Call after the AEAD accepted the packet and before its frames are processed. */
int brisk__quic_rxack_dup(const brisk__quic_rxack *a, uint64_t pn);
/* Records a PN: 1 = duplicate / dropped (see _dup), 0 = new. An ack-eliciting one makes an ACK
 * due at now + max_delay_ms, or at now when `immediate`, when two are pending (13.2.2) or when it
 * arrived out of order or after a gap (13.2.1). */
int brisk__quic_rxack_add(brisk__quic_rxack *a, uint64_t pn, int ack_eliciting, int64_t now,
                          int64_t max_delay_ms, int immediate);
/* ACK frame 0x02 (19.3) into out: the largest range first, the oldest ranges dropped to fit. 0 if
 * nothing to acknowledge or cap is too small. */
size_t brisk__quic_ack_write(const brisk__quic_rxack *a, uint64_t delay_field, uint8_t *out,
                             size_t cap);
/* 13.2.5: the ACK Delay field for `ms` milliseconds at our ack_delay_exponent (0..20). */
uint64_t brisk__quic_ack_delay_field(int64_t ms, unsigned exp);
/* 19.3: a received ACK Delay field at the peer's exponent, in ms (saturating, 2^24 max). */
uint32_t brisk__quic_ack_delay_ms(uint64_t field, unsigned exp);

enum {
    BRISK__QS_USED = 0x001,
    BRISK__QS_ELICIT = 0x002,   /* ack-eliciting */
    BRISK__QS_INFLIGHT = 0x004, /* counted in bytes_in_flight */
    BRISK__QS_FIN = 0x008,      /* the STREAM frame carried FIN */
    BRISK__QS_MAXDATA = 0x010,  /* carried MAX_DATA */
    BRISK__QS_MSD = 0x020,      /* carried MAX_STREAM_DATA */
    BRISK__QS_RESET = 0x040,    /* carried RESET_STREAM */
    BRISK__QS_RETIRE = 0x080,   /* carried RETIRE_CONNECTION_ID */
    BRISK__QS_MAXSTR = 0x100,   /* carried MAX_STREAMS */
    BRISK__QS_ACKED = 0x200,    /* set by rec_on_ack: newly acknowledged */
    BRISK__QS_LOST = 0x400,     /* set by rec_on_ack / rec_on_timeout: declared lost */
    BRISK__QS_STOP = 0x800      /* carried STOP_SENDING */
};
#    define BRISK__QS_CRYPTO 0xff /* slot: the record carried CRYPTO data */
#    define BRISK__QS_NONE   0xfe /* slot: no CRYPTO / STREAM data */
typedef struct {
    uint64_t pn, off; /* off/len: the CRYPTO or STREAM data it carried */
    int64_t t;        /* send time, ms */
    uint16_t size;    /* bytes of the packet (counted in flight when INFLIGHT) */
    uint16_t len;
    uint16_t flags; /* BRISK__QS_*; 0 = a free record */
    uint8_t lvl, slot;
} brisk__quic_sent;
typedef struct {
    brisk__quic_sent s[BRISK__QUIC_SENT];
    uint64_t largest_acked[3];                  /* UINT64_MAX = none: feeds brisk__quic_pn_len */
    int64_t loss_time[3];                       /* INT64_MAX = not armed (6.1.2) */
    int64_t last_elicit[3];                     /* last ack-eliciting send, INT64_MIN = none */
    int64_t recovery_start;                     /* INT64_MIN = never in recovery (7.3.2) */
    int64_t first_sample_t;                     /* INT64_MAX = no RTT sample yet (7.6.2) */
    uint32_t srtt, rttvar, min_rtt, latest_rtt; /* ms, RFC 9002 5 */
    uint32_t cwnd, ssthresh, in_flight, ca_acc; /* bytes, RFC 9002 7 / B */
    uint8_t has_sample, pto_count, hs_acked;
} brisk__quic_rec;
void brisk__quic_rec_init(brisk__quic_rec *r); /* kInitialRtt 333 ms, cwnd 12000 */
/* s->flags must include BRISK__QS_USED. BRISK_OK, or BRISK_E_WANT when no record is free (the
 * caller does not send an ack-eliciting packet then). */
int brisk__quic_rec_on_sent(brisk__quic_rec *r, const brisk__quic_sent *s);
unsigned brisk__quic_rec_free(const brisk__quic_rec *r); /* free records */
/* One ACK frame after its type byte (ecn = type 0x03): parses it (19.3), marks ACKED / LOST in
 * r->s, updates RTT (5) and NewReno (7). The caller then processes and frees the marked records.
 * 0, FRAME_ENCODING, or PROTOCOL_VIOLATION (largest >= next_pn, 13.1). r == NULL = syntax only.
 * *newly = 1 when something was newly acknowledged (may be NULL). */
uint64_t brisk__quic_rec_on_ack(brisk__quic_rec *r, unsigned lvl, int ecn, const uint8_t **p,
                                const uint8_t *end, uint64_t next_pn, unsigned peer_ack_exp,
                                uint32_t peer_max_ack_delay, int confirmed, int64_t now,
                                int *newly);
/* 1 if a datagram of `bytes` more may be sent now (7). Probes bypass it. */
int brisk__quic_rec_can_send(const brisk__quic_rec *r, size_t bytes);
/* Earliest loss / PTO deadline (6.1.2, 6.2.1, 6.2.2.1) and its space in *lvl; INT64_MAX = none. */
int64_t brisk__quic_rec_deadline(const brisk__quic_rec *r, unsigned *lvl, int confirmed,
                                 int have_hs_keys, uint32_t peer_max_ack_delay);
/* The timer fired (call only when deadline <= now): 0 = a loss-time pass marked records LOST,
 * else the number of probes owed in *lvl (6.2.4). */
unsigned brisk__quic_rec_on_timeout(brisk__quic_rec *r, int64_t now, unsigned *lvl, int confirmed,
                                    int have_hs_keys, uint32_t peer_max_ack_delay);
void brisk__quic_rec_discard(brisk__quic_rec *r, unsigned lvl); /* RFC 9002 6.4 + timer reset */
/* srtt + max(4*rttvar, 1) + max_ack_delay (0 below level 2), without backoff (6.2.1) */
uint32_t brisk__quic_rec_pto(const brisk__quic_rec *r, unsigned lvl, uint32_t peer_max_ack_delay);
/* t + d, saturating at INT64_MAX - 1 (so INT64_MAX keeps meaning "never") */
int64_t brisk__quic_tadd(int64_t t, uint32_t d);

/* ---- quic/conn.c: transport parameters, frames, CRYPTO streams, the client connection -------
 *
 * The client side of RFC 9000/9001 up to a confirmed handshake: Initial/Handshake/1-RTT packet
 * spaces, CRYPTO reassembly per level feeding the TLS 1.3 engine (cfg.quic = 1), transport
 * parameters, ACKs, loss recovery and timers (quic/recovery.c), streams (quic/stream.c),
 * CONNECTION_CLOSE, Retry (17.2.5), Version Negotiation (6.2), stateless reset detection (10.3)
 * and key update (RFC 9001 6). Sans-I/O, no malloc, no clock. */
typedef struct {
    uint64_t max_idle_timeout, max_udp_payload_size, initial_max_data,
        initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni,
        ack_delay_exponent, max_ack_delay, active_connection_id_limit;
    uint8_t odcid[20], iscid[20], retry_scid[20], reset_token[16];
    /* preferred_address: the addresses are ignored (the client never migrates), but its CID is
     * sequence 1 (RFC 9000 5.1.1) and must be retired like any other (5.1.2) */
    uint8_t pref_cid[20], pref_token[16];
    uint8_t odcid_len, iscid_len, retry_scid_len, pref_cid_len;
    uint8_t has_odcid, has_iscid, has_retry_scid, has_reset_token, disable_active_migration,
        has_pref_addr;
} brisk__quic_tp;
/* Zero, then the RFC 9000 18.2 defaults (max_udp_payload_size 65527, ack_delay_exponent 3,
 * max_ack_delay 25, active_connection_id_limit 2). */
void brisk__quic_tp_default(brisk__quic_tp *tp);
/* Client TPs (18.2): every integer that differs from its default, disable_active_migration when
 * set, always initial_source_connection_id (iscid, 7.3), in id order. BRISK_E_ARG with *out_len
 * 0 when a server-only TP is set, a value breaks 18.2, or cap is too small. */
int brisk__quic_tp_write(const brisk__quic_tp *tp, uint8_t *out, size_t cap, size_t *out_len);
/* Server TPs: defaults first, unknown and GREASE ids skipped, every 18.2 rule checked.
 * BRISK_OK or BRISK_E_PROTO (= TRANSPORT_PARAMETER_ERROR) with tp zeroed. */
int brisk__quic_tp_parse(const uint8_t *in, size_t len, brisk__quic_tp *tp);

/* Levels = packet number spaces: 0 Initial, 1 Handshake, 2 Application (1-RTT). */
#    define BRISK__QUIC_CIDS   4 /* server CIDs kept: our active_connection_id_limit is 2..4 */
#    define BRISK__QUIC_RETIRE 8 /* pending RETIRE_CONNECTION_ID: 2 * the limit (5.1.2) */

/* One stream slot (RFC 9000 2-4). The rings live in the connection scratch; offsets are stream
 * offsets, *_pos the ring index of rx_read / tx_base. The flags belong to stream.c. */
typedef struct {
    uint64_t id;
    uint64_t rx_read, rx_hi, rx_max, rx_final, rx_err; /* final UINT64_MAX = not known yet */
    uint64_t tx_base, tx_next, tx_hi, tx_len, tx_max;  /* acked prefix .. written by the app */
    uint64_t ack_lo, ack_hi;                           /* one acked range above tx_base */
    uint64_t tx_err, reset_pn, msd_pn, ss_pn; /* our RESET_STREAM code; last carrying PNs */
    uint32_t rx_pos, tx_pos;
    uint16_t flags;
} brisk__quic_stream;
typedef struct {
    uint64_t seq;
    uint8_t cid[20], token[16], len, used;
    uint8_t has_token; /* 0: seq 0 without a stateless_reset_token TP - never a reset match */
} brisk__quic_cid;
typedef struct {
    uint64_t seq, pn;
    uint8_t state; /* 0 free, 1 to send, 2 in flight in packet pn */
} brisk__quic_retire;

typedef void (*brisk__quic_keylog_fn)(void *ctx, const uint8_t *client_random, unsigned epoch,
                                      int is_send, const uint8_t *secret, size_t len);
struct brisk__quic_conn {
    brisk__tls13_hs *hs;
    brisk__quic_keys rx[3], tx[3];
    brisk__quic_keys rx_ku;  /* RFC 9001 6.3 / 6.5: the other 1-RTT key phase - the next keys, or
                              * the previous ones until ku_until */
    int64_t ku_until;        /* INT64_MAX: rx_ku holds the next keys; INT64_MAX - 1: the previous
                              * ones, kept until a packet opens with the new keys (6.1) */
    uint64_t ku_min, ku_max; /* 6.4: PNs opened with the current rx keys - the lowest and the
                              * largest + 1 (UINT64_MAX / 0: none yet) */
    uint64_t ku_tx_first;    /* 6.1: the first PN sent in the current key phase */
    int64_t ku_ack_at;       /* 6.5: we may initiate an update from here - 3 * PTO after the ACK
                              * confirming the current phase (INT64_MAX: none yet; 0 at start) */
    brisk__quic_tp peer_tp;  /* the server's (defaults until its EE) */
    brisk__quic_tp my_tp;    /* ours, as sent: every limit we enforce comes from here */
    brisk__quic_rec rec;
    brisk__quic_rxack rxa[3];
    uint64_t rx_largest[3]; /* largest authenticated PN, UINT64_MAX = none (A.3 decoding) */
    uint64_t tx_pn[3];      /* next PN to send */
    uint64_t crx[3];        /* CRYPTO bytes delivered to TLS per level */
    uint64_t auth_fail;     /* RFC 9001 6.6: packets that failed authentication */
    uint64_t n_opened;      /* packets that passed the AEAD (tests) */
    uint64_t err_code;      /* the QUIC error code once failed (the peer's on a peer close) */
    uint64_t pend_err;      /* set by a callback that refused, read when the engine fails */
    /* flow control (RFC 9000 4): tx = the peer's limits on us, rx = ours on the peer */
    uint64_t max_data_tx, sent_tx;          /* MAX_DATA; sum of the highest offsets sent */
    uint64_t max_data_rx, sum_rx, consumed; /* advertised; highest offsets received; read */
    uint64_t md_pn;                         /* PN of the last MAX_DATA sent */
    uint64_t next_local[2], next_peer[2];   /* [0] bidi [1] uni: streams opened so far */
    uint64_t accepted[2];                   /* peer streams reported by stream_accept */
    uint64_t peer_max_streams[2], my_max_streams[2], ms_pn[2];
    brisk__quic_stream st[BRISK_QUIC_MAX_STREAMS];
    /* connection IDs (RFC 9000 5.1) */
    brisk__quic_cid cids[BRISK__QUIC_CIDS];
    brisk__quic_retire rq[BRISK__QUIC_RETIRE];
    uint64_t rpt_max;
    /* timers (sans-I/O: every time is the caller's now_ms, clamped monotonic) */
    int64_t now, idle_start, burst_t;
    uint32_t burst_bytes;
    /* scratch carve-up: [CRYPTO ring | its bitmap | Initial CRYPTO out | Handshake CRYPTO out |
     * stream rings]. The CRYPTO out areas keep every byte sent for retransmission; after a
     * failure the Initial one holds the CONNECTION_CLOSE datagram. */
    uint8_t *ring, *bits, *ret[2], *srings;
    size_t ring_pos, ret_cap[2], ret_len[2], ret_sent[2], cc_len;
    int err;
    uint8_t ap_secret[2][48]; /* RFC 9001 6: the 1-RTT secrets [0] receive [1] send, kept for
                               * key update (M6 item 3); the engine wipes its own copies */
    uint8_t path_resp[2][8];  /* RFC 9000 8.2.2: PATH_CHALLENGE data owed a PATH_RESPONSE */
    uint8_t dcid[20], scid[20], odcid[20], server_scid[20]; /* server_scid: of its Initial */
    uint8_t dcid_len, scid_len, odcid_len, server_scid_len, ap_len, n_path_resp;
    uint8_t rx_level;    /* level whose CRYPTO stream the ring holds */
    uint8_t got_initial; /* the first server Initial switched dcid (RFC 9000 7.2) */
    uint8_t tp_seen, established, confirmed;
    uint8_t cc_state; /* 1 a CONNECTION_CLOSE waits in ret[0], 2 sent */
    uint8_t probe[3]; /* PTO probes owed per space (RFC 9002 6.2.4) */
    uint8_t md_pend, ms_pend[2], rx_elicit, idle_rx;
    uint8_t token[BRISK__QUIC_TOKEN_MAX]; /* RFC 9000 17.2.5.2: echoed in every later Initial */
    uint16_t token_len;
    uint8_t retry_scid[20], retry_scid_len, retry_done; /* 7.3: checked against the TP */
    uint8_t key_phase; /* RFC 9001 6: the phase we send (and currently receive) */
    uint8_t dcid_unsent; /* RFC 9000 10.3.1: switched to a new server CID, nothing sent on it */
    /* test / interop-harness seam, NULL by default and never reachable from brisk.h: every
     * Handshake and 1-RTT secret as the engine exports it (NSS SSLKEYLOGFILE lines) */
    brisk__quic_keylog_fn keylog;
    void *keylog_ctx;
    const uint8_t *keylog_random; /* the 32-byte client random passed to keylog */
};
typedef struct brisk__quic_conn brisk__quic_conn;
/* CRYPTO reassembly (BRISK_QUIC_CRYPTO_BUF + bitmap) + send retention + the stream rings
 * (BRISK_QUIC_MAX_STREAMS * (2 * BRISK_QUIC_STREAM_BUF + BRISK_QUIC_STREAM_BUF / 8)). */
size_t brisk__quic_scratch_size(void);
/* Takes over hs->cfg.on_secret / on_peer_tp. hs must be hs_init'ed with cfg.quic = 1. tp: our
 * transport parameters, exactly as the caller encodes them into the ClientHello (copied into
 * q->my_tp). dcid: 8..20 unpredictable bytes (RFC 9000 7.2); scid 0..20 bytes. BRISK_E_ARG
 * otherwise, or when tp->iscid differs from scid (7.3), a stream window exceeds
 * BRISK_QUIC_STREAM_BUF, initial_max_data exceeds MAX_STREAMS * STREAM_BUF, the stream counts
 * exceed MAX_STREAMS, or active_connection_id_limit exceeds 4. Caller order: brisk__quic_tp_write
 * -> brisk__tls13_ch_write(quic_tp, session_id_len 0, tls12 0) -> brisk__tls13_hs_client_hello
 * -> brisk__quic_send. After an HRR (hs->state WAIT_CH2) the caller builds and absorbs CH2 the
 * same way. */
int brisk__quic_conn_init(brisk__quic_conn *q, brisk__tls13_hs *hs, const brisk__quic_tp *tp,
                          const uint8_t *dcid, size_t dcid_len, const uint8_t *scid,
                          size_t scid_len, uint8_t *scratch, size_t scratch_len);
/* One received UDP datagram, decrypted in place, coalesced packets one by one (RFC 9000 12.2).
 * Due timers run first. BRISK_OK (dropped packets are not errors), or the sticky BRISK_E_PROTO /
 * E_AUTH / E_ARG (q->err_code = the QUIC error code), BRISK_E_PEER_ALERT (the peer's
 * CONNECTION_CLOSE; a stateless reset, 10.3, err_code 0; a Version Negotiation without v1,
 * 6.2, err_code 0x11) or BRISK_E_IO (idle timeout, RFC 9000 10.1: closed silently - never
 * BRISK_E_TIMEOUT, which the blocking API uses for a harmless stall).
 * Call brisk__quic_send after every recv: data owed at once (a Retry's resent ClientHello, an
 * ACK) is not reported by brisk__quic_deadline. */
int brisk__quic_recv(brisk__quic_conn *q, uint8_t *dgram, size_t len, int64_t now_ms);
/* The next datagram (at most 1200 bytes; one carrying an Initial or a PATH_RESPONSE is padded
 * to 1200), 0 = nothing to send now or cap < 1200. Due timers run first. Coalesces Initial,
 * Handshake and 1-RTT packets (12.2). After a failure or close: one CONNECTION_CLOSE datagram,
 * then 0. */
size_t brisk__quic_send(brisk__quic_conn *q, uint8_t *out, size_t cap, int64_t now_ms);
/* The earliest of the loss / PTO timer, an owed ACK, the idle timeout and the pacing wait:
 * absolute ms, INT64_MAX = none. Call send/recv with now_ms >= it. */
int64_t brisk__quic_deadline(const brisk__quic_conn *q);
/* Close with an application error code (RFC 9000 10.2): CONNECTION_CLOSE 0x1d in 1-RTT once
 * established, else 0x1c APPLICATION_ERROR in Initial/Handshake (10.2.3: no application code
 * there). The next send returns the datagram. BRISK_OK, or the sticky error. */
int brisk__quic_close(brisk__quic_conn *q, uint64_t app_err);
/* 1 once the engine is CONNECTED and the 7.3 CID checks passed; the TPs are in q->peer_tp. */
int brisk__quic_established(const brisk__quic_conn *q);
/* Interop seam (keyupdate case): initiate a key update when RFC 9001 6.1 / 6.5 allow it -
 * confirmed, the next receive keys ready (the previous ones dropped), an ACK for a packet of
 * the current phase, 3 * PTO after it - else BRISK_E_WANT. BRISK_OK, or the sticky error. */
int brisk__quic_key_update(brisk__quic_conn *q);
/* The frames of one decrypted payload at `level` (RFC 9000 12.4, 19). q == NULL checks syntax
 * and Table 3 only (tests, fuzzing). 0 or the QUIC error code. */
uint64_t brisk__quic_frames(brisk__quic_conn *q, unsigned level, const uint8_t *p, size_t len);

/* ---- quic/stream.c: streams and flow control (RFC 9000 2-4, 19.4-19.14) --------------------
 * Fixed slots; a peer stream's slot is reserved for as long as our MAX_STREAMS credit allows it
 * to be opened, so the implicit opening of lower ids (3.2) always finds one. The public
 * brisk_quic_* comes with the item-4 interop harness / M7, as an opaque handle. */
void brisk__quic_streams_init(brisk__quic_conn *q); /* at establishment: limits from both TPs */
/* id >= 0; BRISK_E_WANT = the peer's MAX_STREAMS reached, or no slot free outside the peer's
 * reservation yet (one frees once a finished stream's FIN is ACKed / its data read); BRISK_E_ARG
 * = not established, or closed. */
int64_t brisk__quic_stream_open(brisk__quic_conn *q, int bidi);
/* Bytes copied into the send ring (0..n, less when full); fin once all n are taken. BRISK_E_ARG
 * on a receive-only / unknown / finished stream or a closed connection; BRISK_E_PEER_ALERT after
 * the peer's STOP_SENDING. */
int brisk__quic_stream_write(brisk__quic_conn *q, uint64_t id, const uint8_t *d, size_t n, int fin);
/* > 0 bytes in order; 0 = FIN consumed; BRISK_E_WANT = nothing yet; BRISK_E_PEER_ALERT =
 * RESET_STREAM (*app_err set); BRISK_E_ARG = unknown / send-only / closed. Consuming queues
 * MAX_STREAM_DATA / MAX_DATA. */
int brisk__quic_stream_read(brisk__quic_conn *q, uint64_t id, uint8_t *out, size_t cap,
                            uint64_t *app_err);
/* The next peer-opened stream not reported yet: BRISK_OK with *id, or BRISK_E_WANT. */
int brisk__quic_stream_accept(brisk__quic_conn *q, uint64_t *id);
/* Abort a stream locally (RFC 9000 2.4, 3.5) with application code app_err: dirs & 1 = reset
 * our sending part (RESET_STREAM, final size = the highest offset sent; nothing if every byte
 * and the FIN were acknowledged), dirs & 2 = abort reading (STOP_SENDING unless the final size
 * is already reached; data that still arrives is counted for flow control and dropped). The
 * slot frees once the RESET_STREAM is ACKed and the peer's final size is known. BRISK_OK, or
 * BRISK_E_ARG (unknown / closed stream, code > 2^62-1). */
int brisk__quic_stream_abort(brisk__quic_conn *q, uint64_t id, uint64_t app_err, unsigned dirs);
/* Frame handlers (level 2 only): 0 or a QUIC error code. STREAM 0x08..0x0f. */
uint64_t brisk__quic_stream_frame(brisk__quic_conn *q, uint64_t id, uint64_t off, const uint8_t *d,
                                  size_t n, int fin);
/* RESET_STREAM 0x04 (a = code, b = final size), STOP_SENDING 0x05 (a = code), MAX_STREAM_DATA
 * 0x11 (a), STREAM_DATA_BLOCKED 0x15 (a). */
uint64_t brisk__quic_stream_ctl(brisk__quic_conn *q, uint64_t type, uint64_t id, uint64_t a,
                                uint64_t b);
/* MAX_DATA 0x10, MAX_STREAMS 0x12 (bidi) / 0x13 (uni): a value that does not raise the limit
 * is ignored (4.1, 4.6). */
void brisk__quic_stream_limits(brisk__quic_conn *q, uint64_t type, uint64_t v);
/* The stream frames of one 1-RTT packet into out (room bytes): RESET_STREAM, MAX_DATA,
 * MAX_STREAM_DATA, MAX_STREAMS, then STREAM data of one stream within both flow-control limits
 * unless `ctl_only`. Sets s->flags / slot / off / len; s->pn is the packet's. Returns bytes. */
size_t brisk__quic_stream_out(brisk__quic_conn *q, uint8_t *out, size_t room, int ctl_only,
                              brisk__quic_sent *s);
/* A record rec_on_ack / rec_on_timeout marked ACKED or LOST (RFC 9000 13.3). */
void brisk__quic_stream_record(brisk__quic_conn *q, const brisk__quic_sent *s);
void brisk__quic_streams_wipe(brisk__quic_conn *q); /* every ring and slot */

/* ---- tls/conn.c, shared with quic/api.c (QUIC builds only; static otherwise) ---------- */
/* The front half both transports share: `c` (already aligned) is zeroed and filled from cfg /
 * host / rnd - trust store, X.509 authenticator, ALPN, ticket hooks - and its engine initialised
 * over hs_scratch (brisk__tls13_hs_scratch_size() bytes), with cfg.quic = quic. BRISK_E_ARG on a
 * bad host, ca_mem / client_chain mismatch or an ALPN list that does not encode. */
int brisk__conn_core(brisk_conn *c, const brisk_cfg *cfg, const char *host, int64_t now_ms,
                     const uint8_t rnd[BRISK__CONN_RAND], brisk__x509_anchor_fn sys_anchor,
                     int quic, uint8_t *hs_scratch);
/* The ClientHello the engine's state asks for (CH1 in START, CH2 in WAIT_CH2, RFC 9846 4.1.4),
 * built in buf (2048 bytes) and absorbed; then, once CH2 is queued or the ServerHello is in,
 * the two ECDHE private keys in c->rnd are wiped (4.3.8). BRISK_OK when nothing is owed. */
int brisk__conn_next_hello(brisk_conn *c, uint8_t *buf);

/* ---- quic/api.c: the public brisk_quic (sans-I/O glue) ---------------------------------------
 * [align slack | struct brisk_quic | hs scratch | quic scratch]: the TLS front half of
 * brisk_conn (cfg, host, ALPN, trust store, authenticator, tickets) without its record layer,
 * plus the transport. RANDOMNESS: BRISK__QUIC_RAND = the 160 bytes of brisk_conn (the session id
 * slice unused over QUIC) + the first DCID 8 + our SCID 8 (RFC 9000 7.2 / 7.3). */
#    define BRISK__QUIC_RAND   (BRISK__CONN_RAND + 16)
#    define BRISK__QUIC_RX_MAX 1472 /* the UDP receive buffer = our max_udp_payload_size TP */
#    if BRISK__QUIC_RX_MAX < 1200 || BRISK__QUIC_RX_MAX > 65527
#        error "BRISK__QUIC_RX_MAX: RFC 9000 18.2 max_udp_payload_size is 1200..65527"
#    endif
struct brisk_quic {
    brisk_conn c; /* c.tc unused; c.fd / heap / tx / rx / timeout_ms / io_err: blocking only */
    brisk__quic_conn q;
    /* blocking driver (src/os/linux_udp.c); NULL = sans-I/O. op: BRISK__QIO_* */
    int (*io)(struct brisk_quic *q, int op);
    int64_t last_now; /* the latest now_ms the caller passed */
    int64_t stall;    /* blocking: monotonic ms at which a wait without progress ends */
    uint8_t tp[64];   /* our encoded transport parameters, CH1 and CH2 */
    uint8_t owe;      /* datagrams may be owed now: brisk_quic_deadline says "now" */
};
enum { BRISK__QIO_START = 0, BRISK__QIO_WAIT = 1, BRISK__QIO_FREE = 2, BRISK__QIO_FLUSH = 3 };
/* brisk_quic_init without the OS: rnd as above, wall_ms the wall clock, sys_anchor the file /
 * system store (NULL: cfg.ca_mem only), suites = the TLS 1.3 suites offered (NULL = the
 * engine's default; the interop chacha20 case offers {0x1303}). BRISK_E_ARG (mem wiped). */
int brisk__quic_setup(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                      int64_t wall_ms, const uint8_t rnd[BRISK__QUIC_RAND],
                      brisk__x509_anchor_fn sys_anchor, const uint16_t *suites, size_t n_suites,
                      brisk_quic **out);
/* Blocking handles: one I/O round (flush, wait for a datagram or the next timer, feed):
 * BRISK_OK, BRISK_E_TIMEOUT (cfg.timeout_ms without progress since the last QIO_START) or the
 * sticky error. Sans-I/O handles: BRISK_E_WANT. For modules that drive several streams (h3.c). */
int brisk__quic_wait(brisk_quic *q);

/* ---- os/linux_udp.c: the blocking QUIC driver ------------------------------------------------ */
/* Resolve (first getaddrinfo address), open a non-blocking UDP socket with DF set where the
 * kernel allows it (RFC 9000 14; IP(V6)_PMTUDISC_PROBE: the PMTU cache is ignored) and
 * connect() it. BRISK_OK and *fd, or BRISK_E_IO. */
int brisk__os_udp_connect(const char *host, uint16_t port, int *fd);
/* 1 if a send()/recv() errno means the socket itself is broken (BRISK_E_IO); 0 = only that
 * datagram is lost - ICMP-born errors included (RFC 9000 14.2.1, 21: unauthenticated). */
int brisk__os_udp_fatal(int err);
/* brisk_quic_connect with the seams: fd >= 0 = an already connected datagram socket (consumed:
 * closed on failure), rnd NULL = the kernel's, wall_ms < 0 = the clock, suites as in setup,
 * keylog (may be NULL) installed before the first datagram. */
int brisk__quic_connect_ex(const brisk_cfg *cfg, const char *host, uint16_t port, int fd,
                           const uint8_t *rnd, int64_t wall_ms, const uint16_t *suites,
                           size_t n_suites, brisk__quic_keylog_fn keylog, void *keylog_ctx,
                           brisk_quic **out);
/* Tests: the handshake over a connected socket (socketpair). */
int brisk__quic_connect_fd(const brisk_cfg *cfg, const char *host, int fd, const uint8_t *rnd,
                           int64_t wall_ms, brisk_quic **out);
#endif /* BRISK_ENABLE_QUIC */

#if BRISK_ENABLE_H2
/* ---- http/huffman.c + http/hpack.c: HTTP/2 HPACK (RFC 7541) ----------------------------------
 * Sans-I/O, no malloc, no globals: the caller owns the dynamic-table ring and the scratch.
 * Not constant time (header fields are not secrets in this client). Every decoding error is
 * BRISK_E_PROTO = HTTP/2 COMPRESSION_ERROR, a CONNECTION error (RFC 9113 4.3).
 *
 * NOT done here, and owed by the h2 layer (M4 line 2): the RFC 9113 8.2.1 / 8.3 receive-side
 * field checks (malformed = stream error) - name/value octets, pseudo-header order and presence,
 * connection-specific fields. Run them in the decode callback. HPACK itself accepts any octets. */

/* huffman.c - shared with QPACK (RFC 9204 4.1.1/4.1.2) in M7 */
/* RFC 7541 5.1 prefixed integer. p[0]'s low `n` bits (1..8) start it; the flag bits above them are
 * ignored. On success *v holds the value and *used the octets consumed. BRISK_E_PROTO when the
 * input is truncated, the value exceeds 2^32-1 or there are more than 5 continuation octets;
 * BRISK_E_ARG for NULL pointers or n outside 1..8. */
int brisk__hpack_int_decode(const uint8_t *p, size_t len, unsigned n, uint32_t *v, size_t *used);
/* RFC 7541 5.2 + Appendix B. BRISK_E_PROTO on EOS, padding > 7 bits, non-EOS padding, or output
 * longer than cap (a local limit). An empty input is an empty string. */
int brisk__huff_decode(const uint8_t *in, size_t len, uint8_t *out, size_t cap, size_t *out_len);
/* The same walk without output: BRISK_OK and the decoded length, or BRISK_E_PROTO for an
 * invalid code (so QPACK can tell a coding error from its own buffer limit). */
int brisk__huff_len(const uint8_t *in, size_t len, size_t *out_len);

/* hpack.c */
#    define BRISK__HPACK_NEVER_INDEXED                                                             \
        1u /* 6.2.3: decoder reports it; encoder input asks for it                                 \
            */

typedef struct {
    const uint8_t *name;
    size_t name_len;
    const uint8_t *value;
    size_t value_len;
    unsigned flags; /* BRISK__HPACK_NEVER_INDEXED for Authorization / Cookie style values */
} brisk__hpack_field;

/* Return 0 to continue; any nonzero value aborts the block and is returned as-is. The decoder is
 * then dead. name/value point into the caller's scratch and are valid only during the call.
 * Fields delivered before a later error in the same block must be discarded by the caller: the
 * whole block, and the connection, failed. */
typedef int (*brisk__hpack_field_fn)(void *ctx, const uint8_t *name, size_t name_len,
                                     const uint8_t *value, size_t value_len, unsigned flags);

typedef struct {
    uint8_t *mem;        /* ring, `limit` bytes, caller-owned */
    uint32_t limit;      /* our advertised SETTINGS_HEADER_TABLE_SIZE (<= 65535) */
    uint32_t max;        /* current max from the last 6.3 update (<= limit) */
    uint32_t size;       /* 4.1 accounted size, <= max */
    uint32_t head;       /* ring offset of the oldest entry */
    uint32_t used;       /* ring bytes in use (n + v + 4 per entry) */
    uint32_t count;      /* entries */
    uint8_t need_update; /* RFC 9113 4.3.1: limit < 4096, next block must start with 6.3 */
    uint8_t dead;        /* sticky after any error (RFC 9113 4.3: connection error) */
} brisk__hpack_dec;

/* BRISK_E_ARG if limit > 65535 or (mem == NULL && limit > 0). */
int brisk__hpack_dec_init(brisk__hpack_dec *d, uint8_t *mem, size_t limit);
/* Decode ONE complete field block (HEADERS + CONTINUATION already joined by the h2 layer).
 * scratch/scratch_cap bounds one decoded field (name || value); max_list is our
 * SETTINGS_MAX_HEADER_LIST_SIZE (sum of n + v + 32). BRISK_OK, BRISK_E_PROTO
 * (COMPRESSION_ERROR, sticky), BRISK_E_ARG (NULL arguments), or the callback's nonzero value. */
int brisk__hpack_decode(brisk__hpack_dec *d, const uint8_t *blk, size_t len, uint8_t *scratch,
                        size_t scratch_cap, size_t max_list, brisk__hpack_field_fn fn, void *ctx);

typedef struct {
    uint32_t cur;    /* table max the peer's decoder believes we use: 4096, then 0 once signalled */
    uint8_t pending; /* emit 0x20 (size update 0) at the start of the next block */
} brisk__hpack_enc;

void brisk__hpack_enc_init(brisk__hpack_enc *e);
/* Peer's SETTINGS_HEADER_TABLE_SIZE on receipt of its SETTINGS. Sets pending when v < cur. */
void brisk__hpack_enc_peer_max(brisk__hpack_enc *e, uint32_t v);
/* Encode n fields as one block. BRISK_OK with *out_len set, or BRISK_E_ARG (invalid field per
 * RFC 9113 8.2.1, or out too small) with *out_len = 0 and the state unchanged. Never indexes and
 * never Huffman-encodes (RFC 7541 7.1: no compression-oracle surface) - keep it that way. */
int brisk__hpack_encode(brisk__hpack_enc *e, const brisk__hpack_field *f, size_t n, uint8_t *out,
                        size_t cap, size_t *out_len);
/* RFC 9113 8.2.1: 1 if the field may appear in a well-formed message (name non-empty, no octet
 * 0x00-0x20 / 0x41-0x5a / 0x7f-0xff, ':' only first; value without NUL / LF / CR and without
 * leading or trailing SP / HTAB), else 0. Shared by the encoder and the h2 receive side. */
int brisk__hpack_field_ok(const uint8_t *name, size_t nl, const uint8_t *value, size_t vl);

/* ---- http/h2.c: HTTP/2 frames, streams, flow control (RFC 9113) -------------------------------
 * A pure core (brisk__h2_feed / brisk__h2_pull: frames in, frames out, no I/O) under a thin
 * blocking layer (the public brisk_h2_*) that moves bytes through the two transport callbacks:
 * brisk_read / brisk_write in production (brisk_h2_open, os/linux_net.c), a fake in the tests. */
#    define BRISK__H2_MAX_LIST BRISK_H2_MAX_HEADER_LIST /* = block buffer = scratch */
#    define BRISK__H2_TX       4096 /* outbound frames (control + HEADERS/CONTINUATION/DATA) */
#    define BRISK__H2_RX       1024 /* staging for the transport's reads, fed frame by frame */

/* Same contracts as brisk_read / brisk_write (io = the brisk_conn). */
typedef int (*brisk__h2_rd_fn)(void *io, void *buf, size_t cap);
typedef int (*brisk__h2_wr_fn)(void *io, const void *buf, size_t len);

struct brisk_h2_stream {
    struct brisk_h2 *h;
    uint8_t *ring;        /* BRISK_H2_STREAM_WINDOW + BRISK__H2_MAX_LIST octets: the parked
                           * response fields [u16 nl][u16 vl][name][value]..., then DATA */
    uint32_t id;          /* 0 = free slot */
    int err;              /* this stream's error (BRISK_E_*), 0 = none */
    int32_t swin, rwin;   /* send window (6.9.1, may go negative 6.9.2) / receive window left */
    uint32_t pend;        /* receive credit owed (consumed or padding), not yet WINDOW_UPDATEd */
    uint32_t rhead, rlen; /* ring: oldest byte, bytes in use */
    uint32_t hdr, ready;  /* parked field bytes at the front; DATA bytes of completed frames */
    uint64_t cl, got;     /* content-length (8.1.1) and DATA octets received */
    uint16_t status;
    uint8_t flags; /* H2S_* in h2.c */
    uint8_t n1xx;  /* interim (1xx) responses seen, capped (RFC 9113 10.5) */
};

struct brisk_h2 {
    uint8_t *mem; /* the caller's whole arena (wiped by brisk_h2_close) */
    size_t mem_len;
    brisk__h2_rd_fn rd;
    brisk__h2_wr_fn wr;
    void *io;
    brisk__hpack_dec dec;
    brisk__hpack_enc enc;
    uint8_t *blk, *scratch, *tx, *rx;
    size_t blk_len, tx_len, rx_off, rx_len;
    int err;             /* sticky: connection error (GOAWAY sent) or failed write */
    int eof;             /* transport ended (brisk_read 0 / error): open streams fail */
    int32_t cwin, crwin; /* connection send / receive windows */
    uint32_t cpend;      /* connection receive credit owed */
    uint32_t next_id;    /* next client stream id (odd; > 2^31-1 = exhausted) */
    uint32_t last_id;    /* lowest GOAWAY last_stream_id seen */
    uint32_t p_conc, p_frame, p_list, p_win; /* the server's SETTINGS (6.5.2) */
    uint32_t idle; /* frames without progress in this call (flood guard) */
    uint32_t f_len, f_pos, f_end, f_sid, f_dat; /* frame being parsed; f_dat = DATA ringed */
    struct brisk_h2_stream *f_s;                /* DATA target (NULL = discard) */
    struct brisk_h2_stream *b_s;                /* field block target (NULL = decode only) */
    uint32_t b_sid, b_pre;
    uint64_t b_cl;
    uint16_t b_status, auth_len;
    uint8_t fh[9], fh_n, f_type, f_flags, f_pfx, pad, pb[8], set_n;
    uint8_t in_blk, b_es, b_cont, b_trailer, b_bad, b_seen, b_reg, b_park, b_has_cl;
    uint8_t got_settings, goaway, goaway_err;
    char auth[264]; /* :authority */
    struct brisk_h2_stream s[BRISK_H2_MAX_STREAMS];
};

/* Lay the handle out in mem (any alignment, mem_len >= brisk_h2_size()) and queue the preface,
 * our SETTINGS and (when needed) a connection WINDOW_UPDATE; no I/O. authority = the :authority
 * value (1..255 octets, already bracketed / port-suffixed). BRISK_E_ARG on bad arguments. */
int brisk__h2_setup(void *mem, size_t mem_len, const char *authority, size_t auth_len,
                    brisk__h2_rd_fn rd, brisk__h2_wr_fn wr, void *io, brisk_h2 **out);
/* Blocking: flush, then read and process frames until the server's SETTINGS (RFC 9113 3.4). */
int brisk__h2_start(brisk_h2 *h);
/* The pure core: consume server bytes in any split, at most ONE frame per call (so the blocking
 * layer can stop exactly when its condition holds). *used < len: call again; *used == 0 with
 * BRISK_OK = the tx queue is full, brisk__h2_pull first. BRISK_OK, or the sticky BRISK_E_PROTO
 * (a GOAWAY is queued) / BRISK_E_ARG (internal fault). */
int brisk__h2_feed(brisk_h2 *h, const uint8_t *in, size_t len, size_t *used);
/* Queued outbound bytes, whole frames only, into out[0..cap); returns the count (0 = none). */
size_t brisk__h2_pull(brisk_h2 *h, uint8_t *out, size_t cap);

/* Shared by h2.c and h3.c (RFC 9113 8.x and RFC 9114 4.x ask the same): */
/* RFC 9110 8.6 content-length: 1..19 digits. 1 and *out, else 0. */
int brisk__http_cl_parse(const uint8_t *v, size_t n, uint64_t *out);
/* 1 for connection / proxy-connection / keep-alive / transfer-encoding / upgrade */
int brisk__http_conn_specific(const uint8_t *n, size_t nl);
/* :status value -> 100..599 (never 101), or 0 when malformed */
unsigned brisk__http_status(const uint8_t *v, size_t n);
/* The request checks of brisk_h2_request / brisk_h3_request (method token, not CONNECT; path;
 * every field's octets; no ':' / host / connection-specific; te only "trailers";
 * content-length == body_len; each field n + v + 16 <= max_field). *list = the header section
 * size (n + v + 32 per field, the four pseudo-headers included with :authority auth_len).
 * BRISK_OK or BRISK_E_ARG. */
int brisk__http_req_check(const char *method, const char *path, const brisk_h2_header *hdrs,
                          size_t n, size_t body_len, size_t auth_len, size_t max_field,
                          uint64_t *list);
/* BRISK__HPACK_NEVER_INDEXED for authorization / proxy-authorization / cookie / set-cookie */
unsigned brisk__http_sensitive(const char *name);
/* :authority from a host and port into out (>= host_len + 8): IPv6 literals bracketed,
 * ":port" unless 0 or 443. Returns the length. */
size_t brisk__http_authority(const char *host, size_t host_len, uint16_t port, char *out);
#endif /* BRISK_ENABLE_H2 */

#if BRISK_ENABLE_H3
/* ---- http/qpack.c: QPACK (RFC 9204), static table only ---------------------------------------
 * We advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY 0 and SETTINGS_QPACK_BLOCKED_STREAMS 0 (both
 * the defaults, RFC 9204 5), so the peer's encoder can never insert: every field section has
 * Required Insert Count 0, nothing blocks, no Section Acknowledgment is owed (4.4.1) and we open
 * no encoder / decoder stream of our own (4.2 MAY). Stateless: no dynamic table exists. Not
 * constant time (header fields are not secrets here). */
#    define BRISK__QPACK_DECOMPRESSION_FAILED 0x0200u
#    define BRISK__QPACK_ENCODER_STREAM_ERROR 0x0201u
#    define BRISK__QPACK_DECODER_STREAM_ERROR 0x0202u
/* Internal status only (never returned by a public call): a LOCAL limit was hit - one decoded
 * field larger than the scratch, or the section larger than max_list. HTTP/3 turns it into a
 * stream error (the response is discarded, RFC 9114 4.2.2), not a connection error. */
#    define BRISK__QPACK_E_LIMIT (-64)
/* RFC 9204 4.1.1 (RFC 7541 5.1 with the 62-bit range QPACK needs): p[0]'s low n bits (1..8)
 * start it. BRISK_OK with *v and *used; BRISK_E_WANT = the input ends inside it; BRISK_E_PROTO
 * = above 2^62-1 or more than 10 continuation octets; BRISK_E_ARG = NULL / n out of range. */
int brisk__qpack_int_decode(const uint8_t *p, size_t len, unsigned n, uint64_t *v, size_t *used);
/* One complete encoded field section (a HEADERS frame payload). fn is called per field line
 * with flags = BRISK__HPACK_NEVER_INDEXED for the N bit. scratch bounds one decoded field
 * (name || value), max_list the section (n + v + 32 per field, RFC 9114 4.2.2). BRISK_OK,
 * BRISK_E_PROTO (= QPACK_DECOMPRESSION_FAILED, a connection error: RFC 9204 2.2 / 4.5),
 * BRISK__QPACK_E_LIMIT, BRISK_E_ARG, or fn's nonzero value. Fields delivered before a failure
 * belong to a section that failed: discard them. */
int brisk__qpack_decode(const uint8_t *blk, size_t len, uint8_t *scratch, size_t scratch_cap,
                        size_t max_list, brisk__hpack_field_fn fn, void *ctx);
/* Encode n fields as one section: prefix 00 00 (Required Insert Count 0, Base 0), then per field
 * an indexed static line on an exact match, else a literal with a static name reference, else a
 * literal with a literal name; the N bit for BRISK__HPACK_NEVER_INDEXED; never Huffman (no
 * compression-oracle surface, RFC 9204 7.1). Every field must pass brisk__hpack_field_ok.
 * BRISK_OK with *out_len, or BRISK_E_ARG with *out_len = 0 (invalid field, cap too small). */
int brisk__qpack_encode(const brisk__hpack_field *f, size_t n, uint8_t *out, size_t cap,
                        size_t *out_len);
/* One field line of such a section, without the prefix (h3.c streams a request into its
 * buffer field by field). Same rules and results. */
int brisk__qpack_encode_field(const brisk__hpack_field *f, uint8_t *out, size_t cap,
                              size_t *out_len);
/* The peer's encoder stream (RFC 9204 4.3) / decoder stream (4.4), incremental: whole
 * instructions are consumed, a trailing partial one is left (*used < len - call again with it
 * and more bytes). BRISK_OK, or BRISK_E_PROTO with *err = QPACK_ENCODER_STREAM_ERROR /
 * QPACK_DECODER_STREAM_ERROR (a connection error). With our capacity 0 the encoder stream may
 * only carry Set Dynamic Table Capacity 0; the decoder stream only Stream Cancellation. */
int brisk__qpack_enc_stream(const uint8_t *in, size_t len, size_t *used, uint64_t *err);
int brisk__qpack_dec_stream(const uint8_t *in, size_t len, size_t *used, uint64_t *err);

/* ---- http/h3.c: HTTP/3 (RFC 9114) -------------------------------------------------------------
 * The whole of h3.c talks to QUIC through this seam: the brisk_quic wrappers in h3.c in
 * production (brisk_h3_open), a scripted fake in tests/test_h3.c and fuzz/fuzz_h3.c. Every call
 * is non-blocking except wait. Results follow brisk__quic_stream_*:
 *   read   > 0 bytes, 0 = FIN consumed, BRISK_E_WANT, BRISK_E_PEER_ALERT (RESET_STREAM, *app_err
 *          = its code), BRISK_E_ARG; never a connection error (status reports those)
 *   write  bytes taken (0..n, fin once all n are taken), BRISK_E_PEER_ALERT (STOP_SENDING), < 0
 *   open   the new stream id, BRISK_E_WANT (no credit / slot yet), < 0
 *   accept BRISK_OK and the next server-opened stream, or BRISK_E_WANT
 *   start  a blocking call begins or made progress: restart the stall clock
 *   wait   one I/O round: BRISK_OK, BRISK_E_TIMEOUT (no progress for the timeout), or the
 *          connection's sticky error
 *   abort  brisk__quic_stream_abort; close = close the connection with an H3 / QPACK code
 *   status 0 while the connection lives, else its sticky error */
typedef struct {
    int (*read)(void *io, uint64_t id, uint8_t *buf, size_t cap, uint64_t *app_err);
    int (*write)(void *io, uint64_t id, const uint8_t *buf, size_t n, int fin);
    int64_t (*open)(void *io, int bidi);
    int (*accept)(void *io, uint64_t *id);
    void (*start)(void *io);
    int (*wait)(void *io);
    int (*abort)(void *io, uint64_t id, uint64_t app_err, unsigned dirs);
    void (*close)(void *io, uint64_t app_err);
    int (*status)(void *io);
} brisk__h3_io;
/* Lay brisk_h3 out in mem (any alignment, mem_len >= brisk_h3_size()); no I/O. authority =
 * the :authority value (1..255 octets, already bracketed / port-suffixed). BRISK_E_ARG. */
int brisk__h3_setup(void *mem, size_t mem_len, const char *authority, size_t auth_len,
                    const brisk__h3_io *ops, void *io, brisk_h3 **out);
/* Open our control stream and send its preface (RFC 9114 6.2.1), then serve whatever the
 * server already sent - without waiting for its SETTINGS (7.2.4.2). BRISK_OK or an error. */
int brisk__h3_start(brisk_h3 *h);
/* The control-stream preface: stream type 0x00, then our SETTINGS (MAX_FIELD_SECTION_SIZE =
 * BRISK_H3_MAX_HEADER_LIST and one reserved "grease" setting, 7.2.4.1). Its length, or 0 when
 * cap is too small. */
size_t brisk__h3_settings(uint8_t *out, size_t cap);
#endif /* BRISK_ENABLE_H3 */

/* ---- os/linux_net.c (Linux builds only): clocks and TCP -------------------------------------- */
int64_t brisk__os_wall_ms(void); /* CLOCK_REALTIME, widened; 0 if the clock cannot be read */
int64_t brisk__os_mono_ms(void); /* CLOCK_MONOTONIC: deadlines only */
/* Resolve (getaddrinfo, AF_UNSPEC) and connect a non-blocking TCP socket, trying each address
 * in turn within timeout_ms (after DNS). BRISK_OK and *fd, or BRISK_E_IO / BRISK_E_TIMEOUT. */
int brisk__os_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms, int *fd);
/* Connect to the first address of the getaddrinfo list `res` that answers before the monotonic
 * deadline. Each attempt gets a share of the time left (at least 2 s), so one blackholed
 * address does not starve the next. BRISK_OK and *fd, or BRISK_E_IO / BRISK_E_TIMEOUT. */
struct addrinfo;
int brisk__os_dial(const struct addrinfo *res, int64_t deadline_mono_ms, int *fd);
/* All n bytes, MSG_NOSIGNAL, EINTR retried, polling until the monotonic deadline.
 * BRISK_OK, BRISK_E_IO or BRISK_E_TIMEOUT. */
int brisk__os_send_all(int fd, const uint8_t *p, size_t n, int64_t deadline_mono_ms);
/* Up to cap bytes; *n 0 = the peer closed (TCP EOF). BRISK_OK, BRISK_E_IO or BRISK_E_TIMEOUT. */
int brisk__os_recv(int fd, uint8_t *p, size_t cap, int64_t deadline_mono_ms, size_t *n);
/* Test seam for brisk_connect: handshake over an already connected `fd` (always consumed:
 * closed on failure). rnd NULL = brisk__os_random; now_ms < 0 = the clock, refreshed before
 * every feed; otherwise that fixed time. */
int brisk__connect_fd(const brisk_cfg *cfg, const char *host, int fd, const uint8_t *rnd,
                      int64_t now_ms, brisk_conn **out);

#endif /* BRISK_INT_H */
