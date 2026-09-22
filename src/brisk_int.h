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

#endif /* BRISK_INT_H */
