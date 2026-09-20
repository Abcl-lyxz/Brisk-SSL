/* p256.c - P-256 (secp256r1) ECDHE, ECDSA verify and ECDSA sign on vendored fiat-crypto field
 * arithmetic.
 *
 * RFC 9846 4.3.8.2 (KeyShareEntry encoding and the MUST to validate the peer point), 7.4.2 (the
 * ECDHE shared secret), 4.3.3 (ecdsa_secp256r1_sha256); FIPS 186-5 6.4.2 (verify) and 6.4.1
 * (sign) with the deterministic-plus-hedged nonce of RFC 6979 3.2/3.6; domain parameters from
 * RFC 5903 3.1 = SP 800-186 3.2.1.3 = SEC 2 2.4.2. Signing sits behind BRISK_ENABLE_MTLS: this
 * file is linked into every build for ECDHE, which is mandatory-to-implement, so a TINY image
 * would otherwise carry a signer it never runs.
 *
 * The field layer is vendor/fiat/p256_{64,32}.c, generated and proved by fiat-crypto. Every
 * function there is `static`, so the file is #included here rather than compiled on its own
 * (vendor/VENDORED.md); this translation unit owns the -Wunused-function silencing for what it
 * never calls. Only mul, add, sub, nonzero, to_bytes, from_bytes and set_one are referenced, and
 * the rest is dropped by the compiler. Three substitutions keep that list short, which is what
 * holds the flash promise in docs/ARCHITECTURE.md rather than tripling it on 32-bit targets:
 *   - square       -> mul(a, a)            (~1000 lines on the 32-bit variant)
 *   - to_montgomery-> mul(x, R2), with R2 built at run time by 256 doublings of set_one (~900)
 *   - from_montgomery -> mul(x, 1)         (~540)
 * and Fermat inversion instead of msat/divstep. Both are constant time - fiat's divstep runs a
 * fixed iteration count with cmovznz selection, so this is not a CT argument - but the divstep
 * pair is another large block of generated code on the 32-bit variant.
 *
 * Everything above the field layer is ours: point validation, the complete addition formula, the
 * fixed-step ladder, Fermat inversion, and a small in-house Montgomery core modulo the group
 * order n (the project vendors FIELD arithmetic only).
 *
 * Byte order: two different ones meet here, so neither is left implicit. The wire format is
 * big-endian (RFC 9846 4.3.8.2), unlike X25519's little-endian; fiat's to_bytes/from_bytes are
 * little-endian. be_swap() is the only bridge, every scalar limb is packed with explicit shifts
 * through brisk__load_be32/brisk__store_be32, and no uint8_t * is ever cast to a wider pointer -
 * which is what makes this correct on mips and ppc as well as on x86.
 *
 * Constant time: the ECDH private scalar and the shared secret are secret. The ladder runs a
 * fixed 256 steps with a mask/XOR select, the field inversion walks a fixed exponent chain (never
 * a binary GCD; fiat's divstep would also have done, it is just bigger), and the mod-n inversion
 * walks the bits of the public constant
 * n-2. Five values are declassified, each with its reason written at the point of use: the
 * private-key range verdict in keygen/ECDH/sign, the peer point and its validity verdict, the
 * "the result is the point at infinity" bit in pt_encode, every input to ECDSA verify, and the
 * one-bit "this RFC 6979 candidate was rejected" verdict in the signing retry loop. A caveat
 * valgrind cannot see: on armv5 and MIPS32 the 32x32->64
 * multiply is variable latency, in both fiat p256_32 and the scalar core below - the same caveat
 * already logged for GHASH in docs/ARCHITECTURE.md.
 *
 * Stack: a projective point is 3 field elements (96 bytes); the complete addition holds 8 of them
 * and the ladder keeps an accumulator, an addend and the base alive. Measured with -fstack-usage
 * on gcc 10.3 and summed along the deepest call chain, at the optimisation level named - because
 * the figure is NOT optimisation-independent, and saying so would be the easy lie here:
 *                               ecdh / verify / sign, deepest chain, in bytes
 *   -Os, x86_64 / 64-bit field: 1504 (448 + pt_mul 320 + pt_add 416 + fiat_p256_mul 320)
 *                               1856 (verify 800 + 320 + 416 + 320)
 *                               2688 (sign 832 + verify 800 + 320 + 416 + 320)
 *   -O2, x86_64:                1792 / 2144 / 3200   <- verify and sign both over budget
 *   -O3, x86_64:                1552 / 1904 / 3328   <- sign over budget
 *   -O2, i686 / 32-bit field:   1224 / 1576 / 2296
 * Budget 3 KB with BRISK_ENABLE_MTLS, 2 KB without. Only -Os meets both on the 64-bit field, and
 * that is why -Os is pinned PRIVATE in CMakeLists.txt (so the build type's -O0/-O2 never reaches
 * library code, and there is no -O0 row to quote). Do not raise the level without re-measuring.
 * The sign figure is the fault-check verify nested inside the signing frame:
 * gcc gives brisk__p256_ecdsa_sign 832 B (the inlined rfc6979_ctx, the inlined
 * ecdsa_sign_with_k with its two pt and one 65-byte encoding, and the self-verify's pub[65]) and
 * then brisk__p256_ecdsa_verify's own 800 B sits on top of it. Keeping the DRBG scoped and the
 * verify in a sibling block is what stops it being worse; it cannot be made to disappear, and
 * dropping the countermeasure to save the kilobyte is the one simplification not on offer here.
 * The RFC 6979 branch is shallower, but not by as much as it looks: rfc6979_reseed ends in a real
 * call to rfc6979_v, not a sibling call (&h escapes to brisk__secure_zero), so both frames stack:
 * sign 832 + rfc6979_reseed 496 + rfc6979_v 480 + brisk_hmac_init 368 + brisk__hash_update 8 +
 * brisk_sha512_update 80 + sha512_block 320 = 2584 B at -Os. -O3 inlines fe_inv/fe_pow2k into
 * their callers and pt_add's frame grows 416 -> 560. All of this is above brisk__aes_key's 1.1 KB,
 * and nothing here uses a VLA or malloc to hide it, so these are whole frames and what you measure
 * is what you get - but measure the level you ship.
 *
 * Wipe scope, stated as honestly as the x25519 header states its own: our named locals holding a
 * secret or an intermediate are zeroed before return. What we do not reach is the frame of
 * fiat itself, and the frame of pt_add - it is called 512 times per scalar multiplication, each
 * call's temporaries are immediately overwritten by the next, and only the last call's residue
 * could survive. vendor/fiat/ is edit-blocked, so a stack scan after an ECDH call can still find
 * field-element residue. Closing that means scrubbing the whole stack window below the caller, a
 * separate and deliberate decision - not something this file silently claims to have done.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wunused-function"
#endif
#if BRISK__FIAT_64
#    include "fiat/p256_64.c"
typedef uint64_t p256_limb;
#    define FE_LIMB_BITS 64
#else
#    include "fiat/p256_32.c"
typedef uint32_t p256_limb;
#    define FE_LIMB_BITS 32
#endif
#if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic pop
#endif

typedef fiat_p256_montgomery_domain_field_element fe;

#define FE_LIMBS (sizeof(fe) / sizeof(p256_limb)) /* 4 (64-bit) or 8 (32-bit) */

/* Domain parameters, RFC 5903 3.1, as big-endian byte strings: one spelling, unpacked at run time
 * by the same loader that handles untrusted input, so there is no per-width limb table to get
 * wrong on a big-endian target. tests/test_p256.c pins G (keygen(1) must be exactly G), n (the
 * scalar_valid/reduce boundaries) and p (a peer coordinate equal to p must be rejected) against
 * tests/kat/p256_params.inc, which tools/kat.py parses out of the RFC itself; b is pinned by
 * every on-curve vector at once. */
static const uint8_t P256_P[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t P256_B[32] = {0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD,
                                   0x55, 0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53,
                                   0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};
static const uint8_t P256_N[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
                                   0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
static const uint8_t P256_GX[32] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
static const uint8_t P256_GY[32] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};

/* ------------------------------------------------------------------ big-endian byte helpers */
static void be_swap(uint8_t out[32], const uint8_t in[32])
{
    size_t i;
    for (i = 0; i < 32; i++) {
        out[i] = in[31 - i];
    }
}

/* 1 iff the 32 big-endian bytes at a are numerically below those at b. Constant time: this also
 * runs on the private key, so it must not stop at the first differing byte. */
static uint32_t be_lt(const uint8_t a[32], const uint8_t b[32])
{
    uint32_t borrow = 0;
    size_t i;
    for (i = 32; i-- > 0;) {
        uint32_t d = (uint32_t)a[i] - (uint32_t)b[i] - borrow;
        borrow = (d >> 8) & 1;
    }
    return borrow;
}

/* 1 iff all 32 bytes are zero. Constant time. */
static uint32_t be_is_zero(const uint8_t a[32])
{
    uint32_t acc = 0;
    size_t i;
    for (i = 0; i < 32; i++) {
        acc |= a[i];
    }
    return (acc - 1) >> 31;
}

/* ------------------------------------------------------------------------------ field layer */
/* R^2 mod p, built at run time: fiat_p256_set_one leaves the bit pattern R mod p, so doubling it
 * 256 times gives R * 2^256 = R^2 mod p. This is what replaces fiat_p256_to_montgomery. The cost
 * is 256 field additions once per public call, against the ~7000 field multiplications a scalar
 * multiplication runs - and it buys back ~900 lines of flash on the 32-bit variant. */
static void fe_r2(fe out)
{
    int i;
    fiat_p256_set_one(out);
    for (i = 0; i < 256; i++) {
        fiat_p256_add(out, out, out);
    }
}

/* out = the plain value of a, i.e. a * R^-1. Multiplying by the literal 1 replaces
 * fiat_p256_from_montgomery (~540 lines on the 32-bit variant). */
static void fe_from_mont(fe out, const fe a)
{
    fe one;
    memset(one, 0, sizeof one);
    one[0] = 1; /* limb 0 is the least significant */
    fiat_p256_mul(out, a, one);
}

/* Load a 32-byte big-endian value that is already known to be below p into the Montgomery
 * domain. fiat_p256_from_bytes does NOT reduce, and every Montgomery operation is only proved for
 * inputs below p, so the range check is the caller's precondition - never an afterthought. */
static void fe_load_be(fe out, const uint8_t be[32], const fe r2)
{
    uint8_t le[32];
    be_swap(le, be);
    fiat_p256_from_bytes(out, le);
    fiat_p256_mul(out, out, r2);
    brisk__secure_zero(le, sizeof le);
}

/* Declassify one verdict. Writing it through memory matters: valgrind's client request carries a
 * "memory" clobber, so the compiler has to reload the value afterwards instead of branching on a
 * still-tainted register copy. Compiles to nothing in a normal build. */
static uint32_t ct_public_u32(uint32_t v)
{
    BRISK__CT_PUBLIC(&v, sizeof v);
    return v;
}

/* 1 iff a is zero. fiat keeps every output fully reduced below p, so zero has the unique
 * all-zero limb pattern. */
static uint32_t fe_is_zero(const fe a)
{
    p256_limb nz;
    fiat_p256_nonzero(&nz, a);
    return (uint32_t)(((nz | ((p256_limb)0 - nz)) >> (FE_LIMB_BITS - 1)) ^ 1);
}

/* out = flag ? a : out. Mask/XOR, so both directions run the same instructions - the ladder's
 * only data-dependent step, and it must never become an `if` or an indexed table. */
static void fe_cmov(fe out, const fe a, uint32_t flag)
{
    p256_limb mask = (p256_limb)0 - (p256_limb)flag;
    size_t i;
    BRISK__CT_BARRIER(mask);
    for (i = 0; i < FE_LIMBS; i++) {
        out[i] ^= mask & (out[i] ^ a[i]);
    }
}

/* out = a^(2^k), k >= 1. Squaring is mul(a, a): fiat_p256_square is deliberately never called,
 * being another ~1000 lines on the 32-bit variant for a few percent of speed. out may alias a. */
static void fe_pow2k(fe out, const fe a, unsigned k)
{
    unsigned i;
    fiat_p256_mul(out, a, a);
    for (i = 1; i < k; i++) {
        fiat_p256_mul(out, out, out);
    }
}

/* out = a^(p-2) = 1/a for a != 0, and 0 for a == 0 (the caller treats that as the point at
 * infinity). p-2 is a constant, so the chain is fixed at 255 squarings and 12 multiplications
 * with no data-dependent step: a_k = a^(2^k - 1) for k = 1,2,3,6,12,15,30,32, then the words of
 * p-2 = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFD. out may alias a.
 */
static void fe_inv(fe out, const fe a)
{
    fe a2, a3, a6, a12, a15, a30, a32, t;
    fe_pow2k(a2, a, 1);
    fiat_p256_mul(a2, a2, a); /* 2^2  - 1 */
    fe_pow2k(a3, a2, 1);
    fiat_p256_mul(a3, a3, a); /* 2^3  - 1 */
    fe_pow2k(a6, a3, 3);
    fiat_p256_mul(a6, a6, a3); /* 2^6  - 1 */
    fe_pow2k(a12, a6, 6);
    fiat_p256_mul(a12, a12, a6); /* 2^12 - 1 */
    fe_pow2k(a15, a12, 3);
    fiat_p256_mul(a15, a15, a3); /* 2^15 - 1 */
    fe_pow2k(a30, a15, 15);
    fiat_p256_mul(a30, a30, a15); /* 2^30 - 1 */
    fe_pow2k(a32, a30, 2);
    fiat_p256_mul(a32, a32, a2); /* 2^32 - 1 */

    fe_pow2k(t, a32, 32);
    fiat_p256_mul(t, t, a); /* ... 00000001 */
    fe_pow2k(t, t, 96);     /* ... 96 zero bits */
    fe_pow2k(t, t, 32);
    fiat_p256_mul(t, t, a32);
    fe_pow2k(t, t, 32);
    fiat_p256_mul(t, t, a32);
    fe_pow2k(t, t, 30);
    fiat_p256_mul(t, t, a30);
    fe_pow2k(t, t, 2);
    fiat_p256_mul(out, t, a); /* ... fffffffd */

    brisk__secure_zero(a2, sizeof a2);
    brisk__secure_zero(a3, sizeof a3);
    brisk__secure_zero(a6, sizeof a6);
    brisk__secure_zero(a12, sizeof a12);
    brisk__secure_zero(a15, sizeof a15);
    brisk__secure_zero(a30, sizeof a30);
    brisk__secure_zero(a32, sizeof a32);
    brisk__secure_zero(t, sizeof t);
}

/* ------------------------------------------------------------------------------ point layer */
/* Homogeneous projective coordinates: (X : Y : Z) is the affine (X/Z, Y/Z), and Z == 0 is the
 * point at infinity, written (0 : 1 : 0). */
typedef struct {
    fe x, y, z;
} pt;

/* Complete addition: Renes-Costello-Batina 2015, Algorithm 4 for a = -3 (12M + 2 multiplications
 * by b + 29 additions).
 *
 * "Complete" is the entire reason it is here. The textbook Jacobian formula returns garbage when
 * P == Q and cannot represent infinity as an input, so it has to be paired with a separate
 * doubling and three mask-selects on (u1 == u2 && s1 == s2), Z_P == 0 and Z_Q == 0 - the single
 * most likely correctness bug in a P-256 implementation, and exactly what Wycheproof's 204
 * EdgeCaseDoubling rows hunt for. This formula has no exceptional case at all: P == Q, P == -Q
 * and either input at infinity all come out right with no detection logic. It is also the smaller
 * of the two, because doubling is just pt_add(P, P) and no second formula needs to exist.
 *
 * `bm` is the curve b in the Montgomery domain. out may alias pp and/or qq: every result lands in
 * a local first (line 10 overwrites X3 while X1 is still live).
 *
 * Not wiped: this runs 512 times per scalar multiplication, each call's temporaries are
 * overwritten by the next, and only the last frame could leave residue - the limitation the file
 * header states rather than pretends away. */
static void pt_add(pt *out, const pt *pp, const pt *qq, const fe bm)
{
    fe t0, t1, t2, t3, t4, x3, y3, z3;
    fiat_p256_mul(t0, pp->x, qq->x);
    fiat_p256_mul(t1, pp->y, qq->y);
    fiat_p256_mul(t2, pp->z, qq->z);
    fiat_p256_add(t3, pp->x, pp->y);
    fiat_p256_add(t4, qq->x, qq->y);
    fiat_p256_mul(t3, t3, t4);
    fiat_p256_add(t4, t0, t1);
    fiat_p256_sub(t3, t3, t4);
    fiat_p256_add(t4, pp->y, pp->z);
    fiat_p256_add(x3, qq->y, qq->z);
    fiat_p256_mul(t4, t4, x3);
    fiat_p256_add(x3, t1, t2);
    fiat_p256_sub(t4, t4, x3);
    fiat_p256_add(x3, pp->x, pp->z);
    fiat_p256_add(y3, qq->x, qq->z);
    fiat_p256_mul(x3, x3, y3);
    fiat_p256_add(y3, t0, t2);
    fiat_p256_sub(y3, x3, y3);
    fiat_p256_mul(z3, bm, t2);
    fiat_p256_sub(x3, y3, z3);
    fiat_p256_add(z3, x3, x3);
    fiat_p256_add(x3, x3, z3);
    fiat_p256_sub(z3, t1, x3);
    fiat_p256_add(x3, t1, x3);
    fiat_p256_mul(y3, bm, y3);
    fiat_p256_add(t1, t2, t2);
    fiat_p256_add(t2, t1, t2);
    fiat_p256_sub(y3, y3, t2);
    fiat_p256_sub(y3, y3, t0);
    fiat_p256_add(t1, y3, y3);
    fiat_p256_add(y3, t1, y3);
    fiat_p256_add(t1, t0, t0);
    fiat_p256_add(t0, t1, t0);
    fiat_p256_sub(t0, t0, t2);
    fiat_p256_mul(t1, t4, y3);
    fiat_p256_mul(t2, t0, y3);
    fiat_p256_mul(y3, x3, z3);
    fiat_p256_add(y3, y3, t2);
    fiat_p256_mul(x3, t3, x3);
    fiat_p256_sub(x3, x3, t1);
    fiat_p256_mul(z3, t4, z3);
    fiat_p256_mul(t1, t3, t0);
    fiat_p256_add(z3, z3, t1);
    memcpy(out->x, x3, sizeof x3);
    memcpy(out->y, y3, sizeof y3);
    memcpy(out->z, z3, sizeof z3);
}

/* out = k * base, a fixed 256-step double-and-add-always ladder over the big-endian scalar. Every
 * step runs one doubling and one addition whatever the bit is, and the choice is fe_cmov - never
 * an `if (bit)` and never an indexed table, so the instruction and memory trace is identical for
 * every scalar.
 *
 * ponytail: ~1.6x the field work of a w=4 windowed multiplication. The window is the upgrade path
 * if a handshake ever shows up in a profile; it costs a 15-point table (about 1.4 KB of stack)
 * plus the table-building code, which is what the flash budget cannot spare today. */
static void pt_mul(pt *out, const uint8_t k[32], const pt *base, const fe bm)
{
    pt r, t;
    size_t i;
    memset(r.x, 0, sizeof r.x);
    fiat_p256_set_one(r.y); /* (0 : 1 : 0), the point at infinity */
    memset(r.z, 0, sizeof r.z);
    for (i = 0; i < 256; i++) {
        uint32_t bit = (uint32_t)((k[i >> 3] >> (7 - (i & 7))) & 1);
        pt_add(&r, &r, &r, bm);   /* R = 2R */
        pt_add(&t, &r, base, bm); /* T = R + base */
        fe_cmov(r.x, t.x, bit);
        fe_cmov(r.y, t.y, bit);
        fe_cmov(r.z, t.z, bit);
    }
    memcpy(out, &r, sizeof r);
    brisk__secure_zero(&r, sizeof r);
    brisk__secure_zero(&t, sizeof t);
}

/* Decode and validate a peer point (RFC 9846 4.3.8.2, citing SP 800-56A r3 5.6.2.3.3):
 *   1. the first byte is 0x04 - compressed (0x02/0x03) and hybrid (0x06/0x07) forms are rejected,
 *      never decompressed, because TLS 1.3 removed point-format negotiation;
 *   2. x and y are both in [0, p-1];
 *   3. y^2 == x^3 - 3x + b (mod p).
 * The cofactor is 1, so the same section says subgroup membership need not be checked. Step 2 runs
 * before any field element is built, because fiat_p256_from_bytes does not reduce - that ordering
 * is what blocks the invalid-curve attack rather than merely detecting it afterwards. The point at
 * infinity has no encoding: 0x04 || 0^64 fails step 3 (0 != b).
 * Returns 1 on a good point. The peer point is public, so the early returns are fine here. */
static uint32_t pt_decode(pt *out, const uint8_t enc[65], const fe r2, const fe bm)
{
    fe x, y, lhs, rhs;
    uint32_t ok;
    if (enc[0] != 0x04 || !be_lt(enc + 1, P256_P) || !be_lt(enc + 33, P256_P)) {
        return 0;
    }
    fe_load_be(x, enc + 1, r2);
    fe_load_be(y, enc + 33, r2);
    fiat_p256_mul(lhs, y, y); /* y^2 */
    fiat_p256_mul(rhs, x, x);
    fiat_p256_mul(rhs, rhs, x); /* x^3 */
    fiat_p256_sub(rhs, rhs, x);
    fiat_p256_sub(rhs, rhs, x);
    fiat_p256_sub(rhs, rhs, x); /* x^3 - 3x */
    fiat_p256_add(rhs, rhs, bm);
    fiat_p256_sub(lhs, lhs, rhs);
    ok = fe_is_zero(lhs);
    memcpy(out->x, x, sizeof x);
    memcpy(out->y, y, sizeof y);
    fiat_p256_set_one(out->z);
    brisk__secure_zero(lhs, sizeof lhs);
    brisk__secure_zero(rhs, sizeof rhs);
    return ok;
}

/* enc = 0x04 || X || Y of the affine point, big-endian and zero-padded to 32 bytes each
 * (RFC 9846 4.3.8.2; the same padding rule 7.4.2 states for Z). Returns 0 when the point is at
 * infinity, which has no encoding - fe_inv maps 0 to 0, so enc is then 0x04 || 0^64 and the
 * caller fails closed rather than releasing it.
 *
 * BRISK__CT_PUBLIC on that verdict: on the ECDH and keygen paths it is derived from a secret
 * scalar, so it has to be declassified deliberately rather than left to leak. It is sound
 * because the answer there is a constant - d is in [1, n-1] and the base point has prime order n
 * with cofactor 1, so d*G and d*Q are never the point at infinity, and the branch below is a
 * fail-closed guard against a bug in this file, not a case that data can reach. Even if it did
 * fire, "the computation produced no shared secret" is exactly what the protocol shows the world
 * by sending an alert. The scalar itself stays secret; only this one bit is released. */
static uint32_t pt_encode(uint8_t enc[65], const pt *a)
{
    fe zi, t;
    uint8_t le[32];
    uint32_t ok = fe_is_zero(a->z) ^ 1;
    fe_inv(zi, a->z);
    enc[0] = 0x04;
    fiat_p256_mul(t, a->x, zi);
    fe_from_mont(t, t);
    fiat_p256_to_bytes(le, t);
    be_swap(enc + 1, le);
    fiat_p256_mul(t, a->y, zi);
    fe_from_mont(t, t);
    fiat_p256_to_bytes(le, t);
    be_swap(enc + 33, le);
    brisk__secure_zero(zi, sizeof zi);
    brisk__secure_zero(t, sizeof t);
    brisk__secure_zero(le, sizeof le);
    return ct_public_u32(ok);
}

/* The two per-call constants every entry point needs: R^2 mod p, and the curve b in the
 * Montgomery domain. */
static void p256_consts(fe bm, fe r2)
{
    fe_r2(r2);
    fe_load_be(bm, P256_B, r2);
}

/* The generator G, in the Montgomery domain. Only keygen and verify need it; ECDH does not. */
static void p256_gen(pt *g, const fe r2)
{
    fe_load_be(g->x, P256_GX, r2);
    fe_load_be(g->y, P256_GY, r2);
    fiat_p256_set_one(g->z);
}

/* ---------------------------------------------------- scalar arithmetic modulo n (in-house) */
/* A small fixed-width Montgomery core, ours rather than fiat's: the project keeps crypto in-house
 * and vendors FIELD arithmetic only, and fiat's p256_scalar file is fully unrolled - about twice
 * the flash on the 32-bit targets where the budget is tightest.
 *
 * One width everywhere: 8 limbs of 32 bits with uint64_t products. A 4x64 variant would need
 * unsigned __int128 and a second code path, and would buy roughly 2% of an ECDSA verify: the
 * whole mod-n core is about a tenth of the multiplication count of the two point multiplications
 * that dominate it, and each 32x32 product is a quarter the work of a 64x64 one. Not worth the
 * duplicate. No 64-bit / or %, no float and no `long` appear here (tools/dev.py size fails the
 * build on __udivdi3).
 *
 * n0' = -n^-1 mod 2^32 and R^2 mod n are both derived at run time, so there is no hand-typed
 * Montgomery constant that could be silently wrong; tests/kat/p256_scalar.inc is the differential
 * net under them. */
#define SC_LIMBS 8

static void sc_from_be(uint32_t r[SC_LIMBS], const uint8_t a[32])
{
    size_t i;
    for (i = 0; i < SC_LIMBS; i++) {
        r[i] = brisk__load_be32(a + 32 - 4 * (i + 1)); /* limb 0 is the least significant */
    }
}

static void sc_to_be(uint8_t r[32], const uint32_t a[SC_LIMBS])
{
    size_t i;
    for (i = 0; i < SC_LIMBS; i++) {
        brisk__store_be32(r + 32 - 4 * (i + 1), a[i]);
    }
}

/* r = (hi, t) - n when that does not borrow, else t. hi is the extra high limb, 0 or 1, so the
 * input is below 2n and one conditional subtraction is the whole reduction. Constant time; r may
 * alias t. */
static void sc_cond_sub_n(uint32_t r[SC_LIMBS], const uint32_t t[SC_LIMBS], uint32_t hi,
                          const uint32_t n[SC_LIMBS])
{
    uint32_t d[SC_LIMBS], mask, borrow = 0;
    size_t i;
    for (i = 0; i < SC_LIMBS; i++) {
        uint64_t w = (uint64_t)t[i] - n[i] - borrow;
        d[i] = (uint32_t)w;
        borrow = (uint32_t)((w >> 32) & 1);
    }
    /* Subtract when the extra limb was set (the value is certainly at least n) or when the
     * subtraction did not borrow out (t >= n). */
    mask = (uint32_t)0 - (hi | (borrow ^ 1));
    BRISK__CT_BARRIER(mask);
    for (i = 0; i < SC_LIMBS; i++) {
        r[i] = (t[i] & ~mask) | (d[i] & mask);
    }
    brisk__secure_zero(d, sizeof d);
}

/* n0' = -n^-1 mod 2^32, by Newton iteration: t <- t * (2 - n*t) doubles the number of correct
 * bits each round and starts from 1, which is right mod 2 because n is odd. Five rounds reach 32
 * bits. Branch-free and width-agnostic. */
static uint32_t sc_n0(uint32_t n_low)
{
    uint32_t t = 1;
    int i;
    for (i = 0; i < 5; i++) {
        t = (uint32_t)(t * (uint32_t)(2u - (uint32_t)(n_low * t)));
    }
    return (uint32_t)(0u - t);
}

typedef struct {
    uint32_t n[SC_LIMBS];
    uint32_t rr[SC_LIMBS];  /* R^2 mod n */
    uint32_t one[SC_LIMBS]; /* R mod n: the Montgomery representation of 1 */
    uint32_t n0;
} sc_ctx;

static void sc_init(sc_ctx *c)
{
    uint32_t v[SC_LIMBS], t[SC_LIMBS];
    int i;
    sc_from_be(c->n, P256_N);
    c->n0 = sc_n0(c->n[0]);
    memset(v, 0, sizeof v);
    v[0] = 1;
    /* 256 modular doublings of 1 give R mod n, and 256 more give R^2 mod n. */
    for (i = 0; i < 512; i++) {
        uint32_t carry = 0;
        size_t j;
        for (j = 0; j < SC_LIMBS; j++) {
            t[j] = (v[j] << 1) | carry;
            carry = v[j] >> 31;
        }
        sc_cond_sub_n(v, t, carry, c->n);
        if (i == 255) { /* a public loop counter, not data */
            memcpy(c->one, v, sizeof v);
        }
    }
    memcpy(c->rr, v, sizeof v);
    brisk__secure_zero(v, sizeof v);
    brisk__secure_zero(t, sizeof t);
}

/* r = a * b * R^-1 mod n (CIOS). Fixed loop bounds, no branch, no division. r may alias a and/or b.
 *
 * PRECONDITION, load-bearing and not checked here: a < n and b < n. The caller reduces - every
 * entry point below calls sc_cond_sub_n on its operands first. With it, T stays under 2n and the
 * final t[SC_LIMBS] is 0 or 1, which is the only range sc_cond_sub_n can correct. Feed it an
 * unreduced operand and t[SC_LIMBS] can reach 2, where one conditional subtraction cannot reduce
 * at all and the result is silently wrong - no mask trick rescues that, only the precondition.
 * The sign path honours it too: ecdsa_sign_with_k only ever goes through
 * brisk__p256_scalar_{reduce,add,mul,inv}, which reduce before they get here. */
static void sc_mont_mul(uint32_t r[SC_LIMBS], const uint32_t a[SC_LIMBS],
                        const uint32_t b[SC_LIMBS], const uint32_t n[SC_LIMBS], uint32_t n0)
{
    uint32_t t[SC_LIMBS + 2];
    size_t i, j;
    memset(t, 0, sizeof t);
    for (i = 0; i < SC_LIMBS; i++) {
        uint64_t w;
        uint32_t carry = 0, m;
        for (j = 0; j < SC_LIMBS; j++) {
            w = (uint64_t)a[i] * b[j] + t[j] + carry;
            t[j] = (uint32_t)w;
            carry = (uint32_t)(w >> 32);
        }
        w = (uint64_t)t[SC_LIMBS] + carry;
        t[SC_LIMBS] = (uint32_t)w;
        t[SC_LIMBS + 1] = (uint32_t)(w >> 32);

        m = (uint32_t)(t[0] * n0);
        carry = 0;
        for (j = 0; j < SC_LIMBS; j++) {
            w = (uint64_t)m * n[j] + t[j] + carry;
            t[j] = (uint32_t)w;
            carry = (uint32_t)(w >> 32);
        }
        w = (uint64_t)t[SC_LIMBS] + carry;
        t[SC_LIMBS] = (uint32_t)w;
        t[SC_LIMBS + 1] += (uint32_t)(w >> 32);

        for (j = 0; j <= SC_LIMBS; j++) { /* t >>= 32; t[0] is zero by construction */
            t[j] = t[j + 1];
        }
        t[SC_LIMBS + 1] = 0;
    }
    sc_cond_sub_n(r, t, t[SC_LIMBS], n); /* the CIOS result is below 2n */
    brisk__secure_zero(t, sizeof t);
}

int brisk__p256_scalar_valid(const uint8_t a[32])
{
    return (int)(be_lt(a, P256_N) & (be_is_zero(a) ^ 1));
}

void brisk__p256_scalar_reduce(uint8_t r[32], const uint8_t a[32])
{
    uint32_t n[SC_LIMBS], v[SC_LIMBS];
    sc_from_be(n, P256_N);
    sc_from_be(v, a);
    /* Any 32-byte value is below 2^256, and 2n > 2^256, so one conditional subtraction is exact. */
    sc_cond_sub_n(v, v, 0, n);
    sc_to_be(r, v);
    brisk__secure_zero(v, sizeof v);
}

void brisk__p256_scalar_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t n[SC_LIMBS], x[SC_LIMBS], y[SC_LIMBS], t[SC_LIMBS], carry = 0;
    size_t i;
    sc_from_be(n, P256_N);
    sc_from_be(x, a);
    sc_from_be(y, b);
    sc_cond_sub_n(x, x, 0, n); /* operands are reduced on the way in */
    sc_cond_sub_n(y, y, 0, n);
    for (i = 0; i < SC_LIMBS; i++) {
        uint64_t w = (uint64_t)x[i] + y[i] + carry;
        t[i] = (uint32_t)w;
        carry = (uint32_t)(w >> 32);
    }
    sc_cond_sub_n(t, t, carry, n);
    sc_to_be(r, t);
    brisk__secure_zero(x, sizeof x);
    brisk__secure_zero(y, sizeof y);
    brisk__secure_zero(t, sizeof t);
}

void brisk__p256_scalar_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    sc_ctx c;
    uint32_t x[SC_LIMBS], y[SC_LIMBS];
    sc_init(&c);
    sc_from_be(x, a);
    sc_cond_sub_n(x, x, 0, c.n);
    sc_from_be(y, b);
    sc_cond_sub_n(y, y, 0, c.n);
    sc_mont_mul(x, x, c.rr, c.n, c.n0); /* x -> Montgomery domain */
    sc_mont_mul(x, x, y, c.n, c.n0);    /* = a * b mod n */
    sc_to_be(r, x);
    brisk__secure_zero(&c, sizeof c);
    brisk__secure_zero(x, sizeof x);
    brisk__secure_zero(y, sizeof y);
}

void brisk__p256_scalar_inv(uint8_t r[32], const uint8_t a[32])
{
    sc_ctx c;
    uint32_t x[SC_LIMBS], acc[SC_LIMBS];
    uint8_t e[32];
    size_t i;
    sc_init(&c);
    sc_from_be(x, a);
    sc_cond_sub_n(x, x, 0, c.n);
    sc_mont_mul(x, x, c.rr, c.n, c.n0);
    memcpy(acc, c.one, sizeof acc);

    /* The exponent is n-2, derived from the stored n: it ends in 0x51, so there is no borrow. */
    memcpy(e, P256_N, sizeof e);
    e[31] = (uint8_t)(e[31] - 2);

    for (i = 0; i < 256; i++) {
        uint32_t bit = (uint32_t)((e[i >> 3] >> (7 - (i & 7))) & 1);
        sc_mont_mul(acc, acc, acc, c.n, c.n0);
        /* This branch is on the bits of the fixed public constant n-2, never on `a`: the squaring
         * above always runs, and which multiplications are skipped is the same for every operand.
         * a == 0 falls out correctly, since acc becomes 0 at the first set bit and stays there. */
        if (bit) {
            sc_mont_mul(acc, acc, x, c.n, c.n0);
        }
    }
    memset(x, 0, sizeof x);
    x[0] = 1;
    sc_mont_mul(acc, acc, x, c.n, c.n0); /* out of the Montgomery domain */
    sc_to_be(r, acc);
    brisk__secure_zero(&c, sizeof c);
    brisk__secure_zero(x, sizeof x);
    brisk__secure_zero(acc, sizeof acc);
}

/* ---------------------------------------------------------------------------- public API */
int brisk__p256_keygen(uint8_t pub[65], const uint8_t priv[32])
{
    pt g, q;
    fe bm, r2;
    uint8_t enc[65];
    int ok = brisk__p256_scalar_valid(priv);

    /* BRISK__CT_PUBLIC: the one-bit range verdict for d, not d itself. FIPS 186-5 A.2.2 generates
     * a private key by testing candidates, so "that draw was out of range, take another" is
     * observable by construction - the caller loops visibly. It reveals only that d was 0 or at
     * least n, which happens with probability about 2^-32 and says nothing at all about an
     * accepted d. The comparison inside brisk__p256_scalar_valid stays constant time; only this
     * answer is declassified. */
    BRISK__CT_PUBLIC(&ok, sizeof ok);
    if (!ok) {
        return BRISK_E_ARG; /* pub is left untouched, so the caller can retry into it */
    }
    p256_consts(bm, r2);
    p256_gen(&g, r2);
    pt_mul(&q, priv, &g, bm);
    /* d in [1, n-1] against a generator of prime order n means d*G is never the point at
     * infinity; the check stays so that a bug fails closed instead of emitting 0x04 || 0^64. */
    ok = (int)pt_encode(enc, &q);
    if (ok) {
        memcpy(pub, enc, sizeof enc);
    }
    brisk__secure_zero(&q, sizeof q);
    brisk__secure_zero(enc, sizeof enc);
    return ok ? BRISK_OK : BRISK_E_ARG;
}

int brisk__p256_ecdh(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[65])
{
    pt q, s;
    fe bm, r2;
    uint8_t enc[65];
    int ok = brisk__p256_scalar_valid(priv);

    BRISK__CT_PUBLIC(&ok, sizeof ok); /* same declassification, same reason, as in keygen above */
    /* BRISK__CT_PUBLIC: the peer's point. It arrived in a KeyShareEntry written by whoever we are
     * talking to, so it is the attacker's own input, not our secret - and its validity verdict is
     * public for the same reason, since RFC 9846 4.3.8.2 turns a bad point into an
     * illegal_parameter alert that is visible on the wire. */
    BRISK__CT_PUBLIC(peer, 65);
    p256_consts(bm, r2); /* no generator here: ECDH multiplies the peer's point, never G */
    ok &= (int)pt_decode(&q, peer, r2, bm);
    if (ok) {
        pt_mul(&s, priv, &q, bm);
        ok = (int)pt_encode(enc, &s);
    }
    /* out may alias priv or peer, so it is written only now that both have been consumed. */
    if (ok) {
        memcpy(out, enc + 1, 32); /* Z = X(d*Q), leading zeros kept (RFC 9846 7.4.2) */
    } else {
        memset(out, 0, 32);
    }
    brisk__secure_zero(&q, sizeof q);
    brisk__secure_zero(&s, sizeof s);
    brisk__secure_zero(enc, sizeof enc);
    return ok ? BRISK_OK : BRISK_E_ARG;
}

int brisk__p256_ecdsa_verify(const uint8_t pub[65], const uint8_t *hash, size_t hash_len,
                             const uint8_t sig[64])
{
    pt g, q, a, t;
    fe bm, r2;
    uint8_t e[32], w[32], u1[32], u2[32], v[32], enc[65];

    /* BRISK__CT_PUBLIC: every input to a signature verification is public by construction. r, s
     * and the message hash travel in the clear in a CertificateVerify or inside a certificate,
     * and the peer's public key is published; the verdict is public too, because the protocol
     * turns a bad signature into a visible alert. So this path may branch on anything it is
     * given. This declassifies inputs the caller handed us, never one of our own secrets - the
     * rule against silencing a report by declassifying a secret still stands. */
    BRISK__CT_PUBLIC(pub, 65);
    BRISK__CT_PUBLIC(sig, 64);

    /* hash_len is the caller's own count, not peer data, so it is checked before `hash` is
     * declassified: a length that underflowed upstream would otherwise mark an arbitrary range
     * defined and mask a genuine taint report elsewhere in the same `dev.py ct` run. Only the
     * leftmost 32 bytes are ever read, so that is all this releases. */
    if (hash_len < 32) {
        return BRISK_E_ARG; /* a caller bug: no digest this library compiles is shorter */
    }
    BRISK__CT_PUBLIC(hash, 32);

    /* FIPS 186-5 6.4.2 step 1: "if r and s are not both integers in [1, n-1], output INVALID".
     * INVALID, not an error - a peer can put r = 0 on the wire as easily as a wrong signature, so
     * this is BRISK_E_AUTH like any other signature that fails to verify, and a CertificateVerify
     * caller maps it to decrypt_error (RFC 9846 4.5.2). Returning BRISK_E_ARG here would both
     * emit illegal_parameter and hand the peer an oracle separating "malformed r/s" from "wrong
     * signature". Checked before any arithmetic. */
    if (!brisk__p256_scalar_valid(sig) || !brisk__p256_scalar_valid(sig + 32)) {
        return BRISK_E_AUTH;
    }
    p256_consts(bm, r2);
    p256_gen(&g, r2);
    if (!pt_decode(&q, pub, r2, bm)) {
        /* Deliberately not BRISK_E_AUTH: a public key that is not a point on the curve is
         * malformed key material, which the X.509 layer turns into bad_certificate, not a
         * signature that failed to verify. The two conditions stay distinguishable. */
        return BRISK_E_ARG;
    }
    /* e = the leftmost min(bitlen(n), bitlen(H)) bits of the hash. n is 256 bits and every hash
     * this library compiles is at least that, so it is the first 32 bytes - which is what lets a
     * P-256 key certified with SHA-384 or SHA-512 verify here. */
    memcpy(e, hash, 32);
    brisk__p256_scalar_reduce(e, e);
    brisk__p256_scalar_inv(w, sig + 32); /* w  = s^-1 mod n */
    brisk__p256_scalar_mul(u1, e, w);    /* u1 = e * w mod n */
    brisk__p256_scalar_mul(u2, sig, w);  /* u2 = r * w mod n */

    /* R = u1*G + u2*Q as two independent scalar multiplications and one addition. Shamir's trick
     * would save roughly a third of the field work, but it needs its own interleaved loop and a
     * joint table, where this reuses pt_mul verbatim and adds no code at all - and flash, not
     * handshake latency, is the binding constraint here. */
    pt_mul(&a, u1, &g, bm);
    pt_mul(&t, u2, &q, bm);
    pt_add(&a, &a, &t, bm);
    if (!pt_encode(enc, &a)) {
        return BRISK_E_AUTH; /* R is the point at infinity */
    }
    /* v = x_R mod n; accept iff v == r. x_R is below p < 2^256, so the reduction is exact. */
    brisk__p256_scalar_reduce(v, enc + 1);
    return brisk__ct_memeq(v, sig, 32) ? BRISK_OK : BRISK_E_AUTH;
}

#if BRISK_ENABLE_MTLS
/* ------------------------------------------------------- ECDSA sign: RFC 6979 nonce + 6.4.1 */
/* The per-signature HMAC_DRBG of RFC 6979 3.2. It is nonce derivation, not a randomness source -
 * seeded only from (d, h1, k'), never persisted, never reseeded from anywhere - so the "no
 * userspace DRBG" rule in .claude/rules/crypto.md is not in play here. Written out so a reviewer
 * does not have to re-derive that.
 *
 * K and V are hlen bytes, where hlen is the digest length of the SAME hash that produced the
 * message digest (3.2 b). Everything in it is secret. */
typedef struct {
    uint8_t k[BRISK_HASH_MAX_LEN]; /* DRBG K */
    uint8_t v[BRISK_HASH_MAX_LEN]; /* DRBG V */
    brisk_hash_alg alg;
    uint8_t hlen;
    uint8_t started; /* 0 until the first candidate; a public loop flag, not data */
} rfc6979_ctx;

/* V = HMAC_K(V). */
static void rfc6979_v(rfc6979_ctx *c)
{
    brisk_hmac_ctx h;
    brisk_hmac_init(&h, c->alg, c->k, c->hlen);
    brisk_hmac_update(&h, c->v, c->hlen);
    brisk_hmac_final(&h, c->v); /* wipes h's keyed states */
    brisk__secure_zero(&h, sizeof h);
}

/* K = HMAC_K(V || tag || int2octets(x) || bits2octets(h1) || k'), then V = HMAC_K(V): steps d+e
 * (tag 0x00), f+g (tag 0x01) and the h.3 reject path (tag 0x00 with priv == NULL, so the suffix
 * is absent).
 *
 * int2octets(x) (RFC 6979 2.3.3) is `priv` unchanged, because rlen = 256 = qlen for P-256; there
 * is no re-encoding step. bits2octets(h1) (2.3.4) is `z`, computed once by the caller.
 * k' is appended AFTER bits2octets(h1) - RFC 6979 3.6, bullet 2. Check that order against the
 * RFC text, not against this code: it is the one thing the hedged mode can get wrong, and no
 * official vector covers it (3.6: a variant "ceases to be verifiable against the test vectors
 * published in this document"). What guards it instead is that extra_len == 0 must still
 * reproduce A.2.5 byte-for-byte. */
static void rfc6979_reseed(rfc6979_ctx *c, uint8_t tag, const uint8_t *priv, const uint8_t *z,
                           const uint8_t *extra, size_t extra_len)
{
    brisk_hmac_ctx h;
    brisk_hmac_init(&h, c->alg, c->k, c->hlen);
    brisk_hmac_update(&h, c->v, c->hlen);
    brisk_hmac_update(&h, &tag, 1);
    if (priv != NULL) {
        brisk_hmac_update(&h, priv, BRISK__P256_SCALAR_LEN);
        brisk_hmac_update(&h, z, BRISK__P256_SCALAR_LEN);
        if (extra_len != 0) {
            brisk_hmac_update(&h, extra, extra_len);
        }
    }
    brisk_hmac_final(&h, c->k);
    brisk__secure_zero(&h, sizeof h);
    rfc6979_v(c);
}

/* RFC 6979 3.2 steps a-g. */
static void rfc6979_init(rfc6979_ctx *c, brisk_hash_alg alg, const uint8_t priv[32],
                         const uint8_t z[32], const uint8_t *extra, size_t extra_len)
{
    c->alg = alg;
    c->hlen = (uint8_t)brisk_hash_len(alg);
    c->started = 0;
    memset(c->v, 0x01, c->hlen);                        /* a: V = 0x01 repeated hlen times */
    memset(c->k, 0x00, c->hlen);                        /* b: K = 0x00 repeated hlen times */
    rfc6979_reseed(c, 0x00, priv, z, extra, extra_len); /* c+d+e */
    rfc6979_reseed(c, 0x01, priv, z, extra, extra_len); /* f+g */
}

/* Step h: the next candidate k. The first call generates from the state step g left; every later
 * call first runs the h.3 reject path (K = HMAC_K(V || 0x00), V = HMAC_K(V)), because a later
 * call happens only when the previous candidate was rejected - either out of range here, or
 * r == 0 / s == 0 in the caller (RFC 6979 3.4 reuses the same mechanism).
 *
 * bits2int of T (2.3.2) is the leftmost 32 bytes: qlen = 256 and every accepted hash is at least
 * 256 bits, so one pass of step h.2 always yields enough and there is no shifting path. The
 * candidate is COMPARED against q, never reduced mod q - reducing would bias k.
 * Returns 1 when 1 <= k <= n-1. */
static int rfc6979_next(rfc6979_ctx *c, uint8_t k_out[32])
{
    if (c->started) {
        rfc6979_reseed(c, 0x00, NULL, NULL, NULL, 0);
    }
    c->started = 1;
    rfc6979_v(c); /* h.2: T = V, one pass */
    memcpy(k_out, c->v, BRISK__P256_SCALAR_LEN);
    return brisk__p256_scalar_valid(k_out);
}

/* FIPS 186-5 6.4.1 steps 4-7 with k already chosen: (x1, y1) = k*G, r = x1 mod n,
 * s = k^-1 (e + r*d) mod n, written as r || s. `e` is the reduced digest, which for P-256 is the
 * same value as bits2octets(h1). Returns 1 iff r and s are both non-zero - the caller retries
 * with the next k otherwise (RFC 6979 3.4).
 *
 * No scalar blinding: k^-1 goes through brisk__p256_scalar_inv, which is Fermat over a fixed
 * public exponent, and every multiplication is the constant-time sc_mont_mul, so no intermediate
 * is compared or branched on. Blinding would cost another 32 bytes of entropy and a multiply;
 * that is a decision to take deliberately, not by omission. */
static uint32_t ecdsa_sign_with_k(uint8_t sig[64], const uint8_t k[32], const uint8_t priv[32],
                                  const uint8_t e[32])
{
    pt g, r;
    fe bm, r2;
    uint8_t enc[65], kinv[32], t[32];
    uint32_t ok;

    p256_consts(bm, r2);
    p256_gen(&g, r2);
    pt_mul(&r, k, &g, bm);
    ok = pt_encode(enc, &r); /* k in [1, n-1] against a prime-order G: never infinity */
    brisk__p256_scalar_reduce(sig, enc + 1);   /* r = x1 mod n */
    brisk__p256_scalar_inv(kinv, k);           /* k^-1 mod n */
    brisk__p256_scalar_mul(t, sig, priv);      /* r * d */
    brisk__p256_scalar_add(t, t, e);           /* e + r*d */
    brisk__p256_scalar_mul(sig + 32, kinv, t); /* s */
    /* Both are already reduced mod n, so "valid" here is exactly "non-zero". */
    ok &= (uint32_t)brisk__p256_scalar_valid(sig) & (uint32_t)brisk__p256_scalar_valid(sig + 32);

    brisk__secure_zero(&r, sizeof r);
    brisk__secure_zero(enc, sizeof enc);
    brisk__secure_zero(kinv, sizeof kinv);
    brisk__secure_zero(t, sizeof t);
    return ok;
}

int brisk__p256_ecdsa_sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t *hash,
                           size_t hash_len, const uint8_t *extra, size_t extra_len)
{
    brisk_hash_alg alg;
    rfc6979_ctx drbg;
    uint8_t z[32], k[32], out[64];
    int ok, rc = BRISK_E_AUTH;
    unsigned tries;

    /* hash_len picks the RFC 6979 hash as well as bounding the digest, so it is not a ">= 32"
     * check: it must be exactly the width of the H that produced `hash` (RFC 6979 3.2 b). */
    if (hash_len == BRISK_SHA256_LEN) {
        alg = BRISK_HASH_SHA256;
    } else if (hash_len == BRISK_SHA384_LEN) {
        alg = BRISK_HASH_SHA384;
    } else if (hash_len == BRISK_SHA512_LEN) {
        alg = BRISK_HASH_SHA512;
    } else {
        return BRISK_E_ARG; /* a caller bug; sig is left untouched */
    }

    ok = brisk__p256_scalar_valid(priv);
    /* BRISK__CT_PUBLIC: the one-bit range verdict for d, not d itself - the same declassification
     * brisk__p256_keygen makes, for the same reason (FIPS 186-5 A.2.2 tests candidates, so the
     * caller loops visibly). */
    BRISK__CT_PUBLIC(&ok, sizeof ok);
    if (!ok) {
        return BRISK_E_ARG; /* sig untouched, so the caller can retry into it */
    }

    /* bits2octets(h1) (RFC 6979 2.3.4) = bits2int(h1) mod n. bits2int is the leftmost
     * min(qlen, bitlen H) bits = the first 32 bytes, so this is exactly a scalar_reduce over
     * them - and the same value is e of FIPS 186-5 6.4.1, so it is computed once. */
    brisk__p256_scalar_reduce(z, hash);
    rfc6979_init(&drbg, alg, priv, z, extra, extra_len);
    /* Bounded: an unbounded secret-dependent loop is not acceptable on an IoT watchdog budget.
     * A candidate is rejected with p ~ 2^-32 (out of range) or p ~ 2^-128 (r or s zero), so
     * reaching 64 is a 2^-2048-class event - a bug or a fault, and it fails closed. */
    for (tries = 0; tries < 64; tries++) {
        int got = rfc6979_next(&drbg, k);
        BRISK__CT_PUBLIC(&got, sizeof got); /* the accept/reject bit, never k */
        if (!got) {
            continue;
        }
        got = (int)ecdsa_sign_with_k(out, k, priv, z);
        BRISK__CT_PUBLIC(&got, sizeof got);
        if (got) {
            rc = BRISK_OK;
            break;
        }
    }
    brisk__secure_zero(&drbg, sizeof drbg);
    brisk__secure_zero(k, sizeof k);
    brisk__secure_zero(z, sizeof z);

    if (rc == BRISK_OK) {
        /* Fault countermeasure, deliberately not in the RFC: verify what we just produced. A
         * single glitched ECDSA signature leaks the long-term device key, and on hardware that
         * sits in a cabinet for ten years that is the risk worth one keygen plus one verify. Kept
         * in a sibling scope so its frame does not stack on the signing block's. */
        uint8_t pub[65];
        if (brisk__p256_keygen(pub, priv) != BRISK_OK ||
            brisk__p256_ecdsa_verify(pub, hash, hash_len, out) != BRISK_OK) {
            rc = BRISK_E_AUTH;
        }
        brisk__secure_zero(pub, sizeof pub);
    }
    /* sig may alias hash and/or extra, so it is written only now that both are consumed. On any
     * failure past the argument checks it is zeroed, never left half-written. */
    if (rc == BRISK_OK) {
        memcpy(sig, out, sizeof out);
    } else {
        memset(sig, 0, BRISK__P256_SIG_LEN);
    }
    brisk__secure_zero(out, sizeof out);
    return rc;
}
#endif /* BRISK_ENABLE_MTLS */

#undef FE_LIMBS
#undef FE_LIMB_BITS
#undef SC_LIMBS
