/* p384.c - P-384 (secp384r1) ECDSA VERIFY ONLY, on the generic i31 bignum of src/crypto/bn.c.
 *
 * WHY THIS FILE EXISTS, AND WHY IT IS ONLY HALF A CURVE. RFC 9846 4.3.3 defines
 * ecdsa_secp384r1_sha384 (0x0503) and 9.1 makes only ecdsa_secp256r1_sha256 mandatory to
 * implement, so P-384 sits behind BRISK_ENABLE_P384. What makes it worth compiling at all is
 * X.509, not the handshake: Let's Encrypt's Generation Y intermediates are P-384, so M2 chain
 * building cannot verify a real chain without this. docs/ARCHITECTURE.md locks "no P-384 ECDHE",
 * so there is NO keygen, NO ECDH and NO signing here, and there never will be. One exported
 * symbol: brisk__p384_ecdsa_verify.
 *
 * PUBLIC DATA ONLY - and the ladder branches on it. A public key, a signature and a digest all
 * travel in the clear (a certificate, a CertificateVerify), and the verdict becomes a visible
 * alert. So p384_pt_mul2_pub deliberately branches on the bits of its scalars, and the entry
 * point declassifies its three input buffers with BRISK__CT_PUBLIC so `dev.py ct` keeps
 * reporting everything else. The failure mode to guard against is someone later reusing that
 * ladder for a secret scalar; hence the _pub suffix, the same rule brisk__bn_modpow_pub follows.
 * NEVER pass a secret scalar to anything in this file.
 *
 * FIELD AND SCALAR LAYER. bn.c unchanged, exactly as its own header promises: this file adds
 * curve constants, a point type and a ladder. Both moduli announce 384 bits, so
 * BRISK__BN_LIMBS(384) = 14 words (13 i31 limbs + the header word) is the single width in the
 * file. That also means the compiler CANNOT catch a p-value fed to an n-operation - they are the
 * same type - so the discipline is kept by naming: p384_fe_* take an explicit modulus and the
 * scalar layer is p384_sc_*. Inversions are Fermat via brisk__bn_modpow_pub with the two PUBLIC
 * exponents p-2 and n-2, each derived at run time from the compiled constant with a single
 * `buf[47] -= 2` (p ends 0xFF, n ends 0x73, so neither borrows), so no second constant exists to
 * be wrong.
 *
 * brisk__bn_mont_mul's precondition (x < m, y < m, m odd, same announced width) is unchecked and
 * load-bearing: an unreduced operand is silently wrong, not detected. So every field addition and
 * subtraction goes through the reducing p384_fe_add / p384_fe_sub and never a bare brisk__bn_add,
 * and pt_decode range-checks both coordinates BEFORE any Montgomery value is built - the
 * invalid-curve ordering rule, which blocks the attack rather than noticing it afterwards.
 *
 * POINT ARITHMETIC: homogeneous projective coordinates with the Renes-Costello-Batina 2015
 * Algorithm 4 complete addition for a = -3 (14 Montgomery multiplications + 29 field add/sub),
 * the same formula src/crypto/p256.c uses. "Complete" is the whole reason: P == Q, P == -Q and
 * either input at infinity all come out right with no detection logic - which is what
 * Wycheproof's PointDuplication and EdgeCaseShamirMultiplication rows hunt for - and doubling is
 * just pt_add(P, P), so no second formula exists to get wrong. Jacobian would save ~15% of the
 * multiplies once S == M on a generic bignum, in exchange for the single most likely correctness
 * bug in an ECDSA implementation. Not taken.
 *
 * COST. One verify is 384 doublings + ~384 additions from the ONE interleaved (Straus-Shamir)
 * ladder - against 768 + 1 for two separate double-and-add-always ladders, with no precomputed
 * table and no extra accumulator - plus two 384-bit Fermat inversions: about 12,000 13-limb
 * Montgomery multiplications in total. MEASURED, gcc 14.2 at -Os: 3.2 ms on the x86_64 host
 * (2.7 ms at -O2) and 32 ms per verify under qemu-armv5, which makes the whole p384 suite 42 s
 * there against 148 s for p256. A 400 MHz armv5 gateway pays one of these per certificate in a
 * Let's Encrypt Generation Y chain.
 *
 * The documented upgrade paths, in order and none taken now: bn_muladd_small + a constant-time
 * divrem to replace brisk__bn_to_mont's 403 doublings (written up in the bn.c header), then a
 * 2-bit joint window on the ladder (~12%), then a P-384-specific Solinas fast reduction - which
 * would leave the generic bignum and is a locked-decision change, not an optimisation.
 *
 * STACK: brisk__bn_mont_mul allocates its CIOS accumulator at BRISK__BN_MAX_LIMBS
 * (= BRISK_RSA_MAX_BITS, so 640 B of frame at the 4096 default) whatever the operand width, and
 * it sits under every one of those ~12,000 multiplies. bn.c is deliberately NOT changed for that
 * (the alternatives are a VLA, which -Wvla forbids, or alloca); the coupling is recorded in
 * docs/CONFIG.md instead - and it is why BRISK_RSA_MAX_BITS is now a stack lever for this file
 * too, not only for rsa.c. Measured with -fstack-usage, gcc 14.2 at -Os on x86_64, summed along
 * the deepest chain - gcc inlines ctx_init, gen, pt_decode, pt_mul2_pub, pt_x_affine and
 * sc_inv_pub into the entry point, which is why its own frame is large:
 *   brisk__p384_ecdsa_verify 1424 + p384_pt_add 576 + p384_fe_mul 8 + brisk__bn_mont_mul 640
 *     = 2648 B  <- the deepest
 *   brisk__p384_ecdsa_verify 1424 + brisk__bn_modpow_pub 112 + brisk__bn_mont_mul 640 = 2176 B
 * against the 3 KB budget src/crypto/p256.c already carries. The figures are not
 * optimisation-independent; -Os is pinned PRIVATE in CMakeLists.txt. No VLA and no malloc hides
 * any of it.
 *
 * WIPING: nothing here is secret, so this is hygiene, not necessity. Named scratch is wiped on
 * exit and brisk__bn_modpow_pub wipes the scratch it is handed. p384_pt_add is deliberately NOT
 * wiped per call: it runs ~770 times per verify and each call's temporaries are overwritten by
 * the next, exactly as p256.c's pt_add records.
 *
 * File-local statics and macros carry a p384_ / P384_ prefix for the M8 amalgamation, and every
 * macro is #undef'd at the end of the file.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_P384

#    define P384_BYTES 48
#    define P384_WORDS BRISK__BN_LIMBS(384) /* 14 = 13 i31 limbs + the announced-length header */

/* An i31 value at p's or n's width (they are the same), and a projective point in the Montgomery
 * domain: (X : Y : Z) is the affine (X/Z, Y/Z), and Z == 0 is the point at infinity. */
typedef uint32_t p384_fe[P384_WORDS];
typedef struct {
    p384_fe x, y, z;
} p384_pt;

/* Everything derived once per verify from the constants below. `rm` is R mod p, i.e. the
 * Montgomery representation of 1: the Z of an affine point and the Y of the infinity
 * (0 : 1 : 0). It is not in the spec's struct sketch, but bm alone cannot produce it and the
 * alternative is a third brisk__bn_to_mont per point. */
typedef struct {
    p384_fe p, n, bm, rm;
    uint32_t p0, n0;
} p384_ctx;

/* Domain parameters, RFC 5903 3.2 (= SP 800-186 3.2.1.4 = SEC 2 2.4.3), curve y^2 = x^3 - 3x + b,
 * as big-endian byte strings - one spelling, unpacked at run time by the same loader that handles
 * untrusted input, so no per-width limb table can be wrong on a big-endian target.
 * check_p384_source_constants() in tools/kat.py reads these five arrays back out of this file and
 * compares them byte-for-byte with the RFC text, which is how "never hand-type a vector" is
 * honoured for parameters that cannot come from a generated .inc (src/ cannot include tests/). */
static const uint8_t P384_P[48] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t P384_B[48] = {
    0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
    0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
    0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF};
static const uint8_t P384_N[48] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73};
static const uint8_t P384_GX[48] = {
    0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
    0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
    0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7};
static const uint8_t P384_GY[48] = {
    0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
    0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
    0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F};

/* ------------------------------------------------------------------------------ field layer */
/* r = a + b mod m. The reducing form: brisk__bn_add on its own leaves a value that can exceed m,
 * and feeding that to brisk__bn_mont_mul violates its unchecked x < m precondition. Three passes
 * and no scratch beyond one local, the same trick brisk__bn_to_mont uses internally. The carry
 * term is kept for exactness even though a + b < 2m < 2^385 can never carry out of 13 i31 limbs
 * (403 bits); dropping it would be a correct-by-accident shortcut.
 *
 * `r` may alias a AND/OR b, which the addition formula below relies on, so the work happens in a
 * local first: brisk__bn_add writes its left operand in place and would destroy b if r == b. */
static void p384_fe_add(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *m)
{
    p384_fe t;
    uint32_t carry, borrow;
    memcpy(t, a, sizeof t);
    carry = brisk__bn_add(t, b, 1);
    borrow = brisk__bn_sub(t, m, 1);
    (void)brisk__bn_add(t, m, borrow & (carry ^ 1));
    memcpy(r, t, sizeof t);
}

/* r = a - b mod m, same aliasing contract. */
static void p384_fe_sub(uint32_t *r, const uint32_t *a, const uint32_t *b, const uint32_t *m)
{
    p384_fe t;
    uint32_t borrow;
    memcpy(t, a, sizeof t);
    borrow = brisk__bn_sub(t, b, 1);
    (void)brisk__bn_add(t, m, borrow);
    memcpy(r, t, sizeof t);
}

/* r = a * b * R^-1 mod p. One line, but it is what keeps the 43-operation addition formula below
 * readable enough to check against the paper. */
static void p384_fe_mul(uint32_t *r, const uint32_t *a, const uint32_t *b, const p384_ctx *c)
{
    brisk__bn_mont_mul(r, a, b, c->p, c->p0);
}

/* 1 iff a is zero. Every value here is fully reduced, so zero has the unique all-zero pattern. */
static uint32_t p384_is_zero(const uint32_t *a)
{
    uint32_t acc = 0, i;
    for (i = 1; i < P384_WORDS; i++) {
        acc |= a[i];
    }
    return (acc - 1) >> 31;
}

/* v <- the 48 big-endian octets, at m's announced width, reduced by ONE conditional subtraction.
 * Exact because any 48-byte value is below 2^384 and 2m > 2^384 for both p and n - the property
 * the bn.c header already states. Returns 0 only if the decode itself failed, which cannot happen
 * for a 48-byte source at a 384-bit modulus; checked anyway rather than assumed. */
static uint32_t p384_load_reduced(uint32_t *v, const uint8_t a[48], const uint32_t *m)
{
    uint32_t borrow;
    if (brisk__bn_decode_into(v, m, a, P384_BYTES) != BRISK_OK) {
        return 0;
    }
    borrow = brisk__bn_sub(v, m, 1);
    (void)brisk__bn_add(v, m, borrow);
    return 1;
}

/* The per-call constants: both moduli, their -m^-1 mod 2^31, the curve b in the Montgomery
 * domain, and R mod p. */
static void p384_ctx_init(p384_ctx *c)
{
    /* These five decodes cannot fail: the constants above are 48 odd 384-bit values, and
     * check_p384_source_constants() in tools/kat.py pins them against RFC 5903 3.2 at
     * vector-generation time. The status is dropped deliberately rather than by oversight. */
    (void)brisk__bn_decode_mod(c->p, 384, P384_P, P384_BYTES);
    (void)brisk__bn_decode_mod(c->n, 384, P384_N, P384_BYTES);
    c->p0 = brisk__bn_ninv31(c->p);
    c->n0 = brisk__bn_ninv31(c->n);
    (void)brisk__bn_decode_into(c->bm, c->p, P384_B, P384_BYTES);
    brisk__bn_to_mont(c->bm, c->p);
    memset(c->rm, 0, sizeof c->rm);
    c->rm[0] = c->p[0];
    c->rm[1] = 1;
    brisk__bn_to_mont(c->rm, c->p); /* R mod p = the Montgomery form of 1 */
}

/* ------------------------------------------------------------------------------ point layer */
/* Complete addition: Renes-Costello-Batina 2015, Algorithm 4 for a = -3 (14 multiplications, 2 of
 * them by b, and 29 additions). Transcribed operation for operation from src/crypto/p256.c's
 * pt_add, which is where the reasoning for choosing a complete formula is written out.
 *
 * `o` may alias pp and/or qq - the ladder calls it as pt_add(R, R, R) for the doubling: every
 * result lands in a local first, because line 10 overwrites X3 while X1 is still live.
 *
 * Not wiped: ~770 calls per verify, each call's temporaries overwritten by the next, and nothing
 * here is secret anyway. */
static void p384_pt_add(p384_pt *o, const p384_pt *pp, const p384_pt *qq, const p384_ctx *c)
{
    p384_fe t0, t1, t2, t3, t4, x3, y3, z3;
    const uint32_t *m = c->p;
    p384_fe_mul(t0, pp->x, qq->x, c);
    p384_fe_mul(t1, pp->y, qq->y, c);
    p384_fe_mul(t2, pp->z, qq->z, c);
    p384_fe_add(t3, pp->x, pp->y, m);
    p384_fe_add(t4, qq->x, qq->y, m);
    p384_fe_mul(t3, t3, t4, c);
    p384_fe_add(t4, t0, t1, m);
    p384_fe_sub(t3, t3, t4, m);
    p384_fe_add(t4, pp->y, pp->z, m);
    p384_fe_add(x3, qq->y, qq->z, m);
    p384_fe_mul(t4, t4, x3, c);
    p384_fe_add(x3, t1, t2, m);
    p384_fe_sub(t4, t4, x3, m);
    p384_fe_add(x3, pp->x, pp->z, m);
    p384_fe_add(y3, qq->x, qq->z, m);
    p384_fe_mul(x3, x3, y3, c);
    p384_fe_add(y3, t0, t2, m);
    p384_fe_sub(y3, x3, y3, m);
    p384_fe_mul(z3, c->bm, t2, c);
    p384_fe_sub(x3, y3, z3, m);
    p384_fe_add(z3, x3, x3, m);
    p384_fe_add(x3, x3, z3, m);
    p384_fe_sub(z3, t1, x3, m);
    p384_fe_add(x3, t1, x3, m);
    p384_fe_mul(y3, c->bm, y3, c);
    p384_fe_add(t1, t2, t2, m);
    p384_fe_add(t2, t1, t2, m);
    p384_fe_sub(y3, y3, t2, m);
    p384_fe_sub(y3, y3, t0, m);
    p384_fe_add(t1, y3, y3, m);
    p384_fe_add(y3, t1, y3, m);
    p384_fe_add(t1, t0, t0, m);
    p384_fe_add(t0, t1, t0, m);
    p384_fe_sub(t0, t0, t2, m);
    p384_fe_mul(t1, t4, y3, c);
    p384_fe_mul(t2, t0, y3, c);
    p384_fe_mul(y3, x3, z3, c);
    p384_fe_add(y3, y3, t2, m);
    p384_fe_mul(x3, t3, x3, c);
    p384_fe_sub(x3, x3, t1, m);
    p384_fe_mul(z3, t4, z3, c);
    p384_fe_mul(t1, t3, t0, c);
    p384_fe_add(z3, z3, t1, m);
    memcpy(o->x, x3, sizeof x3);
    memcpy(o->y, y3, sizeof y3);
    memcpy(o->z, z3, sizeof z3);
}

/* o = u1*g + u2*q, ONE interleaved (Straus-Shamir) pass over the 384 bits of both scalars:
 * 384 doublings + about 384 additions, against 768 + 1 for two separate double-and-add-always
 * ladders, with no precomputed table, no second accumulator and no extra stack.
 *
 * THIS LADDER BRANCHES ON THE SCALAR BITS, ON PURPOSE. u1 and u2 are derived from a signature and
 * a digest, both public; the whole verify is public data. Never call this with a secret scalar -
 * P-384 ECDH and P-384 signing are out of scope forever (docs/ARCHITECTURE.md), and if that ever
 * changed this would need a fixed-step sibling with a mask select, not a reuse. Hence _pub. */
static void p384_pt_mul2_pub(p384_pt *o, const uint8_t u1[48], const p384_pt *g,
                             const uint8_t u2[48], const p384_pt *q, const p384_ctx *c)
{
    p384_pt r;
    size_t i;
    memset(r.x, 0, sizeof r.x); /* (0 : 1 : 0), the point at infinity */
    memcpy(r.y, c->rm, sizeof r.y);
    memset(r.z, 0, sizeof r.z);
    r.x[0] = c->p[0]; /* every operand carries the modulus's announced length */
    r.z[0] = c->p[0];
    for (i = 0; i < 384; i++) {
        uint32_t b1 = (uint32_t)((u1[i >> 3] >> (7 - (i & 7))) & 1);
        uint32_t b2 = (uint32_t)((u2[i >> 3] >> (7 - (i & 7))) & 1);
        p384_pt_add(&r, &r, &r, c); /* R = 2R; the complete formula needs no separate doubling */
        if (b1) {
            p384_pt_add(&r, &r, g, c);
        }
        if (b2) {
            p384_pt_add(&r, &r, q, c);
        }
    }
    memcpy(o, &r, sizeof r);
    brisk__secure_zero(&r, sizeof r);
}

/* The generator G, in the Montgomery domain. */
static void p384_gen(p384_pt *g, const p384_ctx *c)
{
    (void)brisk__bn_decode_into(g->x, c->p, P384_GX, P384_BYTES);
    (void)brisk__bn_decode_into(g->y, c->p, P384_GY, P384_BYTES);
    brisk__bn_to_mont(g->x, c->p);
    brisk__bn_to_mont(g->y, c->p);
    memcpy(g->z, c->rm, sizeof g->z);
}

/* Decode and validate an uncompressed public point (RFC 9846 4.3.8.2, citing [ECDP] D.1 /
 * [KEYAGREEMENT] 5.6.2.3):
 *   1. the first byte is 0x04 - compressed (0x02/0x03) and hybrid (0x06/0x07) forms are rejected,
 *      never decompressed, because TLS 1.3 removed point-format negotiation;
 *   2. x and y are both in [0, p-1];
 *   3. y^2 == x^3 - 3x + b (mod p).
 * The cofactor is 1, so no subgroup check is needed. Step 2 runs BEFORE any Montgomery value is
 * built: brisk__bn_mont_mul is only correct for operands below the modulus, so an unreduced
 * coordinate would be silently wrong rather than merely detected late. The point at infinity has
 * no encoding - 0x04 || 0^96 fails step 3, since 0 != b.
 * Returns 1 on a good point. The point is public, so the early returns are fine. */
static uint32_t p384_pt_decode(p384_pt *o, const uint8_t enc[97], const p384_ctx *c)
{
    p384_fe x, y, lhs, rhs;
    uint32_t ok;
    if (enc[0] != 0x04) {
        return 0;
    }
    if (brisk__bn_decode_into(x, c->p, enc + 1, P384_BYTES) != BRISK_OK ||
        brisk__bn_decode_into(y, c->p, enc + 1 + P384_BYTES, P384_BYTES) != BRISK_OK) {
        return 0;
    }
    /* decode_into only checks that the value fits the announced WIDTH; a coordinate in
     * [p, 2^384) fits and must still be rejected. This is the range check, and it is the last
     * thing before the field work starts. */
    if (!brisk__bn_lt(x, c->p) || !brisk__bn_lt(y, c->p)) {
        return 0;
    }
    brisk__bn_to_mont(x, c->p);
    brisk__bn_to_mont(y, c->p);
    p384_fe_mul(lhs, y, y, c); /* y^2 */
    p384_fe_mul(rhs, x, x, c);
    p384_fe_mul(rhs, rhs, x, c); /* x^3 */
    p384_fe_sub(rhs, rhs, x, c->p);
    p384_fe_sub(rhs, rhs, x, c->p);
    p384_fe_sub(rhs, rhs, x, c->p); /* x^3 - 3x */
    p384_fe_add(rhs, rhs, c->bm, c->p);
    p384_fe_sub(lhs, lhs, rhs, c->p);
    ok = p384_is_zero(lhs);
    memcpy(o->x, x, sizeof x);
    memcpy(o->y, y, sizeof y);
    memcpy(o->z, c->rm, sizeof o->z);
    brisk__secure_zero(lhs, sizeof lhs);
    brisk__secure_zero(rhs, sizeof rhs);
    return ok;
}

/* x = the affine X of a, big-endian and zero-padded to 48 bytes. Returns 0 when a is the point at
 * infinity, which has no affine X - the caller fails closed rather than comparing garbage.
 *
 * Z is taken out of the Montgomery domain, inverted as Z^(p-2) with brisk__bn_modpow_pub (p-2 is
 * a public constant), and multiplied back against the Montgomery X: X*R * Z^-1 * R^-1 = X/Z,
 * which lands in the plain domain with no extra conversion. Z == 0 inverts to 0, so x is then
 * all zeros and `ok` is the only thing the caller looks at. */
static uint32_t p384_pt_x_affine(uint8_t x[48], const p384_pt *a, const p384_ctx *c)
{
    p384_fe zi, t;
    uint32_t sc[2 * P384_WORDS]; /* brisk__bn_modpow_pub scratch: 2 * (limbs + 1) words */
    uint8_t e[48];
    uint32_t ok = p384_is_zero(a->z) ^ 1;
    memcpy(zi, a->z, sizeof zi);
    brisk__bn_from_mont(zi, c->p, c->p0, t);
    memcpy(e, P384_P, sizeof e);
    e[P384_BYTES - 1] = (uint8_t)(e[P384_BYTES - 1] - 2); /* p ends in 0xFF: no borrow */
    (void)brisk__bn_modpow_pub(zi, e, sizeof e, c->p, sc);
    p384_fe_mul(t, a->x, zi, c);
    (void)brisk__bn_encode(x, P384_BYTES, t);
    brisk__secure_zero(zi, sizeof zi);
    brisk__secure_zero(t, sizeof t);
    brisk__secure_zero(sc, sizeof sc);
    return ok;
}

/* ------------------------------------------------------ scalar arithmetic modulo n (public) */
/* 1 iff 1 <= a <= n-1 (FIPS 186-5 6.4.2 step 1). */
static uint32_t p384_sc_valid(const uint8_t a[48], const p384_ctx *c)
{
    p384_fe v;
    uint32_t ok;
    if (brisk__bn_decode_into(v, c->n, a, P384_BYTES) != BRISK_OK) {
        return 0;
    }
    ok = brisk__bn_lt(v, c->n) & (p384_is_zero(v) ^ 1);
    brisk__secure_zero(v, sizeof v);
    return ok;
}

/* r = a mod n, for any 48-byte a. */
static void p384_sc_reduce(uint8_t r[48], const uint8_t a[48], const p384_ctx *c)
{
    p384_fe v;
    (void)p384_load_reduced(v, a, c->n);
    (void)brisk__bn_encode(r, P384_BYTES, v);
    brisk__secure_zero(v, sizeof v);
}

/* r = a * b mod n. PRECONDITION: a and b are both already below n - every caller here passes a
 * reduced digest, a validated r, or the output of p384_sc_inv_pub. brisk__bn_to_mont on the left
 * operand and a plain-domain right operand mean a*R * b * R^-1 = a*b comes straight back out,
 * with no R^2 constant and no second conversion. */
static void p384_sc_mul(uint8_t r[48], const uint8_t a[48], const uint8_t b[48], const p384_ctx *c)
{
    p384_fe x, y;
    (void)brisk__bn_decode_into(x, c->n, a, P384_BYTES);
    (void)brisk__bn_decode_into(y, c->n, b, P384_BYTES);
    brisk__bn_to_mont(x, c->n);
    brisk__bn_mont_mul(x, x, y, c->n, c->n0);
    (void)brisk__bn_encode(r, P384_BYTES, x);
    brisk__secure_zero(x, sizeof x);
    brisk__secure_zero(y, sizeof y);
}

/* r = a^(n-2) mod n = 1/a for a in [1, n-1]. n-2 is a PUBLIC fixed exponent, derived here from
 * the stored n so no second constant exists to be wrong, and brisk__bn_modpow_pub branches on its
 * bits by contract. Nothing secret may ever be passed as `a` either - see the file header. */
static void p384_sc_inv_pub(uint8_t r[48], const uint8_t a[48], const p384_ctx *c)
{
    p384_fe x;
    uint32_t sc[2 * P384_WORDS];
    uint8_t e[48];
    (void)brisk__bn_decode_into(x, c->n, a, P384_BYTES);
    memcpy(e, P384_N, sizeof e);
    e[P384_BYTES - 1] = (uint8_t)(e[P384_BYTES - 1] - 2); /* n ends in 0x73: no borrow */
    (void)brisk__bn_modpow_pub(x, e, sizeof e, c->n, sc);
    (void)brisk__bn_encode(r, P384_BYTES, x);
    brisk__secure_zero(x, sizeof x);
    brisk__secure_zero(sc, sizeof sc);
}

/* ---------------------------------------------------------------------------- public API */
int brisk__p384_ecdsa_verify(const uint8_t pub[97], const uint8_t *hash, size_t hash_len,
                             const uint8_t sig[96])
{
    p384_ctx c;
    p384_pt g, q, rpt;
    uint8_t e[48], w[48], u1[48], u2[48], v[48], xr[48];
    int rc;

    /* BRISK__CT_PUBLIC: every input to a signature verification is public by construction. r, s
     * and the digest travel in the clear inside a certificate or a CertificateVerify, the peer's
     * public key is published, and the verdict becomes a visible alert. This declassifies what
     * the caller handed us, never one of our own secrets. */
    BRISK__CT_PUBLIC(pub, BRISK__P384_POINT_LEN);
    BRISK__CT_PUBLIC(sig, BRISK__P384_SIG_LEN);

    /* hash_len is the caller's own count, not peer data, so it is checked BEFORE `hash` is
     * declassified: a length that underflowed upstream would otherwise mark an arbitrary range
     * defined and mask a genuine taint report elsewhere in the same `dev.py ct` run. Only the
     * leftmost 48 bytes are ever read, so that is all this releases. */
    if (hash_len < P384_BYTES) {
        return BRISK_E_ARG; /* a caller bug; RFC 9846 4.3.3 pairs this curve with SHA-384 */
    }
    BRISK__CT_PUBLIC(hash, P384_BYTES);

    p384_ctx_init(&c);
    /* FIPS 186-5 6.4.2 step 1: "if r and s are not both integers in [1, n-1], output INVALID".
     * INVALID, not an error - a peer can put r = 0 on the wire as easily as a wrong signature -
     * so BRISK_E_AUTH, which a CertificateVerify caller maps to decrypt_error (RFC 9846 4.5.2).
     * BRISK_E_ARG here would both emit illegal_parameter and hand the peer an oracle separating
     * "malformed r/s" from "wrong signature". Checked before any point arithmetic. */
    if (!p384_sc_valid(sig, &c) || !p384_sc_valid(sig + P384_BYTES, &c)) {
        rc = BRISK_E_AUTH;
        goto done;
    }
    /* Deliberately not BRISK_E_AUTH: a public key that is not a point on the curve is malformed
     * key material, which the X.509 layer turns into bad_certificate, not a signature that failed
     * to verify. The two conditions stay distinguishable. */
    if (!p384_pt_decode(&q, pub, &c)) {
        rc = BRISK_E_ARG;
        goto done;
    }
    p384_gen(&g, &c);
    /* Step 2: e = the leftmost min(bitlen(n), bitlen(H)) bits of the digest. n is 384 bits, so
     * that is the first 48 octets - which is what lets a P-384 key certified with SHA-512 verify
     * here. A shorter digest was already rejected above. */
    memcpy(e, hash, P384_BYTES);
    p384_sc_reduce(e, e, &c);
    p384_sc_inv_pub(w, sig + P384_BYTES, &c); /* w  = s^-1 mod n */
    p384_sc_mul(u1, e, w, &c);                /* u1 = e * w mod n */
    p384_sc_mul(u2, sig, w, &c);              /* u2 = r * w mod n */
    p384_pt_mul2_pub(&rpt, u1, &g, u2, &q, &c);
    if (!p384_pt_x_affine(xr, &rpt, &c)) {
        rc = BRISK_E_AUTH; /* step 4: R is the point at infinity */
        goto done;
    }
    /* Step 5: accept iff x_R mod n == r. x_R is below p < 2n, so one conditional subtraction. */
    p384_sc_reduce(v, xr, &c);
    rc = brisk__ct_memeq(v, sig, P384_BYTES) ? BRISK_OK : BRISK_E_AUTH;

done:
    /* Nothing here is secret, so this is hygiene rather than necessity - the rule is applied
     * anyway so that a future reader does not have to decide which buffers were exempt. */
    brisk__secure_zero(&c, sizeof c);
    brisk__secure_zero(&g, sizeof g);
    brisk__secure_zero(&q, sizeof q);
    brisk__secure_zero(&rpt, sizeof rpt);
    brisk__secure_zero(e, sizeof e);
    brisk__secure_zero(w, sizeof w);
    brisk__secure_zero(u1, sizeof u1);
    brisk__secure_zero(u2, sizeof u2);
    brisk__secure_zero(v, sizeof v);
    brisk__secure_zero(xr, sizeof xr);
    return rc;
}

#endif /* BRISK_ENABLE_P384 */

#undef P384_BYTES
#undef P384_WORDS
