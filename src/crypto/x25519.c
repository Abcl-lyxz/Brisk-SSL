/* x25519.c - X25519 (RFC 7748 section 5) on vendored fiat-crypto field arithmetic.
 *
 * The field layer is vendor/fiat/curve25519_{64,32}.c, generated and proved by fiat-crypto. Every
 * function in those files is `static`, so the file is #included here rather than compiled on its
 * own (vendor/VENDORED.md); this translation unit owns the -Wunused-function silencing for the
 * operations nothing here calls: opp, and selectznz - the conditional swap is hand-rolled as
 * mask/XOR so it stays visibly branch-free.
 *
 * Everything above the field layer is ours: decodeScalar25519, the Montgomery ladder with the
 * conditional swap, Fermat inversion, and the all-zero check that RFC 9846 section 7.4.2 makes a
 * MUST for TLS.
 *
 * Wipe scope: every local of ours holding a secret or an intermediate is zeroed before return,
 * including the fe_loose scratch inside fe_mul/fe_sq (fe_mul(x2, x2, z2) ends holding the shared
 * secret's factors). What we cannot reach is the frame of fiat itself: fiat_25519_carry_mul and
 * friends keep the same limbs in their own locals and vendor/fiat/ is edit-blocked, so a stack
 * scan after brisk__x25519() can still find field-element residue. Closing that would mean
 * scrubbing the whole stack window below the caller, which is a separate, deliberate decision -
 * not something this file silently claims to have done.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wunused-function"
#endif
#if BRISK__FIAT_64
#    include "fiat/curve25519_64.c"
typedef uint64_t fe_limb;
#else
#    include "fiat/curve25519_32.c"
typedef uint32_t fe_limb;
#endif
#if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic pop
#endif

typedef fiat_25519_tight_field_element fe_tight;
typedef fiat_25519_loose_field_element fe_loose;

#define FE_LIMBS (sizeof(fe_tight) / sizeof(fe_limb)) /* 5 (51-bit) or 10 (25.5-bit) */

/* Conditional swap (RFC 7748 5, "cswap"): mask = 0 - swap is all-ones or all-zero, so the XOR
 * exchange runs the same instructions either way. `swap` is one bit of the private scalar. */
static void fe_cswap(fe_tight a, fe_tight b, uint32_t swap)
{
    fe_limb mask = (fe_limb)0 - (fe_limb)swap;
    size_t i;
    for (i = 0; i < FE_LIMBS; i++) {
        fe_limb t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/* tight-in/tight-out wrappers for the inversion chain, where the extra relax copies do not
 * matter. The ladder below keeps the loose/tight split explicit, because mixing the two breaks
 * the preconditions fiat's carry chains are proved against. out may alias the inputs: relax
 * copies first. */
static void fe_mul(fe_tight out, const fe_tight a, const fe_tight b)
{
    fe_loose la, lb;
    fiat_25519_relax(la, a);
    fiat_25519_relax(lb, b);
    fiat_25519_carry_mul(out, la, lb);
    brisk__secure_zero(la, sizeof la);
    brisk__secure_zero(lb, sizeof lb);
}

static void fe_sq(fe_tight out, const fe_tight a)
{
    fe_loose la;
    fiat_25519_relax(la, a);
    fiat_25519_carry_square(out, la);
    brisk__secure_zero(la, sizeof la);
}

/* out = a^(2^n), n >= 1. out may alias a. */
static void fe_sqn(fe_tight out, const fe_tight a, unsigned n)
{
    unsigned i;
    fe_sq(out, a);
    for (i = 1; i < n; i++) {
        fe_sq(out, out);
    }
}

/* out = z^(p-2) = 1/z for z != 0, and 0 for z == 0 (the small-order case, which the caller then
 * rejects). Fixed 254 squarings + 11 multiplications: the exponent is a constant, so the chain
 * has no data-dependent step. out may alias z. */
static void fe_invert(fe_tight out, const fe_tight z)
{
    fe_tight t0, t1, t2;
    fe_sq(t0, z);       /* z^2 */
    fe_sqn(t1, t0, 2);  /* z^8 */
    fe_mul(t1, t1, z);  /* z^9 */
    fe_mul(t0, t0, t1); /* z^11 */
    fe_sq(t2, t0);      /* z^22 */
    fe_mul(t1, t1, t2); /* z^(2^5 - 1) */
    fe_sqn(t2, t1, 5);
    fe_mul(t1, t2, t1); /* z^(2^10 - 1) */
    fe_sqn(t2, t1, 10);
    fe_mul(t2, t2, t1); /* z^(2^20 - 1) */
    fe_sqn(out, t2, 20);
    fe_mul(t2, out, t2); /* z^(2^40 - 1) */
    fe_sqn(t2, t2, 10);
    fe_mul(t1, t2, t1); /* z^(2^50 - 1) */
    fe_sqn(t2, t1, 50);
    fe_mul(t2, t2, t1); /* z^(2^100 - 1) */
    fe_sqn(out, t2, 100);
    fe_mul(t2, out, t2); /* z^(2^200 - 1) */
    fe_sqn(t2, t2, 50);
    fe_mul(t1, t2, t1); /* z^(2^250 - 1) */
    fe_sqn(t1, t1, 5);
    fe_mul(out, t1, t0); /* z^(2^255 - 21) = z^(p-2) */
    brisk__secure_zero(t0, sizeof t0);
    brisk__secure_zero(t1, sizeof t1);
    brisk__secure_zero(t2, sizeof t2);
}

/* The Montgomery ladder of RFC 7748 5, t = 254..0, leaving (x_2, z_2).
 *
 * One deliberate deviation from the RFC's printed formulas: fiat exports carry_scmul_121666, so
 * the last step is computed as z_2 = E * (BB + 121666*E) instead of the RFC's
 * z_2 = E * (AA + a24*E) with a24 = 121665. With E = AA - BB both expand to 121666*AA -
 * 121665*BB, so they are the same value; this is the donna/BoringSSL arrangement, and the RFC 5.2
 * vectors in tests/test_x25519.c are the proof that it is.
 *
 * `k` is the already-clamped scalar and x1 the (masked, possibly non-canonical) u-coordinate. */
static void ladder(fe_tight x2, fe_tight z2, const uint8_t k[32], const fe_loose x1)
{
    fe_tight x3, z3, da, cb, t;
    fe_loose a, b, c, d, l0, l1;
    uint32_t swap = 0;
    int pos;

    memset(x2, 0, sizeof(fe_tight));
    x2[0] = 1; /* x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1 */
    memset(z2, 0, sizeof(fe_tight));
    memset(z3, 0, sizeof(fe_tight));
    z3[0] = 1;
    fiat_25519_carry(x3, x1); /* x1 is loose; x_3 needs a tight copy */

    for (pos = 254; pos >= 0; pos--) {
        uint32_t bit = (uint32_t)((k[pos >> 3] >> (pos & 7)) & 1);
        fe_cswap(x2, x3, swap ^ bit);
        fe_cswap(z2, z3, swap ^ bit);
        swap = bit;

        fiat_25519_add(a, x2, z2); /* A = x_2 + z_2 */
        fiat_25519_sub(b, x2, z2); /* B = x_2 - z_2 */
        fiat_25519_add(c, x3, z3); /* C = x_3 + z_3 */
        fiat_25519_sub(d, x3, z3); /* D = x_3 - z_3 */
        fiat_25519_carry_mul(da, d, a);
        fiat_25519_carry_mul(cb, c, b);
        fiat_25519_sub(l0, da, cb);
        fiat_25519_carry_square(t, l0);
        fiat_25519_relax(l0, t);
        fiat_25519_carry_mul(z3, l0, x1); /* z_3 = x_1 * (DA - CB)^2 */
        fiat_25519_add(l0, da, cb);
        fiat_25519_carry_square(x3, l0); /* x_3 = (DA + CB)^2 */
        fiat_25519_carry_square(da, a);  /* AA (da is dead) */
        fiat_25519_carry_square(cb, b);  /* BB (cb is dead) */
        fiat_25519_relax(l0, da);
        fiat_25519_relax(l1, cb);
        fiat_25519_carry_mul(x2, l0, l1); /* x_2 = AA * BB */
        fiat_25519_sub(l0, da, cb);       /* E = AA - BB */
        fiat_25519_carry_scmul_121666(t, l0);
        fiat_25519_add(l1, cb, t);
        fiat_25519_carry_mul(z2, l0, l1); /* z_2 = E * (BB + 121666*E) */
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    brisk__secure_zero(x3, sizeof x3);
    brisk__secure_zero(z3, sizeof z3);
    brisk__secure_zero(da, sizeof da);
    brisk__secure_zero(cb, sizeof cb);
    brisk__secure_zero(t, sizeof t);
    brisk__secure_zero(a, sizeof a);
    brisk__secure_zero(b, sizeof b);
    brisk__secure_zero(c, sizeof c);
    brisk__secure_zero(d, sizeof d);
    brisk__secure_zero(l0, sizeof l0);
    brisk__secure_zero(l1, sizeof l1);
}

int brisk__x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    static const uint8_t zero32[BRISK__X25519_LEN] = {0};
    uint8_t k[BRISK__X25519_LEN], ub[BRISK__X25519_LEN];
    fe_tight x1, x2, z2;
    fe_loose x1l;
    int is_zero;

    /* decodeScalar25519 (RFC 7748 5) on a private copy: the caller's scalar is left alone. */
    memcpy(k, scalar, sizeof k);
    k[0] = (uint8_t)(k[0] & 248);
    k[31] = (uint8_t)((k[31] & 127) | 64);

    /* Mask bit 255 of the u-coordinate: a MUST in RFC 7748 5, and also the documented input bound
     * of fiat_25519_from_bytes (arg1[31] is [0x0 ~> 0x7f]). Done here, never left to the caller.
     * A non-canonical u (2^255-19 .. 2^255-1) is accepted and simply reduced by the field
     * arithmetic - the RFC forbids rejecting it, and there is no point validation at all. */
    memcpy(ub, u, sizeof ub);
    ub[31] = (uint8_t)(ub[31] & 127);
    fiat_25519_from_bytes(x1, ub);
    fiat_25519_relax(x1l, x1);

    ladder(x2, z2, k, x1l);
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fiat_25519_to_bytes(out, x2); /* canonical, so bit 255 of out is zero by construction */

    /* RFC 7748 6.1 / 7 and RFC 9846 7.4.2 (MUST): an all-zero shared secret means the peer sent a
     * small-order point. Compare without leaking (the RFC's "OR all the bytes together"), then
     * declassify the one-bit answer - the protocol aborts visibly, so it is public by design. */
    is_zero = brisk__ct_memeq(out, zero32, sizeof zero32);
    BRISK__CT_PUBLIC(&is_zero, sizeof is_zero);

    brisk__secure_zero(k, sizeof k);
    brisk__secure_zero(ub, sizeof ub);
    brisk__secure_zero(x1, sizeof x1);
    brisk__secure_zero(x1l, sizeof x1l);
    brisk__secure_zero(x2, sizeof x2);
    brisk__secure_zero(z2, sizeof z2);
    if (is_zero) {
        brisk__secure_zero(out, BRISK__X25519_LEN);
        return BRISK_E_ARG;
    }
    return BRISK_OK;
}

void brisk__x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    /* u = 9 (RFC 7748 6.1): the base point, encoded as a 9 byte followed by 31 zero bytes. A
     * clamped scalar is a nonzero multiple of 8 below the group order, so the result is never the
     * all-zero value and brisk__x25519 cannot fail here. */
    static const uint8_t base[BRISK__X25519_LEN] = {9};
    (void)brisk__x25519(out, scalar, base);
}

#undef FE_LIMBS
