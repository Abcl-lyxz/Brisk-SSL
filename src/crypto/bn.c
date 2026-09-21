/* bn.c - i31 big integers with a constant-time Montgomery core.
 *
 * The i31 layout and the CIOS multiplication are adapted from BearSSL (MIT, Thomas Pornin): x[0]
 * is the announced bit length and x[1...] are 31-bit limbs, least significant first. RFC 8017
 * 4.1/4.2 (I2OSP/OS2IP) fixes the byte format. See the notice at the end of this header.
 *
 * WHAT THIS FILE IS FOR. Two consumers, both verify-only: src/crypto/rsa.c (RSASSA-PKCS1-v1_5
 * and RSASSA-PSS verification, 2048 to BRISK_RSA_MAX_BITS bits) and, next, P-384 ECDSA verify.
 * P-384 needs mont_mul, add, sub, lt, decode/encode, ninv31 and to_mont/from_mont - all here -
 * plus field inversion a^(p-2) mod p and scalar inversion s^(n-2) mod n, which are PUBLIC fixed
 * exponents and so are served by brisk__bn_modpow_pub unchanged. Reducing a 384-bit digest or
 * x1 mod n is one conditional subtraction, because 2*n384 and 2*p384 both exceed 2^384, exactly
 * as in p256.c's scalar core. p384.c therefore adds curve constants, a point type and a ladder,
 * and needs no change here.
 *
 * CONSTANT TIME, stated honestly rather than claimed. Nothing secret passes through this file
 * today: an RSA public key, a signature and a digest are all public, and P-384 verify inputs will
 * be too. The kernel is branch-free, index-free and division-free on its data anyway, so that the
 * first consumer with a secret scalar inherits a safe core instead of needing a rewrite. The one
 * deliberate exception is brisk__bn_modpow_pub, which walks the bits of a PUBLIC exponent and
 * branches on them; it declassifies them with BRISK__CT_PUBLIC so that dev.py ct keeps reporting
 * everything else. The failure mode to guard against is the opposite of the usual one: someone
 * later passing a secret exponent because the name looked generic. Hence the _pub suffix.
 *
 * NO 64-BIT DIVISION. All length arithmetic is uint32_t with the constant divisor 31, which every
 * compiler in the matrix turns into a multiply; `tools/dev.py size` fails the build on a
 * __udivdi3 reference, and that is the intended guard rather than a warning.
 *
 * BIG-ENDIAN AND 32-BIT TARGETS. Octets are read and written one at a time; no uint8_t * is ever
 * cast to a wider pointer (which would also fault on armv5 and mips), and every shift is by a
 * value below 32 on a uint32_t or below 64 on a uint64_t.
 *
 * File-local statics carry a bn_ prefix rather than bare names, so the M8 amalgamation
 * (dist/brisk.c) has nothing to collide with; p384.c must use p384_ for the same reason.
 *
 * SPDX-License-Identifier: Apache-2.0 AND MIT
 *
 * The i31 representation, the CIOS Montgomery multiplication, the limb add/sub and the ninv31
 * Newton iteration are adapted from BearSSL src/int/i31_montmul.c, i31_add.c, i31_sub.c and
 * i31_ninv31.c (commit 7bea48e5e850ab4cafbe68d3765cdaba13a86d6f); see NOTICE. Changes: own
 * decode/encode pair, run-time n0 derivation, doubling-based to_mont, no general-purpose value
 * type, own wiping and ct annotations. Original notice:
 *
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "brisk_int.h"

#define BN_MASK 0x7FFFFFFFu

/* Number of 31-bit limbs implied by an announced bit length. The header word is not counted. */
static uint32_t bn_limbs(const uint32_t *x)
{
    return (x[0] + 30) / 31;
}

/* Limb k of the big-endian octet string src[0..len), or 0 past the top. All byte access. */
static uint32_t bn_limb_from_be(const uint8_t *src, size_t len, uint32_t k)
{
    uint32_t lo = 31 * k, byte = lo >> 3, sh = lo & 7, v = 0, i;
    for (i = 0; i < 4; i++) {
        size_t idx = (size_t)byte + i;
        v |= (uint32_t)(idx < len ? src[len - 1 - idx] : 0) << (8 * i);
    }
    v >>= sh; /* 32 - sh bits of the value are now in place */
    if (sh > 1) {
        size_t idx = (size_t)byte + 4;
        v |= (uint32_t)(idx < len ? src[len - 1 - idx] : 0) << (32 - sh);
    }
    return v & BN_MASK;
}

/* Bit length of the octet string with leading zero octets already skipped. Saturates: a string
 * that long would wrap (len - 1) * 8, and every caller rejects UINT32_MAX anyway. */
static uint32_t bn_be_bitlen(const uint8_t *src, size_t len)
{
    uint32_t top = src[0], n = 0;
    if (len > 0x1FFFFFFFu) {
        return UINT32_MAX;
    }
    while (top) {
        n++;
        top >>= 1;
    }
    return (uint32_t)(len - 1) * 8 + n;
}

int brisk__bn_decode_mod(uint32_t *m, uint32_t max_bits, const uint8_t *src, size_t src_len)
{
    uint32_t bits, limbs, i;
    m[0] = 0; /* every failure below leaves a zero width, never an indeterminate one */
    while (src_len > 0 && *src == 0) { /* RFC 8017 4.2: leading zero octets are accepted */
        src++;
        src_len--;
    }
    if (src_len == 0) {
        return BRISK_E_ARG; /* zero has no bit length and is not an odd modulus */
    }
    bits = bn_be_bitlen(src, src_len);
    if (bits > max_bits || (src[src_len - 1] & 1) == 0) {
        return BRISK_E_ARG; /* too wide, or even: no inverse mod 2^31 exists */
    }
    m[0] = bits;
    limbs = bn_limbs(m);
    for (i = 0; i < limbs; i++) {
        m[1 + i] = bn_limb_from_be(src, src_len, i);
    }
    return BRISK_OK;
}

int brisk__bn_decode_into(uint32_t *x, const uint32_t *m, const uint8_t *src, size_t src_len)
{
    uint32_t limbs, i;
    while (src_len > 0 && *src == 0) {
        src++;
        src_len--;
    }
    if (src_len > 0 && bn_be_bitlen(src, src_len) > m[0]) {
        return BRISK_E_ARG; /* does not fit the modulus's announced width */
    }
    x[0] = m[0];
    limbs = bn_limbs(x);
    for (i = 0; i < limbs; i++) {
        x[1 + i] = src_len ? bn_limb_from_be(src, src_len, i) : 0;
    }
    return BRISK_OK;
}

int brisk__bn_encode(uint8_t *dst, size_t dst_len, const uint32_t *x)
{
    uint32_t limbs = bn_limbs(x), k = 0, sh = 0, extra = 0, j, nbytes;
    nbytes = (31 * limbs + 7) / 8;
    /* Two passes so that dst is untouched when the value does not fit: the caller's buffer must
     * not be half-written on BRISK_E_ARG. */
    for (j = 0; j < nbytes; j++) {
        uint32_t v = x[1 + k] >> sh;
        if (sh > 23) {
            v |= (k + 1 < limbs ? x[2 + k] : 0) << (31 - sh);
        }
        if ((size_t)j >= dst_len) {
            extra |= v & 0xFFu;
        }
        sh += 8;
        if (sh >= 31) {
            sh -= 31;
            k++;
        }
    }
    /* The one thing this function can reveal about x: whether it fits the width the caller asked
     * for. Declassified on purpose, with the same reasoning as pt_encode's "the result is the
     * point at infinity" bit in p256.c. PKCS#1 v1.5 encodes at the full modulus width, where the
     * answer is always yes; PSS encodes at emLen = ceil((modBits - 1)/8), which is k - 1 when
     * modBits - 1 is a multiple of 8, and there a "no" is exactly RFC 8017 8.1.2 step 2c's
     * "integer too large" -> invalid signature. That outcome is public: it is a fact about a
     * signature the attacker sent. A caller that asks for a narrower buffer has chosen to ask a
     * question about the value. This is the second and last declassification in this file; any
     * other report from `dev.py ct` is a real finding. */
    BRISK__CT_PUBLIC(&extra, sizeof extra);
    if (extra != 0) {
        return BRISK_E_ARG;
    }
    k = 0;
    sh = 0;
    for (j = 0; j < dst_len; j++) {
        uint32_t v = 0;
        if (j < nbytes) {
            v = x[1 + k] >> sh;
            if (sh > 23) {
                v |= (k + 1 < limbs ? x[2 + k] : 0) << (31 - sh);
            }
            sh += 8;
            if (sh >= 31) {
                sh -= 31;
                k++;
            }
        }
        dst[dst_len - 1 - j] = (uint8_t)v;
    }
    return BRISK_OK;
}

uint32_t brisk__bn_lt(const uint32_t *a, const uint32_t *b)
{
    uint32_t limbs = bn_limbs(a), i, borrow = 0;
    for (i = 0; i < limbs; i++) {
        /* Limbs are below 2^31, so the difference lands in [-2^31, 2^31) and bit 31 of the
         * uint32 result is exactly the borrow. */
        uint32_t w = a[1 + i] - b[1 + i] - borrow;
        borrow = (w >> 31) & 1;
    }
    return borrow;
}

uint32_t brisk__bn_add(uint32_t *a, const uint32_t *b, uint32_t ctl)
{
    uint32_t limbs = bn_limbs(a), i, carry = 0, mask = (uint32_t)0 - ctl;
    BRISK__CT_BARRIER(mask);
    for (i = 0; i < limbs; i++) {
        uint32_t w = a[1 + i] + b[1 + i] + carry;
        carry = w >> 31;
        a[1 + i] = (a[1 + i] & ~mask) | ((w & BN_MASK) & mask);
    }
    return carry;
}

uint32_t brisk__bn_sub(uint32_t *a, const uint32_t *b, uint32_t ctl)
{
    uint32_t limbs = bn_limbs(a), i, borrow = 0, mask = (uint32_t)0 - ctl;
    BRISK__CT_BARRIER(mask);
    for (i = 0; i < limbs; i++) {
        uint32_t w = a[1 + i] - b[1 + i] - borrow;
        borrow = (w >> 31) & 1;
        a[1 + i] = (a[1 + i] & ~mask) | ((w & BN_MASK) & mask);
    }
    return borrow;
}

uint32_t brisk__bn_ninv31(const uint32_t *m)
{
    uint32_t y = 1, i;
    /* Newton doubles the number of correct bits each round; y = 1 is correct mod 2 because m is
     * odd, so five rounds reach mod 2^32. Everything wraps, which is the point. */
    for (i = 0; i < 5; i++) {
        y *= 2u - m[1] * y;
    }
    return ((uint32_t)0 - y) & BN_MASK;
}

/* d <- t mod m where t is `limbs` limbs plus the overflow word th, and t < 2m. */
static void bn_cond_sub_m(uint32_t *d, const uint32_t *t, uint32_t th, const uint32_t *m,
                          uint32_t limbs)
{
    uint32_t i, borrow = 0, mask;
    for (i = 0; i < limbs; i++) {
        uint32_t w = t[i] - m[1 + i] - borrow;
        borrow = (w >> 31) & 1;
        d[1 + i] = w & BN_MASK;
    }
    /* Keep the difference iff t >= m, i.e. iff the overflow word is set or there was no borrow.
     * Normalised to 0/1 first: th <= 1 only because of the unchecked x < m, y < m precondition,
     * and a th of 2 would make this 0xFFFFFFFE and silently corrupt limb 0. Free at -Os. */
    mask = (uint32_t)0 - (uint32_t)((th | (borrow ^ 1)) != 0);
    BRISK__CT_BARRIER(mask);
    for (i = 0; i < limbs; i++) {
        d[1 + i] = (d[1 + i] & mask) | (t[i] & ~mask);
    }
}

void brisk__bn_mont_mul(uint32_t *d, const uint32_t *x, const uint32_t *y, const uint32_t *m,
                        uint32_t n0)
{
    uint32_t t[BRISK__BN_MAX_LIMBS]; /* CIOS accumulator: t[0..limbs) only; th is the carry */
    uint32_t limbs = bn_limbs(m), i, j, th = 0;
    for (i = 0; i < limbs; i++) {
        t[i] = 0;
    }
    for (i = 0; i < limbs; i++) {
        uint32_t xi = x[1 + i], f;
        uint64_t cy1 = 0, cy2 = 0, z;
        /* f = (t[0] + x[i]*y[0]) * n0 mod 2^31; only the low bits matter, so uint32 wrapping is
         * exactly right. m[1]*n0 == -1 mod 2^31 then makes limb 0 of the sum vanish. */
        f = ((t[0] + xi * y[1]) * n0) & BN_MASK;
        for (j = 0; j < limbs; j++) {
            uint32_t lo;
            z = (uint64_t)xi * y[1 + j] + t[j] + cy1;
            cy1 = z >> 31;
            lo = (uint32_t)z & BN_MASK;
            z = (uint64_t)f * m[1 + j] + lo + cy2;
            cy2 = z >> 31;
            if (j > 0) {
                t[j - 1] = (uint32_t)z & BN_MASK;
            }
        }
        z = (uint64_t)th + cy1 + cy2;
        t[limbs - 1] = (uint32_t)z & BN_MASK;
        th = (uint32_t)(z >> 31);
    }
    /* The CIOS invariant keeps t below 2m, which one conditional subtraction can correct. */
    bn_cond_sub_m(d, t, th, m, limbs);
    d[0] = m[0];
    /* t[0..limbs) is all that was written. Wiping sizeof t instead would cost P-384 (13 limbs)
     * 536 bytes through the un-inlinable brisk__memset on every one of ~1500 multiplies. */
    brisk__secure_zero(t, (size_t)limbs * sizeof *t);
}

void brisk__bn_to_mont(uint32_t *x, const uint32_t *m)
{
    uint32_t limbs = bn_limbs(m), i, n = 31 * limbs;
    /* MEASURED: 0.95 ms of a 1.15 ms 4096-bit brisk__bn_modpow_pub with e = 65537, gcc 10.3 at
     * -Os on x86_64 - about 80% of the verify, not the quarter this comment used to claim. The
     * upgrade path (muladd_small + a constant-time divrem) is in src/brisk_int.h above the
     * declaration; it is not taken yet because no real target has measured too slow. */
    for (i = 0; i < n; i++) {
        /* x <- 2x mod m, in three passes and with no scratch: double, subtract m, and add m back
         * when the subtraction went negative and there was no carry out of the doubling. */
        uint32_t carry = brisk__bn_add(x, x, 1);
        uint32_t borrow = brisk__bn_sub(x, m, 1);
        (void)brisk__bn_add(x, m, borrow & (carry ^ 1));
    }
}

void brisk__bn_from_mont(uint32_t *x, const uint32_t *m, uint32_t n0, uint32_t *t)
{
    uint32_t limbs = bn_limbs(m), i;
    t[0] = m[0];
    t[1] = 1;
    for (i = 1; i < limbs; i++) {
        t[1 + i] = 0;
    }
    brisk__bn_mont_mul(x, x, t, m, n0);
    brisk__secure_zero(t, (size_t)(limbs + 1) * sizeof *t);
}

int brisk__bn_modpow_pub(uint32_t *x, const uint8_t *e, size_t e_len, const uint32_t *m,
                         uint32_t *t)
{
    uint32_t limbs = bn_limbs(m), n0 = brisk__bn_ninv31(m), i;
    uint32_t *acc = t, *base = t + (limbs + 1);
    size_t k;
    int bit, started;

    /* The exponent is public by contract; say so explicitly so that dev.py ct reports every
     * other data-dependent branch in this file instead of being silenced wholesale. */
    BRISK__CT_PUBLIC(e, e_len);
    while (e_len > 0 && *e == 0) {
        e++;
        e_len--;
    }
    if (e_len == 0) {
        return BRISK_E_ARG;
    }
    for (i = 0; i <= limbs; i++) {
        base[i] = x[i];
    }
    brisk__bn_to_mont(base, m);
    for (i = 0; i <= limbs; i++) {
        acc[i] = base[i];
    }
    started = 0;
    for (k = 0; k < e_len * 8; k++) {
        bit = (e[k >> 3] >> (7 - (k & 7))) & 1;
        if (!started) {
            started = bit; /* skip the leading zero bits of the first octet */
            continue;
        }
        brisk__bn_mont_mul(acc, acc, acc, m, n0);
        if (bit) {
            brisk__bn_mont_mul(acc, acc, base, m, n0);
        }
    }
    /* Leave the Montgomery domain into the caller's buffer: x <- acc * 1 * R^-1. */
    x[0] = m[0];
    x[1] = 1;
    for (i = 1; i < limbs; i++) {
        x[1 + i] = 0;
    }
    brisk__bn_mont_mul(x, acc, x, m, n0);
    brisk__secure_zero(t, (size_t)2 * (limbs + 1) * sizeof *t);
    return BRISK_OK;
}

#undef BN_MASK
