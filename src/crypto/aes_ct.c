/* aes_ct.c - AES-128/256 forward cipher (FIPS 197 5.1, 5.2), bitsliced and constant time, two
 * blocks per pass in uint32_t q[8]; plus the inc32 counter mode of SP 800-38D 6.2/6.5 (GCTR).
 * Compiled on 32-bit targets only (BRISK__AES_CT64 == 0); aes_ct64.c serves 64-bit ones.
 *
 * SPDX-License-Identifier: Apache-2.0 AND MIT
 *
 * Adapted from BearSSL src/symcipher/aes_ct.c, aes_ct_enc.c and aes_ct_ctr.c (commit
 * 7bea48e5e850ab4cafbe68d3765cdaba13a86d6f); see NOTICE. Changes: encrypt only, no AES-192, own
 * API and wiping. Original notice:
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

#if !BRISK__AES_CT64

/* Layout: word i of block A sits in q[2i], of block B in q[2i+1]; ortho() transposes that into
 * 8 bit planes. No table is indexed by secret data anywhere: the S-box is a boolean circuit. */

/* FIPS 197 5.1.1 SubBytes on all 32 bytes at once: the Boyar-Peralta circuit ("A new combinational
 * logic minimization technique with applications to cryptology", eprint 2009/191). x0 is the high
 * bit plane, x7 the low one. */
static void sbox(uint32_t *q)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t y1, y2, y3, y4, y5, y6, y7, y8, y9;
    uint32_t y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
    uint32_t y20, y21;
    uint32_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
    uint32_t z10, z11, z12, z13, z14, z15, z16, z17;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
    uint32_t t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
    uint32_t t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
    uint32_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
    uint32_t t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
    uint32_t t60, t61, t62, t63, t64, t65, t66, t67;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7;

    x0 = q[7];
    x1 = q[6];
    x2 = q[5];
    x3 = q[4];
    x4 = q[3];
    x5 = q[2];
    x6 = q[1];
    x7 = q[0];

    /* top linear transformation */
    y14 = x3 ^ x5;
    y13 = x0 ^ x6;
    y9 = x0 ^ x3;
    y8 = x0 ^ x5;
    t0 = x1 ^ x2;
    y1 = t0 ^ x7;
    y4 = y1 ^ x3;
    y12 = y13 ^ y14;
    y2 = y1 ^ x0;
    y5 = y1 ^ x6;
    y3 = y5 ^ y8;
    t1 = x4 ^ y12;
    y15 = t1 ^ x5;
    y20 = t1 ^ x1;
    y6 = y15 ^ x7;
    y10 = y15 ^ t0;
    y11 = y20 ^ y9;
    y7 = x7 ^ y11;
    y17 = y10 ^ y11;
    y19 = y10 ^ y8;
    y16 = t0 ^ y11;
    y21 = y13 ^ y16;
    y18 = x0 ^ y16;

    /* non-linear section */
    t2 = y12 & y15;
    t3 = y3 & y6;
    t4 = t3 ^ t2;
    t5 = y4 & x7;
    t6 = t5 ^ t2;
    t7 = y13 & y16;
    t8 = y5 & y1;
    t9 = t8 ^ t7;
    t10 = y2 & y7;
    t11 = t10 ^ t7;
    t12 = y9 & y11;
    t13 = y14 & y17;
    t14 = t13 ^ t12;
    t15 = y8 & y10;
    t16 = t15 ^ t12;
    t17 = t4 ^ t14;
    t18 = t6 ^ t16;
    t19 = t9 ^ t14;
    t20 = t11 ^ t16;
    t21 = t17 ^ y20;
    t22 = t18 ^ y19;
    t23 = t19 ^ y21;
    t24 = t20 ^ y18;

    t25 = t21 ^ t22;
    t26 = t21 & t23;
    t27 = t24 ^ t26;
    t28 = t25 & t27;
    t29 = t28 ^ t22;
    t30 = t23 ^ t24;
    t31 = t22 ^ t26;
    t32 = t31 & t30;
    t33 = t32 ^ t24;
    t34 = t23 ^ t33;
    t35 = t27 ^ t33;
    t36 = t24 & t35;
    t37 = t36 ^ t34;
    t38 = t27 ^ t36;
    t39 = t29 & t38;
    t40 = t25 ^ t39;

    t41 = t40 ^ t37;
    t42 = t29 ^ t33;
    t43 = t29 ^ t40;
    t44 = t33 ^ t37;
    t45 = t42 ^ t41;
    z0 = t44 & y15;
    z1 = t37 & y6;
    z2 = t33 & x7;
    z3 = t43 & y16;
    z4 = t40 & y1;
    z5 = t29 & y7;
    z6 = t42 & y11;
    z7 = t45 & y17;
    z8 = t41 & y10;
    z9 = t44 & y12;
    z10 = t37 & y3;
    z11 = t33 & y4;
    z12 = t43 & y13;
    z13 = t40 & y5;
    z14 = t29 & y2;
    z15 = t42 & y9;
    z16 = t45 & y14;
    z17 = t41 & y8;

    /* bottom linear transformation */
    t46 = z15 ^ z16;
    t47 = z10 ^ z11;
    t48 = z5 ^ z13;
    t49 = z9 ^ z10;
    t50 = z2 ^ z12;
    t51 = z2 ^ z5;
    t52 = z7 ^ z8;
    t53 = z0 ^ z3;
    t54 = z6 ^ z7;
    t55 = z16 ^ z17;
    t56 = z12 ^ t48;
    t57 = t50 ^ t53;
    t58 = z4 ^ t46;
    t59 = z3 ^ t54;
    t60 = t46 ^ t57;
    t61 = z14 ^ t57;
    t62 = t52 ^ t58;
    t63 = t49 ^ t58;
    t64 = z4 ^ t59;
    t65 = t61 ^ t62;
    t66 = z1 ^ t63;
    s0 = t59 ^ t63;
    s6 = t56 ^ ~t62;
    s7 = t48 ^ ~t60;
    t67 = t64 ^ t65;
    s3 = t53 ^ t66;
    s4 = t51 ^ t66;
    s5 = t47 ^ t65;
    s1 = t64 ^ ~s3;
    s2 = t55 ^ ~t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/* Bit-matrix transpose between "two interleaved blocks" and "8 bit planes" (an involution). */
#    define BRISK__CT_SWAPN(cl, ch, s, x, y)                                                       \
        do {                                                                                       \
            uint32_t a_ = (x), b_ = (y);                                                           \
            (x) = (a_ & (uint32_t)(cl)) | ((b_ & (uint32_t)(cl)) << (s));                          \
            (y) = ((a_ & (uint32_t)(ch)) >> (s)) | (b_ & (uint32_t)(ch));                          \
        } while (0)
#    define BRISK__CT_SWAP2(x, y) BRISK__CT_SWAPN(0x55555555, 0xAAAAAAAA, 1, x, y)
#    define BRISK__CT_SWAP4(x, y) BRISK__CT_SWAPN(0x33333333, 0xCCCCCCCC, 2, x, y)
#    define BRISK__CT_SWAP8(x, y) BRISK__CT_SWAPN(0x0F0F0F0F, 0xF0F0F0F0, 4, x, y)

static void ortho(uint32_t *q)
{
    BRISK__CT_SWAP2(q[0], q[1]);
    BRISK__CT_SWAP2(q[2], q[3]);
    BRISK__CT_SWAP2(q[4], q[5]);
    BRISK__CT_SWAP2(q[6], q[7]);

    BRISK__CT_SWAP4(q[0], q[2]);
    BRISK__CT_SWAP4(q[1], q[3]);
    BRISK__CT_SWAP4(q[4], q[6]);
    BRISK__CT_SWAP4(q[5], q[7]);

    BRISK__CT_SWAP8(q[0], q[4]);
    BRISK__CT_SWAP8(q[1], q[5]);
    BRISK__CT_SWAP8(q[2], q[6]);
    BRISK__CT_SWAP8(q[3], q[7]);
}

#    undef BRISK__CT_SWAP8
#    undef BRISK__CT_SWAP4
#    undef BRISK__CT_SWAP2
#    undef BRISK__CT_SWAPN

/* FIPS 197 5.2 SubWord through the bitsliced S-box (no key-indexed table). */
static uint32_t sub_word(uint32_t x)
{
    uint32_t q[8], r;
    unsigned i;
    for (i = 0; i < 8; i++) {
        q[i] = x;
    }
    ortho(q);
    sbox(q);
    ortho(q);
    r = q[0];
    brisk__secure_zero(q, sizeof q);
    return r;
}

/* FIPS 197 5.2 Rcon (public constants). */
static const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

int brisk__aes_init(brisk__aes_key *k, const uint8_t *key, size_t key_len)
{
    uint32_t skey[120], tmp;
    unsigned i, j, r, nk, nkf, nr;

    if (key_len != 16 && key_len != 32) {
        return BRISK_E_ARG;
    }
    nk = (unsigned)(key_len >> 2);
    nr = nk + 6;
    nkf = (nr + 1) << 2;
    tmp = 0;
    for (i = 0; i < nk; i++) {
        tmp = brisk__load_le32(key + (i << 2));
        skey[(i << 1) + 0] = tmp;
        skey[(i << 1) + 1] = tmp;
    }
    /* i, j and r depend only on the (public) key length */
    for (i = nk, j = 0, r = 0; i < nkf; i++) {
        if (j == 0) {
            tmp = (tmp << 24) | (tmp >> 8); /* RotWord, little-endian word */
            tmp = sub_word(tmp) ^ RCON[r];
        } else if (nk > 6 && j == 4) {
            tmp = sub_word(tmp);
        }
        tmp ^= skey[(i - nk) << 1];
        skey[(i << 1) + 0] = tmp;
        skey[(i << 1) + 1] = tmp;
        if (++j == nk) {
            j = 0;
            r++;
        }
    }
    for (i = 0; i < nkf; i += 4) {
        ortho(skey + (i << 1));
    }
    for (i = 0, j = 0; i < nkf; i++, j += 2) {
        k->sk.w32[i] = (skey[j + 0] & 0x55555555u) | (skey[j + 1] & 0xAAAAAAAAu);
    }
    k->nr = nr;
    k->pad = 0;
    brisk__secure_zero(skey, sizeof skey);
    return BRISK_OK;
}

/* Compressed schedule -> 8 words per round key. */
static void skey_expand(uint32_t *skey, const brisk__aes_key *k)
{
    unsigned u, v, n = (k->nr + 1) << 2;
    for (u = 0, v = 0; u < n; u++, v += 2) {
        uint32_t x = k->sk.w32[u] & 0x55555555u, y = k->sk.w32[u] & 0xAAAAAAAAu;
        skey[v + 0] = x | (x << 1);
        skey[v + 1] = y | (y >> 1);
    }
}

static void add_round_key(uint32_t *q, const uint32_t *sk)
{
    unsigned i;
    for (i = 0; i < 8; i++) {
        q[i] ^= sk[i];
    }
}

/* FIPS 197 5.1.2 */
static void shift_rows(uint32_t *q)
{
    unsigned i;
    for (i = 0; i < 8; i++) {
        uint32_t x = q[i];
        q[i] = (x & 0x000000FFu) | ((x & 0x0000FC00u) >> 2) | ((x & 0x00000300u) << 6) |
               ((x & 0x00F00000u) >> 4) | ((x & 0x000F0000u) << 4) | ((x & 0xC0000000u) >> 6) |
               ((x & 0x3F000000u) << 2);
    }
}

static uint32_t rotr16(uint32_t x)
{
    return (x << 16) | (x >> 16);
}

/* FIPS 197 5.1.3 */
static void mix_columns(uint32_t *q)
{
    uint32_t q0, q1, q2, q3, q4, q5, q6, q7;
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7;

    q0 = q[0];
    q1 = q[1];
    q2 = q[2];
    q3 = q[3];
    q4 = q[4];
    q5 = q[5];
    q6 = q[6];
    q7 = q[7];
    r0 = (q0 >> 8) | (q0 << 24);
    r1 = (q1 >> 8) | (q1 << 24);
    r2 = (q2 >> 8) | (q2 << 24);
    r3 = (q3 >> 8) | (q3 << 24);
    r4 = (q4 >> 8) | (q4 << 24);
    r5 = (q5 >> 8) | (q5 << 24);
    r6 = (q6 >> 8) | (q6 << 24);
    r7 = (q7 >> 8) | (q7 << 24);

    q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
    q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
    q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
    q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
    q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
}

/* FIPS 197 5.1 Cipher() on the bitsliced state; the last round has no MixColumns. */
static void encrypt_q(unsigned nr, const uint32_t *skey, uint32_t *q)
{
    unsigned u;
    ortho(q);
    add_round_key(q, skey);
    for (u = 1; u < nr; u++) {
        sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, skey + (u << 3));
    }
    sbox(q);
    shift_rows(q);
    add_round_key(q, skey + (nr << 3));
    ortho(q);
}

void brisk__aes_encrypt(const brisk__aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    uint32_t skey[120], q[8];
    unsigned i;
    skey_expand(skey, k);
    for (i = 0; i < 4; i++) {
        q[2 * i] = brisk__load_le32(in + 4 * i);
        q[2 * i + 1] = 0;
    }
    encrypt_q(k->nr, skey, q);
    for (i = 0; i < 4; i++) {
        brisk__store_le32(out + 4 * i, q[2 * i]);
    }
    brisk__secure_zero(skey, sizeof skey);
    brisk__secure_zero(q, sizeof q);
}

static uint32_t bswap32(uint32_t x)
{
    return (x << 24) | ((x & 0xFF00u) << 8) | ((x >> 8) & 0xFF00u) | (x >> 24);
}

void brisk__aes_ctr32(const brisk__aes_key *k, const uint8_t cb[16], const uint8_t *in, size_t len,
                      uint8_t *out)
{
    uint32_t skey[120], q[8], iv0, iv1, iv2, cc;
    uint8_t ks[32];
    unsigned i;

    if (len == 0) {
        return;
    }
    skey_expand(skey, k);
    iv0 = brisk__load_le32(cb);
    iv1 = brisk__load_le32(cb + 4);
    iv2 = brisk__load_le32(cb + 8);
    cc = brisk__load_be32(cb + 12); /* inc32: only this word counts, mod 2^32 */
    for (;;) {
        size_t n = len < 32 ? len : 32, j;
        q[0] = q[1] = iv0;
        q[2] = q[3] = iv1;
        q[4] = q[5] = iv2;
        q[6] = bswap32(cc);
        q[7] = bswap32(cc + 1);
        encrypt_q(k->nr, skey, q);
        for (i = 0; i < 4; i++) {
            brisk__store_le32(ks + 4 * i, q[2 * i]);
            brisk__store_le32(ks + 16 + 4 * i, q[2 * i + 1]);
        }
        for (j = 0; j < n; j++) {
            out[j] = (uint8_t)(in[j] ^ ks[j]);
        }
        len -= n;
        if (len == 0) {
            break;
        }
        in += n;
        out += n;
        cc += 2;
    }
    brisk__secure_zero(skey, sizeof skey);
    brisk__secure_zero(q, sizeof q);
    brisk__secure_zero(ks, sizeof ks);
}

#endif /* !BRISK__AES_CT64 */
