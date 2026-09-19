/* gcm.c - GHASH (SP 800-38D 6.3/6.4) and AES-GCM authenticated encryption (SP 800-38D 7.1/7.2,
 * RFC 5116 AEAD_AES_128_GCM / AEAD_AES_256_GCM), 96-bit IV and 128-bit tag only.
 *
 * GHASH is constant time without tables: carry-less multiplication is done with ordinary integer
 * multiplies on operands whose bits are spread out ("holes" every 4th bit) so no carry can reach
 * a kept bit, and the high half comes from the bit-reversed operands (rev(x) * rev(y) =
 * rev(x * y)). One variant is compiled per target, selected like aes_ct.c / aes_ct64.c:
 * ctmul64 (64x64->64 multiplies) where pointers are 64-bit, ctmul32 (32x32->32 multiplies only)
 * elsewhere, so 32-bit targets never need a widening multiply or __muldi3. Caveat: CPUs with an
 * early-terminating multiplier (ARM7/ARM9 = armv5, some MIPS32 4K cores) are not guaranteed
 * constant time; see docs/ARCHITECTURE.md.
 *
 * SPDX-License-Identifier: Apache-2.0 AND MIT
 *
 * GHASH adapted from BearSSL src/hash/ghash_ctmul32.c and ghash_ctmul64.c (commit
 * 7bea48e5e850ab4cafbe68d3765cdaba13a86d6f); see NOTICE. Changes: own API, byte order helpers
 * and wiping. Original notice:
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

/* One 16-byte GHASH input block: the next 16 bytes, or the zero-padded tail (SP 800-38D 7.1
 * step 5, the 0^v / 0^u padding). */
static const uint8_t *next_block(const uint8_t **data, size_t *len, uint8_t tmp[16])
{
    const uint8_t *src = *data;
    if (*len >= 16) {
        *data += 16;
        *len -= 16;
        return src;
    }
    memset(tmp, 0, 16);
    memcpy(tmp, src, *len);
    *len = 0;
    return tmp;
}

#if BRISK__AES_CT64

/* Carry-less 64x64 multiply, low 64 bits: 4-bit holes keep every carry out of the kept bits. */
static uint64_t bmul64(uint64_t x, uint64_t y)
{
    uint64_t x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3;
    x0 = x & UINT64_C(0x1111111111111111);
    x1 = x & UINT64_C(0x2222222222222222);
    x2 = x & UINT64_C(0x4444444444444444);
    x3 = x & UINT64_C(0x8888888888888888);
    y0 = y & UINT64_C(0x1111111111111111);
    y1 = y & UINT64_C(0x2222222222222222);
    y2 = y & UINT64_C(0x4444444444444444);
    y3 = y & UINT64_C(0x8888888888888888);
    z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    z0 &= UINT64_C(0x1111111111111111);
    z1 &= UINT64_C(0x2222222222222222);
    z2 &= UINT64_C(0x4444444444444444);
    z3 &= UINT64_C(0x8888888888888888);
    return z0 | z1 | z2 | z3;
}

#    define BRISK__GCM_RMS64(x, m, s) ((x) = (((x) & (m)) << (s)) | (((x) >> (s)) & (m)))
static uint64_t rev64(uint64_t x)
{
    BRISK__GCM_RMS64(x, UINT64_C(0x5555555555555555), 1);
    BRISK__GCM_RMS64(x, UINT64_C(0x3333333333333333), 2);
    BRISK__GCM_RMS64(x, UINT64_C(0x0F0F0F0F0F0F0F0F), 4);
    BRISK__GCM_RMS64(x, UINT64_C(0x00FF00FF00FF00FF), 8);
    BRISK__GCM_RMS64(x, UINT64_C(0x0000FFFF0000FFFF), 16);
    return (x << 32) | (x >> 32);
}
#    undef BRISK__GCM_RMS64

void brisk__ghash(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len)
{
    /* s: y0 y1 | h0 h1 h2 h0r h1r h2r (index 0 = low 64 bits of the big-endian block) */
    uint64_t s[8];
    uint8_t tmp[16];
    s[1] = brisk__load_be64(y);
    s[0] = brisk__load_be64(y + 8);
    s[3] = brisk__load_be64(h);
    s[2] = brisk__load_be64(h + 8);
    s[5] = rev64(s[2]);
    s[6] = rev64(s[3]);
    s[4] = s[2] ^ s[3];
    s[7] = s[5] ^ s[6];
    while (len > 0) {
        const uint8_t *src = next_block(&data, &len, tmp);
        uint64_t y0r, y1r, y2, y2r, z0, z1, z2, z0h, z1h, z2h, v0, v1, v2, v3;
        s[1] ^= brisk__load_be64(src);
        s[0] ^= brisk__load_be64(src + 8);
        y0r = rev64(s[0]);
        y1r = rev64(s[1]);
        y2 = s[0] ^ s[1];
        y2r = y0r ^ y1r;
        /* Karatsuba: three 64x64 products, each for the low (direct) and high (reversed) half */
        z0 = bmul64(s[0], s[2]);
        z1 = bmul64(s[1], s[3]);
        z2 = bmul64(y2, s[4]);
        z0h = bmul64(y0r, s[5]);
        z1h = bmul64(y1r, s[6]);
        z2h = bmul64(y2r, s[7]);
        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = rev64(z0h) >> 1;
        z1h = rev64(z1h) >> 1;
        z2h = rev64(z2h) >> 1;
        v0 = z0;
        v1 = z0h ^ z2;
        v2 = z1 ^ z2h;
        v3 = z1h;
        /* the bit-reflected field: shift the 256-bit product left by one, then reduce modulo
         * x^128 + x^7 + x^2 + x + 1 (SP 800-38D 6.3, R = 11100001 || 0^120) */
        v3 = (v3 << 1) | (v2 >> 63);
        v2 = (v2 << 1) | (v1 >> 63);
        v1 = (v1 << 1) | (v0 >> 63);
        v0 = (v0 << 1);
        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        s[0] = v2;
        s[1] = v3;
    }
    brisk__store_be64(y, s[1]);
    brisk__store_be64(y + 8, s[0]);
    brisk__secure_zero(s, sizeof s);
    brisk__secure_zero(tmp, sizeof tmp);
}

#else /* !BRISK__AES_CT64 */

/* Carry-less 32x32 multiply, low 32 bits only: no widening multiply is ever needed. */
static uint32_t bmul32(uint32_t x, uint32_t y)
{
    uint32_t x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3;
    x0 = x & 0x11111111u;
    x1 = x & 0x22222222u;
    x2 = x & 0x44444444u;
    x3 = x & 0x88888888u;
    y0 = y & 0x11111111u;
    y1 = y & 0x22222222u;
    y2 = y & 0x44444444u;
    y3 = y & 0x88888888u;
    z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    z0 &= 0x11111111u;
    z1 &= 0x22222222u;
    z2 &= 0x44444444u;
    z3 &= 0x88888888u;
    return z0 | z1 | z2 | z3;
}

#    define BRISK__GCM_RMS32(x, m, s) ((x) = (((x) & (m)) << (s)) | (((x) >> (s)) & (m)))
static uint32_t rev32(uint32_t x)
{
    BRISK__GCM_RMS32(x, 0x55555555u, 1);
    BRISK__GCM_RMS32(x, 0x33333333u, 2);
    BRISK__GCM_RMS32(x, 0x0F0F0F0Fu, 4);
    BRISK__GCM_RMS32(x, 0x00FF00FFu, 8);
    return (x << 16) | (x >> 16);
}
#    undef BRISK__GCM_RMS32

void brisk__ghash(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len)
{
    /* Karatsuba reduces 128x128 to nine 32x32 products; doing each for the direct and the
     * bit-reversed operands gives 18 (index 0 = least significant word) */
    struct {
        uint32_t yw[4], hw[4], hwr[4], a[18], b[18], c[18], zw[8];
        uint8_t tmp[16];
    } s;
    int i;
    for (i = 0; i < 4; i++) {
        s.yw[3 - i] = brisk__load_be32(y + 4 * i);
        s.hw[3 - i] = brisk__load_be32(h + 4 * i);
        s.hwr[3 - i] = rev32(s.hw[3 - i]);
    }
    /* h side of the Karatsuba operands: fixed for the whole call */
    for (i = 0; i < 4; i++) {
        s.b[i] = s.hw[i];
        s.b[9 + i] = s.hwr[i];
    }
    for (i = 0; i < 18; i += 9) {
        s.b[i + 4] = s.b[i] ^ s.b[i + 1];
        s.b[i + 5] = s.b[i + 2] ^ s.b[i + 3];
        s.b[i + 6] = s.b[i] ^ s.b[i + 2];
        s.b[i + 7] = s.b[i + 1] ^ s.b[i + 3];
        s.b[i + 8] = s.b[i + 6] ^ s.b[i + 7];
    }
    while (len > 0) {
        const uint8_t *src = next_block(&data, &len, s.tmp);
        uint32_t d0, d1, d2, d3, d4, d5, d6, d7;
        for (i = 0; i < 4; i++) {
            s.yw[3 - i] ^= brisk__load_be32(src + 4 * i);
        }
        for (i = 0; i < 4; i++) {
            s.a[i] = s.yw[i];
            s.a[9 + i] = rev32(s.yw[i]);
        }
        for (i = 0; i < 18; i += 9) {
            s.a[i + 4] = s.a[i] ^ s.a[i + 1];
            s.a[i + 5] = s.a[i + 2] ^ s.a[i + 3];
            s.a[i + 6] = s.a[i] ^ s.a[i + 2];
            s.a[i + 7] = s.a[i + 1] ^ s.a[i + 3];
            s.a[i + 8] = s.a[i + 6] ^ s.a[i + 7];
        }
        for (i = 0; i < 18; i++) {
            s.c[i] = bmul32(s.a[i], s.b[i]);
        }
        s.c[4] ^= s.c[0] ^ s.c[1];
        s.c[5] ^= s.c[2] ^ s.c[3];
        s.c[8] ^= s.c[6] ^ s.c[7];
        s.c[13] ^= s.c[9] ^ s.c[10];
        s.c[14] ^= s.c[11] ^ s.c[12];
        s.c[17] ^= s.c[15] ^ s.c[16];
        /* recombine low (direct) and high (reversed) halves into the 256-bit product */
        d0 = s.c[0];
        d1 = s.c[4] ^ (rev32(s.c[9]) >> 1);
        d2 = s.c[1] ^ s.c[0] ^ s.c[2] ^ s.c[6] ^ (rev32(s.c[13]) >> 1);
        d3 = s.c[4] ^ s.c[5] ^ s.c[8] ^ (rev32(s.c[10] ^ s.c[9] ^ s.c[11] ^ s.c[15]) >> 1);
        d4 = s.c[2] ^ s.c[1] ^ s.c[3] ^ s.c[7] ^ (rev32(s.c[13] ^ s.c[14] ^ s.c[17]) >> 1);
        d5 = s.c[5] ^ (rev32(s.c[11] ^ s.c[10] ^ s.c[12] ^ s.c[16]) >> 1);
        d6 = s.c[3] ^ (rev32(s.c[14]) >> 1);
        d7 = rev32(s.c[12]) >> 1;
        /* shift left by one (bit-reflected field), then reduce modulo x^128 + x^7 + x^2 + x + 1
         * (SP 800-38D 6.3, R = 11100001 || 0^120) */
        s.zw[0] = d0 << 1;
        s.zw[1] = (d1 << 1) | (d0 >> 31);
        s.zw[2] = (d2 << 1) | (d1 >> 31);
        s.zw[3] = (d3 << 1) | (d2 >> 31);
        s.zw[4] = (d4 << 1) | (d3 >> 31);
        s.zw[5] = (d5 << 1) | (d4 >> 31);
        s.zw[6] = (d6 << 1) | (d5 >> 31);
        s.zw[7] = (d7 << 1) | (d6 >> 31);
        for (i = 0; i < 4; i++) {
            uint32_t lw = s.zw[i];
            s.zw[i + 4] ^= lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7);
            s.zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
        }
        memcpy(s.yw, s.zw + 4, sizeof s.yw);
    }
    for (i = 0; i < 4; i++) {
        brisk__store_be32(y + 4 * i, s.yw[3 - i]);
    }
    brisk__secure_zero(&s, sizeof s);
}

#endif /* BRISK__AES_CT64 */

/* ---- AES-GCM (SP 800-38D 7.1 / 7.2) ---- */
/* SP 800-38D 5.2.1.1: len(P) <= 2^39 - 256 bits = 2^36 - 32 bytes (2^32 - 2 counter blocks; one
 * more and inc32 wraps into J0, whose keystream masks the tag). RFC 5116 5.1: A_MAX = 2^61 - 1. */
#define BRISK__GCM_P_MAX UINT64_C(68719476704)
#define BRISK__GCM_A_MAX UINT64_C(2305843009213693951)

/* Only reachable with a 64-bit size_t; 32-bit lengths can never exceed either bound. */
static int gcm_too_long(size_t aad_len, size_t len)
{
#if SIZE_MAX > 0xffffffffu
    return (uint64_t)len > BRISK__GCM_P_MAX || (uint64_t)aad_len > BRISK__GCM_A_MAX;
#else
    (void)aad_len;
    (void)len;
    return 0;
#endif
}

int brisk__gcm_init(brisk__gcm_key *k, const uint8_t *key, size_t key_len)
{
    static const uint8_t zero[16];
    int r = brisk__aes_init(&k->aes, key, key_len); /* writes nothing on BRISK_E_ARG */
    if (r != BRISK_OK) {
        return r;
    }
    brisk__aes_encrypt(&k->aes, zero, k->h); /* 7.1 step 1: H = CIPH_K(0^128) */
    return BRISK_OK;
}

/* J0 = IV || 0^31 || c (7.1 step 2 for a 96-bit IV with c = 1; c = 2 is inc32(J0), step 3). */
static void counter_block(uint8_t cb[16], const uint8_t iv[12], uint32_t c)
{
    memcpy(cb, iv, 12);
    brisk__store_be32(cb + 12, c);
}

/* 7.1 steps 5-6: S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64), lengths in
 * bits; T = E(K, J0) XOR S. */
static void gcm_tag(const brisk__gcm_key *k, const uint8_t iv[12], const uint8_t *aad,
                    size_t aad_len, const uint8_t *ct, size_t len, uint8_t tag[16])
{
    uint8_t y[16], blk[16];
    int i;
    memset(y, 0, sizeof y);
    brisk__ghash(y, k->h, aad, aad_len);
    brisk__ghash(y, k->h, ct, len);
    brisk__store_be64(blk, (uint64_t)aad_len << 3);
    brisk__store_be64(blk + 8, (uint64_t)len << 3);
    brisk__ghash(y, k->h, blk, 16);
    counter_block(blk, iv, 1);
    brisk__aes_encrypt(&k->aes, blk, blk);
    for (i = 0; i < 16; i++) {
        tag[i] = (uint8_t)(y[i] ^ blk[i]);
    }
    brisk__secure_zero(y, sizeof y);
    brisk__secure_zero(blk, sizeof blk);
}

int brisk__gcm_seal(const brisk__gcm_key *k, const uint8_t iv[12], const uint8_t *aad,
                    size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16])
{
    uint8_t cb[16];
    if (gcm_too_long(aad_len, len)) {
        return BRISK_E_ARG;
    }
    counter_block(cb, iv, 2); /* 7.1 step 3: C = GCTR_K(inc32(J0), P) */
    brisk__aes_ctr32(&k->aes, cb, in, len, out);
    gcm_tag(k, iv, aad, aad_len, out, len, tag);
    return BRISK_OK;
}

int brisk__gcm_open(const brisk__gcm_key *k, const uint8_t iv[12], const uint8_t *aad,
                    size_t aad_len, const uint8_t *in, size_t len, uint8_t *out,
                    const uint8_t tag[16])
{
    uint8_t calc[16], cb[16];
    int ok;
    if (gcm_too_long(aad_len, len)) {
        return BRISK_E_ARG;
    }
    /* 7.2: authenticate the ciphertext first; nothing is decrypted unless the tag matches */
    gcm_tag(k, iv, aad, aad_len, in, len, calc);
    ok = brisk__ct_memeq(calc, tag, 16);
    brisk__secure_zero(calc, sizeof calc);
    if (!ok) { /* public accept/reject decision */
        brisk__secure_zero(out, len);
        return BRISK_E_AUTH;
    }
    counter_block(cb, iv, 2);
    brisk__aes_ctr32(&k->aes, cb, in, len, out);
    return BRISK_OK;
}

#undef BRISK__GCM_P_MAX
#undef BRISK__GCM_A_MAX
