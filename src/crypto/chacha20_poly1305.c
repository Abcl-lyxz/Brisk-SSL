/* chacha20_poly1305.c - ChaCha20, Poly1305 and AEAD_CHACHA20_POLY1305 (RFC 8439).
 *
 * Portable and constant time: ChaCha20 is add/rotate/xor only; Poly1305 uses five 26-bit limbs
 * with 32x32->64 products (no 64x64 multiply, no 64-bit division, no variable 64-bit shifts, so
 * no libgcc helpers on 32-bit CPUs) and a masked final reduction. All loads/stores are byte-wise
 * little endian, so alignment and host byte order do not matter.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* ---- ChaCha20 (RFC 8439 2.1-2.4) ---- */
#define BRISK__ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define BRISK__QR(x, a, b, c, d)                                                                   \
    do {                                                                                           \
        x[a] += x[b];                                                                              \
        x[d] ^= x[a];                                                                              \
        x[d] = BRISK__ROTL32(x[d], 16);                                                            \
        x[c] += x[d];                                                                              \
        x[b] ^= x[c];                                                                              \
        x[b] = BRISK__ROTL32(x[b], 12);                                                            \
        x[a] += x[b];                                                                              \
        x[d] ^= x[a];                                                                              \
        x[d] = BRISK__ROTL32(x[d], 8);                                                             \
        x[c] += x[d];                                                                              \
        x[b] ^= x[c];                                                                              \
        x[b] = BRISK__ROTL32(x[b], 7);                                                             \
    } while (0)

/* RFC 8439 2.3: 20 rounds (10 column + diagonal double rounds), add the input, serialize LE. */
static void chacha_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof x);
    for (i = 0; i < 10; i++) {
        BRISK__QR(x, 0, 4, 8, 12);
        BRISK__QR(x, 1, 5, 9, 13);
        BRISK__QR(x, 2, 6, 10, 14);
        BRISK__QR(x, 3, 7, 11, 15);
        BRISK__QR(x, 0, 5, 10, 15);
        BRISK__QR(x, 1, 6, 11, 12);
        BRISK__QR(x, 2, 7, 8, 13);
        BRISK__QR(x, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) {
        brisk__store_le32(out + 4 * i, x[i] + in[i]);
    }
    brisk__secure_zero(x, sizeof x);
}

void brisk__chacha20(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint32_t st[16];
    uint8_t ks[64];
    size_t i, n;
    st[0] = 0x61707865; /* "expand 32-byte k" */
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for (i = 0; i < 8; i++) {
        st[4 + i] = brisk__load_le32(key + 4 * i);
    }
    st[12] = counter;
    for (i = 0; i < 3; i++) {
        st[13 + i] = brisk__load_le32(nonce + 4 * i);
    }
    while (len > 0) {
        chacha_block(st, ks);
        n = len < 64 ? len : 64; /* a partial last block uses only what it needs (2.4) */
        for (i = 0; i < n; i++) {
            out[i] = (uint8_t)(in[i] ^ ks[i]);
        }
        st[12]++; /* no wrap check: caller contract, see brisk_int.h */
        in += n;
        out += n;
        len -= n;
    }
    brisk__secure_zero(st, sizeof st);
    brisk__secure_zero(ks, sizeof ks);
}

/* ---- Poly1305 (RFC 8439 2.5), radix 2^26 ---- */
typedef struct {
    uint32_t r[5], s4[4], h[5], pad[4]; /* s4[i] = 5 * r[i + 1] */
} poly_state;

static void poly_init(poly_state *st, const uint8_t key[32])
{
    int i;
    /* r &= 0x0ffffffc0ffffffc0ffffffc0fffffff, split into 26-bit limbs */
    st->r[0] = brisk__load_le32(key + 0) & 0x3ffffff;
    st->r[1] = (brisk__load_le32(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (brisk__load_le32(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (brisk__load_le32(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (brisk__load_le32(key + 12) >> 8) & 0x00fffff;
    for (i = 0; i < 4; i++) {
        st->s4[i] = st->r[i + 1] * 5;
        st->pad[i] = brisk__load_le32(key + 16 + 4 * i);
    }
    for (i = 0; i < 5; i++) {
        st->h[i] = 0;
    }
}

/* h = (h + block + hibit * 2^128) * r mod 2^130-5 for nblocks full 16-byte blocks. */
static void poly_blocks(poly_state *st, const uint8_t *m, size_t nblocks, uint32_t hibit)
{
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = st->s4[0], s2 = st->s4[1], s3 = st->s4[2], s4 = st->s4[3];
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4], c;
    uint64_t d0, d1, d2, d3, d4;
    while (nblocks--) {
        h0 += brisk__load_le32(m + 0) & 0x3ffffff;
        h1 += (brisk__load_le32(m + 3) >> 2) & 0x3ffffff;
        h2 += (brisk__load_le32(m + 6) >> 4) & 0x3ffffff;
        h3 += (brisk__load_le32(m + 9) >> 6) & 0x3ffffff;
        h4 += (brisk__load_le32(m + 12) >> 8) | hibit;

        /* 2^130 = 5 mod p, so limb products that overflow 2^130 fold in times 5 */
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
             (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
             (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
             (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
             (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
             (uint64_t)h4 * r0;

        /* partial reduction: carries by shift and mask only */
        c = (uint32_t)(d0 >> 26);
        h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;
        c = (uint32_t)(d1 >> 26);
        h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;
        c = (uint32_t)(d2 >> 26);
        h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;
        c = (uint32_t)(d3 >> 26);
        h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;
        c = (uint32_t)(d4 >> 26);
        h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;
        m += 16;
    }
    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

/* Absorb len bytes. The trailing partial block is either zero padded as a full block
 * (aead_pad: pad16 of RFC 8439 2.8) or gets the 0x01 byte right after its data (2.5). */
static void poly_update(poly_state *st, const uint8_t *p, size_t len, int aead_pad)
{
    uint8_t b[16];
    size_t rem = len & 15;
    poly_blocks(st, p, len >> 4, 1u << 24);
    if (rem) {
        memset(b, 0, sizeof b);
        memcpy(b, p + (len - rem), rem);
        if (!aead_pad) {
            b[rem] = 1;
        }
        poly_blocks(st, b, 1, aead_pad ? 1u << 24 : 0);
        brisk__secure_zero(b, sizeof b);
    }
}

/* tag = (h mod 2^130-5 + s) mod 2^128, constant time; wipes the state. */
static void poly_finish(poly_state *st, uint8_t tag[16])
{
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t g0, g1, g2, g3, g4, c, mask;
    uint64_t f;

    /* full carry */
    c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c; /* needs h2..h4 all ones and h0 >= 2^26-5 (~2^-100): no vector reaches it */

    /* g = h + 5 - 2^130; keep g if it did not go negative (h >= p), selected by mask */
    g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);
    mask = (g4 >> 31) - 1; /* all ones if g4 >= 0 (take g), else zero (keep h) */
    BRISK__CT_BARRIER(mask);
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* back to 4 x 32 bits (mod 2^128), then + s with carry */
    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);
    f = (uint64_t)h0 + st->pad[0];
    brisk__store_le32(tag + 0, (uint32_t)f);
    f = (uint64_t)h1 + st->pad[1] + (uint32_t)(f >> 32);
    brisk__store_le32(tag + 4, (uint32_t)f);
    f = (uint64_t)h2 + st->pad[2] + (uint32_t)(f >> 32);
    brisk__store_le32(tag + 8, (uint32_t)f);
    f = (uint64_t)h3 + st->pad[3] + (uint32_t)(f >> 32);
    brisk__store_le32(tag + 12, (uint32_t)f);
    brisk__secure_zero(st, sizeof *st);
}

void brisk__poly1305(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16])
{
    poly_state st;
    poly_init(&st, key);
    poly_update(&st, msg, len, 0);
    poly_finish(&st, tag);
}

/* ---- AEAD_CHACHA20_POLY1305 (RFC 8439 2.6, 2.8) ---- */
/* RFC 8439 2.8 note 1: 2^32 - 1 blocks of 64 bytes (counter starts at 1). */
#define BRISK__CHACHA_P_MAX UINT64_C(274877906880)

/* Only reachable with a 64-bit size_t; a 32-bit length can never exceed P_MAX. */
static int too_long(size_t len)
{
#if SIZE_MAX > 0xffffffffu
    return (uint64_t)len > BRISK__CHACHA_P_MAX;
#else
    (void)len;
    return 0;
#endif
}

/* Poly1305 over aad | pad16 | ct | pad16 | le64(aad_len) | le64(ct_len), streamed. */
static void aead_tag(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t len, uint8_t tag[16])
{
    poly_state st;
    uint8_t otk[32], lens[16];
    uint64_t a = (uint64_t)aad_len, n = (uint64_t)len;
    memset(otk, 0, sizeof otk);
    brisk__chacha20(key, 0, nonce, otk, otk, sizeof otk); /* 2.6: first 32 bytes of block 0 */
    poly_init(&st, otk);
    brisk__secure_zero(otk, sizeof otk);
    poly_update(&st, aad, aad_len, 1);
    poly_update(&st, ct, len, 1);
    brisk__store_le32(lens + 0, (uint32_t)a);
    brisk__store_le32(lens + 4, (uint32_t)(a >> 32));
    brisk__store_le32(lens + 8, (uint32_t)n);
    brisk__store_le32(lens + 12, (uint32_t)(n >> 32));
    poly_blocks(&st, lens, 1, 1u << 24);
    poly_finish(&st, tag);
}

int brisk__chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                                  uint8_t *out, uint8_t tag[16])
{
    if (too_long(len)) {
        return BRISK_E_ARG;
    }
    brisk__chacha20(key, 1, nonce, in, out, len);
    aead_tag(key, nonce, aad, aad_len, out, len, tag);
    return BRISK_OK;
}

int brisk__chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                                  const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                                  uint8_t *out, const uint8_t tag[16])
{
    uint8_t calc[16];
    int ok;
    if (too_long(len)) {
        return BRISK_E_ARG;
    }
    /* MAC the ciphertext first; nothing is decrypted unless the tag matches */
    aead_tag(key, nonce, aad, aad_len, in, len, calc);
    ok = brisk__ct_memeq(calc, tag, 16);
    brisk__secure_zero(calc, sizeof calc);
    if (!ok) { /* public accept/reject decision */
        brisk__secure_zero(out, len);
        return BRISK_E_AUTH;
    }
    brisk__chacha20(key, 1, nonce, in, out, len);
    return BRISK_OK;
}

#undef BRISK__ROTL32
#undef BRISK__QR
#undef BRISK__CHACHA_P_MAX
