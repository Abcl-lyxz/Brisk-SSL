/* sha2.c - SHA-256, SHA-384, SHA-512 (FIPS 180-4), loop-rolled for size.
 *
 * No secret-dependent branches or table lookups: the round constants are indexed by the round
 * number only, so hashing secrets (HMAC keys, TLS secrets) is constant-time by construction.
 * 64-bit arithmetic is add/xor/shift/rotate only (no division), so 32-bit targets stay lean.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(e, f, g) ((g) ^ ((e) & ((f) ^ (g))))
#define MAJ(a, b, c) (((a) & (b)) | ((c) & ((a) | (b))))

/* ============================================================================ SHA-256 */

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_block(uint32_t st[8], const uint8_t *p)
{
    uint32_t w[16], a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6],
                    h = st[7], t1, t2;
    int i;
    for (i = 0; i < 64; i++) {
        if (i < 16) {
            w[i] = brisk__load_be32(p + 4 * i);
        } else { /* rolling 16-word schedule: w[i&15] still holds w[i-16] */
            uint32_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];
            w[i & 15] += (ROR32(x, 7) ^ ROR32(x, 18) ^ (x >> 3)) + w[(i + 9) & 15] +
                         (ROR32(y, 17) ^ ROR32(y, 19) ^ (y >> 10));
        }
        t1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + CH(e, f, g) + K256[i] + w[i & 15];
        t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
    brisk__secure_zero(w, sizeof w);
}

void brisk_sha256_init(brisk_sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
}

void brisk_sha256_update(brisk_sha256_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    size_t used = (size_t)(c->len & 63);
    if (n == 0) {
        return; /* also makes data == NULL with n == 0 legal */
    }
    c->len += n;
    if (used) {
        size_t take = 64 - used < n ? 64 - used : n;
        memcpy(c->buf + used, p, take);
        p += take;
        n -= take;
        if (used + take < 64) {
            return;
        }
        sha256_block(c->h, c->buf);
    }
    for (; n >= 64; p += 64, n -= 64) {
        sha256_block(c->h, p);
    }
    if (n) {
        memcpy(c->buf, p, n);
    }
}

void brisk_sha256_final(brisk_sha256_ctx *c, uint8_t out[BRISK_SHA256_LEN])
{
    size_t used = (size_t)(c->len & 63);
    int i;
    c->buf[used++] = 0x80;
    if (used > 56) {
        memset(c->buf + used, 0, 64 - used);
        sha256_block(c->h, c->buf);
        used = 0;
    }
    memset(c->buf + used, 0, 56 - used);
    brisk__store_be64(c->buf + 56, c->len << 3);
    sha256_block(c->h, c->buf);
    for (i = 0; i < 8; i++) {
        brisk__store_be32(out + 4 * i, c->h[i]);
    }
    brisk__secure_zero(c, sizeof *c);
}

void brisk_sha256(const void *data, size_t len, uint8_t out[BRISK_SHA256_LEN])
{
    brisk_sha256_ctx c;
    brisk_sha256_init(&c);
    brisk_sha256_update(&c, data, len);
    brisk_sha256_final(&c, out);
}

/* ============================================================================ SHA-512 / SHA-384 */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static void sha512_block(uint64_t st[8], const uint8_t *p)
{
    uint64_t w[16], a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6],
                    h = st[7], t1, t2;
    int i;
    for (i = 0; i < 80; i++) {
        if (i < 16) {
            w[i] = brisk__load_be64(p + 8 * i);
        } else {
            uint64_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];
            w[i & 15] += (ROR64(x, 1) ^ ROR64(x, 8) ^ (x >> 7)) + w[(i + 9) & 15] +
                         (ROR64(y, 19) ^ ROR64(y, 61) ^ (y >> 6));
        }
        t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + CH(e, f, g) + K512[i] + w[i & 15];
        t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
    brisk__secure_zero(w, sizeof w);
}

void brisk_sha512_init(brisk_sha512_ctx *c)
{
    static const uint64_t iv[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
                                   0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                   0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
}

void brisk_sha384_init(brisk_sha384_ctx *c)
{
    static const uint64_t iv[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                                   0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                                   0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
}

void brisk_sha512_update(brisk_sha512_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    size_t used = (size_t)(c->len & 127);
    if (n == 0) {
        return;
    }
    c->len += n;
    if (used) {
        size_t take = 128 - used < n ? 128 - used : n;
        memcpy(c->buf + used, p, take);
        p += take;
        n -= take;
        if (used + take < 128) {
            return;
        }
        sha512_block(c->h, c->buf);
    }
    for (; n >= 128; p += 128, n -= 128) {
        sha512_block(c->h, p);
    }
    if (n) {
        memcpy(c->buf, p, n);
    }
}

void brisk_sha384_update(brisk_sha384_ctx *c, const void *data, size_t len)
{
    brisk_sha512_update(c, data, len);
}

/* pad, process, write out_len bytes of state, wipe */
static void sha512_finish(brisk_sha512_ctx *c, uint8_t *out, size_t out_len)
{
    size_t used = (size_t)(c->len & 127), i;
    uint8_t word[8];
    c->buf[used++] = 0x80;
    if (used > 112) {
        memset(c->buf + used, 0, 128 - used);
        sha512_block(c->h, c->buf);
        used = 0;
    }
    memset(c->buf + used, 0, 112 - used);
    brisk__store_be64(c->buf + 112, c->len >> 61); /* 128-bit bit length: high part */
    brisk__store_be64(c->buf + 120, c->len << 3);
    sha512_block(c->h, c->buf);
    for (i = 0; i < out_len; i += 8) {
        brisk__store_be64(word, c->h[i / 8]);
        memcpy(out + i, word, out_len - i < 8 ? out_len - i : 8);
    }
    brisk__secure_zero(c, sizeof *c);
}

void brisk_sha512_final(brisk_sha512_ctx *c, uint8_t out[BRISK_SHA512_LEN])
{
    sha512_finish(c, out, BRISK_SHA512_LEN);
}

void brisk_sha384_final(brisk_sha384_ctx *c, uint8_t out[BRISK_SHA384_LEN])
{
    sha512_finish(c, out, BRISK_SHA384_LEN);
}

void brisk_sha512(const void *data, size_t len, uint8_t out[BRISK_SHA512_LEN])
{
    brisk_sha512_ctx c;
    brisk_sha512_init(&c);
    brisk_sha512_update(&c, data, len);
    brisk_sha512_final(&c, out);
}

void brisk_sha384(const void *data, size_t len, uint8_t out[BRISK_SHA384_LEN])
{
    brisk_sha384_ctx c;
    brisk_sha384_init(&c);
    brisk_sha384_update(&c, data, len);
    brisk_sha384_final(&c, out);
}

/* ============================================================================ generic dispatch */

size_t brisk_hash_len(brisk_hash_alg alg)
{
    switch (alg) {
    case BRISK_HASH_SHA256:
        return BRISK_SHA256_LEN;
    case BRISK_HASH_SHA384:
        return BRISK_SHA384_LEN;
    case BRISK_HASH_SHA512:
        return BRISK_SHA512_LEN;
    }
    return 0;
}

size_t brisk__hash_block_len(brisk_hash_alg alg)
{
    return alg == BRISK_HASH_SHA256 ? 64 : brisk_hash_len(alg) ? 128 : 0;
}

void brisk__hash_init(brisk_hash_ctx *c, brisk_hash_alg alg)
{
    if (alg == BRISK_HASH_SHA256) {
        brisk_sha256_init(&c->sha256);
    } else if (alg == BRISK_HASH_SHA384) {
        brisk_sha384_init(&c->sha512);
    } else {
        brisk_sha512_init(&c->sha512);
    }
}

void brisk__hash_update(brisk_hash_ctx *c, brisk_hash_alg alg, const void *data, size_t len)
{
    if (alg == BRISK_HASH_SHA256) {
        brisk_sha256_update(&c->sha256, data, len);
    } else {
        brisk_sha512_update(&c->sha512, data, len);
    }
}

void brisk__hash_final(brisk_hash_ctx *c, brisk_hash_alg alg, uint8_t *out)
{
    if (alg == BRISK_HASH_SHA256) {
        brisk_sha256_final(&c->sha256, out);
    } else {
        sha512_finish(&c->sha512, out, brisk_hash_len(alg));
    }
}
