/* test_aes.c - AES-128/256 forward cipher (FIPS 197) and the inc32 counter mode (SP
 * 800-38D 6.2/6.5) against FIPS 197 C.1/C.3, NIST CAVP AESAVS (KAT, MMT, MCT), SP 800-38A F.5, RFC
 * 9001 A.2/A.3 and a seeded differential set; plus GHASH and AES-GCM (SP 800-38D) against CAVP
 * GCMVS, Wycheproof, the RFC 9001 A.2/A.3 Initial packets and a differential set
 * (tests/kat/SOURCES.md). One of aes_ct (32-bit) /
 * aes_ct64 (64-bit) is linked per arch, so `dev.py test --arch all` covers both in both byte
 * orders. */
#include <stdint.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct aes_ecb_kat {
    const char *key, *pt, *ct; /* pt/ct may be several blocks (MMT) */
};
struct aes_mct_kat {
    int count;
    const char *key, *pt, *ct;
};
struct aes_ctr_kat {
    const char *key, *cb, *in, *out;
};
struct aes_hp_kat {
    const char *hp, *sample, *mask;
};
struct gcm_kat {
    const char *key, *iv, *aad, *pt, *ct, *tag;
    int valid;
};
struct ghash_kat {
    const char *y, *h, *data, *out;
};
struct quic_gcm_kat {
    const char *secret;
    uint64_t pn;
    const char *hdr, *pt, *packet;
};

#include "kat/aes_ecb.inc"
#include "kat/aes_mct.inc"
#include "kat/aes_ctr.inc"
#include "kat/aes_quic_hp.inc"
#include "kat/aes_gcm.inc"
#include "kat/ghash.inc"
#include "kat/quic_gcm.inc"

#define N(a)   (sizeof(a) / sizeof((a)[0]))
#define BUF    320 /* largest vector: 300 bytes (differential); MMT is 160 */
#define CANARY 16

/* struct_size: the key is embedded in public structs later, so its size must not depend on arch */
typedef char aes_key_size_is_fixed[sizeof(brisk__aes_key) == 248 ? 1 : -1];
typedef char gcm_key_size_is_fixed[sizeof(brisk__gcm_key) == 264 ? 1 : -1];

static uint8_t K[32], P[BUF], C[BUF], CB[16];
static uint8_t WK[32 + 8], WI[BUF + 8], WO[BUF + 8 + CANARY];

static int canary_ok(const uint8_t *p)
{
    size_t i;
    for (i = 0; i < CANARY; i++) {
        if (p[i] != 0xA5) {
            return 0;
        }
    }
    return 1;
}

/* inc32 applied n times (SP 800-38D 6.2), for caller-side counter advancing in the tests */
static void inc32(uint8_t cb[16], uint32_t n)
{
    brisk__store_be32(cb + 12, brisk__load_be32(cb + 12) + n);
}

/* kat_fips197 + kat_cavp_ecb + kat_cavp_mmt + unaligned: every block through brisk__aes_encrypt,
 * key and buffers at offsets 0..7, out of place and in place. */
static void test_ecb(void)
{
    size_t i, off, j;
    for (i = 0; i < N(AES_ECB_KAT); i++) {
        const struct aes_ecb_kat *v = &AES_ECB_KAT[i];
        size_t klen = t_unhex(v->key, K, 32), n = t_unhex(v->pt, P, BUF);
        CHECKI(t_unhex(v->ct, C, BUF) == n && n % 16 == 0, i);
        for (off = 0; off < 8; off++) {
            brisk__aes_key k;
            uint8_t *key = WK + off, *in = WI + off, *out = WO + off;
            memcpy(key, K, klen);
            memcpy(in, P, n);
            memset(out, 0, n);
            memset(out + n, 0xA5, CANARY);
            CHECKI(brisk__aes_init(&k, key, klen) == BRISK_OK, i);
            CHECKI(k.nr == (klen == 16 ? 10u : 14u), i);
            for (j = 0; j < n; j += 16) {
                brisk__aes_encrypt(&k, in + j, out + j);
            }
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
            memcpy(out, P, n); /* in place */
            for (j = 0; j < n; j += 16) {
                brisk__aes_encrypt(&k, out + j, out + j);
            }
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
            brisk__secure_zero(&k, sizeof k);
        }
    }
}

/* kat_cavp_mct: AESAVS 6.4 ECB Monte Carlo, 100 x 1000 chained blocks per key size. */
static void test_mct(void)
{
    uint8_t key[32], pt[16], prev[16], ct[16], want[32];
    size_t klen = 0, i;
    int j;
    for (i = 0; i < N(AES_MCT_KAT); i++) {
        const struct aes_mct_kat *v = &AES_MCT_KAT[i];
        brisk__aes_key k;
        size_t m;
        if (v->count == 0) { /* first row of a key size: seed the chain */
            klen = t_unhex(v->key, key, 32);
            t_unhex(v->pt, pt, 16);
        }
        CHECKI(t_unhex(v->key, want, 32) == klen && memcmp(key, want, klen) == 0, i);
        CHECKI(t_unhex(v->pt, want, 16) == 16 && memcmp(pt, want, 16) == 0, i);
        CHECKI(brisk__aes_init(&k, key, klen) == BRISK_OK, i);
        memcpy(ct, pt, 16);
        for (j = 0; j < 1000; j++) {
            memcpy(prev, ct, 16);
            brisk__aes_encrypt(&k, ct, ct);
        }
        t_unhex(v->ct, want, 16);
        CHECKI(memcmp(ct, want, 16) == 0, i);
        if (klen == 16) {
            for (m = 0; m < 16; m++) {
                key[m] ^= ct[m];
            }
        } else {
            for (m = 0; m < 16; m++) {
                key[m] ^= prev[m];
                key[16 + m] ^= ct[m];
            }
        }
        memcpy(pt, ct, 16);
    }
}

/* kat_ctr_sp80038a + differential + ctr32_wrap + unaligned + split_input. */
static void test_ctr_vectors(void)
{
    size_t i, off, b;
    for (i = 0; i < N(AES_CTR_KAT); i++) {
        const struct aes_ctr_kat *v = &AES_CTR_KAT[i];
        brisk__aes_key k;
        uint8_t cb[16 + 8], save[16];
        size_t klen = t_unhex(v->key, K, 32), n = t_unhex(v->in, P, BUF);
        CHECKI(t_unhex(v->cb, CB, 16) == 16, i);
        CHECKI(t_unhex(v->out, C, BUF) == n, i);
        for (off = 0; off < 8; off++) {
            uint8_t *key = WK + off, *in = WI + off, *out = WO + off, *c = cb + off;
            memcpy(key, K, klen);
            memcpy(c, CB, 16);
            memcpy(in, P, n);
            memset(out, 0, n);
            memset(out + n, 0xA5, CANARY);
            CHECKI(brisk__aes_init(&k, key, klen) == BRISK_OK, i);
            brisk__aes_ctr32(&k, c, in, n, out);
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
            CHECKI(memcmp(c, CB, 16) == 0, i); /* cb is not modified */
            memcpy(out, P, n);                 /* in place */
            brisk__aes_ctr32(&k, c, out, n, out);
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
        }
        /* split at every block boundary: ctr32 is stateless, the caller advances cb */
        for (b = 1; 16 * b < n; b++) {
            memset(WO, 0, n);
            memcpy(save, CB, 16);
            brisk__aes_ctr32(&k, save, P, 16 * b, WO);
            inc32(save, (uint32_t)b);
            brisk__aes_ctr32(&k, save, P + 16 * b, n - 16 * b, WO + 16 * b);
            CHECKI(memcmp(WO, C, n) == 0, i);
        }
        brisk__secure_zero(&k, sizeof k);
    }
}

/* ctr32_lengths + const_ctx: every len 0..143 against a block-by-block encrypt XOR reference,
 * with counters that do and do not wrap; the key struct must stay bit-identical. */
static void test_ctr_lengths(void)
{
    static const uint32_t lows[3] = {0x00000001u, 0xFFFFFFFEu, 0xFFFFFFFBu};
    size_t kl, li, len, j;
    for (kl = 16; kl <= 32; kl += 16) {
        brisk__aes_key k, snap;
        for (j = 0; j < kl; j++) {
            K[j] = (uint8_t)(0x3c + 7 * j);
        }
        CHECK(brisk__aes_init(&k, K, kl) == BRISK_OK);
        memcpy(&snap, &k, sizeof k);
        for (li = 0; li < 3; li++) {
            for (j = 0; j < 12; j++) {
                CB[j] = (uint8_t)(0xf0 + j);
            }
            CB[11] = 0xff; /* a carry out of the low word would show up here */
            brisk__store_be32(CB + 12, lows[li]);
            for (j = 0; j < 9 * 16; j++) {
                P[j] = (uint8_t)(j * 13 + li);
            }
            for (len = 0; len < 9 * 16; len++) {
                uint8_t ref[9 * 16], ctr[16];
                memcpy(ctr, CB, 16);
                for (j = 0; j < len; j += 16) {
                    size_t m, t = len - j < 16 ? len - j : 16;
                    uint8_t ks[16];
                    brisk__aes_encrypt(&k, ctr, ks);
                    for (m = 0; m < t; m++) {
                        ref[j + m] = P[j + m] ^ ks[m];
                    }
                    inc32(ctr, 1);
                    CHECK(ctr[11] == 0xff);
                }
                memset(WO + 1, 0, len);
                memset(WO + 1 + len, 0xA5, CANARY);
                brisk__aes_ctr32(&k, CB, P, len, WO + 1);
                CHECKI(memcmp(WO + 1, ref, len) == 0 && canary_ok(WO + 1 + len), len);
            }
        }
        {
            uint8_t blk[16] = {0};
            brisk__aes_encrypt(&k, blk, blk);
        }
        CHECK(memcmp(&snap, &k, sizeof k) == 0);
    }
}

/* kat_quic_hp: RFC 9001 5.4.3 mask = AES-ECB(hp_key, sample), first 5 bytes given by A.2/A.3. */
static void test_quic_hp(void)
{
    size_t i;
    for (i = 0; i < N(AES_HP_KAT); i++) {
        brisk__aes_key k;
        uint8_t hp[16], sample[16], mask[16], want[16];
        size_t mlen;
        CHECKI(t_unhex(AES_HP_KAT[i].hp, hp, 16) == 16, i);
        CHECKI(t_unhex(AES_HP_KAT[i].sample, sample, 16) == 16, i);
        mlen = t_unhex(AES_HP_KAT[i].mask, want, 16);
        CHECKI(brisk__aes_init(&k, hp, 16) == BRISK_OK, i);
        brisk__aes_encrypt(&k, sample, mask);
        CHECKI(mlen == 5 && memcmp(mask, want, mlen) == 0, i);
    }
}

/* invalid_key_len: BRISK_E_ARG before any write (AES-192 is rejected on purpose). */
static void test_invalid(void)
{
    static const size_t bad[] = {0, 1, 15, 17, 24, 31, 33, SIZE_MAX};
    size_t i;
    memset(K, 0x11, 32);
    for (i = 0; i < N(bad); i++) {
        brisk__aes_key k, canary;
        memset(&k, 0x5A, sizeof k);
        memcpy(&canary, &k, sizeof k);
        CHECKI(brisk__aes_init(&k, K, bad[i]) == BRISK_E_ARG, i);
        CHECKI(memcmp(&k, &canary, sizeof k) == 0, i);
    }
}

/* ---- GHASH + AES-GCM (SP 800-38D) ---- */
#define GBUF 4112 /* largest vector: 4097 bytes (differential) */

static uint8_t GK[32], GN[12], GA[GBUF], GP[GBUF], GC[GBUF], GT[16];
static uint8_t GWK[32 + 4], GWN[12 + 4], GWA[GBUF + 4], GWI[GBUF + 4], GWO[GBUF + 4 + CANARY],
    GWT[16 + 4 + CANARY];

static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

/* NULL for an empty buffer at offset 0: exercises aad=NULL / in=NULL / out=NULL
 * with length 0. */
static const uint8_t *opt(const uint8_t *p, size_t n, size_t off)
{
    return n == 0 && off == 0 ? NULL : p;
}

/* Open of (aad, ct, tag) that must fail: BRISK_E_AUTH and out fully zeroed,
 * also in place. */
static int gcm_open_fails(const brisk__gcm_key *k, const uint8_t *iv, const uint8_t *aad,
                          size_t alen, const uint8_t *ct, size_t n, const uint8_t *tag)
{
    int ok;
    memset(GWO, 0xA5, n + CANARY);
    ok = brisk__gcm_open(k, iv, aad, alen, ct, n, GWO, tag) == BRISK_E_AUTH && all_zero(GWO, n) &&
         canary_ok(GWO + n);
    memcpy(GWO, ct, n);
    ok &= brisk__gcm_open(k, iv, aad, alen, GWO, n, GWO, tag) == BRISK_E_AUTH && all_zero(GWO, n) &&
          canary_ok(GWO + n);
    return ok;
}

typedef void (*ghash_fn)(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len);

/* ghash_kat + split_ghash + unaligned: one call, then split at every 16-byte
 * boundary with 0-length calls in between; y and data at offsets 0..3. Run for the build's
 * brisk__ghash and for the multiply-free one, so BRISK_GHASH_MULFREE is covered on every arch. */
static void test_ghash_with(ghash_fn ghash)
{
    size_t i, off, b;
    for (i = 0; i < N(GHASH_KAT); i++) {
        const struct ghash_kat *v = &GHASH_KAT[i];
        uint8_t y0[16], h[16], want[16], wy[16 + 4], wh[16 + 4];
        size_t n = t_unhex(v->data, GP, GBUF);
        CHECKI(t_unhex(v->y, y0, 16) == 16 && t_unhex(v->h, h, 16) == 16, i);
        CHECKI(t_unhex(v->out, want, 16) == 16, i);
        for (off = 0; off < 4; off++) {
            memcpy(wy + off, y0, 16);
            memcpy(wh + off, h, 16);
            memcpy(GWI + off, GP, n);
            ghash(wy + off, wh + off, opt(GWI + off, n, off), n);
            CHECKI(memcmp(wy + off, want, 16) == 0, i);
        }
        for (b = 0; b <= n; b += 16) {
            memcpy(wy, y0, 16);
            ghash(wy, h, GP, b);
            ghash(wy, h, GP + b, 0);
            ghash(wy, h, GP + b, n - b);
            CHECKI(memcmp(wy, want, 16) == 0, i);
        }
    }
}

static void test_ghash(void)
{
    test_ghash_with(brisk__ghash);
    test_ghash_with(brisk__ghash_mulfree);
}

/* kat_cavp + kat_wycheproof + differential + unaligned: seal/open, out of place
 * and in place, canaries after out and tag; invalid rows must fail with out
 * wiped. */
static void test_gcm_vectors(void)
{
    size_t i, off;
    for (i = 0; i < N(GCM_KAT); i++) {
        const struct gcm_kat *v = &GCM_KAT[i];
        brisk__gcm_key gk;
        size_t klen = t_unhex(v->key, GK, 32), alen, n;
        CHECKI(t_unhex(v->iv, GN, 12) == 12, i);
        alen = t_unhex(v->aad, GA, GBUF);
        n = t_unhex(v->ct, GC, GBUF);
        CHECKI(t_unhex(v->tag, GT, 16) == 16, i);
        if (!v->valid) {
            CHECKI(brisk__gcm_init(&gk, GK, klen) == BRISK_OK, i);
            CHECKI(gcm_open_fails(&gk, GN, GA, alen, GC, n, GT), i);
            brisk__secure_zero(&gk, sizeof gk);
            continue;
        }
        CHECKI(t_unhex(v->pt, GP, GBUF) == n, i);
        for (off = 0; off < 4; off++) {
            uint8_t *key = GWK + off, *iv = GWN + off, *aad = GWA + off, *in = GWI + off,
                    *out = GWO + off, *tag = GWT + off;
            const uint8_t *a = opt(aad, alen, off), *pin = opt(in, n, off);
            uint8_t *pout = n == 0 && off == 0 ? NULL : out;
            memcpy(key, GK, klen);
            memcpy(iv, GN, 12);
            memcpy(aad, GA, alen);
            memcpy(in, GP, n);
            memset(out, 0, n);
            memset(out + n, 0xA5, CANARY);
            memset(tag, 0, 16);
            memset(tag + 16, 0xA5, CANARY);
            CHECKI(brisk__gcm_init(&gk, key, klen) == BRISK_OK, i);
            CHECKI(brisk__gcm_seal(&gk, iv, a, alen, pin, n, pout, tag) == BRISK_OK, i);
            CHECKI(memcmp(out, GC, n) == 0 && canary_ok(out + n), i);
            CHECKI(memcmp(tag, GT, 16) == 0 && canary_ok(tag + 16), i);
            /* seal in place */
            memcpy(out, GP, n);
            memset(tag, 0, 16);
            CHECKI(brisk__gcm_seal(&gk, iv, a, alen, out, n, out, tag) == BRISK_OK, i);
            CHECKI(memcmp(out, GC, n) == 0 && memcmp(tag, GT, 16) == 0 && canary_ok(out + n), i);
            /* open out of place, then in place */
            memcpy(in, GC, n);
            memset(out, 0, n);
            CHECKI(brisk__gcm_open(&gk, iv, a, alen, opt(in, n, off), n, pout, tag) == BRISK_OK, i);
            CHECKI(memcmp(out, GP, n) == 0 && canary_ok(out + n), i);
            memcpy(out, GC, n);
            CHECKI(brisk__gcm_open(&gk, iv, a, alen, out, n, out, tag) == BRISK_OK, i);
            CHECKI(memcmp(out, GP, n) == 0 && canary_ok(out + n) && canary_ok(tag + 16), i);
            brisk__secure_zero(&gk, sizeof gk);
        }
    }
}

/* One change at a time on the first valid vector with aad and ct of 3+ bytes:
 * every tag bit, first/middle/last ciphertext byte, one AAD bit, IV byte 0 and
 * 11, AAD or ct shortened by one. */
static void test_gcm_tamper(void)
{
    const struct gcm_kat *v = NULL;
    brisk__gcm_key gk;
    size_t i, klen, alen = 0, n = 0, b, pos[3];
    uint8_t t2[16], n2[12];
    for (i = 0; i < N(GCM_KAT) && !v; i++) {
        alen = t_unhex(GCM_KAT[i].aad, GA, GBUF);
        n = t_unhex(GCM_KAT[i].ct, GC, GBUF);
        if (GCM_KAT[i].valid && alen > 2 && n > 2) {
            v = &GCM_KAT[i];
        }
    }
    CHECK(v != NULL);
    if (!v) {
        return;
    }
    klen = t_unhex(v->key, GK, 32);
    t_unhex(v->iv, GN, 12);
    t_unhex(v->tag, GT, 16);
    CHECK(brisk__gcm_init(&gk, GK, klen) == BRISK_OK);
    for (b = 0; b < 128; b++) {
        memcpy(t2, GT, 16);
        t2[b / 8] ^= (uint8_t)(1u << (b % 8));
        CHECKI(gcm_open_fails(&gk, GN, GA, alen, GC, n, t2), b);
    }
    pos[0] = 0;
    pos[1] = n / 2;
    pos[2] = n - 1;
    for (b = 0; b < 3; b++) {
        GC[pos[b]] ^= 0x10;
        CHECKI(gcm_open_fails(&gk, GN, GA, alen, GC, n, GT), b);
        GC[pos[b]] ^= 0x10;
    }
    GA[alen - 1] ^= 1;
    CHECK(gcm_open_fails(&gk, GN, GA, alen, GC, n, GT));
    GA[alen - 1] ^= 1;
    for (b = 0; b < 12; b += 11) {
        memcpy(n2, GN, 12);
        n2[b] ^= 0x80;
        CHECKI(gcm_open_fails(&gk, n2, GA, alen, GC, n, GT), b);
    }
    CHECK(gcm_open_fails(&gk, GN, GA, alen - 1, GC, n, GT));
    CHECK(gcm_open_fails(&gk, GN, GA, alen, GC, n - 1, GT));
    /* untouched vector still opens (the loop above did not corrupt the inputs) */
    CHECK(brisk__gcm_open(&gk, GN, GA, alen, GC, n, GWO, GT) == BRISK_OK);
    brisk__secure_zero(&gk, sizeof gk);
}

/* invalid key lengths, P_MAX / A_MAX, and the empty message tag E(K, J0) ^
 * GHASH(0^128). */
static void test_gcm_limits(void)
{
    static const size_t bad[] = {0, 15, 24, 33};
    brisk__gcm_key gk, canary;
    uint8_t tag[16], want[16], j0[16], z[16];
    size_t i;
    memset(GK, 0x42, 32);
    memset(GN, 0x24, 12);
    for (i = 0; i < N(bad); i++) {
        memset(&gk, 0x5A, sizeof gk);
        memcpy(&canary, &gk, sizeof gk);
        CHECKI(brisk__gcm_init(&gk, GK, bad[i]) == BRISK_E_ARG, i);
        CHECKI(memcmp(&gk, &canary, sizeof gk) == 0, i);
    }
    CHECK(brisk__gcm_init(&gk, GK, 16) == BRISK_OK);
    /* H = E(K, 0^128) (SP 800-38D 7.1 step 1) */
    memset(z, 0, 16);
    brisk__aes_encrypt(&gk.aes, z, want);
    CHECK(memcmp(gk.h, want, 16) == 0);
    /* both empty: S = GHASH_H(0^128) (zero length block), T = E(K, J0) ^ S; NULLs
     * accepted */
    CHECK(brisk__gcm_seal(&gk, GN, NULL, 0, NULL, 0, NULL, tag) == BRISK_OK);
    memset(want, 0, 16);
    brisk__ghash(want, gk.h, z, 16);
    memcpy(j0, GN, 12);
    brisk__store_be32(j0 + 12, 1);
    brisk__aes_encrypt(&gk.aes, j0, j0);
    for (i = 0; i < 16; i++) {
        want[i] ^= j0[i];
    }
    CHECK(memcmp(tag, want, 16) == 0);
    CHECK(brisk__gcm_open(&gk, GN, NULL, 0, NULL, 0, NULL, tag) == BRISK_OK);
    tag[0] ^= 1;
    CHECK(brisk__gcm_open(&gk, GN, NULL, 0, NULL, 0, NULL, tag) == BRISK_E_AUTH);
#if SIZE_MAX > 0xffffffffu
    /* P_MAX + 1 = 2^36 - 31 (SP 800-38D 5.2.1.1) and A_MAX + 1 = 2^61 (RFC
     * 5116 5.1): rejected before any byte of aad/in/out/tag is touched */
    memset(tag, 0x77, 16);
    CHECK(brisk__gcm_seal(&gk, GN, NULL, 0, NULL, (size_t)68719476705u, NULL, tag) == BRISK_E_ARG);
    CHECK(brisk__gcm_open(&gk, GN, NULL, 0, NULL, (size_t)68719476705u, NULL, tag) == BRISK_E_ARG);
    CHECK(brisk__gcm_seal(&gk, GN, NULL, (size_t)1 << 61, NULL, 0, NULL, tag) == BRISK_E_ARG);
    CHECK(brisk__gcm_open(&gk, GN, NULL, (size_t)1 << 61, NULL, 0, NULL, tag) == BRISK_E_ARG);
    for (i = 0; i < 16; i++) {
        CHECKI(tag[i] == 0x77, i);
    }
#endif
    brisk__secure_zero(&gk, sizeof gk);
}

/* QUIC variable-length integer (RFC 9000 16) */
static size_t quic_varint(const uint8_t *p, uint64_t *v)
{
    size_t n = (size_t)1 << (p[0] >> 6), i;
    *v = p[0] & 0x3f;
    for (i = 1; i < n; i++) {
        *v = (*v << 8) | p[i];
    }
    return n;
}

/* RFC 9001 A.2 (client) / A.3 (server) Initial, receive side end to end: keys
 * from the Initial secret (5.1), header protection removed with AES-ECB(hp,
 * sample) (5.4.1-5.4.3), packet number recovered, nonce = iv ^ pn (5.3), AAD =
 * unprotected header, AES-128-GCM open; then re-seal and compare with the RFC
 * packet, and a one-byte flip must fail. */
static void test_gcm_quic(void)
{
    size_t i;
    for (i = 0; i < N(QUIC_GCM_KAT); i++) {
        const struct quic_gcm_kat *v = &QUIC_GCM_KAT[i];
        static uint8_t pkt[1300], orig[1300], hdr[64], pt[1300];
        uint8_t secret[32], key[16], iv[12], hp[16], mask[16];
        brisk__gcm_key gk;
        brisk__aes_key hk;
        uint64_t tl, ln, pn = 0;
        size_t plen, hlen, want_hlen, p, pn_len, j, n;
        t_unhex(v->secret, secret, 32);
        plen = t_unhex(v->packet, pkt, sizeof pkt);
        memcpy(orig, pkt, plen);
        want_hlen = t_unhex(v->hdr, hdr, sizeof hdr);
        CHECKI(brisk__hkdf_expand_label(BRISK_HASH_SHA256, secret, 32, "quic key", NULL, 0, key,
                                        16) == BRISK_OK,
               i);
        CHECKI(brisk__hkdf_expand_label(BRISK_HASH_SHA256, secret, 32, "quic iv", NULL, 0, iv,
                                        12) == BRISK_OK,
               i);
        CHECKI(brisk__hkdf_expand_label(BRISK_HASH_SHA256, secret, 32, "quic hp", NULL, 0, hp,
                                        16) == BRISK_OK,
               i);
        /* long header: flags, version(4), dcid len + dcid, scid len + scid, token,
         * length */
        CHECKI(pkt[0] & 0x80, i);
        p = 5;
        p += 1 + pkt[p];
        p += 1 + pkt[p];
        p += quic_varint(pkt + p, &tl);
        p += (size_t)tl;
        p += quic_varint(pkt + p, &ln);
        CHECKI(p + (size_t)ln == plen, i);
        CHECK(brisk__aes_init(&hk, hp, 16) == BRISK_OK);
        brisk__aes_encrypt(&hk, pkt + p + 4, mask); /* sample at pn_offset + 4 */
        pkt[0] ^= mask[0] & 0x0f;
        pn_len = (size_t)(pkt[0] & 3) + 1;
        for (j = 0; j < pn_len; j++) {
            pkt[p + j] ^= mask[1 + j];
            pn = (pn << 8) | pkt[p + j];
        }
        hlen = p + pn_len;
        CHECKI(hlen == want_hlen && memcmp(pkt, hdr, hlen) == 0 && pn == v->pn, i);
        for (j = 0; j < 8; j++) {
            iv[4 + j] ^= (uint8_t)(pn >> (56 - 8 * j));
        }
        n = plen - hlen - 16;
        CHECKI(t_unhex(v->pt, GP, GBUF) == n, i);
        CHECK(brisk__gcm_init(&gk, key, 16) == BRISK_OK);
        CHECKI(brisk__gcm_open(&gk, iv, pkt, hlen, pkt + hlen, n, pt, pkt + hlen + n) == BRISK_OK,
               i);
        CHECKI(memcmp(pt, GP, n) == 0, i);
        /* re-seal: ciphertext and tag equal the RFC packet */
        memset(GWO, 0, n + 16);
        CHECKI(brisk__gcm_seal(&gk, iv, hdr, hlen, pt, n, GWO, GWO + n) == BRISK_OK, i);
        CHECKI(memcmp(GWO, orig + hlen, n + 16) == 0, i);
        /* one flipped byte in the protected payload: E_AUTH, output wiped */
        pkt[hlen + n / 2] ^= 1;
        CHECKI(gcm_open_fails(&gk, iv, pkt, hlen, pkt + hlen, n, pkt + hlen + n), i);
        brisk__secure_zero(&gk, sizeof gk);
        brisk__secure_zero(&hk, sizeof hk);
    }
}

void test_aes(void)
{
    test_ecb();
    test_mct();
    test_ctr_vectors();
    test_ctr_lengths();
    test_quic_hp();
    test_invalid();
    test_ghash();
    test_gcm_vectors();
    test_gcm_tamper();
    test_gcm_limits();
    test_gcm_quic();
}
