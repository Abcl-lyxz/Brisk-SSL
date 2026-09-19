/* test_aes.c - AES-128/256 forward cipher (FIPS 197) and the inc32 counter mode (SP
 * 800-38D 6.2/6.5) against FIPS 197 C.1/C.3, NIST CAVP AESAVS (KAT, MMT, MCT), SP 800-38A F.5, RFC
 * 9001 A.2/A.3 and a seeded differential set (tests/kat/SOURCES.md). One of aes_ct (32-bit) /
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

#include "kat/aes_ecb.inc"
#include "kat/aes_mct.inc"
#include "kat/aes_ctr.inc"
#include "kat/aes_quic_hp.inc"

#define N(a)   (sizeof(a) / sizeof((a)[0]))
#define BUF    320 /* largest vector: 300 bytes (differential); MMT is 160 */
#define CANARY 16

/* struct_size: the key is embedded in public structs later, so its size must not depend on arch */
typedef char aes_key_size_is_fixed[sizeof(brisk__aes_key) == 248 ? 1 : -1];

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

void test_aes(void)
{
    test_ecb();
    test_mct();
    test_ctr_vectors();
    test_ctr_lengths();
    test_quic_hp();
    test_invalid();
}
