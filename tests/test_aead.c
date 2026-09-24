/* test_aead.c - ChaCha20, Poly1305 and AEAD_CHACHA20_POLY1305 (RFC 8439) against RFC 8439,
 * Wycheproof and a seeded differential set, plus the RFC 9001 A.5 QUIC ChaCha20 packet
 * (tests/kat/SOURCES.md). Every vector also runs with buffers at offsets 1..3 (misaligned word
 * access on MIPS/ARMv5/PPC), in place, and with canaries after every output. */
#include <stdint.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct chacha_kat {
    const char *key;
    uint32_t counter;
    const char *nonce, *in, *out;
};
struct poly_kat {
    const char *key, *msg, *tag;
};
struct aead_kat {
    const char *key, *nonce, *aad, *pt, *ct, *tag;
    int valid;
};
struct quic_chacha_kat {
    const char *secret;
    uint64_t pn;
    const char *hdr, *pt, *ct_tag, *sample, *mask, *packet;
};

#include "kat/chacha20.inc"
#include "kat/poly1305.inc"
#include "kat/chacha20_poly1305.inc"
#include "kat/quic_chacha.inc"

#define N(a)   (sizeof(a) / sizeof((a)[0]))
#define BUF    1200 /* largest vector: 1094 bytes (Wycheproof) */
#define CANARY 16

/* Decoded vector (aligned) and working copies placed at an offset inside larger arrays. */
static uint8_t K[32], NC[12], A[BUF], P[BUF], C[BUF], T[16];
static uint8_t WK[32 + 4], WN[12 + 4], WA[BUF + 4], WI[BUF + 4], WO[BUF + 4 + CANARY],
    WT[16 + 4 + CANARY];

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

/* NULL for an empty buffer at offset 0: exercises aad=NULL / in=NULL with length 0. */
static const uint8_t *opt(const uint8_t *p, size_t n, size_t off)
{
    return n == 0 && off == 0 ? NULL : p;
}

static void test_chacha(void)
{
    size_t i, off, k;
    for (i = 0; i < N(CHACHA_KAT); i++) {
        const struct chacha_kat *v = &CHACHA_KAT[i];
        size_t n;
        t_unhex(v->key, K, 32);
        t_unhex(v->nonce, NC, 12);
        n = t_unhex(v->in, P, BUF);
        CHECKI(t_unhex(v->out, C, BUF) == n, i);
        for (off = 0; off < 4; off++) {
            uint8_t *key = WK + off, *nonce = WN + off, *in = WI + off, *out = WO + off;
            memcpy(key, K, 32);
            memcpy(nonce, NC, 12);
            memcpy(in, P, n);
            memset(out, 0, n);
            memset(out + n, 0xA5, CANARY);
            brisk__chacha20(key, v->counter, nonce, in, out, n);
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
            /* in place */
            memcpy(out, P, n);
            brisk__chacha20(key, v->counter, nonce, out, out, n);
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
        }
        /* split at every block boundary: [0,64k) then the rest with counter + k */
        for (k = 1; 64 * k < n; k++) {
            memset(WO, 0, n);
            brisk__chacha20(K, v->counter, NC, P, WO, 64 * k);
            brisk__chacha20(K, v->counter + (uint32_t)k, NC, P + 64 * k, WO + 64 * k, n - 64 * k);
            CHECKI(memcmp(WO, C, n) == 0, i);
        }
    }
}

static void test_poly(void)
{
    size_t i, off;
    for (i = 0; i < N(POLY_KAT); i++) {
        const struct poly_kat *v = &POLY_KAT[i];
        size_t n;
        t_unhex(v->key, K, 32);
        n = t_unhex(v->msg, P, BUF);
        t_unhex(v->tag, T, 16);
        for (off = 0; off < 4; off++) {
            uint8_t *key = WK + off, *msg = WI + off, *tag = WT + off;
            memcpy(key, K, 32);
            memcpy(msg, P, n);
            memset(tag + 16, 0xA5, CANARY);
            brisk__poly1305(key, opt(msg, n, off), n, tag);
            CHECKI(memcmp(tag, T, 16) == 0 && canary_ok(tag + 16), i);
        }
    }
}

/* Open of (aad, ct, tag) that must fail: BRISK_E_AUTH and out fully zeroed, also in place. */
static int open_fails(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t alen,
                      const uint8_t *ct, size_t n, const uint8_t *tag)
{
    int ok;
    memset(WO, 0xA5, n + CANARY);
    ok = brisk__chacha20_poly1305_open(key, nonce, aad, alen, ct, n, WO, tag) == BRISK_E_AUTH &&
         all_zero(WO, n) && canary_ok(WO + n);
    memcpy(WO, ct, n);
    ok &= brisk__chacha20_poly1305_open(key, nonce, aad, alen, WO, n, WO, tag) == BRISK_E_AUTH &&
          all_zero(WO, n) && canary_ok(WO + n);
    return ok;
}

static void test_aead_vectors(void)
{
    size_t i, off;
    for (i = 0; i < N(AEAD_KAT); i++) {
        const struct aead_kat *v = &AEAD_KAT[i];
        size_t alen, n;
        t_unhex(v->key, K, 32);
        t_unhex(v->nonce, NC, 12);
        alen = t_unhex(v->aad, A, BUF);
        n = t_unhex(v->pt, P, BUF);
        CHECKI(t_unhex(v->ct, C, BUF) == n, i);
        t_unhex(v->tag, T, 16);
        if (!v->valid) {
            CHECKI(open_fails(K, NC, A, alen, C, n, T), i);
            continue;
        }
        for (off = 0; off < 4; off++) {
            uint8_t *key = WK + off, *nonce = WN + off, *aad = WA + off, *in = WI + off,
                    *out = WO + off, *tag = WT + off;
            const uint8_t *a = opt(aad, alen, off), *pin = opt(in, n, off);
            uint8_t *pout = n == 0 && off == 0 ? NULL : out;
            memcpy(key, K, 32);
            memcpy(nonce, NC, 12);
            memcpy(aad, A, alen);
            memcpy(in, P, n);
            memset(out, 0, n);
            memset(out + n, 0xA5, CANARY);
            memset(tag, 0, 16);
            memset(tag + 16, 0xA5, CANARY);
            CHECKI(brisk__chacha20_poly1305_seal(key, nonce, a, alen, pin, n, pout, tag) ==
                       BRISK_OK,
                   i);
            CHECKI(memcmp(out, C, n) == 0 && canary_ok(out + n), i);
            CHECKI(memcmp(tag, T, 16) == 0 && canary_ok(tag + 16), i);
            /* seal in place */
            memcpy(out, P, n);
            memset(tag, 0, 16);
            CHECKI(brisk__chacha20_poly1305_seal(key, nonce, a, alen, out, n, out, tag) == BRISK_OK,
                   i);
            CHECKI(memcmp(out, C, n) == 0 && memcmp(tag, T, 16) == 0 && canary_ok(out + n), i);
            /* open out of place, then in place */
            memcpy(in, C, n);
            memcpy(tag, T, 16);
            memset(out, 0, n);
            CHECKI(brisk__chacha20_poly1305_open(key, nonce, a, alen, opt(in, n, off), n, pout,
                                                 tag) == BRISK_OK,
                   i);
            CHECKI(memcmp(out, P, n) == 0 && canary_ok(out + n), i);
            memcpy(out, C, n);
            CHECKI(brisk__chacha20_poly1305_open(key, nonce, a, alen, out, n, out, tag) == BRISK_OK,
                   i);
            CHECKI(memcmp(out, P, n) == 0 && canary_ok(out + n) && canary_ok(tag + 16), i);
        }
    }
}

/* RFC 8439 2.8.2 (AEAD_KAT[0]) with one change at a time: every tag bit, first/middle/last
 * ciphertext byte, one AAD bit, one nonce byte, AAD shortened by one. */
static void test_tamper(void)
{
    const struct aead_kat *v = &AEAD_KAT[0];
    size_t alen, n, b;
    uint8_t t2[16], n2[12];
    t_unhex(v->key, K, 32);
    t_unhex(v->nonce, NC, 12);
    alen = t_unhex(v->aad, A, BUF);
    n = t_unhex(v->ct, C, BUF);
    t_unhex(v->tag, T, 16);
    CHECK(n > 2 && alen > 1);
    for (b = 0; b < 128; b++) {
        memcpy(t2, T, 16);
        t2[b / 8] ^= (uint8_t)(1u << (b % 8));
        CHECKI(open_fails(K, NC, A, alen, C, n, t2), b);
    }
    {
        size_t pos[3];
        pos[0] = 0;
        pos[1] = n / 2;
        pos[2] = n - 1;
        for (b = 0; b < 3; b++) {
            C[pos[b]] ^= 0x10;
            CHECKI(open_fails(K, NC, A, alen, C, n, T), b);
            C[pos[b]] ^= 0x10;
        }
    }
    A[alen - 1] ^= 1;
    CHECK(open_fails(K, NC, A, alen, C, n, T));
    A[alen - 1] ^= 1;
    memcpy(n2, NC, 12);
    n2[11] ^= 0x80;
    CHECK(open_fails(K, n2, A, alen, C, n, T));
    CHECK(open_fails(K, NC, A, alen - 1, C, n, T));
    /* untouched vector still opens (the loop above did not corrupt the inputs) */
    CHECK(brisk__chacha20_poly1305_open(K, NC, A, alen, C, n, WO, T) == BRISK_OK);
}

static void test_limits(void)
{
    uint8_t tag[16];
    memset(K, 0x42, 32);
    memset(NC, 0x24, 12);
    /* both empty: tag = Poly1305 over the two zero length words only; NULLs accepted */
    CHECK(brisk__chacha20_poly1305_seal(K, NC, NULL, 0, NULL, 0, NULL, tag) == BRISK_OK);
    CHECK(brisk__chacha20_poly1305_open(K, NC, NULL, 0, NULL, 0, NULL, tag) == BRISK_OK);
    tag[0] ^= 1;
    CHECK(brisk__chacha20_poly1305_open(K, NC, NULL, 0, NULL, 0, NULL, tag) == BRISK_E_AUTH);
#if SIZE_MAX > 0xffffffffu
    /* P_MAX + 1 (RFC 8439 2.8): rejected before any byte of in/out is touched */
    CHECK(brisk__chacha20_poly1305_seal(K, NC, NULL, 0, NULL, (size_t)274877906881u, NULL, tag) ==
          BRISK_E_ARG);
    CHECK(brisk__chacha20_poly1305_open(K, NC, NULL, 0, NULL, (size_t)274877906881u, NULL, tag) ==
          BRISK_E_ARG);
#endif
}

/* RFC 9001 A.5: key schedule, packet nonce (5.3), AEAD, header protection with ChaCha20 (5.4.4). */
static void test_quic_a5(void)
{
    const struct quic_chacha_kat *v = &QUIC_CHACHA_KAT[0];
    uint8_t secret[32], key[32], iv[12], hp[32], hdr[4], pt[1], ct[1 + 16], want[64], sample[16],
        mask[5], pkt[64];
    static const uint8_t zero5[5];
    size_t hlen, plen, pn_len, i;
    t_unhex(v->secret, secret, 32);
    hlen = t_unhex(v->hdr, hdr, sizeof hdr);
    plen = t_unhex(v->pt, pt, sizeof pt);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, secret, 32, "quic key", NULL, 0, key, 32) ==
          BRISK_OK);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, secret, 32, "quic iv", NULL, 0, iv, 12) ==
          BRISK_OK);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, secret, 32, "quic hp", NULL, 0, hp, 32) ==
          BRISK_OK);
    for (i = 0; i < 8; i++) {
        iv[4 + i] ^= (uint8_t)(v->pn >> (56 - 8 * i));
    }
    CHECK(brisk__chacha20_poly1305_seal(key, iv, hdr, hlen, pt, plen, ct, ct + plen) == BRISK_OK);
    CHECK(t_unhex(v->ct_tag, want, sizeof want) == plen + 16 && memcmp(ct, want, plen + 16) == 0);
    pn_len = (size_t)(hdr[0] & 3) + 1;
    memcpy(sample, ct + 4 - pn_len, 16); /* RFC 9001 5.4.2: sample at pn_offset + 4 */
    t_unhex(v->sample, want, 16);
    CHECK(memcmp(sample, want, 16) == 0);
    brisk__chacha20(hp, brisk__load_le32(sample), sample + 4, zero5, mask, 5);
    t_unhex(v->mask, want, 5);
    CHECK(memcmp(mask, want, 5) == 0);
    memcpy(pkt, hdr, hlen);
    pkt[0] ^= mask[0] & 0x1f; /* short header */
    for (i = 0; i < pn_len; i++) {
        pkt[hlen - pn_len + i] ^= mask[1 + i];
    }
    memcpy(pkt + hlen, ct, plen + 16);
    CHECK(t_unhex(v->packet, want, sizeof want) == hlen + plen + 16);
    CHECK(memcmp(pkt, want, hlen + plen + 16) == 0);
}

void test_aead(void)
{
    test_chacha();
    test_poly();
    test_aead_vectors();
    test_tamper();
    test_limits();
    test_quic_a5();
}
