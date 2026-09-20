/* test_x25519.c - X25519 (RFC 7748) against RFC 7748 5.2/6.1, the RFC 8448 TLS 1.3 traces,
 * all 518 Wycheproof XdhComp cases and a seeded differential set (tests/kat/SOURCES.md).
 *
 * Extra passes beyond the plain vectors: the MUST-mask rule (every vector rerun with bit 255 of u
 * set must give the identical output), clamping (the caller's scalar comes back untouched, and
 * two scalars differing only in the clamped bits agree), aliasing (out == scalar, out == u, and
 * both), and the fail-closed cases (small-order u must return BRISK_E_ARG with out all-zero).
 *
 * The vector table carries a `deep` flag: those rows also run at buffer offsets 1..3 with 0xA5
 * canaries. Running all 518 Wycheproof cases four times over would blow the 900 s qemu-armv5
 * budget, so `deep` marks the interesting ones - the RFC rows, every all-zero result and every
 * non-canonical u.
 *
 * brisk__x25519 has no streaming API (one 32-byte scalar, one 32-byte u, one shot), so the
 * c-code rule's "split input" case does not apply here; nothing is missing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct x25519_kat {
    const char *scalar, *u, *out;
    int ok;   /* 1 = BRISK_OK, 0 = BRISK_E_ARG: the all-zero shared secret */
    int deep; /* also run at offsets 1..3 with canaries */
};
struct x25519_iter_kat {
    long iters;
    const char *out;
};

#include "kat/x25519.inc"
#include "kat/x25519_iter.inc"

#define N(a)   (sizeof(a) / sizeof((a)[0]))
#define L      BRISK__X25519_LEN
#define CANARY 16

static const uint8_t BASE[L] = {9};

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

static int all_zero(const uint8_t *p)
{
    size_t i;
    for (i = 0; i < L; i++) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

/* One call at offset `off` inside larger buffers, with a canary after the output. */
static void one(const uint8_t *k, const uint8_t *u, const uint8_t *want, int ok, size_t off,
                long idx)
{
    uint8_t ks[L + 4], us[L + 4], os[L + 4 + CANARY];
    int rc;
    memcpy(ks + off, k, L);
    memcpy(us + off, u, L);
    memset(os + off, 0, L);
    memset(os + off + L, 0xA5, CANARY);
    rc = brisk__x25519(os + off, ks + off, us + off);
    CHECKI(rc == (ok ? BRISK_OK : BRISK_E_ARG), idx);
    CHECKI(memcmp(os + off, want, L) == 0, idx);
    CHECKI(canary_ok(os + off + L), idx);
    CHECKI(memcmp(ks + off, k, L) == 0, idx); /* the scalar is clamped on a private copy */
    CHECKI(memcmp(us + off, u, L) == 0, idx);
    if (!ok) {
        CHECKI(all_zero(os + off), idx); /* fail closed: no half-computed secret is released */
    }
}

static void test_vectors(void)
{
    size_t i, off;
    for (i = 0; i < N(X25519_KAT); i++) {
        const struct x25519_kat *v = &X25519_KAT[i];
        uint8_t k[L], u[L], want[L], o[L], o2[L];
        CHECKI(t_unhex(v->scalar, k, L) == L, i);
        CHECKI(t_unhex(v->u, u, L) == L, i);
        CHECKI(t_unhex(v->out, want, L) == L, i);

        one(k, u, want, v->ok, 0, (long)i);
        if (v->deep) {
            for (off = 1; off < 4; off++) {
                one(k, u, want, v->ok, off, (long)i);
            }
        }
        /* RFC 7748 5 MUST: bit 255 of u is masked off, so setting it changes nothing. */
        u[31] = (uint8_t)(u[31] | 0x80);
        CHECKI(brisk__x25519(o, k, u) == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        CHECKI(memcmp(o, want, L) == 0, i);
        u[31] = (uint8_t)(u[31] & 0x7F);
        /* RFC 7748 5: the output is canonical, so its top bit is always zero. */
        CHECKI((want[31] & 0x80) == 0, i);

        if (memcmp(u, BASE, L) == 0) { /* a public-key row: brisk__x25519_base must agree */
            brisk__x25519_base(o, k);
            CHECKI(memcmp(o, want, L) == 0, i);
        }
        if (!v->deep) {
            continue;
        }
        /* Aliasing: out == scalar, out == u, and out == scalar == u. */
        memcpy(o, k, L);
        CHECKI(brisk__x25519(o, o, u) == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        CHECKI(memcmp(o, want, L) == 0, i);
        memcpy(o, u, L);
        CHECKI(brisk__x25519(o, k, o) == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        CHECKI(memcmp(o, want, L) == 0, i);
        memcpy(o, k, L);
        memcpy(o2, k, L);
        CHECKI(brisk__x25519(o, o, o) == brisk__x25519(o2, k, k), i);
        CHECKI(memcmp(o, o2, L) == 0, i);
    }
}

/* RFC 7748 5.2 iterated test: k, u = 9||0*31; each round k' = X25519(k, u), u' = k.
 * 1,000,000 iterations takes hours under qemu-armv5, so it only runs with BRISK_TEST_SLOW=1. */
static void test_iterated(void)
{
    uint8_t k[L] = {9}, u[L] = {9}, t[L], want[L];
    long i, last = 1000;
    size_t v = 0;
    if (getenv("BRISK_TEST_SLOW") != NULL) {
        last = X25519_ITER_KAT[N(X25519_ITER_KAT) - 1].iters;
    }
    for (i = 1; i <= last; i++) {
        memcpy(t, k, L);
        CHECKI(brisk__x25519(k, t, u) == BRISK_OK, i);
        memcpy(u, t, L);
        if (v < N(X25519_ITER_KAT) && X25519_ITER_KAT[v].iters == i) {
            t_unhex(X25519_ITER_KAT[v].out, want, L);
            CHECKI(memcmp(k, want, L) == 0, i);
            v++;
        }
    }
    CHECK(v >= 2); /* after 1 and after 1,000 always run */
}

/* decodeScalar25519 (RFC 7748 5): the low 3 bits of byte 0 and the top 2 bits of byte 31 are
 * overwritten, so scalars differing only there must agree. */
static void test_clamping(void)
{
    uint8_t a[L], b[L], oa[L], ob[L], u[L];
    size_t i;
    for (i = 0; i < L; i++) {
        a[i] = (uint8_t)(i * 7 + 1);
        u[i] = (uint8_t)(i * 3 + 2);
    }
    memcpy(b, a, L);
    b[0] = (uint8_t)(b[0] ^ 7);
    b[31] = (uint8_t)(b[31] ^ 0xC0);
    CHECK(brisk__x25519(oa, a, u) == brisk__x25519(ob, b, u));
    CHECK(memcmp(oa, ob, L) == 0);
    brisk__x25519_base(oa, a);
    brisk__x25519_base(ob, b);
    CHECK(memcmp(oa, ob, L) == 0);
}

void test_x25519(void)
{
    test_vectors();
    test_iterated();
    test_clamping();
}
