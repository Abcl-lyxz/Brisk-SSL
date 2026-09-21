/* test_p384.c - P-384 (secp384r1) ECDSA verify against RFC 5903 3.2, NIST CAVP (186-3 ECDSAVS
 * SigVer at SHA-384 and SHA-512, PKV), the Wycheproof ecdsa_secp384r1_sha384_p1363 and
 * ecdsa_secp384r1_sha512_p1363 suites, RFC 6979 A.2.6 and a seeded differential set
 * (tests/kat/SOURCES.md).
 *
 * Verify only, by design: there is no P-384 keygen, ECDH or signing in this library and no test
 * here can grow one. The whole file sits inside #if BRISK_ENABLE_P384 (the BRISK_ENABLE_MTLS
 * pattern), so a TINY build compiles and links with no p384 symbols at all.
 *
 * Wycheproof flag coverage worth naming, counted as EMITTED over both files - tools/kat.py drops
 * every row whose signature is not 96 bytes or whose point is not 97, so the upstream per-flag
 * totals are larger: SpecialCaseHash 209, ArithmeticError 182, InvalidSignature 98,
 * EdgeCasePublicKey 36, ModularInverse 30, SmallRandS 12, PointDuplication 14,
 * EdgeCaseShamirMultiplication 2, Untruncatedhash 1. The last three are precisely what the
 * complete Renes-Costello-Batina addition and the interleaved Straus ladder have to survive.
 *
 * Zero rows survive the width filter for SignatureSize, RangeCheck and IntegerOverflow: each of
 * those is a wrong-width encoding this API cannot express, since brisk__p384_ecdsa_verify takes
 * a fixed uint8_t[96] and uint8_t[97]. Their substance is covered instead by the generated r/s
 * edge rows (0, n, n+1, 2^384-1 on each side) and the bad-encoding rows from differential_p384(),
 * and by the 256-value first-byte sweep below - which is what tests/kat/SOURCES.md records.
 *
 * How the curve parameters are pinned, without the library exporting them (tests/kat/
 * p384_params.inc carries the values parsed out of RFC 5903 3.2 by tools/kat.py):
 *   n      the r/s boundary rows: r or s equal to 0, n, n+1 or 2^384-1 must be BRISK_E_AUTH while
 *          n-1 on both sides is still only a failed signature. Shrinking n in src/crypto/p384.c
 *          turns the n-1 row into an accept-range change that these rows catch.
 *   G      every valid vector at once: a wrong G rejects all 435 of them.
 *   b      every on-curve vector at once, for the same reason - no single vector names it.
 *   p      NOT pinned here, and the checks below must not be read as pinning it: they assert only
 *          BRISK_E_ARG, which brisk__p384_ecdsa_verify returns for an out-of-range coordinate and
 *          for a point off the curve alike, so shrinking P384_P leaves every one of them passing.
 *          What pins p is check_p384_source_constants() in tools/kat.py, which reads the C array
 *          out of the source and compares it with the RFC - at vector-generation time, not at
 *          test time. The rows below are still worth their lines as boundary cases.
 *
 * Every entry point here is one-shot over fixed-size buffers - there is no streaming API - so the
 * c-code rule's "split input" case does not apply; nothing is missing.
 *
 * RUNTIME. One verify is about 12,000 13-limb Montgomery multiplications, roughly two P-256
 * verifies, and qemu-armv5 is the binding constraint. So `deep` (offsets 1..3) is set only on the
 * CAVP, PKV, RFC 6979 and differential rows plus the non-valid Wycheproof ones - the rule
 * tools/kat.py already applies for P-256 - and the mutation pass runs on a bounded handful of
 * valid rows rather than all of them. This suite gets the same TIMEOUT 900 as every other one;
 * the measured qemu-armv5 runtime that justifies it is recorded at CMakeLists.txt:74-79.
 * Re-measure there before adding vectors in bulk.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_P384

struct p384_param {
    const char *name, *hex;
};
struct p384_verify_kat {
    const char *pub, *hash, *sig;
    int expect; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG */
    int deep;   /* also run at offsets 1..3 with canaries */
};

#    include "kat/p384_params.inc"
#    include "kat/p384_verify.inc"

#    define N(a) (sizeof(a) / sizeof((a)[0]))

/* The row count named in the header comment above, pinned so regenerating the vectors cannot
 * leave that prose (and the qemu-armv5 budget argument built on it) quietly stale. Same idiom as
 * tests/test_p256.c. Update both places together. */
typedef char p384_verify_row_count[N(P384_VERIFY_KAT) == 630 ? 1 : -1];

#    define SL     BRISK__P384_SCALAR_LEN /* 48 */
#    define PL     BRISK__P384_POINT_LEN  /* 97 */
#    define GL     BRISK__P384_SIG_LEN    /* 96 */
#    define HMAXL  64                     /* the longest digest any row carries (SHA-512) */
#    define CANARY 16

/* expect codes, matching tools/kat.py */
#    define E_OK   0
#    define E_AUTH 1
#    define E_ARG  2

static int rc_code(int rc)
{
    if (rc == BRISK_OK) {
        return E_OK;
    }
    return rc == BRISK_E_AUTH ? E_AUTH : E_ARG;
}

static int canary_ok(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != 0xA5) {
            return 0;
        }
    }
    return 1;
}

/* the RFC 5903 3.2 parameters, as hex, for the pinning checks */
static const char *param(const char *name)
{
    size_t i;
    for (i = 0; i < N(P384_PARAM); i++) {
        if (strcmp(P384_PARAM[i].name, name) == 0) {
            return P384_PARAM[i].hex;
        }
    }
    CHECK(0); /* tools/kat.py emits all five */
    return NULL;
}

/* One verify at a chosen buffer offset, with 0xA5 canaries behind each input. */
static void verify_one(const uint8_t *pub, const uint8_t *h, size_t hlen, const uint8_t *sig,
                       int expect, size_t off, long idx)
{
    uint8_t qs[PL + 4 + CANARY], hs[HMAXL + 4 + CANARY], ss[GL + 4 + CANARY];
    memcpy(qs + off, pub, PL);
    memset(qs + off + PL, 0xA5, CANARY);
    memcpy(hs + off, h, hlen);
    memset(hs + off + hlen, 0xA5, CANARY);
    memcpy(ss + off, sig, GL);
    memset(ss + off + GL, 0xA5, CANARY);
    CHECKI(rc_code(brisk__p384_ecdsa_verify(qs + off, hs + off, hlen, ss + off)) == expect, idx);
    CHECKI(memcmp(qs + off, pub, PL) == 0, idx); /* inputs are never modified */
    CHECKI(memcmp(hs + off, h, hlen) == 0, idx);
    CHECKI(memcmp(ss + off, sig, GL) == 0, idx);
    CHECKI(canary_ok(qs + off + PL, CANARY), idx); /* and nothing is written past them */
    CHECKI(canary_ok(hs + off + hlen, CANARY), idx);
    CHECKI(canary_ok(ss + off + GL, CANARY), idx);
}

static void test_verify(void)
{
    uint8_t pub[PL], h[HMAXL], sig[GL], t[PL];
    size_t i, off, hlen, mutated = 0;
    for (i = 0; i < N(P384_VERIFY_KAT); i++) {
        const struct p384_verify_kat *v = &P384_VERIFY_KAT[i];
        CHECKI(t_unhex(v->pub, pub, PL) == PL, i);
        hlen = t_unhex(v->hash, h, sizeof h);
        CHECKI(t_unhex(v->sig, sig, GL) == GL, i);
        CHECKI(rc_code(brisk__p384_ecdsa_verify(pub, h, hlen, sig)) == v->expect, i);
        if (!v->deep) {
            continue;
        }
        for (off = 1; off < 4; off++) {
            verify_one(pub, h, hlen, sig, v->expect, off, (long)i);
        }
        if (v->expect != E_OK) {
            continue;
        }
        /* Mutation pass, bounded: each row costs 12 more verifies, and one verify is about two
         * P-256 verifies. Four rows are enough to catch a formula that ignores an input. */
        if (mutated < 4) {
            size_t k;
            mutated++;
            for (k = 0; k < 4; k++) {
                /* Only the leftmost 48 bytes feed e (FIPS 186-5 6.4.2), so the hash mutation
                 * stays inside them; bytes past that are asserted to be ignored just below. */
                size_t bit = (k * 97) % (SL * 8);
                h[bit / 8] = (uint8_t)(h[bit / 8] ^ (1u << (bit % 8)));
                CHECKI(brisk__p384_ecdsa_verify(pub, h, hlen, sig) != BRISK_OK, i);
                h[bit / 8] = (uint8_t)(h[bit / 8] ^ (1u << (bit % 8)));

                /* r for k even, s for k odd: the low half of sig is r, the high half s, so the
                 * parity of k picks the half and the stride picks the bit inside it. */
                bit = (k & 1) * (SL * 8) + (k * 131) % (SL * 8);
                sig[bit / 8] = (uint8_t)(sig[bit / 8] ^ (1u << (bit % 8)));
                CHECKI(brisk__p384_ecdsa_verify(pub, h, hlen, sig) != BRISK_OK, i);
                sig[bit / 8] = (uint8_t)(sig[bit / 8] ^ (1u << (bit % 8)));

                bit = (k * 149) % (2 * SL * 8); /* X or Y of the public key */
                memcpy(t, pub, PL);
                t[1 + bit / 8] = (uint8_t)(t[1 + bit / 8] ^ (1u << (bit % 8)));
                CHECKI(brisk__p384_ecdsa_verify(t, h, hlen, sig) != BRISK_OK, i);
            }
        }
        /* The other half of the leftmost-bits rule: a byte past the 48th must not matter. The
         * CAVP [P-384,SHA-512] and RFC 6979 A.2.6 SHA-512 rows are the official ones that reach
         * here with a 64-byte digest. */
        if (hlen > SL) {
            size_t j;
            for (j = SL; j < hlen; j++) {
                h[j] = (uint8_t)(h[j] ^ 0xFF);
            }
            CHECKI(brisk__p384_ecdsa_verify(pub, h, hlen, sig) == BRISK_OK, i);
            for (j = SL; j < hlen; j++) {
                h[j] = (uint8_t)(h[j] ^ 0xFF);
            }
        } else {
            /* and the same row re-presented longer must still verify */
            uint8_t h2[HMAXL];
            memcpy(h2, h, SL);
            memset(h2 + SL, 0x5A, HMAXL - SL);
            CHECKI(brisk__p384_ecdsa_verify(pub, h2, HMAXL, sig) == BRISK_OK, i);
        }
        /* A digest shorter than 48 bytes is BRISK_E_ARG, not a truncated verify. 32 is the
         * R8 boundary case: a SHA-256 digest offered against a P-384 key. These return before
         * any point arithmetic, so they are nearly free. */
        CHECKI(brisk__p384_ecdsa_verify(pub, h, 47, sig) == BRISK_E_ARG, i);
        CHECKI(brisk__p384_ecdsa_verify(pub, h, 32, sig) == BRISK_E_ARG, i);
        CHECKI(brisk__p384_ecdsa_verify(pub, h, 0, sig) == BRISK_E_ARG, i);
    }
    CHECK(mutated == 4); /* the vector table must still contain valid deep rows */
}

/* Every first byte other than 0x04 is rejected, and rejected as malformed key material
 * (BRISK_E_ARG) rather than as a failed signature: compressed (0x02/0x03) and hybrid (0x06/0x07)
 * points are never decompressed, because TLS 1.3 removed point-format negotiation. Free of point
 * arithmetic - the first byte is checked before anything else - so all 256 values are cheap. */
/* Load the first accepting row into pub/h/sig and return its digest length. Always leaves the
 * three buffers defined: CHECK only records a failure, it does not abort, so a generated table
 * with no accepting row must not fall through into a verify with an indeterminate hash_len. */
static size_t first_ok_row(uint8_t pub[PL], uint8_t h[HMAXL], uint8_t sig[GL])
{
    size_t i;
    for (i = 0; i < N(P384_VERIFY_KAT); i++) {
        if (P384_VERIFY_KAT[i].expect != E_OK) {
            continue;
        }
        CHECK(t_unhex(P384_VERIFY_KAT[i].pub, pub, PL) == PL);
        CHECK(t_unhex(P384_VERIFY_KAT[i].sig, sig, GL) == GL);
        return t_unhex(P384_VERIFY_KAT[i].hash, h, HMAXL);
    }
    CHECK(0); /* the generated table must contain an accepting row */
    memset(pub, 0, PL);
    memset(h, 0, HMAXL);
    memset(sig, 0, GL);
    return SL;
}

static void test_point_prefix(void)
{
    uint8_t pub[PL], h[HMAXL], sig[GL];
    size_t i, hlen = first_ok_row(pub, h, sig);
    for (i = 0; i < 256; i++) {
        pub[0] = (uint8_t)i;
        CHECKI(rc_code(brisk__p384_ecdsa_verify(pub, h, hlen, sig)) == (i == 0x04 ? E_OK : E_ARG),
               i);
    }
}

/* n, behaviourally. The generated rows already assert BRISK_E_AUTH for r or s at 0, n, n+1 and
 * 2^384-1; this adds the other side of the boundary from the parsed RFC value, so a p384.c whose
 * n was mistyped low would accept an s that this rejects, or reject an s that it accepts. */
static void test_order_boundary(void)
{
    uint8_t pub[PL], h[HMAXL], sig[GL], n_[SL];
    size_t hlen = first_ok_row(pub, h, sig);
    CHECK(t_unhex(param("n"), n_, SL) == SL);
    /* s = n-1 is in range: a failed signature (AUTH), not malformed input (ARG). s = n is out of
     * range, and FIPS 186-5 6.4.2 step 1 still calls that INVALID - so also AUTH, never ARG.
     * Both land on the same code on purpose: the pair must not become an oracle. */
    memcpy(sig + SL, n_, SL);
    sig[GL - 1] = (uint8_t)(sig[GL - 1] - 1); /* n ends in 0x73, so no borrow */
    CHECK(brisk__p384_ecdsa_verify(pub, h, hlen, sig) == BRISK_E_AUTH);
    memcpy(sig + SL, n_, SL);
    CHECK(brisk__p384_ecdsa_verify(pub, h, hlen, sig) == BRISK_E_AUTH);
    memcpy(sig, n_, SL); /* r = n as well */
    CHECK(brisk__p384_ecdsa_verify(pub, h, hlen, sig) == BRISK_E_AUTH);
}

void test_p384(void)
{
    test_verify();
    test_point_prefix();
    test_order_boundary();
}

#else /* !BRISK_ENABLE_P384 */

void test_p384(void)
{
    /* The knob is off: p384.c is an empty translation unit and no symbol exists to call. Saying
     * so with one passing check keeps test_main.c's "no checks ran" guard meaningful. */
    CHECK(1);
}

#endif /* BRISK_ENABLE_P384 */
