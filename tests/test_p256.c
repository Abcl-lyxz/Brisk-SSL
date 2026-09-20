/* test_p256.c - P-256 (secp256r1) ECDHE, ECDSA verify and ECDSA sign against RFC 5903 3.1/8.1,
 * NIST CAVP (KAS ECC CDH, 186-3 ECDSAVS KeyPair/PKV/SigVer/SigGen at SHA-256, SHA-384 and
 * SHA-512), the full Wycheproof ecdh_secp256r1_ecpoint and ecdsa_secp256r1_sha256_p1363 suites,
 * RFC 6979 A.2.5 and a seeded differential set (tests/kat/SOURCES.md).
 *
 * Signing (BRISK_ENABLE_MTLS): the 6 usable RFC 6979 A.2.5 rows are the only official pin on the
 * deterministic-k derivation, and tools/kat.py checks the published k as well as r and s before
 * emitting them. The hedged rows (RFC 6979 3.6) can only be generated - the RFC itself says a
 * variant stops matching its published vectors - so what anchors them is that the same code path
 * with k' absent reproduces A.2.5 byte-for-byte. The k-out-of-range and r/s == 0 retries ship
 * with no vector coverage at all; that gap is recorded in tests/kat/SOURCES.md.
 *
 * Wycheproof flag coverage worth naming, counted as EMITTED - tools/kat.py drops every row whose
 * point is not 65 bytes or whose signature is not 64, so the upstream per-flag totals are larger:
 * ECDH EdgeCaseDoubling 204, EdgeCaseSharedSecret 54, EdgeCaseEphemeralKey 54,
 * InvalidCurveAttack 16, AdditionChain 15, CVE-2017-8932 2; ECDSA ArithmeticError 97 (of 110
 * upstream), SpecialCaseHash 54, InvalidSignature 49, EdgeCasePublicKey 24, ModularInverse 15,
 * SmallRandS 8 (of 16), PointDuplication 7.
 *
 * Zero rows survive the filter for WrongCurve, CompressedPoint, SignatureSize, RangeCheck and
 * IntegerOverflow: every one of those is a wrong-width encoding this API cannot express. Their
 * substance is covered instead by the generated r/s edge rows (0, n, n+1, 2^256-1 on each side)
 * from differential_p256() and by the 256-value first-byte sweep below - which is what
 * tests/kat/SOURCES.md records.
 *
 * How the curve parameters are pinned, without the library exporting them (tests/kat/
 * p256_params.inc carries the values parsed out of RFC 5903 3.1 by tools/kat.py):
 *   G      keygen(1) must be exactly 0x04 || Gx || Gy.
 *   n      scalar_valid() flips at n-1/n, and reduce(n) == 0, reduce(n+1) == 1.
 *   p      NOT pinned here, and the checks below must not be read as pinning it: they assert only
 *          BRISK_E_ARG, which brisk__p256_ecdh returns for an out-of-range coordinate and for a
 *          point off the curve alike, so shrinking P256_P in src/crypto/p256.c leaves every one
 *          of them passing. What pins p is check_p256_source_constants() in tools/kat.py, which
 *          reads the C array out of the source and compares it to the RFC - at vector-generation
 *          time, not at test time. The rows below are still worth their lines as boundary cases.
 *   b      every on-curve vector in p256_ecdh.inc; a wrong b rejects all 330 valid Wycheproof
 *          rows at once.
 *
 * Beyond the plain vectors: a mutation pass over every valid signature (flip one bit of the hash,
 * r, s or the public key -> never BRISK_OK), aliasing (out == priv, out inside the peer buffer,
 * and both), input immutability, fail-closed output wiping, and the identities the mod-n core must
 * satisfy with no vectors at all (inv(a)*a == 1, inv(0) == 0, add(a, n-a) == 0).
 *
 * The `deep` flag on a row also runs it at buffer offsets 1..3 with 0xA5 canaries. Running all
 * 462 ECDH and 344 verify rows four times over would blow the 900 s qemu-armv5 budget, so `deep`
 * marks the interesting ones: the RFC, CAVP SigVer and generated rows, plus every Wycheproof row
 * whose expected result is not "valid" (tools/kat.py sets deep = result != "valid" there, so the
 * 204 EdgeCaseDoubling rows and the other valid edge cases run at offset 0 only). The 45 CAVP
 * SigGen rows are deep = 0 for the same budget reason - they are there to pin keygen(d) and the
 * published (R, S), not to repeat the mutation pass.
 *
 * Every entry point here is one-shot over fixed-size buffers - there is no streaming API - so the
 * c-code rule's "split input" case does not apply; nothing is missing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct p256_param {
    const char *name, *hex;
};
struct p256_keygen_kat {
    const char *priv, *pub;
    int ok; /* 1 = BRISK_OK, 0 = BRISK_E_ARG: d outside [1, n-1] */
};
struct p256_ecdh_kat {
    const char *priv, *peer, *z;
    int ok;   /* 1 = BRISK_OK, 0 = BRISK_E_ARG: bad point or bad d */
    int deep; /* also run at offsets 1..3 with canaries */
};
struct p256_verify_kat {
    const char *pub, *hash, *sig;
    int expect; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG */
    int deep;
};
struct p256_scalar_kat {
    int op; /* 0 = reduce(a), 1 = add(a,b), 2 = mul(a,b), 3 = inv(a) */
    const char *a, *b, *r;
};
struct p256_sign_kat {
    const char *priv, *hash, *extra, *sig;
    int ok; /* 1 = BRISK_OK and sig is exact; 0 = BRISK_E_ARG with sig untouched */
};

#include "kat/p256_ecdh.inc"
#include "kat/p256_keygen.inc"
#include "kat/p256_params.inc"
#include "kat/p256_scalar.inc"
#include "kat/p256_verify.inc"
#if BRISK_ENABLE_MTLS
#    include "kat/p256_sign.inc"
#endif

#define N(a) (sizeof(a) / sizeof((a)[0]))

/* The row counts named in the header comment above, pinned so regenerating the vectors cannot
 * leave that prose (and the qemu-armv5 budget argument built on it) quietly stale. Same idiom as
 * test_aes.c:53. Update both places together. */
typedef char p256_ecdh_row_count[N(P256_ECDH_KAT) == 462 ? 1 : -1];
typedef char p256_verify_row_count[N(P256_VERIFY_KAT) == 344 ? 1 : -1];
#if BRISK_ENABLE_MTLS
typedef char p256_sign_row_count[N(P256_SIGN_KAT) == 57 ? 1 : -1];
#endif

#define SL     BRISK__P256_SCALAR_LEN /* 32 */
#define PL     BRISK__P256_POINT_LEN  /* 65 */
#define GL     BRISK__P256_SIG_LEN    /* 64 */
#define CANARY 16

/* expect codes, matching tools/kat.py */
#define E_OK   0
#define E_AUTH 1
#define E_ARG  2

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

/* the RFC 5903 3.1 parameters, as bytes, for the pinning checks */
static const char *param(const char *name)
{
    size_t i;
    for (i = 0; i < N(P256_PARAM); i++) {
        if (strcmp(P256_PARAM[i].name, name) == 0) {
            return P256_PARAM[i].hex;
        }
    }
    CHECK(0); /* tools/kat.py emits all five */
    return NULL;
}

/* ------------------------------------------------------------------ scalar arithmetic mod n */
static void test_scalar(void)
{
    uint8_t a[SL], b[SL], want[SL], got[SL], t[SL];
    size_t i;
    for (i = 0; i < N(P256_SCALAR_KAT); i++) {
        const struct p256_scalar_kat *v = &P256_SCALAR_KAT[i];
        CHECKI(t_unhex(v->a, a, SL) == SL, i);
        CHECKI(t_unhex(v->b, b, SL) == SL, i);
        CHECKI(t_unhex(v->r, want, SL) == SL, i);
        memset(got, 0, SL);
        switch (v->op) {
        case 0:
            brisk__p256_scalar_reduce(got, a);
            break;
        case 1:
            brisk__p256_scalar_add(got, a, b);
            break;
        case 2:
            brisk__p256_scalar_mul(got, a, b);
            break;
        default:
            brisk__p256_scalar_inv(got, a);
            break;
        }
        CHECKI(memcmp(got, want, SL) == 0, i);

        /* inv(a) * a == 1 mod n for every nonzero row; inv(0) == 0. No vector needed. */
        if (v->op == 3) {
            if (all_zero(want, SL)) {
                CHECKI(all_zero(got, SL), i);
            } else {
                static const uint8_t one[SL] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                brisk__p256_scalar_mul(t, got, a);
                CHECKI(memcmp(t, one, SL) == 0, i);
            }
        }
        /* add(a, b) built from reduced operands must match add on the raw ones. */
        if (v->op == 1) {
            uint8_t ra[SL], rb[SL];
            brisk__p256_scalar_reduce(ra, a);
            brisk__p256_scalar_reduce(rb, b);
            brisk__p256_scalar_add(t, ra, rb);
            CHECKI(memcmp(t, want, SL) == 0, i);
        }
        /* aliasing: r == a == b must give the same answer as distinct buffers. */
        memcpy(t, a, SL);
        switch (v->op) {
        case 0:
            brisk__p256_scalar_reduce(t, t);
            break;
        case 1:
            brisk__p256_scalar_add(t, t, b);
            break;
        case 2:
            brisk__p256_scalar_mul(t, t, b);
            break;
        default:
            brisk__p256_scalar_inv(t, t);
            break;
        }
        CHECKI(memcmp(t, got, SL) == 0, i);
    }

    /* Boundary behaviour of scalar_valid and reduce, which is exactly what pins n. */
    {
        uint8_t n_[SL], nm1[SL], np1[SL], zero[SL], one[SL], max[SL];
        size_t j;
        CHECK(t_unhex(param("n"), n_, SL) == SL);
        memset(zero, 0, SL);
        memset(one, 0, SL);
        one[SL - 1] = 1;
        memset(max, 0xFF, SL);
        memcpy(nm1, n_, SL);
        nm1[SL - 1] = (uint8_t)(nm1[SL - 1] - 1); /* n ends in 0x51, no borrow */
        memcpy(np1, n_, SL);
        np1[SL - 1] = (uint8_t)(np1[SL - 1] + 1);

        CHECK(brisk__p256_scalar_valid(zero) == 0);
        CHECK(brisk__p256_scalar_valid(one) == 1);
        CHECK(brisk__p256_scalar_valid(nm1) == 1);
        CHECK(brisk__p256_scalar_valid(n_) == 0);
        CHECK(brisk__p256_scalar_valid(np1) == 0);
        CHECK(brisk__p256_scalar_valid(max) == 0);

        brisk__p256_scalar_reduce(got, n_);
        CHECK(all_zero(got, SL));
        brisk__p256_scalar_reduce(got, np1);
        CHECK(memcmp(got, one, SL) == 0);
        brisk__p256_scalar_reduce(got, nm1);
        CHECK(memcmp(got, nm1, SL) == 0);

        /* add(a, n-a) == 0 for a handful of a, with no vector. */
        for (j = 1; j < 8; j++) {
            uint8_t na[SL];
            memset(a, 0, SL);
            a[SL - 1] = (uint8_t)j;
            memcpy(na, n_, SL);
            na[SL - 1] = (uint8_t)(na[SL - 1] - (uint8_t)j);
            brisk__p256_scalar_add(got, a, na);
            CHECK(all_zero(got, SL));
        }
        brisk__p256_scalar_inv(got, zero);
        CHECK(all_zero(got, SL));
    }
}

/* --------------------------------------------------------------------------------- keygen */
static void test_keygen(void)
{
    uint8_t priv[SL], want[PL], pub[PL];
    size_t i;
    for (i = 0; i < N(P256_KEYGEN_KAT); i++) {
        const struct p256_keygen_kat *v = &P256_KEYGEN_KAT[i];
        int rc;
        CHECKI(t_unhex(v->priv, priv, SL) == SL, i);
        memset(pub, 0xA5, PL);
        rc = brisk__p256_keygen(pub, priv);
        CHECKI(rc == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        if (v->ok) {
            CHECKI(t_unhex(v->pub, want, PL) == PL, i);
            CHECKI(memcmp(pub, want, PL) == 0, i);
            CHECKI(pub[0] == 0x04, i);
        } else {
            CHECKI(canary_ok(pub, PL), i); /* pub untouched on a rejected private key */
        }
        CHECKI(brisk__p256_scalar_valid(priv) == v->ok, i);
    }
    /* priv = 1 must be exactly G: this is what pins Gx and Gy. */
    {
        uint8_t one[SL], g[PL];
        memset(one, 0, SL);
        one[SL - 1] = 1;
        CHECK(brisk__p256_keygen(pub, one) == BRISK_OK);
        g[0] = 0x04;
        CHECK(t_unhex(param("gx"), g + 1, SL) == SL);
        CHECK(t_unhex(param("gy"), g + 1 + SL, SL) == SL);
        CHECK(memcmp(pub, g, PL) == 0);
    }
}

/* ----------------------------------------------------------------------------------- ECDH */
static void ecdh_one(const uint8_t *priv, const uint8_t *peer, const uint8_t *want, int ok,
                     size_t off, long idx)
{
    uint8_t ps[SL + 4], qs[PL + 4], os[SL + 4 + CANARY];
    int rc;
    memcpy(ps + off, priv, SL);
    memcpy(qs + off, peer, PL);
    memset(os + off, 0, SL);
    memset(os + off + SL, 0xA5, CANARY);
    rc = brisk__p256_ecdh(os + off, ps + off, qs + off);
    CHECKI(rc == (ok ? BRISK_OK : BRISK_E_ARG), idx);
    CHECKI(canary_ok(os + off + SL, CANARY), idx);
    CHECKI(memcmp(ps + off, priv, SL) == 0, idx); /* inputs are never modified */
    CHECKI(memcmp(qs + off, peer, PL) == 0, idx);
    if (ok) {
        CHECKI(memcmp(os + off, want, SL) == 0, idx);
    } else {
        CHECKI(all_zero(os + off, SL), idx); /* fail closed: no half-computed secret */
    }
}

static void test_ecdh(void)
{
    uint8_t priv[SL], peer[PL], want[SL], o[SL], o2[SL], buf[PL];
    size_t i, off;
    for (i = 0; i < N(P256_ECDH_KAT); i++) {
        const struct p256_ecdh_kat *v = &P256_ECDH_KAT[i];
        CHECKI(t_unhex(v->priv, priv, SL) == SL, i);
        CHECKI(t_unhex(v->peer, peer, PL) == PL, i);
        memset(want, 0, SL);
        if (v->ok) {
            CHECKI(t_unhex(v->z, want, SL) == SL, i);
        }
        ecdh_one(priv, peer, want, v->ok, 0, (long)i);
        if (!v->deep) {
            continue;
        }
        for (off = 1; off < 4; off++) {
            ecdh_one(priv, peer, want, v->ok, off, (long)i);
        }
        /* Aliasing: out == priv, out inside the peer buffer, and both. */
        memcpy(o, priv, SL);
        CHECKI(brisk__p256_ecdh(o, o, peer) == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        CHECKI(memcmp(o, want, SL) == 0, i);
        memcpy(buf, peer, PL);
        CHECKI(brisk__p256_ecdh(buf + 1, priv, buf) == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        CHECKI(memcmp(buf + 1, want, SL) == 0, i);
        memcpy(o2, priv, SL);
        memcpy(buf, peer, PL);
        CHECKI(brisk__p256_ecdh(o2, o2, buf) == (v->ok ? BRISK_OK : BRISK_E_ARG), i);
        CHECKI(memcmp(o2, want, SL) == 0, i);
    }
    /* Every non-uncompressed first byte is rejected, never decompressed (RFC 9846 4.3.8.2). */
    {
        unsigned b;
        CHECK(t_unhex(P256_KEYGEN_KAT[0].priv, priv, SL) == SL);
        CHECK(t_unhex(P256_KEYGEN_KAT[0].pub, peer, PL) == PL);
        CHECK(brisk__p256_ecdh(o, priv, peer) == BRISK_OK);
        for (b = 0; b < 256; b++) {
            if (b == 0x04) {
                continue;
            }
            memcpy(buf, peer, PL);
            buf[0] = (uint8_t)b;
            CHECKI(brisk__p256_ecdh(o, priv, buf) == BRISK_E_ARG, b);
            CHECKI(all_zero(o, SL), b);
        }
    }
    /* x == p and y == p are out of range; x == p-1 is in range and fails the curve equation
     * instead. Both must be BRISK_E_ARG, but for different reasons - this is what pins p. */
    {
        uint8_t pbytes[SL];
        CHECK(t_unhex(param("p"), pbytes, SL) == SL);
        memcpy(buf, peer, PL);
        memcpy(buf + 1, pbytes, SL);
        CHECK(brisk__p256_ecdh(o, priv, buf) == BRISK_E_ARG);
        memcpy(buf, peer, PL);
        memcpy(buf + 1 + SL, pbytes, SL);
        CHECK(brisk__p256_ecdh(o, priv, buf) == BRISK_E_ARG);
        memcpy(buf, peer, PL);
        memcpy(buf + 1, pbytes, SL);
        buf[SL] = (uint8_t)(buf[SL] - 1); /* x = p-1, p ends in 0xFF */
        CHECK(brisk__p256_ecdh(o, priv, buf) == BRISK_E_ARG);
    }
}

/* ---------------------------------------------------------------------------- ECDSA verify */
static void verify_one(const uint8_t *pub, const uint8_t *h, size_t hlen, const uint8_t *sig,
                       int expect, size_t off, long idx)
{
    uint8_t qs[PL + 4], hs[64 + 4], ss[GL + 4];
    memcpy(qs + off, pub, PL);
    memcpy(hs + off, h, hlen);
    memcpy(ss + off, sig, GL);
    CHECKI(rc_code(brisk__p256_ecdsa_verify(qs + off, hs + off, hlen, ss + off)) == expect, idx);
    CHECKI(memcmp(qs + off, pub, PL) == 0, idx); /* inputs are never modified */
    CHECKI(memcmp(hs + off, h, hlen) == 0, idx);
    CHECKI(memcmp(ss + off, sig, GL) == 0, idx);
}

static void test_verify(void)
{
    uint8_t pub[PL], h[64], sig[GL], t[PL];
    size_t i, off, hlen;
    for (i = 0; i < N(P256_VERIFY_KAT); i++) {
        const struct p256_verify_kat *v = &P256_VERIFY_KAT[i];
        CHECKI(t_unhex(v->pub, pub, PL) == PL, i);
        hlen = t_unhex(v->hash, h, sizeof h);
        CHECKI(t_unhex(v->sig, sig, GL) == GL, i);
        CHECKI(rc_code(brisk__p256_ecdsa_verify(pub, h, hlen, sig)) == v->expect, i);
        if (!v->deep) {
            continue;
        }
        for (off = 1; off < 4; off++) {
            verify_one(pub, h, hlen, sig, v->expect, off, (long)i);
        }
        if (v->expect != E_OK) {
            continue;
        }
        /* Mutation pass: one flipped bit anywhere must stop it verifying. */
        {
            size_t k;
            for (k = 0; k < 8; k++) {
                /* Only the leftmost 32 bytes feed e (FIPS 186-5 6.4.2), so the mutation stays
                 * inside them; bytes past that are asserted to be ignored just below. */
                size_t bit = (k * 37) % (32 * 8);
                h[bit / 8] = (uint8_t)(h[bit / 8] ^ (1u << (bit % 8)));
                CHECKI(brisk__p256_ecdsa_verify(pub, h, hlen, sig) != BRISK_OK, i);
                h[bit / 8] = (uint8_t)(h[bit / 8] ^ (1u << (bit % 8)));

                bit = (k * 53) % (GL * 8);
                sig[bit / 8] = (uint8_t)(sig[bit / 8] ^ (1u << (bit % 8)));
                CHECKI(brisk__p256_ecdsa_verify(pub, h, hlen, sig) != BRISK_OK, i);
                sig[bit / 8] = (uint8_t)(sig[bit / 8] ^ (1u << (bit % 8)));

                bit = (k * 41) % (64 * 8);
                memcpy(t, pub, PL);
                t[1 + bit / 8] = (uint8_t)(t[1 + bit / 8] ^ (1u << (bit % 8)));
                CHECKI(brisk__p256_ecdsa_verify(t, h, hlen, sig) != BRISK_OK, i);
            }
        }
        /* The other half of the leftmost-bits rule: a byte past the 32nd must not matter. The
         * RFC 6979 A.2.5 SHA-384 and SHA-512 rows are the official vectors that reach here. */
        if (hlen > 32) {
            size_t j;
            for (j = 32; j < hlen; j++) {
                h[j] = (uint8_t)(h[j] ^ 0xFF);
            }
            CHECKI(brisk__p256_ecdsa_verify(pub, h, hlen, sig) == BRISK_OK, i);
            for (j = 32; j < hlen; j++) {
                h[j] = (uint8_t)(h[j] ^ 0xFF);
            }
        }
        /* A hash shorter than 32 bytes is BRISK_E_ARG, not a truncated verify. */
        CHECKI(brisk__p256_ecdsa_verify(pub, h, 31, sig) == BRISK_E_ARG, i);
        CHECKI(brisk__p256_ecdsa_verify(pub, h, 0, sig) == BRISK_E_ARG, i);
        /* A longer hash uses only its leftmost 32 bytes (FIPS 186-5 6.4.2). */
        if (hlen == 32) {
            uint8_t h2[64];
            memcpy(h2, h, 32);
            memset(h2 + 32, 0x5A, 32);
            CHECKI(brisk__p256_ecdsa_verify(pub, h2, 64, sig) == BRISK_OK, i);
            memset(h2 + 32, 0xA5, 32);
            CHECKI(brisk__p256_ecdsa_verify(pub, h2, 48, sig) == BRISK_OK, i);
        }
    }
}

#if BRISK_ENABLE_MTLS
/* ------------------------------------------------------------------------------ ECDSA sign */
/* One sign at chosen offsets, with canaries around the output. */
static void sign_one(const uint8_t *priv, const uint8_t *h, size_t hlen, const uint8_t *ex,
                     size_t exlen, const uint8_t *want, size_t os, size_t op, size_t oh, size_t oe,
                     long idx)
{
    uint8_t ss[GL + 8 + CANARY], ps[SL + 8], hs[96 + 8], es[64 + 8];
    memcpy(ps + op, priv, SL);
    memcpy(hs + oh, h, hlen);
    if (exlen) {
        memcpy(es + oe, ex, exlen);
    }
    memset(ss + os, 0, GL);
    memset(ss + os + GL, 0xA5, CANARY);
    CHECKI(brisk__p256_ecdsa_sign(ss + os, ps + op, hs + oh, hlen, exlen ? es + oe : NULL, exlen) ==
               BRISK_OK,
           idx);
    CHECKI(memcmp(ss + os, want, GL) == 0, idx);
    CHECKI(canary_ok(ss + os + GL, CANARY), idx);
    CHECKI(memcmp(ps + op, priv, SL) == 0, idx); /* inputs are never modified */
    CHECKI(memcmp(hs + oh, h, hlen) == 0, idx);
}

static void test_sign(void)
{
    uint8_t priv[SL], h[96], ex[64], want[GL], sig[GL], pub[PL], buf[128];
    size_t i, hlen, exlen;

    for (i = 0; i < N(P256_SIGN_KAT); i++) {
        const struct p256_sign_kat *v = &P256_SIGN_KAT[i];
        CHECKI(t_unhex(v->priv, priv, SL) == SL, i);
        hlen = t_unhex(v->hash, h, sizeof h);
        exlen = t_unhex(v->extra, ex, sizeof ex);
        memset(sig, 0xA5, GL);
        if (!v->ok) {
            /* Bad d, or a hash_len that is not 32/48/64: BRISK_E_ARG before any DRBG or point
             * work, with sig left untouched so the caller can retry into the same buffer. */
            CHECKI(brisk__p256_ecdsa_sign(sig, priv, h, hlen, exlen ? ex : NULL, exlen) ==
                       BRISK_E_ARG,
                   i);
            CHECKI(canary_ok(sig, GL), i);
            continue;
        }
        CHECKI(t_unhex(v->sig, want, GL) == GL, i);
        CHECKI(brisk__p256_ecdsa_sign(sig, priv, h, hlen, exlen ? ex : NULL, exlen) == BRISK_OK, i);
        CHECKI(memcmp(sig, want, GL) == 0, i);
        /* The signature must verify under the matching public key. (The module already
         * self-verifies internally; this pins that the key it used is keygen(priv).) */
        CHECKI(brisk__p256_keygen(pub, priv) == BRISK_OK, i);
        CHECKI(brisk__p256_ecdsa_verify(pub, h, hlen, sig) == BRISK_OK, i);
    }

    /* Everything below runs on one vector: each extra sign costs four scalar multiplications
     * (the sign itself, plus the keygen and two inside the fault-check verify), and the p256
     * suite has a 900 s qemu-armv5 budget. */
    CHECK(t_unhex(P256_SIGN_KAT[0].priv, priv, SL) == SL);
    hlen = t_unhex(P256_SIGN_KAT[0].hash, h, sizeof h);
    CHECK(t_unhex(P256_SIGN_KAT[0].sig, want, GL) == GL);
    CHECK(brisk__p256_keygen(pub, priv) == BRISK_OK);

    /* Unaligned: every buffer at every offset 0..7, rotated so each one sees each offset. The
     * full 8^4 cross product would be 4096 signatures and buys nothing - an alignment fault
     * depends on one pointer's low bits, not on a combination. */
    for (i = 0; i < 8; i++) {
        sign_one(priv, h, hlen, NULL, 0, want, i, (i + 1) % 8, (i + 3) % 8, (i + 5) % 8, (long)i);
    }

    /* Aliasing: sig is written only after hash and extra are consumed. */
    memcpy(buf, h, hlen);
    CHECK(brisk__p256_ecdsa_sign(buf, priv, buf, hlen, NULL, 0) == BRISK_OK);
    CHECK(memcmp(buf, want, GL) == 0);
    memcpy(buf, h, hlen); /* sig overlapping extra, and extra == hash */
    CHECK(brisk__p256_ecdsa_sign(buf + 4, priv, buf, hlen, buf, hlen) == BRISK_OK);
    {
        uint8_t ref[GL];
        CHECK(brisk__p256_ecdsa_sign(ref, priv, h, hlen, h, hlen) == BRISK_OK);
        CHECK(memcmp(buf + 4, ref, GL) == 0);
    }

    /* Hedging: k' = NULL reproduces the RFC 6979 A.2.5 row exactly - the proof that the hedged
     * code path and the deterministic one are the same path - while two different k' give two
     * different signatures, both valid. */
    {
        uint8_t e1[32], e2[32], s1[GL], s2[GL];
        memset(e1, 0x01, sizeof e1);
        memset(e2, 0x02, sizeof e2);
        CHECK(brisk__p256_ecdsa_sign(s1, priv, h, hlen, e1, sizeof e1) == BRISK_OK);
        CHECK(brisk__p256_ecdsa_sign(s2, priv, h, hlen, e2, sizeof e2) == BRISK_OK);
        CHECK(memcmp(s1, s2, GL) != 0);
        CHECK(memcmp(s1, want, GL) != 0);
        CHECK(brisk__p256_ecdsa_verify(pub, h, hlen, s1) == BRISK_OK);
        CHECK(brisk__p256_ecdsa_verify(pub, h, hlen, s2) == BRISK_OK);
        /* Same k' twice is the same signature: the variant is still deterministic. */
        CHECK(brisk__p256_ecdsa_sign(s2, priv, h, hlen, e1, sizeof e1) == BRISK_OK);
        CHECK(memcmp(s1, s2, GL) == 0);
        /* extra_len 0 with a non-NULL pointer is the same as NULL. */
        CHECK(brisk__p256_ecdsa_sign(s2, priv, h, hlen, e1, 0) == BRISK_OK);
        CHECK(memcmp(s2, want, GL) == 0);
    }

    /* Negative: one flipped bit anywhere must stop it verifying, and a signature made with d
     * does not verify under a different key. */
    {
        uint8_t t[GL], h2[96], pub2[PL], priv2[SL];
        size_t k;
        for (k = 0; k < 8; k++) {
            size_t bit = (k * 53) % (GL * 8);
            memcpy(t, want, GL);
            t[bit / 8] = (uint8_t)(t[bit / 8] ^ (1u << (bit % 8)));
            CHECKI(brisk__p256_ecdsa_verify(pub, h, hlen, t) != BRISK_OK, (long)k);
            bit = (k * 37) % (32 * 8); /* only the leftmost 32 bytes feed e */
            memcpy(h2, h, hlen);
            h2[bit / 8] = (uint8_t)(h2[bit / 8] ^ (1u << (bit % 8)));
            CHECKI(brisk__p256_ecdsa_verify(pub, h2, hlen, want) != BRISK_OK, (long)k);
        }
        memcpy(priv2, priv, SL);
        priv2[SL - 1] = (uint8_t)(priv2[SL - 1] ^ 0x01);
        CHECK(brisk__p256_keygen(pub2, priv2) == BRISK_OK);
        CHECK(brisk__p256_ecdsa_verify(pub2, h, hlen, want) == BRISK_E_AUTH);
    }

    /* hash_len is checked before anything reads `hash`, so a poisoned pointer must survive. The
     * generated rows cover 31/33/47/49/63/65; these are the ones no vector can express. */
    {
        static const size_t bad[] = {0, 1, 2, 16, 96, (size_t)-1};
        for (i = 0; i < N(bad); i++) {
            memset(sig, 0xA5, GL);
            CHECKI(brisk__p256_ecdsa_sign(sig, priv, NULL, bad[i], NULL, 0) == BRISK_E_ARG, i);
            CHECKI(canary_ok(sig, GL), i);
        }
    }
}
/* The brisk_sign_fn hook (include/brisk.h). It has no caller until the M3 handshake, so what can
 * be tested today is the contract itself, and that is worth pinning before an integrator builds
 * against it: `tbs` is the raw to-be-signed bytes and NOT a digest, the output is the RAW r || s
 * and not DER, a scheme other than ecdsa_secp256r1_sha256 is BRISK_E_ARG, and a buffer smaller
 * than the signature is a refusal rather than a truncation. The callback below is exactly what a
 * software signer looks like; a secure-element one passes its PKCS#11 output straight through. */
#    define SCHEME_ECDSA_P256_SHA256 0x0403

static int demo_sign(void *ctx, uint16_t scheme, const uint8_t *tbs, size_t tbs_len, uint8_t *sig,
                     size_t sig_cap, size_t *sig_len)
{
    uint8_t digest[BRISK_SHA256_LEN];
    int rc;
    if (scheme != SCHEME_ECDSA_P256_SHA256 || sig_cap < BRISK_SIG_ECDSA_P256_LEN) {
        return BRISK_E_ARG; /* never truncate: a short buffer is a caller bug */
    }
    brisk_sha256(tbs, tbs_len, digest);
    rc = brisk__p256_ecdsa_sign(sig, (const uint8_t *)ctx, digest, sizeof digest, NULL, 0);
    if (rc == BRISK_OK) {
        *sig_len = BRISK_SIG_ECDSA_P256_LEN;
    }
    brisk__secure_zero(digest, sizeof digest);
    return rc;
}

static void test_sign_hook(void)
{
    brisk_sign_fn fn = demo_sign;
    uint8_t priv[SL], pub[PL], sig[GL + 1], digest[BRISK_SHA256_LEN];
    static const uint8_t tbs[] = "TLS 1.3, server CertificateVerify";
    size_t sig_len = 0;

    CHECK(t_unhex(P256_SIGN_KAT[0].priv, priv, SL) == SL);
    CHECK(brisk__p256_keygen(pub, priv) == BRISK_OK);
    memset(sig, 0xA5, sizeof sig);
    CHECK(fn(priv, SCHEME_ECDSA_P256_SHA256, tbs, sizeof tbs - 1, sig, GL, &sig_len) == BRISK_OK);
    CHECK(sig_len == BRISK_SIG_ECDSA_P256_LEN);
    CHECK(sig[GL] == 0xA5); /* wrote exactly sig_len bytes */
    /* Raw r || s, over the digest of the RAW tbs bytes - not DER, and tbs is not pre-hashed. */
    brisk_sha256(tbs, sizeof tbs - 1, digest);
    CHECK(brisk__p256_ecdsa_verify(pub, digest, sizeof digest, sig) == BRISK_OK);

    memset(sig, 0xA5, sizeof sig);
    CHECK(fn(priv, 0x0804, tbs, sizeof tbs - 1, sig, GL, &sig_len) == BRISK_E_ARG); /* rsa_pss */
    CHECK(fn(priv, SCHEME_ECDSA_P256_SHA256, tbs, sizeof tbs - 1, sig, GL - 1, &sig_len) ==
          BRISK_E_ARG);
    CHECK(canary_ok(sig, GL)); /* refused, not truncated */
}
#endif /* BRISK_ENABLE_MTLS */

void test_p256(void)
{
    test_scalar();
    test_keygen();
    test_ecdh();
    test_verify();
#if BRISK_ENABLE_MTLS
    test_sign();
    test_sign_hook();
#endif
}
