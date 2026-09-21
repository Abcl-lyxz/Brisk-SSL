/* test_rsa.c - the i31 bignum kernel and both RSASSA verifiers.
 *
 * Vectors (tests/kat/SOURCES.md has the full provenance and the exclusions):
 *   NIST CAVP 186-2 SigVer15_186-3.rsp and SigVerPSS_186-3.rsp - mod 2048, 3072 and 4096 with
 *     SHA-256/384/512. The 186-2 archive is the ONLY official source in existence with 4096-bit
 *     rows; its PSS salt length is 10 for every row, which is precisely why salt_len has to be
 *     an API parameter rather than hLen.
 *   NIST CAVP 186-3 - mod 2048 and 3072, and PSS salt lengths 0, 24, 32, 48 and 64, including
 *     sLen = 0 which no other source covers. Its e values include 3, 17 and random 24-bit
 *     exponents, which is what drives the public-exponent bit loop past 65537, and its e field is
 *     zero-padded to the modulus width, which is what proves leading zeros are accepted.
 *   Wycheproof rsa_signature_{2048,3072,4096}_{sha256,sha384,sha512} - all nine in-scope suites,
 *     every row. This is the strict-DER net RFC 8017 9.2 note 2 asks for: InvalidAsnInPadding
 *     1065, ModifiedPadding 675, WrongHash 183, BerEncodedPadding 126, InvalidPadding 45,
 *     SignatureMalleability 27, NoHash 18, MissingNull 9, ShortPadding 9, SmallPublicKey 5,
 *     SmallSignature 4, EdgeCaseSignature 1, counted over all nine.
 *   Wycheproof rsa_pss_* - eight in-scope suites plus rsa_pss_misc: SpecialCaseHash 634,
 *     ModifiedSignature 363, WrongPrimitive 45, sLen = 0 and sLen != hLen included.
 *   Generated EM-corruption rows, one per structural rule of 9.2 and 9.1.2, built by signing a
 *     deliberately malformed EM with a private key CAVP publishes (p and q are in the file). No
 *     public suite isolates the rules one at a time; Wycheproof's padding rows are a net, not a
 *     map, so without these a regression says "something in the padding" instead of which rule.
 *   Generated PSS rows on a 2049- and a 3073-bit modulus. emLen = ceil((modBits - 1)/8) is k - 1
 *     only when modBits % 8 == 1, and every published vector on earth uses 1024/2048/3072/4096,
 *     so that branch of RFC 8017 8.1.2 step 2c would otherwise ship untested.
 *   tests/kat/bn.inc - a seeded differential set against Python's arbitrary-precision int, at the
 *     i31 limb boundaries (31k - 1, 31k, 31k + 1). NO official vector source exists for a bare
 *     big-integer library; that gap is named in SOURCES.md rather than papered over, and what
 *     stands under it is this set plus the 4077 RSA rows end to end.
 *
 * Beyond the plain vectors: every rule of RFC 8017 8.2.2 / 9.2 / 9.1.2 exercised at buffer
 * offsets 1..3 with 0xA5 canaries (the `deep` flag), input immutability on every row, a bit-flip
 * mutation pass over sig / hash / n / e, the key-material and signature-length rejections that no
 * vector can express, and the bignum identities that need no vectors at all.
 *
 * `deep` = every CAVP row, every generated row, and every Wycheproof row that is not `valid` at
 * 2048 bits. Not the 3072- and 4096-bit invalid rows: the offset pass is about pointer alignment,
 * which is width-independent, and running those four times over costs the 900 s qemu-armv5 budget
 * for coverage the 2048-bit rows already give.
 *
 * SPLIT INPUT does not apply and this says so rather than leaving a hole: every entry point here
 * is one-shot over caller-supplied buffers, there is no streaming API, and the streaming case
 * that does exist - the digest - is covered by tests/test_hash.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct rsa_key {
    const char *n, *e;
};
struct rsa_kat {
    int key;      /* index into RSA_KEY */
    int bits;     /* digest: 256, 384 or 512 */
    int salt_len; /* PSS salt length, or -1 for PKCS#1 v1.5 */
    const char *hash, *sig;
    int expect; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG */
    int deep;   /* also run at offsets 1..3 with canaries */
};
struct bn_mod {
    const char *hex;
};
struct bn_kat {
    int op;  /* 0 encode, 1 add, 2 sub, 3 mont_mul, 4 modpow */
    int mod; /* index into BN_MOD */
    const char *a, *b, *r;
    int k; /* carry / borrow */
};

#include "kat/bn.inc"
#include "kat/bn_mod.inc"
#include "kat/rsa_key.inc"
#include "kat/rsa_pkcs1.inc"
#include "kat/rsa_pss.inc"

#define N(a) (sizeof(a) / sizeof((a)[0]))
/* Buffer widths are sized by the VECTORS, not by BRISK_RSA_MAX_BITS: a build with the knob at
 * 2048 must still run this suite, and it does so by expecting BRISK_E_ARG on the wider rows (see
 * be_bits below) rather than by skipping them. The +16 of slack is real, not padding: Wycheproof
 * prints a DER INTEGER's leading 0x00 inside the modulus field, and CAVP zero-pads e to the
 * modulus width, so a buffer of exactly k octets is short of what the files actually carry. */
#define KAT_MAX_BITS 4096
#define MAXOCT       (KAT_MAX_BITS / 8 + 16)
/* Widest add/sub result: those are limb-level, so the value spans 31 * limbs bits, not modBits. */
#define MAXFULL (31 * (KAT_MAX_BITS / 31 + 2) / 8 + 1)
#define PAD     8

enum { BN_ENCODE = 0, BN_ADD, BN_SUB, BN_MONTMUL, BN_MODPOW };

static brisk_hash_alg alg_of(int bits)
{
    return bits == 256 ? BRISK_HASH_SHA256 : bits == 384 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA512;
}

static int code_of(int expect)
{
    return expect == 0 ? BRISK_OK : expect == 1 ? BRISK_E_AUTH : BRISK_E_ARG;
}

/* True bit length of a big-endian octet string, so a row whose modulus is wider than this build
 * accepts can be re-expected as BRISK_E_ARG instead of being silently skipped. */
static size_t be_bits(const uint8_t *p, size_t len)
{
    size_t i = 0;
    unsigned t;
    size_t n = 0;
    while (i < len && p[i] == 0) {
        i++;
    }
    if (i == len) {
        return 0;
    }
    for (t = p[i]; t; t >>= 1) {
        n++;
    }
    return (len - i - 1) * 8 + n;
}

static int canary_ok(const uint8_t *buf, size_t off, size_t len, size_t cap)
{
    size_t i;
    for (i = 0; i < cap; i++) {
        if ((i < off || i >= off + len) && buf[i] != 0xA5) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ RSA vector driver */
struct row_bufs {
    uint8_t n[MAXOCT], e[MAXOCT], h[BRISK_SHA512_LEN], s[MAXOCT];
    size_t nl, el, hl, sl;
};

static int rsa_call(const struct rsa_kat *v, const uint8_t *n, size_t nl, const uint8_t *e,
                    size_t el, const uint8_t *h, size_t hl, const uint8_t *s, size_t sl)
{
    if (v->salt_len < 0) {
        return brisk__rsa_pkcs1_verify(n, nl, e, el, alg_of(v->bits), h, hl, s, sl);
    }
    return brisk__rsa_pss_verify(n, nl, e, el, alg_of(v->bits), (size_t)v->salt_len, h, hl, s, sl);
}

/* One row at one offset, in canaried buffers, with every input checked for immutability. */
static void rsa_at_offset(const struct rsa_kat *v, const struct row_bufs *b, int want, size_t off,
                          long idx)
{
    uint8_t nb[MAXOCT + PAD], eb[MAXOCT + PAD], hb[BRISK_SHA512_LEN + PAD], sb[MAXOCT + PAD];
    int rc;
    memset(nb, 0xA5, sizeof nb);
    memset(eb, 0xA5, sizeof eb);
    memset(hb, 0xA5, sizeof hb);
    memset(sb, 0xA5, sizeof sb);
    memcpy(nb + off, b->n, b->nl);
    memcpy(eb + off, b->e, b->el);
    memcpy(hb + off, b->h, b->hl);
    memcpy(sb + off, b->s, b->sl);
    rc = rsa_call(v, nb + off, b->nl, eb + off, b->el, hb + off, b->hl, sb + off, b->sl);
    CHECKI(rc == want, idx);
    /* Nothing the caller owns may move, and nothing outside the operands may be touched. */
    CHECKI(memcmp(nb + off, b->n, b->nl) == 0, idx);
    CHECKI(memcmp(eb + off, b->e, b->el) == 0, idx);
    CHECKI(memcmp(hb + off, b->h, b->hl) == 0, idx);
    CHECKI(memcmp(sb + off, b->s, b->sl) == 0, idx);
    CHECKI(canary_ok(nb, off, b->nl, sizeof nb), idx);
    CHECKI(canary_ok(eb, off, b->el, sizeof eb), idx);
    CHECKI(canary_ok(hb, off, b->hl, sizeof hb), idx);
    CHECKI(canary_ok(sb, off, b->sl, sizeof sb), idx);
}

static void rsa_vectors(const struct rsa_kat *tab, size_t n, const char *what)
{
    struct row_bufs b;
    size_t i, off;
    (void)what;
    for (i = 0; i < n; i++) {
        const struct rsa_kat *v = &tab[i];
        int want;
        b.nl = t_unhex(RSA_KEY[v->key].n, b.n, sizeof b.n);
        b.el = t_unhex(RSA_KEY[v->key].e, b.e, sizeof b.e);
        b.hl = t_unhex(v->hash, b.h, sizeof b.h);
        b.sl = t_unhex(v->sig, b.s, sizeof b.s);
        want = code_of(v->expect);
        /* A build with a lower BRISK_RSA_MAX_BITS must still run this suite: a modulus it does
         * not accept is malformed key material, not a failed signature. */
        if (be_bits(b.n, b.nl) > BRISK__RSA_MAX_BITS) {
            want = BRISK_E_ARG;
        }
        rsa_at_offset(v, &b, want, 0, (long)i);
        if (v->deep) {
            for (off = 1; off < 4; off++) {
                rsa_at_offset(v, &b, want, off, (long)i);
            }
            /* Bit-flip mutation: one flipped bit anywhere in the signature, the digest, the
             * modulus or the exponent must never leave the row verifying. Restricted to the deep
             * rows because every flip is another modular exponentiation and the whole suite has
             * a 900 s budget on qemu-armv5; the deep set is every CAVP and generated row. */
            if (want == BRISK_OK) {
                uint8_t save;
                size_t p;
                struct row_bufs m = b;
                static const size_t bit[4] = {3, 11, 37, 5};
                p = b.sl - 1;
                save = m.s[p];
                m.s[p] ^= (uint8_t)(1u << bit[0]);
                CHECKI(rsa_call(v, m.n, m.nl, m.e, m.el, m.h, m.hl, m.s, m.sl) != BRISK_OK,
                       (long)i);
                m.s[p] = save;
                m.h[b.hl - 1] ^= (uint8_t)(1u << (bit[1] & 7));
                CHECKI(rsa_call(v, m.n, m.nl, m.e, m.el, m.h, m.hl, m.s, m.sl) != BRISK_OK,
                       (long)i);
                m.h[b.hl - 1] = b.h[b.hl - 1];
                m.n[b.nl - 1] ^= 0x02; /* keep n odd, so this stays a signature failure */
                CHECKI(rsa_call(v, m.n, m.nl, m.e, m.el, m.h, m.hl, m.s, m.sl) != BRISK_OK,
                       (long)i);
                m.n[b.nl - 1] = b.n[b.nl - 1];
                m.e[b.el - 1] ^= 0x02; /* NIST failure reason 2: public key e changed */
                CHECKI(rsa_call(v, m.n, m.nl, m.e, m.el, m.h, m.hl, m.s, m.sl) != BRISK_OK,
                       (long)i);
            }
        }
    }
}

/* ------------------------------------------------------------------ key / signature rejections */
/* The cases no vector can express: they are about lengths and shapes, not about arithmetic. */
static void test_rsa_invalid(void)
{
    struct row_bufs b;
    const struct rsa_kat *good = NULL;
    uint8_t buf[MAXOCT + 16];
    size_t i;

    for (i = 0; i < N(RSA_PKCS1_KAT); i++) {
        if (RSA_PKCS1_KAT[i].expect == 0) {
            good = &RSA_PKCS1_KAT[i];
            break;
        }
    }
    CHECK(good != NULL);
    if (good == NULL) {
        return;
    }
    b.nl = t_unhex(RSA_KEY[good->key].n, b.n, sizeof b.n);
    b.el = t_unhex(RSA_KEY[good->key].e, b.e, sizeof b.e);
    b.hl = t_unhex(good->hash, b.h, sizeof b.h);
    b.sl = t_unhex(good->sig, b.s, sizeof b.s);
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, b.s, b.sl) == BRISK_OK);

    /* n with 1..8 leading zero octets is the SAME key (RFC 8017 4.2) and must still verify.
     * This is the parser trap - a decoder that rejects them breaks on real DER INTEGERs. */
    for (i = 1; i <= 8; i++) {
        memset(buf, 0, i);
        memcpy(buf + i, b.n, b.nl);
        CHECKI(rsa_call(good, buf, b.nl + i, b.e, b.el, b.h, b.hl, b.s, b.sl) == BRISK_OK, i);
    }
    /* ... and so is e zero-padded to the modulus width, which is exactly what CAVP emits. */
    memset(buf, 0, 128);
    memcpy(buf + 128, b.e, b.el);
    CHECK(rsa_call(good, b.n, b.nl, buf, b.el + 128, b.h, b.hl, b.s, b.sl) == BRISK_OK);

    /* Modulus width: one bit below the floor and one bit above the ceiling. Built explicitly
     * rather than by poking the row's own n, so the check cannot quietly stop meaning anything
     * if the first valid row ever changes key. Both are BRISK_E_ARG - bad_certificate. */
    memset(buf, 0xFF, sizeof buf);
    buf[0] = 0x7F; /* 2047 bits: below BRISK__RSA_MIN_BITS */
    CHECK(rsa_call(good, buf, BRISK__RSA_MIN_BITS / 8, b.e, b.el, b.h, b.hl, b.s, b.sl) ==
          BRISK_E_ARG);
    buf[0] = 0x01; /* BRISK_RSA_MAX_BITS + 1 bits: above the ceiling */
    CHECK(rsa_call(good, buf, BRISK__RSA_MAX_BITS / 8 + 1, b.e, b.el, b.h, b.hl, b.s, b.sl) ==
          BRISK_E_ARG);
    /* Zero, empty and even are refused whatever the width. */
    memcpy(buf, b.n, b.nl);
    buf[b.nl - 1] = (uint8_t)(buf[b.nl - 1] & 0xFE); /* even n: no Montgomery inverse */
    CHECK(rsa_call(good, buf, b.nl, b.e, b.el, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
    memset(buf, 0, b.nl);
    CHECK(rsa_call(good, buf, b.nl, b.e, b.el, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
    CHECK(rsa_call(good, b.n, 0, b.e, b.el, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);

    /* Public exponent: 0, 1, 2 and even are refused on their own rules; e == n, e == n + 1 and
     * e wider than n are all >= 2048 bits, so they exit at the 32-octet cap below rather than at
     * the e < n test - which is unreachable while that cap and BRISK__RSA_MIN_BITS both stand. */
    {
        static const uint8_t bad_e[][2] = {{0x00, 0x00}, {0x00, 0x01}, {0x00, 0x02}, {0x01, 0x02}};
        for (i = 0; i < N(bad_e); i++) {
            CHECKI(rsa_call(good, b.n, b.nl, bad_e[i], 2, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG, i);
        }
        CHECK(rsa_call(good, b.n, b.nl, b.n, b.nl, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
        memcpy(buf, b.n, b.nl);
        buf[b.nl - 1] = (uint8_t)(buf[b.nl - 1] + 1); /* n + 1 (n is odd, so no carry) */
        CHECK(rsa_call(good, b.n, b.nl, buf, b.nl, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
        buf[0] = 0x03;
        memcpy(buf + 1, b.n, b.nl);
        CHECK(rsa_call(good, b.n, b.nl, buf, b.nl + 1, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
    }

    /* e < 2^256, the CPU-DoS bound. RFC 8017 3.1 alone accepts e = n - 2 (odd and below n), and
     * one verification then costs ~6100 Montgomery multiplications instead of 17. The ceiling is
     * where NIST SP 800-89 5.3.3, FIPS 186-5 B.3 and CA/B Forum BR 6.1.6 put it, so 33 octets
     * must be refused and 32 must still reach the signature check - a BR-compliant certificate
     * may not be rejected, and this cannot quietly become "only 65537 is allowed". Every e here
     * is odd, so the width is what decides, not the even test above. */
    {
        memset(buf, 0, 33);
        buf[0] = 0x01;
        buf[32] = 0x01; /* 2^256 + 1: one octet too wide */
        CHECK(rsa_call(good, b.n, b.nl, buf, 33, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
        memset(buf, 0, 49); /* leading zeros are stripped before the width is judged */
        buf[16] = 0x01;
        buf[48] = 0x01;
        CHECK(rsa_call(good, b.n, b.nl, buf, 49, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
        /* 2^255 + 1, the widest accepted e. Wrong signature, not malformed key material. */
        memset(buf, 0, 32);
        buf[0] = 0x80;
        buf[31] = 0x01;
        CHECK(rsa_call(good, b.n, b.nl, buf, 32, b.h, b.hl, b.s, b.sl) == BRISK_E_AUTH);
        memcpy(buf, b.n, b.nl);
        buf[b.nl - 1] = (uint8_t)(buf[b.nl - 1] - 2); /* e = n - 2: odd, < n, and 4096 bits */
        CHECK(rsa_call(good, b.n, b.nl, buf, b.nl, b.h, b.hl, b.s, b.sl) == BRISK_E_ARG);
    }

    /* Digest length and algorithm. hash_len != brisk_hash_len(alg) is a caller bug. */
    for (i = 0; i <= BRISK_SHA512_LEN; i++) {
        int want = (i == b.hl) ? BRISK_OK : BRISK_E_ARG;
        CHECKI(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, i, b.s, b.sl) == want, i);
    }
    CHECK(brisk__rsa_pkcs1_verify(b.n, b.nl, b.e, b.el, (brisk_hash_alg)0, b.h, b.hl, b.s, b.sl) ==
          BRISK_E_ARG);
    CHECK(brisk__rsa_pkcs1_verify(b.n, b.nl, b.e, b.el, (brisk_hash_alg)4, b.h, b.hl, b.s, b.sl) ==
          BRISK_E_ARG);
    CHECK(brisk__rsa_pss_verify(b.n, b.nl, b.e, b.el, (brisk_hash_alg)0, 32, b.h, b.hl, b.s,
                                b.sl) == BRISK_E_ARG);
    CHECK(brisk__rsa_pss_verify(b.n, b.nl, b.e, b.el, (brisk_hash_alg)4, 32, b.h, b.hl, b.s,
                                b.sl) == BRISK_E_ARG);

    /* Signature: every one of these is an INVALID SIGNATURE (RFC 8017 8.2.2 step 1 / 5.2.2
     * step 1), never BRISK_E_ARG - the TLS layer must send decrypt_error, and a split here would
     * make the pair of return codes an oracle. */
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, b.s, b.sl - 1) == BRISK_E_AUTH);
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, b.s, 0) == BRISK_E_AUTH);
    memcpy(buf, b.s, b.sl);
    buf[b.sl] = 0;
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, buf, b.sl + 1) == BRISK_E_AUTH);
    memset(buf, 0, b.sl); /* s = 0 */
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, buf, b.sl) == BRISK_E_AUTH);
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, b.n, b.nl) == BRISK_E_AUTH); /* s = n */
    memcpy(buf, b.n, b.nl);
    buf[b.nl - 1] = (uint8_t)(buf[b.nl - 1] + 1); /* s = n + 1 */
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, buf, b.nl) == BRISK_E_AUTH);
    memset(buf, 0xFF, b.sl); /* s = 2^(8k) - 1 */
    CHECK(rsa_call(good, b.n, b.nl, b.e, b.el, b.h, b.hl, buf, b.sl) == BRISK_E_AUTH);

    /* PSS salt lengths that make emLen < hLen + sLen + 2: "inconsistent", so BRISK_E_AUTH. */
    {
        const struct rsa_kat *p = NULL;
        for (i = 0; i < N(RSA_PSS_KAT); i++) {
            if (RSA_PSS_KAT[i].expect == 0) {
                p = &RSA_PSS_KAT[i];
                break;
            }
        }
        CHECK(p != NULL);
        if (p != NULL) {
            size_t nl = t_unhex(RSA_KEY[p->key].n, b.n, sizeof b.n);
            size_t el = t_unhex(RSA_KEY[p->key].e, b.e, sizeof b.e);
            size_t hl = t_unhex(p->hash, b.h, sizeof b.h);
            size_t sl = t_unhex(p->sig, b.s, sizeof b.s);
            static const size_t big[] = {190, 1000, 65535};
            CHECK(rsa_call(p, b.n, nl, b.e, el, b.h, hl, b.s, sl) == BRISK_OK);
            for (i = 0; i < N(big); i++) {
                CHECKI(brisk__rsa_pss_verify(b.n, nl, b.e, el, alg_of(p->bits), big[i], b.h, hl,
                                             b.s, sl) == BRISK_E_AUTH,
                       i);
            }
        }
    }
}

/* ------------------------------------------------------------------ i31 bignum */
static void bn_identities(const uint32_t *m, const uint8_t *mb, size_t mlen)
{
    uint32_t a[BRISK__BN_MAX_LIMBS], b[BRISK__BN_MAX_LIMBS], t[2 * BRISK__BN_MAX_LIMBS];
    uint32_t m2[BRISK__BN_MAX_LIMBS];
    uint8_t buf[MAXOCT + 16], out[MAXFULL];
    uint32_t n0 = brisk__bn_ninv31(m), i;
    static const uint8_t one_be[1] = {1};

    /* ninv31: m0 * n0 == -1 mod 2^31, by construction and not by a table. */
    CHECK(((m[1] * n0) & 0x7FFFFFFFu) == 0x7FFFFFFFu);

    /* Leading zero octets decode to the same modulus, however many there are. */
    for (i = 1; i <= 8; i++) {
        memset(buf, 0, i);
        memcpy(buf + i, mb, mlen);
        CHECKI(brisk__bn_decode_mod(m2, BRISK__BN_MAX_BITS, buf, mlen + i) == BRISK_OK, i);
        CHECKI(memcmp(m2, m, (size_t)((m[0] + 30) / 31 + 1) * sizeof *m) == 0, i);
    }
    /* Zero, even and oversize are all refused. */
    memset(buf, 0, mlen);
    CHECK(brisk__bn_decode_mod(m2, BRISK__BN_MAX_BITS, buf, mlen) == BRISK_E_ARG);
    CHECK(brisk__bn_decode_mod(m2, BRISK__BN_MAX_BITS, buf, 0) == BRISK_E_ARG);
    memcpy(buf, mb, mlen);
    buf[mlen - 1] = (uint8_t)(buf[mlen - 1] & 0xFE);
    CHECK(brisk__bn_decode_mod(m2, BRISK__BN_MAX_BITS, buf, mlen) == BRISK_E_ARG);
    CHECK(brisk__bn_decode_mod(m2, m[0] - 1, mb, mlen) == BRISK_E_ARG);
    /* Every refusal leaves a zero announced width, so decode_into on an unchecked m2 writes
     * nothing instead of deriving a limb count from an indeterminate header word. */
    CHECK(m2[0] == 0);
    a[0] = 0xDEADBEEFu;
    CHECK(brisk__bn_decode_into(a, m2, mb, mlen) == BRISK_E_ARG);
    CHECK(a[0] == 0xDEADBEEFu);
    CHECK(brisk__bn_decode_into(a, m2, NULL, 0) == BRISK_OK && a[0] == 0);

    /* decode_into zero-extends to the modulus's announced width, and refuses an oversize value. */
    CHECK(brisk__bn_decode_into(a, m, one_be, 1) == BRISK_OK);
    CHECK(a[0] == m[0] && a[1] == 1);
    CHECK(brisk__bn_decode_into(a, m, NULL, 0) == BRISK_OK);
    for (i = 0; i < (m[0] + 30) / 31; i++) {
        CHECKI(a[1 + i] == 0, i);
    }
    memset(buf, 0xFF, mlen + 1);
    CHECK(brisk__bn_decode_into(a, m, buf, mlen + 1) == BRISK_E_ARG);

    /* lt at the three interesting places, and a == b is not less than. */
    CHECK(brisk__bn_decode_into(a, m, mb, mlen) == BRISK_OK);
    CHECK(brisk__bn_decode_into(b, m, mb, mlen) == BRISK_OK);
    CHECK(brisk__bn_lt(a, b) == 0);
    CHECK(brisk__bn_sub(b, b, 1) == 0); /* b = 0 */
    CHECK(brisk__bn_lt(a, b) == 0 && brisk__bn_lt(b, a) == 1);
    CHECK(brisk__bn_decode_into(b, m, one_be, 1) == BRISK_OK);
    CHECK(brisk__bn_sub(a, b, 1) == 0); /* a = m - 1 */
    CHECK(brisk__bn_lt(a, m) == 1 && brisk__bn_lt(m, a) == 0);

    /* ctl = 0 is an exact no-op that still reports the true carry / borrow. */
    CHECK(brisk__bn_decode_into(a, m, mb, mlen) == BRISK_OK);
    CHECK(brisk__bn_decode_into(b, m, one_be, 1) == BRISK_OK);
    CHECK(brisk__bn_sub(a, b, 0) == 0);
    CHECK(brisk__bn_encode(out, mlen, a) == BRISK_OK && memcmp(out, mb, mlen) == 0);
    CHECK(brisk__bn_decode_into(b, m, NULL, 0) == BRISK_OK);
    CHECK(brisk__bn_sub(b, a, 0) == 1); /* 0 - m borrows, but b is untouched */
    CHECK(brisk__bn_encode(out, 1, b) == BRISK_OK && out[0] == 0);
    CHECK(brisk__bn_add(b, a, 0) == 0); /* 0 + m never carries, and b is still untouched */
    CHECK(brisk__bn_encode(out, 1, b) == BRISK_OK && out[0] == 0);

    /* from_mont(to_mont(x)) == x, and x^1 == x. */
    CHECK(brisk__bn_decode_into(a, m, mb, mlen) == BRISK_OK);
    CHECK(brisk__bn_sub(a, b, 0) == 0);
    CHECK(brisk__bn_decode_into(a, m, one_be, 1) == BRISK_OK);
    CHECK(brisk__bn_add(a, a, 1) == 0); /* a = 2, safely below m */
    brisk__bn_to_mont(a, m);
    brisk__bn_from_mont(a, m, n0, t);
    CHECK(brisk__bn_encode(out, 1, a) == BRISK_OK && out[0] == 2);
    CHECK(brisk__bn_modpow_pub(a, one_be, 1, m, t) == BRISK_OK);
    CHECK(brisk__bn_encode(out, 1, a) == BRISK_OK && out[0] == 2);
    /* A zero exponent, with or without leading zero octets, is a caller error. */
    memset(buf, 0, 4);
    CHECK(brisk__bn_modpow_pub(a, buf, 4, m, t) == BRISK_E_ARG);
    CHECK(brisk__bn_modpow_pub(a, buf, 0, m, t) == BRISK_E_ARG);

    /* encode refuses to truncate, and pads on the left when asked for more octets. */
    CHECK(brisk__bn_encode(out, mlen, m) == BRISK_OK && memcmp(out, mb, mlen) == 0);
    CHECK(brisk__bn_encode(out, mlen - 1, m) == BRISK_E_ARG);
    memset(out, 0x5A, sizeof out);
    CHECK(brisk__bn_encode(out, mlen + 3, m) == BRISK_OK);
    CHECK(out[0] == 0 && out[1] == 0 && out[2] == 0 && memcmp(out + 3, mb, mlen) == 0);
}

static void test_bn(void)
{
    uint32_t m[BRISK__BN_MAX_LIMBS], a[BRISK__BN_MAX_LIMBS], b[BRISK__BN_MAX_LIMBS];
    uint32_t d[BRISK__BN_MAX_LIMBS], t[2 * BRISK__BN_MAX_LIMBS];
    uint8_t mb[MAXOCT], ab[MAXOCT], bb[MAXOCT], rb[MAXFULL], out[MAXFULL];
    size_t i, mlen = 0, alen, blen, rlen;
    uint32_t n0 = 0;
    int last = -1;

    for (i = 0; i < N(BN_KAT); i++) {
        const struct bn_kat *v = &BN_KAT[i];
        if (v->mod != last) {
            mlen = t_unhex(BN_MOD[v->mod].hex, mb, sizeof mb);
            if (be_bits(mb, mlen) > BRISK__BN_MAX_BITS) {
                continue; /* a narrower build simply cannot hold this modulus */
            }
            CHECKI(brisk__bn_decode_mod(m, BRISK__BN_MAX_BITS, mb, mlen) == BRISK_OK, i);
            n0 = brisk__bn_ninv31(m);
            if (last < 0) {
                bn_identities(m, mb, mlen);
            }
            last = v->mod;
        }
        alen = t_unhex(v->a, ab, sizeof ab);
        blen = t_unhex(v->b, bb, sizeof bb);
        rlen = t_unhex(v->r, rb, sizeof rb);
        CHECKI(brisk__bn_decode_into(a, m, ab, alen) == BRISK_OK, i);
        switch (v->op) {
        case BN_ENCODE:
            CHECKI(brisk__bn_encode(out, rlen, a) == BRISK_OK, i);
            CHECKI(memcmp(out, rb, rlen) == 0, i);
            break;
        case BN_ADD:
            CHECKI(brisk__bn_decode_into(b, m, bb, blen) == BRISK_OK, i);
            CHECKI(brisk__bn_add(a, b, 1) == (uint32_t)v->k, i);
            CHECKI(brisk__bn_encode(out, rlen, a) == BRISK_OK, i);
            CHECKI(memcmp(out, rb, rlen) == 0, i);
            break;
        case BN_SUB:
            CHECKI(brisk__bn_decode_into(b, m, bb, blen) == BRISK_OK, i);
            /* The borrow is also what lt must return; one vector, two functions pinned. */
            CHECKI(brisk__bn_lt(a, b) == (uint32_t)v->k, i);
            CHECKI(brisk__bn_sub(a, b, 1) == (uint32_t)v->k, i);
            CHECKI(brisk__bn_encode(out, rlen, a) == BRISK_OK, i);
            CHECKI(memcmp(out, rb, rlen) == 0, i);
            break;
        case BN_MONTMUL:
            CHECKI(brisk__bn_decode_into(b, m, bb, blen) == BRISK_OK, i);
            brisk__bn_mont_mul(d, a, b, m, n0);
            CHECKI(brisk__bn_encode(out, rlen, d) == BRISK_OK, i);
            CHECKI(memcmp(out, rb, rlen) == 0, i);
            /* d may alias x and/or y: same answer, in place. */
            brisk__bn_mont_mul(a, a, b, m, n0);
            CHECKI(brisk__bn_encode(out, rlen, a) == BRISK_OK, i);
            CHECKI(memcmp(out, rb, rlen) == 0, i);
            break;
        case BN_MODPOW:
            CHECKI(brisk__bn_modpow_pub(a, bb, blen, m, t) == BRISK_OK, i);
            CHECKI(brisk__bn_encode(out, rlen, a) == BRISK_OK, i);
            CHECKI(memcmp(out, rb, rlen) == 0, i);
            break;
        default:
            CHECKI(0, i);
            break;
        }
    }
}

void test_rsa(void)
{
    test_bn();
    rsa_vectors(RSA_PKCS1_KAT, N(RSA_PKCS1_KAT), "pkcs1");
    rsa_vectors(RSA_PSS_KAT, N(RSA_PSS_KAT), "pss");
    test_rsa_invalid();
}
