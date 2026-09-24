/* test_ct.c - the constant-time suite: every primitive once, with its secrets marked secret.
 *
 * In a normal build BRISK__CT_SECRET/BRISK__CT_PUBLIC are no-ops and this is a plain smoke test.
 * Under `python tools/dev.py ct` it runs inside valgrind with -DBRISK_CT_CHECK, where the marked
 * bytes are "undefined" and memcheck reports any branch, memory index or division whose result
 * depends on one. Public values (nonces, lengths, ciphertext, tags) stay defined on purpose: they
 * are what an attacker already has, so only the secrets are under test.
 *
 * Adding a primitive = call it here with its key marked. Never silence a report by marking a
 * secret public; see BRISK__CT_PUBLIC in src/brisk_int.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

/* Keys and plaintexts are secret; the nonce, AAD and lengths are not. Values are arbitrary: what
 * matters is only that the bytes are marked, not what they are. */
static uint8_t secret32[32], secret16[16], plain[96];
static uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
static uint8_t ctr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 1};
static uint8_t aad[13] = {'a', 'a', 'd'};

static void mark_secrets(void)
{
    memset(secret32, 0xA5, sizeof secret32);
    memset(secret16, 0x5A, sizeof secret16);
    memset(plain, 0x42, sizeof plain);
    BRISK__CT_SECRET(secret32, sizeof secret32);
    BRISK__CT_SECRET(secret16, sizeof secret16);
    BRISK__CT_SECRET(plain, sizeof plain);
}

static void ct_hash_hkdf(void)
{
    brisk_hash_ctx c;
    uint8_t out[64], prk[64], key[32]; /* prk is HashLen: 64 for SHA-512 */
    brisk_hash_alg algs[3] = {BRISK_HASH_SHA256, BRISK_HASH_SHA384, BRISK_HASH_SHA512};
    int i;
    for (i = 0; i < 3; i++) {
        brisk__hash_init(&c, algs[i]);
        brisk__hash_update(&c, algs[i], plain, sizeof plain); /* secret message */
        brisk__hash_update(&c, algs[i], secret32, 1);         /* unaligned tail */
        brisk__hash_final(&c, algs[i], out);
        CHECK(brisk__hkdf_extract(algs[i], nonce, sizeof nonce, secret32, sizeof secret32, prk) ==
              BRISK_OK);
        /* out is the transcript-hash context here, so expand into a separate buffer: the
         * documented alias rule is out-may-alias-prk, never out-overlaps-info. */
        CHECK(brisk__hkdf_expand_label(algs[i], prk, brisk_hash_len(algs[i]), "quic key", out,
                                       brisk_hash_len(algs[i]), key, sizeof key) == BRISK_OK);
    }
    brisk__secure_zero(key, sizeof key); /* the wipe itself must not branch on the data */
    brisk__secure_zero(prk, sizeof prk);
}

static void ct_chacha20_poly1305(void)
{
    uint8_t ct[sizeof plain], pt[sizeof plain], tag[16];
    brisk__chacha20(secret32, 1, nonce, plain, ct, sizeof plain);
    brisk__poly1305(secret32, plain, sizeof plain, tag);
    CHECK(brisk__chacha20_poly1305_seal(secret32, nonce, aad, sizeof aad, plain, sizeof plain, ct,
                                        tag) == BRISK_OK);
    /* The ciphertext and tag went over the wire, so they are public from here on; the open path
     * must still be constant time in the key. */
    BRISK__CT_PUBLIC(ct, sizeof ct);
    BRISK__CT_PUBLIC(tag, sizeof tag);
    CHECK(brisk__chacha20_poly1305_open(secret32, nonce, aad, sizeof aad, ct, sizeof ct, pt, tag) ==
          BRISK_OK);
    tag[0] ^= 1;
    CHECK(brisk__chacha20_poly1305_open(secret32, nonce, aad, sizeof aad, ct, sizeof ct, pt, tag) ==
          BRISK_E_AUTH);
}

static void ct_aes_gcm(void)
{
    brisk__aes_key ak;
    brisk__gcm_key gk;
    uint8_t ct[sizeof plain], pt[sizeof plain], tag[16], block[16], h[16];
    size_t klen;
    for (klen = 16; klen <= 32; klen += 16) { /* AES-128 and AES-256 */
        CHECK(brisk__aes_init(&ak, secret32, klen) == BRISK_OK);
        brisk__aes_encrypt(&ak, ctr, block);       /* one block of a public counter */
        brisk__aes_ctr32(&ak, ctr, plain, 48, ct); /* keystream over a secret plaintext */
        CHECK(brisk__gcm_init(&gk, secret32, klen) == BRISK_OK);
        CHECK(brisk__gcm_seal(&gk, nonce, aad, sizeof aad, plain, sizeof plain, ct, tag) ==
              BRISK_OK);
        BRISK__CT_PUBLIC(ct, sizeof ct);
        BRISK__CT_PUBLIC(tag, sizeof tag);
        CHECK(brisk__gcm_open(&gk, nonce, aad, sizeof aad, ct, sizeof ct, pt, tag) == BRISK_OK);
        tag[15] ^= 1;
        CHECK(brisk__gcm_open(&gk, nonce, aad, sizeof aad, ct, sizeof ct, pt, tag) == BRISK_E_AUTH);
        brisk__secure_zero(&ak, sizeof ak);
        brisk__secure_zero(&gk, sizeof gk);
    }
    /* GHASH with a secret H, the case the multiplier caveat is about (docs/ARCHITECTURE.md). */
    memcpy(h, secret16, 16);
    memset(block, 0, sizeof block);
    brisk__ghash(block, h, plain, sizeof plain);
    brisk__ghash_mulfree(block, h, plain, sizeof plain);
}

/* X25519: the scalar is the private key, the peer's u-coordinate is public (it came over the
 * wire). The only declassified value is the all-zero verdict, which RFC 9846 7.4.2 makes a
 * visible abort - see BRISK__CT_PUBLIC in brisk__x25519. */
static void ct_x25519(void)
{
    uint8_t pub[32], shared[32];
    static const uint8_t peer[32] = {0xE6, 0xDB, 0x68, 0x67, 0x58, 0x30, 0x30, 0xDB};
    brisk__x25519_base(pub, secret32);
    BRISK__CT_PUBLIC(pub, sizeof pub); /* the public key goes into the KeyShareEntry */
    CHECK(brisk__x25519(shared, secret32, peer) == BRISK_OK);
    brisk__secure_zero(shared, sizeof shared);
}

/* P-256: the private scalar is secret, the peer point and our own public key are not. Three
 * things are declassified inside the module, each with its reason written there: the private-key
 * range verdict (FIPS 186-5 A.2.2 rejection sampling is observable by construction), the peer
 * point and its validity verdict (the attacker wrote it, and a bad point is a visible alert), and
 * every input to ECDSA verify, which is public by definition. */
static void ct_p256(void)
{
    uint8_t pub[65], shared[32], sig[64], hash[32];
    static const uint8_t peer[65] = {
        0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
        0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
        0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E,
        0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E,
        0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5}; /* the generator, a valid point */

    /* secret32 is 0xA5 repeated, which is below n, so the range verdict is "accept". */
    CHECK(brisk__p256_keygen(pub, secret32) == BRISK_OK);
    BRISK__CT_PUBLIC(pub, sizeof pub); /* our public key goes into the KeyShareEntry */
    CHECK(brisk__p256_ecdh(shared, secret32, peer) == BRISK_OK);
    brisk__secure_zero(shared, sizeof shared);

    /* The mod-n core with a secret operand: ECDSA signing uses it that way, so it is exercised
     * here as a secret even though verify only feeds it public data. */
    brisk__p256_scalar_inv(shared, secret32);
    brisk__p256_scalar_mul(shared, secret32, shared);
    brisk__p256_scalar_add(shared, secret32, shared);
    brisk__p256_scalar_reduce(shared, secret32);
    {
        /* The range verdict for a secret scalar, declassified exactly as brisk__p256_keygen
         * declassifies it and for the same reason (FIPS 186-5 A.2.2 rejection is observable). */
        int v = brisk__p256_scalar_valid(secret32);
        BRISK__CT_PUBLIC(&v, sizeof v);
        CHECK(v == 1);
    }
    brisk__secure_zero(shared, sizeof shared);

    /* Verify: everything public, so nothing here should report either way. */
    memset(hash, 0x11, sizeof hash);
    memset(sig, 0x22, sizeof sig);
    CHECK(brisk__p256_ecdsa_verify(peer, hash, sizeof hash, sig) == BRISK_E_AUTH);

#if BRISK_ENABLE_MTLS
    /* ECDSA sign: the device key and the RFC 6979 3.6 hedging input k' are secret, and so is
     * everything the DRBG derives from them (K, V, k, k^-1, s). The message digest is public -
     * it is the transcript hash the peer computes too. The only value declassified inside the
     * module is the one-bit "this candidate k was rejected" verdict, the same declassification
     * brisk__p256_keygen makes for its range check; any other report from this call is a real
     * leak and must not be silenced with BRISK__CT_PUBLIC. */
    {
        uint8_t kprime[32];
        memset(kprime, 0x3C, sizeof kprime);
        BRISK__CT_SECRET(kprime, sizeof kprime);
        CHECK(brisk__p256_ecdsa_sign(sig, secret32, hash, sizeof hash, kprime, sizeof kprime) ==
              BRISK_OK);
        brisk__secure_zero(kprime, sizeof kprime);
    }
#endif
}

#if BRISK_ENABLE_P384
/* P-384: verify only, and every input is public by construction - a certificate, a
 * CertificateVerify and the verdict all travel in the clear. So the call below is made on buffers
 * valgrind has marked UNDEFINED and must still report nothing: that proves the three
 * BRISK__CT_PUBLIC declassifications inside brisk__p384_ecdsa_verify are explicit and that no
 * other branch escapes them: delete any one of the three and this case reports. Their ORDER is
 * not testable here - VALGRIND_MAKE_MEM_DEFINED marks a range defined and addressable without
 * complaint, so moving the `hash` declassification above the hash_len check would be silent to
 * memcheck; that one is held in place by the comment at its site, not by this test. The ladder
 * inside deliberately branches on its scalar bits; that is why nothing secret may ever be passed
 * here. */
static void ct_p384(void)
{
    uint8_t pub[97], sig[96], hash[48];
    memset(pub, 0x04, sizeof pub); /* 0x04 || 0x04... - not on the curve, which is fine */
    memset(sig, 0x33, sizeof sig);
    memset(hash, 0x44, sizeof hash);
    BRISK__CT_SECRET(pub, sizeof pub);
    BRISK__CT_SECRET(sig, sizeof sig);
    BRISK__CT_SECRET(hash, sizeof hash);
    CHECK(brisk__p384_ecdsa_verify(pub, hash, sizeof hash, sig) == BRISK_E_ARG);

    /* And a point that IS on the curve, so the ladder, both inversions and the final comparison
     * all run under the same marking rather than being cut short by the decode. */
    {
        static const uint8_t
            g[97] = {0x04, 0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E,
                     0xF3, 0x20, 0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59,
                     0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55,
                     0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7, 0x36, 0x17, 0xDE,
                     0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
                     0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5,
                     0xF0, 0xB8, 0xC0, 0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43,
                     0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F}; /* the RFC 5903 3.2 generator */
        memcpy(pub, g, sizeof pub);
        /* All three, not just pub: BRISK__CT_PUBLIC is VALGRIND_MAKE_MEM_DEFINED, which sticks to
         * the memory. The first call declassified sig and hash, and the marking survives it, so
         * without re-marking them here the ladder would run on data valgrind already considers
         * defined and the declassification of `hash` would never be exercised at all. */
        BRISK__CT_SECRET(pub, sizeof pub);
        BRISK__CT_SECRET(sig, sizeof sig);
        BRISK__CT_SECRET(hash, sizeof hash);
        CHECK(brisk__p384_ecdsa_verify(pub, hash, sizeof hash, sig) == BRISK_E_AUTH);
    }
}
#endif

static void ct_memeq(void)
{
    uint8_t copy[16];
    memcpy(copy, secret16, sizeof copy);
    CHECK(brisk__ct_memeq(secret16, copy, sizeof copy) == 1); /* declassified result: may branch */
    copy[7] ^= 0x80;
    CHECK(brisk__ct_memeq(secret16, copy, sizeof copy) == 0);
}

/* bn.c / rsa.c. Read the caveat before reading the code: NOTHING here is genuinely secret. RSA is
 * verify-only and every input - modulus, exponent, signature, digest - is public, and P-384 verify
 * will be the same. What this case exists to prove is that the i31 kernel a future secret-key
 * consumer would inherit is branch-free, index-free and division-free on its DATA. So the limbs
 * are marked secret while the announced bit length is not: the width of a modulus is public by
 * construction (it is the key size), and every limb count in bn.c is derived from it.
 *
 * Exactly two things are declassified, each for a reason written at the point of use: the public
 * exponent's bits inside brisk__bn_modpow_pub (the _pub in the name, see src/brisk_int.h), and
 * the final verdict. Any other report from this case is a real finding and must never be silenced
 * with a third BRISK__CT_PUBLIC.
 *
 * The two RSA entry points are called with everything public, because they branch on all of it by
 * design (RFC 8017 8.2.2 and 9.1.2 are structural checks over public octets). They are here so
 * that the valgrind run still walks them for memory errors, not as a constant-time claim. */
static void ct_bn_rsa(void)
{
    uint32_t m[BRISK__BN_MAX_LIMBS], x[BRISK__BN_MAX_LIMBS], d[BRISK__BN_MAX_LIMBS];
    uint32_t t[2 * BRISK__BN_MAX_LIMBS];
    uint8_t mb[256], xb[256], out[256];
    static const uint8_t e[3] = {0x01, 0x00, 0x01};
    uint32_t n0, limbs;
    size_t i;

    /* Any odd 2048-bit modulus will do; the values never reach a comparison that matters. */
    memset(mb, 0xA5, sizeof mb);
    mb[0] = 0xC7;
    mb[sizeof mb - 1] = 0x8D;
    for (i = 0; i < sizeof xb; i++) {
        xb[i] = (uint8_t)(i * 7 + 3);
    }
    xb[0] = 0x42; /* keeps x below m */
    CHECK(brisk__bn_decode_mod(m, BRISK__BN_MAX_BITS, mb, sizeof mb) == BRISK_OK);
    CHECK(brisk__bn_decode_into(x, m, xb, sizeof xb) == BRISK_OK);
    limbs = (m[0] + 30) / 31;
    /* The header word stays public - it is the key size - and the limbs become secret. */
    BRISK__CT_SECRET(m + 1, limbs * sizeof *m);
    BRISK__CT_SECRET(x + 1, limbs * sizeof *x);
    n0 = brisk__bn_ninv31(m);
    {
        uint32_t verdict = brisk__bn_lt(x, m);
        BRISK__CT_PUBLIC(&verdict, sizeof verdict); /* the range check the protocol reveals */
        CHECK(verdict == 1);
    }
    (void)brisk__bn_add(x, m, 0);
    (void)brisk__bn_sub(x, m, 0);
    brisk__bn_mont_mul(d, x, x, m, n0);
    brisk__bn_to_mont(d, m);
    brisk__bn_from_mont(d, m, n0, t);
    CHECK(brisk__bn_modpow_pub(x, e, sizeof e, m, t) == BRISK_OK);
    CHECK(brisk__bn_encode(out, sizeof out, x) == BRISK_OK);
    BRISK__CT_PUBLIC(out, sizeof out); /* the result is the signature representative: public */
    BRISK__CT_PUBLIC(m, sizeof m);
    BRISK__CT_PUBLIC(x, sizeof x);
    brisk__secure_zero(t, sizeof t);

    /* Public-input smoke run of both verifiers, for the memory check rather than the CT one. */
    CHECK(brisk__rsa_pkcs1_verify(mb, sizeof mb, e, sizeof e, BRISK_HASH_SHA256, out, 32, xb,
                                  sizeof xb) != BRISK_OK);
    CHECK(brisk__rsa_pss_verify(mb, sizeof mb, e, sizeof e, BRISK_HASH_SHA256, 32, out, 32, xb,
                                sizeof xb) != BRISK_OK);
}

void test_ct(void)
{
    mark_secrets();
    ct_hash_hkdf();
    ct_chacha20_poly1305();
    ct_aes_gcm();
    ct_x25519();
    ct_p256();
#if BRISK_ENABLE_P384
    ct_p384();
#endif
    ct_bn_rsa();
    ct_memeq();
    tls13_hs_ct_run();  /* the handshake engine over RFC 8448 sect 3, ECDHE key secret */
    tls13_rec_ct_run(); /* record seal/open, dir_init/update with secret keys */
    tls12_ct_run();     /* TLS 1.2: PRF, EMS, key block, CV, Finished, 1.2 records */
    quic_ct_run();      /* QUIC packet + header protection, secret key/iv/hp (M6) */
}
