/* rsa.c - RSASSA-PKCS1-v1_5 and RSASSA-PSS signature VERIFICATION (RFC 8017).
 *
 * Verify only, and that is a locked project decision: no signing, no RSAES-PKCS1-v1_5, no OAEP,
 * no CRT, no key generation, no primality testing. Nothing in this file consumes randomness, and
 * nothing in it is secret - an RSA public key, a signature and a digest are all public, which is
 * why every path here may branch freely. The arithmetic underneath (src/crypto/bn.c) is
 * constant-time anyway, for the next consumer's sake rather than this one's.
 *
 * Both schemes are mandatory to implement for a TLS 1.3 client (RFC 9846 9.1: rsa_pkcs1_sha256
 * for certificates, rsa_pss_rsae_sha256 for CertificateVerify and certificates), so neither sits
 * behind a config knob - the same reasoning that keeps p256.c unconditional for ECDHE. There is
 * no honest place to hide them, and the flash cost is simply owed.
 *
 * WHY THE PKCS#1 v1.5 CHECK IS "IN PLACE" AND WHY THAT IS THE SAME THING. RFC 8017 8.2.2 step 4
 * says to build EM' with EMSA-PKCS1-v1_5-ENCODE and compare it to EM. This file instead walks EM
 * and asserts each octet against what EM' would have held: 0x00, 0x01, exactly k - tLen - 3
 * octets of 0xff, 0x00, the DER DigestInfo prefix, then the digest. The two are equivalent by
 * construction because the PS length is FIXED at k - tLen - 3 rather than discovered by scanning
 * for the 0x00 separator - and that is the whole security argument: a scanning parser accepts a
 * short PS with trailing garbage, which is the Bleichenbacher e = 3 forgery class (and BERserk).
 * Wycheproof's InvalidAsnInPadding / ModifiedPadding / ShortPadding rows are exactly that net.
 * The saving is a second k-octet buffer, 512 bytes of stack at 4096 bits, which on a device with
 * an 8 KB thread stack is worth the paragraph it takes to justify.
 *
 * RFC 8017 9.2 note 2's BER-lenient variant is NOT adopted: a DigestInfo without the explicit
 * NULL parameters, BER-encoded padding, or any octet after the digest is INVALID here. Wycheproof
 * marks the MissingNull case "acceptable" upstream; tests/kat/SOURCES.md records the decision.
 *
 * STACK, measured with -fstack-usage at -Os (gcc 14, x86_64) and summed along the deepest call
 * chain, at the optimisation level named - because the figures are NOT optimisation-independent
 * and saying otherwise would be the easy lie here:
 *                                                BRISK_RSA_MAX_BITS = 4096 / = 2048, in bytes
 *   brisk__rsa_pkcs1_verify, deepest chain:       3088 / 1760
 *     = verify 2256/1200 + rsa_vp1 80 + brisk__bn_modpow_pub 112 + brisk__bn_mont_mul 640/368
 *   brisk__rsa_pss_verify, deepest chain:         3392 / 2064
 *     = verify 2560/1504 + the same 832/560 below it. The MGF1 and H' hashing is a SIBLING of
 *       that chain, not on top of it: brisk__hash_final 16 + brisk_sha512_final 8 +
 *       sha512_block 272 is 296, well under the modexp branch, so it never sets the maximum.
 * Budget 3.5 KB at 4096 and 2.25 KB at 2048, DELIBERATELY SEPARATE from p256.c's 3 KB: a chain
 * verification does one signature at a time and the two are never on the same call chain.
 * BRISK_RSA_MAX_BITS (include/brisk_config.h) is the lever, and it roughly halves the figure.
 * Three design choices hold the number down and none is free to undo: the in-place EM check
 * above; reusing the modexp scratch as the EM buffer once the exponentiation is done
 * (rsa_em_scratch below); and comparing e against n as octet strings in rsa_vp1 rather than
 * decoding e into a second i31 value, which alone was 536 bytes on the deepest chain.
 * Re-measure if the -Os pin in CMakeLists.txt ever moves.
 *
 * File-local statics carry an rsa_ prefix so the M8 amalgamation has nothing to collide with.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* DER DigestInfo prefixes, RFC 8017 9.2 note 1, with the explicit NULL parameters. 19 octets
 * each for these three digests. No value here was typed from memory: tools/kat.py parses the
 * table out of the RFC text itself and checks these constants against it - but that runs on
 * `kat.py`, not on `dev.py test`, so a corrupted prefix shows up in the suite only as "every
 * pkcs1 row fails". A net, not a map; emit them into rsa_pkcs1.inc if that ever bites. */
#define RSA_DI_LEN 19
static const uint8_t RSA_DI_SHA256[RSA_DI_LEN] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                                  0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                  0x01, 0x05, 0x00, 0x04, 0x20};
static const uint8_t RSA_DI_SHA384[RSA_DI_LEN] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                                  0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                  0x02, 0x05, 0x00, 0x04, 0x30};
static const uint8_t RSA_DI_SHA512[RSA_DI_LEN] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                                  0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                  0x03, 0x05, 0x00, 0x04, 0x40};

static const uint8_t *rsa_digestinfo(brisk_hash_alg alg)
{
    switch (alg) {
    case BRISK_HASH_SHA256:
        return RSA_DI_SHA256;
    case BRISK_HASH_SHA384:
        return RSA_DI_SHA384;
    case BRISK_HASH_SHA512:
        return RSA_DI_SHA512;
    default:
        return NULL;
    }
}

/* Everything both schemes share: decode the key, check it, range-check s, exponentiate.
 * On BRISK_OK, `m` holds the modulus (announced length = modBits), `x` holds s^e mod n at the
 * same width, and *k is the octet length of the modulus. `t` is the 2-value modexp scratch. */
struct rsa_ctx {
    uint32_t m[BRISK__BN_LIMBS(BRISK__RSA_MAX_BITS)];
    uint32_t x[BRISK__BN_LIMBS(BRISK__RSA_MAX_BITS)];
    uint32_t t[2 * BRISK__BN_LIMBS(BRISK__RSA_MAX_BITS)];
};

/* The EM buffer lives inside the modexp scratch, which is dead once brisk__bn_modpow_pub has
 * returned: 2 * 134 words is 1072 octets, comfortably more than the 512 a 4096-bit EM needs.
 * uint32_t -> uint8_t is a narrowing cast, so it is alignment-safe everywhere. */
static uint8_t *rsa_em_scratch(struct rsa_ctx *c)
{
    return (uint8_t *)c->t;
}

/* ... and here is the check that it really is, at whatever BRISK_RSA_MAX_BITS is set to. */
typedef char rsa_em_fits[(sizeof(((struct rsa_ctx *)0)->t) >= BRISK__RSA_MAX_BITS / 8) ? 1 : -1];

static int rsa_vp1(struct rsa_ctx *c, const uint8_t *n, size_t n_len, const uint8_t *e,
                   size_t e_len, const uint8_t *sig, size_t sig_len, size_t *k)
{
    /* RFC 8017 3.1: n is a product of odd primes, so n is odd, and 3 <= e < n. Plus the project
     * policy floor and ceiling (NIST SP 800-57 Part 1 Rev 5 5.6.2 / CA-Browser Forum BR 6.1.5
     * for 2048; BRISK_RSA_MAX_BITS is a stack lever). All of it is malformed key material, which
     * the TLS layer must turn into bad_certificate - never a failed signature. */
    if (brisk__bn_decode_mod(c->m, BRISK__RSA_MAX_BITS, n, n_len) != BRISK_OK ||
        c->m[0] < BRISK__RSA_MIN_BITS) {
        return BRISK_E_ARG;
    }
    while (n_len > 0 && *n == 0) { /* RFC 8017 4.2: leading zero octets carry no value */
        n++;
        n_len--;
    }
    while (e_len > 0 && *e == 0) { /* the CAVP files zero-pad e to the modulus width */
        e++;
        e_len--;
    }
    if (e_len == 0 || (e[e_len - 1] & 1) == 0) {
        return BRISK_E_ARG; /* e = 0 or e even: no valid public exponent */
    }
    if (e_len == 1 && e[0] < 3) {
        return BRISK_E_ARG; /* e = 1; e = 2 is already out as even */
    }
    /* ... and e < 2^256. RFC 8017 3.1 bounds e only by n, and that bound is a CPU DoS: a
     * 4096-bit e makes one verification ~6100 Montgomery multiplications instead of the 17 an F4
     * exponent costs, all spent on an UNAUTHENTICATED chain certificate before anything is
     * verified - on the 400 MHz armv5/mips targets this library exists for, seconds per
     * certificate. 2^256 is where NIST SP 800-89 5.3.3, FIPS 186-5 B.3 and CA/B Forum BR 6.1.6
     * all put the ceiling, so no BR-compliant certificate can be refused here; the worst case it
     * still allows is ~384 multiplications, bounded and not a DoS. A tighter cap (BoringSSL uses
     * 33 bits) would cover every e in the wild but would also reject a valid chain. */
    if (e_len > 32) {
        return BRISK_E_ARG;
    }
    /* e < n (RFC 8017 3.1). Unreachable at today's bounds - the 32-octet cap above and the
     * 2048-bit floor on n (256 octets) leave no overlap - but kept as defence in depth so the
     * rule survives a change to either. Compared as the stripped big-endian strings they already
     * are: decoding e into a second i31 value would cost another BRISK__BN_LIMBS words on the stack
     * (536 at 4096 bits, on the deepest chain) to answer a question two lines of memcmp answer. */
    if (e_len > n_len || (e_len == n_len && memcmp(e, n, e_len) >= 0)) {
        return BRISK_E_ARG;
    }

    *k = (size_t)((c->m[0] + 7) / 8);
    /* RFC 8017 8.2.2 step 1 / 8.1.2 step 1: a signature of the wrong length is an INVALID
     * SIGNATURE, not a caller bug - the TLS layer must send decrypt_error, not a bad_certificate
     * alert, so this may not be BRISK_E_ARG. */
    if (sig_len != *k) {
        return BRISK_E_AUTH;
    }
    if (brisk__bn_decode_into(c->x, c->m, sig, sig_len) != BRISK_OK ||
        brisk__bn_lt(c->x, c->m) == 0) {
        return BRISK_E_AUTH; /* 5.2.2 step 1: signature representative out of range */
    }
    /* x < n now holds, which is also what makes brisk__bn_mont_mul's precondition true. */
    if (brisk__bn_modpow_pub(c->x, e, e_len, c->m, c->t) != BRISK_OK) {
        return BRISK_E_ARG;
    }
    return BRISK_OK;
}

int brisk__rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                            brisk_hash_alg alg, const uint8_t *hash, size_t hash_len,
                            const uint8_t *sig, size_t sig_len)
{
    struct rsa_ctx c;
    const uint8_t *di = rsa_digestinfo(alg);
    uint8_t *em;
    size_t k, tlen, ps, i;
    uint32_t bad = 0;
    int rc;

    if (di == NULL || hash_len != brisk_hash_len(alg)) {
        return BRISK_E_ARG;
    }
    rc = rsa_vp1(&c, n, n_len, e, e_len, sig, sig_len, &k);
    if (rc != BRISK_OK) {
        goto out;
    }
    tlen = RSA_DI_LEN + hash_len;
    /* RFC 8017 9.2 step 3: emLen < tLen + 11. Unreachable at BRISK__RSA_MIN_BITS (k >= 256,
     * max tLen + 11 = 94). 8.2.2 step 3 calls it "RSA modulus too short", an error distinct from
     * "invalid signature"; folded into E_AUTH because no caller can act on the difference. */
    if (k < tlen + 11) {
        rc = BRISK_E_AUTH;
        goto out;
    }
    em = rsa_em_scratch(&c);
    if (brisk__bn_encode(em, k, c.x) != BRISK_OK) {
        rc = BRISK_E_AUTH; /* cannot happen once x < n, but never emit an unchecked EM */
        goto out;
    }
    /* EM must be 0x00 || 0x01 || PS || 0x00 || T, with the PS length FIXED at k - tLen - 3.
     * Accumulating into `bad` rather than returning early is not a timing argument - everything
     * here is public - it just keeps the whole rule in one expression per octet. */
    ps = k - tlen - 3;
    bad |= em[0] ^ 0x00u;
    bad |= em[1] ^ 0x01u;
    for (i = 0; i < ps; i++) {
        bad |= em[2 + i] ^ 0xFFu;
    }
    bad |= em[2 + ps] ^ 0x00u;
    for (i = 0; i < RSA_DI_LEN; i++) {
        bad |= em[3 + ps + i] ^ di[i];
    }
    for (i = 0; i < hash_len; i++) {
        bad |= em[3 + ps + RSA_DI_LEN + i] ^ hash[i];
    }
    rc = bad ? BRISK_E_AUTH : BRISK_OK;
out:
    brisk__secure_zero(&c, sizeof c);
    return rc;
}

int brisk__rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                          brisk_hash_alg alg, size_t salt_len, const uint8_t *hash, size_t hash_len,
                          const uint8_t *sig, size_t sig_len)
{
    struct rsa_ctx c;
    brisk_hash_ctx hc;
    uint8_t hp[BRISK_SHA512_LEN];
    uint8_t *em, *db, *hh;
    size_t k, hlen, emlen, dblen, i;
    uint32_t embits, top, bad = 0;
    int rc;

    hlen = brisk_hash_len(alg);
    if (hlen == 0 || hash_len != hlen) {
        return BRISK_E_ARG;
    }
    rc = rsa_vp1(&c, n, n_len, e, e_len, sig, sig_len, &k);
    if (rc != BRISK_OK) {
        goto out;
    }
    /* RFC 8017 8.1.2 step 2c: emLen = ceil((modBits - 1)/8), from the TRUE bit length of n. It
     * is k - 1 exactly when modBits - 1 is a multiple of 8, and k otherwise; 8*emLen - emBits is
     * the number of leftmost bits that steps 6 and 9 must see clear. Using 8*n_len here instead
     * of modBits would be wrong in both branches. */
    embits = c.m[0] - 1;
    emlen = (size_t)((embits + 7) / 8);
    top = 8 * (uint32_t)emlen - embits;
    em = rsa_em_scratch(&c);
    if (brisk__bn_encode(em, emlen, c.x) != BRISK_OK) {
        rc = BRISK_E_AUTH; /* m does not fit emLen octets: "invalid signature" */
        goto out;
    }
    /* Step 3: emLen < hLen + sLen + 2 is "inconsistent", which is a failed signature and not a
     * caller error - salt_len comes off the wire in an X.509 AlgorithmIdentifier. The addition
     * cannot overflow: hLen <= 64 and salt_len is bounded by the caller's own size_t, so test it
     * by subtraction instead. */
    if (emlen < hlen + 2 || salt_len > emlen - hlen - 2) {
        rc = BRISK_E_AUTH;
        goto out;
    }
    if (em[emlen - 1] != 0xBC) { /* step 4 */
        rc = BRISK_E_AUTH;
        goto out;
    }
    dblen = emlen - hlen - 1;
    db = em;
    hh = em + dblen;
    if (top != 0 && (db[0] >> (8 - top)) != 0) { /* step 6 */
        rc = BRISK_E_AUTH;
        goto out;
    }
    /* Steps 7-8: DB = maskedDB XOR MGF1(H, emLen - hLen - 1), unmasked in place. The mask is
     * generated one hash block at a time straight into db, so no second dblen buffer exists. */
    {
        uint8_t block[BRISK_SHA512_LEN];
        size_t off = 0;
        uint32_t counter = 0;
        while (off < dblen) {
            size_t take = dblen - off < hlen ? dblen - off : hlen;
            uint8_t cb[4];
            brisk__store_be32(cb, counter);
            brisk__hash_init(&hc, alg);
            brisk__hash_update(&hc, alg, hh, hlen);
            brisk__hash_update(&hc, alg, cb, sizeof cb);
            brisk__hash_final(&hc, alg, block);
            for (i = 0; i < take; i++) {
                db[off + i] ^= block[i];
            }
            off += take;
            counter++;
        }
        brisk__secure_zero(block, sizeof block);
    }
    if (top != 0) { /* step 9: clear the same leftmost bits in DB */
        db[0] = (uint8_t)(db[0] & (0xFFu >> top));
    }
    /* Step 10: the leading emLen - hLen - sLen - 2 octets of DB are zero, then a single 0x01. */
    for (i = 0; i + salt_len + 1 < dblen; i++) {
        bad |= db[i];
    }
    bad |= db[dblen - salt_len - 1] ^ 0x01u;
    if (bad) {
        rc = BRISK_E_AUTH;
        goto out;
    }
    /* Steps 11-14: salt is the last sLen octets of DB, H' = Hash(0x00 x8 || mHash || salt). */
    brisk__hash_init(&hc, alg);
    {
        static const uint8_t zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        brisk__hash_update(&hc, alg, zeros, sizeof zeros);
    }
    brisk__hash_update(&hc, alg, hash, hlen);
    brisk__hash_update(&hc, alg, db + dblen - salt_len, salt_len);
    brisk__hash_final(&hc, alg, hp);
    rc = brisk__ct_memeq(hp, hh, hlen) ? BRISK_OK : BRISK_E_AUTH;
out:
    brisk__secure_zero(&c, sizeof c);
    brisk__secure_zero(&hc, sizeof hc);
    brisk__secure_zero(hp, sizeof hp);
    return rc;
}

#undef RSA_DI_LEN
