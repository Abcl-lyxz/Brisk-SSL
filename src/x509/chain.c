/* chain.c - build a path from an end entity to a trust anchor and check every signature on it
 * (RFC 5280 6.1). What is checked, what is not, and how the search behaves is documented in the
 * x509/chain.c block of src/brisk_int.h.
 *
 * Two layers, and the split is deliberate: brisk__x509_signed_by knows about keys and knows
 * nothing about Names or CA bits, while the walk knows about Names and CA bits and treats the
 * verifier as a yes/no. A caller that has its own path (a pinned issuer, say) can use the first
 * without the second.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* ------------------------------------------------------------------ signature ------------- */

/* An ECDSA-Sig-Value (RFC 5480 A.1) as the fixed-width r || s the verifiers take. This is DER
 * the certificate-wide brisk__der_walk never saw - it sits inside the signatureValue BIT
 * STRING, which is a leaf to the walk - so the strict cursor runs over it here, trailing bytes
 * and all. */
static int ecdsa_raw(const uint8_t *sig, size_t sig_len, size_t flen, uint8_t *out)
{
    brisk__der c, body;
    const uint8_t *r = NULL, *s = NULL;
    size_t r_len = 0, s_len = 0;

    brisk__der_init(&c, sig, sig_len);
    brisk__der_enter(&c, BRISK__DER_SEQUENCE, &body);
    brisk__der_unsigned(&body, &r, &r_len);
    brisk__der_unsigned(&body, &s, &s_len);
    brisk__der_close(&c, &body);
    brisk__der_end(&c);
    if (brisk__der_err(&c) != BRISK_OK || r_len > flen || s_len > flen) {
        return BRISK_E_ARG;
    }
    /* Left-pad each into its field width. A leading zero octet the encoder had to add is
     * already gone: brisk__der_unsigned hands back the magnitude. */
    memset(out, 0, 2 * flen);
    memcpy(out + flen - r_len, r, r_len);
    memcpy(out + 2 * flen - s_len, s, s_len);
    return BRISK_OK;
}

/* An RSAPublicKey (RFC 8017 A.1.1) split into the modulus and exponent brisk__rsa_* want. Same
 * story as ecdsa_raw: this lives inside the subjectPublicKey BIT STRING, which read_spki hands
 * over without descending into it. */
static int rsa_key(const brisk__x509_cert *issuer, const uint8_t **n, size_t *n_len,
                   const uint8_t **e, size_t *e_len)
{
    brisk__der c, body;

    brisk__der_init(&c, issuer->key, issuer->key_len);
    brisk__der_enter(&c, BRISK__DER_SEQUENCE, &body);
    brisk__der_unsigned(&body, n, n_len);
    brisk__der_unsigned(&body, e, e_len);
    brisk__der_close(&c, &body);
    brisk__der_end(&c);
    return brisk__der_err(&c);
}

int brisk__x509_signed_by(const brisk__x509_cert *child, const brisk__x509_cert *issuer)
{
#if BRISK_ENABLE_P384
    uint8_t raw[96]; /* two field elements, at the widest curve this build verifies */
#else
    uint8_t raw[64];
#endif
    uint8_t hash[BRISK_HASH_MAX_LEN];
    const uint8_t *n = NULL, *e = NULL;
    size_t hash_len, n_len = 0, e_len = 0, flen;
    brisk_hash_alg alg;
    int rc;

    if (child == NULL || issuer == NULL || child->tbs == NULL || issuer->key == NULL) {
        return BRISK_E_ARG;
    }
    alg = (brisk_hash_alg)child->sig_hash;
    hash_len = brisk_hash_len(alg);
    if (hash_len == 0) {
        return BRISK_E_ARG;
    }
    {
        /* The 200-byte hash context lives in its own scope so its slot is dead before the
         * verifier below is called: this function sits at the top of the deepest stack chain
         * in the library (see the budget in src/crypto/rsa.c) and every frame counts on a
         * router with an 8 KB thread stack. */
        brisk_hash_ctx h;
        brisk__hash_init(&h, alg);
        brisk__hash_update(&h, alg, child->tbs, child->tbs_len);
        brisk__hash_final(&h, alg, hash);
    }

    switch (child->sig_alg) {
    case BRISK__X509_SIG_ECDSA:
        /* The curve is the ISSUER's, never anything the signature claims - an
         * ecdsa-with-SHA256 OID says which digest was used and nothing about the key. */
        if (issuer->key_alg == BRISK__X509_KEY_P256) {
            flen = 32;
        } else if (issuer->key_alg == BRISK__X509_KEY_P384) {
#if BRISK_ENABLE_P384
            flen = 48;
#else
            /* Before anything writes into raw[], which is sized for P-256 in this build.
             * cert.c cannot produce such a key here, but this function takes an issuer from
             * whoever calls it - including a trust store's own callback. */
            return BRISK_E_ARG;
#endif
        } else {
            return BRISK_E_AUTH;
        }
        /* A digest shorter than the field IS verifiable in principle - FIPS 186-5 6.4.2 takes
         * the leftmost min(N, outlen) bits, so a short hash is used whole - but RFC 5480 4
         * pairs a 384-bit key with SHA-384 or SHA-512 and the M1 verifiers take that as their
         * contract (hash_len >= 32 / >= 48). So this is a pairing the build will not do, which
         * the P-384 block of brisk_int.h says to answer with unsupported_certificate: it is
         * BRISK_E_ARG, not a signature that failed. */
        if (hash_len < flen) {
            return BRISK_E_ARG;
        }
        /* The verifiers read a fixed 65 or 97 bytes. cert.c bounds an EC point to exactly that,
         * but this function is documented as usable on its own and inside the walk the issuer
         * can be an anchor a CALLER's store filled in - so the length is checked here too
         * rather than trusted twice over. */
        if (issuer->key_len != 2 * flen + 1) {
            return BRISK_E_AUTH;
        }
        rc = ecdsa_raw(child->sig, child->sig_len, flen, raw);
        if (rc != BRISK_OK) {
            return rc;
        }
#if BRISK_ENABLE_P384
        if (flen == 48) {
            return brisk__p384_ecdsa_verify(issuer->key, hash, hash_len, raw);
        }
#endif
        return brisk__p256_ecdsa_verify(issuer->key, hash, hash_len, raw);

    case BRISK__X509_SIG_RSA_PKCS1:
    case BRISK__X509_SIG_RSA_PSS:
        if (issuer->key_alg != BRISK__X509_KEY_RSA) {
            return BRISK_E_AUTH;
        }
        rc = rsa_key(issuer, &n, &n_len, &e, &e_len);
        if (rc != BRISK_OK) {
            return rc;
        }
        if (child->sig_alg == BRISK__X509_SIG_RSA_PKCS1) {
            return brisk__rsa_pkcs1_verify(n, n_len, e, e_len, alg, hash, hash_len, child->sig,
                                           child->sig_len);
        }
        /* The saltLength is the one the certificate's own AlgorithmIdentifier declared (RFC 4055
         * 3.1); unlike a CertificateVerify, X.509 does not tie it to hLen. */
        return brisk__rsa_pss_verify(n, n_len, e, e_len, alg, child->sig_salt_len, hash, hash_len,
                                     child->sig, child->sig_len);

    default:
        return BRISK_E_ARG;
    }
}

/* ------------------------------------------------------------------ validity -------------- */

int brisk__x509_time_ok(const brisk__x509_cert *c, int64_t now)
{
    if (c == NULL) {
        return BRISK_E_ARG;
    }
#if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
    (void)now;
    return BRISK_OK;
#else
    /* A clock below the floor is an unset counter, not a time: the firmware cannot be running
     * before it was built. cert.c has already refused notBefore > notAfter, so the window is
     * never inverted here. */
    if (now < (int64_t)(BRISK_X509_TIME_FLOOR)) {
#    if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_STRICT
        return BRISK_E_AUTH;
#    else
        /* notBefore is unjudgeable in this state - the real time is somewhere above the floor,
         * so a certificate issued after this build is legitimate and cannot be told apart from
         * one dated in the future. notAfter can still be judged, and that is the half that
         * stops a long-dead leaf. */
        return (c->not_after >= (int64_t)(BRISK_X509_TIME_FLOOR)) ? BRISK_OK : BRISK_E_AUTH;
#    endif
    }
    return (c->not_before <= now && now <= c->not_after) ? BRISK_OK : BRISK_E_AUTH;
#endif
}

/* ------------------------------------------------------------------ the walk -------------- */

/* Names chain byte for byte: RFC 5280 6.1.3 (a)(4) with the canonical comparison of 7.1
 * deliberately left out (see the brisk__x509_cert block). */
static int name_eq(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    return a != NULL && b != NULL && a_len == b_len && a_len != 0 && memcmp(a, b, a_len) == 0;
}

/* RFC 5280 6.1: "self-issued" is issuer == subject, which is not the same thing as self-SIGNED
 * - a cross-certificate a CA writes to itself during a key rollover is self-issued and signed
 * by the old key. 6.1.4 (l) lets those through the path length budget untouched. */
static int self_issued(const brisk__x509_cert *c)
{
    return name_eq(c->issuer, c->issuer_len, c->subject, c->subject_len);
}

/* May this certificate act as the parent, given `below` non-self-issued certificates already
 * standing between it and the end entity? RFC 5280 6.1.4 (k), (l), (m) and (n).
 *
 * `anchor` says whether this is a trust anchor, and it changes exactly one rule. 6.1.1 (d)
 * takes an anchor as a NAME and a KEY - a certificate is just the convenient way to carry
 * them - and 6.1.3 runs "for all i in [1..n]", a range the anchor is not in, so none of
 * (k)..(n) is defined for it. Refusing a v1 or v2 anchor would therefore only lock an operator
 * out of a trust store they configured themselves, which is how a private PKI with a root from
 * before 1999 gets bricked. The other three rules are kept for anchors even though the RFC does
 * not ask for them: they cost nothing when the root is well formed, they are what every
 * mainstream implementation enforces, and a root that says cA FALSE meant it. */
static int usable_ca(const brisk__x509_cert *ca, size_t below, int anchor)
{
    if (ca->version == 3) {
        if (!ca->is_ca) {
            return 0; /* (k) */
        }
    } else if (!anchor) {
        return 0; /* (k), taking its permission to refuse v1 and v2 INTERMEDIATES */
    }
    if (ca->key_usage != 0 && !(ca->key_usage & BRISK__X509_KU_KEY_CERT_SIGN)) {
        return 0; /* (n); key_usage == 0 is "the extension was absent", never "no bits" */
    }
    if (ca->path_len >= 0 && (size_t)ca->path_len < below) {
        return 0; /* (l) and (m), counted from the bottom: the budget is what fits underneath */
    }
    return 1;
}

/* ------------------------------------------------------------------ pins ----------------- */

/* Does this certificate's SubjectPublicKeyInfo hash to one of the pins? Public data on both
 * sides - the key is in the certificate the peer sent and the pin is in the firmware - so an
 * ordinary memcmp and an early exit are right; there is no secret here to leak the timing of.
 * The whole SPKI TLV is the preimage, which is RFC 7469 3's fingerprint without the base64. */
static int pinned(const brisk__x509_trust *t, const brisk__x509_cert *c)
{
    uint8_t h[BRISK_SHA256_LEN];
    size_t i;

    /* pins == NULL with n_pins > 0 is a caller that half-configured its trust - the shape M3's
     * brisk_cfg will make easy to write. It means "no pin can ever match", so every path fails
     * the additive test and the connection is refused; it must not mean memcmp(h, NULL, 32). */
    if (c->spki == NULL || t->pins == NULL) {
        return 0;
    }
    brisk_sha256(c->spki, c->spki_len, h);
    for (i = 0; i < t->n_pins; i++) {
        if (memcmp(h, t->pins[i], sizeof h) == 0) {
            return 1;
        }
    }
    return 0;
}

int brisk__x509_chain_verify(const brisk__x509_cert *certs, size_t n_certs, int64_t now,
                             const brisk__x509_trust *trust)
{
    static const brisk__x509_trust empty = {NULL, NULL, NULL, 0};
    const brisk__x509_cert *cur;
    size_t depth, below = 0, work = 0;
    int pin_hit;

    if (certs == NULL || n_certs == 0) {
        return BRISK_E_ARG;
    }
    if (trust == NULL) {
        trust = &empty;
    }
    cur = &certs[0];
    /* With no pins configured every path is "pinned" from the start, so the one test at the
     * anchor below covers both worlds and nothing hashes anything it did not have to. */
    pin_hit = trust->n_pins == 0 || pinned(trust, cur);
    /* 6.1.3 (a)(2) for the end entity. Every other certificate of the path is checked below, as
     * a condition for being CHOSEN as the parent - never after the walk has committed to it.
     * That distinction is the whole difference between refusing an expired chain and refusing a
     * chain that has an in-date path through it: a CA that re-issues an intermediate under the
     * same Name and the same key (a rollover, and the shape of every cross-certificate incident
     * this file already worries about) leaves BOTH on the wire, and the expired one is often
     * first. Checked as a filter, the walk skips it and takes the live one; checked one level
     * later, the walk would have thrown the live one away by then. It also means an expired
     * candidate costs no public-key operation and no verify budget. */
    if (brisk__x509_time_ok(cur, now) != BRISK_OK) {
        return BRISK_E_AUTH;
    }
    for (depth = 0; depth < BRISK__X509_MAX_CHAIN; depth++) {
        const brisk__x509_cert *parent = NULL;
        brisk__x509_cert anchor;
        size_t i;

        /* Trust anchors first, which is what makes a stale cross-certificate at the end of the
         * peer's list harmless: the path stops here and the tail is never looked at. */
        for (i = 0; trust->find_anchor != NULL && i < BRISK__X509_MAX_ANCHORS; i++) {
            if (trust->find_anchor(trust->anchor_ctx, cur->issuer, cur->issuer_len, i, &anchor) !=
                BRISK_OK) {
                break;
            }
            /* 6.1.3 (a)(4) is checked here and not left to the store: a lookup that buckets
             * by a hash of the Name, or one that just enumerates its roots, must not be able to
             * hand back an anchor whose subject is not the issuer that was asked for. */
            if (!name_eq(cur->issuer, cur->issuer_len, anchor.subject, anchor.subject_len)) {
                continue;
            }
            if (!usable_ca(&anchor, below, 1)) {
                continue;
            }
            if (++work > BRISK__X509_MAX_VERIFY) {
                return BRISK_E_AUTH;
            }
            if (brisk__x509_signed_by(cur, &anchor) != BRISK_OK) {
                continue;
            }
            if (pin_hit || pinned(trust, &anchor)) {
                return BRISK_OK;
            }
            /* A complete, verified path that satisfies no pin is NOT the verdict - it is one
             * candidate that failed a selection predicate, exactly like an expired sibling
             * above. Keep walking: the shape this is here for is a cross-signed rollover, where
             * the peer also ships the old root under the NEW root's signature, and the longer
             * path through it ends at the anchor the pin names. Returning here would refuse a
             * chain the device was given every certificate for.
             *
             * HOW FAR THAT GOES, precisely, because it is less far than it looks: this recovers
             * the longer path only when every level BELOW has one candidate. The peer loop
             * below still commits to the first certificate that verifies and never revisits it
             * (the "no backtracking ACROSS levels" limit in the brisk_int.h block), so a
             * rollover that ALSO ships two same-Name intermediates - one chaining to the old
             * root, one to the pinned new one - is refused if the old one arrives first, which
             * on the wire it does. Pins make that reachable far more often than plain chain
             * building did, because a pin miss now forces the walk down here at a depth where
             * it used to return. The fix is a depth-first search with a resume index per level,
             * bounded by BRISK__X509_MAX_VERIFY as this already is; it is its own ROADMAP line
             * because it changes path construction for every chain, not just pinned ones.
             * Until then the failure is closed and loud: a connection that does not build. */
        }

        /* Then the certificates the peer supplied, in whatever order they arrived. Every
         * candidate that carries the right Name is tried, so two intermediates sharing one - a
         * key rollover - do not depend on which came first.
         *
         * This level is re-scanned at every depth, so without a cap a peer that sent n
         * plausible same-Name candidates would cost BRISK__X509_MAX_CHAIN * n public-key
         * verifications - tens of seconds of pre-auth CPU on an armv5 router at 4096-bit RSA,
         * from one handshake. BRISK__X509_MAX_VERIFY bounds the total instead, because n
         * belongs to the peer and this function is documented as safe on peer input. */
        for (i = 1; i < n_certs; i++) {
            const brisk__x509_cert *p = &certs[i];
            if (p == cur || !name_eq(cur->issuer, cur->issuer_len, p->subject, p->subject_len)) {
                continue;
            }
            if (!usable_ca(p, below, 0) || brisk__x509_time_ok(p, now) != BRISK_OK) {
                continue; /* (k)(l)(m)(n) and (a)(2), all of them selection predicates */
            }
            if (++work > BRISK__X509_MAX_VERIFY) {
                return BRISK_E_AUTH;
            }
            if (brisk__x509_signed_by(cur, p) == BRISK_OK) {
                parent = p;
                break;
            }
        }
        if (parent == NULL) {
            return BRISK_E_AUTH;
        }
        if (!self_issued(parent)) {
            below++; /* (l): the parent now stands between the next one and the end entity */
        }
        cur = parent;
        /* Only now, with the walk committed to this parent, does its key count towards the
         * pins: a candidate that was tried and rejected is on no path, and neither is a
         * certificate the peer attached that the walk never chose. */
        if (!pin_hit && pinned(trust, cur)) {
            pin_hit = 1;
        }
    }
    return BRISK_E_AUTH; /* BRISK__X509_MAX_CHAIN levels and still no anchor */
}
