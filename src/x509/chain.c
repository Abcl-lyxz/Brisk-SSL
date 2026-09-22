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

/* One pin bit per path level plus the bit-31 marker has to fit in the uint32_t below. The
 * failure this stops is silent and fail-OPEN - at MAX_CHAIN 32 the top level's bit IS the
 * marker - and the constant sits in another file with a comment inviting people to tune it. */
typedef char brisk__chain_pin_bits_fit[BRISK__X509_MAX_CHAIN <= 31 ? 1 : -1];

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
    /* The path under construction. chosen[d] is the parent taken at depth d, and it is BOTH
     * halves of the search state: it is the path, and because it points into certs[] its index
     * plus one is where depth d's scan resumes when everything above it dead-ends. That is why
     * there is no separate resume array - the stack budget in brisk_int.h has no room for one,
     * and a second array would be a second thing to keep in step. */
    const brisk__x509_cert *chosen[BRISK__X509_MAX_CHAIN];
    const brisk__x509_cert *cur;
    /* Bit d: chosen[d]'s SubjectPublicKeyInfo matched a pin. Bit 31 is the end entity's, and
     * doubles as the "no pins configured" marker, so `pin_mask != 0` is the one question the
     * anchor test asks in both worlds. A mask and not a flag because backtracking has to UNDO
     * what a parent it is abandoning contributed, and a bool cannot be un-set. */
    uint32_t pin_mask;
    size_t depth = 0, resume = 1, below = 0, work = 0, lookups = 0;

    if (certs == NULL || n_certs == 0) {
        return BRISK_E_ARG;
    }
    if (trust == NULL) {
        trust = &empty;
    }
    cur = &certs[0];
    /* 6.1.3 (a)(2) for the end entity. Every other certificate of the path is checked below, as
     * a condition for being CHOSEN as the parent - never after the search has committed to it.
     * That distinction is the whole difference between refusing an expired chain and refusing a
     * chain that has an in-date path through it: a CA that re-issues an intermediate under the
     * same Name and the same key (a rollover, and the shape of every cross-certificate incident
     * this file already worries about) leaves BOTH on the wire, and the expired one is often
     * first. Checked as a filter, the search skips it and takes the live one. It also means an
     * expired candidate costs no public-key operation and no verify budget. */
    if (brisk__x509_time_ok(cur, now) != BRISK_OK) {
        return BRISK_E_AUTH;
    }
    pin_mask = (trust->n_pins == 0 || pinned(trust, cur)) ? 0x80000000u : 0;

    for (;;) {
        const brisk__x509_cert *parent = NULL;
        size_t i;

        /* Trust anchors first, which is what makes a stale cross-certificate at the end of the
         * peer's list harmless: the path stops here and the tail is never looked at.
         *
         * The depth bound is on this block as well as on the descent below, and that is what
         * makes BRISK__X509_MAX_CHAIN mean "end entity + 7 certificates" rather than "+ 8": a
         * path that needs an anchor above the last certificate the bound allows is one
         * certificate too long, and it has to fail rather than be rescued by an anchor lookup
         * the bound never budgeted for.
         *
         * Only on FIRST arrival at this depth (resume == 1). Coming back here from a dead end
         * above means these same anchors were already tried against this same `cur`, under a
         * pin_mask that can only have been larger - so re-asking the store would buy nothing
         * and would spend the verify budget twice for it.
         *
         * And at most BRISK__X509_MAX_LOOKUPS times in the whole search, which is a budget of
         * its own because the other two do not cover this one. Depth used to: the anchor block
         * lived inside a loop that ran BRISK__X509_MAX_CHAIN times, so a handshake could ask
         * the store at most 8 * MAX_ANCHORS times. Backtracking runs it once per fresh DESCENT
         * instead, and descents are capped by MAX_VERIFY, so the ceiling would quietly become
         * 33 * MAX_ANCHORS - and a store lookup is NOT paid for out of the verify budget,
         * because a candidate refused by name_eq or usable_ca never reaches ++work. That is
         * not academic with the CA bundle behind it: one miss is an open() and a full pass over
         * ~200 KB of PEM, and a peer that sends ~40 certificates which all sign the leaf and
         * all name an issuer nobody has would buy itself 33 of those for one handshake, on a
         * 200 MHz router, before authenticating anything. */
        if (resume == 1 && depth < BRISK__X509_MAX_CHAIN && ++lookups <= BRISK__X509_MAX_LOOKUPS) {
            brisk__x509_cert anchor;
            for (i = 0; trust->find_anchor != NULL && i < BRISK__X509_MAX_ANCHORS; i++) {
                if (trust->find_anchor(trust->anchor_ctx, cur->issuer, cur->issuer_len, i,
                                       &anchor) != BRISK_OK) {
                    break;
                }
                /* 6.1.3 (a)(4) is checked here and not left to the store: a lookup that buckets
                 * by a hash of the Name, or one that just enumerates its roots, must not be able
                 * to hand back an anchor whose subject is not the issuer that was asked for. */
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
                if (pin_mask != 0 || pinned(trust, &anchor)) {
                    return BRISK_OK;
                }
                /* A complete, verified path that satisfies no pin is NOT the verdict - it is one
                 * candidate that failed a selection predicate, exactly like an expired sibling.
                 * Fall through and keep searching: the shape this is here for is a cross-signed
                 * rollover, where the peer also ships the old root under the NEW root's
                 * signature and the longer path through it ends at the anchor the pin names.
                 * Returning here would refuse a chain the device holds every certificate for. */
            }
        }

        /* Then the certificates the peer supplied: from 1 on the way down, from one past the
         * candidate being abandoned on the way back up. Every candidate carrying the right Name
         * is tried, so two intermediates sharing one - a key rollover - do not depend on which
         * came first, and a wrong first pick is no longer fatal, because the search returns.
         *
         * A level is re-scanned at every depth and now once per backtrack as well, so without a
         * cap a peer that sent n plausible same-Name candidates could cost a multiple of n
         * public-key verifications - tens of seconds of pre-auth CPU on an armv5 router at
         * 4096-bit RSA, from one handshake. BRISK__X509_MAX_VERIFY bounds the total instead,
         * and it bounds the SEARCH with it: every descent costs at least one verification, so
         * the number of paths explored cannot outrun the budget however the peer shapes its
         * list. */
        if (depth < BRISK__X509_MAX_CHAIN) {
            for (i = resume; i < n_certs; i++) {
                const brisk__x509_cert *p = &certs[i];
                if (p == cur ||
                    !name_eq(cur->issuer, cur->issuer_len, p->subject, p->subject_len)) {
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
        }

        if (parent != NULL) { /* descend */
            chosen[depth] = parent;
            if (!self_issued(parent)) {
                below++; /* (l): the parent now stands between the next one and the end entity */
            }
            /* Only now, with the search committed to this parent, does its key count towards the
             * pins: a candidate that was tried and rejected is on no path, and neither is a
             * certificate the peer attached that the search never chose. */
            if (trust->n_pins != 0 && pinned(trust, parent)) {
                pin_mask |= (uint32_t)1 << depth;
            }
            cur = parent;
            depth++;
            resume = 1;
            continue;
        }

        /* Dead end: no anchor above `cur` and no untried candidate either. Back up one level and
         * resume that level's scan just past the certificate being given up, undoing everything
         * it contributed on the way down. Depth 0 has nothing below it, so that is where the
         * SEARCH fails rather than just this branch of it. */
        if (depth == 0) {
            return BRISK_E_AUTH;
        }
        depth--;
        resume = (size_t)(chosen[depth] - certs) + 1;
        if (!self_issued(chosen[depth])) {
            below--;
        }
        /* (uint32_t)1 and not 1u: on a target with a 16-bit int the complement of an
         * unsigned int would be computed at 16 bits and zero-extended, clearing bit 31 - the
         * "no pins configured" marker - so every unpinned chain would start failing the moment
         * the search backtracked once. None of the ten targets has one; it costs nothing to
         * stop the coupling existing. */
        pin_mask &= ~((uint32_t)1 << depth);
        cur = depth == 0 ? &certs[0] : chosen[depth - 1];
    }
}
