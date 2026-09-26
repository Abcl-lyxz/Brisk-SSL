/* key.c - the device's P-256 private key out of what an integrator actually has on disk.
 *
 * cfg.client_key used to be the bare 32-byte scalar, which nobody has: openssl, AWS IoT, Azure
 * DPS and every CA portal hand out a PEM file, SEC1 ("EC PRIVATE KEY") or PKCS#8 ("PRIVATE
 * KEY"), and converting it by hand is exactly the kind of step that ships a wrong key. This
 * reads the raw scalar, both DER structures and both PEM labels, once, at connection setup, and
 * refuses everything else loudly: other curves, encrypted keys, BER, trailing bytes, a public
 * key that is not keygen(d). The rules are on brisk__x509_p256_key in src/brisk_int.h.
 *
 * SECRETS: d, and every copy of it (the output on failure, the PEM decode buffer on every path)
 * is wiped; the DER cursors hold only pointers into those. The DER framing (tags, lengths, OIDs)
 * is public structure; d itself only ever meets memcpy and the constant-time keygen.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_MTLS

/* RFC 5480 2.1.1 / 2.1.1.1: id-ecPublicKey and secp256r1 (prime256v1), the value octets of
 * the OBJECT IDENTIFIERs. KEY_-prefixed: cert.c has its own OID_* statics (amalgamation). */
static const uint8_t KEY_OID_EC[7] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t KEY_OID_P256[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

#    define KEY_PEM_CAP 256 /* the largest key in use is a 138-byte PKCS#8 v2 */
#    define KEY_ANY     0   /* DER: SEC1 or PKCS#8, told apart by what follows the version */
#    define KEY_SEC1    1   /* "EC PRIVATE KEY" */
#    define KEY_PKCS8   2   /* "PRIVATE KEY" */

static int key_oid(brisk__der *c, const uint8_t *want, size_t want_len)
{
    const uint8_t *v;
    size_t n;
    if (brisk__der_oid(c, &v, &n) != BRISK_OK) {
        return 0;
    }
    if (n != want_len || memcmp(v, want, n) != 0) {
        brisk__der_fail(c);
        return 0;
    }
    return 1;
}

/* An ECPrivateKey (RFC 5915 3) from privateKey on - the caller has read version 1 - into d, with
 * pub = keygen(d). standalone: SEC1 on its own, where the [0] parameters "MUST always" be there;
 * inside PKCS#8 the curve is in the algorithm identifier and OpenSSL omits [0]. */
static int key_ec(brisk__der *s, uint8_t d[32], uint8_t pub[65], int standalone)
{
    brisk__der t;
    const uint8_t *v;
    size_t n;
    unsigned unused;

    /* privateKey = I2OSP(d, ceiling(log2(n)/8)): exactly 32 octets. A 31-octet key from an
     * encoder that stripped a leading zero is refused too (re-export it with openssl pkey). */
    if (brisk__der_value(s, BRISK__DER_OCTET_STRING, &v, &n) != BRISK_OK || n != 32) {
        return 0;
    }
    memcpy(d, v, 32);
    BRISK__CT_SECRET(d, 32); /* the PEM path declassified its framing; d stays secret */
    /* 1 <= d <= n-1 is keygen's own check, constant time; its verdict alone is declassified */
    if (brisk__p256_keygen(pub, d) != BRISK_OK) {
        return 0;
    }
    BRISK__CT_PUBLIC(pub, 65); /* the public key: compared with memcmp below */
    if (brisk__der_peek(s) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0)) {
        /* RFC 5480 2.1.1: namedCurve only - implicitCurve (NULL) and specifiedCurve fail the
         * OID read */
        brisk__der_enter(s, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0, &t);
        key_oid(&t, KEY_OID_P256, sizeof KEY_OID_P256);
        brisk__der_close(s, &t);
    } else if (standalone) {
        return 0;
    }
    if (brisk__der_peek(s) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 1)) {
        /* RFC 5480 2.2: the uncompressed 0x04 || X || Y, and it must be OUR point */
        brisk__der_enter(s, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 1, &t);
        if (brisk__der_bitstring(&t, &v, &n, &unused) == BRISK_OK &&
            (unused != 0 || n != 65 || memcmp(v, pub, 65) != 0)) {
            brisk__der_fail(&t);
        }
        brisk__der_close(s, &t);
    }
    return brisk__der_end(s) == BRISK_OK; /* unknown fields, [1] before [0] */
}

/* d from DER (form: KEY_ANY / KEY_SEC1 / KEY_PKCS8). The whole input is exactly one value. */
static int key_der(uint8_t d[32], const uint8_t *in, size_t len, int form)
{
    brisk__der top, s, t, e;
    uint8_t pub[65];
    const uint8_t *v;
    size_t n;
    uint32_t ver, iver;
    int ok = 0;

    /* the cursor trusts a prior walk (brisk_int.h): DER only, also in what is skipped */
    if (brisk__der_walk(in, len) != BRISK_OK) {
        return 0;
    }
    brisk__der_init(&top, in, len);
    if (brisk__der_enter(&top, BRISK__DER_SEQUENCE, &s) != BRISK_OK ||
        brisk__der_end(&top) != BRISK_OK || brisk__der_uint(&s, &ver) != BRISK_OK) {
        return 0;
    }
    if (brisk__der_peek(&s) == BRISK__DER_OCTET_STRING && form != KEY_PKCS8) {
        /* SEC1: version ecPrivkeyVer1. An EncryptedPrivateKeyInfo (RFC 5958 3) never gets
         * here: its first field is a SEQUENCE, so the INTEGER read above failed. */
        return ver == 1 && key_ec(&s, d, pub, 1);
    }
    /* PKCS#8 / OneAsymmetricKey (RFC 5958 2): v1(0) or v2(1) */
    if (form == KEY_SEC1 || ver > 1 || brisk__der_enter(&s, BRISK__DER_SEQUENCE, &t) != BRISK_OK) {
        return 0;
    }
    if (!key_oid(&t, KEY_OID_EC, sizeof KEY_OID_EC) ||
        !key_oid(&t, KEY_OID_P256, sizeof KEY_OID_P256) || brisk__der_close(&s, &t) != BRISK_OK ||
        brisk__der_value(&s, BRISK__DER_OCTET_STRING, &v, &n) != BRISK_OK) {
        return 0;
    }
    /* "an ECC key is represented as ECPrivateKey as defined in RFC 5915" (RFC 5958 2) */
    if (brisk__der_walk(v, n) != BRISK_OK) { /* an OCTET STRING is a leaf to the outer walk */
        return 0;
    }
    brisk__der_init(&top, v, n);
    if (brisk__der_enter(&top, BRISK__DER_SEQUENCE, &e) == BRISK_OK &&
        brisk__der_end(&top) == BRISK_OK && brisk__der_uint(&e, &iver) == BRISK_OK && iver == 1 &&
        key_ec(&e, d, pub, 0)) {
        if (brisk__der_peek(&s) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0)) {
            brisk__der_skip(&s); /* attributes [0] IMPLICIT SET */
        }
        if (brisk__der_peek(&s) == (BRISK__DER_CONTEXT | 1)) {
            /* publicKey [1] IMPLICIT BIT STRING: "If publicKey is present, then version is set
             * to v2" - and it must be keygen(d) too */
            if (brisk__der_value(&s, BRISK__DER_CONTEXT | 1, &v, &n) == BRISK_OK &&
                (ver != 1 || n != 66 || v[0] != 0 || memcmp(v + 1, pub, 65) != 0)) {
                brisk__der_fail(&s);
            }
        }
        ok = brisk__der_end(&s) == BRISK_OK;
    }
    return ok;
}

int brisk__x509_p256_key(uint8_t d[32], const uint8_t *in, size_t len)
{
    static const char LABEL[2][15] = {"EC PRIVATE KEY", "PRIVATE KEY"}; /* rodata, no RAM */
    uint8_t buf[KEY_PEM_CAP];
    size_t off, n, found = 0;
    int ok = 0, i, form = 0;

    if (d == NULL) {
        return BRISK_E_ARG;
    }
    if (in == NULL) {
        ok = 0;
    } else if (len == 32) {
        uint8_t pub[65];
        memcpy(d, in, 32);
        ok = brisk__p256_keygen(pub, d) == BRISK_OK; /* 1 <= d <= n-1, constant time */
        brisk__secure_zero(pub, sizeof pub);
    } else if (len != 0 && in[0] == BRISK__DER_SEQUENCE) {
        ok = key_der(d, in, len, KEY_ANY);
    } else {
        /* PEM (RFC 7468 10 / OpenSSL's "EC PRIVATE KEY"): exactly ONE key block across both
         * labels, every key-labelled block well formed. Blocks with other labels - the "EC
         * PARAMETERS" openssl ecparam writes first, the certificate of a combined .pem - are
         * skipped. Pass 1 validates and counts without writing anything. */
        ok = 1;
        for (i = 0; i < 2 && ok; i++) {
            off = 0;
            do {
                if (brisk__x509_pem_block(in, len, &off, LABEL[i], NULL, 0, &n) != BRISK_OK) {
                    ok = 0;
                } else if (n != 0) {
                    found++;
                    form = i + 1;
                }
            } while (ok && n != 0);
        }
        off = 0;
        if (ok && found == 1 &&
            brisk__x509_pem_block(in, len, &off, LABEL[form - 1], buf, sizeof buf, &n) ==
                BRISK_OK) {
            /* The DER framing inside is public structure (the base64 decode above was the
             * constant-time part); key_ec marks d secret again, so keygen stays checked. */
            BRISK__CT_PUBLIC(buf, n);
            ok = key_der(d, buf, n, form);
        } else {
            ok = 0;
        }
        brisk__secure_zero(buf, sizeof buf);
    }
    if (!ok) {
        brisk__secure_zero(d, 32);
        return BRISK_E_ARG;
    }
    return BRISK_OK;
}

#    undef KEY_PEM_CAP
#    undef KEY_ANY
#    undef KEY_SEC1
#    undef KEY_PKCS8
#endif /* BRISK_ENABLE_MTLS */
