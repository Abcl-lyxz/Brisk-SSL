/* cert.c - parse one X.509 certificate (RFC 5280). What is rejected and why, and the contract
 * of every field, is documented in the brisk__x509_cert block of src/brisk_int.h.
 *
 * The shape follows der.c: read with a sticky cursor, let the errors accumulate, check once at
 * the end. A semantic rejection - a version that is out of range, a DEFAULT that was encoded
 * anyway - is reported by failing the cursor it was read from, so it travels the same path as a
 * malformed length and no caller has to distinguish the two.
 *
 * Every OBJECT IDENTIFIER below is checked against its dotted form by
 * check_x509_source_constants() in tools/kat.py, the same guard the P-256 parameters and the
 * PKCS#1 DigestInfo prefixes get. None of them was typed from memory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

struct x509_oid {
    uint8_t len;
    uint8_t v[9];
};

/* RFC 4055 1.2 / 5: keys and PKCS#1 v1.5 signatures under 1.2.840.113549.1.1 */
static const struct x509_oid OID_RSA = {9, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}};
static const struct x509_oid OID_RSA_PSS = {9,
                                            {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a}};
/* id-mgf1, RFC 4055 2.2 */
static const struct x509_oid OID_MGF1 = {9, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08}};
static const struct x509_oid OID_RSA_SHA256 = {
    9, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}};
static const struct x509_oid OID_RSA_SHA384 = {
    9, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c}};
static const struct x509_oid OID_RSA_SHA512 = {
    9, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d}};
/* RFC 5480 2.1.1 keys, RFC 5758 3.2 signatures, under 1.2.840.10045 */
static const struct x509_oid OID_EC_KEY = {7, {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}};
static const struct x509_oid OID_P256 = {8, {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}};
static const struct x509_oid OID_ECDSA_SHA256 = {8,
                                                 {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}};
static const struct x509_oid OID_ECDSA_SHA384 = {8,
                                                 {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}};
static const struct x509_oid OID_ECDSA_SHA512 = {8,
                                                 {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}};
#if BRISK_ENABLE_P384
static const struct x509_oid OID_P384 = {5, {0x2b, 0x81, 0x04, 0x00, 0x22}}; /* 1.3.132.0.34 */
#endif
/* NIST hashes, 2.16.840.1.101.3.4.2.x (RFC 4055 2.1) */
static const struct x509_oid OID_SHA256 = {9,
                                           {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}};
static const struct x509_oid OID_SHA384 = {9,
                                           {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}};
static const struct x509_oid OID_SHA512 = {9,
                                           {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}};
/* id-ce extensions, 2.5.29.x (RFC 5280 4.2.1) */
static const struct x509_oid OID_KEY_USAGE = {3, {0x55, 0x1d, 0x0f}};    /* 4.2.1.3  */
static const struct x509_oid OID_SAN = {3, {0x55, 0x1d, 0x11}};          /* 4.2.1.6  */
static const struct x509_oid OID_BASIC_CONSTR = {3, {0x55, 0x1d, 0x13}}; /* 4.2.1.9  */
static const struct x509_oid OID_EKU = {3, {0x55, 0x1d, 0x25}};          /* 4.2.1.12 */
static const struct x509_oid OID_EKU_ANY = {4, {0x55, 0x1d, 0x25, 0x00}};
/* id-kp, 1.3.6.1.5.5.7.3.x (RFC 5280 4.2.1.12) */
static const struct x509_oid OID_KP_SERVER = {8, {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01}};
static const struct x509_oid OID_KP_CLIENT = {8, {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}};

static int oid_is(const uint8_t *v, size_t len, const struct x509_oid *o)
{
    return v != NULL && len == o->len && memcmp(v, o->v, len) == 0;
}

/* ---------------------------------------------------------------------------- time -------- */

static int two_digits(const uint8_t *p, int *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') {
        return 0;
    }
    *out = (p[0] - '0') * 10 + (p[1] - '0');
    return 1;
}

static int days_in_month(int y, int m)
{
    static const uint8_t DAYS[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) {
        return 29;
    }
    return DAYS[m - 1];
}

/* Days from 1970-01-01 to y-m-d, by Howard Hinnant's civil-from-days inverse. Everything stays
 * in int: y is 1950..9999 here, so era * 146097 peaks at 3.5 million and nothing comes close to
 * overflowing - which also keeps the whole calendar free of the 64-bit division that
 * tools/dev.py size forbids. */
static int32_t days_from_civil(int y, int m, int d)
{
    int era, yoe, doy, doe;

    y -= (m <= 2); /* March-based year: the leap day lands at the end */
    era = y / 400;
    yoe = y - era * 400;                                   /* [0, 399] */
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1; /* [0, 365] */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           /* [0, 146096] */
    return (int32_t)(era * 146097 + doe - 719468);
}

int brisk__x509_time(unsigned tag, const uint8_t *v, size_t len, int64_t *out)
{
    int y = 0, century, mo, d, h, mi, s;
    size_t need, i;

    *out = 0;
    if (tag == (unsigned)BRISK__DER_UTC_TIME) {
        need = 13; /* YYMMDDHHMMSSZ: 4.1.2.5.1 makes both the seconds and the Z mandatory */
    } else if (tag == (unsigned)BRISK__DER_GENERALIZED_TIME) {
        need = 15; /* YYYYMMDDHHMMSSZ: 4.1.2.5.2, and no fractional part is allowed */
    } else {
        return BRISK_E_ARG;
    }
    if (len != need || v[len - 1] != 'Z') {
        return BRISK_E_ARG;
    }
    if (need == 15) {
        if (!two_digits(v, &century) || !two_digits(v + 2, &y)) {
            return BRISK_E_ARG;
        }
        y += century * 100;
        i = 4;
    } else {
        if (!two_digits(v, &y)) {
            return BRISK_E_ARG;
        }
        y += (y < 50) ? 2000 : 1900; /* 4.1.2.5.1: YY < 50 is 20YY, otherwise 19YY */
        i = 2;
    }
    if (!two_digits(v + i, &mo) || !two_digits(v + i + 2, &d) || !two_digits(v + i + 4, &h) ||
        !two_digits(v + i + 6, &mi) || !two_digits(v + i + 8, &s)) {
        return BRISK_E_ARG;
    }
    /* 1950 is where UTCTime's sliding window starts, 9999 is where GeneralizedTime stops. A
     * leap second (s == 60) is refused: ASN.1 allows it, no CA has ever issued one, and
     * accepting it would mean two encodings of one instant. */
    if (y < 1950 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > days_in_month(y, mo) || h > 23 ||
        mi > 59 || s > 59) {
        return BRISK_E_ARG;
    }
    *out = (int64_t)days_from_civil(y, mo, d) * 86400 + (h * 3600 + mi * 60 + s);
    return BRISK_OK;
}

/* One Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime } (RFC 5280 4.1.2.5). */
static void read_time(brisk__der *c, int64_t *out)
{
    const uint8_t *v;
    size_t n;
    int tag = brisk__der_peek(c);

    if (tag != BRISK__DER_UTC_TIME && tag != BRISK__DER_GENERALIZED_TIME) {
        brisk__der_fail(c);
        return;
    }
    if (brisk__der_value(c, (unsigned)tag, &v, &n) != BRISK_OK) {
        return;
    }
    if (brisk__x509_time((unsigned)tag, v, n, out) != BRISK_OK) {
        brisk__der_fail(c);
    }
}

/* ------------------------------------------------------------------- algorithms ----------- */

/* A HashAlgorithm inside RSASSA-PSS-params. RFC 4055 2.1 requires implementations to accept a
 * SHA identifier with the parameters absent as well as with NULL, so both are taken. */
static int read_hash_alg(brisk__der *c)
{
    brisk__der alg;
    const uint8_t *oid;
    size_t oid_len;
    int h = 0;

    brisk__der_enter(c, BRISK__DER_SEQUENCE, &alg);
    brisk__der_oid(&alg, &oid, &oid_len);
    if (oid_is(oid, oid_len, &OID_SHA256)) {
        h = BRISK_HASH_SHA256;
    } else if (oid_is(oid, oid_len, &OID_SHA384)) {
        h = BRISK_HASH_SHA384;
    } else if (oid_is(oid, oid_len, &OID_SHA512)) {
        h = BRISK_HASH_SHA512;
    } else {
        brisk__der_fail(&alg); /* SHA-1 and everything else: RFC 9325 4.5 */
    }
    if (brisk__der_peek(&alg) == BRISK__DER_NULL) {
        brisk__der_null(&alg);
    }
    brisk__der_close(c, &alg);
    return h;
}

/* RSASSA-PSS-params, RFC 4055 3.1. Every field has a DEFAULT and every default is a SHA-1 one,
 * so a conforming encoder omits whatever it can - X.690 11.5 requires it and RFC 4055 3.1 makes
 * omitting trailerField a MUST for signers, which means the four-fields-present form this parser
 * first demanded is the one shape no CA emits. A validator instead has to take all four absent:
 * 3.1 says so in as many words for hashAlgorithm ("MUST recognize ... an absent hashAlgorithm
 * field"), maskGenAlgorithm ("MUST accept both the default value encoding (i.e., an absent
 * field) and mfg1SHA1Identifier to be explicitly present") and trailerField ("MUST recognize
 * both a present trailerField field with value 1 and an absent trailerField field").
 *
 * An absent field is therefore read as its default and refused by the policy below, not by its
 * absence. A trailerField that IS present is accepted at value 1, because 3.1 tells validators
 * to recognise it - this is the one place where X.690 11.5 is deliberately not enforced, and it
 * is safe because 1 is the only legal value, so the two encodings cannot mean different things
 * the way an explicit cA FALSE could. */
static void read_pss_params(brisk__der *c, brisk__x509_cert *out)
{
    brisk__der p, f, mgf;
    const uint8_t *oid;
    size_t oid_len;
    uint32_t salt = 20, trailer = 1; /* the DEFAULTs of RFC 4055 3.1 */
    int mgf_hash = 0;                /* 0 stands for the SHA-1 default, which is refused below */

    out->sig_hash = 0;
    brisk__der_enter(c, BRISK__DER_SEQUENCE, &p);

    if (brisk__der_peek(&p) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0)) {
        brisk__der_enter(&p, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0, &f);
        out->sig_hash = (uint8_t)read_hash_alg(&f);
        brisk__der_close(&p, &f);
    }
    if (brisk__der_peek(&p) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 1)) {
        brisk__der_enter(&p, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 1, &f);
        brisk__der_enter(&f, BRISK__DER_SEQUENCE, &mgf);
        brisk__der_oid(&mgf, &oid, &oid_len);
        if (!oid_is(oid, oid_len, &OID_MGF1)) {
            brisk__der_fail(&mgf);
        }
        mgf_hash = read_hash_alg(&mgf);
        brisk__der_close(&f, &mgf);
        brisk__der_close(&p, &f);
    }
    if (brisk__der_peek(&p) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 2)) {
        brisk__der_enter(&p, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 2, &f);
        brisk__der_uint(&f, &salt);
        brisk__der_close(&p, &f);
    }
    if (brisk__der_peek(&p) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 3)) {
        brisk__der_enter(&p, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 3, &f);
        brisk__der_uint(&f, &trailer);
        brisk__der_close(&p, &f);
    }

    /* sig_hash stays 0 when hashAlgorithm was absent, i.e. SHA-1 (RFC 9325 4.5: "SHA-1 or MD5
     * MUST NOT be used"). mgf_hash must equal it, which also catches an absent maskGenAlgorithm,
     * because RFC 9846 4.3.3 pairs one hash with its own MGF1 and brisk__rsa_pss_verify takes a
     * single `alg` for both. RFC 4055 3.1: trailerField's "value MUST be 1". The salt is capped
     * so it fits the field; brisk__rsa_pss_verify range-checks it against the modulus. */
    if (out->sig_hash == 0 || mgf_hash != (int)out->sig_hash || trailer != 1 || salt > 255) {
        brisk__der_fail(&p);
    }
    out->sig_salt_len = (uint8_t)salt;
    brisk__der_close(c, &p);
}

/* AlgorithmIdentifier for a signature: the `signature` field of the TBS (4.1.2.3) and the outer
 * signatureAlgorithm (4.1.1.2) are both this. */
static void read_sig_alg(brisk__der *c, brisk__x509_cert *out)
{
    brisk__der alg;
    const uint8_t *oid;
    size_t oid_len;

    brisk__der_enter(c, BRISK__DER_SEQUENCE, &alg);
    brisk__der_oid(&alg, &oid, &oid_len);
    if (oid_is(oid, oid_len, &OID_RSA_SHA256) || oid_is(oid, oid_len, &OID_RSA_SHA384) ||
        oid_is(oid, oid_len, &OID_RSA_SHA512)) {
        out->sig_alg = BRISK__X509_SIG_RSA_PKCS1;
        out->sig_hash = (uint8_t)(oid_is(oid, oid_len, &OID_RSA_SHA256)   ? BRISK_HASH_SHA256
                                  : oid_is(oid, oid_len, &OID_RSA_SHA384) ? BRISK_HASH_SHA384
                                                                          : BRISK_HASH_SHA512);
        /* RFC 4055 5: "the parameters MUST be NULL. Implementations MUST accept the
         * parameters being absent as well as present." The second sentence is a MUST on
         * the validating side, so an absent parameters field has to be taken here. */
        if (brisk__der_peek(&alg) == BRISK__DER_NULL) {
            brisk__der_null(&alg);
        }
    } else if (oid_is(oid, oid_len, &OID_ECDSA_SHA256) || oid_is(oid, oid_len, &OID_ECDSA_SHA384) ||
               oid_is(oid, oid_len, &OID_ECDSA_SHA512)) {
        out->sig_alg = BRISK__X509_SIG_ECDSA;
        out->sig_hash = (uint8_t)(oid_is(oid, oid_len, &OID_ECDSA_SHA256)   ? BRISK_HASH_SHA256
                                  : oid_is(oid, oid_len, &OID_ECDSA_SHA384) ? BRISK_HASH_SHA384
                                                                            : BRISK_HASH_SHA512);
        /* RFC 5758 3.2: "the parameters field MUST be absent" - brisk__der_close enforces it */
    } else if (oid_is(oid, oid_len, &OID_RSA_PSS)) {
        out->sig_alg = BRISK__X509_SIG_RSA_PSS;
        read_pss_params(&alg, out);
    } else {
        brisk__der_fail(&alg); /* SHA-1 (RFC 9325 4.5), DSA, GOST, Ed25519: not verifiable here */
    }
    brisk__der_close(c, &alg);
}

/* SubjectPublicKeyInfo, RFC 5280 4.1.2.7. */
static void read_spki(brisk__der *c, brisk__x509_cert *out)
{
    brisk__der spki, alg;
    const uint8_t *oid, *curve = NULL;
    size_t oid_len, curve_len = 0, want;
    unsigned unused = 0;

    brisk__der_enter(c, BRISK__DER_SEQUENCE, &spki);
    brisk__der_enter(&spki, BRISK__DER_SEQUENCE, &alg);
    brisk__der_oid(&alg, &oid, &oid_len);
    if (oid_is(oid, oid_len, &OID_RSA)) {
        out->key_alg = BRISK__X509_KEY_RSA;
        brisk__der_null(&alg); /* RFC 4055 1.2: the parameters MUST be NULL */
    } else if (oid_is(oid, oid_len, &OID_EC_KEY)) {
        brisk__der_oid(&alg, &curve, &curve_len); /* RFC 5480 2.1.1: a named curve, never
                                                     implicitCurve or specifiedCurve */
        if (oid_is(curve, curve_len, &OID_P256)) {
            out->key_alg = BRISK__X509_KEY_P256;
#if BRISK_ENABLE_P384
        } else if (oid_is(curve, curve_len, &OID_P384)) {
            out->key_alg = BRISK__X509_KEY_P384;
#endif
        } else {
            brisk__der_fail(&alg);
        }
    } else {
        brisk__der_fail(&alg);
    }
    brisk__der_close(&spki, &alg);
    brisk__der_bitstring(&spki, &out->key, &out->key_len, &unused);
    if (unused != 0) {
        brisk__der_fail(&spki);
    }
    /* An EC key is the uncompressed point of RFC 5480 2.2; the compressed forms are legal there
     * but neither p256.c nor p384.c decodes one, so refusing it here beats a decode failure
     * three layers up. RSA is left to brisk__rsa_*, which parse the RSAPublicKey themselves. */
    if (out->key_alg == BRISK__X509_KEY_P256 || out->key_alg == BRISK__X509_KEY_P384) {
        want = (out->key_alg == BRISK__X509_KEY_P256) ? 65u : 97u;
        if (out->key_len != want || out->key[0] != 0x04) {
            brisk__der_fail(&spki);
        }
    }
    brisk__der_close(c, &spki);
}

/* ------------------------------------------------------------------- extensions ----------- */

#define SEEN_BASIC_CONSTR 0x01u
#define SEEN_KEY_USAGE    0x02u
#define SEEN_SAN          0x04u
#define SEEN_EKU          0x08u
#define SEEN_SAN_CRITICAL 0x10u /* not an extension: 4.1.2.6 asks whether the SAN was critical */

static void read_basic_constraints(brisk__der *c, brisk__x509_cert *out)
{
    brisk__der body;
    uint32_t path = 0;
    int ca = 0;

    brisk__der_enter(c, BRISK__DER_SEQUENCE, &body);
    if (brisk__der_peek(&body) == BRISK__DER_BOOLEAN) {
        brisk__der_bool(&body, &ca);
        if (!ca) {
            brisk__der_fail(&body); /* X.690 11.5: cA DEFAULT FALSE must be omitted, not encoded */
        }
        out->is_ca = (uint8_t)(ca != 0);
    }
    if (brisk__der_peek(&body) == BRISK__DER_INTEGER) {
        brisk__der_uint(&body, &path);
        /* 4.2.1.9: "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is
         * asserted and the key usage extension asserts the keyCertSign bit". That companion
         * condition is checked once, after the whole extension list, because keyUsage may come
         * later in the SEQUENCE. */
        if (!out->is_ca || path > 32767u) {
            brisk__der_fail(&body);
        } else {
            out->path_len = (int16_t)path; /* only where the cast is defined (C99 6.3.1.3) */
        }
    }
    brisk__der_close(c, &body);
}

static void read_key_usage(brisk__der *c, brisk__x509_cert *out)
{
    const uint8_t *v;
    size_t n, i, bits;
    unsigned unused = 0;

    brisk__der_bitstring(c, &v, &n, &unused);
    if (brisk__der_err(c) != BRISK_OK) {
        return;
    }
    /* 4.2.1.3 defines exactly nine bits, and X.690 11.2.2 makes a NamedBitList drop every
     * trailing zero bit - so the last bit present is always 1 and the string is never longer
     * than nine bits. Bounding the LENGTH rather than the octet count is what makes
     * key_usage == 0 mean "extension absent" and nothing else: a two-octet string whose only
     * set bit is 9 or above satisfies 11.2.2, harvests nothing, and would otherwise hand the
     * chain code a zero it reads as "unrestricted". With the bound, "at least one of the bits
     * MUST be set to 1" (4.2.1.3) follows rather than needing its own test. */
    if (n == 0) {
        brisk__der_fail(c);
        return;
    }
    bits = n * 8 - unused;
    if (bits > 9 || (v[n - 1] & (0x80u >> (7 - unused))) == 0) {
        brisk__der_fail(c);
        return;
    }
    for (i = 0; i < bits; i++) {
        if (v[i / 8] & (0x80u >> (i % 8))) {
            out->key_usage |= (uint16_t)(1u << i);
        }
    }
}

static void read_eku(brisk__der *c, brisk__x509_cert *out)
{
    brisk__der list;
    const uint8_t *oid;
    size_t oid_len;

    brisk__der_enter(c, BRISK__DER_SEQUENCE, &list);
    if (brisk__der_peek(&list) == -1) {
        brisk__der_fail(&list); /* 4.2.1.12: ExtKeyUsageSyntax is SIZE (1..MAX) */
    }
    while (brisk__der_peek(&list) != -1) {
        brisk__der_oid(&list, &oid, &oid_len);
        if (oid_is(oid, oid_len, &OID_KP_SERVER)) {
            out->eku |= BRISK__X509_EKU_SERVER;
        } else if (oid_is(oid, oid_len, &OID_KP_CLIENT)) {
            out->eku |= BRISK__X509_EKU_CLIENT;
        } else if (oid_is(oid, oid_len, &OID_EKU_ANY)) {
            out->eku |= BRISK__X509_EKU_ANY;
        } else if (brisk__der_err(&list) == BRISK_OK) {
            out->eku |= BRISK__X509_EKU_OTHER;
        }
    }
    brisk__der_close(c, &list);
}

static void read_san(brisk__der *c, brisk__x509_cert *out)
{
    brisk__der names;

    brisk__der_enter(c, BRISK__DER_SEQUENCE, &names);
    if (brisk__der_peek(&names) == -1) {
        brisk__der_fail(c); /* 4.2.1.6: "the sequence MUST contain at least one entry" */
        return;
    }
    /* The entries stay encoded: matching them against a hostname is the RFC 9525 item's job,
     * and it needs the tags (dNSName [2] against iPAddress [7]) that a decode would throw away.
     * Note this does NOT close `names`: the whole point is to leave the entries unread. */
    out->san = names.p;
    out->san_len = (size_t)(names.end - names.p);
}

/* One Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
 * (RFC 5280 4.2). */
static void read_extension(brisk__der *exts, brisk__x509_cert *out, uint32_t *seen)
{
    brisk__der ext, body;
    const uint8_t *oid, *value;
    size_t oid_len, value_len;
    uint32_t bit = 0;
    int critical = 0;

    brisk__der_enter(exts, BRISK__DER_SEQUENCE, &ext);
    brisk__der_oid(&ext, &oid, &oid_len);
    if (brisk__der_peek(&ext) == BRISK__DER_BOOLEAN) {
        brisk__der_bool(&ext, &critical);
        if (!critical) {
            brisk__der_fail(&ext); /* X.690 11.5: critical DEFAULT FALSE must be omitted */
        }
    }
    brisk__der_value(&ext, BRISK__DER_OCTET_STRING, &value, &value_len);
    brisk__der_close(exts, &ext);
    if (brisk__der_err(exts) != BRISK_OK) {
        return;
    }

    if (oid_is(oid, oid_len, &OID_BASIC_CONSTR)) {
        bit = SEEN_BASIC_CONSTR;
    } else if (oid_is(oid, oid_len, &OID_KEY_USAGE)) {
        bit = SEEN_KEY_USAGE;
    } else if (oid_is(oid, oid_len, &OID_SAN)) {
        bit = SEEN_SAN;
    } else if (oid_is(oid, oid_len, &OID_EKU)) {
        bit = SEEN_EKU;
    } else if (critical) {
        /* 4.2: "A certificate-using system MUST reject the certificate if it encounters a
         * critical extension it does not recognize or a critical extension that contains
         * information that it cannot process." That deliberately includes name constraints,
         * policy constraints, certificate policies and inhibit anyPolicy, which this client
         * does not implement - refusing the certificate is the only safe reading. */
        brisk__der_fail(exts);
        return;
    } else {
        return; /* an unknown non-critical extension: 4.2 says it MAY be ignored */
    }

    /* The gate in brisk__x509_parse walked the certificate, but extnValue is an OCTET STRING and
     * brisk__der_walk treats one as an opaque leaf - so nothing has looked inside this yet. It
     * matters most for subjectAltName, whose entries are handed to the hostname matcher without
     * ever being read here: without this pass a dNSName carrying a BER length or the
     * high-tag-number form would reach it, which is exactly the parser differential the walk
     * exists to close. An unknown non-critical extension is left unwalked on purpose - it is
     * ignored, and 4.2 says it MAY be. */
    if (brisk__der_walk(value, value_len) != BRISK_OK) {
        brisk__der_fail(exts);
        return;
    }
    brisk__der_init(&body, value, value_len);
    if (bit == SEEN_BASIC_CONSTR) {
        read_basic_constraints(&body, out);
    } else if (bit == SEEN_KEY_USAGE) {
        read_key_usage(&body, out);
    } else if (bit == SEEN_SAN) {
        read_san(&body, out);
        if (critical) {
            *seen |= SEEN_SAN_CRITICAL; /* 4.1.2.6 needs this when the subject is empty */
        }
    } else {
        read_eku(&body, out);
    }
    /* extnValue holds exactly one DER value and nothing after it. */
    if (brisk__der_end(&body) != BRISK_OK) {
        brisk__der_fail(exts);
        return;
    }
    /* 4.2: "A certificate MUST NOT include more than one instance of a particular extension."
     * Only the four extensions above are tracked - a repeated keyUsage, basicConstraints,
     * subjectAltName or extendedKeyUsage. Two copies of one this client ignores change nothing
     * it decides, and a table of every OID seen would cost more than it buys; the residual risk
     * is a differential with a verifier that takes the first instance of such an extension. */
    if (*seen & bit) {
        brisk__der_fail(exts);
    }
    *seen |= bit;
}

/* ---------------------------------------------------------------------- certificate ------- */

int brisk__x509_parse(brisk__x509_cert *c, const uint8_t *der, size_t len)
{
    brisk__der top, cert, tbs, val, exts, wrap, scan;
    const uint8_t *tbs_alg, *outer_alg;
    size_t tbs_alg_len, outer_alg_len;
    uint32_t version = 0, seen = 0;
    unsigned unused = 0;
    int tag;

    memset(c, 0, sizeof *c);
    c->path_len = -1;
    c->version = 1;

    /* The gate. brisk__der_tlv and brisk__der_skip below validate only the header they step
     * over, so without this pass a BER body could ride along inside a field this parser keeps
     * but does not descend into - a Name, an unknown extension, the TBS bytes that get hashed. */
    if (brisk__der_walk(der, len) != BRISK_OK) {
        return BRISK_E_ARG;
    }
    c->raw = der;
    c->raw_len = len;

    brisk__der_init(&top, der, len);
    brisk__der_enter(&top, BRISK__DER_SEQUENCE, &cert);

    scan = cert; /* a copy reads the same value twice: once raw, once field by field */
    brisk__der_tlv(&scan, &c->tbs, &c->tbs_len);
    brisk__der_enter(&cert, BRISK__DER_SEQUENCE, &tbs);

    /* version [0] EXPLICIT Version DEFAULT v1 (4.1.2.1) */
    if (brisk__der_peek(&tbs) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0)) {
        brisk__der_enter(&tbs, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 0, &val);
        brisk__der_uint(&val, &version);
        brisk__der_close(&tbs, &val);
        if (version == 0 || version > 2) {
            brisk__der_fail(&tbs); /* v1 is the DEFAULT and X.690 11.5 omits it; v4 does not
                                      exist */
        }
        c->version = (uint8_t)(version + 1);
    }

    brisk__der_int(&tbs, &c->serial, &c->serial_len);

    scan = tbs;
    brisk__der_tlv(&scan, &tbs_alg, &tbs_alg_len);
    read_sig_alg(&tbs, c);

    /* issuer: a Name, kept whole. 4.1.2.4 requires it to be non-empty, and an empty RDNSequence
     * encodes as the two bytes 30 00. */
    if (brisk__der_peek(&tbs) != BRISK__DER_SEQUENCE) {
        brisk__der_fail(&tbs);
    }
    brisk__der_tlv(&tbs, &c->issuer, &c->issuer_len);
    if (c->issuer_len <= 2) {
        brisk__der_fail(&tbs);
    }

    brisk__der_enter(&tbs, BRISK__DER_SEQUENCE, &val);
    read_time(&val, &c->not_before);
    read_time(&val, &c->not_after);
    brisk__der_close(&tbs, &val);
    if (c->not_before > c->not_after) {
        brisk__der_fail(&tbs);
    }

    /* subject: may be the empty sequence, in which case 4.2.1.6 requires a subjectAltName */
    if (brisk__der_peek(&tbs) != BRISK__DER_SEQUENCE) {
        brisk__der_fail(&tbs);
    }
    brisk__der_tlv(&tbs, &c->subject, &c->subject_len);

    scan = tbs;
    brisk__der_tlv(&scan, &c->spki, &c->spki_len);
    read_spki(&tbs, c);

    /* issuerUniqueID [1] and subjectUniqueID [2], IMPLICIT BIT STRING, v2 and v3 only
     * (4.1.2.8). Nothing in the Web PKI uses them and this client ignores their contents, but
     * a v1 certificate carrying one is malformed. */
    for (tag = 1; tag <= 2; tag++) {
        if (brisk__der_peek(&tbs) == (BRISK__DER_CONTEXT | tag)) {
            if (c->version < 2) {
                brisk__der_fail(&tbs);
            }
            brisk__der_skip(&tbs);
        }
    }

    /* extensions [3] EXPLICIT Extensions OPTIONAL (4.1.2.9) */
    if (brisk__der_peek(&tbs) == (BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 3)) {
        if (c->version != 3) {
            brisk__der_fail(&tbs);
        }
        brisk__der_enter(&tbs, BRISK__DER_CONTEXT | BRISK__DER_CONSTRUCTED | 3, &wrap);
        brisk__der_enter(&wrap, BRISK__DER_SEQUENCE, &exts);
        if (brisk__der_peek(&exts) == -1) {
            brisk__der_fail(&exts); /* Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension */
        }
        while (brisk__der_peek(&exts) != -1) {
            read_extension(&exts, c, &seen);
        }
        brisk__der_close(&wrap, &exts);
        brisk__der_close(&tbs, &wrap);
    }

    /* 4.2.1.9: "If the cA boolean is not asserted, then the keyCertSign bit in the key usage
     * extension MUST NOT be asserted", and pathLenConstraint needs keyCertSign as well. Both
     * are checked here because the two extensions may arrive in either order. */
    if (!c->is_ca && (c->key_usage & BRISK__X509_KU_KEY_CERT_SIGN)) {
        brisk__der_fail(&tbs);
    }
    if (c->path_len >= 0 && c->key_usage != 0 && !(c->key_usage & BRISK__X509_KU_KEY_CERT_SIGN)) {
        brisk__der_fail(&tbs);
    }
    /* 4.1.2.6: "If subject naming information is present only in the subjectAltName extension
     * ..., then the subject name MUST be an empty sequence and the subjectAltName extension MUST
     * be critical", and 4.2.1.6 repeats the criticality as a CA requirement. Checking only for
     * the SAN's presence would admit the dangerous shape - an empty subject with a NON-critical
     * SAN - where a verifier that does not recognise subjectAltName sees a certificate with no
     * subject identity at all while this one binds the identity from the extension. */
    if (c->subject_len <= 2 && (c->san == NULL || !(seen & SEEN_SAN_CRITICAL))) {
        brisk__der_fail(&tbs);
    }
    /* 4.1.2.6: "If the subject is a CA ... then the subject field MUST be populated with a
     * non-empty distinguished name matching the contents of the issuer field". Name chaining
     * here is a byte compare, so a CA with an empty subject could only ever be chained to by a
     * child whose issuer is the empty name. */
    if (c->is_ca && c->subject_len <= 2) {
        brisk__der_fail(&tbs);
    }
    brisk__der_close(&cert, &tbs);

    /* 4.1.1.2: "This field MUST contain the same algorithm identifier as the signature field in
     * the sequence tbsCertificate". Compared as raw DER, so a different encoding of the same
     * algorithm is refused too - that is the substitution this check exists to stop. */
    brisk__der_tlv(&cert, &outer_alg, &outer_alg_len);
    if (tbs_alg == NULL || outer_alg == NULL || tbs_alg_len != outer_alg_len ||
        memcmp(tbs_alg, outer_alg, tbs_alg_len) != 0) {
        brisk__der_fail(&cert);
    }

    brisk__der_bitstring(&cert, &c->sig, &c->sig_len, &unused);
    if (unused != 0 || c->sig_len == 0) {
        brisk__der_fail(&cert);
    }
    brisk__der_close(&top, &cert);
    brisk__der_end(&top);

    if (brisk__der_err(&top) != BRISK_OK) {
        memset(c, 0, sizeof *c);
        return BRISK_E_ARG;
    }
    return BRISK_OK;
}

#undef SEEN_BASIC_CONSTR
#undef SEEN_KEY_USAGE
#undef SEEN_SAN
#undef SEEN_EKU
#undef SEEN_SAN_CRITICAL
