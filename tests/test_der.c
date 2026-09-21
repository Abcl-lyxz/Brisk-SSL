/* test_der.c - the strict DER reader (src/x509/der.c).
 *
 * tests/kat/der.inc is the strictness oracle: 874 blobs with the verdict a second, independent
 * X.690 implementation in tools/kat.py gave them - 337 real SubjectPublicKeyInfo / RSAPublicKey
 * encodings out of the Wycheproof suites, the 481 adversarial signature blobs of
 * ecdsa_secp256r1_sha256_test.json, and one generated row per clause the reader enforces.
 * tests/kat/der_val.inc pins what the typed readers decode. Everything below those two is a
 * property or an API contract, not a vector: truncation, trailing bytes, stickiness and depth.
 */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct der_kat {
    const char *der;
    int reject; /* 1 = brisk__der_walk must return BRISK_E_ARG */
    const char *note;
};
#include "kat/der.inc"

/* Must match DER_OP in tools/kat.py. */
enum { OP_UINT, OP_INT, OP_UNSIGNED, OP_BOOL, OP_OID, OP_BITS, OP_NULL };

struct der_val_kat {
    int op;
    const char *der;
    int reject;
    const char *want; /* hex of the decoded bytes; aux carries a number instead */
    unsigned aux;
};
#include "kat/der_val.inc"

#define DER_KAT_N (sizeof DER_KAT / sizeof DER_KAT[0])
#define DER_VAL_N (sizeof DER_VAL_KAT / sizeof DER_VAL_KAT[0])
#define DER_CAP   8192 /* the longest corpus blob is 4172 bytes */

/* +2 so every test can work at g_buf + 1 - an odd address, because a reader that quietly
 * assumed alignment would pass at offset 0 on x86_64 and fault on armv5. */
static uint8_t g_buf[DER_CAP + 2];

static void t_walk(void)
{
    size_t i;
    for (i = 0; i < DER_KAT_N; i++) {
        uint8_t *p = g_buf + 1;
        size_t n = t_unhex(DER_KAT[i].der, p, DER_CAP);
        CHECKI(brisk__der_walk(p, n) == (DER_KAT[i].reject ? BRISK_E_ARG : BRISK_OK), i);
    }
}

/* Two properties of "exactly one complete value" that no corpus can state: a value is never
 * complete before its last byte, and it is never still valid with one byte more. Run over the
 * short accepted blobs - the long ones would cost O(n^2) byte scans under qemu for nothing new.
 */
static void t_truncate(void)
{
    size_t i, k, done = 0;
    for (i = 0; i < DER_KAT_N && done < 40; i++) {
        uint8_t *p = g_buf + 1;
        size_t n;
        if (DER_KAT[i].reject) {
            continue;
        }
        n = t_unhex(DER_KAT[i].der, p, DER_CAP);
        if (n < 2 || n > 300) {
            continue;
        }
        done++;
        for (k = 0; k < n; k++) {
            CHECKI(brisk__der_walk(p, k) == BRISK_E_ARG, i);
        }
        p[n] = 0x00;
        CHECKI(brisk__der_walk(p, n + 1) == BRISK_E_ARG, i);
    }
    CHECK(done == 40);
}

static void t_values(void)
{
    size_t i;
    for (i = 0; i < DER_VAL_N; i++) {
        const struct der_val_kat *k = &DER_VAL_KAT[i];
        uint8_t *p = g_buf + 1, want[64];
        size_t n = t_unhex(k->der, p, DER_CAP), wn = t_unhex(k->want, want, sizeof want), vn = 0;
        const uint8_t *v = NULL;
        unsigned unused = 123u;
        uint32_t u = 0xdeadbeefu;
        int b = 7, rc;
        brisk__der c;

        brisk__der_init(&c, p, n);
        switch (k->op) {
        case OP_UINT:
            rc = brisk__der_uint(&c, &u);
            break;
        case OP_INT:
            rc = brisk__der_int(&c, &v, &vn);
            break;
        case OP_UNSIGNED:
            rc = brisk__der_unsigned(&c, &v, &vn);
            break;
        case OP_BOOL:
            rc = brisk__der_bool(&c, &b);
            break;
        case OP_OID:
            rc = brisk__der_oid(&c, &v, &vn);
            break;
        case OP_BITS:
            rc = brisk__der_bitstring(&c, &v, &vn, &unused);
            break;
        default:
            rc = brisk__der_null(&c);
            break;
        }

        if (k->reject) {
            /* A failed read clears its own outputs: nothing stale reaches the caller, which is
             * what lets a parser check the status once at the end instead of after every
             * field. The other locals still hold their poison values - only the reader that
             * ran is under test. */
            CHECKI(rc == BRISK_E_ARG && brisk__der_err(&c) == BRISK_E_ARG, i);
            if (k->op == OP_UINT) {
                CHECKI(u == 0, i);
            } else if (k->op == OP_BOOL) {
                CHECKI(b == 0, i);
            } else if (k->op != OP_NULL) {
                CHECKI(v == NULL && vn == 0, i);
                if (k->op == OP_BITS) {
                    CHECKI(unused == 0, i);
                }
            }
            continue;
        }
        CHECKI(rc == BRISK_OK, i);
        CHECKI(brisk__der_end(&c) == BRISK_OK, i); /* the value covered the whole blob */
        if (k->op == OP_UINT) {
            CHECKI(u == k->aux, i);
        } else if (k->op == OP_BOOL) {
            CHECKI(b == (int)k->aux, i);
        } else if (k->op != OP_NULL) {
            if (k->op == OP_BITS) {
                CHECKI(unused == k->aux, i);
            }
            CHECKI(vn == wn && (wn == 0 || memcmp(v, want, wn) == 0), i);
        }
    }
}

/* Wrap n bytes at buf in `levels` SEQUENCE headers. Lengths stay below 128 here, so one header
 * is always two bytes and the move is in place. */
static size_t nest(uint8_t *buf, size_t n, size_t levels)
{
    while (levels--) {
        memmove(buf + 2, buf, n);
        buf[0] = (uint8_t)BRISK__DER_SEQUENCE;
        buf[1] = (uint8_t)n;
        n += 2;
    }
    return n;
}

static void t_depth(void)
{
    uint8_t *p = g_buf + 1;
    brisk__der c[BRISK__DER_MAX_DEPTH + 2];
    size_t n, i;

    p[0] = (uint8_t)BRISK__DER_NULL;
    p[1] = 0x00;
    n = nest(p, 2, BRISK__DER_MAX_DEPTH);
    CHECK(brisk__der_walk(p, n) == BRISK_OK);
    brisk__der_init(&c[0], p, n);
    for (i = 0; i < BRISK__DER_MAX_DEPTH; i++) {
        CHECKI(brisk__der_enter(&c[i], BRISK__DER_SEQUENCE, &c[i + 1]) == BRISK_OK, i);
    }
    CHECK(brisk__der_null(&c[BRISK__DER_MAX_DEPTH]) == BRISK_OK);

    p[0] = (uint8_t)BRISK__DER_NULL;
    p[1] = 0x00;
    n = nest(p, 2, BRISK__DER_MAX_DEPTH + 1);
    CHECK(brisk__der_walk(p, n) == BRISK_E_ARG); /* one level past the cap */
    brisk__der_init(&c[0], p, n);
    for (i = 0; i < BRISK__DER_MAX_DEPTH; i++) {
        CHECKI(brisk__der_enter(&c[i], BRISK__DER_SEQUENCE, &c[i + 1]) == BRISK_OK, i);
    }
    /* The refused enter still hands back a usable cursor - empty and already failed, so a
     * caller who ignored the status reads nothing rather than the parent's bytes. */
    CHECK(brisk__der_enter(&c[BRISK__DER_MAX_DEPTH], BRISK__DER_SEQUENCE,
                           &c[BRISK__DER_MAX_DEPTH + 1]) == BRISK_E_ARG);
    CHECK(brisk__der_err(&c[BRISK__DER_MAX_DEPTH + 1]) == BRISK_E_ARG);
    CHECK(brisk__der_peek(&c[BRISK__DER_MAX_DEPTH + 1]) == -1);
}

static void t_api(void)
{
    uint8_t *p = g_buf + 1;
    const uint8_t *v = NULL;
    size_t n, vn = 0;
    uint32_t u = 0;
    brisk__der c, body;

    p[0] = (uint8_t)BRISK__DER_INTEGER; /* SEQUENCE { INTEGER 1, NULL } */
    p[1] = 0x01;
    p[2] = 0x01;
    p[3] = (uint8_t)BRISK__DER_NULL;
    p[4] = 0x00;
    n = nest(p, 5, 1);
    CHECK(brisk__der_walk(p, n) == BRISK_OK);

    brisk__der_init(&c, p, n);
    CHECK(brisk__der_enter(&c, BRISK__DER_SEQUENCE, &body) == BRISK_OK);
    CHECK(brisk__der_end(&c) == BRISK_OK); /* the parent is already past the whole child */
    CHECK(brisk__der_peek(&body) == BRISK__DER_INTEGER);
    CHECK(brisk__der_uint(&body, &u) == BRISK_OK && u == 1);
    CHECK(brisk__der_peek(&body) == BRISK__DER_NULL);
    CHECK(brisk__der_null(&body) == BRISK_OK);
    CHECK(brisk__der_peek(&body) == -1);
    CHECK(brisk__der_close(&c, &body) == BRISK_OK);

    /* A tag mismatch fails the cursor, and everything after it is a no-op that still reports. */
    brisk__der_init(&c, p, n);
    CHECK(brisk__der_enter(&c, BRISK__DER_SET, &body) == BRISK_E_ARG);
    CHECK(brisk__der_err(&body) == BRISK_E_ARG);
    CHECK(brisk__der_peek(&c) == -1);
    CHECK(brisk__der_tlv(&c, &v, &vn) == BRISK_E_ARG && v == NULL && vn == 0);
    CHECK(brisk__der_end(&c) == BRISK_E_ARG);

    /* A primitive encoding of a constructed type is not something to enter. */
    brisk__der_init(&c, p + 2, 3);
    CHECK(brisk__der_enter(&c, BRISK__DER_INTEGER, &body) == BRISK_E_ARG);

    /* Bytes the child never read are the parent's error, surfaced by close(). */
    brisk__der_init(&c, p, n);
    CHECK(brisk__der_enter(&c, BRISK__DER_SEQUENCE, &body) == BRISK_OK);
    CHECK(brisk__der_close(&c, &body) == BRISK_E_ARG);

    /* brisk__der_tlv keeps the header: these are the bytes TBSCertificate gets hashed over. */
    brisk__der_init(&c, p, n);
    CHECK(brisk__der_tlv(&c, &v, &vn) == BRISK_OK && v == p && vn == n);
    CHECK(brisk__der_end(&c) == BRISK_OK);

    /* brisk__der_fail lets a caller's own rejection join the same sticky chain. */
    brisk__der_init(&c, p, n);
    CHECK(brisk__der_fail(&c) == BRISK_E_ARG);
    CHECK(brisk__der_enter(&c, BRISK__DER_SEQUENCE, &body) == BRISK_E_ARG);

    /* brisk__der_skip validates the header and nothing below it, so BER inside a value it
     * steps over is invisible here - which is exactly why the certificate entry point walks
     * the whole encoding first. Pinned so the day that changes, this line changes with it. */
    p[0] = 0x24; /* constructed OCTET STRING: brisk__der_walk refuses it */
    p[1] = 0x03;
    p[2] = (uint8_t)BRISK__DER_OCTET_STRING;
    p[3] = 0x01;
    p[4] = 0x00;
    CHECK(brisk__der_walk(p, 5) == BRISK_E_ARG);
    brisk__der_init(&c, p, 5);
    CHECK(brisk__der_skip(&c) == BRISK_OK && brisk__der_end(&c) == BRISK_OK);

    /* An empty buffer is a legal cursor on which every read fails. */
    brisk__der_init(&c, p, 0);
    CHECK(brisk__der_peek(&c) == -1);
    CHECK(brisk__der_end(&c) == BRISK_OK);
    CHECK(brisk__der_skip(&c) == BRISK_E_ARG);
}

/* Parse every real key in the corpus the way the certificate code of the next ROADMAP item
 * will, and check the status exactly once:
 *   SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT
 *   STRING }                                                             -- RFC 5280 4.1.2.7
 */
static void t_spki(void)
{
    size_t i, done = 0;
    for (i = 0; i < DER_KAT_N; i++) {
        uint8_t *p = g_buf + 1;
        const uint8_t *oid = NULL, *key = NULL;
        size_t n, oid_len = 0, key_len = 0;
        unsigned unused = 1;
        brisk__der c, spki, alg;

        if (DER_KAT[i].reject || strstr(DER_KAT[i].note, "publicKeyDer") == NULL) {
            continue;
        }
        n = t_unhex(DER_KAT[i].der, p, DER_CAP);
        brisk__der_init(&c, p, n);
        brisk__der_enter(&c, BRISK__DER_SEQUENCE, &spki);
        brisk__der_enter(&spki, BRISK__DER_SEQUENCE, &alg);
        brisk__der_oid(&alg, &oid, &oid_len);
        if (brisk__der_peek(&alg) != -1) { /* parameters: a curve OID for EC, NULL for RSA */
            brisk__der_skip(&alg);
        }
        brisk__der_close(&spki, &alg);
        brisk__der_bitstring(&spki, &key, &key_len, &unused);
        brisk__der_close(&c, &spki);
        CHECKI(brisk__der_end(&c) == BRISK_OK, i);
        CHECKI(oid_len >= 7 && key_len > 16 && unused == 0, i);
        done++;
    }
    CHECK(done > 300); /* the corpus really is mostly real keys */
}

void test_der(void)
{
    t_walk();
    t_truncate();
    t_values();
    t_depth();
    t_api();
    t_spki();
}
