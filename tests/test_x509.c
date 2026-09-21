/* test_x509.c - certificate parsing (src/x509/cert.c).
 *
 * tests/kat/x509_cert.inc is built by tools/kat.py: certificates constructed one per rule the
 * parser enforces, plus the same shell wrapped around real SubjectPublicKeyInfo blobs from the
 * Wycheproof suites. Every accepted row carries the decode the parser is expected to produce,
 * so a field that silently reads the wrong bytes fails here and not three milestones later.
 * tests/kat/x509_time.inc drives brisk__x509_time on its own, where the calendar lives.
 */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct x509_time_kat {
    int tag;
    const char *text;
    int reject;
    int64_t want;
};
#include "kat/x509_time.inc"

struct cert_kat {
    const char *der;
    int reject;
    const char *note;
    int flags; /* 1 = the row needs BRISK_ENABLE_P384 */
    int version, key_alg, sig_alg, sig_hash, salt;
    unsigned key_usage, eku;
    int is_ca, path_len;
    const char *serial, *san;
    int64_t nbf, naf;
};
#include "kat/x509_cert.inc"

#define TIME_N   (sizeof X509_TIME_KAT / sizeof X509_TIME_KAT[0])
#define CERT_N   (sizeof X509_CERT_KAT / sizeof X509_CERT_KAT[0])
#define CERT_CAP 8192

static uint8_t g_cert[CERT_CAP + 2];

static void t_time(void)
{
    size_t i;
    for (i = 0; i < TIME_N; i++) {
        const struct x509_time_kat *k = &X509_TIME_KAT[i];
        int64_t got = 12345;
        int rc =
            brisk__x509_time((unsigned)k->tag, (const uint8_t *)k->text, strlen(k->text), &got);
        if (k->reject) {
            CHECKI(rc == BRISK_E_ARG && got == 0, i);
        } else {
            CHECKI(rc == BRISK_OK && got == k->want, i);
        }
    }
}

/* Is this row parseable in the configuration the library was built with? */
static int row_enabled(const struct cert_kat *k)
{
#if BRISK_ENABLE_P384
    (void)k;
    return 1;
#else
    return (k->flags & 1) == 0;
#endif
}

static void t_certs(void)
{
    size_t i;
    for (i = 0; i < CERT_N; i++) {
        const struct cert_kat *k = &X509_CERT_KAT[i];
        uint8_t *p = g_cert + 1, want[64];
        size_t n = t_unhex(k->der, p, CERT_CAP), wn;
        brisk__x509_cert c;
        int rc;

        if (!row_enabled(k)) {
            continue;
        }
        rc = brisk__x509_parse(&c, p, n);
        if (k->reject) {
            CHECKI(rc == BRISK_E_ARG, i);
            /* A rejected certificate leaves nothing behind for a caller to misread. */
            CHECKI(c.raw == NULL && c.tbs == NULL && c.key == NULL && c.san == NULL &&
                       c.key_usage == 0 && c.is_ca == 0 && c.not_after == 0,
                   i);
            continue;
        }
        CHECKI(rc == BRISK_OK, i);
        if (rc != BRISK_OK) {
            continue;
        }
        CHECKI(c.raw == p && c.raw_len == n, i);
        /* The TBS is a prefix of the certificate's contents and is what gets hashed, so an
         * off-by-one here is a signature over the wrong bytes. */
        CHECKI(c.tbs > p && c.tbs + c.tbs_len < p + n, i);
        CHECKI(c.version == k->version, i);
        CHECKI(c.key_alg == k->key_alg, i);
        CHECKI(c.sig_alg == k->sig_alg && c.sig_hash == k->sig_hash, i);
        CHECKI(c.sig_salt_len == k->salt, i);
        CHECKI(c.key_usage == k->key_usage, i);
        CHECKI(c.eku == k->eku, i);
        CHECKI(c.is_ca == k->is_ca && c.path_len == k->path_len, i);
        CHECKI(c.not_before == k->nbf && c.not_after == k->naf, i);
        wn = t_unhex(k->serial, want, sizeof want);
        CHECKI(c.serial_len == wn && memcmp(c.serial, want, wn) == 0, i);
        wn = t_unhex(k->san, want, sizeof want);
        if (wn == 0) {
            CHECKI(c.san == NULL && c.san_len == 0, i);
        } else {
            CHECKI(c.san_len == wn && memcmp(c.san, want, wn) == 0, i);
        }
        /* Every pointer aims inside the caller's buffer - nothing was copied or invented. */
        CHECKI(c.issuer > p && c.issuer + c.issuer_len <= p + n, i);
        CHECKI(c.subject > p && c.subject + c.subject_len <= p + n, i);
        CHECKI(c.spki > p && c.spki + c.spki_len <= p + n, i);
        CHECKI(c.key > p && c.key + c.key_len <= p + n, i);
        CHECKI(c.sig > p && c.sig + c.sig_len <= p + n, i);
    }
}

/* A certificate is one complete value: no prefix of it parses, and no suffix may follow. The
 * parser gets this from brisk__der_walk, which is exactly the gate this pins. */
static void t_truncate(void)
{
    size_t i, k, done = 0;
    for (i = 0; i < CERT_N && done < 8; i++) {
        uint8_t *p = g_cert + 1;
        size_t n;
        brisk__x509_cert c;

        if (X509_CERT_KAT[i].reject || !row_enabled(&X509_CERT_KAT[i])) {
            continue;
        }
        n = t_unhex(X509_CERT_KAT[i].der, p, CERT_CAP);
        if (n > 600) {
            continue;
        }
        done++;
        for (k = 0; k < n; k++) {
            CHECKI(brisk__x509_parse(&c, p, k) == BRISK_E_ARG, i);
        }
        p[n] = 0x00;
        CHECKI(brisk__x509_parse(&c, p, n + 1) == BRISK_E_ARG, i);
    }
    CHECK(done == 8);
}

/* Corrupt one byte at a time in the first accepted certificate. Nothing here asserts a verdict -
 * a flipped byte in a name is still a valid certificate - only that the parser stays inside the
 * buffer and always returns one of its two answers. Under the asan preset this is the cheap
 * version of the fuzz run. */
static void t_flip(void)
{
    uint8_t *p = g_cert + 1;
    size_t i, n = 0;
    brisk__x509_cert c;

    for (i = 0; i < CERT_N; i++) {
        if (!X509_CERT_KAT[i].reject && row_enabled(&X509_CERT_KAT[i])) {
            n = t_unhex(X509_CERT_KAT[i].der, p, CERT_CAP);
            break;
        }
    }
    CHECK(n > 0);
    for (i = 0; i < n; i++) {
        int rc;
        p[i] ^= 0xff;
        rc = brisk__x509_parse(&c, p, n);
        p[i] ^= 0xff;
        CHECKI(rc == BRISK_OK || rc == BRISK_E_ARG, i);
    }
}

void test_x509(void)
{
    t_time();
    t_certs();
    t_truncate();
    t_flip();
}
