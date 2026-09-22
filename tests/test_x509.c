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

/* The fixed widths tools/kat.py emits its chain rows into, and a cap that fits any certificate
 * those rows hold - they are built here, none of them reaches 1 KB. CHAIN_CERTS is one past
 * BRISK__X509_MAX_CHAIN so a row can hold a path that is deliberately too long. */
#define CHAIN_CERTS    9
#define CHAIN_ANCHORS  2
#define CHAIN_CERT_CAP 2048

/* ---------------------------------------------------------------------- chains ----------- */

struct chain_kat {
    const char *certs[CHAIN_CERTS];     /* [0] is the end entity; NULL ends the list */
    const char *anchors[CHAIN_ANCHORS]; /* the trust store for this row */
    int want;                           /* 0 = BRISK_OK, 1 = BRISK_E_AUTH */
    int flags;                          /* 1 = the row needs BRISK_ENABLE_P384 */
    const char *note;
};
#include "kat/x509_chain.inc"

/* brisk__x509_signed_by on its own, where BRISK_E_ARG and BRISK_E_AUTH are told apart - a chain
 * row cannot do that, it only ever reports that no path was built. */
struct sig_kat {
    const char *child, *issuer;
    int want; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG */
    int flags;
    const char *note;
};
#include "kat/x509_sig.inc"

#define CHAIN_N (sizeof X509_CHAIN_KAT / sizeof X509_CHAIN_KAT[0])
#define SIG_N   (sizeof X509_SIG_KAT / sizeof X509_SIG_KAT[0])

/* One row's certificates, decoded and parsed. The DER has to outlive the parse, which is what
 * the byte arrays are for - brisk__x509_cert only points into them. */
struct chain_row {
    uint8_t der[CHAIN_CERTS][CHAIN_CERT_CAP];
    uint8_t anchor_der[CHAIN_ANCHORS][CHAIN_CERT_CAP];
    brisk__x509_cert certs[CHAIN_CERTS];
    brisk__x509_cert anchors[CHAIN_ANCHORS];
    size_t n_certs, n_anchors;
};

static struct chain_row g_row;

/* Can this row's certificates be parsed by the library as configured? */
static int chain_row_enabled(int flags)
{
#if BRISK_ENABLE_P384
    (void)flags;
    return 1;
#else
    return (flags & 1) == 0;
#endif
}

/* The first two-deep accepted row every configuration can run, for the checks that want one
 * concrete chain rather than the whole table. */
static size_t plain_row(void)
{
    size_t i;
    for (i = 0; i < CHAIN_N; i++) {
        const struct chain_kat *k = &X509_CHAIN_KAT[i];
        if (chain_row_enabled(k->flags) && k->want == 0 && k->certs[1] != NULL &&
            k->certs[2] == NULL && k->anchors[0] != NULL) {
            return i;
        }
    }
    return 0;
}

/* The trust store of one row, looked up the way a CA bundle would be: by subject Name, with
 * `index` walking the certificates that share one. */
static int t_find_anchor(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                         brisk__x509_cert *out)
{
    const struct chain_row *r = ctx;
    size_t i, hit = 0;

    for (i = 0; i < r->n_anchors; i++) {
        if (r->anchors[i].subject_len == dn_len && memcmp(r->anchors[i].subject, dn, dn_len) == 0) {
            if (hit++ == index) {
                *out = r->anchors[i];
                return BRISK_OK;
            }
        }
    }
    return BRISK_E_ARG;
}

/* Parse every certificate of a row. A row whose own fixtures do not parse is a broken vector,
 * not a chain failure, so this is checked rather than folded into the verdict. */
static int chain_load(const struct chain_kat *k, size_t idx)
{
    size_t i, n;
    int ok = 1;

    g_row.n_certs = g_row.n_anchors = 0;
    for (i = 0; i < CHAIN_CERTS && k->certs[i] != NULL; i++) {
        n = t_unhex(k->certs[i], g_row.der[i], CHAIN_CERT_CAP);
        if (brisk__x509_parse(&g_row.certs[i], g_row.der[i], n) != BRISK_OK) {
            ok = 0;
        }
        g_row.n_certs++;
    }
    for (i = 0; i < CHAIN_ANCHORS && k->anchors[i] != NULL; i++) {
        n = t_unhex(k->anchors[i], g_row.anchor_der[i], CHAIN_CERT_CAP);
        if (brisk__x509_parse(&g_row.anchors[i], g_row.anchor_der[i], n) != BRISK_OK) {
            ok = 0;
        }
        g_row.n_anchors++;
    }
    CHECKI(ok, idx);
    return ok;
}

static void t_chain(void)
{
    size_t i;
    for (i = 0; i < CHAIN_N; i++) {
        const struct chain_kat *k = &X509_CHAIN_KAT[i];
        int rc;

        if (!chain_row_enabled(k->flags)) {
            continue;
        }
        if (!chain_load(k, i)) {
            continue;
        }
        rc = brisk__x509_chain_verify(g_row.certs, g_row.n_certs, t_find_anchor, &g_row);
        CHECKI(rc == (k->want ? BRISK_E_AUTH : BRISK_OK), i);
    }
}

/* The arguments the walk must refuse or survive on their own, which no vector covers: an empty
 * certificate list, and a trust store that is not there at all. */
static void t_chain_args(void)
{
    size_t row = plain_row();
    const struct chain_kat *k = &X509_CHAIN_KAT[row];

    CHECK(brisk__x509_chain_verify(NULL, 0, NULL, NULL) == BRISK_E_ARG);
    if (chain_load(k, row)) {
        CHECK(brisk__x509_chain_verify(g_row.certs, 0, t_find_anchor, &g_row) == BRISK_E_ARG);
        CHECK(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, NULL, NULL) == BRISK_E_AUTH);
    }
}

/* brisk__x509_signed_by on its own: the row that chains cleanly says OK for the pair it was
 * built from and AUTH for every other pairing, so a verifier that ignored the key would show up
 * here rather than as a chain that happens to succeed. */
static void t_signed_by(void)
{
    size_t row = plain_row();

    if (!chain_load(&X509_CHAIN_KAT[row], row)) {
        return;
    }
    CHECK(g_row.n_certs == 2 && g_row.n_anchors == 1);
    CHECK(brisk__x509_signed_by(NULL, &g_row.certs[1]) == BRISK_E_ARG);
    CHECK(brisk__x509_signed_by(&g_row.certs[0], NULL) == BRISK_E_ARG);
    CHECK(brisk__x509_signed_by(&g_row.certs[0], &g_row.certs[1]) == BRISK_OK);
    CHECK(brisk__x509_signed_by(&g_row.certs[1], &g_row.anchors[0]) == BRISK_OK);
    CHECK(brisk__x509_signed_by(&g_row.certs[0], &g_row.anchors[0]) == BRISK_E_AUTH);
    CHECK(brisk__x509_signed_by(&g_row.certs[1], &g_row.certs[0]) == BRISK_E_AUTH);
    CHECK(brisk__x509_signed_by(&g_row.certs[0], &g_row.certs[0]) == BRISK_E_AUTH);
}

/* The two DER parsers brisk__x509_signed_by owns - an ECDSA-Sig-Value and an RSAPublicKey,
 * both inside BIT STRINGs that brisk__der_walk treats as leaves - and the pairings it refuses.
 * Nothing else in the suite tells BRISK_E_ARG from BRISK_E_AUTH here. */
static void t_sig(void)
{
    static uint8_t child_der[CHAIN_CERT_CAP], issuer_der[CHAIN_CERT_CAP];
    size_t i;

    for (i = 0; i < SIG_N; i++) {
        const struct sig_kat *k = &X509_SIG_KAT[i];
        brisk__x509_cert child, issuer;
        size_t cn, in;
        int want;

        if (!chain_row_enabled(k->flags)) {
            continue;
        }
        cn = t_unhex(k->child, child_der, sizeof child_der);
        in = t_unhex(k->issuer, issuer_der, sizeof issuer_der);
        if (brisk__x509_parse(&child, child_der, cn) != BRISK_OK ||
            brisk__x509_parse(&issuer, issuer_der, in) != BRISK_OK) {
            CHECKI(0, i); /* a fixture that does not parse is a broken vector, not a verdict */
            continue;
        }
        want = (k->want == 0) ? BRISK_OK : (k->want == 1) ? BRISK_E_AUTH : BRISK_E_ARG;
        CHECKI(brisk__x509_signed_by(&child, &issuer) == want, i);
    }
}

void test_x509(void)
{
    t_time();
    t_certs();
    t_truncate();
    t_flip();
    t_chain();
    t_chain_args();
    t_signed_by();
    t_sig();
}
