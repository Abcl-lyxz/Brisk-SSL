/* test_x509.c - certificate parsing (src/x509/cert.c).
 *
 * tests/kat/x509_cert.inc is built by tools/kat.py: certificates constructed one per rule the
 * parser enforces, plus the same shell wrapped around real SubjectPublicKeyInfo blobs from the
 * Wycheproof suites. Every accepted row carries the decode the parser is expected to produce,
 * so a field that silently reads the wrong bytes fails here and not three milestones later.
 * tests/kat/x509_time.inc drives brisk__x509_time on its own, where the calendar lives.
 */
/* O_CLOEXEC and O_NOFOLLOW, used by the Linux-only CA bundle test at the bottom of this file:
 * POSIX 2008, which glibc hides under a bare -std=c99. Must precede every #include. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200809L
#    undef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#endif
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

struct name_kat {
    const char *san; /* the GeneralNames CONTENTS, i.e. brisk__x509_cert.san */
    const char *host;
    int want; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG */
    const char *note;
};
#include "kat/x509_name.inc"

struct ip_kat {
    const char *text;
    const char *want; /* the octets, or "" when the literal must be refused */
    const char *note;
};
#include "kat/x509_ip.inc"

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
#define NAME_N   (sizeof X509_NAME_KAT / sizeof X509_NAME_KAT[0])
#define IP_N     (sizeof X509_IP_KAT / sizeof X509_IP_KAT[0])
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
    int flags;   /* 1 = the row needs BRISK_ENABLE_P384; 2 = it needs the validity window
                  * enforced, so an INSECURE_NO_TIME build has to skip it */
    int64_t now; /* the clock the walk is given, above BRISK_X509_TIME_FLOOR in every row */
    const char *note;
};
#include "kat/x509_chain.inc"

/* One certificate against one clock: the policy table, where all three BRISK_X509_TIME_POLICY
 * answers travel together and the build reads its own column. */
struct validity_kat {
    const char *cert;
    int64_t now;
    int want[3]; /* STRICT, FLOOR, INSECURE_NO_TIME - indexed by the policy, which is 1-based */
    const char *note;
};
#include "kat/x509_validity.inc"

/* brisk__x509_signed_by on its own, where BRISK_E_ARG and BRISK_E_AUTH are told apart - a chain
 * row cannot do that, it only ever reports that no path was built. */
struct sig_kat {
    const char *child, *issuer;
    int want; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG */
    int flags;
    const char *note;
};
#include "kat/x509_sig.inc"

/* The PEM decoder on its own: a file's text in, a list of decoded blobs out. The base64 rows
 * come from RFC 4648 section 10, so the alphabet is pinned by the RFC rather than by a
 * certificate that a subtly wrong decoder would still round-trip. */
#define BUNDLE_BLOBS 7
struct bundle_kat {
    const char *pem;
    const char *blobs[BUNDLE_BLOBS]; /* hex, in order; NULL ends the list, "" is a real entry */
    const char *note;
};
#include "kat/x509_bundle.inc"

/* A whole chain against a bundle FILE, which is what exercises src/os/linux_ca.c: autodetect
 * skipped (the row names its own path), open, scan, match a Name, walk `index`, close. */
#define STORE_CERTS 3
struct store_kat {
    const char *pem;
    const char *certs[STORE_CERTS];
    int want; /* 0 = BRISK_OK, 1 = BRISK_E_AUTH */
    int64_t now;
    const char *note;
};
#include "kat/x509_store.inc"

/* brisk__x509_trust.pins. Same shape as a chain row plus the pin set. */
#define PIN_MAX 3
struct pin_kat {
    const char *certs[CHAIN_CERTS];
    const char *anchors[CHAIN_ANCHORS];
    const char *pins[PIN_MAX]; /* sha256(SPKI) as hex; NULL ends the list */
    int want;
    int64_t now;
    const char *note;
};
#include "kat/x509_pin.inc"

#define CHAIN_N    (sizeof X509_CHAIN_KAT / sizeof X509_CHAIN_KAT[0])
#define BUNDLE_N   (sizeof X509_BUNDLE_KAT / sizeof X509_BUNDLE_KAT[0])
#define STORE_N    (sizeof X509_STORE_KAT / sizeof X509_STORE_KAT[0])
#define PIN_N      (sizeof X509_PIN_KAT / sizeof X509_PIN_KAT[0])
#define SIG_N      (sizeof X509_SIG_KAT / sizeof X509_SIG_KAT[0])
#define VALIDITY_N (sizeof X509_VALIDITY_KAT / sizeof X509_VALIDITY_KAT[0])

/* One row's certificates, decoded and parsed. The DER has to outlive the parse, which is what
 * the byte arrays are for - brisk__x509_cert only points into them. */
struct chain_row {
    uint8_t der[CHAIN_CERTS][CHAIN_CERT_CAP];
    uint8_t anchor_der[CHAIN_ANCHORS][CHAIN_CERT_CAP];
    brisk__x509_cert certs[CHAIN_CERTS];
    brisk__x509_cert anchors[CHAIN_ANCHORS];
    size_t n_certs, n_anchors;
    size_t lookups; /* find_anchor calls for this row; the only way its budget is testable */
};

static struct chain_row g_row;

/* Can this row's verdict be reproduced by the library as configured? Bit 1 is a certificate
 * this build cannot parse (P-384), bit 2 a verdict that only holds where the validity window is
 * enforced at all, bit 4 one that needs the unset-clock fallback STRICT does not have. */
static int chain_row_enabled(int flags)
{
#if !BRISK_ENABLE_P384
    if (flags & 1) {
        return 0;
    }
#endif
#if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
    if (flags & 2) {
        return 0;
    }
#endif
#if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_STRICT
    if (flags & 4) {
        return 0;
    }
#endif
    (void)flags;
    return 1;
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
    struct chain_row *r = ctx;
    size_t i, hit = 0;

    r->lookups++;

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

/* The trust store of whatever row is loaded in g_row, with no pins. Rebuilt on every call so a
 * pin row that borrowed the same static cannot leave its pins behind. */
static const brisk__x509_trust *row_trust(void)
{
    static brisk__x509_trust t;
    t.find_anchor = t_find_anchor;
    t.anchor_ctx = &g_row;
    t.pins = NULL;
    t.n_pins = 0;
    return &t;
}

/* Parse every certificate of a row. A row whose own fixtures do not parse is a broken vector,
 * not a chain failure, so this is checked rather than folded into the verdict. Takes the two
 * arrays rather than a struct, because the pin and store tables carry the same pair with other
 * columns around it. `anchors` may be NULL for a table that has none. */
static int row_load(const char *const *certs, size_t n_max, const char *const *anchors, size_t idx)
{
    size_t i, n;
    int ok = 1;

    /* n_max is the caller's ARRAY LENGTH, not CHAIN_CERTS: a store row's certs[] is shorter,
     * and a full row has no NULL in it to stop on. Scanning past the end would read the int
     * and int64 that follow the array - a wild pointer on the targets with no padding there. */
    g_row.n_certs = g_row.n_anchors = 0;
    g_row.lookups = 0;
    for (i = 0; i < n_max && certs[i] != NULL; i++) {
        n = t_unhex(certs[i], g_row.der[i], CHAIN_CERT_CAP);
        if (brisk__x509_parse(&g_row.certs[i], g_row.der[i], n) != BRISK_OK) {
            ok = 0;
        }
        g_row.n_certs++;
    }
    for (i = 0; anchors != NULL && i < CHAIN_ANCHORS && anchors[i] != NULL; i++) {
        n = t_unhex(anchors[i], g_row.anchor_der[i], CHAIN_CERT_CAP);
        if (brisk__x509_parse(&g_row.anchors[i], g_row.anchor_der[i], n) != BRISK_OK) {
            ok = 0;
        }
        g_row.n_anchors++;
    }
    CHECKI(ok, idx);
    return ok;
}

static int chain_load(const struct chain_kat *k, size_t idx)
{
    return row_load(k->certs, CHAIN_CERTS, k->anchors, idx);
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
        rc = brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, row_trust());
        CHECKI(rc == (k->want ? BRISK_E_AUTH : BRISK_OK), i);
        /* The trust store is I/O - for the real one, a pass over ~200 KB of PEM per miss - and
         * backtracking made the depth limit stop bounding how often it is asked. Nothing else
         * in the suite would notice that budget going away, because a bigger budget only ever
         * accepts MORE. So it is asserted here, on every row, against the documented ceiling. */
        CHECKI(g_row.lookups <= BRISK__X509_MAX_LOOKUPS * BRISK__X509_MAX_ANCHORS, i);
    }
}

/* The time policy: one certificate, one clock, the verdict this build's BRISK_X509_TIME_POLICY
 * owes. The row carries all three, so the two policies this binary was not built with are still
 * written down next to the one it was - and switching the knob re-runs the same table against a
 * different column instead of needing a table of its own. */
static void t_validity(void)
{
    static uint8_t der[CHAIN_CERT_CAP];
    size_t i;

    for (i = 0; i < VALIDITY_N; i++) {
        const struct validity_kat *k = &X509_VALIDITY_KAT[i];
        brisk__x509_cert c;
        size_t n = t_unhex(k->cert, der, sizeof der);
        int want = k->want[BRISK_X509_TIME_POLICY - 1] ? BRISK_E_AUTH : BRISK_OK;

        CHECKI(brisk__x509_parse(&c, der, n) == BRISK_OK, i);
        CHECKI(brisk__x509_time_ok(&c, k->now) == want, i);
    }
    CHECK(brisk__x509_time_ok(NULL, 0) == BRISK_E_ARG);
}

/* The arguments the walk must refuse or survive on their own, which no vector covers: an empty
 * certificate list, and a trust store that is not there at all. */
static void t_chain_args(void)
{
    size_t row = plain_row();
    const struct chain_kat *k = &X509_CHAIN_KAT[row];

    brisk__x509_trust storeless = {NULL, NULL, NULL, 0};

    CHECK(brisk__x509_chain_verify(NULL, 0, k->now, NULL) == BRISK_E_ARG);
    if (chain_load(k, row)) {
        CHECK(brisk__x509_chain_verify(g_row.certs, 0, k->now, row_trust()) == BRISK_E_ARG);
        /* No trust at all, spelled both ways: no struct, and a struct with no store in it. */
        CHECK(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, NULL) == BRISK_E_AUTH);
        CHECK(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, &storeless) ==
              BRISK_E_AUTH);
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

/* RFC 9525 matching, one row per rule (src/x509/name.c). The vector carries only the SAN,
 * because that is all the matcher is allowed to look at: the rest of the certificate is left
 * zeroed on purpose, so a rule that quietly consulted the subject or the validity dates would
 * read a NULL here rather than pass. */
static void t_name(void)
{
    static uint8_t san[1025];
    size_t i;

    for (i = 0; i < NAME_N; i++) {
        const struct name_kat *k = &X509_NAME_KAT[i];
        brisk__x509_cert c;
        size_t n = t_unhex(k->san, san + 1, sizeof san - 1);
        int want = (k->want == 0) ? BRISK_OK : (k->want == 1) ? BRISK_E_AUTH : BRISK_E_ARG;

        memset(&c, 0, sizeof c);
        c.san = san + 1; /* unaligned on purpose */
        c.san_len = n;
        CHECKI(brisk__x509_match_host(&c, k->host, strlen(k->host)) == want, i);
    }
}

/* The two rules no SAN vector can carry: a certificate with no subjectAltName at all, and RFC
 * 9525 1.3's ban on falling back to the subject. The fixture is written out rather than
 * generated because it is one GeneralName and its point is that it is NOT the reference. */
static void t_name_args(void)
{
    static const char host[] = "device.example.com";
    static const uint8_t other[] = {0x82, 0x09, 'o', 't', 'h', 'e', 'r', '.', 'c', 'o', 'm'};
    brisk__x509_cert c;

    memset(&c, 0, sizeof c);
    CHECK(brisk__x509_match_host(NULL, host, strlen(host)) == BRISK_E_ARG);
    CHECK(brisk__x509_match_host(&c, NULL, 0) == BRISK_E_ARG);
    CHECK(brisk__x509_match_host(&c, host, 0) == BRISK_E_ARG);
    CHECK(brisk__x509_match_host(&c, ".", 1) == BRISK_E_ARG);
    CHECK(brisk__x509_match_host(&c, host, strlen(host)) == BRISK_E_AUTH); /* no SAN at all */

    /* A subject that IS the reference identifier, over a SAN that is not: the answer must not
     * change. */
    c.san = other;
    c.san_len = sizeof other;
    c.subject = (const uint8_t *)host;
    c.subject_len = strlen(host);
    CHECK(brisk__x509_match_host(&c, host, strlen(host)) == BRISK_E_AUTH);
    CHECK(brisk__x509_match_host(&c, "other.com", 9) == BRISK_OK);
    CHECK(brisk__x509_match_host(&c, "other.com.", 10) == BRISK_OK); /* one root dot, stripped */
}

/* brisk__x509_parse_ip: the classifier both the matcher and (later) SNI hang off. */
static void t_ip(void)
{
    size_t i;

    for (i = 0; i < IP_N; i++) {
        const struct ip_kat *k = &X509_IP_KAT[i];
        uint8_t want[16], got[16];
        size_t n = t_unhex(k->want, want, sizeof want);
        size_t rc = brisk__x509_parse_ip(k->text, strlen(k->text), got);

        CHECKI(rc == n, i);
        if (rc == n && n > 0) {
            CHECKI(memcmp(got, want, n) == 0, i);
        }
    }
    CHECK(brisk__x509_parse_ip(NULL, 4, NULL) == 0);
    /* Not NUL-terminated and not NUL-scanned: the length is the only thing that ends it. */
    CHECK(brisk__x509_parse_ip("192.0.2.1junk", 9, (uint8_t[16]){0}) == 4);
}

/* -------------------------------------------------------------- PEM + pins + store -------- */

static size_t bundle_expected(const struct bundle_kat *k)
{
    size_t n = 0;
    while (n < BUNDLE_BLOBS && k->blobs[n] != NULL) {
        n++;
    }
    return n;
}

/* The decoder, fed at every chunk size that can cut a block in a different place: one byte at a
 * time catches anything that was left in a local instead of the struct, 2/3/7 straddle base64
 * groups and line endings, and the whole file in one call is the ordinary case. A decoder whose
 * answer depends on how the file was read is the bug this is shaped to find - and it is the
 * realistic one, because read() returns what it feels like. */
static void t_pem(void)
{
    static const size_t chunks[] = {1, 2, 3, 7, 64, 0}; /* 0 = everything in one call */
    static uint8_t want[CHAIN_CERT_CAP];
    static brisk__x509_pem pem; /* 2 KB: too big for this frame */
    size_t i, ci;

    for (i = 0; i < BUNDLE_N; i++) {
        const struct bundle_kat *k = &X509_BUNDLE_KAT[i];
        size_t pem_len = strlen(k->pem), n_want = bundle_expected(k);

        for (ci = 0; ci < sizeof chunks / sizeof chunks[0]; ci++) {
            size_t step = chunks[ci] != 0 ? chunks[ci] : (pem_len != 0 ? pem_len : 1);
            size_t off = 0, got = 0;
            int ok = 1;

            brisk__x509_pem_init(&pem);
            while (off < pem_len && ok) {
                size_t take = pem_len - off < step ? pem_len - off : step;
                const uint8_t *p = (const uint8_t *)k->pem + off;
                size_t left = take;

                off += take;
                while (brisk__x509_pem_feed(&pem, &p, &left) == 1) {
                    size_t n;
                    if (got == n_want) {
                        ok = 0; /* a block the vector says is not there */
                        break;
                    }
                    n = t_unhex(k->blobs[got], want, sizeof want);
                    if (pem.der_len != n || (n != 0 && memcmp(pem.der, want, n) != 0)) {
                        ok = 0;
                    }
                    got++;
                }
            }
            CHECKI(ok && got == n_want, i);
        }
    }
    /* The arguments a caller can get wrong. A NULL anywhere is "no bytes", never a read. */
    {
        const uint8_t *p = (const uint8_t *)"";
        size_t left = 0;
        brisk__x509_pem_init(NULL);
        CHECK(brisk__x509_pem_feed(NULL, &p, &left) == 0);
        CHECK(brisk__x509_pem_feed(&pem, NULL, &left) == 0);
        CHECK(brisk__x509_pem_feed(&pem, &p, NULL) == 0);
    }
}

/* brisk__x509_trust.pins: additive, path members only, and a selection predicate at the anchor
 * rather than a verdict applied once the walk has committed. */
static void t_pin(void)
{
    static uint8_t pins[PIN_MAX][BRISK_SHA256_LEN];
    size_t i, j;

    for (i = 0; i < PIN_N; i++) {
        const struct pin_kat *k = &X509_PIN_KAT[i];
        brisk__x509_trust trust;
        size_t n_pins = 0;

        if (!row_load(k->certs, CHAIN_CERTS, k->anchors, i)) {
            continue;
        }
        for (j = 0; j < PIN_MAX && k->pins[j] != NULL; j++) {
            CHECKI(t_unhex(k->pins[j], pins[j], BRISK_SHA256_LEN) == BRISK_SHA256_LEN, i);
            n_pins++;
        }
        /* A row with no anchors is the "pins are not a trust store" case, and it is spelled the
         * way a caller would spell it: no callback at all, not a callback with nothing behind
         * it. */
        trust.find_anchor = g_row.n_anchors != 0 ? t_find_anchor : NULL;
        trust.anchor_ctx = &g_row;
        trust.pins = n_pins != 0 ? (const uint8_t (*)[BRISK_SHA256_LEN])pins : NULL;
        trust.n_pins = n_pins;
        CHECKI(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, &trust) ==
                   (k->want != 0 ? BRISK_E_AUTH : BRISK_OK),
               i);
    }

    /* The half-configured trust store M3's brisk_cfg makes easy to write: a pin COUNT with no
     * pin ARRAY behind it. It has to mean "a pin nothing can satisfy" - so a chain that would
     * otherwise verify is refused - and not a NULL dereference on a gateway. Driven from a row
     * that is known to pass with no pins at all, so only the pins can be what refuses it. */
    for (i = 0; i < PIN_N; i++) {
        const struct pin_kat *k = &X509_PIN_KAT[i];
        brisk__x509_trust trust;

        if (k->want != 0 || k->pins[0] != NULL || !row_load(k->certs, CHAIN_CERTS, k->anchors, i)) {
            continue;
        }
        trust.find_anchor = t_find_anchor;
        trust.anchor_ctx = &g_row;
        trust.pins = NULL;
        trust.n_pins = 0;
        CHECKI(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, &trust) == BRISK_OK, i);
        trust.n_pins = 3; /* ... and the same call with a count but no array fails closed */
        CHECKI(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, &trust) == BRISK_E_AUTH,
               i);
        break;
    }
}

#ifdef __linux__
#    include <fcntl.h>
#    include <unistd.h>

/* The CA bundle as a trust store, through a real file. Everything below this line is Linux
 * only, because src/os/ is: the mingw host build does not compile linux_ca.c at all. */
static int write_bundle(const char *path, const char *text)
{
    size_t len = strlen(text), off = 0;
    /* O_NOFOLLOW: this path is predictable, so a symlink planted there must make the test fail
     * rather than make it write through. O_EXCL is not usable - the file is rewritten per row. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);

    if (fd < 0) {
        return 0;
    }
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n <= 0) {
            close(fd);
            return 0;
        }
        off += (size_t)n;
    }
    return close(fd) == 0;
}

static void t_store(void)
{
    static const char path[] = "/tmp/brisk_ca_bundle_test.pem";
    static brisk__x509_bundle bundle;
    brisk__x509_cert anchor;
    size_t i;

    for (i = 0; i < STORE_N; i++) {
        const struct store_kat *k = &X509_STORE_KAT[i];
        brisk__x509_trust trust;
        int wrote = write_bundle(path, k->pem);

        CHECKI(wrote, i);
        if (!wrote || !row_load(k->certs, STORE_CERTS, NULL, i)) {
            continue;
        }
        bundle.path = path; /* named, so no autodetection runs and the row decides the file */
        trust.find_anchor = brisk__os_ca_anchor;
        trust.anchor_ctx = &bundle;
        trust.pins = NULL;
        trust.n_pins = 0;
        CHECKI(brisk__x509_chain_verify(g_row.certs, g_row.n_certs, k->now, &trust) ==
                   (k->want != 0 ? BRISK_E_AUTH : BRISK_OK),
               i);
    }

    /* The lookup's own argument handling, which no row reaches: a Name nobody has, an empty
     * Name, a bundle whose path does not exist, and a NULL context. */
    bundle.path = path;
    CHECK(brisk__os_ca_anchor(&bundle, (const uint8_t *)"nope", 4, 0, &anchor) == BRISK_E_ARG);
    CHECK(brisk__os_ca_anchor(&bundle, (const uint8_t *)"", 0, 0, &anchor) == BRISK_E_ARG);
    CHECK(brisk__os_ca_anchor(&bundle, (const uint8_t *)"nope", 4, 0, NULL) == BRISK_E_ARG);
    CHECK(brisk__os_ca_anchor(NULL, (const uint8_t *)"nope", 4, 0, &anchor) == BRISK_E_ARG);
    unlink(path);
    bundle.path = "/nonexistent/brisk/ca-bundle.pem";
    CHECK(brisk__os_ca_anchor(&bundle, (const uint8_t *)"nope", 4, 0, &anchor) == BRISK_E_ARG);

    /* Autodetection. A build host has a bundle and a scratch container may not, so the verdict
     * is not "a path was found" - it is that whatever comes back is one of the paths the module
     * offers and that it really opens. */
    {
        const char *found = brisk__os_ca_path();
        if (found != NULL) {
            int fd = open(found, O_RDONLY | O_CLOEXEC);
            CHECK(fd >= 0);
            if (fd >= 0) {
                close(fd);
            }
            /* And a bundle that was never given a path finds the same one. */
            bundle.path = NULL;
            (void)brisk__os_ca_anchor(&bundle, (const uint8_t *)"nope", 4, 0, &anchor);
            CHECK(bundle.path == found);
        }
    }
}
#endif /* __linux__ */

void test_x509(void)
{
    t_time();
    t_certs();
    t_truncate();
    t_flip();
    t_validity();
    t_chain();
    t_chain_args();
    t_signed_by();
    t_sig();
    t_name();
    t_name_args();
    t_ip();
    t_pem();
    t_pin();
#ifdef __linux__
    t_store();
#endif
}
