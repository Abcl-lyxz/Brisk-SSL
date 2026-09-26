/* test_key.c - the device private key decoder brisk__x509_p256_key (src/x509/key.c) and the
 * strict one-shot PEM decoder brisk__x509_pem_block it shares with a PEM client_chain
 * (src/x509/bundle.c), against tools/kat.py's key.inc: NIST CAVP KeyPair in every encoding, the
 * RFC 7468 Figure 12 key (secp256k1, refused), OpenSSL-checked forms and one row per rule.
 *
 * Every key row runs at offset 0 and 1 (unaligned), and a failure must leave d all-zero. The
 * parser is one-shot, so "split input" becomes a prefix sweep: every prefix shorter than the
 * row's min_ok is BRISK_E_ARG (32 excepted - 32 bytes are a raw d by definition), every longer
 * one gives the same d; a DER row with ANY byte appended is refused, a PEM row with a newline
 * appended is not (text after the END line is allowed, RFC 7468 2). The PEM rows check that the
 * size pass (out NULL) counts exactly what the write pass writes, and that a failed write pass
 * leaves the output wiped. Suite "key"; empty without BRISK_ENABLE_MTLS. */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_MTLS
struct key_kat {
    const char *in;
    int ok;
    const char *d;
    int min_ok;
    const char *note;
};
struct key_pem_kat {
    const char *in;
    int cap;
    int ok;
    const char *blobs;
    const char *note;
};
#    include "kat/key.inc"

static uint8_t blob[4096 + 1], in_buf[4096 + 2], want_b[4096], got_b[4096], out[4096];

static int zero32(const uint8_t *p)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < 32; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

static void key_rows(void)
{
    uint8_t d[32], want[32];
    size_t i, len, k, off;
    unsigned b;
    int rc;

    for (i = 0; i < sizeof KEY_KAT / sizeof KEY_KAT[0]; i++) {
        const struct key_kat *r = &KEY_KAT[i];
        len = t_unhex(r->in, blob, sizeof blob - 1);
        if (r->ok) {
            t_unhex(r->d, want, sizeof want);
        }
        for (off = 0; off < 2; off++) {
            memcpy(in_buf + off, blob, len);
            memset(d, 0xa5, sizeof d);
            rc = brisk__x509_p256_key(d, in_buf + off, len);
            CHECKI(rc == (r->ok ? BRISK_OK : BRISK_E_ARG), i);
            CHECKI(r->ok ? memcmp(d, want, 32) == 0 : zero32(d), i);
            CHECKI(memcmp(in_buf + off, blob, len) == 0, i); /* the input is never written */
        }
        if (!r->ok || len == 32) {
            continue;
        }
        for (k = 0; k < len; k++) {
            if (k == 32) {
                continue;
            }
            memset(d, 0xa5, sizeof d);
            rc = brisk__x509_p256_key(d, blob, k);
            if (k < (size_t)r->min_ok) {
                CHECKI(rc == BRISK_E_ARG && zero32(d), i);
            } else {
                CHECKI(rc == BRISK_OK && memcmp(d, want, 32) == 0, i);
            }
        }
        if (blob[0] == BRISK__DER_SEQUENCE) {
            for (b = 0; b < 256; b++) { /* trailing junk: every value of the extra byte */
                blob[len] = (uint8_t)b;
                memset(d, 0xa5, sizeof d);
                CHECKI(brisk__x509_p256_key(d, blob, len + 1) == BRISK_E_ARG && zero32(d), i);
            }
        } else {
            blob[len] = '\n';
            CHECKI(brisk__x509_p256_key(d, blob, len + 1) == BRISK_OK && memcmp(d, want, 32) == 0,
                   i);
        }
    }
    CHECK(brisk__x509_p256_key(NULL, blob, 32) == BRISK_E_ARG);
    memset(d, 1, sizeof d);
    CHECK(brisk__x509_p256_key(d, NULL, 32) == BRISK_E_ARG && zero32(d));
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

static void pem_rows(void)
{
    size_t i, len, want_len, got_len, off, off1, n1, n2, cap;
    int rc, rc1;

    for (i = 0; i < sizeof KEY_PEM_KAT / sizeof KEY_PEM_KAT[0]; i++) {
        const struct key_pem_kat *r = &KEY_PEM_KAT[i];
        len = t_unhex(r->in, blob, sizeof blob);
        want_len = t_unhex(r->blobs, want_b, sizeof want_b);
        cap = (size_t)r->cap;
        got_len = 0;
        off = 0;
        for (;;) {
            off1 = off;
            memset(out, 0, sizeof out);
            rc1 = brisk__x509_pem_block(blob, len, &off1, "CERTIFICATE", NULL, 0, &n1);
            rc = brisk__x509_pem_block(blob, len, &off, "CERTIFICATE", out, cap, &n2);
            if (rc == BRISK_OK) {
                /* pass 1 counts exactly what pass 2 writes, and ends at the same place */
                CHECKI(rc1 == BRISK_OK && n1 == n2 && off1 == off && off <= len, i);
            } else {
                CHECKI(n2 == 0 && all_zero(out, sizeof out), i); /* a failed write is wiped */
            }
            if (rc != BRISK_OK || n2 == 0) {
                break;
            }
            CHECKI(got_len + 2 + n2 <= sizeof got_b, i);
            if (got_len + 2 + n2 > sizeof got_b) {
                break;
            }
            got_b[got_len] = (uint8_t)(n2 >> 8);
            got_b[got_len + 1] = (uint8_t)n2;
            memcpy(got_b + got_len + 2, out, n2);
            got_len += 2 + n2;
        }
        CHECKI((rc == BRISK_OK) == (r->ok != 0), i);
        CHECKI(got_len == want_len && memcmp(got_b, want_b, want_len) == 0, i);
        CHECKI(rc != BRISK_OK || off == len, i);
    }
    off = 2;
    CHECK(brisk__x509_pem_block(blob, 1, &off, "CERTIFICATE", NULL, 0, &n1) == BRISK_E_ARG &&
          n1 == 0);
    off = 0;
    CHECK(brisk__x509_pem_block(NULL, 1, &off, "CERTIFICATE", NULL, 0, &n1) == BRISK_E_ARG);
    CHECK(brisk__x509_pem_block(blob, 1, NULL, "CERTIFICATE", NULL, 0, &n1) == BRISK_E_ARG);
    CHECK(brisk__x509_pem_block(blob, 1, &off, NULL, NULL, 0, &n1) == BRISK_E_ARG);
    CHECK(brisk__x509_pem_block(blob, 1, &off, "CERTIFICATE", NULL, 0, NULL) == BRISK_E_ARG);
}
#endif

void test_key(void)
{
#if BRISK_ENABLE_MTLS
    key_rows();
    pem_rows();
#endif
}
