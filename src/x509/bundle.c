/* bundle.c - one certificate at a time out of a PEM byte stream (RFC 7468).
 *
 * A CA bundle is a text file with a hundred-odd roots in it and no index, and the device that
 * has to search it has less RAM than the file has bytes. So this is a decoder, not a loader:
 * bytes go in in whatever slices the reader produced, a DER certificate comes out, and the only
 * memory that is held is the one certificate. Every scrap of state lives in brisk__x509_pem, so
 * a block may straddle any number of read() boundaries and nothing here knows what a file is -
 * which is the point, because src/os/ owns the syscalls and this owns the format.
 *
 * What it accepts, what it drops and why it is lenient are documented on the x509/bundle.c
 * block of src/brisk_int.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* Matched WHOLE, which is the only reason a "-----BEGIN RSA PRIVATE KEY-----" line cannot open
 * a certificate block. The NUL is not part of it. */
static const char BEGIN_LINE[] = "-----BEGIN CERTIFICATE-----";
#define BEGIN_LEN (sizeof BEGIN_LINE - 1)

/* PEM_-prefixed although they are file-scope: these are enum constants, so #undef cannot save
 * them if the amalgamation ever puts a record-layer or HPACK state machine in the same TU, and
 * PEM_SCAN is a name all three would want. */
enum { PEM_SCAN = 0, PEM_BODY = 1 };

/* The RFC 4648 4 alphabet, as a value or -1. A table would be 256 bytes of flash to save a
 * handful of comparisons on data that is not secret and not hot: this runs ~200 KB per
 * handshake at most, against public bytes, so the branches are free and the flash is not. */
static int b64_val(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

void brisk__x509_pem_init(brisk__x509_pem *p)
{
    if (p != NULL) {
        /* der[] is deliberately NOT cleared: 2 KB of stores on every lookup, to hide bytes that
         * der_len already says are not there. der_len is what bounds every read of it. */
        p->der_len = 0;
        p->acc = 0;
        p->bits = 0;
        p->tok = 0;
        p->state = PEM_SCAN;
        p->over = 0;
        p->bol = 1; /* the first byte of the stream starts a line */
    }
}

/* Leave a body and go back to looking for a BEGIN line. `c` is the byte that ended it and
 * `at_bol` says whether it stood at the start of a line; the pair is offered to the matcher
 * rather than dropped, because a body with no END line at all is ended by the '-' of the NEXT
 * BEGIN line - and that '-' is the one the match has to start from, or the certificate after a
 * truncated one is lost. der_len is left alone: the caller reads it when feed() returns a
 * block, and a new body zeroes it before writing anything. */
static void to_scan(brisk__x509_pem *p, uint8_t c, int at_bol)
{
    p->state = PEM_SCAN;
    p->tok = (uint8_t)(at_bol && c == (uint8_t)BEGIN_LINE[0] ? 1 : 0);
    p->acc = 0;
    p->bits = 0;
    p->over = 0;
}

int brisk__x509_pem_feed(brisk__x509_pem *p, const uint8_t **in, size_t *len)
{
    const uint8_t *s;
    size_t n;

    if (p == NULL || in == NULL || *in == NULL || len == NULL) {
        return 0;
    }
    s = *in;
    n = *len;
    while (n > 0) {
        uint8_t c = *s++;
        /* Whether THIS byte stands at the start of a line, tracked in every state: a body ends
         * on a byte the scanner may have to start matching from, so the flag has to be current
         * there too, not only while scanning. */
        int at_bol = p->bol;
        n--;
        p->bol = (uint8_t)(c == '\n');
        if (p->state == PEM_SCAN) {
            /* A match may only START at the beginning of a line (RFC 7468 3: the boundary is
             * its own line). Anchoring costs one flag and buys the end of a parser
             * DIFFERENTIAL: OpenSSL's PEM_read_bio anchors too, so without this an indented or
             * mid-line block would be a trust anchor to this library and invisible to the
             * tooling an integrator audits the bundle with before shipping it. */
            if (p->tok != 0 || at_bol) {
                if (c == (uint8_t)BEGIN_LINE[p->tok]) {
                    if (++p->tok == BEGIN_LEN) {
                        p->state = PEM_BODY;
                        p->tok = 0;
                        p->der_len = 0;
                        p->acc = 0;
                        p->bits = 0;
                        p->over = 0;
                    }
                } else {
                    p->tok = 0; /* the next line start is the next chance */
                }
            }
            continue;
        }
        if (c == '-') { /* the END line, or the next BEGIN after a truncated block */
            int over = p->over;
            to_scan(p, c, at_bol);
            if (over) {
                p->der_len = 0; /* the block is gone, not truncated: never hand over a prefix */
                continue;
            }
            *in = s;
            *len = n;
            return 1;
        }
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue; /* padding and layout; the length is what says how many bytes there are */
        }
        {
            int v = b64_val(c);
            if (v < 0) {
                to_scan(p, c, at_bol); /* junk in a body: drop the block, keep the file */
                p->der_len = 0;
                continue;
            }
            if (p->over) {
                continue; /* already too big; keep reading to find the END line */
            }
            p->acc = (p->acc << 6) | (uint32_t)v;
            p->bits = (uint8_t)(p->bits + 6);
            if (p->bits >= 8) {
                p->bits = (uint8_t)(p->bits - 8);
                if (p->der_len >= sizeof p->der) {
                    p->over = 1;
                } else {
                    p->der[p->der_len++] = (uint8_t)(p->acc >> p->bits);
                }
            }
        }
    }
    *in = s;
    *len = n;
    return 0;
}

#undef BEGIN_LEN
