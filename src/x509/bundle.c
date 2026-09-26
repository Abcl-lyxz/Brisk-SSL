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

/* The RFC 4648 4 alphabet in mask arithmetic, no branch and no table. The streaming reader only
 * ever sees public certificates, but brisk__x509_pem_block also decodes the device's PRIVATE KEY,
 * whose base64 characters ARE the secret - so the one function both use must not branch or index
 * on the character (base64 decoders are a known key-loading side channel). A 256-byte table would
 * also cost more flash than these few instructions. b64_in is all-ones when lo <= c <= hi: for
 * c < 256 either subtraction wraps (sets bit 31) exactly when c is outside. */
static uint32_t b64_in(uint32_t c, uint32_t lo, uint32_t hi)
{
    return (((c - lo) | (hi - c)) >> 31) - 1u;
}

/* The 6-bit value of c; *ok is all-ones when c is in the alphabet, else 0 (and the value 0). */
static uint32_t b64_ct(uint32_t c, uint32_t *ok)
{
    uint32_t m, v = 0, k = 0;
    m = b64_in(c, 'A', 'Z');
    v |= m & (c - 'A');
    k |= m;
    m = b64_in(c, 'a', 'z');
    v |= m & (c - ('a' - 26));
    k |= m;
    m = b64_in(c, '0', '9');
    v |= m & (c + (52 - '0'));
    k |= m;
    m = b64_in(c, '+', '+');
    v |= m & 62u;
    k |= m;
    m = b64_in(c, '/', '/');
    v |= m & 63u;
    k |= m;
    *ok = k;
    return v;
}

/* The value, or -1 outside the alphabet (the streaming reader's public branch). */
static int b64_val(uint8_t c)
{
    uint32_t ok, v = b64_ct(c, &ok);
    return (int)(v & ok) - (int)(~ok & 1u);
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

#if BRISK_ENABLE_MTLS
/* ---- one-shot and STRICT: the device's own chain and key (see brisk_int.h for
 * why) -------- */

/* Body byte classes. The loop branches on the class, which is declassified: it
 * says where the layout is and that a character is in the alphabet, never which
 * character it is. */
enum { PEM_K_BAD = 0, PEM_K_DATA = 1, PEM_K_PAD = 2, PEM_K_WS = 4, PEM_K_LF = 8, PEM_K_DASH = 16 };

static uint32_t pem_eq(uint32_t c, uint32_t x)
{
    return b64_in(c, x, x);
}

/* The length of "-----" kw label "-----" when in[i..len) starts with it, else
 * 0. Only ever called on a '-' at a line start, which no valid body contains:
 * public text. */
static size_t pem_line(const uint8_t *in, size_t len, size_t i, const char *kw, const char *label)
{
    size_t k = strlen(kw), l = strlen(label);
    if (len - i < 10 + k + l || memcmp(in + i, "-----", 5) != 0 || memcmp(in + i + 5, kw, k) != 0 ||
        memcmp(in + i + 5 + k, label, l) != 0 || memcmp(in + i + 5 + k + l, "-----", 5) != 0) {
        return 0;
    }
    return 10 + k + l;
}

int brisk__x509_pem_block(const uint8_t *in, size_t len, size_t *off, const char *label,
                          uint8_t *out, size_t cap, size_t *out_len)
{
    size_t i, k = 0, n = 0, chars = 0, pads = 0;
    uint32_t acc = 0, bits = 0, bad = 0, bol = 0, hdr = 1, cls, ok, v, c;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (in == NULL || off == NULL || label == NULL || out_len == NULL || *off > len) {
        return BRISK_E_ARG;
    }
    /* RFC 7468 2: BEGIN at a line start (the streaming reader's anchor, and
     * OpenSSL's) and the label matched WHOLE, so "-----BEGIN EC PRIVATE KEY-----"
     * is no "PRIVATE KEY" block and "ENCRYPTED PRIVATE KEY" never matches at all.
     * "A '-' at a line start" is computed without a branch on the byte: this scan
     * also crosses the bodies of blocks with other labels, and one of those may
     * be a private key. */
    for (i = *off; i < len; i++) {
        uint32_t at = pem_eq(in[i], '-') & (i == 0 ? ~0u : pem_eq(in[i - 1], '\n'));
        BRISK__CT_PUBLIC(&at, sizeof at);
        if (at != 0 && (k = pem_line(in, len, i, "BEGIN ", label)) != 0) {
            break;
        }
    }
    if (i >= len) {
        *off = len;
        return BRISK_OK; /* no more blocks */
    }
    /* RFC 4648 3.3: "MUST reject ... characters outside the base alphabet" - SP /
     * HTAB / CR / LF are RFC 7468's layout (its lax W without VT / FF), anything
     * else fails the block. A bad character is accumulated, not returned on the
     * spot: the characters are the secret. */
    for (i += k;; i++) {
        if (i >= len) {
            goto fail; /* no END line */
        }
        c = in[i];
        v = b64_ct(c, &ok);
        cls = (ok & PEM_K_DATA) | (pem_eq(c, '=') & PEM_K_PAD) |
              ((pem_eq(c, ' ') | pem_eq(c, '\t') | pem_eq(c, '\r')) & PEM_K_WS) |
              (pem_eq(c, '\n') & PEM_K_LF) | (pem_eq(c, '-') & PEM_K_DASH);
        BRISK__CT_PUBLIC(&cls, sizeof cls);
        if (cls == PEM_K_DASH) {
            break;
        }
        if (cls == PEM_K_LF) {
            hdr = 0;
        } else if ((cls & (PEM_K_DATA | PEM_K_PAD)) != 0) {
            bad |= hdr; /* RFC 7468 2: the BEGIN line is a line of its own */
        }
        if (cls == PEM_K_DATA) {
            bad |= (uint32_t)(pads != 0); /* '=' only at the end */
            chars++;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                if (out != NULL) {
                    if (n >= cap) {
                        goto fail;
                    }
                    out[n] = (uint8_t)(acc >> bits);
                }
                n++;
            }
        } else if (cls == PEM_K_PAD) {
            pads++;
            chars++;
        } else if (cls == PEM_K_BAD) {
            bad = 1;
        }
        bol = (uint32_t)(cls == PEM_K_LF);
    }
    /* RFC 7468 2: the END line is its own line and carries the SAME label. The
     * count includes the pads and is a whole number of quanta, at most two '='
     * (RFC 4648 4). */
    if (!bol || (k = pem_line(in, len, i, "END ", label)) == 0 || chars == 0 || (chars & 3u) != 0 ||
        pads > 2) {
        goto fail;
    }
    /* RFC 4648 3.5: the pad bits of the last quantum are zero ("decoders MAY
     * choose to reject" and this one does: one canonical encoding per key). They
     * are secret-derived, so they are folded into one 0/1 verdict and only that
     * is declassified. */
    bad |= acc & ((1u << bits) - 1u);
    bad = (bad | (0u - bad)) >> 31;
    BRISK__CT_PUBLIC(&bad, sizeof bad);
    if (bad != 0) {
        goto fail;
    }
    *off = i + k;
    *out_len = n;
    return BRISK_OK;
fail:
    if (out != NULL) {
        brisk__secure_zero(out, n); /* n <= cap: only written bytes are counted */
    }
    return BRISK_E_ARG;
}
#endif /* BRISK_ENABLE_MTLS */
