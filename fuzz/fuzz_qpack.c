/* fuzz_qpack.c - libFuzzer / AFL++ entry point for QPACK, static table only (RFC 9204;
 * src/http/qpack.c): the field-section decoder, the encoder, and the encoder / decoder
 * instruction-stream parsers.
 *
 *   python tools/dev.py fuzz qpack    # clang + ASan/UBSan, seeded from qpack_fuzz.inc
 *
 * Input: byte 0 selects the target (bits 0-1: 0 field section, 1 encoder stream, 2 decoder
 * stream) and a split point (bits 2-7); the rest is the input.
 * Oracles: a section decodes to BRISK_OK, BRISK_E_PROTO or BRISK__QPACK_E_LIMIT, never more
 * fields than bytes; on BRISK_OK the fields our encoder accepts re-encode and decode back to the
 * same list (N bits included). An instruction stream fed in two pieces (the partial instruction
 * carried over, as h3.c does) ends exactly like the same stream fed whole.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#ifndef BRISK_ENABLE_H3
#    define BRISK_ENABLE_H3 1 /* FULL only; dev.py passes the same -D to src/http/ */
#endif
#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FZ_FIELDS 32

typedef struct {
    uint8_t buf[8192];
    size_t len;
    brisk__hpack_field f[FZ_FIELDS];
    size_t n, at;
    int cmp, bad;
} fz_ctx;

static int fz_sink(void *ctx, const uint8_t *name, size_t nl, const uint8_t *value, size_t vl,
                   unsigned flags)
{
    fz_ctx *c = (fz_ctx *)ctx;
    if (c->cmp) {
        const brisk__hpack_field *w;
        if (c->at >= c->n) {
            c->bad = 1;
            return 0;
        }
        w = &c->f[c->at++];
        if (w->name_len != nl || w->value_len != vl || memcmp(w->name, name, nl) != 0 ||
            memcmp(w->value, value, vl) != 0 || w->flags != flags) {
            c->bad = 1;
        }
        return 0;
    }
    /* keep the first fields our encoder may send (RFC 9113 8.2.1 octets) */
    if (c->n < FZ_FIELDS && nl + vl <= sizeof c->buf - c->len &&
        brisk__hpack_field_ok(name, nl, value, vl)) {
        brisk__hpack_field *f = &c->f[c->n++];
        memcpy(c->buf + c->len, name, nl);
        memcpy(c->buf + c->len + nl, value, vl);
        f->name = c->buf + c->len;
        f->name_len = nl;
        f->value = c->buf + c->len + nl;
        f->value_len = vl;
        f->flags = flags;
        c->len += nl + vl;
    }
    return 0;
}

static int fz_stream(int dec, const uint8_t *in, size_t len, size_t *used, uint64_t *err)
{
    return dec ? brisk__qpack_dec_stream(in, len, used, err)
               : brisk__qpack_enc_stream(in, len, used, err);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t scratch[4096], out[16384], two[1u << 17];
    static fz_ctx c;
    size_t n, split, used, u1, u2, have;
    uint64_t err, err2;
    int rc, rc2, dec;

    if (size < 1) {
        return 0;
    }
    split = (size_t)(data[0] >> 2);
    dec = (data[0] & 3) == 2;
    n = size - 1;
    if ((data[0] & 3) == 0) {
        memset(&c, 0, sizeof c);
        rc = brisk__qpack_decode(data + 1, n, scratch, sizeof scratch, 8192, fz_sink, &c);
        if (rc != BRISK_OK && rc != BRISK_E_PROTO && rc != BRISK__QPACK_E_LIMIT) {
            abort();
        }
        if (rc == BRISK_OK && brisk__qpack_encode(c.f, c.n, out, sizeof out, &used) == BRISK_OK) {
            c.cmp = 1;
            c.at = 0;
            if (brisk__qpack_decode(out, used, scratch, sizeof scratch, 1u << 20, fz_sink, &c) !=
                    BRISK_OK ||
                c.bad || c.at != c.n) {
                abort(); /* our own output must read back unchanged */
            }
        }
        return 0;
    }
    /* whole, then in two pieces at `split` with the partial instruction carried over */
    rc = fz_stream(dec, data + 1, n, &u1, &err);
    split = split < n ? split : n;
    rc2 = fz_stream(dec, data + 1, split, &u2, &err2);
    if (rc2 == BRISK_OK) {
        have = split - u2;
        if (have + (n - split) > sizeof two) {
            return 0; /* longer than any libFuzzer input */
        }
        memcpy(two, data + 1 + u2, have);
        memcpy(two + have, data + 1 + split, n - split);
        rc2 = fz_stream(dec, two, have + n - split, &used, &err2);
        u2 += used;
    }
    if (rc != rc2 || err != err2 || (rc == BRISK_OK && u1 != u2) ||
        (rc == BRISK_OK) != (err == 0)) {
        abort();
    }
    return 0;
}
