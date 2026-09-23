/* fuzz_hpack.c - libFuzzer / AFL++ entry point for the HPACK decoder, the Huffman decoder and the
 * encoder (RFC 7541).
 *
 *   python tools/dev.py fuzz hpack    # clang + ASan/UBSan, seeded from hpack_fuzz.inc
 *
 * Input: byte 0 selects our advertised table limit (bits 0-1: 0, 256, 4096, 65535) and the
 * max_list (bits 2-3: 64, 1024, 16384, 65536); the rest is [u16 BE length][block]... fed through
 * ONE decoder, as consecutive field blocks on one connection (a short last length is clamped).
 * Oracle: the verdict is BRISK_OK or BRISK_E_PROTO; the ring invariants hold after every call
 * (size <= max <= limit, used <= limit, used + 28 * count == size); after an error every later
 * call is BRISK_E_PROTO. The raw input also goes through brisk__huff_decode. The first fields
 * the decoder delivers are re-encoded: when our encoder accepts them, a fresh decoder must read
 * back the same list and keep an empty table (the encoder never indexes).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FZ_FIELDS 16

typedef struct {
    uint8_t buf[4096];
    size_t len;
    brisk__hpack_field f[FZ_FIELDS];
    size_t n;
    int cmp; /* compare mode: the list must equal f[] in order */
    size_t at;
    int bad;
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
            memcmp(w->value, value, vl) != 0 ||
            (w->flags & BRISK__HPACK_NEVER_INDEXED) != (flags & BRISK__HPACK_NEVER_INDEXED)) {
            c->bad = 1;
        }
        return 0;
    }
    if (c->n < FZ_FIELDS && nl + vl <= sizeof c->buf - c->len) {
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

static void fz_invariants(const brisk__hpack_dec *d)
{
    if (d->size > d->max || d->max > d->limit || d->used > d->limit ||
        d->used + 28 * d->count != d->size || d->count * 32 > d->size) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint32_t LIMIT[4] = {0, 256, 4096, 65535};
    static const size_t MAX_LIST[4] = {64, 1024, 16384, 65536};
    static uint8_t ring[65535], scratch[4096], huff[16384], enc[8192];
    static fz_ctx ctx;
    brisk__hpack_dec d;
    brisk__hpack_enc e;
    size_t p = 1, n;
    int rc = BRISK_OK;

    if (size == 0) {
        return 0;
    }
    /* raw Huffman: 8 input bits can yield at most 8/5 symbols, so the cap never binds here */
    rc = brisk__huff_decode(data, size, huff, sizeof huff, &n);
    if ((rc != BRISK_OK && rc != BRISK_E_PROTO) || (rc == BRISK_OK && n > size * 8 / 5)) {
        abort();
    }

    memset(&ctx, 0, sizeof ctx);
    if (brisk__hpack_dec_init(&d, ring, LIMIT[data[0] & 3]) != BRISK_OK) {
        abort();
    }
    rc = BRISK_OK;
    while (p + 2 <= size) {
        size_t bl = brisk__load_be16(data + p);
        p += 2;
        if (bl > size - p) {
            bl = size - p;
        }
        rc = brisk__hpack_decode(&d, data + p, bl, scratch, sizeof scratch,
                                 MAX_LIST[(data[0] >> 2) & 3], fz_sink, &ctx);
        fz_invariants(&d);
        if (rc != BRISK_OK) {
            if (rc != BRISK_E_PROTO || !d.dead ||
                brisk__hpack_decode(&d, data + p, bl, scratch, sizeof scratch, 65536, fz_sink,
                                    &ctx) != BRISK_E_PROTO) {
                abort();
            }
            break;
        }
        p += bl;
    }

    /* encoder round trip on what the decoder delivered */
    brisk__hpack_enc_init(&e);
    brisk__hpack_enc_peer_max(&e, data[0] & 0x10 ? 0 : 4096);
    rc = brisk__hpack_encode(&e, ctx.f, ctx.n, enc, sizeof enc, &n);
    if (rc == BRISK_OK) {
        if (brisk__hpack_dec_init(&d, ring, 4096) != BRISK_OK) {
            abort();
        }
        ctx.cmp = 1;
        ctx.at = 0;
        if (brisk__hpack_decode(&d, enc, n, scratch, sizeof scratch, (size_t)1 << 20, fz_sink,
                                &ctx) != BRISK_OK ||
            ctx.bad || ctx.at != ctx.n || d.count != 0) {
            abort();
        }
    } else if (rc != BRISK_E_ARG || n != 0) {
        abort();
    }
    return 0;
}
