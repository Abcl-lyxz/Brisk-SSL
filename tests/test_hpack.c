/* test_hpack.c - HPACK (RFC 7541): prefixed integers, the Huffman decoder, the decoder with its
 * dynamic-table ring, and the encoder. Every vector comes from tests/kat/hpack.inc (tools/kat.py):
 * RFC 7541 Appendix C, hpack-test-case stories from eight independent encoders, and generated
 * rows each confirmed by kat.py's independent Python decoder.
 *
 * Per block row the decoder's delivered fields, its verdict, `Table size` and (where listed) the
 * dynamic table newest-first must match; the ring invariants are checked after every call, and a
 * canary past the ring catches any write beyond `limit`. The whole block table runs at buffer
 * offsets 0..7 (block, ring and scratch unaligned). Appendix C blocks are also cut at every
 * prefix length: BRISK_OK exactly on the representation boundaries kat.py emitted.
 *
 * The whole file sits inside #if BRISK_ENABLE_H2; a TINY build runs an empty suite.
 */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_H2

struct hpack_int_kat {
    const char *hex;
    unsigned n;
    uint32_t v;
    size_t used;
    int ok;
    const char *note;
};
struct hpack_huff_kat {
    const char *enc, *dec;
    int ok;
    const char *note;
};
struct hpack_blk_kat {
    const char *wire;
    int fresh; /* start a new decoder of `limit` */
    uint32_t limit;
    size_t max_list, scratch;
    int ok;
    const char *fields; /* delivered: [u16 n][name][u16 v][value][u8 flags]... */
    const char *table;  /* newest first: [u16 n][name][u16 v][value]...; "" + size>0 = not listed */
    uint32_t table_size;
    const char *split; /* prefix lengths that decode OK (u16 each), or "" */
    const char *note;
};
struct hpack_enc_kat {
    const char *fields; /* as above, flags = BRISK__HPACK_NEVER_INDEXED or 0 */
    uint32_t peer_max;  /* 0xffffffff = no enc_peer_max call */
    int ok;
    const char *out1, *out2; /* first and second encode of the same list */
    const char *note;
};
#    include "kat/hpack.inc"

#    define T_SCRATCH 16384 /* must match HPACK_SCRATCH in tools/kat.py */
#    define T_BUF     65536
#    define T_CANARY  0xa5

static uint8_t g_wire[T_BUF + 8], g_want[T_BUF], g_got[T_BUF], g_tab[T_BUF], g_tab2[T_BUF];
static uint8_t g_ring[65536 + 8 + 64], g_ring2[65536], g_ring3[65536 + 8];
static uint8_t g_scratch[T_SCRATCH + 8];

/* callback: serialise every field as the .inc does */
typedef struct {
    uint8_t *buf;
    size_t len, cap;
    int calls, abort_at, abort_rc;
} sink;

static int collect(void *ctx, const uint8_t *name, size_t nl, const uint8_t *value, size_t vl,
                   unsigned flags)
{
    sink *s = (sink *)ctx;
    if (++s->calls == s->abort_at) {
        return s->abort_rc;
    }
    if (nl + vl + 5 > s->cap - s->len) {
        return 99; /* test buffer too small: fails the row loudly */
    }
    brisk__store_be16(s->buf + s->len, (uint32_t)nl);
    memcpy(s->buf + s->len + 2, name, nl);
    s->len += 2 + nl;
    brisk__store_be16(s->buf + s->len, (uint32_t)vl);
    memcpy(s->buf + s->len + 2, value, vl);
    s->len += 2 + vl;
    s->buf[s->len++] = (uint8_t)flags;
    return 0;
}

/* The ring newest first, in the .inc's table format, walking the documented layout
 * ([u16 BE n][u16 BE v][name][value], byte-wise wrap). */
static uint8_t rb(const brisk__hpack_dec *d, uint32_t p)
{
    return d->mem[p % d->limit];
}

static size_t dump_table(const brisk__hpack_dec *d, uint8_t *out)
{
    static uint32_t off[2048];
    uint32_t pos = d->head, i, k, nl, vl;
    size_t n = 0;
    for (i = 0; i < d->count && i < 2048; i++) {
        off[i] = pos;
        nl = (uint32_t)rb(d, pos) << 8 | rb(d, pos + 1);
        vl = (uint32_t)rb(d, pos + 2) << 8 | rb(d, pos + 3);
        pos = (pos + 4 + nl + vl) % d->limit;
    }
    while (i-- > 0) {
        pos = off[i];
        nl = (uint32_t)rb(d, pos) << 8 | rb(d, pos + 1);
        vl = (uint32_t)rb(d, pos + 2) << 8 | rb(d, pos + 3);
        brisk__store_be16(out + n, nl);
        n += 2;
        for (k = 0; k < nl; k++) {
            out[n++] = rb(d, pos + 4 + k);
        }
        brisk__store_be16(out + n, vl);
        n += 2;
        for (k = 0; k < vl; k++) {
            out[n++] = rb(d, pos + 4 + nl + k);
        }
    }
    return n;
}

static int invariants(const brisk__hpack_dec *d)
{
    return d->size <= d->max && d->max <= d->limit && d->used <= d->limit &&
           d->used + 28 * d->count == d->size && d->count * 32 <= d->size &&
           (d->count > 0 || (d->used == 0 && d->size == 0));
}

static void test_int(void)
{
    size_t i, off;
    for (i = 0; i < sizeof HPACK_INT_KAT / sizeof HPACK_INT_KAT[0]; i++) {
        const struct hpack_int_kat *r = &HPACK_INT_KAT[i];
        for (off = 0; off < 8; off += 3) {
            size_t len = t_unhex(r->hex, g_wire + off, 16), used = 777;
            uint32_t v = 12345;
            int rc = brisk__hpack_int_decode(g_wire + off, len, r->n, &v, &used);
            if (r->ok) {
                CHECKI(rc == BRISK_OK && v == r->v && used == r->used, i);
            } else {
                CHECKI(rc == BRISK_E_PROTO, i);
            }
        }
    }
    {
        uint32_t v;
        size_t used;
        CHECK(brisk__hpack_int_decode(g_wire, 1, 0, &v, &used) == BRISK_E_ARG);
        CHECK(brisk__hpack_int_decode(g_wire, 1, 9, &v, &used) == BRISK_E_ARG);
    }
}

static void test_huff(void)
{
    size_t i, n, len, want, out_len;
    for (i = 0; i < sizeof HPACK_HUFF_KAT / sizeof HPACK_HUFF_KAT[0]; i++) {
        const struct hpack_huff_kat *r = &HPACK_HUFF_KAT[i];
        size_t off = i % 8;
        len = t_unhex(r->enc, g_wire + off, 4096);
        want = t_unhex(r->dec, g_want, sizeof g_want);
        if (!r->ok) {
            CHECKI(brisk__huff_decode(g_wire + off, len, g_got, sizeof g_got, &out_len) ==
                       BRISK_E_PROTO,
                   i);
            continue;
        }
        n = 999;
        /* the exact cap passes; one octet less is an error (local limit) */
        CHECKI(brisk__huff_decode(g_wire + off, len, g_got + off, want, &n) == BRISK_OK &&
                   n == want && memcmp(g_got + off, g_want, want) == 0,
               i);
        if (want > 0) {
            CHECKI(brisk__huff_decode(g_wire + off, len, g_got, want - 1, &n) == BRISK_E_PROTO, i);
        }
    }
    CHECK(brisk__huff_decode(g_wire, 0, NULL, 0, &n) == BRISK_OK && n == 0); /* cap 0, empty */
}

static void load_fields(const char *hex, brisk__hpack_field *f, size_t *nf, uint8_t *buf)
{
    size_t len = t_unhex(hex, buf, T_BUF), p = 0;
    *nf = 0;
    while (p < len) {
        f[*nf].name_len = brisk__load_be16(buf + p);
        f[*nf].name = buf + p + 2;
        p += 2 + f[*nf].name_len;
        f[*nf].value_len = brisk__load_be16(buf + p);
        f[*nf].value = buf + p + 2;
        p += 2 + f[*nf].value_len;
        f[*nf].flags = buf[p++];
        (*nf)++;
    }
}

/* One pass over the block table with every buffer at offset `off`. */
static void run_blocks(size_t off, int do_split)
{
    static brisk__hpack_dec pre;
    brisk__hpack_dec d;
    uint8_t *ring = g_ring + off, *scr = g_scratch + off;
    size_t i, k, j;

    memset(&d, 0, sizeof d);
    for (i = 0; i < sizeof HPACK_BLK_KAT / sizeof HPACK_BLK_KAT[0]; i++) {
        const struct hpack_blk_kat *r = &HPACK_BLK_KAT[i];
        size_t len = t_unhex(r->wire, g_wire + off, T_BUF), want, tl;
        sink s = {g_got, 0, T_BUF, 0, 0, 0};
        int rc;
        if (r->fresh) {
            memset(g_ring, T_CANARY, sizeof g_ring);
            CHECKI(brisk__hpack_dec_init(&d, ring, r->limit) == BRISK_OK, i);
        }
        pre = d;
        memcpy(g_ring2, ring, r->limit);
        rc = brisk__hpack_decode(&d, g_wire + off, len, scr, r->scratch, r->max_list, collect, &s);
        CHECKI(rc == (r->ok ? BRISK_OK : BRISK_E_PROTO), i);
        want = t_unhex(r->fields, g_want, T_BUF);
        CHECKI(s.len == want && memcmp(g_got, g_want, want) == 0, i);
        CHECKI(invariants(&d), i);
        CHECKI(ring[r->limit] == T_CANARY && ring[r->limit + 63] == T_CANARY, i);
        if (!r->ok) {
            /* sticky: RFC 9113 4.3 connection error, even a valid block is refused now */
            CHECKI(d.dead && brisk__hpack_decode(&d, (const uint8_t *)"\x82", 1, scr, T_SCRATCH,
                                                 1024, collect, &s) == BRISK_E_PROTO,
                   i);
            continue;
        }
        CHECKI(d.size == r->table_size, i);
        if (r->table[0] || r->table_size == 0) {
            want = t_unhex(r->table, g_want, T_BUF);
            tl = dump_table(&d, g_tab);
            CHECKI(tl == want && memcmp(g_tab, g_want, want) == 0, i);
        }
        if (!do_split || !r->split[0]) {
            continue;
        }
        /* every prefix k on a copy of the pre-block state: OK iff k is a boundary */
        want = t_unhex(r->split, g_want, T_BUF);
        for (k = 0, j = 0; k <= len; k++) {
            brisk__hpack_dec t = pre;
            int ok = j < want && brisk__load_be16(g_want + j) == k;
            t.mem = g_ring3 + 5; /* a copy of the pre-block ring, itself unaligned */
            memcpy(t.mem, g_ring2, r->limit);
            memcpy(g_tab2, g_wire + off, k);
            memset(g_tab2 + k, 0xff, 16); /* anything read past k would change the verdict */
            s.len = 0;
            s.calls = 0;
            rc = brisk__hpack_decode(&t, g_tab2, k, scr, r->scratch, r->max_list, collect, &s);
            CHECKI(rc == (ok ? BRISK_OK : BRISK_E_PROTO), i);
            j += ok ? 2 : 0;
        }
        CHECKI(j == want, i);
    }
}

static const struct hpack_blk_kat *find_blk(const char *note)
{
    size_t i;
    for (i = 0; i < sizeof HPACK_BLK_KAT / sizeof HPACK_BLK_KAT[0]; i++) {
        if (strcmp(HPACK_BLK_KAT[i].note, note) == 0) {
            return &HPACK_BLK_KAT[i];
        }
    }
    return NULL;
}

static void test_dec_misc(void)
{
    brisk__hpack_dec d;
    const struct hpack_blk_kat *c31 = find_blk("RFC 7541 C.3.1");
    size_t len;
    sink s = {g_got, 0, T_BUF, 0, 2, 7};

    CHECK(brisk__hpack_dec_init(&d, g_ring, 65536) == BRISK_E_ARG);
    CHECK(brisk__hpack_dec_init(&d, NULL, 1) == BRISK_E_ARG);
    CHECK(brisk__hpack_dec_init(&d, NULL, 0) == BRISK_OK && d.need_update && d.max == 0);
    CHECK(brisk__hpack_dec_init(&d, g_ring, 8192) == BRISK_OK && !d.need_update && d.max == 4096);
    CHECK(brisk__hpack_decode(&d, NULL, 1, g_scratch, 1, 1, collect, &s) == BRISK_E_ARG);
    CHECK(brisk__hpack_decode(&d, g_wire, 1, NULL, 1, 1, collect, &s) == BRISK_E_ARG);
    CHECK(brisk__hpack_decode(&d, g_wire, 1, g_scratch, 1, 1, NULL, &s) == BRISK_E_ARG);
    CHECK(!d.dead); /* argument errors are local faults and leave the decoder alive */

    /* a callback's nonzero value comes back unchanged, and the decoder is dead afterwards */
    CHECK(c31 != NULL);
    if (c31) {
        len = t_unhex(c31->wire, g_wire, T_BUF);
        CHECK(brisk__hpack_dec_init(&d, g_ring, 4096) == BRISK_OK);
        CHECK(brisk__hpack_decode(&d, g_wire, len, g_scratch, T_SCRATCH, 65536, collect, &s) == 7);
        CHECK(s.calls == 2 && d.dead);
        s.abort_at = 0;
        CHECK(brisk__hpack_decode(&d, g_wire, len, g_scratch, T_SCRATCH, 65536, collect, &s) ==
              BRISK_E_PROTO);
    }
}

static void test_enc(void)
{
    static brisk__hpack_field f[64];
    static uint8_t fb[T_BUF], out[T_BUF + 8], want1[T_BUF], want2[T_BUF];
    size_t i, nf, n, w1, w2, off;
    for (i = 0; i < sizeof HPACK_ENC_KAT / sizeof HPACK_ENC_KAT[0]; i++) {
        const struct hpack_enc_kat *r = &HPACK_ENC_KAT[i];
        brisk__hpack_enc e, before;
        brisk__hpack_dec d;
        sink s = {g_got, 0, T_BUF, 0, 0, 0};
        off = i % 8;
        load_fields(r->fields, f, &nf, fb);
        brisk__hpack_enc_init(&e);
        if (r->peer_max != 0xffffffffu) {
            brisk__hpack_enc_peer_max(&e, r->peer_max);
        }
        before = e;
        n = 999;
        if (!r->ok) {
            CHECKI(brisk__hpack_encode(&e, f, nf, out + off, T_BUF, &n) == BRISK_E_ARG && n == 0 &&
                       memcmp(&e, &before, sizeof e) == 0,
                   i);
            continue;
        }
        w1 = t_unhex(r->out1, want1, T_BUF);
        w2 = t_unhex(r->out2, want2, T_BUF);
        /* one octet short: refused, nothing emitted, a pending size update still pending */
        CHECKI(brisk__hpack_encode(&e, f, nf, out + off, w1 - 1, &n) == BRISK_E_ARG && n == 0 &&
                   memcmp(&e, &before, sizeof e) == 0,
               i);
        CHECKI(brisk__hpack_encode(&e, f, nf, out + off, w1, &n) == BRISK_OK && n == w1 &&
                   memcmp(out + off, want1, w1) == 0,
               i);
        /* round trip: the same list back, and the peer's table untouched (no indexing, 7.1) */
        CHECKI(brisk__hpack_dec_init(&d, g_ring, 4096) == BRISK_OK &&
                   brisk__hpack_decode(&d, out + off, n, g_scratch, T_SCRATCH, 1u << 20, collect,
                                       &s) == BRISK_OK &&
                   d.count == 0 && s.len == t_unhex(r->fields, g_want, T_BUF) &&
                   memcmp(g_got, g_want, s.len) == 0,
               i);
        /* the size update goes out once */
        CHECKI(brisk__hpack_encode(&e, f, nf, out + off, T_BUF, &n) == BRISK_OK && n == w2 &&
                   memcmp(out + off, want2, w2) == 0 && e.pending == 0,
               i);
    }
    {
        brisk__hpack_enc e;
        brisk__hpack_enc_init(&e);
        CHECK(brisk__hpack_encode(&e, NULL, 0, NULL, 0, &n) == BRISK_OK && n == 0);
        CHECK(brisk__hpack_encode(&e, NULL, 1, out, 8, &n) == BRISK_E_ARG && n == 0);
        CHECK(brisk__hpack_encode(NULL, NULL, 0, out, 8, &n) == BRISK_E_ARG);
    }
}

void test_hpack(void)
{
    size_t off;
    test_int();
    test_huff();
    for (off = 0; off < 8; off++) {
        run_blocks(off, off == 0 || off == 3);
    }
    test_dec_misc();
    test_enc();
}

#else /* !BRISK_ENABLE_H2 */

void test_hpack(void)
{
    CHECK(1); /* HTTP/2 is compiled out in this profile */
}

#endif /* BRISK_ENABLE_H2 */
