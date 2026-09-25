/* test_qpack.c - QPACK, static table only (RFC 9204; src/http/qpack.c).
 *
 * tests/kat/qpack.inc (tools/kat.py): RFC 9204 B.1 (the one static-only example) and B.2-B.5 as
 * invalid rows; ls-qpack's .qif captures encoded server-style (Huffman, name references, N bits,
 * huge Delta Base); every dynamic-table form, bad prefixes, bad integers and strings; local
 * limits; our encoder policy byte for byte; the encoder / decoder instruction streams. Every
 * verdict comes from PyQpackDec, cross-checked with ls-qpack at generation time.
 *
 * Inputs are always decoded from an odd address. The integer sweep runs on every preset, which
 * covers the 32-bit and big-endian targets (constant shifts only, no 64-bit division). The
 * instruction streams are fed at every split point with the partial instruction carried over,
 * exactly as h3.c does. The whole file sits inside #if BRISK_ENABLE_H3; other profiles run an
 * empty suite. */
#include <stdio.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_H3

struct qpack_int_kat {
    const char *hex;
    unsigned n;
    uint64_t v;
    unsigned used;
    int rc;
    const char *note;
};
struct qpack_dec_kat {
    const char *blk, *fields;
    int rc;
    unsigned scratch, max_list;
    const char *note;
};
struct qpack_enc_kat {
    const char *fields, *blk;
    int rc;
    const char *note;
};
struct qpack_ins_kat {
    unsigned dec;
    const char *hex;
    int rc;
    unsigned err, used;
    const char *note;
};
#    include "kat/qpack.inc"

#    define T_BUF (1u << 17)
static uint8_t g_in[T_BUF + 8], g_want[T_BUF], g_got[T_BUF], g_scratch[1u << 16], g_out[T_BUF];

typedef struct {
    uint8_t *buf;
    size_t len;
    int abort_at; /* return 7 from this field (1-based), 0 = never */
    int n;
} sink;

static int on_field(void *ctx, const uint8_t *name, size_t nl, const uint8_t *value, size_t vl,
                    unsigned flags)
{
    sink *s = (sink *)ctx;
    if (++s->n == s->abort_at) {
        return 7;
    }
    if (nl + vl + 5 > T_BUF - s->len) {
        return 99;
    }
    brisk__store_be16(s->buf + s->len, (uint32_t)nl);
    memcpy(s->buf + s->len + 2, name, nl);
    brisk__store_be16(s->buf + s->len + 2 + nl, (uint32_t)vl);
    memcpy(s->buf + s->len + 4 + nl, value, vl);
    s->buf[s->len + 4 + nl + vl] = (uint8_t)flags;
    s->len += nl + vl + 5;
    return 0;
}

static void test_int(void)
{
    size_t i, n, used;
    uint64_t v;
    int rc;
    for (i = 0; i < sizeof QPACK_INT_KAT / sizeof QPACK_INT_KAT[0]; i++) {
        const struct qpack_int_kat *k = &QPACK_INT_KAT[i];
        n = t_unhex(k->hex, g_in + 1, T_BUF);
        v = 0xa5;
        used = 99;
        rc = brisk__qpack_int_decode(g_in + 1, n, k->n, &v, &used);
        CHECKI(rc == k->rc, i);
        CHECKI(rc != BRISK_OK || (v == k->v && used == k->used), i);
        /* octets after the integer never change it */
        if (rc == BRISK_OK) {
            g_in[1 + n] = 0xff;
            CHECKI(brisk__qpack_int_decode(g_in + 1, n + 1, k->n, &v, &used) == BRISK_OK &&
                       v == k->v && used == k->used,
                   i);
        }
    }
    CHECK(brisk__qpack_int_decode(g_in, 1, 0, &v, &used) == BRISK_E_ARG);
    CHECK(brisk__qpack_int_decode(g_in, 1, 9, &v, &used) == BRISK_E_ARG);
    CHECK(brisk__qpack_int_decode(NULL, 1, 8, &v, &used) == BRISK_E_ARG);
}

static void test_decode(void)
{
    size_t i, n, wn;
    sink s;
    int rc;
    for (i = 0; i < sizeof QPACK_DEC_KAT / sizeof QPACK_DEC_KAT[0]; i++) {
        const struct qpack_dec_kat *k = &QPACK_DEC_KAT[i];
        n = t_unhex(k->blk, g_in + 1, T_BUF);
        wn = t_unhex(k->fields, g_want, T_BUF);
        memset(&s, 0, sizeof s);
        s.buf = g_got;
        rc = brisk__qpack_decode(g_in + 1, n, g_scratch, k->scratch, k->max_list, on_field, &s);
        CHECKI(rc == k->rc, i);
        if (rc != k->rc) {
            fprintf(stderr, "  qpack row %lu (%s): got %d\n", (unsigned long)i, k->note, rc);
        }
        CHECKI(rc != BRISK_OK || (s.len == wn && memcmp(g_got, g_want, wn) == 0), i);
        /* a nonzero callback result aborts the section and comes back as-is */
        if (rc == BRISK_OK && wn != 0) {
            memset(&s, 0, sizeof s);
            s.buf = g_got;
            s.abort_at = 1;
            CHECKI(brisk__qpack_decode(g_in + 1, n, g_scratch, k->scratch, k->max_list, on_field,
                                       &s) == 7,
                   i);
        }
    }
    memset(&s, 0, sizeof s);
    s.buf = g_got;
    CHECK(brisk__qpack_decode(NULL, 2, g_scratch, 16, 16, on_field, &s) == BRISK_E_ARG);
    CHECK(brisk__qpack_decode(g_in, 2, NULL, 16, 16, on_field, &s) == BRISK_E_ARG);
    CHECK(brisk__qpack_decode(g_in, 2, g_scratch, 16, 16, NULL, &s) == BRISK_E_ARG);
}

/* [u16 nl][n][u16 vl][v][u8 flags]... -> fields pointing into buf */
static size_t parse_fields(const uint8_t *buf, size_t len, brisk__hpack_field *f, size_t max)
{
    size_t p = 0, n = 0;
    while (p < len && n < max) {
        f[n].name_len = brisk__load_be16(buf + p);
        f[n].name = buf + p + 2;
        p += 2 + f[n].name_len;
        f[n].value_len = brisk__load_be16(buf + p);
        f[n].value = buf + p + 2;
        p += 2 + f[n].value_len;
        f[n].flags = buf[p++];
        n++;
    }
    return n;
}

static void test_encode(void)
{
    static brisk__hpack_field f[64];
    size_t i, n, wn, fn, out_len;
    sink s;
    int rc;
    for (i = 0; i < sizeof QPACK_ENC_KAT / sizeof QPACK_ENC_KAT[0]; i++) {
        const struct qpack_enc_kat *k = &QPACK_ENC_KAT[i];
        n = t_unhex(k->fields, g_in + 1, T_BUF);
        fn = parse_fields(g_in + 1, n, f, 64);
        wn = t_unhex(k->blk, g_want, T_BUF);
        out_len = 99;
        rc = brisk__qpack_encode(f, fn, g_out + 1, T_BUF - 1, &out_len);
        CHECKI(rc == k->rc, i);
        if (rc != BRISK_OK) {
            CHECKI(out_len == 0, i);
            continue;
        }
        CHECKI(out_len == wn && memcmp(g_out + 1, g_want, wn) == 0, i);
        /* exact room is enough, one octet less is BRISK_E_ARG with nothing reported */
        CHECKI(brisk__qpack_encode(f, fn, g_out + 1, wn, &out_len) == BRISK_OK && out_len == wn, i);
        CHECKI(brisk__qpack_encode(f, fn, g_out + 1, wn - 1, &out_len) == BRISK_E_ARG &&
                   out_len == 0,
               i);
        /* our decoder reads it back, N bits included */
        memset(&s, 0, sizeof s);
        s.buf = g_got;
        CHECKI(brisk__qpack_decode(g_out + 1, wn, g_scratch, sizeof g_scratch, 1u << 20, on_field,
                                   &s) == BRISK_OK &&
                   s.len == n && memcmp(g_got, g_in + 1, n) == 0,
               i);
    }
    CHECK(brisk__qpack_encode(NULL, 1, g_out, 8, &out_len) == BRISK_E_ARG && out_len == 0);
    CHECK(brisk__qpack_encode(NULL, 0, g_out, 8, NULL) == BRISK_E_ARG);
}

/* Feed data[0..n) to the parser in pieces (cut at `a`, then at `b`), keeping the partial
 * instruction as h3.c does. Returns the parser's final result; *used = total consumed. */
static int ins_feed(unsigned dec, const uint8_t *data, size_t n, size_t a, size_t b, size_t *used,
                    uint64_t *err)
{
    uint8_t buf[64 + 8];
    size_t have = 0, pos = 0, u, cut[3];
    unsigned c;
    int rc = BRISK_OK;
    cut[0] = a;
    cut[1] = b;
    cut[2] = n;
    *used = 0;
    *err = 0;
    for (c = 0; c < 3; c++) {
        size_t end = cut[c] < pos ? pos : cut[c];
        while (pos < end) { /* bytes arrive; the buffer holds at most one partial instruction */
            size_t k = end - pos < sizeof buf - 1 - have ? end - pos : sizeof buf - 1 - have;
            memcpy(buf + 1 + have, data + pos, k);
            have += k;
            pos += k;
            rc = dec ? brisk__qpack_dec_stream(buf + 1, have, &u, err)
                     : brisk__qpack_enc_stream(buf + 1, have, &u, err);
            *used += u;
            if (rc != BRISK_OK) {
                return rc;
            }
            memmove(buf + 1, buf + 1 + u, have - u);
            have -= u;
            if (have >= 32) {
                return -100; /* a partial instruction never grows this big */
            }
        }
    }
    return rc;
}

static void test_ins(void)
{
    size_t i, n, a, b, used;
    uint64_t err;
    int rc, ok;
    for (i = 0; i < sizeof QPACK_INS_KAT / sizeof QPACK_INS_KAT[0]; i++) {
        const struct qpack_ins_kat *k = &QPACK_INS_KAT[i];
        n = t_unhex(k->hex, g_in, T_BUF);
        ok = 1;
        for (a = 0; a <= n; a++) {
            for (b = a; b <= n; b++) {
                rc = ins_feed(k->dec, g_in, n, a, b, &used, &err);
                ok &= rc == k->rc && err == k->err && used == k->used;
            }
        }
        /* one octet at a time */
        {
            size_t u = 0, tot = 0, have = 0;
            uint8_t one[16];
            rc = BRISK_OK;
            err = 0;
            for (a = 0; a < n && rc == BRISK_OK; a++) {
                one[have++] = g_in[a];
                rc = k->dec ? brisk__qpack_dec_stream(one, have, &u, &err)
                            : brisk__qpack_enc_stream(one, have, &u, &err);
                tot += u;
                memmove(one, one + u, have - u);
                have -= u;
            }
            ok &= rc == k->rc && err == k->err && tot == k->used;
        }
        CHECKI(ok, i);
        if (!ok) {
            fprintf(stderr, "  qpack ins row %lu: %s\n", (unsigned long)i, k->note);
        }
    }
    CHECK(brisk__qpack_enc_stream(NULL, 1, &used, &err) == BRISK_E_ARG);
    CHECK(brisk__qpack_dec_stream(g_in, 1, NULL, &err) == BRISK_E_ARG);
}

void test_qpack(void)
{
    test_int();
    test_decode();
    test_encode();
    test_ins();
}

#else

void test_qpack(void)
{
    CHECK(1); /* BRISK_ENABLE_H3 is 0 in this profile */
}

#endif
