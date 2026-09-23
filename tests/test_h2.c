/* test_h2.c - HTTP/2 (RFC 9113): frames, streams, flow control and the brisk_h2_* API.
 *
 * Every row of tests/kat/h2.inc (tools/kat.py) is a scenario: the server byte stream, a script of
 * public calls with the result each must return, and the exact client byte stream. A fake
 * transport serves the server bytes through the brisk__h2_rd_fn seam and captures what is
 * written, so the whole blocking API runs on every preset, the mingw host included.
 *
 * Each row is replayed with the server bytes cut into 1-byte, 7-byte, 9-byte (a frame header),
 * 4096-byte, whole and three seeded random chunk patterns, with the arena at offsets 0 / 1 / 3
 * (unaligned), and once more with a BRISK_E_TIMEOUT injected before every third read (the call
 * is simply repeated): results and client bytes must be identical every time. After the
 * closing brisk_h2_close the arena must be all zero.
 *
 * Script ops (space-separated; fields by ','; hex for bytes):
 *   O<rc>                                 brisk__h2_start (what brisk_h2_open blocks in)
 *   Q<slot>,<rc>,<method>,<path>,<hdrs>,<body>  brisk_h2_request;
 *                                         hdrs = [u16 n][name][u16 v][value]...
 *   R<slot>,<rc>,<status>,<hdrs>          brisk_h2_response; the callback's fields, same layout
 *   D<slot>,<rc>,<cap>,<data>             brisk_h2_read(cap) until <= 0: all data, final result
 *   d<slot>,<rc>,<cap>,<data>             one brisk_h2_read
 *   C<slot>                               brisk_h2_stream_close
 *   X                                     brisk_h2_close, then the arena must be zero
 *
 * The whole file sits inside #if BRISK_ENABLE_H2; a TINY build runs an empty suite.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_H2

struct h2_kat {
    const char *auth, *srv, *cli, *script, *note;
};
struct h2_fuzz_seed {
    const char *hex, *note;
};
#    include "kat/h2.inc"

#    define T_BUF   (1u << 17)
#    define T_ARENA (1u << 18)
#    define T_SLOTS 8

static uint8_t g_srv[T_BUF], g_cli[T_BUF], g_want[T_BUF], g_tmp[T_BUF], g_body[T_BUF];
static uint8_t g_arena[T_ARENA + 8];
static char g_tok[2 * T_BUF + 64], g_str[T_BUF];

typedef struct {
    const uint8_t *srv;
    size_t len, pos, chunk;
    uint32_t rng;
    size_t clen;
    int tmo, armed, reads, wr_fail, writes;
    size_t tmo_at; /* one BRISK_E_TIMEOUT once pos reaches it (0 = never) */
} fake;

static uint32_t f_next(fake *f)
{
    f->rng ^= f->rng << 13;
    f->rng ^= f->rng >> 17;
    f->rng ^= f->rng << 5;
    return f->rng;
}

static int f_rd(void *io, void *buf, size_t cap)
{
    fake *f = (fake *)io;
    size_t n;
    if (f->tmo && f->armed && ++f->reads % f->tmo == 0) {
        return BRISK_E_TIMEOUT;
    }
    if (f->tmo_at && f->pos >= f->tmo_at) {
        f->tmo_at = 0;
        return BRISK_E_TIMEOUT;
    }
    if (f->pos == f->len) {
        return 0; /* close_notify */
    }
    n = f->chunk ? f->chunk : 1 + f_next(f) % 97;
    n = n < cap ? n : cap;
    n = n < f->len - f->pos ? n : f->len - f->pos;
    memcpy(buf, f->srv + f->pos, n);
    f->pos += n;
    return (int)n;
}

static int f_wr(void *io, const void *buf, size_t len)
{
    fake *f = (fake *)io;
    if (f->wr_fail && ++f->writes >= f->wr_fail) {
        return BRISK_E_IO;
    }
    if (len > T_BUF - f->clen) {
        return BRISK_E_ARG;
    }
    memcpy(g_cli + f->clen, buf, len);
    f->clen += len;
    return BRISK_OK;
}

/* the response-header callback: serialise as the .inc does */
typedef struct {
    uint8_t *buf;
    size_t len;
    int bad;
} sink;

static void on_hdr(void *ctx, const char *name, size_t nl, const char *value, size_t vl)
{
    sink *s = (sink *)ctx;
    if (strlen(name) != nl || strlen(value) != vl || nl + vl + 4 > T_BUF - s->len) {
        s->bad = 1; /* not NUL-terminated where promised */
        return;
    }
    brisk__store_be16(s->buf + s->len, (uint32_t)nl);
    memcpy(s->buf + s->len + 2, name, nl);
    brisk__store_be16(s->buf + s->len + 2 + nl, (uint32_t)vl);
    memcpy(s->buf + s->len + 4 + nl, value, vl);
    s->len += nl + vl + 4;
}

/* next ','-separated field of the current token */
static char *fld(char **p)
{
    char *s = *p, *c = strchr(s, ',');
    if (c) {
        *c = 0;
        *p = c + 1;
    } else {
        *p = s + strlen(s);
    }
    return s;
}

static size_t unhex(const char *h, uint8_t *out)
{
    return t_unhex(h, out, T_BUF);
}

/* hex -> NUL-terminated string in g_str at *off */
static const char *hstr(const char *h, size_t *off)
{
    char *s = g_str + *off;
    size_t n = t_unhex(h, (uint8_t *)s, T_BUF - *off - 1);
    s[n] = 0;
    *off += n + 1;
    return s;
}

static int is_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

/* One replay. Returns the client byte count (in g_cli). */
static size_t run_row(const struct h2_kat *k, long idx, size_t chunk, uint32_t seed, size_t off,
                      int tmo)
{
    static brisk_h2_header hd[64];
    brisk_h2_stream *st[T_SLOTS] = {0};
    size_t size = brisk_h2_size(), srv_len;
    const char *p = k->script;
    brisk_h2 *h = NULL;
    fake f;
    int rc;

    memset(&f, 0, sizeof f);
    srv_len = unhex(k->srv, g_srv);
    f.srv = g_srv;
    f.len = srv_len;
    f.chunk = chunk;
    f.rng = seed;
    f.tmo = tmo;
    memset(g_arena, 0x5a, sizeof g_arena);
    rc = brisk__h2_setup(g_arena + off, size, k->auth, strlen(k->auth), f_rd, f_wr, &f, &h);
    CHECKI(rc == BRISK_OK, idx);
    if (rc != BRISK_OK) {
        return 0;
    }
    while (*p) {
        char *t = g_tok, *q, op;
        size_t n = 0;
        while (*p == ' ') {
            p++;
        }
        while (*p && *p != ' ') {
            g_tok[n++] = *p++;
        }
        g_tok[n] = 0;
        if (n == 0) {
            break;
        }
        op = t[0];
        q = t + 1;
        f.armed = tmo && op != 'Q';
        if (op == 'O') {
            int want = atoi(fld(&q));
            do {
                rc = brisk__h2_start(h);
            } while (tmo && rc == BRISK_E_TIMEOUT);
            CHECKI(rc == want, idx);
        } else if (op == 'Q') {
            int slot = atoi(fld(&q)), want = atoi(fld(&q));
            size_t so = 0, hn = 0, hl, i = 0, bl;
            const char *m = hstr(fld(&q), &so), *pa = hstr(fld(&q), &so);
            brisk_h2_stream *s = NULL;
            hl = unhex(fld(&q), g_tmp);
            while (i < hl && hn < 64) {
                size_t nl = brisk__load_be16(g_tmp + i), vl;
                char *nm = g_str + so, *vv;
                memcpy(nm, g_tmp + i + 2, nl);
                nm[nl] = 0;
                so += nl + 1;
                vl = brisk__load_be16(g_tmp + i + 2 + nl);
                vv = g_str + so;
                memcpy(vv, g_tmp + i + 4 + nl, vl);
                vv[vl] = 0;
                so += vl + 1;
                hd[hn].name = nm;
                hd[hn].value = vv;
                hn++;
                i += 4 + nl + vl;
            }
            bl = unhex(fld(&q), g_body);
            rc = brisk_h2_request(h, m, pa, hd, hn, bl ? g_body : NULL, bl, &s);
            CHECKI(rc == want, idx);
            CHECKI((rc == BRISK_OK) == (s != NULL), idx);
            if (rc == BRISK_OK) {
                st[slot] = s;
            }
        } else if (op == 'R') {
            int slot = atoi(fld(&q)), want = atoi(fld(&q)), wst = atoi(fld(&q)), status = -1;
            size_t wl = unhex(fld(&q), g_want);
            sink sk;
            sk.buf = g_tmp;
            sk.len = 0;
            sk.bad = 0;
            do {
                rc = brisk_h2_response(st[slot], &status, on_hdr, &sk);
            } while (tmo && rc == BRISK_E_TIMEOUT);
            CHECKI(rc == want, idx);
            if (rc == BRISK_OK) {
                CHECKI(status == wst, idx);
                CHECKI(!sk.bad && sk.len == wl && memcmp(g_tmp, g_want, wl) == 0, idx);
            } else {
                CHECKI(status == 0 && sk.len == 0, idx);
            }
        } else if (op == 'D' || op == 'd') {
            int slot = atoi(fld(&q)), want = atoi(fld(&q));
            size_t cap = (size_t)atoi(fld(&q)), wl = unhex(fld(&q), g_want), got = 0;
            for (;;) {
                rc = brisk_h2_read(st[slot], g_tmp + got, cap);
                if (tmo && rc == BRISK_E_TIMEOUT) {
                    continue;
                }
                if (rc > 0) {
                    CHECKI((size_t)rc <= cap, idx);
                    got += (size_t)rc;
                    if (op == 'D' && got + cap <= T_BUF) {
                        continue;
                    }
                }
                break;
            }
            if (op == 'd') {
                CHECKI(rc == want, idx);
            } else {
                CHECKI(rc == want, idx);
            }
            CHECKI(got == wl && memcmp(g_tmp, g_want, wl) == 0, idx);
        } else if (op == 'C') {
            brisk_h2_stream_close(st[atoi(fld(&q))]);
        } else if (op == 'X') {
            brisk_h2_close(h);
            CHECKI(is_zero(g_arena + off, size), idx); /* every buffer and field wiped */
            h = NULL;
        } else {
            CHECKI(0 && "bad script op", idx);
            break;
        }
    }
    return f.clen;
}

static void rows(void)
{
    static const size_t CHUNK[] = {T_BUF, 1, 7, 9, 4096, 0, 0, 0};
    size_t i, j;
    for (i = 0; i < sizeof H2_KAT / sizeof H2_KAT[0]; i++) {
        const struct h2_kat *k = &H2_KAT[i];
        size_t wl = unhex(k->cli, g_want), n;
        static uint8_t first[T_BUF];
        CHECKI(wl >= 24 && memcmp(g_want, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0, (long)i);
        for (j = 0; j <= sizeof CHUNK / sizeof CHUNK[0]; j++) {
            int tmo = j == sizeof CHUNK / sizeof CHUNK[0];
            /* the flood budget counts frames per call: a repeated (timed-out) call restarts it */
            if (tmo && strstr(k->note, "without progress") != NULL) {
                break;
            }
            n = run_row(k, (long)i, tmo ? 7 : CHUNK[j], 0x9e3779b9u * (uint32_t)(j + 1),
                        (size_t)(j % 3 == 2 ? 3 : j % 3), tmo ? 3 : 0);
            unhex(k->cli, g_want);
            if (!(n == wl && memcmp(g_cli, g_want, wl) == 0)) {
                CHECKI(0 && "client bytes differ", (long)i);
                if (j == 0) {
                    size_t d = 0;
                    while (d < n && d < wl && g_cli[d] == g_want[d]) {
                        d++;
                    }
                    fprintf(stderr,
                            "  row %lu (%s): client bytes differ at %lu (got %lu, want %lu)\n",
                            (unsigned long)i, k->note, (unsigned long)d, (unsigned long)n,
                            (unsigned long)wl);
                }
                break;
            }
            if (j == 0) {
                memcpy(first, g_cli, n);
            }
        }
    }
}

/* Setup refusals, the preface, pull framing and a failing transport. */
static void misc(void)
{
    size_t size = brisk_h2_size();
    brisk_h2 *h = (brisk_h2 *)1;
    fake f;
    uint8_t out[64];
    size_t used;

    memset(&f, 0, sizeof f);
    CHECK(brisk__h2_setup(g_arena, size - 1, "a", 1, f_rd, f_wr, &f, &h) == BRISK_E_ARG && !h);
    CHECK(brisk__h2_setup(g_arena, size, "", 0, f_rd, f_wr, &f, &h) == BRISK_E_ARG);
    CHECK(brisk__h2_setup(g_arena, size, "a\rb", 3, f_rd, f_wr, &f, &h) == BRISK_E_ARG);
    CHECK(brisk__h2_setup(NULL, size, "a", 1, f_rd, f_wr, &f, &h) == BRISK_E_ARG);
    CHECK(brisk__h2_setup(g_arena, size, "a", 1, NULL, f_wr, &f, &h) == BRISK_E_ARG);
    CHECK(brisk_h2_request(NULL, "GET", "/", NULL, 0, NULL, 0, NULL) == BRISK_E_ARG);
    CHECK(brisk_h2_response(NULL, NULL, NULL, NULL) == BRISK_E_ARG);
    CHECK(brisk_h2_read(NULL, out, 1) == BRISK_E_ARG);
    brisk_h2_stream_close(NULL);
    brisk_h2_close(NULL);
    CHECK(brisk__h2_feed(NULL, out, 0, &used) == BRISK_E_ARG);
    CHECK(brisk__h2_pull(NULL, out, sizeof out) == 0);

    /* pull: whole frames only; the queue starts with the 24-octet preface as its own unit */
    CHECK(brisk__h2_setup(g_arena + 5, size, "a", 1, f_rd, f_wr, &f, &h) == BRISK_OK);
    CHECK(brisk__h2_pull(h, out, 8) == 0);
    brisk_h2_close(h);

    /* a failed write is final: the ACK flush after the server SETTINGS fails */
    {
        static const uint8_t srv[] = {0, 0, 0, 4, 0, 0, 0, 0, 0};
        brisk_h2_stream *s = (brisk_h2_stream *)1;
        memset(&f, 0, sizeof f);
        f.srv = srv;
        f.len = sizeof srv;
        f.chunk = 64;
        f.wr_fail = 2;
        CHECK(brisk__h2_setup(g_arena + 1, size, "a", 1, f_rd, f_wr, &f, &h) == BRISK_OK);
        CHECK(brisk__h2_start(h) == BRISK_E_IO);
        CHECK(brisk_h2_request(h, "GET", "/", NULL, 0, NULL, 0, &s) == BRISK_E_IO && s == NULL);
        brisk_h2_close(h);
        CHECK(f.writes == 2); /* nothing after the failure, not even the GOAWAY */
        CHECK(is_zero(g_arena + 1, size));
    }
}

static size_t frame(uint8_t *p, uint32_t len, uint8_t type, uint8_t fl, uint32_t sid)
{
    brisk__store_be24(p, len);
    p[3] = type;
    p[4] = fl;
    brisk__store_be32(p + 5, sid);
    return 9 + len;
}

/* A stream closed while its DATA frame is half received (the read timed out mid-frame): the
 * rest of the frame is dropped, the whole frame is credited back to the connection, and the
 * connection goes on (RFC 9113 5.1 closed, 6.9). */
static void mid_frame_close(void)
{
    size_t size = brisk_h2_size(), n = 0, data_at, c0;
    brisk_h2_stream *s = NULL, *s3 = NULL;
    brisk_h2 *h;
    uint8_t buf[64], want[26];
    int st;
    fake f;

    n += frame(g_srv + n, 0, 4, 0, 0);                  /* SETTINGS */
    n += frame(g_srv + n, 1, 1, 4, 1);                  /* HEADERS :status 200 (0x88) */
    g_srv[n - 1] = 0x88;
    data_at = n;
    n += frame(g_srv + n, 5000, 0, 0, 1);               /* DATA 5000, not ended */
    memset(g_srv + data_at + 9, 0x61, 5000);
    n += frame(g_srv + n, 1, 1, 4 | 1, 3);              /* HEADERS stream 3, END_STREAM */
    g_srv[n - 1] = 0x88;
    memset(&f, 0, sizeof f);
    f.srv = g_srv;
    f.len = n;
    f.chunk = 100;
    f.tmo_at = data_at + 9 + 500; /* inside the DATA payload */
    CHECK(brisk__h2_setup(g_arena + 3, size, "a", 1, f_rd, f_wr, &f, &h) == BRISK_OK);
    CHECK(brisk__h2_start(h) == BRISK_OK);
    CHECK(brisk_h2_request(h, "GET", "/", NULL, 0, NULL, 0, &s) == BRISK_OK);
    CHECK(brisk_h2_response(s, &st, NULL, NULL) == BRISK_OK && st == 200);
    CHECK(brisk_h2_read(s, buf, sizeof buf) == BRISK_E_TIMEOUT);
    c0 = f.clen;
    brisk_h2_stream_close(s);
    frame(want, 4, 3, 0, 1);
    brisk__store_be32(want + 9, 8);    /* RST_STREAM CANCEL */
    frame(want + 13, 4, 8, 0, 0);
    brisk__store_be32(want + 22, 5000); /* WINDOW_UPDATE: all of the frame */
    CHECK(f.clen == c0 + 26 && memcmp(g_cli + c0, want, 26) == 0);
    CHECK(brisk_h2_request(h, "GET", "/", NULL, 0, NULL, 0, &s3) == BRISK_OK);
    CHECK(brisk_h2_response(s3, &st, NULL, NULL) == BRISK_OK && st == 200);
    CHECK(brisk_h2_read(s3, buf, sizeof buf) == 0);
    CHECK(h->crwin == 65535 && h->cpend == 0);
    brisk_h2_close(h);
}

/* Streams whose last DATA frame is padded, each closed after read() == 0: the padding must be
 * credited to the connection exactly once (RFC 9113 6.9.1), so the connection receive window
 * plus what is still owed never exceeds its initial 65535. */
static void padded_end_close(void)
{
    size_t n = 0;
    brisk_h2_stream *s = NULL;
    brisk_h2 *h;
    uint8_t buf[64];
    uint32_t i, sid;
    int st;
    fake f;

    n += frame(g_srv + n, 0, 4, 0, 0); /* SETTINGS */
    for (i = 0, sid = 1; i < 20; i++, sid += 2) {
        n += frame(g_srv + n, 1, 1, 4, sid); /* HEADERS :status 200 */
        g_srv[n - 1] = 0x88;
        frame(g_srv + n, 256, 0, 8 | 1, sid); /* DATA PADDED|END_STREAM, pad 255, no data */
        memset(g_srv + n + 9, 0, 256);
        g_srv[n + 9] = 0xff;
        n += 9 + 256;
    }
    memset(&f, 0, sizeof f);
    f.srv = g_srv;
    f.len = n;
    f.chunk = 4096;
    f.tmo_at = 0; /* never */
    CHECK(brisk__h2_setup(g_arena, brisk_h2_size(), "a", 1, f_rd, f_wr, &f, &h) == BRISK_OK);
    CHECK(brisk__h2_start(h) == BRISK_OK);
    for (i = 0; i < 20; i++) {
        CHECKI(brisk_h2_request(h, "GET", "/", NULL, 0, NULL, 0, &s) == BRISK_OK, i);
        CHECKI(brisk_h2_response(s, &st, NULL, NULL) == BRISK_OK && st == 200, i);
        CHECKI(brisk_h2_read(s, buf, sizeof buf) == 0, i);
        brisk_h2_stream_close(s);
        CHECKI((int64_t)h->crwin + (int64_t)h->cpend <= 65535, i);
    }
    brisk_h2_close(h);
}

void test_h2(void)
{
    printf("h2       brisk_h2_size() = %lu (streams %d, window %d)\n",
           (unsigned long)brisk_h2_size(), BRISK_H2_MAX_STREAMS, BRISK_H2_STREAM_WINDOW);
    CHECK(brisk_h2_size() + 8 <= sizeof g_arena);
    misc();
#    if BRISK_H2_STREAM_WINDOW == H2_KAT_W && BRISK_H2_MAX_STREAMS == H2_KAT_MAX &&                \
        BRISK_H2_HEADER_TABLE_SIZE == 4096
    mid_frame_close(); /* its expected bytes assume the default window and stream count */
    padded_end_close();
    rows();
#    else
    printf("h2       rows skipped: they assume window %d, %d streams, table 4096\n", H2_KAT_W,
           H2_KAT_MAX);
    (void)rows; /* built but not run with non-default knobs */
    (void)mid_frame_close;
#    endif
}

#else /* !BRISK_ENABLE_H2 */

void test_h2(void)
{
    CHECK(1); /* HTTP/2 is compiled out in this profile */
}

#endif /* BRISK_ENABLE_H2 */
