/* test_h3.c - HTTP/3 (RFC 9114; src/http/h3.c) and brisk_h3_*.
 *
 * Every row of tests/kat/h3.inc (tools/kat.py) is a scenario: the server's stream events, a
 * script of public calls with the result each must return, and the exact client log. A scripted
 * brisk__h3_io stands in for QUIC: each wait() delivers ONE chunk of the next event (stream data,
 * FIN, RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE); when none is left the connection "idles
 * out" (BRISK_E_IO). Reads, writes, aborts and the close are logged as
 *   W<id>,<hex>  (consecutive writes to one stream joined)   F<id>  (FIN)
 *   A<id>,<code hex>,<dirs>  (RESET_STREAM / STOP_SENDING)    X<code hex>  (CONNECTION_CLOSE)
 *
 * Each row is replayed with the events cut into whole, 1-, 2-, 3-, 7-byte and seeded random
 * chunks, with the arena at offsets 0 / 1 / 3, and once more with a BRISK_E_TIMEOUT injected on
 * every third wait (the timed-out call is repeated): results and the log must be identical
 * every time. After brisk_h3_close the arena must be all zero.
 *
 * Script ops (space-separated; fields by ','; hex for bytes):
 *   O<rc>                                        brisk__h3_start (what brisk_h3_open runs)
 *   Q<slot>,<rc>,<method>,<path>,<hdrs>,<body>   brisk_h3_request; hdrs = [u16 n][name][u16 v][v]..
 *   R<slot>,<rc>,<status>,<hdrs>                 brisk_h3_response; the callback's fields
 *   D<slot>,<rc>,<cap>,<data>                    brisk_h3_read(cap) until <= 0: all data, result
 *   d<slot>,<rc>,<cap>,<data>                    one brisk_h3_read
 *   C<slot>                                      brisk_h3_stream_close
 *   X                                            brisk_h3_close, then the arena must be zero
 *   P                                            deliver every pending event between calls (what
 *                                                a blocking QUIC wait in an earlier call leaves
 *                                                in the rings, unparsed)
 *
 * The whole file sits inside #if BRISK_ENABLE_H3; other profiles run an empty suite. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_H3

struct h3_kat {
    const char *events, *script, *cli;
    unsigned flags; /* 1: no TIMEOUT replay (a flood budget counts per call) */
    const char *note;
};
struct h3_fuzz_seed {
    const char *hex, *note;
};
#    include "kat/h3.inc"

#    define T_BUF   (1u << 17)
#    define T_ARENA (1u << 17)
#    define T_NS    24     /* streams the fake tracks */
#    define T_SBUF  32768u /* bytes per fake stream */
#    define T_EV    2048   /* events per row */
#    define T_LOG   (1u << 18)

typedef struct {
    uint64_t id;
    size_t len, rd;
    uint64_t reset, stop;
    uint8_t used, fin, has_reset, reset_told, has_stop, aborted, accepted, ours;
    uint8_t buf[T_SBUF];
} fst;

typedef struct {
    char type;
    uint64_t id, code;
    size_t off, len; /* S: bytes in g_evb */
} fev;

typedef struct {
    fev ev[T_EV];
    size_t nev, cur, pos; /* next event, octets of it already delivered */
    size_t chunk;         /* 0 = seeded random */
    uint32_t rng;
    int tmo, waits;
    int killed, closed, idle;
    uint64_t next_bidi, next_uni;
    uint64_t accept_q[T_NS];
    size_t n_acc, acc_rd;
    char *log;
    size_t log_len;
    int log_w_id; /* id of the last W record, -1 = the last record is not a W */
    fst st[T_NS]; /* last: only the headers are reset per run */
} fake;

static uint8_t g_evb[T_BUF], g_tmp[T_BUF], g_want[T_BUF], g_body[T_BUF];
static uint8_t g_arena[T_ARENA + 8];
static char g_tok[2 * T_BUF + 64], g_str[T_BUF], g_log[T_LOG];
static fake g_f;

static uint32_t f_next(fake *f)
{
    f->rng ^= f->rng << 13;
    f->rng ^= f->rng >> 17;
    f->rng ^= f->rng << 5;
    return f->rng;
}

static fst *f_find(fake *f, uint64_t id, int create)
{
    unsigned i;
    for (i = 0; i < T_NS; i++) {
        if (f->st[i].used && f->st[i].id == id) {
            return &f->st[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (i = 0; i < T_NS; i++) {
        if (!f->st[i].used) {
            memset(&f->st[i], 0, sizeof f->st[i] - T_SBUF);
            f->st[i].used = 1;
            f->st[i].id = id;
            return &f->st[i];
        }
    }
    return NULL;
}

static void log_s(fake *f, const char *s)
{
    size_t n = strlen(s);
    if (f->log_len + n + 2 < T_LOG) {
        if (f->log_len) {
            f->log[f->log_len++] = ' ';
        }
        memcpy(f->log + f->log_len, s, n + 1);
        f->log_len += n;
    }
}

static void log_hex(fake *f, const uint8_t *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n && f->log_len + 3 < T_LOG; i++) {
        f->log[f->log_len++] = hx[p[i] >> 4];
        f->log[f->log_len++] = hx[p[i] & 15];
    }
    f->log[f->log_len] = 0;
}

static int f_read(void *io, uint64_t id, uint8_t *buf, size_t cap, uint64_t *app_err)
{
    fake *f = (fake *)io;
    fst *s = f_find(f, id, 0);
    size_t n;
    if (s == NULL || s->aborted || cap == 0) {
        return BRISK_E_ARG;
    }
    if (s->has_reset) {
        if (s->reset_told) {
            return BRISK_E_ARG; /* QUIC frees the slot once the reset is reported */
        }
        s->reset_told = 1;
        *app_err = s->reset;
        return BRISK_E_PEER_ALERT;
    }
    n = s->len - s->rd;
    if (n != 0) {
        n = n < cap ? n : cap;
        memcpy(buf, s->buf + s->rd, n);
        s->rd += n;
        return (int)n;
    }
    return s->fin ? 0 : BRISK_E_WANT;
}

static int f_write(void *io, uint64_t id, const uint8_t *buf, size_t n, int fin)
{
    fake *f = (fake *)io;
    fst *s = f_find(f, id, 0);
    char b[32];
    if (s == NULL || !s->ours || s->aborted) {
        return BRISK_E_ARG;
    }
    if (s->has_stop) {
        return BRISK_E_PEER_ALERT;
    }
    if (n != 0) {
        if (f->log_w_id != (int)id) {
            sprintf(b, "W%lu,", (unsigned long)id);
            log_s(f, b);
        }
        log_hex(f, buf, n);
        f->log_w_id = (int)id;
    }
    if (fin) {
        sprintf(b, "F%lu", (unsigned long)id);
        log_s(f, b);
        f->log_w_id = -1;
    }
    return (int)n;
}

static int64_t f_open(void *io, int bidi)
{
    fake *f = (fake *)io;
    uint64_t id = bidi ? f->next_bidi : f->next_uni;
    fst *s = f_find(f, id, 1);
    if (s == NULL) {
        return BRISK_E_WANT;
    }
    s->ours = 1;
    if (bidi) {
        f->next_bidi += 4;
    } else {
        f->next_uni += 4;
    }
    return (int64_t)id;
}

static int f_accept(void *io, uint64_t *id)
{
    fake *f = (fake *)io;
    if (f->acc_rd < f->n_acc) {
        *id = f->accept_q[f->acc_rd++];
        return BRISK_OK;
    }
    return BRISK_E_WANT;
}

static void f_start(void *io)
{
    (void)io;
}

static int f_status(void *io)
{
    fake *f = (fake *)io;
    return f->killed ? BRISK_E_PEER_ALERT : f->closed ? BRISK_E_PROTO : f->idle ? BRISK_E_IO : 0;
}

static int f_wait(void *io)
{
    fake *f = (fake *)io;
    fev *e;
    fst *s;
    int st = f_status(io);
    if (st != 0) {
        return st;
    }
    if (f->tmo && ++f->waits % f->tmo == 0) {
        return BRISK_E_TIMEOUT;
    }
    if (f->cur == f->nev) {
        f->idle = 1; /* RFC 9000 10.1: nothing more will come */
        return BRISK_E_IO;
    }
    e = &f->ev[f->cur];
    if (e->type == 'K') {
        f->killed = 1;
        f->cur++;
        return BRISK_E_PEER_ALERT;
    }
    s = f_find(f, e->id, 1);
    if (s == NULL) {
        return BRISK_E_ARG;
    }
    if ((e->id & 3) == 3 && !s->accepted) {
        s->accepted = 1;
        f->accept_q[f->n_acc++] = e->id;
    }
    if (e->type == 'S') {
        size_t k = f->chunk ? f->chunk : 1 + f_next(f) % 97;
        k = k < e->len - f->pos ? k : e->len - f->pos;
        if (s->len + k <= T_SBUF) {
            memcpy(s->buf + s->len, g_evb + e->off + f->pos, k);
            s->len += k;
        }
        f->pos += k;
        if (f->pos < e->len) {
            return BRISK_OK;
        }
    } else if (e->type == 'F') {
        s->fin = 1;
    } else if (e->type == 'R') {
        s->has_reset = 1;
        s->reset = e->code;
    } else if (e->type == 'T') {
        s->has_stop = 1;
        s->stop = e->code;
    }
    f->cur++;
    f->pos = 0;
    return BRISK_OK;
}

static int f_abort(void *io, uint64_t id, uint64_t code, unsigned dirs)
{
    fake *f = (fake *)io;
    fst *s = f_find(f, id, 0);
    char b[64];
    sprintf(b, "A%lu,%lx,%u", (unsigned long)id, (unsigned long)code, dirs);
    log_s(f, b);
    f->log_w_id = -1;
    if (s != NULL) {
        s->aborted = 1;
    }
    return BRISK_OK;
}

static void f_close(void *io, uint64_t code)
{
    fake *f = (fake *)io;
    char b[32];
    sprintf(b, "X%lx", (unsigned long)code);
    log_s(f, b);
    f->log_w_id = -1;
    f->closed = 1;
}

static const brisk__h3_io f_ops = {f_read, f_write, f_open,  f_accept, f_start,
                                   f_wait, f_abort, f_close, f_status};

/* Events "S<id>,<hex> F<id> R<id>,<code> T<id>,<code> K<code>" into f->ev / g_evb */
static int parse_events(fake *f, const char *ev)
{
    size_t off = 0;
    f->nev = 0;
    while (*ev) {
        fev *e;
        char *end;
        while (*ev == ' ') {
            ev++;
        }
        if (!*ev) {
            break;
        }
        if (f->nev == T_EV) {
            return 0;
        }
        e = &f->ev[f->nev++];
        memset(e, 0, sizeof *e);
        e->type = *ev++;
        if (e->type == 'K') {
            e->code = strtoul(ev, &end, 16);
            ev = end;
            continue;
        }
        e->id = strtoul(ev, &end, 10);
        ev = end;
        if (e->type == 'S') {
            size_t n = 0;
            ev++; /* ',' */
            while (ev[n] && ev[n] != ' ') {
                n++;
            }
            memcpy(g_tok, ev, n);
            g_tok[n] = 0;
            e->off = off;
            e->len = t_unhex(g_tok, g_evb + off, T_BUF - off);
            off += e->len;
            ev += n;
        } else if (e->type == 'R' || e->type == 'T') {
            e->code = strtoul(ev + 1, &end, 16);
            ev = end;
        }
    }
    return 1;
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
        s->bad = 1;
        return;
    }
    brisk__store_be16(s->buf + s->len, (uint32_t)nl);
    memcpy(s->buf + s->len + 2, name, nl);
    brisk__store_be16(s->buf + s->len + 2 + nl, (uint32_t)vl);
    memcpy(s->buf + s->len + 4 + nl, value, vl);
    s->len += nl + vl + 4;
}

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

/* One replay; the client log ends up in g_log. */
static void run_row(const struct h3_kat *k, long idx, size_t chunk, uint32_t seed, size_t off,
                    int tmo)
{
    static brisk_h2_header hd[64];
    brisk_h3_stream *st[8] = {0};
    size_t size = brisk_h3_size();
    const char *p = k->script;
    brisk_h3 *h = NULL;
    fake *f = &g_f;
    size_t n;
    int rc;

    memset(f, 0, offsetof(fake, st));
    for (n = 0; n < T_NS; n++) {
        f->st[n].used = 0;
    }
    f->chunk = chunk;
    f->rng = seed;
    f->tmo = tmo;
    f->next_uni = 2;
    f->log = g_log;
    f->log_w_id = -1;
    g_log[0] = 0;
    CHECKI(parse_events(f, k->events), idx);
    memset(g_arena, 0x5a, sizeof g_arena);
    rc = brisk__h3_setup(g_arena + off, size, "example.com", 11, &f_ops, f, &h);
    CHECKI(rc == BRISK_OK, idx);
    if (rc != BRISK_OK) {
        return;
    }
    while (*p) {
        char *t = g_tok, *q, op;
        n = 0;
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
        if (op == 'P') {
            int w = BRISK_OK;
            while (f->cur < f->nev && (w == BRISK_OK || w == BRISK_E_TIMEOUT)) {
                w = f_wait(f);
            }
        } else if (op == 'O') {
            int want = atoi(fld(&q));
            CHECKI(brisk__h3_start(h) == want, idx);
        } else if (op == 'Q') {
            int slot = atoi(fld(&q)), want = atoi(fld(&q));
            size_t so = 0, hn = 0, hl, i = 0, bl;
            const char *m = hstr(fld(&q), &so), *pa = hstr(fld(&q), &so);
            brisk_h3_stream *s = NULL;
            hl = t_unhex(fld(&q), g_tmp, T_BUF);
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
            bl = t_unhex(fld(&q), g_body, T_BUF);
            rc = brisk_h3_request(h, m, pa, hd, hn, bl ? g_body : NULL, bl, &s);
            CHECKI(rc == want, idx);
            CHECKI((rc == BRISK_OK) == (s != NULL), idx);
            if (rc == BRISK_OK) {
                st[slot] = s;
            }
        } else if (op == 'R') {
            int slot = atoi(fld(&q)), want = atoi(fld(&q)), wst = atoi(fld(&q)), status = -1;
            size_t wl = t_unhex(fld(&q), g_want, T_BUF);
            sink sk;
            sk.buf = g_tmp;
            sk.len = 0;
            sk.bad = 0;
            do {
                rc = brisk_h3_response(st[slot], &status, on_hdr, &sk);
            } while (tmo && rc == BRISK_E_TIMEOUT);
            CHECKI(rc == want, idx);
            if (rc != want) {
                fprintf(stderr, "  h3 row %ld (%s): R got %d want %d\n", idx, k->note, rc, want);
            }
            if (rc == BRISK_OK) {
                CHECKI(status == wst, idx);
                CHECKI(!sk.bad && sk.len == wl && memcmp(g_tmp, g_want, wl) == 0, idx);
            } else {
                CHECKI(status == 0 && sk.len == 0, idx);
            }
        } else if (op == 'D' || op == 'd') {
            int slot = atoi(fld(&q)), want = atoi(fld(&q));
            size_t cap = (size_t)atoi(fld(&q)), wl = t_unhex(fld(&q), g_want, T_BUF), got = 0;
            for (;;) {
                rc = brisk_h3_read(st[slot], g_tmp + got, cap);
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
            CHECKI(rc == want, idx);
            if (rc != want) {
                fprintf(stderr, "  h3 row %ld (%s): %c got %d want %d\n", idx, k->note, op, rc,
                        want);
            }
            CHECKI(got == wl && memcmp(g_tmp, g_want, wl) == 0, idx);
        } else if (op == 'C') {
            brisk_h3_stream_close(st[atoi(fld(&q))]);
        } else if (op == 'X') {
            brisk_h3_close(h);
            CHECKI(is_zero(g_arena + off, size), idx); /* every buffer and field wiped */
            h = NULL;
        } else {
            CHECKI(0 && "bad script op", idx);
            break;
        }
    }
}

static void rows(void)
{
    static const size_t CHUNK[] = {T_BUF, 1, 2, 3, 7, 0, 0};
    size_t i, j;
    for (i = 0; i < sizeof H3_KAT / sizeof H3_KAT[0]; i++) {
        const struct h3_kat *k = &H3_KAT[i];
        for (j = 0; j <= sizeof CHUNK / sizeof CHUNK[0]; j++) {
            int tmo = j == sizeof CHUNK / sizeof CHUNK[0];
            if (tmo && (k->flags & 1)) {
                break;
            }
            run_row(k, (long)i, tmo ? 5 : CHUNK[j], 0x9e3779b9u * (uint32_t)(j + 1),
                    (size_t)(j % 3 == 2 ? 3 : j % 3), tmo ? 3 : 0);
            if (strcmp(g_log, k->cli) != 0) {
                CHECKI(0 && "client log differs", (long)i);
                fprintf(stderr,
                        "  h3 row %lu (%s), chunking %lu:\n    got  %.300s\n    want %.300s\n",
                        (unsigned long)i, k->note, (unsigned long)j, g_log, k->cli);
                break;
            }
        }
    }
}

/* Setup refusals, the control preface bytes, NULL handling. */
static void misc(void)
{
    size_t size = brisk_h3_size();
    brisk_h3 *h = (brisk_h3 *)1;
    brisk_h3_stream *s = (brisk_h3_stream *)1;
    uint8_t pre[64], want[64];
    size_t n, wn;
    int st;

    CHECK(brisk__h3_setup(g_arena, size - 1, "a", 1, &f_ops, &g_f, &h) == BRISK_E_ARG && !h);
    CHECK(brisk__h3_setup(g_arena, size, "", 0, &f_ops, &g_f, &h) == BRISK_E_ARG);
    CHECK(brisk__h3_setup(g_arena, size, "a\rb", 3, &f_ops, &g_f, &h) == BRISK_E_ARG);
    CHECK(brisk__h3_setup(NULL, size, "a", 1, &f_ops, &g_f, &h) == BRISK_E_ARG);
    CHECK(brisk__h3_setup(g_arena, size, "a", 1, NULL, &g_f, &h) == BRISK_E_ARG);
    CHECK(brisk_h3_request(NULL, "GET", "/", NULL, 0, NULL, 0, &s) == BRISK_E_ARG && s == NULL);
    CHECK(brisk_h3_response(NULL, &st, NULL, NULL) == BRISK_E_ARG);
    CHECK(brisk_h3_read(NULL, pre, 1) == BRISK_E_ARG);
    CHECK(brisk__h3_start(NULL) == BRISK_E_ARG);
    CHECK(brisk_h3_open(NULL, g_arena, size, &h) == BRISK_E_ARG && h == NULL);
    brisk_h3_stream_close(NULL);
    brisk_h3_close(NULL);
    /* RFC 9114 6.2.1 / 7.2.4: our control preface, byte for byte (kat.py h3_preface) */
    n = brisk__h3_settings(pre, sizeof pre);
    wn = t_unhex(H3_KAT_PREFACE, want, sizeof want);
    CHECK(n == wn && memcmp(pre, want, n) == 0);
    CHECK(brisk__h3_settings(pre, n - 1) == 0);
}

void test_h3(void)
{
    printf("h3       brisk_h3_size() = %lu (request slots %d, header list %d)\n",
           (unsigned long)brisk_h3_size(), BRISK_QUIC_MAX_STREAMS - 4, BRISK_H3_MAX_HEADER_LIST);
    CHECK(brisk_h3_size() + 8 <= sizeof g_arena);
#    if BRISK_H3_MAX_HEADER_LIST == H3_KAT_L && BRISK_QUIC_MAX_STREAMS - 4 == H3_KAT_NS
    misc();
    rows();
#    else
    printf("h3       rows skipped: they assume header list %d and %d request slots\n", H3_KAT_L,
           H3_KAT_NS);
    (void)rows;
    (void)misc;
#    endif
}

#else /* !BRISK_ENABLE_H3 */

void test_h3(void)
{
    CHECK(1); /* HTTP/3 is compiled out in this profile */
}

#endif /* BRISK_ENABLE_H3 */
