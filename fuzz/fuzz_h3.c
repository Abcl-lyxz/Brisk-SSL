/* fuzz_h3.c - libFuzzer / AFL++ entry point for HTTP/3 (RFC 9114; src/http/h3.c + qpack.c):
 * server stream events through the brisk__h3_io seam while the public calls run.
 *
 *   python tools/dev.py fuzz h3    # clang + ASan/UBSan, seeded from h3_fuzz.inc
 *
 * Input: byte 0 = the chunk size each wait() delivers (low 3 bits + 1), then events. An event is
 * one octet: bits 0-1 the kind (0 data: a length octet and that many bytes follow; 1 FIN;
 * 2 RESET_STREAM: a 2-octet code follows; 3 the peer closes the connection), bits 2-4 the
 * stream: 3, 7, 11, 15 (server uni), 0, 4, 8 (our requests), 19. The script is fixed: start, two
 * requests (GET, POST with a body), then response / read / close on each.
 * Oracles: no crash, no sanitizer report; every call returns BRISK_OK, a byte count or one of
 * the documented errors; read never returns more than asked; after brisk_h3_close the arena is
 * zero.
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

/* The QUIC side h3.c links against in production (its brisk_quic wrappers, never called here):
 * stubs, so this target builds from src/http/ alone. The two varint helpers are real (RFC 9000
 * 16) - h3.c parses every frame header with them. */
int brisk__quic_varint_get(const uint8_t **p, const uint8_t *end, uint64_t *v)
{
    const uint8_t *q = *p;
    size_t n, i;
    uint64_t x;
    if (q == NULL || q >= end) {
        return 0;
    }
    n = (size_t)1 << (q[0] >> 6);
    if ((size_t)(end - q) < n) {
        return 0;
    }
    x = q[0] & 0x3f;
    for (i = 1; i < n; i++) {
        x = (x << 8) | q[i];
    }
    *v = x;
    *p = q + n;
    return 1;
}

size_t brisk__quic_varint_put(uint8_t *p, size_t cap, uint64_t v)
{
    size_t n = v < 64 ? 1 : v < 16384 ? 2 : v < 1073741824 ? 4 : 8, i;
    if (p == NULL) {
        return n;
    }
    if (cap < n) {
        return 0;
    }
    for (i = n; i-- > 0;) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
    p[0] |= (uint8_t)((n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3) << 6);
    return n;
}

int brisk__quic_stream_read(brisk__quic_conn *q, uint64_t id, uint8_t *out, size_t cap,
                            uint64_t *app_err)
{
    (void)q, (void)id, (void)out, (void)cap, (void)app_err;
    abort();
}
int brisk__quic_stream_write(brisk__quic_conn *q, uint64_t id, const uint8_t *d, size_t n, int fin)
{
    (void)q, (void)id, (void)d, (void)n, (void)fin;
    abort();
}
int64_t brisk__quic_stream_open(brisk__quic_conn *q, int bidi)
{
    (void)q, (void)bidi;
    abort();
}
int brisk__quic_stream_accept(brisk__quic_conn *q, uint64_t *id)
{
    (void)q, (void)id;
    abort();
}
int brisk__quic_stream_abort(brisk__quic_conn *q, uint64_t id, uint64_t app_err, unsigned dirs)
{
    (void)q, (void)id, (void)app_err, (void)dirs;
    abort();
}
int brisk__quic_close(brisk__quic_conn *q, uint64_t app_err)
{
    (void)q, (void)app_err;
    abort();
}
int brisk__quic_wait(brisk_quic *q)
{
    (void)q;
    abort();
}
int brisk_quic_alpn(const brisk_quic *q, const char **name, size_t *len)
{
    (void)q, (void)name, (void)len;
    abort();
}

#define FZ_NS  8
#define FZ_BUF 65536

typedef struct {
    uint64_t id;
    uint8_t buf[FZ_BUF];
    size_t len, rd;
    uint64_t reset;
    uint8_t fin, has_reset, told, accepted, aborted;
} fz_st;

typedef struct {
    const uint8_t *in;
    size_t len, pos, chunk, part; /* part: octets of the current data event delivered */
    fz_st st[FZ_NS];
    uint64_t acc[FZ_NS];
    size_t nacc, accrd, waits;
    int killed, closed, idle;
    uint64_t next_bidi;
} fz_io;

static const uint64_t fz_ids[FZ_NS] = {3, 7, 11, 15, 0, 4, 8, 19};

static fz_st *fz_find(fz_io *f, uint64_t id)
{
    unsigned i;
    for (i = 0; i < FZ_NS; i++) {
        if (fz_ids[i] == id) {
            return &f->st[i];
        }
    }
    return NULL;
}

static int fz_read(void *io, uint64_t id, uint8_t *buf, size_t cap, uint64_t *e)
{
    fz_st *s = fz_find((fz_io *)io, id);
    size_t n;
    if (s == NULL || s->aborted || cap == 0) {
        return BRISK_E_ARG;
    }
    if (s->has_reset) {
        if (s->told) {
            return BRISK_E_ARG;
        }
        s->told = 1;
        *e = s->reset;
        return BRISK_E_PEER_ALERT;
    }
    n = s->len - s->rd;
    if (n == 0) {
        return s->fin ? 0 : BRISK_E_WANT;
    }
    n = n < cap ? n : cap;
    memcpy(buf, s->buf + s->rd, n);
    s->rd += n;
    return (int)n;
}

static int fz_write(void *io, uint64_t id, const uint8_t *buf, size_t n, int fin)
{
    (void)io;
    (void)id;
    (void)buf;
    (void)fin;
    return n > 100000 ? 100000 : (int)n;
}

static int64_t fz_open(void *io, int bidi)
{
    fz_io *f = (fz_io *)io;
    uint64_t id;
    if (!bidi) {
        return 2;
    }
    if (f->next_bidi > 8) {
        return BRISK_E_WANT;
    }
    id = f->next_bidi;
    f->next_bidi += 4;
    return (int64_t)id;
}

static int fz_accept(void *io, uint64_t *id)
{
    fz_io *f = (fz_io *)io;
    if (f->accrd < f->nacc) {
        *id = f->acc[f->accrd++];
        return BRISK_OK;
    }
    return BRISK_E_WANT;
}

static void fz_start(void *io)
{
    (void)io;
}

static int fz_status(void *io)
{
    fz_io *f = (fz_io *)io;
    return f->killed ? BRISK_E_PEER_ALERT : f->closed ? BRISK_E_PROTO : f->idle ? BRISK_E_IO : 0;
}

static int fz_wait(void *io)
{
    fz_io *f = (fz_io *)io;
    fz_st *s;
    uint8_t ev;
    int st = fz_status(io);
    if (st != 0) {
        return st;
    }
    if (++f->waits % 7 == 0) {
        return BRISK_E_TIMEOUT;
    }
    if (f->pos >= f->len) {
        f->idle = 1;
        return BRISK_E_IO;
    }
    ev = f->in[f->pos];
    s = &f->st[(ev >> 2) & 7];
    if ((s->id & 3) == 3 && !s->accepted && f->nacc < FZ_NS) {
        s->accepted = 1;
        f->acc[f->nacc++] = s->id;
    }
    switch (ev & 3) {
    case 0: {
        size_t n = f->pos + 1 < f->len ? f->in[f->pos + 1] : 0, k;
        const uint8_t *d = f->in + f->pos + 2;
        if (f->pos + 2 + n > f->len) {
            n = f->pos + 2 <= f->len ? f->len - f->pos - 2 : 0;
        }
        k = n - f->part < f->chunk ? n - f->part : f->chunk;
        if (s->len + k <= FZ_BUF) {
            memcpy(s->buf + s->len, d + f->part, k);
            s->len += k;
        }
        f->part += k;
        if (f->part < n) {
            return BRISK_OK;
        }
        f->pos += 2 + n;
        f->part = 0;
        return BRISK_OK;
    }
    case 1:
        s->fin = 1;
        f->pos++;
        return BRISK_OK;
    case 2:
        s->has_reset = 1;
        s->reset = f->pos + 2 < f->len ? (uint64_t)f->in[f->pos + 1] << 8 | f->in[f->pos + 2] : 0;
        f->pos += 3;
        return BRISK_OK;
    default:
        f->killed = 1;
        f->pos++;
        return BRISK_E_PEER_ALERT;
    }
}

static int fz_abort(void *io, uint64_t id, uint64_t code, unsigned dirs)
{
    fz_st *s = fz_find((fz_io *)io, id);
    (void)code;
    (void)dirs;
    if (s != NULL) {
        s->aborted = 1;
    }
    return BRISK_OK;
}

static void fz_close(void *io, uint64_t code)
{
    (void)code;
    ((fz_io *)io)->closed = 1;
}

static const brisk__h3_io fz_ops = {fz_read, fz_write, fz_open,  fz_accept, fz_start,
                                    fz_wait, fz_abort, fz_close, fz_status};

static int fz_ok(int rc)
{
    return rc == BRISK_OK || rc == BRISK_E_ARG || rc == BRISK_E_PROTO || rc == BRISK_E_PEER_ALERT ||
           rc == BRISK_E_IO || rc == BRISK_E_TIMEOUT || rc == BRISK_E_RETRY;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t arena[1u << 17];
    static fz_io f;
    static const brisk_h2_header hd[] = {{"content-type", "application/json"},
                                         {"authorization", "Bearer x"}};
    brisk_h3_stream *s[2] = {NULL, NULL};
    brisk_h3 *h = NULL;
    uint8_t buf[97];
    unsigned i, tries;
    int rc, status;
    size_t j;

    if (size < 1 || brisk_h3_size() > sizeof arena) {
        return 0;
    }
    memset(&f, 0, sizeof f);
    for (i = 0; i < FZ_NS; i++) {
        f.st[i].id = fz_ids[i];
    }
    f.in = data + 1;
    f.len = size - 1;
    f.chunk = (size_t)(data[0] & 7) + 1;
    if (brisk__h3_setup(arena + 1, brisk_h3_size(), "example.com", 11, &fz_ops, &f, &h) !=
        BRISK_OK) {
        abort();
    }
    rc = brisk__h3_start(h);
    if (!fz_ok(rc)) {
        abort();
    }
    rc = brisk_h3_request(h, "GET", "/", NULL, 0, NULL, 0, &s[0]);
    if (!fz_ok(rc) || (rc == BRISK_OK) != (s[0] != NULL)) {
        abort();
    }
    rc = brisk_h3_request(h, "POST", "/up", hd, 2, "{}", 2, &s[1]);
    if (!fz_ok(rc) || (rc == BRISK_OK) != (s[1] != NULL)) {
        abort();
    }
    for (i = 0; i < 2; i++) {
        if (s[i] == NULL) {
            continue;
        }
        for (tries = 0; tries < 8; tries++) {
            rc = brisk_h3_response(s[i], &status, NULL, NULL);
            if (!fz_ok(rc) || (rc == BRISK_OK && (status < 200 || status > 599))) {
                abort();
            }
            if (rc != BRISK_E_TIMEOUT) {
                break;
            }
        }
        for (j = 0; rc == BRISK_OK && j < 100000; j++) {
            rc = brisk_h3_read(s[i], buf, 1 + (j % sizeof buf));
            if (rc > (int)(1 + (j % sizeof buf)) || (rc < 0 && !fz_ok(rc))) {
                abort();
            }
            rc = rc > 0 || rc == BRISK_E_TIMEOUT ? BRISK_OK : rc == 0 ? 1 : rc;
        }
        brisk_h3_stream_close(s[i]);
    }
    brisk_h3_close(h);
    for (j = 0; j < brisk_h3_size(); j++) {
        if (arena[1 + j] != 0) {
            abort();
        }
    }
    return 0;
}
