/* fuzz_h2.c - libFuzzer / AFL++ entry point for the HTTP/2 frame parser and stream machinery
 * (RFC 9113, src/http/h2.c).
 *
 *   python tools/dev.py fuzz h2       # clang + ASan/UBSan, seeded from h2_fuzz.inc
 *
 * Input: byte 0 picks the feed split (bits 0-1: 1, 7, 64 or everything at once) and whether a
 * POST with a body is open besides the GET (bit 2); the rest is the server byte stream, fed
 * through brisk__h2_feed after a setup and the scripted requests. Oracle: every result is
 * BRISK_OK or BRISK_E_PROTO (BRISK_E_ARG would be an internal fault); after an error every feed
 * returns it; a feed that consumes nothing leaves whole frames for brisk__h2_pull (never a
 * stall); every pulled chunk is a sequence of whole, well-formed frames; windows stay within
 * [-(2^31-1), 2^31-1] and no ring holds more than it owns. Then the blocking calls run over the
 * same handle (the fake transport reports end of stream) and it is closed: the arena must be
 * all zero.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t fz_arena[1 << 18];

static void fz_frames(const uint8_t *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (n - i < 9 || n - i - 9 < brisk__load_be24(p + i)) {
            abort(); /* not whole frames */
        }
        if (brisk__load_be24(p + i) > 16384 || (p[i + 5] & 0x80)) {
            abort(); /* above the peer's initial SETTINGS_MAX_FRAME_SIZE, or R bit set */
        }
        i += 9 + brisk__load_be24(p + i);
    }
}

static int fz_rd(void *io, void *buf, size_t cap)
{
    (void)io;
    (void)buf;
    (void)cap;
    return 0; /* close_notify: everything was fed already */
}

static int fz_wr(void *io, const void *buf, size_t len)
{
    size_t *first = (size_t *)io;
    const uint8_t *p = (const uint8_t *)buf;
    if (*first) { /* the preface is not a frame */
        if (len < 24 || memcmp(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) {
            abort();
        }
        p += 24;
        len -= 24;
        *first = 0;
    }
    fz_frames(p, len);
    return BRISK_OK;
}

static void fz_invariants(const brisk_h2 *h)
{
    unsigned i;
    if (h->crwin < 0 || h->cwin < -0x7fffffff || h->tx_len > BRISK__H2_TX) {
        abort();
    }
    for (i = 0; i < BRISK_H2_MAX_STREAMS; i++) {
        const struct brisk_h2_stream *s = &h->s[i];
        if (s->id == 0) {
            continue;
        }
        if (s->rlen > (uint32_t)BRISK_H2_STREAM_WINDOW + BRISK__H2_MAX_LIST || s->hdr > s->rlen ||
            s->ready > s->rlen - s->hdr || s->rwin < 0 || s->rwin > BRISK_H2_STREAM_WINDOW ||
            s->swin < -0x7fffffff) {
            abort();
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const size_t SPLIT[4] = {1, 7, 64, (size_t)-1};
    static uint8_t out[BRISK__H2_TX], buf[512];
    brisk_h2_stream *s1 = NULL, *s2 = NULL;
    size_t first = 1, p = 1, split, n;
    brisk_h2 *h;
    int rc = BRISK_OK, status;

    if (size == 0) {
        return 0;
    }
    split = SPLIT[data[0] & 3];
    if (brisk__h2_setup(fz_arena + (data[0] >> 4), brisk_h2_size(), "example.com", 11, fz_rd, fz_wr,
                        &first, &h) != BRISK_OK) {
        abort();
    }
    /* requests go out before any server byte: fine for the core (the blocking open waits) */
    if (brisk_h2_request(h, "GET", "/", NULL, 0, NULL, 0, &s1) != BRISK_OK) {
        abort();
    }
    if ((data[0] & 4) && brisk_h2_request(h, "POST", "/p", NULL, 0, "body", 4, &s2) != BRISK_OK) {
        abort();
    }
    while (p < size) {
        size_t used, len = size - p < split ? size - p : split;
        int r = brisk__h2_feed(h, data + p, len, &used);
        fz_invariants(h);
        if (r != BRISK_OK && r != BRISK_E_PROTO) {
            abort();
        }
        if (used > len || (rc != BRISK_OK && r != rc)) {
            abort();
        }
        rc = r;
        n = brisk__h2_pull(h, out, sizeof out);
        fz_frames(out, n);
        if (r != BRISK_OK) {
            break;
        }
        if (used == 0 && n == 0) {
            abort(); /* a feed that takes nothing must leave something to pull */
        }
        p += used;
    }
    /* the blocking layer over what is left: the transport now reports end of stream */
    rc = brisk_h2_response(s1, &status, NULL, NULL);
    if (rc == BRISK_OK) {
        while (brisk_h2_read(s1, buf, sizeof buf) > 0) {
        }
    }
    fz_invariants(h);
    brisk_h2_stream_close(s1);
    brisk_h2_stream_close(s2);
    brisk_h2_close(h);
    for (n = 0; n < brisk_h2_size(); n++) {
        if (fz_arena[(data[0] >> 4) + n]) {
            abort();
        }
    }
    return 0;
}
