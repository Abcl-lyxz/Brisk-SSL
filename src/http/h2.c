/* h2.c - HTTP/2 client (RFC 9113): frames, streams, flow control, SETTINGS, PING, GOAWAY and the
 * blocking brisk_h2_* API.
 *
 * LAYERS. brisk__h2_feed / brisk__h2_pull are the pure core: server bytes in (any split, one
 * frame per call), client frames out through a 4 KB queue, no I/O, no clock, no malloc. The
 * public calls are a thin loop over them (h2_wait): flush the queue through `wr`, read into the
 * rx staging through `rd`, feed ONE frame, re-check the condition. Stopping on a frame boundary
 * the moment the condition holds makes every result and every client byte independent of how
 * the transport splits the input (tests/test_h2.c replays each row at many splits).
 *
 * MEMORY (caller's, brisk_h2_size): the struct, the HPACK table ring, a 4 KB field-block
 * assembly buffer (= our SETTINGS_MAX_HEADER_LIST_SIZE), a 4 KB scratch, tx 4 KB, rx 1 KB and one
 * ring per stream of W + 4096 octets (W = BRISK_H2_STREAM_WINDOW). A stream ring holds the final
 * response's decoded fields (parked until brisk_h2_response, [u16 nl][u16 vl][name][value] each,
 * n + v + 4 <= n + v + 32, so <= 4096) followed by DATA. We advertise W as the stream window and
 * credit only what the application consumed, so a ring can never overflow (6.9).
 *
 * WINDOWS. Receive: stream window W, credited (WINDOW_UPDATE) once W/2 octets are owed; the
 * connection window is max(65535, MAX_STREAMS * W) (a WINDOW_UPDATE after SETTINGS raises it,
 * 6.9.2), credited at the same W/2 step as octets leave any ring - consumed, discarded by
 * stream_close, padding, or DATA for streams we no longer track. Send: 6.9.1 windows, int32
 * with range checks before every add.
 *
 * STRICTNESS. Connection errors (5.4.1) queue GOAWAY(0, code) and make the handle sticky
 * BRISK_E_PROTO; stream errors (5.4.2) queue RST_STREAM for that stream only. Documented leniency:
 * frames on a stream we no longer track (closed, reset, freed) are minimally processed and
 * dropped (5.1 "closed" allows it); a PRIORITY with a bad length and PUSH_PROMISE are connection
 * errors (5.4.1 permits it); a field block over our 4 KB limit is COMPRESSION_ERROR (it cannot be
 * decoded, 4.3). RFC 9113 9.2.3 (post-handshake CertificateRequest = connection error) is met by
 * the TLS layer: the handshake engine rejects it and brisk_read fails.
 *
 * Not constant time: nothing secret is branched on. Authorization / cookie values pass through
 * tx, scratch and the rings: brisk_h2_stream_close wipes the ring, brisk_h2_close the arena.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_H2

#    include <limits.h>
#    include <string.h>

#    define H2_W        ((uint32_t)BRISK_H2_STREAM_WINDOW)
#    define H2_L        BRISK__H2_MAX_LIST
#    define H2_RING     (H2_W + H2_L)
#    define H2_CREDIT   (H2_W / 2)  /* WINDOW_UPDATE step, stream and connection */
#    define H2_RESERVE  64u         /* tx room a frame's reactions may need (RST+2 WU+GOAWAY) */
#    define H2_MAXWIN   0x7fffffffL /* 6.9.1: 2^31-1 */
#    define H2_CONT_MAX 32u         /* CONTINUATION frames per field block (VU#421644) */
#    define H2_IDLE_MAX 1000u       /* frames without progress per call (CVE-2019-9512 class) */
#    define H2_FRAME    16384u      /* our SETTINGS_MAX_FRAME_SIZE (4.2), never changed */

/* 6.x frame types */
#    define H2_DATA     0x0
#    define H2_HEADERS  0x1
#    define H2_PRIORITY 0x2
#    define H2_RST      0x3
#    define H2_SETTINGS 0x4
#    define H2_PUSH     0x5
#    define H2_PING     0x6
#    define H2_GOAWAY   0x7
#    define H2_WU       0x8
#    define H2_CONT     0x9
/* flags */
#    define H2_F_ES   0x01 /* END_STREAM (DATA/HEADERS), ACK (SETTINGS/PING) */
#    define H2_F_EH   0x04 /* END_HEADERS */
#    define H2_F_PAD  0x08
#    define H2_F_PRIO 0x20
/* 7. error codes */
#    define H2_NO_ERROR      0x0
#    define H2_PROTOCOL      0x1
#    define H2_FLOW          0x3
#    define H2_STREAM_CLOSED 0x5
#    define H2_FRAME_SIZE    0x6
#    define H2_REFUSED       0x7
#    define H2_CANCEL        0x8
#    define H2_COMPRESSION   0x9
#    define H2_CALM          0xb
/* stream flags */
#    define H2S_SENT_END 0x01 /* we sent END_STREAM (or the upload was stopped) */
#    define H2S_RECV_END 0x02 /* END_STREAM received */
#    define H2S_FINAL    0x04 /* final response fields parked */
#    define H2S_RESP     0x08 /* brisk_h2_response returned them */
#    define H2S_HEAD     0x10 /* request method HEAD */
#    define H2S_HAS_CL   0x20
#    define H2S_NOCL     0x40 /* 204 / 304 / HEAD: content-length is not the DATA length */
#    define H2S_RST      0x80 /* reset / refused / GOAWAY'd: later frames are dropped */
/* h2_class */
#    define H2C_ZERO   0
#    define H2C_IDLE   1
#    define H2C_CLOSED 2
#    define H2C_LIVE   3

typedef struct brisk_h2_stream h2s;

struct h2_align_probe {
    char c;
    struct brisk_h2 x;
};
#    define H2_ALIGN offsetof(struct h2_align_probe, x)

static const uint8_t h2_preface[24] = {'P',  'R',  'I', ' ', '*',  ' ',  'H',  'T',
                                       'T',  'P',  '/', '2', '.',  '0',  '\r', '\n',
                                       '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'};

size_t brisk_h2_size(void)
{
    return (H2_ALIGN - 1) + sizeof(struct brisk_h2) + BRISK_H2_HEADER_TABLE_SIZE + 2 * H2_L +
           BRISK__H2_TX + BRISK__H2_RX + (size_t)BRISK_H2_MAX_STREAMS * H2_RING;
}

/* ------------------------------------------------------------------------------ output queue */

static void h2_fhdr(uint8_t *p, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid)
{
    brisk__store_be24(p, len);
    p[3] = type;
    p[4] = flags;
    brisk__store_be32(p + 5, sid & 0x7fffffffu); /* 4.1: R is sent as 0 */
}

/* A whole control frame into tx. BRISK_E_ARG only if the reserve was mis-sized (internal). */
static int h2_ctrl(brisk_h2 *h, uint8_t type, uint8_t flags, uint32_t sid, const uint8_t *pl,
                   uint32_t n)
{
    if (BRISK__H2_TX - h->tx_len < 9 + (size_t)n) {
        return BRISK_E_ARG;
    }
    h2_fhdr(h->tx + h->tx_len, n, type, flags, sid);
    if (n) {
        memcpy(h->tx + h->tx_len + 9, pl, n);
    }
    h->tx_len += 9 + (size_t)n;
    return BRISK_OK;
}

static int h2_u32(brisk_h2 *h, uint8_t type, uint32_t sid, uint32_t v)
{
    uint8_t b[4];
    brisk__store_be32(b, v);
    return h2_ctrl(h, type, 0, sid, b, 4);
}

/* 5.4.1: GOAWAY(last_stream_id 0 - we accept no server streams, code), sticky BRISK_E_PROTO. */
static int h2_conn_err(brisk_h2 *h, uint32_t code)
{
    uint8_t b[8];
    if (h->err == 0) {
        brisk__store_be32(b, 0);
        brisk__store_be32(b + 4, code);
        h->err = h2_ctrl(h, H2_GOAWAY, 0, 0, b, 8) == BRISK_OK ? BRISK_E_PROTO : BRISK_E_ARG;
    }
    return h->err;
}

/* 5.4.2: RST_STREAM(code) on that stream only; its calls fail with BRISK_E_PROTO. Later frames
 * on it are dropped (5.1 closed after our RST). A stream already closed both ways gets no RST. */
static int h2_stream_err(brisk_h2 *h, h2s *s, uint32_t code)
{
    if (s->err == 0) {
        s->err = BRISK_E_PROTO;
    }
    if (s->flags & H2S_RST) {
        return BRISK_OK;
    }
    s->flags |= H2S_RST;
    if ((s->flags & (H2S_SENT_END | H2S_RECV_END)) == (H2S_SENT_END | H2S_RECV_END)) {
        return BRISK_OK;
    }
    return h2_u32(h, H2_RST, s->id, code);
}

/* 6.9: WINDOW_UPDATE once W/2 octets are owed - the stream first (not after END_STREAM or a
 * reset: nothing more may come), then the connection. Windows stay <= max(65535, n*W). */
static int h2_credit(brisk_h2 *h, h2s *s)
{
    int rc = BRISK_OK;
    if (s != NULL && s->pend >= H2_CREDIT && !(s->flags & (H2S_RECV_END | H2S_RST))) {
        rc = h2_u32(h, H2_WU, s->id, s->pend);
        s->rwin += (int32_t)s->pend;
        s->pend = 0;
    }
    if (rc == BRISK_OK && h->cpend >= H2_CREDIT) {
        rc = h2_u32(h, H2_WU, 0, h->cpend);
        h->crwin += (int32_t)h->cpend;
        h->cpend = 0;
    }
    return rc;
}

size_t brisk__h2_pull(brisk_h2 *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (h == NULL || (out == NULL && cap)) {
        return 0;
    }
    while (n < h->tx_len) { /* whole frames only */
        size_t f = 9 + (size_t)brisk__load_be24(h->tx + n);
        if (f > cap - n) {
            break;
        }
        n += f;
    }
    if (n == 0) {
        return 0;
    }
    memcpy(out, h->tx, n);
    memmove(h->tx, h->tx + n, h->tx_len - n);
    h->tx_len -= n;
    return n;
}

/* --------------------------------------------------------------------------------- rings */

static int h2_ring_put(h2s *s, const uint8_t *p, size_t n)
{
    uint32_t pos, k;
    if (n > H2_RING - s->rlen) {
        return BRISK_E_ARG; /* cannot happen: window + header-list bounds (internal fault) */
    }
    pos = s->rhead + s->rlen;
    if (pos >= H2_RING) {
        pos -= H2_RING;
    }
    k = H2_RING - pos < n ? H2_RING - pos : (uint32_t)n;
    memcpy(s->ring + pos, p, k);
    memcpy(s->ring, p + k, n - k);
    s->rlen += (uint32_t)n;
    return BRISK_OK;
}

static void h2_ring_get(h2s *s, uint8_t *p, size_t n)
{
    uint32_t k = H2_RING - s->rhead < n ? H2_RING - s->rhead : (uint32_t)n;
    memcpy(p, s->ring + s->rhead, k);
    memcpy(p + k, s->ring, n - k);
    s->rhead += (uint32_t)n;
    if (s->rhead >= H2_RING) {
        s->rhead -= H2_RING;
    }
    s->rlen -= (uint32_t)n;
}

/* ----------------------------------------------------------------------------- receive side */

/* 5.1 / 5.1.1: stream 0, idle (even = server-initiated, never valid with push off; odd above
 * the highest we opened), closed (ours, no longer tracked or reset), or live. */
static int h2_class(brisk_h2 *h, uint32_t sid, h2s **out)
{
    unsigned i;
    *out = NULL;
    if (sid == 0) {
        return H2C_ZERO;
    }
    if (!(sid & 1) || sid >= h->next_id) {
        return H2C_IDLE;
    }
    for (i = 0; i < BRISK_H2_MAX_STREAMS; i++) {
        if (h->s[i].id == sid) {
            /* reset, or closed both ways (5.1 closed: minimal processing, then dropped) */
            if (!(h->s[i].flags & H2S_RST) && (h->s[i].flags & (H2S_SENT_END | H2S_RECV_END)) !=
                                                    (H2S_SENT_END | H2S_RECV_END)) {
                *out = &h->s[i];
                return H2C_LIVE;
            }
            break;
        }
    }
    return H2C_CLOSED;
}

/* 8.1.1: the stream received END_STREAM; a content-length the DATA did not reach = malformed */
static int h2_recv_end(brisk_h2 *h, h2s *s)
{
    s->flags |= H2S_RECV_END;
    if ((s->flags & (H2S_HAS_CL | H2S_NOCL)) == H2S_HAS_CL && s->got != s->cl) {
        return h2_stream_err(h, s, H2_PROTOCOL);
    }
    return BRISK_OK;
}

/* 8.1.1 / RFC 9110 8.6: 1*DIGIT, 19 digits at most (no overflow; no 64-bit multiply). */
static int h2_cl_parse(const uint8_t *v, size_t n, uint64_t *out)
{
    uint64_t x = 0;
    size_t i;
    if (n == 0 || n > 19) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return 0;
        }
        x = (x << 3) + (x << 1) + (uint64_t)(v[i] - '0');
    }
    *out = x;
    return 1;
}

static int h2_is(const uint8_t *n, size_t nl, const char *lit)
{
    return strlen(lit) == nl && memcmp(n, lit, nl) == 0;
}

/* 8.2.2: connection-specific fields never appear in HTTP/2 */
static int h2_conn_specific(const uint8_t *n, size_t nl)
{
    return h2_is(n, nl, "connection") || h2_is(n, nl, "proxy-connection") ||
           h2_is(n, nl, "keep-alive") || h2_is(n, nl, "transfer-encoding") ||
           h2_is(n, nl, "upgrade");
}

/* The HPACK decode callback: RFC 9113 8.2 / 8.3 checks on every field of a block for a live
 * stream, and parking of the final response's fields. Never aborts the decode - the table must
 * stay in sync (4.3) - a violation only marks the block malformed (8.1.1). */
static int h2_on_field(void *ctx, const uint8_t *name, size_t nl, const uint8_t *value, size_t vl,
                       unsigned flags)
{
    brisk_h2 *h = (brisk_h2 *)ctx;
    h2s *s = h->b_s;
    (void)flags;
    if (s == NULL || h->b_bad) {
        return 0;
    }
    if (!brisk__hpack_field_ok(name, nl, value, vl)) {
        h->b_bad = 1; /* 8.2.1 */
        return 0;
    }
    if (name[0] == ':') {
        /* 8.3: a response carries exactly one :status, before every regular field; trailers
         * carry none (8.1); every other pseudo-header is malformed (8.3.2) */
        if (h->b_trailer || h->b_seen || h->b_reg || !h2_is(name, nl, ":status") || vl != 3 ||
            value[0] < '1' || value[0] > '5' || value[1] < '0' || value[1] > '9' ||
            value[2] < '0' || value[2] > '9') {
            h->b_bad = 1;
            return 0;
        }
        h->b_seen = 1;
        h->b_status = (uint16_t)((value[0] - '0') * 100 + (value[1] - '0') * 10 + (value[2] - '0'));
        if (h->b_status == 101) {
            h->b_bad = 1; /* 8.6: HTTP/2 removes 101 */
        }
        h->b_park = h->b_status >= 200;
        return 0;
    }
    if ((!h->b_trailer && !h->b_seen) || h2_conn_specific(name, nl)) {
        h->b_bad = 1; /* pseudo-headers first (8.3); 8.2.2 */
        return 0;
    }
    h->b_reg = 1;
    if (!h->b_park) {
        return 0; /* interim 1xx and trailers: validated, discarded */
    }
    if (h2_is(name, nl, "content-length")) {
        uint64_t v;
        if (!h2_cl_parse(value, vl, &v) || (h->b_has_cl && v != h->b_cl)) {
            h->b_bad = 1; /* 8.1.1 / RFC 9110 8.6: identical duplicates only */
            return 0;
        }
        h->b_cl = v;
        h->b_has_cl = 1;
    }
    {
        uint8_t b[4];
        brisk__store_be16(b, (uint32_t)nl);
        brisk__store_be16(b + 2, (uint32_t)vl);
        if (h2_ring_put(s, b, 4) || h2_ring_put(s, name, nl) || h2_ring_put(s, value, vl)) {
            h->b_bad = 1; /* unreachable: n + v + 4 <= n + v + 32 <= max_list <= ring */
        }
    }
    return 0;
}

/* A complete field block (4.3): always decoded - even for a stream we dropped - then judged. */
static int h2_block_end(brisk_h2 *h)
{
    h2s *s = h->b_s;
    int rc;
    h->in_blk = 0;
    rc = brisk__hpack_decode(&h->dec, h->blk, h->blk_len, h->scratch, H2_L, H2_L, h2_on_field, h);
    h->blk_len = 0;
    if (rc != BRISK_OK) {
        return h2_conn_err(h, H2_COMPRESSION); /* 4.3 */
    }
    if (s == NULL) {
        return BRISK_OK;
    }
    if (h->b_trailer || h->b_status >= 200) {
        h->idle = 0; /* 10.5: an endless run of 1xx blocks is not progress */
    }
    if (!h->b_trailer && !h->b_bad &&
        (!h->b_seen || (h->b_status < 200 && h->b_es))) { /* 8.1: 1xx never ends a stream */
        h->b_bad = 1;
    }
    if (h->b_trailer && !h->b_es) {
        h->b_bad = 1; /* 8.1: trailers MUST end the stream */
    }
    if (h->b_bad) {
        s->rlen = h->b_pre; /* drop what was parked */
        return h2_stream_err(h, s, H2_PROTOCOL);
    }
    if (!h->b_trailer && h->b_status < 200 && ++s->n1xx > 16) {
        /* 10.5: a local cap - retried blocking calls reset h->idle, so this must not rely on it */
        return h2_conn_err(h, H2_CALM);
    }
    if (!h->b_trailer && h->b_status >= 200) {
        s->flags |= H2S_FINAL;
        s->status = h->b_status;
        s->hdr = s->rlen;
        if (h->b_has_cl) {
            s->flags |= H2S_HAS_CL;
            s->cl = h->b_cl;
        }
        if (s->status == 204 || s->status == 304 || (s->flags & H2S_HEAD)) {
            s->flags |= H2S_NOCL; /* 8.1.1: no content by definition */
        }
    }
    return h->b_es ? h2_recv_end(h, s) : BRISK_OK;
}

/* 6.5.2: one 6-octet setting (in pb) */
static int h2_setting(brisk_h2 *h)
{
    uint32_t id = brisk__load_be16(h->pb), v = brisk__load_be32(h->pb + 2);
    unsigned i;
    switch (id) {
    case 0x1: /* HEADER_TABLE_SIZE: RFC 7541 4.2 / RFC 9113 4.3.1 */
        brisk__hpack_enc_peer_max(&h->enc, v);
        break;
    case 0x2: /* ENABLE_PUSH: a server MUST NOT send 1; anything but 0 / 1 is invalid */
        if (v != 0) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        break;
    case 0x3:
        h->p_conc = v;
        break;
    case 0x4: /* INITIAL_WINDOW_SIZE: 6.9.2 adjusts every open stream's send window */
        if (v > (uint32_t)H2_MAXWIN) {
            return h2_conn_err(h, H2_FLOW);
        }
        for (i = 0; i < BRISK_H2_MAX_STREAMS; i++) {
            int64_t w = (int64_t)h->s[i].swin + (int64_t)v - (int64_t)h->p_win;
            if (h->s[i].id == 0) {
                continue;
            }
            if (w > H2_MAXWIN || w < -H2_MAXWIN) {
                return h2_conn_err(h, H2_FLOW);
            }
            h->s[i].swin = (int32_t)w;
        }
        h->p_win = v;
        break;
    case 0x5: /* MAX_FRAME_SIZE: 2^14 .. 2^24-1 */
        if (v < 16384 || v > 16777215) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        h->p_frame = v;
        break;
    case 0x6:
        h->p_list = v;
        break;
    default: /* 6.5.2: unknown settings (RFC 8441 0x8, RFC 9218 0x9, ...) MUST be ignored */
        break;
    }
    return BRISK_OK;
}

/* 6.8 */
static void h2_goaway(brisk_h2 *h, uint32_t last, uint32_t code)
{
    unsigned i;
    if (!h->goaway || last < h->last_id) {
        h->last_id = last; /* it may only shrink */
    }
    h->goaway = 1;
    if (code != H2_NO_ERROR) {
        h->goaway_err = 1;
    }
    for (i = 0; i < BRISK_H2_MAX_STREAMS; i++) {
        h2s *s = &h->s[i];
        if (s->id > h->last_id && !(s->flags & (H2S_RST | H2S_RECV_END))) {
            s->flags |= H2S_RST;
            if (s->err == 0) {
                s->err = BRISK_E_RETRY; /* 8.7: not processed, safe to retry */
            }
        }
    }
}

/* 6.4 on a live stream */
static void h2_rst_recv(h2s *s, uint32_t code)
{
    s->flags |= H2S_RST;
    if (s->err != 0) {
        return;
    }
    if (code == H2_REFUSED) {
        s->err = BRISK_E_RETRY; /* 8.7 */
    } else if (code == H2_NO_ERROR && (s->flags & H2S_RECV_END)) {
        s->flags |= H2S_SENT_END; /* 8.1: complete response - keep it, stop the upload */
    } else {
        s->err = BRISK_E_PEER_ALERT;
    }
}

/* Frame header complete: every check that needs only the header, before any payload octet. */
static int h2_frame_start(brisk_h2 *h)
{
    uint32_t len = brisk__load_be24(h->fh), sid = brisk__load_be32(h->fh + 5) & 0x7fffffffu;
    uint8_t t = h->fh[3], fl = h->fh[4];
    h2s *s;
    int cls;

    h->f_len = len;
    h->f_pos = 0;
    h->f_end = len;
    h->f_type = t;
    h->f_flags = fl;
    h->f_sid = sid;
    h->f_pfx = 0;
    h->f_s = NULL;
    h->f_dat = 0;
    h->set_n = 0;
    if (++h->idle > H2_IDLE_MAX) {
        return h2_conn_err(h, H2_CALM); /* control-frame flood without progress */
    }
    if (len > H2_FRAME) {
        return h2_conn_err(h, H2_FRAME_SIZE); /* 4.2 */
    }
    if (!h->got_settings && (t != H2_SETTINGS || (fl & H2_F_ES))) {
        return h2_conn_err(h, H2_PROTOCOL); /* 3.4: the server preface is a SETTINGS frame */
    }
    /* 6.2 / 6.10: a field block is contiguous; CONTINUATION only continues one */
    if (h->in_blk ? (t != H2_CONT || sid != h->b_sid) : t == H2_CONT) {
        return h2_conn_err(h, H2_PROTOCOL);
    }
    cls = h2_class(h, sid, &s);
    switch (t) {
    case H2_DATA: /* 6.1 */
        if (cls == H2C_ZERO || cls == H2C_IDLE) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        h->f_pfx = (fl & H2_F_PAD) ? 1 : 0;
        if (len < h->f_pfx) {
            return h2_conn_err(h, H2_FRAME_SIZE); /* 4.2: too small for its mandatory fields */
        }
        if (len > (uint32_t)h->crwin) {
            return h2_conn_err(h, H2_FLOW); /* 6.9.1 */
        }
        h->crwin -= (int32_t)len; /* the whole payload counts, padding included */
        if (s == NULL) {
            h->cpend += len; /* 5.1 closed: counts, then credited back at once */
        } else if (s->flags & H2S_RECV_END) {
            h->cpend += len;
            return h2_stream_err(h, s, H2_STREAM_CLOSED); /* 5.1 half-closed (remote) */
        } else if (!(s->flags & H2S_FINAL)) {
            h->cpend += len;
            return h2_stream_err(h, s, H2_PROTOCOL); /* 8.1: DATA before the response */
        } else if (len > (uint32_t)s->rwin) {
            h->cpend += len;
            return h2_stream_err(h, s, H2_FLOW); /* 6.9.1 */
        } else {
            s->rwin -= (int32_t)len;
            h->f_s = s;
        }
        return BRISK_OK;
    case H2_HEADERS: /* 6.2 */
        if (cls == H2C_ZERO || cls == H2C_IDLE) {
            return h2_conn_err(h, H2_PROTOCOL); /* incl. server-initiated: push is off */
        }
        h->f_pfx = (uint8_t)(((fl & H2_F_PAD) ? 1 : 0) + ((fl & H2_F_PRIO) ? 5 : 0));
        if (len < h->f_pfx) {
            return h2_conn_err(h, H2_FRAME_SIZE); /* 4.2: a field-block frame, so connection */
        }
        h->in_blk = 1;
        h->b_sid = sid;
        h->blk_len = 0;
        h->b_es = (uint8_t)(fl & H2_F_ES);
        h->b_cont = 0;
        h->b_s = NULL;
        h->b_bad = h->b_seen = h->b_reg = h->b_park = h->b_has_cl = 0;
        h->b_status = 0;
        h->b_cl = 0;
        if (s != NULL) {
            if (s->flags & H2S_RECV_END) {
                return h2_stream_err(h, s, H2_STREAM_CLOSED); /* decoded, then dropped */
            }
            h->b_s = s;
            h->b_trailer = (s->flags & H2S_FINAL) ? 1 : 0;
            h->b_pre = s->rlen;
        }
        return BRISK_OK;
    case H2_CONT: /* 6.10 */
        if (++h->b_cont > H2_CONT_MAX) {
            return h2_conn_err(h, H2_CALM);
        }
        return BRISK_OK;
    case H2_PRIORITY: /* 6.3; content ignored (5.3.2) */
        if (cls == H2C_ZERO) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        return len != 5 ? h2_conn_err(h, H2_FRAME_SIZE) : BRISK_OK;
    case H2_RST: /* 6.4 */
        if (cls == H2C_ZERO || cls == H2C_IDLE) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        return len != 4 ? h2_conn_err(h, H2_FRAME_SIZE) : BRISK_OK;
    case H2_SETTINGS: /* 6.5 */
        if (cls != H2C_ZERO) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        if ((fl & H2_F_ES) ? len != 0 : len % 6 != 0) {
            return h2_conn_err(h, H2_FRAME_SIZE);
        }
        return BRISK_OK;
    case H2_PUSH: /* 6.6: we sent SETTINGS_ENABLE_PUSH = 0 before any request (8.4) */
        return h2_conn_err(h, H2_PROTOCOL);
    case H2_PING: /* 6.7 */
        if (cls != H2C_ZERO) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        return len != 8 ? h2_conn_err(h, H2_FRAME_SIZE) : BRISK_OK;
    case H2_GOAWAY: /* 6.8 */
        if (cls != H2C_ZERO) {
            return h2_conn_err(h, H2_PROTOCOL);
        }
        return len < 8 ? h2_conn_err(h, H2_FRAME_SIZE) : BRISK_OK;
    case H2_WU: /* 6.9 */
        if (len != 4) {
            return h2_conn_err(h, H2_FRAME_SIZE);
        }
        return cls == H2C_IDLE ? h2_conn_err(h, H2_PROTOCOL) : BRISK_OK;
    default: /* 5.5: unknown types are ignored */
        return BRISK_OK;
    }
}

/* n payload octets of the current frame */
static int h2_payload(brisk_h2 *h, const uint8_t *p, size_t n)
{
    int rc;
    while (n) {
        size_t k = n;
        switch (h->f_type) {
        case H2_DATA:
        case H2_HEADERS:
        case H2_CONT:
            if (h->f_pos < h->f_pfx) {
                k = 1;
                if (h->f_pos == 0 && (h->f_flags & H2_F_PAD)) {
                    /* 6.1 / 6.2: padding as long as the payload or longer = PROTOCOL_ERROR */
                    h->pad = *p;
                    if (h->pad > h->f_len - h->f_pfx) {
                        return h2_conn_err(h, H2_PROTOCOL);
                    }
                    h->f_end = h->f_len - h->pad;
                }
            } else if (h->f_pos < h->f_end) {
                k = h->f_end - h->f_pos < n ? h->f_end - h->f_pos : n;
                if (h->f_type != H2_DATA) {
                    if (k > H2_L - h->blk_len) {
                        return h2_conn_err(h, H2_COMPRESSION); /* over our list size: 4.3 */
                    }
                    memcpy(h->blk + h->blk_len, p, k);
                    h->blk_len += k;
                } else if (h->f_s != NULL) {
                    if ((rc = h2_ring_put(h->f_s, p, k)) != BRISK_OK) {
                        return h->err = rc;
                    }
                    h->f_dat += (uint32_t)k;
                }
            } /* else padding: skipped (non-zero padding MAY be ignored) */
            break;
        case H2_SETTINGS:
            k = 1;
            h->pb[h->set_n++] = *p;
            if (h->set_n == 6) {
                h->set_n = 0;
                if ((rc = h2_setting(h)) != BRISK_OK) {
                    return rc;
                }
            }
            break;
        case H2_RST:
        case H2_PING:
        case H2_GOAWAY:
        case H2_WU:
            if (h->f_pos < 8) {
                k = 1;
                h->pb[h->f_pos] = *p;
            }
            break;
        default:
            break;
        }
        p += k;
        n -= k;
        h->f_pos += (uint32_t)k;
    }
    return BRISK_OK;
}

/* Frame complete: act on it. */
static int h2_frame_end(brisk_h2 *h)
{
    h2s *s = h->f_s;
    uint32_t v, sid = h->f_sid;
    int rc;
    switch (h->f_type) {
    case H2_DATA:
        h->f_s = NULL; /* the frame is fully counted: a later stream_close must not credit it */
        if (s != NULL) {
            uint32_t data = h->f_end - h->f_pfx, padn = h->f_len - data;
            s->ready = s->rlen - s->hdr; /* only whole frames become readable */
            s->pend += padn;             /* 6.9.1: padding is credited back at once */
            h->cpend += padn;
            s->got += data;
            if (data || (h->f_flags & H2_F_ES)) {
                h->idle = 0;
            }
            if ((s->flags & (H2S_HAS_CL | H2S_NOCL)) == H2S_HAS_CL && s->got > s->cl) {
                rc = h2_stream_err(h, s, H2_PROTOCOL); /* 8.1.1 */
            } else {
                rc = (h->f_flags & H2_F_ES) ? h2_recv_end(h, s) : BRISK_OK;
            }
            if (rc != BRISK_OK) {
                return rc;
            }
        }
        return h2_credit(h, s);
    case H2_HEADERS:
    case H2_CONT:
        return (h->f_flags & H2_F_EH) ? h2_block_end(h) : BRISK_OK;
    case H2_RST:
        if (h2_class(h, sid, &s) == H2C_LIVE) {
            h2_rst_recv(s, brisk__load_be32(h->pb));
        }
        return BRISK_OK;
    case H2_SETTINGS:
        if (h->f_flags & H2_F_ES) {
            return BRISK_OK; /* ACK of ours */
        }
        h->got_settings = 1;
        return h2_ctrl(h, H2_SETTINGS, H2_F_ES, 0, NULL, 0); /* 6.5.3: one ACK each */
    case H2_PING:
        return (h->f_flags & H2_F_ES) ? BRISK_OK : h2_ctrl(h, H2_PING, H2_F_ES, 0, h->pb, 8);
    case H2_GOAWAY:
        h2_goaway(h, brisk__load_be32(h->pb) & 0x7fffffffu, brisk__load_be32(h->pb + 4));
        return BRISK_OK;
    case H2_WU:
        v = brisk__load_be32(h->pb) & 0x7fffffffu;
        if (sid == 0) {
            if (v == 0) {
                return h2_conn_err(h, H2_PROTOCOL); /* 6.9 */
            }
            if ((int64_t)h->cwin + v > H2_MAXWIN) {
                return h2_conn_err(h, H2_FLOW); /* 6.9.1 */
            }
            h->cwin += (int32_t)v;
            return BRISK_OK;
        }
        if (h2_class(h, sid, &s) != H2C_LIVE) {
            return BRISK_OK; /* closed: may still arrive (5.1) */
        }
        if (v == 0) {
            return h2_stream_err(h, s, H2_PROTOCOL);
        }
        if ((int64_t)s->swin + v > H2_MAXWIN) {
            return h2_stream_err(h, s, H2_FLOW);
        }
        s->swin += (int32_t)v;
        return BRISK_OK;
    default:
        return BRISK_OK;
    }
}

int brisk__h2_feed(brisk_h2 *h, const uint8_t *in, size_t len, size_t *used)
{
    size_t p = 0;
    int rc = BRISK_OK;
    if (used != NULL) {
        *used = 0;
    }
    if (h == NULL || used == NULL || (in == NULL && len)) {
        return BRISK_E_ARG;
    }
    if (h->err != 0) {
        return h->err;
    }
    while (h->fh_n < 9) {
        if (h->fh_n == 0 && BRISK__H2_TX - h->tx_len < H2_RESERVE) {
            return BRISK_OK; /* backpressure: pull first, never drop an ACK */
        }
        if (p == len) {
            *used = p;
            return BRISK_OK;
        }
        h->fh[h->fh_n++] = in[p++];
        if (h->fh_n == 9 && (rc = h2_frame_start(h)) != BRISK_OK) {
            *used = p;
            return rc;
        }
    }
    if (h->f_pos < h->f_len && p < len) {
        size_t n = h->f_len - h->f_pos < len - p ? h->f_len - h->f_pos : len - p;
        rc = h2_payload(h, in + p, n);
        p += n;
    }
    if (rc == BRISK_OK && h->f_pos == h->f_len) {
        h->fh_n = 0;
        rc = h2_frame_end(h);
    }
    *used = p;
    return rc != BRISK_OK ? rc : h->err;
}

/* ------------------------------------------------------------------------- blocking layer */

/* Write the whole queue. A failed write is final for the handle (a frame may be half sent). */
static int h2_flush(brisk_h2 *h)
{
    int rc;
    if (h->tx_len == 0) {
        return BRISK_OK;
    }
    rc = h->wr(h->io, h->tx, h->tx_len);
    h->tx_len = 0;
    if (rc < 0 && h->err == 0) {
        h->err = rc;
    }
    return rc < 0 ? rc : BRISK_OK;
}

typedef int (*h2_cond_fn)(brisk_h2 *h, h2s *s);

static int h2_c_settings(brisk_h2 *h, h2s *s)
{
    (void)s;
    return h->got_settings;
}

static int h2_c_final(brisk_h2 *h, h2s *s)
{
    (void)h;
    return (s->flags & H2S_FINAL) || s->err != 0;
}

static int h2_c_data(brisk_h2 *h, h2s *s)
{
    (void)h;
    return s->ready != 0 || (s->flags & H2S_RECV_END) || s->err != 0;
}

static int h2_c_window(brisk_h2 *h, h2s *s)
{
    return (s->swin > 0 && h->cwin > 0) || s->err != 0 || (s->flags & (H2S_SENT_END | H2S_RST));
}

/* Process server frames one at a time until cond holds (then flush and return BRISK_OK), the
 * handle fails (sticky), the transport ends, or the read times out (harmless, nothing lost). */
static int h2_wait(brisk_h2 *h, h2_cond_fn cond, h2s *s)
{
    for (;;) {
        size_t used;
        int r;
        if (h->err != 0) {
            (void)h2_flush(h); /* the GOAWAY, best effort */
            return h->err;
        }
        if (h->fh_n == 0 && cond(h, s)) { /* frame boundaries only: split-independent */
            return h2_flush(h);
        }
        if (h->eof != 0) {
            return h->eof;
        }
        if (h->rx_off < h->rx_len) {
            r = brisk__h2_feed(h, h->rx + h->rx_off, h->rx_len - h->rx_off, &used);
            h->rx_off += used;
            if (r == BRISK_OK && used == 0 && (r = h2_flush(h)) != BRISK_OK) {
                return r;
            }
            continue;
        }
        if ((r = h2_flush(h)) != BRISK_OK) {
            return r;
        }
        r = h->rd(h->io, h->rx, BRISK__H2_RX);
        if (r > 0) {
            h->rx_off = 0;
            h->rx_len = (size_t)r;
        } else if (r == BRISK_E_TIMEOUT) {
            return r;
        } else {
            /* close_notify or a dead TLS connection: what completed stays readable */
            h->eof = r < 0 ? r : (h->goaway_err ? BRISK_E_PEER_ALERT : BRISK_E_IO);
        }
    }
}

int brisk__h2_setup(void *mem, size_t mem_len, const char *authority, size_t auth_len,
                    brisk__h2_rd_fn rd, brisk__h2_wr_fn wr, void *io, brisk_h2 **out)
{
    uint8_t *m = (uint8_t *)mem, set[24];
    brisk_h2 *h;
    size_t n = 0;
    unsigned i;
    if (out != NULL) {
        *out = NULL;
    }
    if (mem == NULL || out == NULL || authority == NULL || rd == NULL || wr == NULL ||
        mem_len < brisk_h2_size() || auth_len == 0 || auth_len >= sizeof h->auth ||
        !brisk__hpack_field_ok((const uint8_t *)":authority", 10, (const uint8_t *)authority,
                               auth_len)) {
        return BRISK_E_ARG;
    }
    m += (H2_ALIGN - ((uintptr_t)m & (H2_ALIGN - 1))) & (H2_ALIGN - 1);
    h = (brisk_h2 *)(void *)m;
    memset(h, 0, sizeof *h);
    m += sizeof *h;
    h->mem = (uint8_t *)mem;
    h->mem_len = mem_len;
    h->rd = rd;
    h->wr = wr;
    h->io = io;
    if (brisk__hpack_dec_init(&h->dec, m, BRISK_H2_HEADER_TABLE_SIZE) != BRISK_OK) {
        return BRISK_E_ARG;
    }
    m += BRISK_H2_HEADER_TABLE_SIZE;
    brisk__hpack_enc_init(&h->enc);
    h->blk = m;
    h->scratch = m + H2_L;
    h->tx = m + 2 * H2_L;
    h->rx = h->tx + BRISK__H2_TX;
    m = h->rx + BRISK__H2_RX;
    for (i = 0; i < BRISK_H2_MAX_STREAMS; i++) {
        h->s[i].h = h;
        h->s[i].ring = m + (size_t)i * H2_RING;
    }
    memcpy(h->auth, authority, auth_len);
    h->auth_len = (uint16_t)auth_len;
    h->next_id = 1;
    h->p_conc = 0xffffffffu; /* 6.5.2 initial values: unlimited */
    h->p_list = 0xffffffffu;
    h->p_frame = 16384;
    h->p_win = 65535;
    h->cwin = 65535;
    h->crwin = 65535;
    /* 3.4: preface, then our SETTINGS (6.5.2) */
    memcpy(h->tx, h2_preface, sizeof h2_preface);
    h->tx_len = sizeof h2_preface;
#    if BRISK_H2_HEADER_TABLE_SIZE != 4096
    brisk__store_be16(set + n, 0x1);
    brisk__store_be32(set + n + 2, BRISK_H2_HEADER_TABLE_SIZE);
    n += 6;
#    endif
    brisk__store_be16(set + n, 0x2); /* ENABLE_PUSH 0 */
    brisk__store_be32(set + n + 2, 0);
    brisk__store_be16(set + n + 6, 0x4); /* INITIAL_WINDOW_SIZE W */
    brisk__store_be32(set + n + 8, H2_W);
    brisk__store_be16(set + n + 12, 0x6); /* MAX_HEADER_LIST_SIZE */
    brisk__store_be32(set + n + 14, H2_L);
    n += 18;
    (void)h2_ctrl(h, H2_SETTINGS, 0, 0, set, (uint32_t)n);
    /* 6.9.2: SETTINGS cannot move the connection window; raise it to cover every stream */
    if ((uint32_t)BRISK_H2_MAX_STREAMS * H2_W > 65535u) {
        uint32_t d = (uint32_t)BRISK_H2_MAX_STREAMS * H2_W - 65535u;
        (void)h2_u32(h, H2_WU, 0, d);
        h->crwin += (int32_t)d;
    }
    *out = h;
    return BRISK_OK;
}

int brisk__h2_start(brisk_h2 *h)
{
    if (h == NULL) {
        return BRISK_E_ARG;
    }
    h->idle = 0;
    return h2_wait(h, h2_c_settings, NULL);
}

/* ------------------------------------------------------------------------------ public API */

/* RFC 9110 5.6.2 tchar */
static int h2_token(const char *m)
{
    const char *x = "!#$%&'*+-.^_`|~";
    if (*m == 0) {
        return 0;
    }
    for (; *m; m++) {
        char c = *m;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              strchr(x, c) != NULL)) {
            return 0;
        }
    }
    return 1;
}

/* Frees the slot: RST_STREAM CANCEL while either direction is open, unread DATA credited back
 * to the connection, the ring wiped. */
static void h2_release(h2s *s)
{
    brisk_h2 *h = s->h;
    if (h->err == 0) {
        if (!(s->flags & H2S_RST) &&
            (s->flags & (H2S_SENT_END | H2S_RECV_END)) != (H2S_SENT_END | H2S_RECV_END)) {
            if (BRISK__H2_TX - h->tx_len < 13 + 13) {
                (void)h2_flush(h);
            }
            (void)h2_u32(h, H2_RST, s->id, H2_CANCEL);
        }
        h->cpend += s->rlen - s->hdr;
        if (h->f_s == s) {
            /* closed mid-DATA frame (after a TIMEOUT): the rest of it is dropped on arrival;
             * credit every octet of it that is not already counted in the ring */
            h->cpend += h->f_len - h->f_dat;
            h->f_s = NULL;
        }
        (void)h2_credit(h, NULL);
        (void)h2_flush(h);
    }
    if (h->b_s == s) {
        h->b_s = NULL; /* mid field block: decode it, park nothing */
    }
    brisk__secure_zero(s->ring, H2_RING);
    {
        uint8_t *ring = s->ring;
        memset(s, 0, sizeof *s);
        s->h = h;
        s->ring = ring;
    }
}

/* One request field: [literal] into frames, spilling into CONTINUATION as tx fills (6.10: the
 * block goes out back to back - nothing else is queued meanwhile). */
static int h2_hfield(brisk_h2 *h, uint32_t *fstart, const uint8_t *n, size_t nl, const uint8_t *v,
                     size_t vl, unsigned flags, uint32_t sid)
{
    brisk__hpack_field f;
    size_t len, off = 0;
    int rc;
    f.name = n;
    f.name_len = nl;
    f.value = v;
    f.value_len = vl;
    f.flags = flags;
    rc = brisk__hpack_encode(&h->enc, &f, 1, h->scratch, H2_L, &len);
    if (rc != BRISK_OK) {
        return rc;
    }
    while (off < len) {
        size_t room = BRISK__H2_TX - h->tx_len, k;
        if (room == 0) {
            /* close this frame (no END_HEADERS), ship it, open a CONTINUATION */
            h2_fhdr(h->tx + *fstart, (uint32_t)(h->tx_len - *fstart - 9), h->tx[*fstart + 3],
                    h->tx[*fstart + 4], sid);
            if ((rc = h2_flush(h)) != BRISK_OK) {
                return rc;
            }
            *fstart = 0;
            h2_fhdr(h->tx, 0, H2_CONT, 0, sid);
            h->tx_len = 9;
            continue;
        }
        k = len - off < room ? len - off : room;
        memcpy(h->tx + h->tx_len, h->scratch + off, k);
        h->tx_len += k;
        off += k;
    }
    return BRISK_OK;
}

static int h2_is_c(const char *s, const char *lit)
{
    return strcmp(s, lit) == 0;
}

int brisk_h2_request(brisk_h2 *h, const char *method, const char *path, const brisk_h2_header *hdrs,
                     size_t n, const void *body, size_t body_len, brisk_h2_stream **out)
{
    const uint8_t *b = (const uint8_t *)body;
    uint64_t list, cl;
    size_t i, off = 0, ml, pl;
    uint32_t fstart;
    unsigned used = 0, lim;
    h2s *s = NULL;
    int rc;

    if (out != NULL) {
        *out = NULL;
    }
    if (h == NULL || method == NULL || path == NULL || (hdrs == NULL && n) ||
        (body == NULL && body_len) || out == NULL) {
        return BRISK_E_ARG;
    }
    if (h->err != 0) {
        return h->err;
    }
    if (h->eof != 0) {
        return h->eof;
    }
    if (h->goaway) {
        return BRISK_E_RETRY; /* 6.8: no new streams after GOAWAY - never sent, safe to retry */
    }
    /* 8.3.1 pseudo-headers; CONNECT (8.5) needs another set and is not supported */
    ml = strlen(method);
    pl = strlen(path);
    if (!h2_token(method) || h2_is_c(method, "CONNECT") || pl == 0 ||
        !(path[0] == '/' || (h2_is_c(path, "*") && h2_is_c(method, "OPTIONS"))) ||
        !brisk__hpack_field_ok((const uint8_t *)":path", 5, (const uint8_t *)path, pl) ||
        ml + 16 > H2_L || pl + 16 > H2_L) {
        return BRISK_E_ARG;
    }
    list = (uint64_t)ml + 7 + 32 + 5 + 7 + 32 + h->auth_len + 10 + 32 + pl + 5 + 32;
    for (i = 0; i < n; i++) {
        const char *nm = hdrs[i].name, *v = hdrs[i].value;
        size_t nl, vl;
        if (nm == NULL || v == NULL) {
            return BRISK_E_ARG;
        }
        nl = strlen(nm);
        vl = strlen(v);
        /* 8.2.1 octets (and lowercase), no pseudo-header from the caller (8.3), no
         * connection-specific field (8.2.2), te only as "trailers", no host (8.3.1: :authority
         * carries it), content-length that matches the body (8.1.1) */
        if (!brisk__hpack_field_ok((const uint8_t *)nm, nl, (const uint8_t *)v, vl) ||
            nm[0] == ':' || h2_conn_specific((const uint8_t *)nm, nl) || h2_is_c(nm, "host") ||
            (h2_is_c(nm, "te") && !h2_is_c(v, "trailers")) || nl + vl + 16 > H2_L ||
            (h2_is_c(nm, "content-length") &&
             (!h2_cl_parse((const uint8_t *)v, vl, &cl) || cl != (uint64_t)body_len))) {
            return BRISK_E_ARG;
        }
        list += (uint64_t)nl + vl + 32;
    }
    if (list > h->p_list) {
        return BRISK_E_ARG; /* 10.5.1: the server's SETTINGS_MAX_HEADER_LIST_SIZE */
    }
    if (h->next_id > 0x7fffffffu) {
        return BRISK_E_ARG; /* 5.1.1: ids exhausted - open a new connection */
    }
    lim = h->p_conc < BRISK_H2_MAX_STREAMS ? (unsigned)h->p_conc : BRISK_H2_MAX_STREAMS;
    for (i = 0; i < BRISK_H2_MAX_STREAMS; i++) {
        if (h->s[i].id != 0) {
            used++;
        } else if (s == NULL) {
            s = &h->s[i];
        }
    }
    if (used >= lim || s == NULL) {
        return BRISK_E_ARG; /* 5.1.2: close a stream first */
    }

    s->id = h->next_id;
    h->next_id += 2;
    s->swin = (int32_t)h->p_win;
    s->rwin = (int32_t)H2_W;
    s->flags = h2_is_c(method, "HEAD") ? H2S_HEAD : 0;
    h->idle = 0;

    /* HEADERS (+ CONTINUATION): open a frame with at least one octet of room */
    if (BRISK__H2_TX - h->tx_len < 10 && (rc = h2_flush(h)) != BRISK_OK) {
        goto fail;
    }
    fstart = (uint32_t)h->tx_len;
    h2_fhdr(h->tx + fstart, 0, H2_HEADERS, body_len ? 0 : H2_F_ES, s->id);
    h->tx_len += 9;
    rc =
        h2_hfield(h, &fstart, (const uint8_t *)":method", 7, (const uint8_t *)method, ml, 0, s->id);
    if (rc == BRISK_OK) {
        rc = h2_hfield(h, &fstart, (const uint8_t *)":scheme", 7, (const uint8_t *)"https", 5, 0,
                       s->id);
    }
    if (rc == BRISK_OK) {
        rc = h2_hfield(h, &fstart, (const uint8_t *)":authority", 10, (const uint8_t *)h->auth,
                       h->auth_len, 0, s->id);
    }
    if (rc == BRISK_OK) {
        rc =
            h2_hfield(h, &fstart, (const uint8_t *)":path", 5, (const uint8_t *)path, pl, 0, s->id);
    }
    for (i = 0; i < n && rc == BRISK_OK; i++) {
        const char *nm = hdrs[i].name;
        /* RFC 7541 7.1.3: credentials never enter any table */
        unsigned fl = h2_is_c(nm, "authorization") || h2_is_c(nm, "proxy-authorization") ||
                              h2_is_c(nm, "cookie") || h2_is_c(nm, "set-cookie")
                          ? BRISK__HPACK_NEVER_INDEXED
                          : 0;
        rc = h2_hfield(h, &fstart, (const uint8_t *)nm, strlen(nm), (const uint8_t *)hdrs[i].value,
                       strlen(hdrs[i].value), fl, s->id);
    }
    if (rc != BRISK_OK) {
        goto fail;
    }
    h2_fhdr(h->tx + fstart, (uint32_t)(h->tx_len - fstart - 9), h->tx[fstart + 3],
            (uint8_t)(h->tx[fstart + 4] | H2_F_EH), s->id);
    if (!body_len) {
        s->flags |= H2S_SENT_END;
    }

    /* body: DATA within both send windows and the peer's frame size (6.9.1, 4.2) */
    while (off < body_len && !(s->flags & (H2S_SENT_END | H2S_RST)) && s->err == 0) {
        size_t room = BRISK__H2_TX - h->tx_len, k = body_len - off;
        if (room < 10) {
            if ((rc = h2_flush(h)) != BRISK_OK) {
                goto fail;
            }
            continue;
        }
        if (s->swin <= 0 || h->cwin <= 0) {
            /* shut: read (WINDOW_UPDATE, SETTINGS, other streams' DATA) until credit arrives */
            if ((rc = h2_wait(h, h2_c_window, s)) != BRISK_OK) {
                goto fail;
            }
            continue;
        }
        k = k < room - 9 ? k : room - 9;
        k = k < (uint32_t)s->swin ? k : (uint32_t)s->swin;
        k = k < (uint32_t)h->cwin ? k : (uint32_t)h->cwin;
        k = k < h->p_frame ? k : h->p_frame;
        h2_fhdr(h->tx + h->tx_len, (uint32_t)k, H2_DATA, off + k == body_len ? H2_F_ES : 0, s->id);
        memcpy(h->tx + h->tx_len + 9, b + off, k);
        h->tx_len += 9 + k;
        off += k;
        s->swin -= (int32_t)k;
        h->cwin -= (int32_t)k;
        h->idle = 0;
        if (off == body_len) {
            s->flags |= H2S_SENT_END;
        }
    }
    if ((rc = h2_flush(h)) != BRISK_OK) {
        goto fail;
    }
    if (h->err != 0 || s->err != 0) {
        rc = h->err != 0 ? h->err : s->err;
        goto fail;
    }
    *out = s;
    return BRISK_OK;
fail:
    h2_release(s);
    return rc;
}

int brisk_h2_response(brisk_h2_stream *s, int *status, brisk_h2_header_fn fn, void *ctx)
{
    brisk_h2 *h;
    int rc;
    if (status != NULL) {
        *status = 0;
    }
    if (s == NULL || status == NULL || s->id == 0 || (s->flags & H2S_RESP)) {
        return BRISK_E_ARG;
    }
    h = s->h;
    h->idle = 0;
    rc = h2_wait(h, h2_c_final, s);
    if (rc != BRISK_OK) {
        return rc;
    }
    if (s->err != 0) {
        return s->err;
    }
    while (s->hdr) { /* replay the parked fields, NUL-terminated copies */
        uint8_t b[4];
        uint32_t nl, vl;
        h2_ring_get(s, b, 4);
        nl = brisk__load_be16(b);
        vl = brisk__load_be16(b + 2);
        h2_ring_get(s, h->scratch, nl);
        h->scratch[nl] = 0;
        h2_ring_get(s, h->scratch + nl + 1, vl);
        h->scratch[nl + 1 + vl] = 0;
        s->hdr -= 4 + nl + vl;
        if (fn != NULL) {
            fn(ctx, (const char *)h->scratch, nl, (const char *)h->scratch + nl + 1, vl);
        }
    }
    s->flags |= H2S_RESP;
    *status = s->status;
    return BRISK_OK;
}

int brisk_h2_read(brisk_h2_stream *s, void *buf, size_t cap)
{
    brisk_h2 *h;
    size_t n;
    int rc;
    if (s == NULL || buf == NULL || cap == 0 || s->id == 0 || !(s->flags & H2S_RESP)) {
        return BRISK_E_ARG;
    }
    h = s->h;
    if (h->err != 0) {
        return h->err;
    }
    if (s->ready == 0 && !(s->flags & H2S_RECV_END) && s->err == 0) {
        h->idle = 0;
        if ((rc = h2_wait(h, h2_c_data, s)) != BRISK_OK) {
            return rc;
        }
    }
    if (s->err != 0) {
        return s->err;
    }
    if (s->ready == 0) {
        return 0; /* END_STREAM, content-length matched */
    }
    n = cap < s->ready ? cap : s->ready;
    n = n < INT_MAX ? n : INT_MAX;
    h2_ring_get(s, (uint8_t *)buf, n);
    s->ready -= (uint32_t)n;
    s->pend += (uint32_t)n;
    h->cpend += (uint32_t)n;
    if ((rc = h2_credit(h, s)) != BRISK_OK) {
        return h->err = rc;
    }
    return (int)n;
}

void brisk_h2_stream_close(brisk_h2_stream *s)
{
    if (s != NULL && s->id != 0) {
        h2_release(s);
    }
}

void brisk_h2_close(brisk_h2 *h)
{
    uint8_t b[8];
    if (h == NULL) {
        return;
    }
    if (h->err == 0) {
        brisk__store_be32(b, 0);
        brisk__store_be32(b + 4, H2_NO_ERROR);
        if (BRISK__H2_TX - h->tx_len < 17) {
            (void)h2_flush(h);
        }
        if (h2_ctrl(h, H2_GOAWAY, 0, 0, b, 8) == BRISK_OK) {
            (void)h2_flush(h);
        }
    }
    brisk__secure_zero(h->mem, h->mem_len);
}

#    undef H2_W
#    undef H2_L
#    undef H2_RING
#    undef H2_CREDIT
#    undef H2_RESERVE
#    undef H2_MAXWIN
#    undef H2_CONT_MAX
#    undef H2_IDLE_MAX
#    undef H2_FRAME
#    undef H2_DATA
#    undef H2_HEADERS
#    undef H2_PRIORITY
#    undef H2_RST
#    undef H2_SETTINGS
#    undef H2_PUSH
#    undef H2_PING
#    undef H2_GOAWAY
#    undef H2_WU
#    undef H2_CONT
#    undef H2_F_ES
#    undef H2_F_EH
#    undef H2_F_PAD
#    undef H2_F_PRIO
#    undef H2_NO_ERROR
#    undef H2_PROTOCOL
#    undef H2_FLOW
#    undef H2_STREAM_CLOSED
#    undef H2_FRAME_SIZE
#    undef H2_REFUSED
#    undef H2_CANCEL
#    undef H2_COMPRESSION
#    undef H2_CALM
#    undef H2S_SENT_END
#    undef H2S_RECV_END
#    undef H2S_FINAL
#    undef H2S_RESP
#    undef H2S_HEAD
#    undef H2S_HAS_CL
#    undef H2S_NOCL
#    undef H2S_RST
#    undef H2C_ZERO
#    undef H2C_IDLE
#    undef H2C_CLOSED
#    undef H2C_LIVE
#    undef H2_ALIGN

#endif /* BRISK_ENABLE_H2 */
