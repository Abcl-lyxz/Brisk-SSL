/* h3.c - HTTP/3 client (RFC 9114) over the QUIC streams of brisk_quic: frames, the control
 * stream, SETTINGS, GOAWAY, the QPACK streams (static table only, qpack.c) and the blocking
 * brisk_h3_* API.
 *
 * LAYERS. Every stream is read through the brisk__h3_io seam (brisk_int.h): the brisk_quic
 * wrappers at the bottom of this file in production, a scripted fake in tests/test_h3.c. The
 * public calls are loops of "serve the server's unidirectional streams, advance the one request
 * stream the caller waits on, else wait for I/O" - never the blocking brisk_quic_stream_read, so
 * the control stream (GOAWAY) and the QPACK streams are served while any call waits, and a
 * request stream is only read when its caller asks (the rest stays in its QUIC buffer).
 * Frames are parsed incrementally over any split: headers are read exactly (varint by varint),
 * DATA payloads are copied from QUIC straight into the caller's buffer, never buffered here.
 *
 * STREAMS. We open one unidirectional control stream (type 0x00 + SETTINGS first, 6.2.1) and
 * never close it. The server's control (0x00), QPACK encoder (0x02) and decoder (0x03) streams
 * are required and must stay open (6.2.1, RFC 9204 4.2); a second one of a kind is
 * H3_STREAM_CREATION_ERROR. A push stream (0x01) is H3_ID_ERROR: we never send MAX_PUSH_ID, so
 * every push ID exceeds the limit (6.2.2, 7.2.5 logic; the push ID is not read first - a
 * documented SHOULD-level shortcut). Other types (reserved 0x1f*N+0x21 included) are read and
 * dropped until they end (6.2 MUST NOT be an error); the QUIC slot then frees.
 *
 * MEMORY (caller's, brisk_h3_size): the handle, a field-decode scratch and a park buffer of
 * L octets each (L = BRISK_H3_MAX_HEADER_LIST), and one L-octet buffer per request slot: the
 * HEADERS frame being assembled, then the parked final fields until brisk_h3_response.
 *
 * STRICTNESS. Connection errors close QUIC with the code (sticky BRISK_E_PROTO); stream errors
 * abort that request both ways (RESET_STREAM + STOP_SENDING). Local limits (a HEADERS frame or a
 * decoded section over L) abort the request with H3_EXCESSIVE_LOAD. More than 1000 frames
 * without progress in one call, or more than 16 interim responses on a request, is
 * H3_EXCESSIVE_LOAD for the connection (the h2.c flood rules). Not constant time: nothing secret
 * is branched on; authorization / cookie values pass through the buffers, which stream_close and
 * brisk_h3_close wipe.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_H3

#    include <limits.h>
#    include <string.h>

#    define H3_L        ((size_t)BRISK_H3_MAX_HEADER_LIST)
#    define H3_NS       (BRISK_QUIC_MAX_STREAMS - 4) /* request slots */
#    define H3_UNI      4                            /* server uni streams tracked at once */
#    define H3_SET_MAX  256u                         /* local cap on a SETTINGS payload */
#    define H3_IDLE_MAX 1000u
#    define H3_1XX_MAX  16u
#    define H3_GREASE   0x157u /* 0x1f * 10 + 0x21: our reserved setting (7.2.4.1) */
/* 7.2 frame types */
#    define H3F_DATA     0x00
#    define H3F_HEADERS  0x01
#    define H3F_CANCEL   0x03
#    define H3F_SETTINGS 0x04
#    define H3F_PUSH     0x05
#    define H3F_GOAWAY   0x07
#    define H3F_MAXPUSH  0x0d
/* 8.1 error codes */
#    define H3E_NO_ERROR         0x0100u
#    define H3E_STREAM_CREATION  0x0103u
#    define H3E_CLOSED_CRITICAL  0x0104u
#    define H3E_FRAME_UNEXPECTED 0x0105u
#    define H3E_FRAME            0x0106u
#    define H3E_EXCESSIVE_LOAD   0x0107u
#    define H3E_ID               0x0108u
#    define H3E_SETTINGS         0x0109u
#    define H3E_MISSING_SETTINGS 0x010au
#    define H3E_REQUEST_REJECTED 0x010bu
#    define H3E_REQUEST_CANCELED 0x010cu
#    define H3E_MESSAGE          0x010eu
/* server uni stream kinds */
#    define H3U_NEW  1 /* type not read yet */
#    define H3U_CTL  2
#    define H3U_ENC  3
#    define H3U_DEC  4
#    define H3U_SKIP 5
/* request stream states */
#    define H3R_HDR   0 /* waiting for the final response header section */
#    define H3R_BODY  1 /* final fields parked / returned; DATA */
#    define H3R_TRAIL 2 /* trailers received */
#    define H3R_END   3 /* FIN consumed */
/* request stream flags */
#    define H3S_HEAD  0x01 /* method HEAD */
#    define H3S_CL    0x02 /* content-length present */
#    define H3S_NOCL  0x04 /* 204 / 304 / HEAD: no content by definition */
#    define H3S_RESP  0x08 /* brisk_h3_response returned the fields */
#    define H3S_SENT  0x10 /* our FIN is written (or the server stopped the upload) */
#    define H3S_ABORT 0x20 /* aborted (by us, or reset by the server): nothing more to cancel */
#    define H3S_SEEN  0x40 /* a response HEADERS frame arrived (1xx included) */

typedef struct {
    uint64_t type, len, pos; /* the frame being read; pos = payload octets consumed */
    uint8_t fh[16], fh_n;    /* its type + length varints as they arrive */
    uint8_t in;              /* 1 = header complete, in the payload */
} h3_fr;

typedef struct {
    uint64_t id;
    h3_fr fr;
    uint8_t kind, tb[8], tn;
} h3_us;

struct brisk_h3_stream {
    struct brisk_h3 *h;
    uint8_t *buf;     /* H3_L: the HEADERS payload being assembled, then the parked fields */
    uint64_t id;      /* QUIC stream id */
    uint64_t cl, got; /* content-length; DATA octets announced so far (4.1.2) */
    h3_fr fr;
    size_t blen, hdr; /* octets in buf; parked field octets not replayed yet */
    int err;          /* this request's error, 0 = none */
    uint16_t status;
    uint8_t used, state, flags, n1xx;
};
typedef struct brisk_h3_stream h3s;

struct brisk_h3 {
    uint8_t *mem; /* the caller's whole arena (wiped by brisk_h3_close) */
    size_t mem_len;
    const brisk__h3_io *op;
    void *io;
    uint8_t *scratch, *park; /* H3_L each: one decoded field; the fields of one section */
    size_t plen;             /* octets parked for the section being decoded */
    uint64_t ctl_id;         /* our control stream */
    uint64_t p_list;         /* the server's SETTINGS_MAX_FIELD_SECTION_SIZE (7.2.4.1) */
    uint64_t goaway_id;      /* lowest GOAWAY stream id received (5.2) */
    uint64_t b_cl;
    int err;       /* sticky: we closed the connection (BRISK_E_PROTO) */
    uint32_t idle; /* frames without progress in this call */
    uint16_t b_status, auth_len;
    uint8_t b_bad, b_seen, b_reg, b_park, b_has_cl, b_trailer;
    uint8_t got_ctl, got_enc, got_dec, got_settings, goaway, qd_n;
    uint8_t used[H3_UNI];
    h3_us uni[H3_UNI];
    uint8_t set[H3_SET_MAX], gb[8], qd[16];
    char auth[264];
    h3s s[H3_NS];
};

struct h3_align_probe {
    char c;
    struct brisk_h3 x;
};
#    define H3_ALIGN offsetof(struct h3_align_probe, x)

size_t brisk_h3_size(void)
{
    return (H3_ALIGN - 1) + sizeof(struct brisk_h3) + (2 + (size_t)H3_NS) * H3_L;
}

size_t brisk__h3_settings(uint8_t *out, size_t cap)
{
    /* 6.2.1: stream type 0x00, then SETTINGS (7.2.4) as the first frame: our
     * SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) and one reserved identifier (7.2.4.1 SHOULD).
     * QPACK_MAX_TABLE_CAPACITY / QPACK_BLOCKED_STREAMS are omitted: 0 is their default. */
    uint8_t pl[24];
    size_t n = 0, k;
    n += brisk__quic_varint_put(pl + n, 8, 0x06);
    n += brisk__quic_varint_put(pl + n, 8, H3_L);
    n += brisk__quic_varint_put(pl + n, 8, H3_GREASE);
    n += brisk__quic_varint_put(pl + n, 8, 0);
    if (cap < 3 + n) {
        return 0;
    }
    k = 0;
    out[k++] = 0x00;
    out[k++] = H3F_SETTINGS;
    out[k++] = (uint8_t)n; /* < 64: a one-octet varint */
    memcpy(out + k, pl, n);
    return k + n;
}

/* ------------------------------------------------------------------------------ errors */

/* 8: a connection error - CONNECTION_CLOSE with the code, sticky BRISK_E_PROTO */
static int h3_conn_err(brisk_h3 *h, uint64_t code)
{
    if (h->err == 0) {
        h->err = BRISK_E_PROTO;
        h->op->close(h->io, code);
    }
    return h->err;
}

/* 8: a stream error - abort the request both ways (4.1.1); the connection continues */
static void h3_stream_err(brisk_h3 *h, h3s *s, uint64_t code, int rc)
{
    if (s->err == 0) {
        s->err = rc;
    }
    if (!(s->flags & H3S_ABORT)) {
        s->flags |= H3S_ABORT;
        (void)h->op->abort(h->io, s->id, code, 3);
    }
}

/* The connection's own failure (the peer closed it, idle timeout) or ours */
static int h3_dead(brisk_h3 *h)
{
    return h->err != 0 ? h->err : h->op->status(h->io);
}

/* ------------------------------------------------------------------------- frame reading */

/* Read the frame header of stream id exactly (never past it). 1 = complete (fr->type, len);
 * else the read result: 0 = FIN, BRISK_E_WANT, BRISK_E_PEER_ALERT (*e), < 0. */
static int h3_fhdr(brisk_h3 *h, uint64_t id, h3_fr *fr, uint64_t *e)
{
    for (;;) {
        size_t need, n1, n2;
        int r;
        if (fr->fh_n == 0) {
            need = 1;
        } else {
            n1 = (size_t)1 << (fr->fh[0] >> 6); /* RFC 9000 16: the 2 MSBs give the length */
            if (fr->fh_n < n1) {
                need = n1 - fr->fh_n;
            } else if (fr->fh_n == n1) {
                need = 1;
            } else {
                n2 = (size_t)1 << (fr->fh[n1] >> 6);
                if (fr->fh_n < n1 + n2) {
                    need = n1 + n2 - fr->fh_n;
                } else {
                    const uint8_t *p = fr->fh;
                    (void)brisk__quic_varint_get(&p, fr->fh + n1, &fr->type);
                    (void)brisk__quic_varint_get(&p, fr->fh + n1 + n2, &fr->len);
                    fr->pos = 0;
                    fr->in = 1;
                    return 1;
                }
            }
        }
        r = h->op->read(h->io, id, fr->fh + fr->fh_n, need, e);
        if (r <= 0) {
            return r;
        }
        fr->fh_n = (uint8_t)(fr->fh_n + r);
    }
}

static void h3_fr_next(h3_fr *fr)
{
    fr->in = 0;
    fr->fh_n = 0;
}

/* 7.2.8: frame types reserved for HTTP/2 constructs without an HTTP/3 mapping */
static int h3_h2_type(uint64_t t)
{
    return t == 0x02 || t == 0x06 || t == 0x08 || t == 0x09;
}

/* --------------------------------------------------------------------------- control stream */

static int h3_settings_end(brisk_h3 *h, size_t len)
{
    const uint8_t *p = h->set, *end = h->set + len, *q;
    uint64_t id, v, id2, v2;
    while (p < end) {
        const uint8_t *at = p;
        /* 7.1: a setting cut in half is a frame whose payload does not match its length */
        if (!brisk__quic_varint_get(&p, end, &id) || !brisk__quic_varint_get(&p, end, &v)) {
            return h3_conn_err(h, H3E_FRAME);
        }
        /* 7.2.4.1 / 11.2.2: the HTTP/2 identifiers 0x00, 0x02-0x05 MUST be an error */
        if (id == 0x00 || (id >= 0x02 && id <= 0x05)) {
            return h3_conn_err(h, H3E_SETTINGS);
        }
        /* 7.2.4: the same identifier twice MAY be an error - taken (fail closed) */
        for (q = h->set; q < at;) {
            (void)brisk__quic_varint_get(&q, end, &id2);
            (void)brisk__quic_varint_get(&q, end, &v2);
            if (id2 == id) {
                return h3_conn_err(h, H3E_SETTINGS);
            }
        }
        if (id == 0x06) {
            h->p_list = v; /* SETTINGS_MAX_FIELD_SECTION_SIZE: bounds our requests (4.2.2) */
        }
        /* 0x01 QPACK_MAX_TABLE_CAPACITY, 0x07 QPACK_BLOCKED_STREAMS: our encoder never uses
         * the table, so both are recorded nowhere. Unknown identifiers MUST be ignored. */
    }
    return BRISK_OK;
}

/* 5.2 / 7.2.6 */
static int h3_goaway_end(brisk_h3 *h, size_t len)
{
    const uint8_t *p = h->gb;
    uint64_t id;
    unsigned i;
    if (!brisk__quic_varint_get(&p, h->gb + len, &id) || p != h->gb + len) {
        return h3_conn_err(h, H3E_FRAME); /* 7.1: not exactly one varint */
    }
    /* 7.2.6: a server's GOAWAY carries a client-initiated bidirectional stream id; 5.2: it MUST
     * NOT increase */
    if ((id & 3) != 0 || (h->goaway && id > h->goaway_id)) {
        return h3_conn_err(h, H3E_ID);
    }
    h->goaway = 1;
    h->goaway_id = id;
    for (i = 0; i < H3_NS; i++) {
        h3s *s = &h->s[i];
        /* 5.2: requests at or above it were not processed - safe to retry elsewhere */
        if (s->used && s->id >= id && s->state != H3R_END && s->err == 0) {
            s->err = BRISK_E_RETRY;
        }
    }
    return BRISK_OK;
}

/* A control-stream frame header is complete: every check that needs only the header. */
static int h3_ctl_start(brisk_h3 *h, const h3_fr *fr)
{
    if (++h->idle > H3_IDLE_MAX) {
        return h3_conn_err(h, H3E_EXCESSIVE_LOAD); /* control-frame flood */
    }
    /* 6.2.1: the first frame MUST be SETTINGS - whatever the other frame is */
    if (!h->got_settings && fr->type != H3F_SETTINGS) {
        return h3_conn_err(h, H3E_MISSING_SETTINGS);
    }
    switch (fr->type) {
    case H3F_SETTINGS:
        if (h->got_settings) {
            return h3_conn_err(h, H3E_FRAME_UNEXPECTED); /* 7.2.4: a second SETTINGS */
        }
        h->got_settings = 1;
        if (fr->len > H3_SET_MAX) {
            return h3_conn_err(h, H3E_EXCESSIVE_LOAD); /* our cap, before any buffering */
        }
        return BRISK_OK;
    case H3F_GOAWAY:
        return fr->len == 0 || fr->len > 8 ? h3_conn_err(h, H3E_FRAME) : BRISK_OK;
    case H3F_CANCEL:
        /* 7.2.3: a push ID we never allowed (no MAX_PUSH_ID) MUST be H3_ID_ERROR */
        return h3_conn_err(h, H3E_ID);
    case H3F_DATA:    /* 7.2.1 */
    case H3F_HEADERS: /* 7.2.2 */
    case H3F_PUSH:    /* 7.2.5: only on request streams */
    case H3F_MAXPUSH: /* 7.2.7: a server MUST NOT send it */
        return h3_conn_err(h, H3E_FRAME_UNEXPECTED);
    default:
        /* 7.2.8 reserved HTTP/2 types MUST be an error; 9: unknown types are ignored */
        return h3_h2_type(fr->type) ? h3_conn_err(h, H3E_FRAME_UNEXPECTED) : BRISK_OK;
    }
}

static int h3_ctl(brisk_h3 *h, h3_us *u)
{
    h3_fr *fr = &u->fr;
    uint64_t e;
    int r, rc;
    for (;;) {
        if (!fr->in) {
            r = h3_fhdr(h, u->id, fr, &e);
            if (r == BRISK_E_WANT) {
                return BRISK_OK;
            }
            if (r == 0 || r == BRISK_E_PEER_ALERT) {
                return h3_conn_err(h, H3E_CLOSED_CRITICAL); /* 6.2.1 MUST */
            }
            if (r < 0) {
                return r;
            }
            if ((rc = h3_ctl_start(h, fr)) != BRISK_OK) {
                return rc;
            }
        }
        if (fr->pos < fr->len) {
            uint64_t rem = fr->len - fr->pos;
            uint8_t *dst = fr->type == H3F_SETTINGS ? h->set + fr->pos
                           : fr->type == H3F_GOAWAY ? h->gb + fr->pos
                                                    : h->scratch; /* unknown: dropped */
            size_t k = rem < H3_L ? (size_t)rem : H3_L;
            r = h->op->read(h->io, u->id, dst, k, &e);
            if (r == BRISK_E_WANT) {
                return BRISK_OK;
            }
            if (r == 0 || r == BRISK_E_PEER_ALERT) {
                return h3_conn_err(h, H3E_CLOSED_CRITICAL);
            }
            if (r < 0) {
                return r;
            }
            fr->pos += (uint64_t)r;
            continue;
        }
        if (fr->type == H3F_SETTINGS) {
            rc = h3_settings_end(h, (size_t)fr->len);
        } else if (fr->type == H3F_GOAWAY) {
            rc = h3_goaway_end(h, (size_t)fr->len);
        } else {
            rc = BRISK_OK;
        }
        h3_fr_next(fr);
        if (rc != BRISK_OK) {
            return rc;
        }
    }
}

/* ------------------------------------------------------------------ unidirectional streams */

static int h3_uni_one(brisk_h3 *h, unsigned i)
{
    h3_us *u = &h->uni[i];
    uint64_t e, used64;
    size_t used;
    int r;
    for (;;) {
        if (u->kind == H3U_NEW) {
            size_t need = u->tn == 0 ? 1 : ((size_t)1 << (u->tb[0] >> 6)) - u->tn;
            if (need != 0) {
                r = h->op->read(h->io, u->id, u->tb + u->tn, need, &e);
                if (r == BRISK_E_WANT) {
                    return BRISK_OK;
                }
                if (r <= 0) {
                    h->used[i] = 0; /* 6.2: ended before its type - tolerated (MUST) */
                    return r == 0 || r == BRISK_E_PEER_ALERT ? BRISK_OK : r;
                }
                u->tn = (uint8_t)(u->tn + r);
                continue;
            }
            {
                const uint8_t *p = u->tb;
                uint64_t t;
                (void)brisk__quic_varint_get(&p, u->tb + u->tn, &t);
                switch (t) {
                case 0x00: /* 6.2.1: one control stream */
                    if (h->got_ctl) {
                        return h3_conn_err(h, H3E_STREAM_CREATION);
                    }
                    h->got_ctl = 1;
                    u->kind = H3U_CTL;
                    break;
                case 0x01: /* 6.2.2: push stream - we never sent MAX_PUSH_ID */
                    return h3_conn_err(h, H3E_ID);
                case 0x02: /* RFC 9204 4.2: one encoder, one decoder stream */
                    if (h->got_enc) {
                        return h3_conn_err(h, H3E_STREAM_CREATION);
                    }
                    h->got_enc = 1;
                    u->kind = H3U_ENC;
                    break;
                case 0x03:
                    if (h->got_dec) {
                        return h3_conn_err(h, H3E_STREAM_CREATION);
                    }
                    h->got_dec = 1;
                    u->kind = H3U_DEC;
                    break;
                default: /* 6.2 / 6.2.3: unknown and reserved types are not errors */
                    u->kind = H3U_SKIP;
                    break;
                }
            }
            continue;
        }
        if (u->kind == H3U_CTL) {
            return h3_ctl(h, u);
        }
        if (u->kind == H3U_DEC) {
            r = h->op->read(h->io, u->id, h->qd + h->qd_n, sizeof h->qd - h->qd_n, &e);
        } else {
            r = h->op->read(h->io, u->id, h->scratch, u->kind == H3U_ENC ? 256 : H3_L, &e);
        }
        if (r == BRISK_E_WANT) {
            return BRISK_OK;
        }
        if (r == 0 || r == BRISK_E_PEER_ALERT) {
            if (u->kind != H3U_SKIP) {
                /* RFC 9204 4.2: closing either QPACK stream MUST be H3_CLOSED_CRITICAL_STREAM */
                return h3_conn_err(h, H3E_CLOSED_CRITICAL);
            }
            h->used[i] = 0;
            return BRISK_OK;
        }
        if (r < 0) {
            return r;
        }
        if (u->kind == H3U_ENC) {
            if (brisk__qpack_enc_stream(h->scratch, (size_t)r, &used, &used64) != BRISK_OK) {
                return h3_conn_err(h, used64);
            }
        } else if (u->kind == H3U_DEC) {
            h->qd_n = (uint8_t)(h->qd_n + r);
            if (brisk__qpack_dec_stream(h->qd, h->qd_n, &used, &used64) != BRISK_OK) {
                return h3_conn_err(h, used64);
            }
            memmove(h->qd, h->qd + used, h->qd_n - used); /* a partial instruction (< 11) */
            h->qd_n = (uint8_t)(h->qd_n - used);
        }
    }
}

/* Serve the server's unidirectional streams: take new ones, read what is readable. */
static int h3_uni(brisk_h3 *h)
{
    uint64_t id;
    unsigned i;
    int rc = h3_dead(h);
    if (rc != 0) {
        return rc;
    }
    /* 6.2.1 MUST: a STOP_SENDING on our control stream closes it - a zero-length write probe
     * (sends nothing) fails once QUIC reset it (ST_STOP) or freed the slot (reset acked).
     * ctl_id 0 = not opened yet (client uni ids are 2 mod 4). */
    if (h->ctl_id != 0 && h->op->write(h->io, h->ctl_id, NULL, 0, 0) < 0) {
        return h3_conn_err(h, H3E_CLOSED_CRITICAL);
    }
    while (h->op->accept(h->io, &id) == BRISK_OK) {
        if ((id & 3) != 3) {
            continue; /* 6.1: server bidi streams never get credit (QUIC refuses them) */
        }
        for (i = 0; i < H3_UNI && h->used[i]; i++) {
        }
        if (i == H3_UNI) {
            return h3_conn_err(h, H3E_EXCESSIVE_LOAD); /* beyond the 3 our credit allows */
        }
        memset(&h->uni[i], 0, sizeof h->uni[i]);
        h->uni[i].id = id;
        h->uni[i].kind = H3U_NEW;
        h->used[i] = 1;
    }
    for (i = 0; i < H3_UNI; i++) {
        if (h->used[i] && (rc = h3_uni_one(h, i)) != BRISK_OK) {
            return rc;
        }
    }
    return h->err;
}

/* ------------------------------------------------------------------------ request streams */

/* The QPACK callback: RFC 9114 4.2 / 4.3.2 checks on every field of a response section, and
 * parking of the final response's fields. Never aborts: a violation marks the section
 * malformed (4.1.2) and the rest is still decoded (QPACK errors are connection errors). */
static int h3_on_field(void *ctx, const uint8_t *name, size_t nl, const uint8_t *value, size_t vl,
                       unsigned flags)
{
    brisk_h3 *h = (brisk_h3 *)ctx;
    (void)flags;
    if (h->b_bad) {
        return 0;
    }
    /* 4.2: uppercase and invalid octets (RFC 9113 8.2.1 rules, as brisk_h2) */
    if (!brisk__hpack_field_ok(name, nl, value, vl)) {
        h->b_bad = 1;
        return 0;
    }
    if (name[0] == ':') {
        /* 4.3: exactly one :status in a response, before every regular field; none in
         * trailers; request pseudo-headers are malformed (4.3.2); no 101 (4.5) */
        if (h->b_trailer || h->b_seen || h->b_reg || nl != 7 || memcmp(name, ":status", 7) != 0 ||
            brisk__http_status(value, vl) == 0) {
            h->b_bad = 1;
            return 0;
        }
        h->b_seen = 1;
        h->b_status = (uint16_t)brisk__http_status(value, vl);
        h->b_park = h->b_status >= 200;
        return 0;
    }
    /* pseudo-headers first (4.3); 4.2: connection-specific fields (te: requests only); 4.1:
     * transfer-encoding */
    if ((!h->b_trailer && !h->b_seen) || brisk__http_conn_specific(name, nl) ||
        (nl == 2 && memcmp(name, "te", 2) == 0)) {
        h->b_bad = 1;
        return 0;
    }
    h->b_reg = 1;
    if (!h->b_park) {
        return 0; /* interim 1xx and trailers: validated, discarded */
    }
    if (nl == 14 && memcmp(name, "content-length", 14) == 0) {
        uint64_t v;
        if (!brisk__http_cl_parse(value, vl, &v) || (h->b_has_cl && v != h->b_cl)) {
            h->b_bad = 1; /* RFC 9110 8.6: identical duplicates only */
            return 0;
        }
        h->b_cl = v;
        h->b_has_cl = 1;
    }
    /* [u16 nl][u16 vl][name][value]: n + v + 4 <= n + v + 32, so the section limit bounds it */
    if (nl + vl + 4 > H3_L - h->plen) {
        h->b_bad = 1; /* unreachable: max_list = H3_L */
        return 0;
    }
    brisk__store_be16(h->park + h->plen, (uint32_t)nl);
    brisk__store_be16(h->park + h->plen + 2, (uint32_t)vl);
    memcpy(h->park + h->plen + 4, name, nl);
    memcpy(h->park + h->plen + 4 + nl, value, vl);
    h->plen += nl + vl + 4;
    return 0;
}

/* A complete HEADERS frame on request stream s: decoded (always - QPACK errors are the
 * connection's), then judged as a response (4.1) or trailer section. */
static int h3_block(brisk_h3 *h, h3s *s)
{
    int rc;
    h->b_bad = h->b_seen = h->b_reg = h->b_park = h->b_has_cl = 0;
    h->b_trailer = s->state == H3R_BODY;
    h->b_status = 0;
    h->b_cl = 0;
    h->plen = 0;
    rc = brisk__qpack_decode(s->buf, s->blen, h->scratch, H3_L, H3_L, h3_on_field, h);
    s->blen = 0;
    if (rc == BRISK_E_PROTO) {
        return h3_conn_err(h, BRISK__QPACK_DECOMPRESSION_FAILED); /* RFC 9204 2.2 / 4.5 */
    }
    if (rc != BRISK_OK) {
        /* 4.2.2: a section over our SETTINGS_MAX_FIELD_SECTION_SIZE - "can discard" it */
        h3_stream_err(h, s, H3E_EXCESSIVE_LOAD, BRISK_E_PROTO);
        return BRISK_OK;
    }
    if (h->b_trailer) {
        if (h->b_bad) {
            h3_stream_err(h, s, H3E_MESSAGE, BRISK_E_PROTO); /* 4.1.2 */
        } else {
            s->state = H3R_TRAIL; /* 4.1: trailers - validated, discarded */
        }
        return BRISK_OK;
    }
    s->flags |= H3S_SEEN;
    if (h->b_bad || !h->b_seen) {
        h3_stream_err(h, s, H3E_MESSAGE, BRISK_E_PROTO); /* 4.1.2 / 4.3.2 */
        return BRISK_OK;
    }
    if (h->b_status < 200) {
        if (++s->n1xx > H3_1XX_MAX) {
            return h3_conn_err(h, H3E_EXCESSIVE_LOAD); /* a local cap (RFC 9114 10.5) */
        }
        return BRISK_OK; /* 4.1: interim - discarded */
    }
    memcpy(s->buf, h->park, h->plen);
    s->blen = s->hdr = h->plen;
    s->status = h->b_status;
    s->state = H3R_BODY;
    if (h->b_has_cl) {
        s->flags |= H3S_CL;
        s->cl = h->b_cl;
    }
    if (s->status == 204 || s->status == 304 || (s->flags & H3S_HEAD)) {
        s->flags |= H3S_NOCL; /* 4.1.2: "defined as never having content" */
    }
    h->idle = 0;
    return BRISK_OK;
}

/* A request-stream frame header is complete. */
static int h3_rs_start(brisk_h3 *h, h3s *s)
{
    const h3_fr *fr = &s->fr;
    if (++h->idle > H3_IDLE_MAX) {
        return h3_conn_err(h, H3E_EXCESSIVE_LOAD);
    }
    switch (fr->type) {
    case H3F_DATA:
        if (s->state == H3R_TRAIL || (s->state == H3R_HDR && !(s->flags & H3S_SEEN))) {
            return h3_conn_err(h, H3E_FRAME_UNEXPECTED); /* 4.1 MUST: before HEADERS / after
                                                            trailers */
        }
        if (s->state == H3R_HDR) {
            h3_stream_err(h, s, H3E_MESSAGE, BRISK_E_PROTO); /* 4.1: content after a 1xx */
            return BRISK_OK;
        }
        s->got += fr->len;
        if ((s->flags & (H3S_CL | H3S_NOCL)) == H3S_CL && s->got > s->cl) {
            h3_stream_err(h, s, H3E_MESSAGE, BRISK_E_PROTO); /* 4.1.2 content-length */
        }
        return BRISK_OK;
    case H3F_HEADERS:
        if (s->state == H3R_TRAIL) {
            return h3_conn_err(h, H3E_FRAME_UNEXPECTED); /* 4.1 MUST */
        }
        if (fr->len > H3_L) {
            /* 4.2.2: larger than we could decode - dropped without buffering (a local limit,
             * so not H3_FRAME_ERROR) */
            h3_stream_err(h, s, H3E_EXCESSIVE_LOAD, BRISK_E_PROTO);
        }
        s->blen = 0;
        return BRISK_OK;
    case H3F_PUSH:
        return h3_conn_err(h, H3E_ID); /* 7.2.5: a push ID above our (never sent) maximum */
    case H3F_CANCEL:                   /* 7.2.3 */
    case H3F_SETTINGS:                 /* 7.2.4 */
    case H3F_GOAWAY:                   /* 7.2.6 */
    case H3F_MAXPUSH:                  /* 7.2.7 */
        return h3_conn_err(h, H3E_FRAME_UNEXPECTED);
    default:
        return h3_h2_type(fr->type) ? h3_conn_err(h, H3E_FRAME_UNEXPECTED) : BRISK_OK;
    }
}

/* The server reset the request stream (RFC 9000 19.4); the QUIC slot is done. */
static void h3_rs_reset(h3s *s, uint64_t code)
{
    s->flags |= H3S_ABORT;
    if (s->state == H3R_END || s->err != 0) {
        return;
    }
    /* 4.1.1: REJECTED = not processed, safe to retry; anything else (unknown codes are
     * H3_NO_ERROR, 9) ends the request */
    s->err = code == H3E_REQUEST_REJECTED ? BRISK_E_RETRY : BRISK_E_PEER_ALERT;
}

/* 1 when the caller's condition holds: final fields (headers) / DATA payload ready (data) */
static int h3_rs_ready(const h3s *s, int data)
{
    if (s->err != 0 || s->state == H3R_END) {
        return 1;
    }
    if (!data) {
        return s->state != H3R_HDR;
    }
    return s->fr.in && s->fr.type == H3F_DATA && s->fr.pos < s->fr.len;
}

/* Advance request stream s until the condition holds or nothing more is readable now. */
static int h3_rs(brisk_h3 *h, h3s *s, int data)
{
    h3_fr *fr = &s->fr;
    uint64_t e;
    int r, rc;
    while (!h3_rs_ready(s, data)) {
        if (s->flags & H3S_ABORT) {
            return BRISK_OK; /* aborted: nothing is read any more (s->err is set) */
        }
        if (!fr->in) {
            r = h3_fhdr(h, s->id, fr, &e);
            if (r == BRISK_E_WANT) {
                return BRISK_OK;
            }
            if (r == BRISK_E_PEER_ALERT) {
                h3_rs_reset(s, e);
                return BRISK_OK;
            }
            if (r == 0) {
                if (fr->fh_n != 0) {
                    return h3_conn_err(h, H3E_FRAME); /* 7.1: a truncated last frame */
                }
                if (s->state == H3R_HDR ||
                    ((s->flags & (H3S_CL | H3S_NOCL)) == H3S_CL && s->got != s->cl)) {
                    /* 4.1: no final response; 4.1.2: content-length not matched */
                    h3_stream_err(h, s, H3E_MESSAGE, BRISK_E_PROTO);
                    return BRISK_OK;
                }
                s->state = H3R_END;
                return BRISK_OK;
            }
            if (r < 0) {
                return r;
            }
            if ((rc = h3_rs_start(h, s)) != BRISK_OK) {
                return rc;
            }
            continue;
        }
        if (fr->pos < fr->len) {
            uint64_t rem = fr->len - fr->pos;
            uint8_t *dst;
            size_t k;
            if (fr->type == H3F_DATA) {
                return BRISK_OK; /* data: the payload is the caller's (h3_rs_ready) */
            }
            if (fr->type == H3F_HEADERS) {
                dst = s->buf + s->blen;
                k = (size_t)rem; /* <= H3_L - blen: checked at the frame start */
            } else {
                dst = h->scratch; /* unknown / reserved types: dropped (9) */
                k = rem < H3_L ? (size_t)rem : H3_L;
            }
            r = h->op->read(h->io, s->id, dst, k, &e);
            if (r == BRISK_E_WANT) {
                return BRISK_OK;
            }
            if (r == BRISK_E_PEER_ALERT) {
                h3_rs_reset(s, e);
                return BRISK_OK;
            }
            if (r == 0) {
                return h3_conn_err(h, H3E_FRAME); /* 7.1: a truncated last frame */
            }
            if (r < 0) {
                return r;
            }
            fr->pos += (uint64_t)r;
            if (fr->type == H3F_HEADERS) {
                s->blen += (size_t)r;
            }
            continue;
        }
        h3_fr_next(fr); /* a frame is complete */
        if (fr->type == H3F_HEADERS && (rc = h3_block(h, s)) != BRISK_OK) {
            return rc;
        }
    }
    return BRISK_OK;
}

/* Serve the connection and advance s (may be NULL) until its condition holds, the handle
 * fails, or the wait times out (harmless). */
static int h3_wait(brisk_h3 *h, h3s *s, int data)
{
    int rc;
    for (;;) {
        if ((rc = h3_uni(h)) != BRISK_OK) {
            return rc;
        }
        if (s != NULL) {
            if ((rc = h3_rs(h, s, data)) != BRISK_OK) {
                return rc;
            }
            if (h3_rs_ready(s, data)) {
                return BRISK_OK;
            }
        }
        if ((rc = h->op->wait(h->io)) != BRISK_OK) {
            return rc;
        }
    }
}

/* ------------------------------------------------------------------------------ public API */

int brisk__h3_setup(void *mem, size_t mem_len, const char *authority, size_t auth_len,
                    const brisk__h3_io *ops, void *io, brisk_h3 **out)
{
    uint8_t *m = (uint8_t *)mem;
    brisk_h3 *h;
    unsigned i;
    if (out != NULL) {
        *out = NULL;
    }
    if (mem == NULL || out == NULL || authority == NULL || ops == NULL ||
        mem_len < brisk_h3_size() || auth_len == 0 || auth_len >= sizeof h->auth ||
        !brisk__hpack_field_ok((const uint8_t *)":authority", 10, (const uint8_t *)authority,
                               auth_len)) {
        return BRISK_E_ARG;
    }
    m += (H3_ALIGN - ((uintptr_t)m & (H3_ALIGN - 1))) & (H3_ALIGN - 1);
    h = (brisk_h3 *)(void *)m;
    memset(h, 0, sizeof *h);
    m += sizeof *h;
    h->mem = (uint8_t *)mem;
    h->mem_len = mem_len;
    h->op = ops;
    h->io = io;
    h->scratch = m;
    h->park = m + H3_L;
    m += 2 * H3_L;
    for (i = 0; i < H3_NS; i++) {
        h->s[i].h = h;
        h->s[i].buf = m + (size_t)i * H3_L;
    }
    memcpy(h->auth, authority, auth_len);
    h->auth_len = (uint16_t)auth_len;
    h->p_list = UINT64_MAX; /* 7.2.4.1: unlimited until the server says otherwise */
    *out = h;
    return BRISK_OK;
}

/* Write all n octets (fin after the last), serving the connection while the stream's buffer
 * is full. *stopped = the server sent STOP_SENDING (the rest is not sent). */
static int h3_send(brisk_h3 *h, uint64_t id, const uint8_t *p, size_t n, int fin, int *stopped)
{
    size_t done = 0;
    int r, rc;
    for (;;) {
        r = h->op->write(h->io, id, p + done, n - done, fin);
        if (r == BRISK_E_PEER_ALERT && stopped != NULL) {
            *stopped = 1;
            return BRISK_OK;
        }
        if (r < 0) {
            rc = h3_dead(h);
            return rc != 0 ? rc : r;
        }
        done += (size_t)r;
        if (done == n) {
            return BRISK_OK;
        }
        if (r > 0) {
            h->op->start(h->io); /* progress restarts the stall clock */
        }
        if ((rc = h3_uni(h)) != BRISK_OK || (rc = h->op->wait(h->io)) != BRISK_OK) {
            return rc;
        }
    }
}

int brisk__h3_start(brisk_h3 *h)
{
    uint8_t pre[24];
    size_t n;
    int64_t id;
    int rc;
    if (h == NULL) {
        return BRISK_E_ARG;
    }
    h->op->start(h->io);
    h->idle = 0;
    /* 6.2.1 MUST: our control stream, opened "as soon as the transport is ready" (7.2.4.2) */
    for (;;) {
        if ((rc = h3_dead(h)) != 0) {
            return rc;
        }
        id = h->op->open(h->io, 0);
        if (id >= 0) {
            break;
        }
        if (id != BRISK_E_WANT) {
            return (int)id;
        }
        if ((rc = h3_uni(h)) != BRISK_OK || (rc = h->op->wait(h->io)) != BRISK_OK) {
            return rc;
        }
    }
    h->ctl_id = (uint64_t)id;
    n = brisk__h3_settings(pre, sizeof pre);
    if ((rc = h3_send(h, h->ctl_id, pre, n, 0, NULL)) != BRISK_OK) {
        /* 6.2.1: a STOP_SENDING on our control stream is a closed critical stream */
        return rc == BRISK_E_PEER_ALERT ? h3_conn_err(h, H3E_CLOSED_CRITICAL) : rc;
    }
    return h3_uni(h); /* what already arrived; 7.2.4.2: no wait for the server's SETTINGS */
}

/* Release a slot: cancel (4.1.1) what is still open, wipe the buffer. */
static void h3_release(h3s *s)
{
    brisk_h3 *h = s->h;
    uint8_t *buf = s->buf;
    if (h3_dead(h) == 0 && !(s->flags & H3S_ABORT) &&
        !(s->state == H3R_END && (s->flags & H3S_SENT))) {
        (void)h->op->abort(h->io, s->id, H3E_REQUEST_CANCELED, 3); /* 4.1.1 SHOULD */
    }
    brisk__secure_zero(buf, H3_L);
    memset(s, 0, sizeof *s);
    s->h = h;
    s->buf = buf;
}

/* One request field into buf at *pos (the HEADERS payload). BRISK_E_ARG when it does not fit. */
static int h3_field(uint8_t *buf, size_t cap, size_t *pos, const char *n, size_t nl, const char *v,
                    size_t vl, unsigned flags)
{
    brisk__hpack_field f;
    size_t k;
    f.name = (const uint8_t *)n;
    f.name_len = nl;
    f.value = (const uint8_t *)v;
    f.value_len = vl;
    f.flags = flags;
    if (brisk__qpack_encode_field(&f, buf + *pos, cap - *pos, &k) != BRISK_OK) {
        return BRISK_E_ARG;
    }
    *pos += k;
    return BRISK_OK;
}

int brisk_h3_request(brisk_h3 *h, const char *method, const char *path, const brisk_h2_header *hdrs,
                     size_t n, const void *body, size_t body_len, brisk_h3_stream **out)
{
    uint8_t *buf, dh[9];
    uint64_t list;
    size_t i, pos = 9 + 2, hl, dl;
    int64_t id;
    int rc, stopped = 0;
    h3s *s = NULL;

    if (out != NULL) {
        *out = NULL;
    }
    if (h == NULL || method == NULL || path == NULL || (hdrs == NULL && n) ||
        (body == NULL && body_len) || out == NULL) {
        return BRISK_E_ARG;
    }
    /* serve the control stream first: a GOAWAY may sit unparsed in its ring (5.2) */
    if ((rc = h3_uni(h)) != 0) {
        return rc;
    }
    if (h->goaway) {
        return BRISK_E_RETRY; /* 5.2 MUST NOT: no new request after GOAWAY - never sent */
    }
    if (brisk__http_req_check(method, path, hdrs, n, body_len, h->auth_len, H3_L, &list) !=
            BRISK_OK ||
        list > h->p_list) { /* 4.2.2: the server's SETTINGS_MAX_FIELD_SECTION_SIZE */
        return BRISK_E_ARG;
    }
    for (i = 0; i < H3_NS && s == NULL; i++) {
        if (!h->s[i].used) {
            s = &h->s[i];
        }
    }
    if (s == NULL) {
        return BRISK_E_ARG; /* every slot held: close one first */
    }
    /* 4.3.1 + RFC 9204 4.5: the section after room for the frame header, prefix 00 00 */
    buf = s->buf;
    buf[9] = 0x00;
    buf[10] = 0x00;
    if (h3_field(buf, H3_L, &pos, ":method", 7, method, strlen(method), 0) ||
        h3_field(buf, H3_L, &pos, ":scheme", 7, "https", 5, 0) ||
        h3_field(buf, H3_L, &pos, ":authority", 10, h->auth, h->auth_len, 0) ||
        h3_field(buf, H3_L, &pos, ":path", 5, path, strlen(path), 0)) {
        brisk__secure_zero(buf, H3_L);
        return BRISK_E_ARG;
    }
    for (i = 0; i < n; i++) {
        const char *nm = hdrs[i].name;
        if (h3_field(buf, H3_L, &pos, nm, strlen(nm), hdrs[i].value, strlen(hdrs[i].value),
                     brisk__http_sensitive(nm))) { /* RFC 9204 7.1.3: the N bit */
            brisk__secure_zero(buf, H3_L);
            return BRISK_E_ARG; /* our encoded section over BRISK_H3_MAX_HEADER_LIST */
        }
    }
    /* 7.2.2 HEADERS: type, length, then the section, written just before it */
    hl = 1 + brisk__quic_varint_put(NULL, 0, pos - 9);
    buf[9 - hl] = H3F_HEADERS;
    (void)brisk__quic_varint_put(buf + 10 - hl, 8, pos - 9);

    h->op->start(h->io);
    h->idle = 0;
    for (;;) { /* a bidirectional stream: RFC 9000 4.6 credit and a free slot */
        id = h->op->open(h->io, 1);
        if (id >= 0) {
            break;
        }
        if (id != BRISK_E_WANT) {
            rc = h3_dead(h);
            brisk__secure_zero(buf, H3_L);
            return rc != 0 ? rc : (int)id;
        }
        if ((rc = h3_uni(h)) != BRISK_OK || (rc = h->op->wait(h->io)) != BRISK_OK) {
            brisk__secure_zero(buf, H3_L);
            return rc;
        }
        if (h->goaway) {
            brisk__secure_zero(buf, H3_L);
            return BRISK_E_RETRY;
        }
    }
    s->used = 1;
    s->id = (uint64_t)id;
    s->state = H3R_HDR;
    s->flags = strcmp(method, "HEAD") == 0 ? H3S_HEAD : 0;
    /* 4.1: one request, then FIN */
    rc = h3_send(h, s->id, buf + 9 - hl, pos - 9 + hl, body_len == 0, &stopped);
    if (rc == BRISK_OK && body_len != 0 && !stopped) {
        dh[0] = H3F_DATA; /* 7.2.1: the whole body as one DATA frame */
        dl = 1 + brisk__quic_varint_put(dh + 1, 8, body_len);
        rc = h3_send(h, s->id, dh, dl, 0, &stopped);
        if (rc == BRISK_OK && !stopped) {
            rc = h3_send(h, s->id, (const uint8_t *)body, body_len, 1, &stopped);
        }
    }
    s->blen = 0;
    brisk__secure_zero(buf, H3_L); /* the section (credentials) is in QUIC's buffer now */
    if (rc != BRISK_OK) {
        h3_release(s);
        return rc;
    }
    s->flags |= H3S_SENT; /* FIN written, or the server stopped the upload (4.1) */
    *out = s;
    return BRISK_OK;
}

int brisk_h3_response(brisk_h3_stream *s, int *status, brisk_h2_header_fn fn, void *ctx)
{
    brisk_h3 *h;
    size_t p = 0;
    int rc;
    if (status != NULL) {
        *status = 0;
    }
    if (s == NULL || status == NULL || !s->used || (s->flags & H3S_RESP)) {
        return BRISK_E_ARG;
    }
    h = s->h;
    h->op->start(h->io);
    h->idle = 0;
    if ((rc = h3_wait(h, s, 0)) != BRISK_OK) {
        return rc;
    }
    if (s->err != 0) {
        return s->err;
    }
    while (p < s->hdr) { /* replay the parked fields as NUL-terminated copies */
        size_t nl = brisk__load_be16(s->buf + p), vl = brisk__load_be16(s->buf + p + 2);
        memcpy(h->scratch, s->buf + p + 4, nl);
        h->scratch[nl] = 0;
        memcpy(h->scratch + nl + 1, s->buf + p + 4 + nl, vl);
        h->scratch[nl + 1 + vl] = 0;
        p += 4 + nl + vl;
        if (fn != NULL) {
            fn(ctx, (const char *)h->scratch, nl, (const char *)h->scratch + nl + 1, vl);
        }
    }
    brisk__secure_zero(s->buf, s->hdr);
    s->hdr = s->blen = 0;
    s->flags |= H3S_RESP;
    *status = s->status;
    return BRISK_OK;
}

int brisk_h3_read(brisk_h3_stream *s, void *buf, size_t cap)
{
    brisk_h3 *h;
    uint64_t e;
    int r, rc;
    if (s == NULL || buf == NULL || cap == 0 || !s->used || !(s->flags & H3S_RESP)) {
        return BRISK_E_ARG;
    }
    h = s->h;
    h->op->start(h->io);
    h->idle = 0;
    for (;;) {
        if ((rc = h3_wait(h, s, 1)) != BRISK_OK) {
            return rc;
        }
        if (s->err != 0) {
            return s->err;
        }
        if (s->state == H3R_END) {
            return 0; /* FIN, content-length matched */
        }
        {
            uint64_t rem = s->fr.len - s->fr.pos;
            size_t k = cap < INT_MAX ? cap : INT_MAX;
            k = rem < k ? (size_t)rem : k;
            r = h->op->read(h->io, s->id, (uint8_t *)buf, k, &e);
        }
        if (r > 0) {
            s->fr.pos += (uint64_t)r;
            h->idle = 0;
            return r;
        }
        if (r == BRISK_E_PEER_ALERT) {
            h3_rs_reset(s, e);
            return s->err;
        }
        if (r == 0) {
            return h3_conn_err(h, H3E_FRAME); /* 7.1: FIN inside a DATA frame */
        }
        if (r != BRISK_E_WANT) {
            rc = h3_dead(h);
            return rc != 0 ? rc : r;
        }
        if ((rc = h->op->wait(h->io)) != BRISK_OK) {
            return rc;
        }
    }
}

void brisk_h3_stream_close(brisk_h3_stream *s)
{
    if (s != NULL && s->used) {
        h3_release(s);
    }
}

void brisk_h3_close(brisk_h3 *h)
{
    if (h != NULL) {
        /* our control stream stays open with the connection (6.2.1: never closed) */
        brisk__secure_zero(h->mem, h->mem_len);
    }
}

/* ------------------------------------------------------------- over brisk_quic (production) */

static int h3q_read(void *io, uint64_t id, uint8_t *buf, size_t cap, uint64_t *app_err)
{
    brisk_quic *q = (brisk_quic *)io;
    int r = brisk__quic_stream_read(&q->q, id, buf, cap < INT_MAX ? cap : INT_MAX, app_err);
    if (r >= 0) {
        q->owe = 1; /* MAX_STREAM_DATA / MAX_DATA / MAX_STREAMS may be owed */
    }
    return r;
}

static int h3q_write(void *io, uint64_t id, const uint8_t *buf, size_t n, int fin)
{
    brisk_quic *q = (brisk_quic *)io;
    int r;
    if (n > INT_MAX) {
        n = INT_MAX; /* the FIN waits for the rest */
        fin = 0;
    }
    r = brisk__quic_stream_write(&q->q, id, buf, n, fin);
    if (r >= 0) {
        q->owe = 1;
    }
    return r;
}

static int64_t h3q_open(void *io, int bidi)
{
    return brisk__quic_stream_open(&((brisk_quic *)io)->q, bidi);
}

static int h3q_accept(void *io, uint64_t *id)
{
    return brisk__quic_stream_accept(&((brisk_quic *)io)->q, id);
}

static void h3q_start(void *io)
{
    brisk_quic *q = (brisk_quic *)io;
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_START);
    }
}

static int h3q_wait(void *io)
{
    return brisk__quic_wait((brisk_quic *)io);
}

static int h3q_abort(void *io, uint64_t id, uint64_t app_err, unsigned dirs)
{
    brisk_quic *q = (brisk_quic *)io;
    q->owe = 1;
    return brisk__quic_stream_abort(&q->q, id, app_err, dirs);
}

static void h3q_close(void *io, uint64_t app_err)
{
    brisk_quic *q = (brisk_quic *)io;
    /* RFC 9114 8 / RFC 9000 10.2: CONNECTION_CLOSE 0x1d with the H3 / QPACK code; the handle
     * reports BRISK_E_PROTO (the peer broke the protocol), brisk_quic_error() the code */
    if (brisk__quic_close(&q->q, app_err) == BRISK_OK) {
        q->q.err = BRISK_E_PROTO;
    }
    q->owe = 1;
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_FLUSH);
    }
}

static int h3q_status(void *io)
{
    return ((brisk_quic *)io)->q.err;
}

static const brisk__h3_io h3q_ops = {h3q_read, h3q_write, h3q_open,  h3q_accept, h3q_start,
                                     h3q_wait, h3q_abort, h3q_close, h3q_status};

int brisk_h3_open(brisk_quic *q, void *mem, size_t mem_len, brisk_h3 **out)
{
    char auth[264];
    const char *alpn;
    size_t alen, n;
    brisk_h3 *h;
    int rc;
    if (out != NULL) {
        *out = NULL;
    }
    if (q == NULL || mem == NULL || out == NULL || q->io == NULL) {
        return BRISK_E_ARG; /* a sans-I/O handle has no wait to block in */
    }
    /* RFC 9114 3.1: "h3" is the ALPN token - no protocol switching here */
    if (brisk_quic_alpn(q, &alpn, &alen) != BRISK_OK || alen != 2 || memcmp(alpn, "h3", 2) != 0) {
        return BRISK_E_ARG;
    }
    n = brisk__http_authority(q->c.host, q->c.host_len, q->c.port, auth); /* 3.3 / 4.3.1 */
    rc = brisk__h3_setup(mem, mem_len, auth, n, &h3q_ops, q, &h);
    if (rc == BRISK_OK) {
        rc = brisk__h3_start(h);
        if (rc != BRISK_OK) {
            brisk_h3_close(h);
            return rc;
        }
        *out = h;
    }
    return rc;
}

#    undef H3_L
#    undef H3_NS
#    undef H3_UNI
#    undef H3_SET_MAX
#    undef H3_IDLE_MAX
#    undef H3_1XX_MAX
#    undef H3_GREASE
#    undef H3F_DATA
#    undef H3F_HEADERS
#    undef H3F_CANCEL
#    undef H3F_SETTINGS
#    undef H3F_PUSH
#    undef H3F_GOAWAY
#    undef H3F_MAXPUSH
#    undef H3E_NO_ERROR
#    undef H3E_STREAM_CREATION
#    undef H3E_CLOSED_CRITICAL
#    undef H3E_FRAME_UNEXPECTED
#    undef H3E_FRAME
#    undef H3E_EXCESSIVE_LOAD
#    undef H3E_ID
#    undef H3E_SETTINGS
#    undef H3E_MISSING_SETTINGS
#    undef H3E_REQUEST_REJECTED
#    undef H3E_REQUEST_CANCELED
#    undef H3E_MESSAGE
#    undef H3U_NEW
#    undef H3U_CTL
#    undef H3U_ENC
#    undef H3U_DEC
#    undef H3U_SKIP
#    undef H3R_HDR
#    undef H3R_BODY
#    undef H3R_TRAIL
#    undef H3R_END
#    undef H3S_HEAD
#    undef H3S_CL
#    undef H3S_NOCL
#    undef H3S_RESP
#    undef H3S_SENT
#    undef H3S_ABORT
#    undef H3S_SEEN
#    undef H3_ALIGN

#endif /* BRISK_ENABLE_H3 */
