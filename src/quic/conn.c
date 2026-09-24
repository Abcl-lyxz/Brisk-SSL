/* conn.c - QUIC v1 client connection up to a confirmed handshake (RFC 9000, RFC 9001): transport
 * parameters (RFC 9000 18), frames (12.4, 19), CRYPTO streams per encryption level on the one
 * TLS 1.3 engine (RFC 9001 4), packet number spaces (RFC 9000 12.3), key discard (RFC 9001 4.9)
 * and CONNECTION_CLOSE (RFC 9000 10.2.3). Sans-I/O: datagrams in, datagrams out; no malloc, no
 * clock, no syscall.
 *
 * NOT here yet (M6 items 2-3): ACK generation, loss recovery, PTO and idle timers, streams and
 * flow control, Retry, Version Negotiation, key update, stateless reset. Until then such input is
 * DROPPED or ignored after a strict syntax check, never half-processed: VN / Retry / unknown
 * versions and 0-RTT packets are dropped, a key-phase flip is dropped, ACK and 1-RTT frames
 * other than CRYPTO / HANDSHAKE_DONE / CONNECTION_CLOSE are parsed and ignored, except for the
 * checks that need no stream state (MAX_STREAMS / STREAMS_BLOCKED <= 2^60, RETIRE_CONNECTION_ID
 * of our only CID, NEW_CONNECTION_ID to an empty DCID).
 *
 * Policy choices (each MAY/SHOULD, recorded so the reviewers need not re-derive them):
 *   - a duplicate transport parameter is TRANSPORT_PARAMETER_ERROR (RFC 9000 7.4 SHOULD) for
 *     ids 0x00..0x10; repeated unknown ids are not tracked (they are ignored anyway, 18.1);
 *   - a frame type not in its minimal encoding is PROTOCOL_VIOLATION (12.4 MAY);
 *   - a server Initial with a non-empty token is dropped, not an error (17.2.2 allows both);
 *   - overlapping CRYPTO data: the first copy wins, differing bytes are not compared (the MAY
 *     error of 19.6 is not taken);
 *   - datagrams are at most 1200 bytes (RFC 9000 14.1's floor) until path MTU exists;
 *   - one packet per sent datagram, except the CONNECTION_CLOSE (coalesced at every level).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_QUIC

#    define QC_RING  BRISK_QUIC_CRYPTO_BUF
#    define QC_BITS  ((BRISK_QUIC_CRYPTO_BUF + 7) / 8)
#    define QC_RET0  2048 /* Initial CRYPTO sent: CH1 + CH2 after an HRR, and later the close */
#    define QC_RET1  BRISK__TLS13_OUT_MAX /* Handshake CRYPTO sent: the client flight */
#    define QC_DGRAM BRISK__QUIC_MIN_INITIAL
#    define QC_NONE  UINT64_MAX

static const uint8_t QC_EPOCH[3] = {BRISK__EPOCH_INITIAL, BRISK__EPOCH_HANDSHAKE, BRISK__EPOCH_APP};

/* ------------------------------------------------------------------ transport parameters -- */

enum {
    TP_ODCID = 0x00,
    TP_IDLE = 0x01,
    TP_RESET = 0x02,
    TP_UDP = 0x03,
    TP_ACK_EXP = 0x0a,
    TP_ACK_DELAY = 0x0b,
    TP_NO_MIGRATE = 0x0c,
    TP_PREF_ADDR = 0x0d,
    TP_CID_LIMIT = 0x0e,
    TP_ISCID = 0x0f,
    TP_RSCID = 0x10
};

void brisk__quic_tp_default(brisk__quic_tp *tp)
{
    memset(tp, 0, sizeof *tp);
    tp->max_udp_payload_size = 65527; /* 18.2 defaults */
    tp->ack_delay_exponent = 3;
    tp->max_ack_delay = 25;
    tp->active_connection_id_limit = 2;
}

/* The integer TPs (18.2) by id, NULL for the others. */
static uint64_t *tp_int(brisk__quic_tp *tp, uint64_t id)
{
    uint64_t *f[15] = {NULL};
    f[0x01] = &tp->max_idle_timeout;
    f[0x03] = &tp->max_udp_payload_size;
    f[0x04] = &tp->initial_max_data;
    f[0x05] = &tp->initial_max_stream_data_bidi_local;
    f[0x06] = &tp->initial_max_stream_data_bidi_remote;
    f[0x07] = &tp->initial_max_stream_data_uni;
    f[0x08] = &tp->initial_max_streams_bidi;
    f[0x09] = &tp->initial_max_streams_uni;
    f[0x0a] = &tp->ack_delay_exponent;
    f[0x0b] = &tp->max_ack_delay;
    f[0x0e] = &tp->active_connection_id_limit;
    return id < 15 ? f[id] : NULL;
}

/* 18.2 value rules shared by parse and write; 1 = acceptable */
static int tp_values_ok(const brisk__quic_tp *tp)
{
    /* 4.6: a stream count above 2^60 cannot be expressed as a stream id */
    return tp->max_udp_payload_size >= 1200 && tp->ack_delay_exponent <= 20 &&
           tp->max_ack_delay < ((uint64_t)1 << 14) && tp->active_connection_id_limit >= 2 &&
           tp->initial_max_streams_bidi <= ((uint64_t)1 << 60) &&
           tp->initial_max_streams_uni <= ((uint64_t)1 << 60);
}

static int tp_cid(uint8_t *dst, uint8_t *dst_len, uint8_t *has, const uint8_t *v, uint64_t l)
{
    if (l > BRISK__QUIC_MAX_CID) {
        return 0; /* 18.2 / 17.2: a v1 connection ID is at most 20 bytes */
    }
    memcpy(dst, v, (size_t)l);
    *dst_len = (uint8_t)l;
    *has = 1;
    return 1;
}

int brisk__quic_tp_parse(const uint8_t *in, size_t len, brisk__quic_tp *tp)
{
    const uint8_t *p = in, *end = in, *v, *q;
    uint64_t id, l, *f;
    uint32_t seen = 0;
    if (tp == NULL) {
        return BRISK_E_ARG;
    }
    brisk__quic_tp_default(tp);
    if (in == NULL && len != 0) {
        goto bad;
    }
    end = len != 0 ? in + len : in; /* NULL + 0 is not C */
    while (p < end) {
        /* 18: {id (i), length (i), value}; a length past the block is malformed */
        if (!brisk__quic_varint_get(&p, end, &id) || !brisk__quic_varint_get(&p, end, &l) ||
            l > (uint64_t)(end - p)) {
            goto bad;
        }
        v = p;
        p += (size_t)l;
        if (id > TP_RSCID) {
            continue; /* 7.4.2 / 18.1 (MUST): unknown and reserved 31*N+27 ids are ignored */
        }
        if (seen & ((uint32_t)1 << id)) {
            goto bad; /* 7.4: a duplicate SHOULD be TRANSPORT_PARAMETER_ERROR - taken */
        }
        seen |= (uint32_t)1 << id;
        f = tp_int(tp, id);
        if (f != NULL) {
            /* 18.2: one varint that fills the value exactly */
            q = v;
            if (!brisk__quic_varint_get(&q, v + l, f) || q != v + l) {
                goto bad;
            }
            continue;
        }
        switch (id) {
        case TP_ODCID:
            if (!tp_cid(tp->odcid, &tp->odcid_len, &tp->has_odcid, v, l)) {
                goto bad;
            }
            break;
        case TP_ISCID:
            if (!tp_cid(tp->iscid, &tp->iscid_len, &tp->has_iscid, v, l)) {
                goto bad;
            }
            break;
        case TP_RSCID:
            if (!tp_cid(tp->retry_scid, &tp->retry_scid_len, &tp->has_retry_scid, v, l)) {
                goto bad;
            }
            break;
        case TP_RESET: /* 18.2: stateless_reset_token is 16 bytes */
            if (l != 16) {
                goto bad;
            }
            memcpy(tp->reset_token, v, 16);
            tp->has_reset_token = 1;
            break;
        case TP_NO_MIGRATE: /* 18.2: a zero-length value */
            if (l != 0) {
                goto bad;
            }
            tp->disable_active_migration = 1;
            break;
        default: /* TP_PREF_ADDR, 18.2: IPv4(4) port(2) IPv6(16) port(2) cid_len(1) cid token(16),
                    and a zero-length connection ID MUST NOT be sent */
            if (l < 25 || v[24] == 0 || v[24] > BRISK__QUIC_MAX_CID || l != 41u + v[24]) {
                goto bad;
            }
            tp->has_pref_addr = 1; /* validated, then ignored: this client never migrates */
            break;
        }
    }
    /* 18.2 (MUST): a server using a zero-length connection ID sends no preferred_address */
    if (!tp_values_ok(tp) || (tp->has_pref_addr && tp->has_iscid && tp->iscid_len == 0)) {
        goto bad;
    }
    return BRISK_OK;
bad:
    memset(tp, 0, sizeof *tp);
    return BRISK_E_PROTO;
}

static int tp_put(uint8_t *out, size_t cap, size_t *n, uint64_t id, const uint8_t *v, size_t vl)
{
    size_t a = brisk__quic_varint_put(out + *n, cap - *n, id), b;
    if (a == 0) {
        return 0;
    }
    b = brisk__quic_varint_put(out + *n + a, cap - *n - a, vl);
    if (b == 0 || vl > cap - *n - a - b) {
        return 0;
    }
    memcpy(out + *n + a + b, v, vl);
    *n += a + b + vl;
    return 1;
}

int brisk__quic_tp_write(const brisk__quic_tp *tp, uint8_t *out, size_t cap, size_t *out_len)
{
    brisk__quic_tp def;
    uint8_t tmp[8];
    uint64_t id, *f, *d;
    size_t n = 0, vl;
    int ok;
    if (out_len != NULL) {
        *out_len = 0;
    }
    /* 18.2 (MUST NOT): a client never sends the server-only parameters */
    if (tp == NULL || out == NULL || out_len == NULL || tp->has_odcid || tp->has_retry_scid ||
        tp->has_reset_token || tp->has_pref_addr || tp->iscid_len > BRISK__QUIC_MAX_CID ||
        !tp_values_ok(tp)) {
        return BRISK_E_ARG;
    }
    brisk__quic_tp_default(&def);
    ok = 1;
    for (id = TP_IDLE; ok && id <= TP_CID_LIMIT; id++) {
        f = tp_int((brisk__quic_tp *)tp, id);
        d = tp_int(&def, id);
        if (f != NULL && *f != *d) {
            vl = brisk__quic_varint_put(tmp, sizeof tmp, *f);
            ok = vl != 0 && tp_put(out, cap, &n, id, tmp, vl);
        } else if (id == TP_NO_MIGRATE && tp->disable_active_migration) {
            ok = tp_put(out, cap, &n, id, tmp, 0);
        }
    }
    /* 7.3 (MUST): initial_source_connection_id = the SCID of our first Initial */
    if (!ok || !tp_put(out, cap, &n, TP_ISCID, tp->iscid, tp->iscid_len)) {
        return BRISK_E_ARG;
    }
    *out_len = n;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ failure --------------- */

static size_t cc_build(brisk__quic_conn *q, uint8_t *out);

static void wipe_all(brisk__quic_conn *q)
{
    size_t i;
    for (i = 0; i < 3; i++) {
        brisk__quic_keys_wipe(&q->rx[i]);
        brisk__quic_keys_wipe(&q->tx[i]);
    }
    brisk__secure_zero(q->ring, QC_RING + QC_BITS);
    brisk__secure_zero(q->ret[0] + q->cc_len, QC_RET0 - q->cc_len);
    brisk__secure_zero(q->ret[1], QC_RET1);
    q->ret_len[0] = q->ret_len[1] = q->ret_sent[0] = q->ret_sent[1] = 0;
    brisk__tls13_hs_wipe(q->hs); /* every engine secret, its scratch included */
}

/* The sticky failure: the CONNECTION_CLOSE is built now, while the keys exist, then every key
 * and secret is wiped. silent = no close (12.3: PN space exhausted; 6.6: key used up). */
static int q_fail(brisk__quic_conn *q, uint64_t code, int rc, int silent)
{
    q->err = rc;
    q->err_code = code;
    q->cc_len = silent ? 0 : cc_build(q, q->ret[0]);
    q->cc_state = q->cc_len != 0;
    wipe_all(q);
    return rc;
}

/* The engine failed: its alert as a QUIC error (RFC 9001 4.8), or what our callback asked for. */
static uint64_t engine_code(const brisk__quic_conn *q)
{
    if (q->pend_err != 0) {
        return q->pend_err;
    }
    if (q->hs->alert == BRISK__ALERT_QUIC_PROTOCOL_VIOLATION) {
        return BRISK__QERR_PROTOCOL_VIOLATION; /* RFC 9001 4.6.1 */
    }
    return BRISK__QERR_CRYPTO + q->hs->alert; /* 4.8: 0x0100 + AlertDescription */
}

static int fail_rc(const brisk__quic_conn *q)
{
    return q->pend_err == 0 && q->hs->state == BRISK__HS_FAILED ? q->hs->err : BRISK_E_PROTO;
}

/* ------------------------------------------------------------------ engine callbacks ------ */

static int on_secret(void *ctx, unsigned epoch, int is_send, uint16_t suite, const uint8_t *secret,
                     size_t len)
{
    brisk__quic_conn *q = (brisk__quic_conn *)ctx;
    unsigned lvl = epoch == BRISK__EPOCH_HANDSHAKE ? 1 : epoch == BRISK__EPOCH_APP ? 2 : 0;
    size_t i;
    if (lvl == 0) {
        return -1; /* the engine never exports Initial secrets; they come from the DCID */
    }
    if (is_send) {
        return brisk__quic_keys_init(&q->tx[lvl], suite, secret, len) == BRISK_OK ? 0 : -1;
    }
    /* RFC 9001 4.1.3 (MUST): keys for a higher level while CRYPTO data at the current one is
     * still buffered, unconsumed, is PROTOCOL_VIOLATION */
    for (i = 0; i < QC_BITS; i++) {
        if (q->bits[i] != 0) {
            q->pend_err = BRISK__QERR_PROTOCOL_VIOLATION;
            return -1;
        }
    }
    if (lvl <= q->rx_level || brisk__quic_keys_init(&q->rx[lvl], suite, secret, len) != BRISK_OK) {
        q->pend_err = BRISK__QERR_INTERNAL;
        return -1;
    }
    q->rx_level = (uint8_t)lvl;
    q->ring_pos = 0;
    return 0;
}

/* RFC 9001 8.2: the server's parameters. Parsed and copied now (the bytes die with the call),
 * acted on only at CONNECTED, when they are authenticated. */
static int on_peer_tp(void *ctx, const uint8_t *tp, size_t len)
{
    brisk__quic_conn *q = (brisk__quic_conn *)ctx;
    if (brisk__quic_tp_parse(tp, len, &q->peer_tp) != BRISK_OK) {
        q->pend_err = BRISK__QERR_TRANSPORT_PARAMETER;
        return -1;
    }
    q->tp_seen = 1;
    return 0;
}

/* ------------------------------------------------------------------ CRYPTO streams -------- */

#    define QC_BIT(q, i) ((q)->bits[(i) >> 3] & (1u << ((i) & 7)))

/* Hand the contiguous prefix of the ring to the engine (RFC 9001 4.1.3: in order, at the
 * current level). 0 or a QUIC error code. */
static uint64_t deliver(brisk__quic_conn *q, unsigned lvl)
{
    size_t k = 0, pos = q->ring_pos, start = q->ring_pos, a;
    int rc;
    while (k < QC_RING && QC_BIT(q, pos)) {
        q->bits[pos >> 3] &= (uint8_t)~(1u << (pos & 7));
        k++;
        pos = pos + 1 == QC_RING ? 0 : pos + 1;
    }
    if (k == 0) {
        return 0;
    }
    q->ring_pos = pos;
    q->crx[lvl] += k;
    a = k < QC_RING - start ? k : QC_RING - start;
    /* the engine may install the next level's keys inside this call (on_secret resets the
     * ring); a wrapped second part is then fed at the old epoch and refused by the engine */
    rc = brisk__tls13_hs_feed(q->hs, QC_EPOCH[lvl], q->ring + start, a);
    if (rc == BRISK_OK && k > a) {
        rc = brisk__tls13_hs_feed(q->hs, QC_EPOCH[lvl], q->ring, k - a);
    }
    return rc == BRISK_OK ? 0 : engine_code(q);
}

/* One CRYPTO frame (RFC 9000 19.6, RFC 9001 4.1.3). off + n <= 2^62-1 was checked. */
static uint64_t crypto_in(brisk__quic_conn *q, unsigned lvl, uint64_t off, const uint8_t *data,
                          size_t n)
{
    uint64_t base = q->crx[lvl], end = off + n, rel, code;
    size_t chunk, j, pos;
    if (lvl != q->rx_level) {
        /* 4.1.3 (MUST): at a previously installed level, nothing past what was received.
         * A later level cannot occur: its packets are not decryptable yet. */
        return lvl < q->rx_level && end <= base ? 0 : BRISK__QERR_PROTOCOL_VIOLATION;
    }
    if (end <= base) {
        return 0; /* all delivered already: a retransmission */
    }
    if (off < base) {
        data += (size_t)(base - off);
        n = (size_t)(end - base);
        off = base;
    }
    while (n != 0) {
        rel = off - q->crx[lvl];
        /* 7.5 (MUST): at least 4096 bytes of out-of-order data; beyond the buffer during the
         * handshake is CRYPTO_BUFFER_EXCEEDED. Delivered data frees room, so an in-order
         * frame larger than the ring goes through in pieces. */
        if (rel >= QC_RING) {
            return BRISK__QERR_CRYPTO_BUFFER_EXCEEDED;
        }
        chunk = (size_t)(QC_RING - rel) < n ? (size_t)(QC_RING - rel) : n;
        pos = q->ring_pos + (size_t)rel;
        for (j = 0; j < chunk; j++, pos++) {
            if (pos >= QC_RING) {
                pos -= QC_RING;
            }
            if (!QC_BIT(q, pos)) { /* overlapping data: the first copy wins */
                q->ring[pos] = data[j];
                q->bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
            }
        }
        off += chunk;
        data += chunk;
        n -= chunk;
        code = deliver(q, lvl);
        if (code != 0) {
            return code;
        }
        if (q->rx_level != lvl) {
            /* 4.1.3: the keys changed; more data at the old level is unconsumed */
            return n != 0 ? BRISK__QERR_PROTOCOL_VIOLATION : 0;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ frames (12.4, 19) ----- */

/* Varints to skip for the frames that are only syntax-checked in this item (19.4-19.19). */
static const uint8_t QC_SKIP[0x1f] = {[0x04] = 3, [0x05] = 2, [0x10] = 1,
                                      [0x11] = 2, [0x14] = 1, [0x15] = 2};

uint64_t brisk__quic_frames(brisk__quic_conn *q, unsigned lvl, const uint8_t *p, size_t len)
{
    const uint8_t *end, *t0;
    uint64_t type, a, b, c, i, code;
    /* 12.4: a packet containing no frames is PROTOCOL_VIOLATION */
    if (p == NULL || len == 0) {
        return BRISK__QERR_PROTOCOL_VIOLATION;
    }
    end = p + len;
#    define QC_GET(v)                                                                              \
        do {                                                                                       \
            if (!brisk__quic_varint_get(&p, end, &(v))) {                                          \
                return BRISK__QERR_FRAME_ENCODING;                                                 \
            }                                                                                      \
        } while (0)
#    define QC_SKIPN(n)                                                                            \
        do {                                                                                       \
            if ((n) > (uint64_t)(end - p)) {                                                       \
                return BRISK__QERR_FRAME_ENCODING;                                                 \
            }                                                                                      \
            p += (size_t)(n);                                                                      \
        } while (0)
    while (p < end) {
        t0 = p;
        QC_GET(type);
        if (type > 0x1e) {
            return BRISK__QERR_FRAME_ENCODING; /* 12.4: an unknown frame type */
        }
        if ((size_t)(p - t0) != brisk__quic_varint_put(NULL, 0, type)) {
            return BRISK__QERR_PROTOCOL_VIOLATION; /* 12.4: MUST be minimal; MAY error - taken */
        }
        /* 12.4 Table 3: Initial and Handshake carry only PADDING, PING, ACK, CRYPTO and
         * CONNECTION_CLOSE 0x1c; anything else there is PROTOCOL_VIOLATION */
        if (lvl != 2 && !(type <= 0x03 || type == 0x06 || type == 0x1c)) {
            return BRISK__QERR_PROTOCOL_VIOLATION;
        }
        switch (type) {
        case 0x00: /* PADDING (19.1) */
        case 0x01: /* PING (19.2) */
            break;
        case 0x02: /* ACK (19.3): syntax only until loss recovery (M6 item 2) */
        case 0x03:
            QC_GET(a); /* Largest Acknowledged */
            QC_GET(b); /* ACK Delay */
            QC_GET(c); /* ACK Range Count */
            QC_GET(b); /* First ACK Range */
            if (b > a) {
                return BRISK__QERR_FRAME_ENCODING; /* 19.3.1: a negative packet number */
            }
            a -= b; /* smallest acknowledged so far */
            for (i = 0; i < c; i++) {
                QC_GET(b); /* Gap: the next largest is smallest - gap - 2 */
                if (b > a || a - b < 2) {
                    return BRISK__QERR_FRAME_ENCODING;
                }
                a -= b + 2;
                QC_GET(b); /* ACK Range Length */
                if (b > a) {
                    return BRISK__QERR_FRAME_ENCODING;
                }
                a -= b;
            }
            if (type == 0x03) { /* ECN counts */
                QC_GET(a);
                QC_GET(a);
                QC_GET(a);
            }
            break;
        case 0x06: /* CRYPTO (19.6) */
            QC_GET(a);
            QC_GET(b);
            /* a length past the packet, or offset + length past 2^62-1 */
            if (b > (uint64_t)(end - p) || a > BRISK__QUIC_VARINT_MAX - b) {
                return BRISK__QERR_FRAME_ENCODING;
            }
            if (q != NULL) {
                code = crypto_in(q, lvl, a, p, (size_t)b);
                if (code != 0) {
                    return code;
                }
            }
            p += (size_t)b;
            break;
        case 0x07: /* NEW_TOKEN (19.7): an empty token is FRAME_ENCODING_ERROR */
            QC_GET(a);
            if (a == 0) {
                return BRISK__QERR_FRAME_ENCODING;
            }
            QC_SKIPN(a);
            break;
        case 0x08: /* STREAM (19.8): Stream ID, [Offset], [Length], data */
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
        case 0x0e:
        case 0x0f:
            QC_GET(a);
            a = 0;
            if (type & 0x04) {
                QC_GET(a);
            }
            if (type & 0x02) {
                QC_GET(b);
            } else {
                b = (uint64_t)(end - p);
            }
            if (b > (uint64_t)(end - p) || a > BRISK__QUIC_VARINT_MAX - b) {
                return BRISK__QERR_FRAME_ENCODING;
            }
            p += (size_t)b;
            break;
        case 0x18: /* NEW_CONNECTION_ID (19.15) */
            QC_GET(a);
            QC_GET(b);
            if (b > a || p == end || *p < 1 || *p > BRISK__QUIC_MAX_CID) {
                return BRISK__QERR_FRAME_ENCODING;
            }
            c = *p++;
            QC_SKIPN(c + 16);
            if (q != NULL && q->dcid_len == 0) {
                return BRISK__QERR_PROTOCOL_VIOLATION; /* 19.15 MUST: we send an empty DCID */
            }
            break;
        case 0x12: /* MAX_STREAMS (19.11), STREAMS_BLOCKED (19.14): MUST be at most 2^60 */
        case 0x13:
        case 0x16:
        case 0x17:
            QC_GET(a);
            if (a > ((uint64_t)1 << 60)) {
                return BRISK__QERR_FRAME_ENCODING;
            }
            break;
        case 0x19: /* RETIRE_CONNECTION_ID (19.16): we issued only sequence 0, the DCID of every
                    * 1-RTT packet (MAY), and none at all with an empty SCID (MUST) */
            QC_GET(a);
            if (q != NULL) {
                return BRISK__QERR_PROTOCOL_VIOLATION;
            }
            break;
        case 0x1a: /* PATH_CHALLENGE / PATH_RESPONSE (19.17, 19.18) */
        case 0x1b:
            QC_SKIPN(8);
            break;
        case 0x1c: /* CONNECTION_CLOSE (19.19) */
        case 0x1d:
            QC_GET(a);
            if (type == 0x1c) {
                QC_GET(b);
            }
            QC_GET(c);
            QC_SKIPN(c);
            if (q != NULL) {
                /* 10.2.2: draining; nothing is sent back */
                q->err = BRISK_E_PEER_ALERT;
                q->err_code = a;
                return 0;
            }
            break;
        case 0x1e: /* HANDSHAKE_DONE (19.20): 1-RTT only (Table 3 above) */
            if (q != NULL) {
                /* RFC 9001 4.1.2: confirmed. 4.9.2 (MUST): discard the Handshake keys. */
                q->confirmed = 1;
                brisk__quic_keys_wipe(&q->rx[1]);
                brisk__quic_keys_wipe(&q->tx[1]);
                brisk__secure_zero(q->ret[1], QC_RET1);
                q->ret_len[1] = q->ret_sent[1] = 0;
            }
            break;
        default:
            for (i = 0; i < QC_SKIP[type]; i++) {
                QC_GET(a);
            }
            break;
        }
    }
#    undef QC_GET
#    undef QC_SKIPN
    return 0;
}

/* ------------------------------------------------------------------ connection ------------ */

size_t brisk__quic_scratch_size(void)
{
    return QC_RING + QC_BITS + QC_RET0 + QC_RET1;
}

int brisk__quic_conn_init(brisk__quic_conn *q, brisk__tls13_hs *hs, const uint8_t *dcid,
                          size_t dcid_len, const uint8_t *scid, size_t scid_len, uint8_t *scratch,
                          size_t scratch_len)
{
    uint8_t c[32], s[32];
    int rc;
    /* RFC 9000 7.2 (MUST): the first DCID is at least 8 unpredictable bytes */
    if (q == NULL || hs == NULL || !hs->cfg.quic || dcid == NULL || dcid_len < 8 ||
        dcid_len > BRISK__QUIC_MAX_CID || scid_len > BRISK__QUIC_MAX_CID ||
        (scid == NULL && scid_len != 0) || scratch == NULL ||
        scratch_len < brisk__quic_scratch_size()) {
        return BRISK_E_ARG;
    }
    memset(q, 0, sizeof *q);
    q->hs = hs;
    hs->cfg.on_secret = on_secret;
    hs->cfg.secret_ctx = q;
    hs->cfg.on_peer_tp = on_peer_tp;
    hs->cfg.tp_ctx = q;
    memcpy(q->dcid, dcid, dcid_len);
    memcpy(q->odcid, dcid, dcid_len);
    q->dcid_len = q->odcid_len = (uint8_t)dcid_len;
    if (scid_len != 0) {
        memcpy(q->scid, scid, scid_len);
    }
    q->scid_len = (uint8_t)scid_len;
    q->rx_largest[0] = q->rx_largest[1] = q->rx_largest[2] = QC_NONE;
    memset(scratch, 0, brisk__quic_scratch_size());
    q->ring = scratch;
    q->bits = scratch + QC_RING;
    q->ret[0] = q->bits + QC_BITS;
    q->ret[1] = q->ret[0] + QC_RET0;
    q->ret_cap[0] = QC_RET0;
    q->ret_cap[1] = QC_RET1;
    /* RFC 9001 5.2: Initial keys from the client's first DCID, AES-128-GCM */
    rc = brisk__quic_initial_secrets(dcid, dcid_len, c, s);
    if (rc == BRISK_OK) {
        rc = brisk__quic_keys_init(&q->tx[0], 0x1301, c, 32);
    }
    if (rc == BRISK_OK) {
        rc = brisk__quic_keys_init(&q->rx[0], 0x1301, s, 32);
    }
    brisk__secure_zero(c, sizeof c);
    brisk__secure_zero(s, sizeof s);
    return rc;
}

/* RFC 9000 12.3 (MUST): a duplicate is discarded - called only after the AEAD accepted the
 * packet. 1 = seen before (or too old to tell: 64 below the largest). */
static int dup_seen(brisk__quic_conn *q, unsigned lvl, uint64_t pn)
{
    uint64_t d, bit = 1, *seen = &q->rx_seen[lvl];
    if (q->rx_largest[lvl] == QC_NONE || pn > q->rx_largest[lvl]) {
        d = q->rx_largest[lvl] == QC_NONE ? 64 : pn - q->rx_largest[lvl];
        *seen = d >= 64 ? 0 : *seen;
        while (d-- != 0 && *seen != 0) { /* constant shifts only: no __ashldi3 on 32-bit */
            *seen <<= 1;
        }
        *seen |= 1;
        q->rx_largest[lvl] = pn;
        return 0;
    }
    d = q->rx_largest[lvl] - pn;
    if (d >= 64) {
        return 1; /* ponytail: a 64-packet window; item 2's ACK ranges replace it */
    }
    while (d-- != 0) {
        bit <<= 1;
    }
    if (*seen & bit) {
        return 1;
    }
    *seen |= bit;
    return 0;
}

/* RFC 9000 7.3 (MUST): the server's CIDs as authenticated by the handshake */
static int cids_ok(const brisk__quic_conn *q)
{
    const brisk__quic_tp *t = &q->peer_tp;
    return q->tp_seen && t->has_odcid && t->odcid_len == q->odcid_len &&
           memcmp(t->odcid, q->odcid, q->odcid_len) == 0 && t->has_iscid &&
           t->iscid_len == q->dcid_len && memcmp(t->iscid, q->dcid, q->dcid_len) == 0 &&
           !t->has_retry_scid; /* no Retry was received (Retry is M6 item 3) */
}

static int one_packet(brisk__quic_conn *q, const brisk__quic_hdr *h, uint8_t *pkt)
{
    brisk__quic_keys *k;
    unsigned lvl;
    uint64_t pn, code;
    size_t po, pl;
    uint8_t first;
    int rc, is_long = h->type != BRISK__QPKT_1RTT;

    if (h->type == BRISK__QPKT_INITIAL) {
        lvl = 0;
    } else if (h->type == BRISK__QPKT_HANDSHAKE) {
        lvl = 1;
    } else if (h->type == BRISK__QPKT_1RTT) {
        lvl = 2;
    } else {
        return BRISK_OK; /* 0-RTT (never sent to a client), Retry and VN (M6 item 3): drop */
    }
    /* 5.2.1: another version than the one selected MUST be dropped; a DCID that is not ours
     * is not our packet. 7.2 (MUST): after the first server Initial every long header carries
     * its SCID. 17.2.2: a server Initial with a token - dropped (policy, see the file head). */
    if ((is_long && h->version != BRISK__QUIC_V1) || h->dcid_len != q->scid_len ||
        memcmp(h->dcid, q->scid, q->scid_len) != 0 ||
        (is_long && q->got_initial &&
         (h->scid_len != q->dcid_len || memcmp(h->scid, q->dcid, q->dcid_len) != 0)) ||
        (lvl == 0 && h->token_len != 0)) {
        return BRISK_OK;
    }
    k = &q->rx[lvl];
    /* keys not (yet / any more) available: drop. RFC 9001 5.7 (MUST): no 1-RTT processing
     * before the handshake is complete, even with the keys installed. */
    if (k->suite == 0 || (lvl == 2 && q->hs->state != BRISK__HS_CONNECTED)) {
        return BRISK_OK;
    }
    rc = brisk__quic_open(k, pkt, h->pn_off, h->pkt_len, q->rx_largest[lvl], &first, &pn, &po, &pl);
    if (rc == BRISK_E_AUTH) {
        /* RFC 9001 5.5: dropped, not an error. 6.6: count them across the connection;
         * 2^52 for AES-GCM, 2^36 for ChaCha20-Poly1305 -> AEAD_LIMIT_REACHED */
        q->auth_fail++;
        if (q->auth_fail >= (k->suite == 0x1303 ? (uint64_t)1 << 36 : (uint64_t)1 << 52)) {
            return q_fail(q, BRISK__QERR_AEAD_LIMIT_REACHED, BRISK_E_AUTH, 0);
        }
        return BRISK_OK;
    }
    if (rc != BRISK_OK) {
        return BRISK_OK;
    }
    q->n_opened++;
    /* 17.2 / 17.3.1 (MUST): reserved bits non-zero after removing BOTH protections */
    if (first & (is_long ? 0x0c : 0x18)) {
        return q_fail(q, BRISK__QERR_PROTOCOL_VIOLATION, BRISK_E_PROTO, 0);
    }
    /* key phase flip = key update (M6 item 3): dropped. 12.3: duplicates, after protection. */
    if ((!is_long && (first & 0x04)) || dup_seen(q, lvl, pn)) {
        return BRISK_OK;
    }
    if (lvl == 0 && !q->got_initial) {
        /* 7.2 (MUST): switch to the SCID of the first server Initial */
        memcpy(q->dcid, h->scid, h->scid_len);
        q->dcid_len = h->scid_len;
        q->got_initial = 1;
    }
    code = brisk__quic_frames(q, lvl, pkt + po, pl);
    if (q->err != 0) {
        wipe_all(q); /* the peer closed: draining, no CONNECTION_CLOSE back */
        return q->err;
    }
    if (code != 0) {
        return q_fail(q, code, fail_rc(q), 0);
    }
    if (!q->established && q->hs->state == BRISK__HS_CONNECTED) {
        if (!cids_ok(q)) {
            return q_fail(q, BRISK__QERR_TRANSPORT_PARAMETER, BRISK_E_PROTO, 0);
        }
        q->established = 1;
    }
    return BRISK_OK;
}

int brisk__quic_recv(brisk__quic_conn *q, uint8_t *dgram, size_t len, int64_t now_ms)
{
    brisk__quic_hdr h;
    size_t off = 0;
    int rc;
    (void)now_ms; /* timers are M6 item 2 */
    if (q == NULL || (dgram == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    if (q->err != 0) {
        return q->err;
    }
    /* 12.2 (MUST): coalesced packets one by one; a packet that fails to decrypt does not stop
     * the rest. A header that does not parse ends the datagram (its length is unknown). */
    while (off < len &&
           brisk__quic_hdr_parse(dgram + off, len - off, q->scid_len, &h) == BRISK_OK) {
        rc = one_packet(q, &h, dgram + off);
        if (rc != BRISK_OK) {
            return rc;
        }
        off += h.pkt_len;
    }
    return BRISK_OK;
}

/* ------------------------------------------------------------------ sending --------------- */

static size_t hdr_len(const brisk__quic_conn *q, unsigned lvl)
{
    /* long: byte0 version dcid_len dcid scid_len scid [token_len 0] Length(2); short: byte0 dcid */
    return lvl == 2 ? 1u + q->dcid_len
                    : 1u + 4 + 1 + q->dcid_len + 1 + q->scid_len + (lvl == 0) + 2;
}

/* Header + 4-byte PN + seal around payload_len bytes already at p + hdr_len + 4. Returns the
 * packet length, 0 if the key refused (6.6 limit) or the PN space is spent (12.3). */
static size_t pkt_finish(brisk__quic_conn *q, unsigned lvl, uint8_t *p, size_t payload_len)
{
    size_t hl = hdr_len(q, lvl), i = 0;
    /* 17.1: the full 4-byte PN until the space is acknowledged. The callers lay the payload
     * out at hl + 4; ACK processing (M6 item 2) must pass brisk__quic_pn_len's value to them. */
    const unsigned pnl = 4;
    if (q->tx_pn[lvl] >= BRISK__QUIC_VARINT_MAX) {
        return 0;
    }
    if (lvl == 2) {
        p[i++] = (uint8_t)(0x40 | (pnl - 1)); /* 17.3.1: fixed bit, spin 0, key phase 0 */
    } else {
        p[i++] =
            (uint8_t)(0xc0 | (lvl == 0 ? 0x00 : 0x20) | (pnl - 1)); /* 17.2: Initial/Handshake */
        brisk__store_be32(p + i, BRISK__QUIC_V1);
        i += 4;
        p[i++] = q->dcid_len;
    }
    memcpy(p + i, q->dcid, q->dcid_len);
    i += q->dcid_len;
    if (lvl != 2) {
        p[i++] = q->scid_len;
        memcpy(p + i, q->scid, q->scid_len);
        i += q->scid_len;
        if (lvl == 0) {
            p[i++] = 0; /* Token Length: a client without a Retry / NEW_TOKEN sends none */
        }
        brisk__store_be16(p + i,
                          (uint32_t)(0x4000 | (pnl + payload_len + 16))); /* Length, 2-byte */
        i += 2;
    }
    if (brisk__quic_seal(&q->tx[lvl], p, i, pnl, q->tx_pn[lvl], payload_len) != BRISK_OK) {
        return 0;
    }
    q->tx_pn[lvl]++;
    return hl + pnl + payload_len + 16;
}

/* RFC 9000 10.2.3: CONNECTION_CLOSE 0x1c (never 0x1d below 1-RTT; this client has no
 * application close yet) in every level we still hold send keys for - Initial and Handshake
 * while unsure what the server has, 1-RTT once it exists - coalesced, padded to 1200 when an
 * Initial is in it (14.1). No reason phrase, frame type 0. */
static size_t cc_build(brisk__quic_conn *q, uint8_t *out)
{
    size_t pos = 0, hl, pl, w, n;
    unsigned lvl, last = 3;
    for (lvl = 0; lvl < 3; lvl++) {
        if (q->tx[lvl].suite != 0 && q->tx_pn[lvl] < BRISK__QUIC_VARINT_MAX) {
            last = lvl;
        }
    }
    for (lvl = 0; lvl < 3 && last != 3; lvl++) {
        if (q->tx[lvl].suite == 0 || q->tx_pn[lvl] >= BRISK__QUIC_VARINT_MAX) {
            continue;
        }
        hl = hdr_len(q, lvl);
        w = pos + hl + 4;
        out[w] = 0x1c;
        pl = 1 + brisk__quic_varint_put(out + w + 1, 8, q->err_code);
        out[w + pl++] = 0x00; /* Frame Type */
        out[w + pl++] = 0x00; /* Reason Phrase Length */
        if (lvl == last && q->tx[0].suite != 0 && pos + hl + 4 + pl + 16 < QC_DGRAM) {
            n = QC_DGRAM - (pos + hl + 4 + pl + 16);
            memset(out + w + pl, 0, n); /* PADDING */
            pl += n;
        }
        n = pkt_finish(q, lvl, out + pos, pl);
        if (n == 0) {
            break;
        }
        pos += n;
    }
    return pos;
}

size_t brisk__quic_send(brisk__quic_conn *q, uint8_t *out, size_t cap, int64_t now_ms)
{
    uint8_t tmp[512];
    unsigned e, lvl;
    size_t n, hl, room, fo, pl, w;
    uint64_t off;
    (void)now_ms;
    if (q == NULL || out == NULL || cap < QC_DGRAM) {
        return 0;
    }
    if (q->err == 0) {
        /* the engine's CRYPTO output joins the level's send stream (kept for item 2's
         * retransmissions) */
        while ((n = brisk__tls13_hs_pull(q->hs, &e, tmp, sizeof tmp)) != 0) {
            lvl = e == BRISK__EPOCH_INITIAL ? 0 : 1;
            if (e == BRISK__EPOCH_APP || q->tx[lvl].suite == 0 ||
                n > q->ret_cap[lvl] - q->ret_len[lvl]) {
                q_fail(q, BRISK__QERR_INTERNAL, BRISK_E_ARG, 0);
                break;
            }
            memcpy(q->ret[lvl] + q->ret_len[lvl], tmp, n);
            q->ret_len[lvl] += n;
        }
        brisk__secure_zero(tmp, sizeof tmp);
    }
    if (q->err != 0) {
        if (q->cc_state != 1) {
            return 0;
        }
        memcpy(out, q->ret[0], q->cc_len);
        brisk__secure_zero(q->ret[0], q->cc_len);
        q->cc_state = 2;
        return q->cc_len;
    }
    /* RFC 9001 4.9: new data at the highest level it belongs to; Initial first while it has
     * unsent CRYPTO (after an HRR, CH2 continues the stream after CH1, RFC 9000 17.2.2) */
    lvl = q->tx[0].suite != 0 && q->ret_sent[0] < q->ret_len[0] ? 0 : 1;
    if (q->tx[lvl].suite == 0 || q->ret_sent[lvl] >= q->ret_len[lvl]) {
        return 0;
    }
    hl = hdr_len(q, lvl);
    room = QC_DGRAM - hl - 4 - 16;
    off = q->ret_sent[lvl];
    fo = 1 + brisk__quic_varint_put(NULL, 0, off) + 2; /* CRYPTO type, offset, length (<= 2) */
    n = q->ret_len[lvl] - q->ret_sent[lvl];
    n = n < room - fo ? n : room - fo;
    w = hl + 4;
    out[w] = 0x06; /* CRYPTO (19.6) */
    pl = 1 + brisk__quic_varint_put(out + w + 1, 8, off);
    pl += brisk__quic_varint_put(out + w + pl, 8, n);
    memcpy(out + w + pl, q->ret[lvl] + q->ret_sent[lvl], n);
    pl += n;
    if (lvl == 0) {
        /* RFC 9000 14.1 (MUST): a datagram carrying an Initial is at least 1200 bytes */
        memset(out + w + pl, 0, room - pl);
        pl = room;
    }
    w = pkt_finish(q, lvl, out, pl);
    if (w == 0) {
        /* 12.3: PN space spent, or 6.6: the key is used up - close without a frame */
        q_fail(q, BRISK__QERR_AEAD_LIMIT_REACHED, BRISK_E_ARG, 1);
        return 0;
    }
    q->ret_sent[lvl] += n;
    if (lvl == 1 && q->tx[0].suite != 0) {
        /* RFC 9001 4.9.1 / RFC 9000 17.2.2.1 (MUST): the first Handshake packet sent ends the
         * Initial keys and the Initial CRYPTO state; no Initial is sent after it */
        brisk__quic_keys_wipe(&q->tx[0]);
        brisk__quic_keys_wipe(&q->rx[0]);
        brisk__secure_zero(q->ret[0], QC_RET0);
        q->ret_len[0] = q->ret_sent[0] = 0;
    }
    return w;
}

int brisk__quic_established(const brisk__quic_conn *q)
{
    return q != NULL && q->err == 0 && q->established;
}

#    undef QC_BIT
#    undef QC_RING
#    undef QC_BITS
#    undef QC_RET0
#    undef QC_RET1
#    undef QC_DGRAM
#    undef QC_NONE

#endif /* BRISK_ENABLE_QUIC */
