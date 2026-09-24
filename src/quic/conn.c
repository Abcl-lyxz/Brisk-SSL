/* conn.c - QUIC v1 client connection (RFC 9000, RFC 9001, RFC 9002): transport parameters
 * (RFC 9000 18), frames (12.4, 19), CRYPTO streams per encryption level on the one TLS 1.3
 * engine (RFC 9001 4), packet number spaces (RFC 9000 12.3), ACK generation (13.2), loss
 * recovery and congestion control via recovery.c (RFC 9002), streams and flow control via
 * stream.c, connection IDs (5.1), path validation responses (8.2.2), idle timeout (10.1), key
 * discard (RFC 9001 4.9) and CONNECTION_CLOSE (RFC 9000 10.2). Sans-I/O: datagrams in,
 * datagrams out, time from the caller; no malloc, no clock, no syscall.
 *
 * NOT here yet (M6 item 3): Retry, Version Negotiation, key update, stateless reset. Until then
 * VN / Retry / unknown versions and 0-RTT packets are dropped and a key-phase flip is dropped.
 *
 * Policy choices (each MAY/SHOULD, recorded so the reviewers need not re-derive them):
 *   - a duplicate transport parameter is TRANSPORT_PARAMETER_ERROR (RFC 9000 7.4 SHOULD) for
 *     ids 0x00..0x10; repeated unknown ids are not tracked (they are ignored anyway, 18.1);
 *   - a frame type not in its minimal encoding is PROTOCOL_VIOLATION (12.4 MAY);
 *   - a server Initial with a non-empty token is dropped, not an error (17.2.2 allows both);
 *   - overlapping CRYPTO data: the first copy wins, differing bytes are not compared (the MAY
 *     error of 19.6 is not taken);
 *   - datagrams are at most 1200 bytes (RFC 9000 14.1's floor) until path MTU exists; one
 *     datagram coalesces at most one packet per level, Initial -> Handshake -> 1-RTT (12.2);
 *   - a NEW_CONNECTION_ID that reuses a sequence number with another CID or token, or a CID
 *     with another sequence number, is PROTOCOL_VIOLATION (19.15 MAY, taken); more pending
 *     RETIRE_CONNECTION_IDs than 2 * active_connection_id_limit is CONNECTION_ID_LIMIT_ERROR
 *     (5.1.2 MAY, taken: it bounds a peer's Retire Prior To of 2^62-1);
 *   - PATH_CHALLENGE: two response slots; a third challenge before they are sent drops the
 *     oldest (8.2.2 says "each"; a burst of more than two in one flight is not answered in
 *     full); a PATH_RESPONSE we did not solicit is ignored (19.18 MAY error not taken: we
 *     never send PATH_CHALLENGE);
 *   - PTO probes at the Initial / Handshake level resend the unacknowledged CRYPTO data; a
 *     1-RTT probe carries new data if any, else a PING (RFC 9002 6.2.4 SHOULD);
 *   - pacing (RFC 9002 7.7: MUST pace or limit bursts): at most 12000 bytes per ms of caller
 *     time without an ACK in between; the deadline is then now + 1;
 *   - 13.2.4 (stop acknowledging acked ACK ranges, optional) is not done: 8 ranges bound the
 *     ACK frame instead.
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
#    define QC_STREAMS                                                                             \
        ((size_t)BRISK_QUIC_MAX_STREAMS * (2 * BRISK_QUIC_STREAM_BUF + BRISK_QUIC_STREAM_BUF / 8))
#    define QC_BURST    12000 /* RFC 9002 7.7: bytes per ms of caller time without an ACK */
#    define QC_MIN_ROOM 8     /* the smallest payload worth a packet */

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
            tp->has_pref_addr = 1; /* the addresses are ignored: this client never migrates */
            tp->pref_cid_len = v[24];
            memcpy(tp->pref_cid, v + 25, v[24]);
            memcpy(tp->pref_token, v + 25 + v[24], 16);
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

static size_t cc_build(brisk__quic_conn *q, uint8_t *out, unsigned type);

static void wipe_all(brisk__quic_conn *q)
{
    size_t i;
    for (i = 0; i < 3; i++) {
        brisk__quic_keys_wipe(&q->rx[i]);
        brisk__quic_keys_wipe(&q->tx[i]);
        brisk__quic_rxack_init(&q->rxa[i]);
    }
    brisk__secure_zero(q->ring, QC_RING + QC_BITS);
    brisk__secure_zero(q->ret[0] + q->cc_len, QC_RET0 - q->cc_len);
    brisk__secure_zero(q->ret[1], QC_RET1);
    q->ret_len[0] = q->ret_len[1] = q->ret_sent[0] = q->ret_sent[1] = 0;
    brisk__secure_zero(q->ap_secret, sizeof q->ap_secret);
    brisk__secure_zero(q->path_resp, sizeof q->path_resp);
    brisk__secure_zero(q->cids, sizeof q->cids);
    brisk__secure_zero(&q->rec, sizeof q->rec);
    q->ap_len = q->n_path_resp = 0;
    brisk__quic_streams_wipe(q); /* every stream ring: plaintext */
    brisk__tls13_hs_wipe(q->hs); /* every engine secret, its scratch included */
}

/* The sticky end: the CONNECTION_CLOSE (frame `type`, 0 = none) is built now, while the keys
 * exist, then every key and secret is wiped. */
static int q_end(brisk__quic_conn *q, uint64_t code, int rc, unsigned type)
{
    q->err = rc;
    q->err_code = code;
    q->cc_len = type != 0 ? cc_build(q, q->ret[0], type) : 0;
    q->cc_state = q->cc_len != 0;
    wipe_all(q);
    return rc;
}

/* A transport error: CONNECTION_CLOSE 0x1c. silent = no close (12.3: PN space exhausted; 6.6:
 * key used up). */
static int q_fail(brisk__quic_conn *q, uint64_t code, int rc, int silent)
{
    return q_end(q, code, rc, silent ? 0 : 0x1c);
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
    if (lvl == 0 || len > sizeof q->ap_secret[0]) {
        return -1; /* the engine never exports Initial secrets; they come from the DCID */
    }
    if (lvl == 2) {
        /* RFC 9001 6: key update derives from the 1-RTT secrets, which the engine wipes right
         * after this call - keep both (6.1) */
        memcpy(q->ap_secret[is_send ? 1 : 0], secret, len);
        q->ap_len = (uint8_t)len;
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
 * acted on only at CONNECTED, when they are authenticated - except ack_delay_exponent and
 * max_ack_delay, which only scale our RTT estimate (RFC 9002 5.3). */
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

/* ------------------------------------------------------------------ records, CIDs ---------- */

/* The records rec_on_ack / rec_on_timeout marked: their retransmission state (RFC 9000 13.3). */
static void reap(brisk__quic_conn *q)
{
    unsigned i, j;
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        brisk__quic_sent *s = &q->rec.s[i];
        int acked = (s->flags & BRISK__QS_ACKED) != 0;
        if (!(s->flags & (BRISK__QS_ACKED | BRISK__QS_LOST))) {
            continue;
        }
        if (s->slot == BRISK__QS_CRYPTO && !acked && s->lvl < 2 && q->tx[s->lvl].suite != 0 &&
            s->off < q->ret_sent[s->lvl]) {
            q->ret_sent[s->lvl] = (size_t)s->off; /* 13.3: CRYPTO again from the lost offset */
        }
        if (s->flags & BRISK__QS_RETIRE) {
            for (j = 0; j < BRISK__QUIC_RETIRE; j++) {
                if (q->rq[j].state == 2 && q->rq[j].pn == s->pn) {
                    q->rq[j].state = acked ? 0 : 1; /* 13.3: resent until acknowledged */
                }
            }
        }
        if (s->lvl == 2) {
            brisk__quic_stream_record(q, s);
        }
        memset(s, 0, sizeof *s);
    }
}

/* Queue RETIRE_CONNECTION_ID for seq (5.1.2). 0 or CONNECTION_ID_LIMIT_ERROR. */
static uint64_t retire(brisk__quic_conn *q, uint64_t seq)
{
    unsigned j, used = 0, fr = BRISK__QUIC_RETIRE;
    for (j = 0; j < BRISK__QUIC_RETIRE; j++) {
        if (q->rq[j].state != 0 && q->rq[j].seq == seq) {
            return 0; /* 19.15: already done for that sequence number */
        }
        if (q->rq[j].state != 0) {
            used++;
        } else if (fr == BRISK__QUIC_RETIRE) {
            fr = j;
        }
    }
    /* 5.1.2 (SHOULD track 2 * limit; MAY error beyond it - taken) */
    if (used >= 2 * q->my_tp.active_connection_id_limit || fr == BRISK__QUIC_RETIRE) {
        return BRISK__QERR_CONNECTION_ID_LIMIT;
    }
    q->rq[fr].seq = seq;
    q->rq[fr].state = 1;
    return 0;
}

/* NEW_CONNECTION_ID (19.15, 5.1.1, 5.1.2). 0 or a QUIC error code. */
static uint64_t new_cid(brisk__quic_conn *q, uint64_t seq, uint64_t rpt, const uint8_t *cid,
                        size_t len, const uint8_t *token)
{
    brisk__quic_cid *e;
    unsigned i, active = 0, lo = BRISK__QUIC_CIDS;
    int dup = 0, cur = 0;
    uint64_t code;
    if (q->dcid_len == 0) {
        return BRISK__QERR_PROTOCOL_VIOLATION; /* 19.15 MUST: we send an empty DCID */
    }
    for (i = 0; i < BRISK__QUIC_CIDS; i++) {
        e = &q->cids[i];
        if (!e->used) {
            continue;
        }
        if (e->seq == seq) {
            /* 19.15: the same frame twice is not an error (MUST NOT); another CID or token
             * under the same number is (MAY, taken) */
            if (e->len != len || memcmp(e->cid, cid, len) != 0 || memcmp(e->token, token, 16)) {
                return BRISK__QERR_PROTOCOL_VIOLATION;
            }
            dup = 1;
        } else if (e->len == len && memcmp(e->cid, cid, len) == 0) {
            return BRISK__QERR_PROTOCOL_VIOLATION; /* the same CID under another number */
        }
    }
    if (rpt > q->rpt_max) {
        /* 5.1.2 (MUST): stop using and retire every CID below Retire Prior To, before the
         * new one is added; a Retire Prior To that does not grow is ignored (19.15 MUST) */
        q->rpt_max = rpt;
        for (i = 0; i < BRISK__QUIC_CIDS; i++) {
            e = &q->cids[i];
            if (e->used && e->seq < rpt) {
                code = retire(q, e->seq);
                if (code != 0) {
                    return code;
                }
                e->used = 0;
            }
        }
    }
    if (seq < q->rpt_max) {
        code = retire(q, seq); /* 19.15 (MUST): already below Retire Prior To */
        if (code != 0) {
            return code;
        }
    } else if (!dup) {
        for (i = 0; i < BRISK__QUIC_CIDS && q->cids[i].used; i++) {
        }
        if (i == BRISK__QUIC_CIDS) {
            return BRISK__QERR_CONNECTION_ID_LIMIT;
        }
        e = &q->cids[i];
        e->used = 1;
        e->seq = seq;
        e->len = (uint8_t)len;
        memcpy(e->cid, cid, len);
        memcpy(e->token, token, 16);
    }
    for (i = 0; i < BRISK__QUIC_CIDS; i++) {
        e = &q->cids[i];
        if (e->used) {
            active++;
            cur |= e->len == q->dcid_len && memcmp(e->cid, q->dcid, q->dcid_len) == 0;
            if (lo == BRISK__QUIC_CIDS || e->seq < q->cids[lo].seq) {
                lo = i;
            }
        }
    }
    /* 5.1.1 (MUST): more active CIDs than our active_connection_id_limit */
    if (active > q->my_tp.active_connection_id_limit) {
        return BRISK__QERR_CONNECTION_ID_LIMIT;
    }
    if (!cur && lo != BRISK__QUIC_CIDS) {
        /* 5.1.2: ours was retired - switch to the lowest active sequence number */
        memcpy(q->dcid, q->cids[lo].cid, q->cids[lo].len);
        q->dcid_len = q->cids[lo].len;
    }
    return 0;
}

/* ------------------------------------------------------------------ frames (12.4, 19) ----- */

/* Varints to skip for the frames that carry nothing for this client: DATA_BLOCKED 0x14,
 * STREAMS_BLOCKED 0x16 / 0x17 (their value is checked below) */
static const uint8_t QC_SKIP[0x1f] = {[0x14] = 1};

uint64_t brisk__quic_frames(brisk__quic_conn *q, unsigned lvl, const uint8_t *p, size_t len)
{
    const uint8_t *end, *t0, *cid;
    uint64_t type, a, b, c, i, code;
    int newly;
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
        if (q != NULL &&
            !(type == 0x00 || type == 0x02 || type == 0x03 || type == 0x1c || type == 0x1d)) {
            q->rx_elicit = 1; /* 13.2: everything but PADDING, ACK and CONNECTION_CLOSE */
        }
        switch (type) {
        case 0x00: /* PADDING (19.1) */
            break;
        case 0x01: /* PING (19.2) */
            if (q != NULL) {
                q->rx_elicit = 1;
            }
            break;
        case 0x02: /* ACK (19.3): parsed, applied to this space only (13.2.6) */
        case 0x03:
            if (q == NULL) {
                code =
                    brisk__quic_rec_on_ack(NULL, lvl, type == 0x03, &p, end, 0, 0, 0, 0, 0, NULL);
            } else {
                code = brisk__quic_rec_on_ack(&q->rec, lvl, type == 0x03, &p, end, q->tx_pn[lvl],
                                              (unsigned)q->peer_tp.ack_delay_exponent,
                                              (uint32_t)q->peer_tp.max_ack_delay, q->confirmed,
                                              q->now, &newly);
                if (code == 0) {
                    reap(q);
                    if (newly) {
                        q->burst_bytes = 0; /* 7.7: an ACK ends the burst */
                    }
                }
            }
            if (code != 0) {
                return code;
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
        case 0x07: /* NEW_TOKEN (19.7): an empty token is FRAME_ENCODING_ERROR; kept for no one
                    * (address validation tokens are M6 item 3) */
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
            QC_GET(c);
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
            if (q != NULL) {
                code = brisk__quic_stream_frame(q, c, a, p, (size_t)b, (int)(type & 1));
                if (code != 0) {
                    return code;
                }
            }
            p += (size_t)b;
            break;
        case 0x04: /* RESET_STREAM (19.4): id, code, final size */
        case 0x05: /* STOP_SENDING (19.5): id, code */
        case 0x11: /* MAX_STREAM_DATA (19.10): id, limit */
        case 0x15: /* STREAM_DATA_BLOCKED (19.13): id, limit */
            QC_GET(c);
            QC_GET(a);
            b = 0;
            if (type == 0x04) {
                QC_GET(b);
            }
            if (q != NULL) {
                code = brisk__quic_stream_ctl(q, type, c, a, b);
                if (code != 0) {
                    return code;
                }
            }
            break;
        case 0x10: /* MAX_DATA (19.9) */
            QC_GET(a);
            if (q != NULL) {
                brisk__quic_stream_limits(q, type, a);
            }
            break;
        case 0x18: /* NEW_CONNECTION_ID (19.15) */
            QC_GET(a);
            QC_GET(b);
            if (b > a || p == end || *p < 1 || *p > BRISK__QUIC_MAX_CID) {
                return BRISK__QERR_FRAME_ENCODING;
            }
            c = *p++;
            cid = p;
            QC_SKIPN(c + 16);
            if (q != NULL) {
                code = new_cid(q, a, b, cid, (size_t)c, cid + c);
                if (code != 0) {
                    return code;
                }
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
            if (q != NULL && type <= 0x13) {
                brisk__quic_stream_limits(q, type, a);
            }
            break;
        case 0x19: /* RETIRE_CONNECTION_ID (19.16): we issued only sequence 0, the DCID of every
                    * 1-RTT packet (MAY), and none at all with an empty SCID (MUST) */
            QC_GET(a);
            if (q != NULL) {
                return BRISK__QERR_PROTOCOL_VIOLATION;
            }
            break;
        case 0x1a: /* PATH_CHALLENGE (19.17): 8.2.2 (MUST) echo it in a PATH_RESPONSE */
            QC_SKIPN(8);
            if (q != NULL) {
                if (q->n_path_resp == 2) {
                    memcpy(q->path_resp[0], q->path_resp[1], 8); /* policy: drop the oldest */
                    q->n_path_resp = 1;
                }
                memcpy(q->path_resp[q->n_path_resp++], p - 8, 8);
            }
            break;
        case 0x1b: /* PATH_RESPONSE (19.18): never solicited - ignored (policy) */
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
            if (q != NULL && !q->confirmed) {
                /* RFC 9001 4.1.2: confirmed. 4.9.2 (MUST): discard the Handshake keys;
                 * RFC 9002 6.4: and that space's recovery state */
                q->confirmed = 1;
                brisk__quic_keys_wipe(&q->rx[1]);
                brisk__quic_keys_wipe(&q->tx[1]);
                brisk__secure_zero(q->ret[1], QC_RET1);
                q->ret_len[1] = q->ret_sent[1] = 0;
                brisk__quic_rec_discard(&q->rec, 1);
                brisk__quic_rxack_init(&q->rxa[1]);
                q->probe[1] = 0;
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
    return QC_RING + QC_BITS + QC_RET0 + QC_RET1 + QC_STREAMS;
}

int brisk__quic_conn_init(brisk__quic_conn *q, brisk__tls13_hs *hs, const brisk__quic_tp *tp,
                          const uint8_t *dcid, size_t dcid_len, const uint8_t *scid,
                          size_t scid_len, uint8_t *scratch, size_t scratch_len)
{
    uint8_t c[32], s[32];
    int rc;
    size_t i;
    /* RFC 9000 7.2 (MUST): the first DCID is at least 8 unpredictable bytes */
    if (q == NULL || hs == NULL || tp == NULL || !hs->cfg.quic || dcid == NULL || dcid_len < 8 ||
        dcid_len > BRISK__QUIC_MAX_CID || scid_len > BRISK__QUIC_MAX_CID ||
        (scid == NULL && scid_len != 0) || scratch == NULL ||
        scratch_len < brisk__quic_scratch_size()) {
        return BRISK_E_ARG;
    }
    /* 7.3 (MUST): initial_source_connection_id is the SCID of our first Initial */
    if (tp->iscid_len != scid_len || (scid_len != 0 && memcmp(tp->iscid, scid, scid_len) != 0)) {
        return BRISK_E_ARG;
    }
    /* The limits we advertise are what the rings can hold: a stream window <= the ring (so
     * FLOW_CONTROL_ERROR guards memory), a connection window <= all rings, stream credit <=
     * the slots, and CIDs <= the table (18.2: 2 at least) */
    if (tp->initial_max_stream_data_bidi_local > BRISK_QUIC_STREAM_BUF ||
        tp->initial_max_stream_data_bidi_remote > BRISK_QUIC_STREAM_BUF ||
        tp->initial_max_stream_data_uni > BRISK_QUIC_STREAM_BUF ||
        tp->initial_max_data > (uint64_t)BRISK_QUIC_MAX_STREAMS * BRISK_QUIC_STREAM_BUF ||
        tp->initial_max_streams_bidi > BRISK_QUIC_MAX_STREAMS ||
        tp->initial_max_streams_uni > BRISK_QUIC_MAX_STREAMS ||
        tp->initial_max_streams_bidi + tp->initial_max_streams_uni > BRISK_QUIC_MAX_STREAMS ||
        tp->active_connection_id_limit < 2 || tp->active_connection_id_limit > BRISK__QUIC_CIDS ||
        tp->ack_delay_exponent > 20 || tp->max_ack_delay >= ((uint64_t)1 << 14)) {
        return BRISK_E_ARG;
    }
    memset(q, 0, sizeof *q);
    q->hs = hs;
    hs->cfg.on_secret = on_secret;
    hs->cfg.secret_ctx = q;
    hs->cfg.on_peer_tp = on_peer_tp;
    hs->cfg.tp_ctx = q;
    q->my_tp = *tp;
    brisk__quic_tp_default(&q->peer_tp);
    memcpy(q->dcid, dcid, dcid_len);
    memcpy(q->odcid, dcid, dcid_len);
    q->dcid_len = q->odcid_len = (uint8_t)dcid_len;
    if (scid_len != 0) {
        memcpy(q->scid, scid, scid_len);
    }
    q->scid_len = (uint8_t)scid_len;
    for (i = 0; i < 3; i++) {
        q->rx_largest[i] = QC_NONE;
        brisk__quic_rxack_init(&q->rxa[i]);
    }
    brisk__quic_rec_init(&q->rec);
    q->idle_start = INT64_MIN;
    q->idle_rx = 1;
    q->burst_t = -1;
    memset(scratch, 0, brisk__quic_scratch_size());
    q->ring = scratch;
    q->bits = scratch + QC_RING;
    q->ret[0] = q->bits + QC_BITS;
    q->ret[1] = q->ret[0] + QC_RET0;
    q->srings = q->ret[1] + QC_RET1;
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

/* RFC 9000 7.3 (MUST): the server's CIDs as authenticated by the handshake */
static int cids_ok(const brisk__quic_conn *q)
{
    const brisk__quic_tp *t = &q->peer_tp;
    return q->tp_seen && t->has_odcid && t->odcid_len == q->odcid_len &&
           memcmp(t->odcid, q->odcid, q->odcid_len) == 0 && t->has_iscid &&
           t->iscid_len == q->dcid_len && memcmp(t->iscid, q->dcid, q->dcid_len) == 0 &&
           !t->has_retry_scid; /* no Retry was received (Retry is M6 item 3) */
}

static uint32_t peer_mad(const brisk__quic_conn *q)
{
    return (uint32_t)q->peer_tp.max_ack_delay;
}

/* RFC 9000 10.1: min of the non-zero max_idle_timeouts, at least 3 * PTO. INT64_MAX = none. */
static int64_t idle_deadline(const brisk__quic_conn *q)
{
    uint64_t t = q->my_tp.max_idle_timeout, p = q->established ? q->peer_tp.max_idle_timeout : 0;
    uint32_t pto3;
    if (p != 0 && (t == 0 || p < t)) {
        t = p;
    }
    if (t == 0 || q->idle_start == INT64_MIN) {
        return INT64_MAX;
    }
    pto3 = brisk__quic_rec_pto(&q->rec, q->confirmed ? 2 : 1, peer_mad(q));
    pto3 = pto3 + (pto3 << 1); /* pto <= 2^27: no overflow */
    if (t > UINT32_MAX) {
        t = UINT32_MAX;
    }
    return brisk__quic_tadd(q->idle_start, (uint32_t)t > pto3 ? (uint32_t)t : pto3);
}

static int64_t rec_deadline(const brisk__quic_conn *q, unsigned *lvl)
{
    return brisk__quic_rec_deadline(&q->rec, lvl, q->confirmed, q->tx[1].suite != 0, peer_mad(q));
}

/* Sans-I/O time: never backwards (clamped to the last value seen), never below 0. */
static void set_now(brisk__quic_conn *q, int64_t now)
{
    if (now > q->now) {
        q->now = now;
    }
}

/* The due timers (RFC 9000 10.1, RFC 9002 6): idle expiry closes silently; the loss / PTO
 * timer runs once. */
static void run_timers(brisk__quic_conn *q)
{
    unsigned lvl = 0, k, i;
    uint64_t lo;
    if (q->err != 0) {
        return;
    }
    if (idle_deadline(q) <= q->now) {
        /* 10.1 / 10.2.1: silently closed - no CONNECTION_CLOSE, all state discarded */
        q_end(q, BRISK__QERR_NO_ERROR, BRISK_E_TIMEOUT, 0);
        return;
    }
    if (rec_deadline(q, &lvl) > q->now) {
        return;
    }
    k = brisk__quic_rec_on_timeout(&q->rec, q->now, &lvl, q->confirmed, q->tx[1].suite != 0,
                                   peer_mad(q));
    if (k != 0 && q->tx[lvl].suite != 0) {
        q->probe[lvl] = (uint8_t)(q->probe[lvl] + k > 2 ? 2 : q->probe[lvl] + k);
        if (lvl < 2) {
            /* 6.2.4 (SHOULD): the probe carries the unacknowledged CRYPTO data */
            lo = QC_NONE;
            for (i = 0; i < BRISK__QUIC_SENT; i++) {
                const brisk__quic_sent *s = &q->rec.s[i];
                if ((s->flags & BRISK__QS_USED) && s->lvl == lvl && s->slot == BRISK__QS_CRYPTO &&
                    s->off < lo) {
                    lo = s->off;
                }
            }
            if (lo < q->ret_sent[lvl]) {
                q->ret_sent[lvl] = (size_t)lo;
            }
        }
    }
    reap(q);
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
         (h->scid_len != q->server_scid_len ||
          memcmp(h->scid, q->server_scid, h->scid_len) != 0)) ||
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
    /* key phase flip = key update (M6 item 3): dropped. 12.3 / 13.2.3: duplicates (and PNs
     * below what we still track), after protection. */
    if ((!is_long && (first & 0x04)) || brisk__quic_rxack_dup(&q->rxa[lvl], pn)) {
        return BRISK_OK;
    }
    if (q->rx_largest[lvl] == QC_NONE || pn > q->rx_largest[lvl]) {
        q->rx_largest[lvl] = pn;
    }
    if (lvl == 0 && !q->got_initial) {
        /* 7.2 (MUST): switch to the SCID of the first server Initial */
        memcpy(q->dcid, h->scid, h->scid_len);
        q->dcid_len = h->scid_len;
        memcpy(q->server_scid, h->scid, h->scid_len);
        q->server_scid_len = h->scid_len;
        q->got_initial = 1;
    }
    q->rx_elicit = 0;
    code = brisk__quic_frames(q, lvl, pkt + po, pl);
    if (q->err != 0) {
        wipe_all(q); /* the peer closed: draining, no CONNECTION_CLOSE back */
        return q->err;
    }
    if (code != 0) {
        return q_fail(q, code, fail_rc(q), 0);
    }
    /* 13.2.1: Initial / Handshake at once, 1-RTT within our max_ack_delay */
    brisk__quic_rxack_add(&q->rxa[lvl], pn, q->rx_elicit, q->now,
                          lvl == 2 ? (int64_t)q->my_tp.max_ack_delay : 0, lvl < 2);
    q->idle_start = q->now; /* 10.1: restarted by every processed packet */
    q->idle_rx = 1;
    if (!q->established && q->hs->state == BRISK__HS_CONNECTED) {
        if (!cids_ok(q)) {
            return q_fail(q, BRISK__QERR_TRANSPORT_PARAMETER, BRISK_E_PROTO, 0);
        }
        q->established = 1;
        brisk__quic_streams_init(q);
        /* 5.1.1: the handshake's server CID is sequence 0 */
        q->cids[0].used = 1;
        q->cids[0].len = q->dcid_len;
        memcpy(q->cids[0].cid, q->dcid, q->dcid_len);
        memcpy(q->cids[0].token, q->peer_tp.reset_token, 16);
        if (q->peer_tp.has_pref_addr) { /* 5.1.1: preferred_address carries sequence 1 */
            q->cids[1].used = 1;
            q->cids[1].seq = 1;
            q->cids[1].len = q->peer_tp.pref_cid_len;
            memcpy(q->cids[1].cid, q->peer_tp.pref_cid, q->peer_tp.pref_cid_len);
            memcpy(q->cids[1].token, q->peer_tp.pref_token, 16);
        }
    }
    return BRISK_OK;
}

int brisk__quic_recv(brisk__quic_conn *q, uint8_t *dgram, size_t len, int64_t now_ms)
{
    brisk__quic_hdr h;
    size_t off = 0;
    int rc;
    if (q == NULL || (dgram == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    set_now(q, now_ms);
    run_timers(q);
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

int64_t brisk__quic_deadline(const brisk__quic_conn *q)
{
    int64_t t, d;
    unsigned lvl, i;
    if (q == NULL || q->err != 0) {
        return q != NULL && q->cc_state == 1 ? q->now : INT64_MAX;
    }
    if (q->probe[0] | q->probe[1] | q->probe[2] ||
        (q->n_path_resp != 0 && brisk__quic_rec_can_send(&q->rec, QC_DGRAM))) {
        return q->now; /* RFC 9002 6.2.4 / RFC 9000 8.2.2 (MUST): owed now, not at the next timer */
    }
    t = idle_deadline(q);
    d = rec_deadline(q, &lvl);
    t = d < t ? d : t;
    for (i = 0; i < 3; i++) { /* 13.2.1: an ACK owed */
        if (q->tx[i].suite != 0 && q->rxa[i].pending && q->rxa[i].ack_due < t) {
            t = q->rxa[i].ack_due;
        }
    }
    if (q->burst_bytes >= QC_BURST) {
        d = brisk__quic_tadd(q->burst_t, 1); /* RFC 9002 7.7: the pacing wait */
        t = d < t ? d : t;
    }
    return t;
}

/* ------------------------------------------------------------------ sending --------------- */

static size_t hdr_len(const brisk__quic_conn *q, unsigned lvl)
{
    /* long: byte0 version dcid_len dcid scid_len scid [token_len 0] Length(2); short: byte0 dcid */
    return lvl == 2 ? 1u + q->dcid_len
                    : 1u + 4 + 1 + q->dcid_len + 1 + q->scid_len + (lvl == 0) + 2;
}

/* RFC 9000 17.1 / A.2: the PN length for the next packet at lvl */
static unsigned pn_len(const brisk__quic_conn *q, unsigned lvl)
{
    return brisk__quic_pn_len(q->tx_pn[lvl], q->rec.largest_acked[lvl]);
}

/* Header + PN of pnl bytes + seal around payload_len bytes already at p + hdr_len + pnl.
 * Returns the packet length, 0 if the key refused (6.6 limit) or the PN space is spent (12.3). */
static size_t pkt_finish(brisk__quic_conn *q, unsigned lvl, uint8_t *p, size_t payload_len,
                         unsigned pnl)
{
    size_t hl = hdr_len(q, lvl), i = 0;
    if (q->tx_pn[lvl] >= BRISK__QUIC_VARINT_MAX) {
        return 0; /* 12.3 (MUST): PN 2^62-1 is never used - close silently */
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

/* RFC 9000 10.2.3: CONNECTION_CLOSE of `type` in every level we still hold send keys for -
 * 0x1c at Initial and Handshake while unsure what the server has, 1-RTT once it exists; 0x1d
 * (an application close) in 1-RTT only - coalesced, the last packet padded to 1200 when an
 * Initial is in it (14.1). No reason phrase; frame type 0. */
static size_t cc_build(brisk__quic_conn *q, uint8_t *out, unsigned type)
{
    size_t pos = 0, hl, pl, w, n;
    unsigned lvl, last = 3, pnl;
    for (lvl = 0; lvl < 3; lvl++) {
        if (q->tx[lvl].suite != 0 && q->tx_pn[lvl] < BRISK__QUIC_VARINT_MAX &&
            (type == 0x1c || lvl == 2)) {
            last = lvl;
        }
    }
    for (lvl = 0; lvl < 3 && last != 3; lvl++) {
        if (q->tx[lvl].suite == 0 || q->tx_pn[lvl] >= BRISK__QUIC_VARINT_MAX ||
            (type == 0x1d && lvl != 2)) {
            continue;
        }
        hl = hdr_len(q, lvl);
        pnl = pn_len(q, lvl);
        w = pos + hl + pnl;
        out[w] = (uint8_t)type;
        pl = 1 + brisk__quic_varint_put(out + w + 1, 8, q->err_code);
        if (type == 0x1c) {
            out[w + pl++] = 0x00; /* Frame Type */
        }
        out[w + pl++] = 0x00; /* Reason Phrase Length */
        if (lvl == last && q->tx[0].suite != 0 && pos + hl + pnl + pl + 16 < QC_DGRAM) {
            n = QC_DGRAM - (pos + hl + pnl + pl + 16);
            memset(out + w + pl, 0, n); /* PADDING */
            pl += n;
        }
        n = pkt_finish(q, lvl, out + pos, pl, pnl);
        if (n == 0) {
            break;
        }
        pos += n;
    }
    return pos;
}

int brisk__quic_close(brisk__quic_conn *q, uint64_t app_err)
{
    if (q == NULL || app_err > BRISK__QUIC_VARINT_MAX) {
        return BRISK_E_ARG;
    }
    if (q->err != 0) {
        return q->err;
    }
    /* 10.2.3 (MUST NOT): no application error code in Initial / Handshake packets - there it
     * is APPLICATION_ERROR in a 0x1c frame */
    if (q->established) {
        q_end(q, app_err, BRISK_E_ARG, 0x1d);
    } else {
        q_end(q, BRISK__QERR_APPLICATION, BRISK_E_ARG, 0x1c);
    }
    return BRISK_OK;
}

/* The ack-eliciting frames of one packet at lvl into w (room bytes); fills the record. */
static size_t elicit_frames(brisk__quic_conn *q, unsigned lvl, uint8_t *w, size_t room,
                            brisk__quic_sent *s, int *pad)
{
    size_t n = 0, fo, k;
    uint64_t off;
    unsigned j;
    if (lvl < 2) {
        /* CRYPTO (19.6) from the first byte not sent yet (or lost, 13.3) */
        off = q->ret_sent[lvl];
        fo = 1 + brisk__quic_varint_put(NULL, 0, off) + 2; /* type, offset, length (<= 2) */
        if (q->ret_sent[lvl] < q->ret_len[lvl] && room > fo) {
            k = q->ret_len[lvl] - q->ret_sent[lvl];
            k = k < room - fo ? k : room - fo;
            w[n++] = 0x06;
            n += brisk__quic_varint_put(w + n, 8, off);
            n += brisk__quic_varint_put(w + n, 8, k);
            memcpy(w + n, q->ret[lvl] + q->ret_sent[lvl], k);
            n += k;
            q->ret_sent[lvl] += k;
            s->slot = BRISK__QS_CRYPTO;
            s->off = off;
            s->len = (uint16_t)k;
        }
    } else {
        /* PATH_RESPONSE (19.18): each challenge answered once, never retransmitted (13.3) */
        while (q->n_path_resp != 0 && room - n >= 9) {
            w[n++] = 0x1b;
            memcpy(w + n, q->path_resp[0], 8);
            n += 8;
            memcpy(q->path_resp[0], q->path_resp[1], 8);
            brisk__secure_zero(q->path_resp[1], 8);
            q->n_path_resp--;
            *pad = 1; /* 8.2.2 (MUST): in a datagram of at least 1200 bytes */
        }
        /* RETIRE_CONNECTION_ID (19.16) */
        for (j = 0; j < BRISK__QUIC_RETIRE; j++) {
            if (q->rq[j].state == 1 &&
                1 + brisk__quic_varint_put(NULL, 0, q->rq[j].seq) <= room - n) {
                w[n++] = 0x19;
                n += brisk__quic_varint_put(w + n, 8, q->rq[j].seq);
                q->rq[j].state = 2;
                q->rq[j].pn = s->pn;
                s->flags |= BRISK__QS_RETIRE;
            }
        }
        n += brisk__quic_stream_out(q, w + n, room - n, 0, s);
    }
    if (n == 0 && q->probe[lvl] != 0) {
        w[n++] = 0x01; /* PING (19.2): 6.2.4 (MUST) a probe is ack-eliciting */
    }
    return n;
}

typedef struct {
    size_t pos, pl;
    unsigned lvl, pnl;
    int elicit, inflight;
    brisk__quic_sent s;
} qc_pkt;

size_t brisk__quic_send(brisk__quic_conn *q, uint8_t *out, size_t cap, int64_t now_ms)
{
    uint8_t tmp[512];
    unsigned e, lvl, np = 0, free_recs, i, pnl;
    size_t n, hl, room, pos = 0, ackn, el, w;
    int cc_ok, pad = 0, elicited = 0, handshake = 0;
    qc_pkt pk[3];
    if (q == NULL || out == NULL || cap < QC_DGRAM) {
        return 0;
    }
    set_now(q, now_ms);
    run_timers(q);
    if (q->err == 0) {
        /* the engine's CRYPTO output joins the level's send stream, kept for retransmission */
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
    if (q->now != q->burst_t) {
        q->burst_t = q->now;
        q->burst_bytes = 0;
    }
    if (q->burst_bytes >= QC_BURST) {
        return 0; /* RFC 9002 7.7: burst limit - the deadline says when */
    }
    free_recs = brisk__quic_rec_free(&q->rec);
    /* RFC 9002 7 (MUST NOT): nothing ack-eliciting past the window; a whole datagram's worth
     * is checked, so the padded size is covered too. Probes (7.5) and ACK-only packets are
     * exempt. */
    cc_ok = brisk__quic_rec_can_send(&q->rec, QC_DGRAM);
    /* RFC 9000 12.2: one packet per level, Initial -> Handshake -> 1-RTT, in one datagram */
    for (lvl = 0; lvl < 3; lvl++) {
        if (q->tx[lvl].suite == 0 || (lvl == 2 && !q->established)) {
            continue;
        }
        hl = hdr_len(q, lvl);
        pnl = pn_len(q, lvl);
        if (pos + hl + pnl + 16 + QC_MIN_ROOM > QC_DGRAM) {
            break;
        }
        w = pos + hl + pnl;
        room = QC_DGRAM - w - 16;
        memset(&pk[np], 0, sizeof pk[np]);
        pk[np].s.pn = q->tx_pn[lvl];
        pk[np].s.lvl = (uint8_t)lvl;
        pk[np].s.slot = BRISK__QS_NONE;
        /* 13.2.1: an ACK when one is owed; 13.2.1 SHOULD: piggybacked whenever pending */
        ackn = 0;
        if (q->rxa[lvl].pending != 0) {
            ackn = brisk__quic_ack_write(
                &q->rxa[lvl],
                brisk__quic_ack_delay_field(q->now - q->rxa[lvl].largest_t,
                                            (unsigned)q->my_tp.ack_delay_exponent),
                out + w, room);
        }
        el = 0;
        /* the last two records are the PTO probes' (RFC 9002 6.2.4 MUST), so a full table
         * cannot stall recovery */
        if ((cc_ok && free_recs > 2) || (q->probe[lvl] != 0 && free_recs != 0)) {
            el = elicit_frames(q, lvl, out + w + ackn, room - ackn, &pk[np].s, &pad);
        }
        /* 13.2.1 (MUST NOT): an ACK-only packet only when one is due */
        if (el == 0 && (ackn == 0 || q->rxa[lvl].ack_due > q->now)) {
            continue;
        }
        if (el == 0 && (pad || lvl == 0)) {
            /* it may end the datagram and be padded, so in flight (RFC 9002 2): it needs a
             * record that is not a probe's; otherwise the ACK waits */
            if (free_recs <= 2) {
                continue;
            }
            free_recs--;
        }
        n = ackn + el;
        if (pnl + n < 4) {
            memset(out + w + n, 0, 4 - pnl - n); /* RFC 9001 5.4.2: room for the HP sample */
            n = 4 - pnl;
        }
        if (ackn != 0) {
            q->rxa[lvl].pending = 0;
            q->rxa[lvl].ack_due = INT64_MAX;
        }
        if (el != 0) {
            free_recs--;
            elicited = 1;
            if (q->probe[lvl] != 0) {
                q->probe[lvl]--;
            }
        }
        pad |= lvl == 0; /* RFC 9000 14.1 (MUST): a datagram with an Initial is >= 1200 */
        pk[np].pos = pos;
        pk[np].pl = n;
        pk[np].lvl = lvl;
        pk[np].pnl = pnl;
        pk[np].elicit = el != 0;
        pk[np].inflight = el != 0;
        pos = w + n + 16;
        np++;
    }
    if (np == 0) {
        return 0;
    }
    if (pad && pos < QC_DGRAM) {
        /* PADDING at the end of the last packet (14.1, 8.2.2); a packet with PADDING is in
         * flight (RFC 9002 2) */
        i = np - 1;
        memset(out + pos - 16, 0, QC_DGRAM - pos);
        pk[i].pl += QC_DGRAM - pos;
        pk[i].inflight = 1;
        pos = QC_DGRAM;
    }
    for (i = 0; i < np; i++) {
        n = pkt_finish(q, pk[i].lvl, out + pk[i].pos, pk[i].pl, pk[i].pnl);
        if (n == 0) {
            /* 12.3: PN space spent, or 6.6: the key is used up - close without a frame */
            q_fail(q, BRISK__QERR_AEAD_LIMIT_REACHED, BRISK_E_ARG, 1);
            return 0;
        }
        if (pk[i].inflight) {
            pk[i].s.t = q->now;
            pk[i].s.size = (uint16_t)n;
            pk[i].s.flags |= (uint16_t)(BRISK__QS_INFLIGHT | (pk[i].elicit ? BRISK__QS_ELICIT : 0));
            (void)brisk__quic_rec_on_sent(&q->rec, &pk[i].s); /* one is always kept free */
        }
        handshake |= pk[i].lvl == 1;
    }
    if (handshake && q->tx[0].suite != 0) {
        /* RFC 9001 4.9.1 / RFC 9000 17.2.2.1 (MUST): the first Handshake packet sent ends the
         * Initial keys and the Initial CRYPTO state; RFC 9002 6.4: and its recovery state */
        brisk__quic_keys_wipe(&q->tx[0]);
        brisk__quic_keys_wipe(&q->rx[0]);
        brisk__secure_zero(q->ret[0], QC_RET0);
        q->ret_len[0] = q->ret_sent[0] = 0;
        brisk__quic_rec_discard(&q->rec, 0);
        if (!q->rec.hs_acked && q->rec.last_elicit[1] == INT64_MIN) {
            q->rec.last_elicit[1] = q->now; /* RFC 9002 6.2.2.1: anchor the anti-deadlock PTO */
        }
        brisk__quic_rxack_init(&q->rxa[0]);
        q->probe[0] = 0;
    }
    if (elicited && q->idle_rx) {
        q->idle_start = q->now; /* 10.1: the first ack-eliciting packet after a receive */
        q->idle_rx = 0;
    }
    q->burst_bytes += (uint32_t)pos;
    return pos;
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
#    undef QC_STREAMS
#    undef QC_BURST
#    undef QC_MIN_ROOM

#endif /* BRISK_ENABLE_QUIC */
