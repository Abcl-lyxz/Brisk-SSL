/* stream.c - QUIC streams and flow control for the client (RFC 9000 2, 3, 4, 19.4-19.14).
 * Fixed stream slots in brisk__quic_conn, their rings in the connection scratch: per slot a
 * receive ring of BRISK_QUIC_STREAM_BUF bytes + a bitmap of received bytes, and a send ring of
 * the same size. The flow-control window we advertise per stream never exceeds the receive
 * ring (conn_init refuses larger initial_max_stream_data_*, and every MAX_STREAM_DATA is
 * rx_read + window), so FLOW_CONTROL_ERROR is what keeps peer data inside the ring.
 *
 * Slot reservation: our MAX_STREAMS credit for the peer (my_max_streams - next_peer, per type)
 * always has free slots behind it; a local open needs a free slot beyond that reservation. So
 * the implicit opening of every lower peer stream (3.2 MUST) never runs out of slots. A peer
 * stream's slot, once freed, raises our MAX_STREAMS by one (4.6).
 *
 * Policy choices (MAY / SHOULD, recorded for the reviewers):
 *   - retransmission goes back to the lowest lost offset (13.3 allows any repacketization);
 *     acknowledgements are tracked as the acked prefix plus one range above it - an ACK that
 *     fits neither sends that data again (ponytail: no per-byte ack bitmap);
 *   - MAX_STREAM_DATA / MAX_DATA are sent once half a window has been consumed (4.2); the
 *     *_BLOCKED frames are never sent (4.1 / 4.6 SHOULD), received ones are only checked;
 *   - FINAL_SIZE_ERROR for every final-size change, data past it, or a final size below the
 *     highest offset received (4.5 SHOULD, taken);
 *   - RESET_STREAM, STREAM_DATA_BLOCKED for a locally initiated stream not yet opened are
 *     STREAM_STATE_ERROR like STREAM / STOP_SENDING / MAX_STREAM_DATA (19.4 / 19.13 name only
 *     the send-only case; 20.1 defines the error as "a frame for a stream that was not in a
 *     state that permitted that frame");
 *   - after STOP_SENDING the stream is reset even in "Data Sent" (3.5 MAY defer - not taken),
 *     with final size = the highest offset sent.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_QUIC

#    define QS_BUF  BRISK_QUIC_STREAM_BUF
#    define QS_SLOT (2 * BRISK_QUIC_STREAM_BUF + BRISK_QUIC_STREAM_BUF / 8)
#    define QS_N    BRISK_QUIC_MAX_STREAMS
#    define QS_NONE UINT64_MAX

enum {
    ST_USED = 0x0001,
    ST_RX = 0x0002,     /* has a receiving part */
    ST_TX = 0x0004,     /* has a sending part */
    ST_TX_FIN = 0x0008, /* the application ended the stream at tx_len */
    ST_FIN_SENT = 0x0010,
    ST_FIN_ACKED = 0x0020,
    ST_RX_RESET = 0x0040, /* RESET_STREAM received */
    ST_RX_DONE = 0x0080,  /* FIN or reset consumed by the application */
    ST_STOP = 0x0100,     /* STOP_SENDING received: we reset */
    ST_RST_PEND = 0x0200,
    ST_RST_ACKED = 0x0400,
    ST_MSD_PEND = 0x0800
};

static uint8_t *rx_ring(brisk__quic_conn *q, unsigned i)
{
    return q->srings + (size_t)i * QS_SLOT;
}

static uint8_t *rx_bits(brisk__quic_conn *q, unsigned i)
{
    return rx_ring(q, i) + QS_BUF;
}

static uint8_t *tx_ring(brisk__quic_conn *q, unsigned i)
{
    return rx_ring(q, i) + QS_BUF + QS_BUF / 8;
}

static size_t qs_vlen(uint64_t v)
{
    return brisk__quic_varint_put(NULL, 0, v);
}

/* Our receive window by stream type (2.1: bit 0 initiator, bit 1 direction) */
static uint64_t rx_window(const brisk__quic_conn *q, uint64_t id)
{
    switch (id & 3) {
    case 0:
        return q->my_tp.initial_max_stream_data_bidi_local;
    case 1:
        return q->my_tp.initial_max_stream_data_bidi_remote;
    default:
        return q->my_tp.initial_max_stream_data_uni;
    }
}

/* The peer's initial limit on what we send (18.2, from the peer's point of view) */
static uint64_t tx_limit(const brisk__quic_conn *q, uint64_t id)
{
    switch (id & 3) {
    case 0:
        return q->peer_tp.initial_max_stream_data_bidi_remote;
    case 1:
        return q->peer_tp.initial_max_stream_data_bidi_local;
    default:
        return q->peer_tp.initial_max_stream_data_uni;
    }
}

void brisk__quic_streams_init(brisk__quic_conn *q)
{
    memset(q->st, 0, sizeof q->st);
    q->max_data_tx = q->peer_tp.initial_max_data;
    q->max_data_rx = q->my_tp.initial_max_data;
    q->sent_tx = q->sum_rx = q->consumed = 0;
    q->peer_max_streams[0] = q->peer_tp.initial_max_streams_bidi;
    q->peer_max_streams[1] = q->peer_tp.initial_max_streams_uni;
    q->my_max_streams[0] = q->my_tp.initial_max_streams_bidi;
    q->my_max_streams[1] = q->my_tp.initial_max_streams_uni;
    q->md_pn = q->ms_pn[0] = q->ms_pn[1] = QS_NONE;
}

void brisk__quic_streams_wipe(brisk__quic_conn *q)
{
    if (q->srings != NULL) {
        brisk__secure_zero(q->srings, (size_t)QS_N * QS_SLOT);
    }
    brisk__secure_zero(q->st, sizeof q->st);
}

static int find(const brisk__quic_conn *q, uint64_t id)
{
    unsigned i;
    for (i = 0; i < QS_N; i++) {
        if ((q->st[i].flags & ST_USED) && q->st[i].id == id) {
            return (int)i;
        }
    }
    return -1;
}

static unsigned free_slots(const brisk__quic_conn *q)
{
    unsigned i, n = 0;
    for (i = 0; i < QS_N; i++) {
        n += !(q->st[i].flags & ST_USED);
    }
    return n;
}

/* Slots promised to the peer by our MAX_STREAMS credit */
static uint64_t reserved(const brisk__quic_conn *q)
{
    return (q->my_max_streams[0] - q->next_peer[0]) + (q->my_max_streams[1] - q->next_peer[1]);
}

static int alloc(brisk__quic_conn *q, uint64_t id)
{
    unsigned i;
    brisk__quic_stream *s;
    for (i = 0; i < QS_N; i++) {
        if (!(q->st[i].flags & ST_USED)) {
            break;
        }
    }
    if (i == QS_N) {
        return -1;
    }
    s = &q->st[i];
    memset(s, 0, sizeof *s);
    s->id = id;
    /* 2.1: client uni (2) is send-only, server uni (3) receive-only */
    s->flags = (uint16_t)(ST_USED | ((id & 3) != 2 ? ST_RX : 0) | ((id & 3) != 3 ? ST_TX : 0));
    s->rx_final = s->reset_pn = s->msd_pn = QS_NONE;
    s->rx_max = rx_window(q, id);
    s->tx_max = tx_limit(q, id);
    return (int)i;
}

static void maybe_free(brisk__quic_conn *q, unsigned i)
{
    brisk__quic_stream *s = &q->st[i];
    unsigned j, d;
    int tx_done = !(s->flags & ST_TX) || (s->flags & ST_RST_ACKED) ||
                  ((s->flags & ST_FIN_ACKED) && s->tx_base >= s->tx_len);
    int rx_done = !(s->flags & ST_RX) || (s->flags & ST_RX_DONE);
    if (!tx_done || !rx_done) {
        return;
    }
    if (s->id & 1) {
        /* 4.6: a peer stream is gone - its slot backs one more stream of credit */
        d = (unsigned)((s->id >> 1) & 1);
        q->my_max_streams[d]++;
        q->ms_pend[d] = 1;
    }
    for (j = 0; j < BRISK__QUIC_SENT; j++) {
        if (q->rec.s[j].slot == i) { /* records outlive the slot: detach them */
            q->rec.s[j].slot = BRISK__QS_NONE;
        }
    }
    brisk__secure_zero(rx_ring(q, i), QS_SLOT);
    brisk__secure_zero(s, sizeof *s);
}

int64_t brisk__quic_stream_open(brisk__quic_conn *q, int bidi)
{
    unsigned d = bidi ? 0 : 1;
    uint64_t id;
    if (q == NULL || q->err != 0 || !q->established) {
        return BRISK_E_ARG;
    }
    if (q->next_local[d] >= q->peer_max_streams[d]) {
        return BRISK_E_WANT; /* 4.6 (MUST NOT): past the peer's stream limit */
    }
    if ((uint64_t)free_slots(q) <= reserved(q)) {
        return BRISK_E_ARG; /* every free slot is promised to the peer */
    }
    id = (q->next_local[d] << 2) | (bidi ? 0 : 2);
    if (alloc(q, id) < 0) {
        return BRISK_E_ARG;
    }
    q->next_local[d]++;
    return (int64_t)id;
}

int brisk__quic_stream_accept(brisk__quic_conn *q, uint64_t *id)
{
    unsigned d;
    if (q == NULL || id == NULL) {
        return BRISK_E_ARG;
    }
    for (d = 0; d < 2; d++) {
        if (q->accepted[d] < q->next_peer[d]) {
            *id = (q->accepted[d] << 2) | (d ? 3 : 1);
            q->accepted[d]++;
            return BRISK_OK;
        }
    }
    return BRISK_E_WANT;
}

/* The slot a frame refers to (2.1, 3.2, 4.6). rx = the frame is about the peer's sending part
 * (STREAM, RESET_STREAM, STREAM_DATA_BLOCKED), else about ours (STOP_SENDING, MAX_STREAM_DATA).
 * 0 with *slot = -1 for a closed stream (a retransmission: ignored), or a QUIC error code. */
static uint64_t lookup(brisk__quic_conn *q, uint64_t id, int rx, int *slot)
{
    unsigned d = (unsigned)((id >> 1) & 1);
    uint64_t idx = id >> 2;
    *slot = -1;
    if (!(id & 1)) {
        /* 19.8 / 19.5 / 19.10 (MUST): a locally initiated stream not opened yet; 19.8 / 19.4 /
         * 19.13 (MUST): STREAM / RESET_STREAM / STREAM_DATA_BLOCKED on our send-only stream */
        if (idx >= q->next_local[d] || (rx && d == 1)) {
            return BRISK__QERR_STREAM_STATE;
        }
    } else {
        /* 19.5 / 19.10 (MUST): STOP_SENDING / MAX_STREAM_DATA on a receive-only stream */
        if (!rx && d == 1) {
            return BRISK__QERR_STREAM_STATE;
        }
        /* 4.6 (MUST): past the stream count we allowed */
        if (idx >= q->my_max_streams[d]) {
            return BRISK__QERR_STREAM_LIMIT;
        }
        /* 3.2 (MUST): opening stream N opens every lower one of its type */
        while (q->next_peer[d] <= idx) {
            if (alloc(q, (q->next_peer[d] << 2) | (id & 3)) < 0) {
                return BRISK__QERR_INTERNAL; /* the reservation makes this unreachable */
            }
            q->next_peer[d]++;
        }
    }
    *slot = find(q, id);
    return 0;
}

/* 4.1 / 4.5: the highest offset of a stream grows to `end`; the connection counts the sum.
 * 0 or FLOW_CONTROL_ERROR. */
static uint64_t rx_grow(brisk__quic_conn *q, brisk__quic_stream *s, uint64_t end)
{
    if (end > s->rx_max) {
        return BRISK__QERR_FLOW_CONTROL; /* 4.1 (MUST): past the stream's limit */
    }
    if (end > s->rx_hi) {
        q->sum_rx += end - s->rx_hi;
        s->rx_hi = end;
        if (q->sum_rx > q->max_data_rx) {
            return BRISK__QERR_FLOW_CONTROL; /* 4.1 (MUST): past the connection's limit */
        }
    }
    return 0;
}

/* 4.2: advertise more credit once half a window is consumed; the advertised limit never passes
 * consumed + window (window <= the ring for a stream) */
static void credit(brisk__quic_conn *q, brisk__quic_stream *s)
{
    uint64_t win = q->my_tp.initial_max_data, nl = q->consumed + win;
    if (nl > q->max_data_rx && nl - q->max_data_rx >= (win >> 1)) {
        q->max_data_rx = nl;
        q->md_pend = 1;
    }
    if (s == NULL || s->rx_final != QS_NONE) {
        return; /* the final size is known: no more MAX_STREAM_DATA (19.10) */
    }
    win = rx_window(q, s->id);
    nl = s->rx_read + win;
    if (nl > s->rx_max && nl - s->rx_max >= (win >> 1)) {
        s->rx_max = nl;
        s->flags |= ST_MSD_PEND;
    }
}

uint64_t brisk__quic_stream_frame(brisk__quic_conn *q, uint64_t id, uint64_t off, const uint8_t *d,
                                  size_t n, int fin)
{
    brisk__quic_stream *s;
    uint64_t end = off + n, code, o;
    uint8_t *ring, *bits;
    size_t j, pos;
    int i;
    code = lookup(q, id, 1, &i);
    if (code != 0 || i < 0) {
        return code;
    }
    s = &q->st[i];
    /* 4.5 (SHOULD): a final size that moves, or data past it */
    if (s->rx_final != QS_NONE && (end > s->rx_final || (fin && end != s->rx_final))) {
        return BRISK__QERR_FINAL_SIZE;
    }
    if (fin && end < s->rx_hi) {
        return BRISK__QERR_FINAL_SIZE; /* 4.5: below data already received */
    }
    code = rx_grow(q, s, end);
    if (code != 0) {
        return code;
    }
    if (fin) {
        s->rx_final = end;
    }
    if ((s->flags & (ST_RX_RESET | ST_RX_DONE)) || end <= s->rx_read) {
        return 0; /* reset or already consumed: a retransmission */
    }
    if (off < s->rx_read) {
        d += (size_t)(s->rx_read - off);
        off = s->rx_read;
    }
    ring = rx_ring(q, (unsigned)i);
    bits = rx_bits(q, (unsigned)i);
    /* end <= rx_max <= rx_read + QS_BUF: every byte has a ring slot */
    pos = s->rx_pos + (size_t)(off - s->rx_read);
    for (o = off, j = 0; o < end; o++, j++, pos++) {
        if (pos >= QS_BUF) {
            pos -= QS_BUF;
        }
        if (!(bits[pos >> 3] & (1u << (pos & 7)))) { /* overlapping data: the first copy wins */
            ring[pos] = d[j];
            bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
        }
    }
    return 0;
}

uint64_t brisk__quic_stream_ctl(brisk__quic_conn *q, uint64_t type, uint64_t id, uint64_t a,
                                uint64_t b)
{
    brisk__quic_stream *s;
    uint64_t code;
    int i, rx = type == 0x04 || type == 0x15;
    code = lookup(q, id, rx, &i);
    if (code != 0 || i < 0) {
        return code;
    }
    s = &q->st[i];
    switch (type) {
    case 0x04: /* RESET_STREAM (19.4): a = error code, b = final size */
        if ((s->rx_final != QS_NONE && b != s->rx_final) || b < s->rx_hi) {
            return BRISK__QERR_FINAL_SIZE; /* 4.5 */
        }
        code = rx_grow(q, s, b); /* 4.5 (MUST): the final size counts against the limits */
        if (code != 0) {
            return code;
        }
        s->rx_final = b;
        if (!(s->flags & (ST_RX_RESET | ST_RX_DONE))) {
            /* 4.4 / 3.2: Reset Recvd - the data is dropped, its connection credit released */
            s->flags |= ST_RX_RESET;
            s->rx_err = a;
            brisk__secure_zero(rx_ring(q, (unsigned)i), QS_BUF + QS_BUF / 8);
            q->consumed += b - s->rx_read;
            s->rx_read = b;
            credit(q, NULL);
        }
        break;
    case 0x05: /* STOP_SENDING (19.5): 3.5 (MUST) answer with RESET_STREAM */
        if (!(s->flags & (ST_STOP | ST_FIN_ACKED))) {
            s->flags |= ST_STOP | ST_RST_PEND;
            s->tx_err = a;
        }
        break;
    case 0x11: /* MAX_STREAM_DATA (19.10): 4.1 (MUST) a limit that does not grow is ignored */
        if (a > s->tx_max) {
            s->tx_max = a;
        }
        break;
    default: /* STREAM_DATA_BLOCKED (19.13): nothing to do beyond the checks */
        break;
    }
    return 0;
}

void brisk__quic_stream_limits(brisk__quic_conn *q, uint64_t type, uint64_t v)
{
    /* 4.1 / 4.6 (MUST): only an increase counts */
    if (type == 0x10) {
        q->max_data_tx = v > q->max_data_tx ? v : q->max_data_tx;
    } else {
        unsigned d = type == 0x13;
        q->peer_max_streams[d] = v > q->peer_max_streams[d] ? v : q->peer_max_streams[d];
    }
}

int brisk__quic_stream_write(brisk__quic_conn *q, uint64_t id, const uint8_t *d, size_t n, int fin)
{
    brisk__quic_stream *s;
    uint8_t *ring;
    size_t room, k, j, pos;
    int i;
    if (q == NULL || q->err != 0 || (d == NULL && n != 0)) {
        return BRISK_E_ARG;
    }
    i = find(q, id);
    if (i < 0 || !(q->st[i].flags & ST_TX) || (q->st[i].flags & ST_TX_FIN)) {
        return BRISK_E_ARG;
    }
    s = &q->st[i];
    if (s->flags & ST_STOP) {
        return BRISK_E_PEER_ALERT; /* the peer asked us to stop (3.5) */
    }
    room = QS_BUF - (size_t)(s->tx_len - s->tx_base);
    k = n < room ? n : room;
    ring = tx_ring(q, (unsigned)i);
    pos = s->tx_pos + (size_t)(s->tx_len - s->tx_base);
    for (j = 0; j < k; j++, pos++) {
        if (pos >= QS_BUF) {
            pos -= QS_BUF;
        }
        ring[pos] = d[j];
    }
    s->tx_len += k;
    if (fin && k == n) {
        s->flags |= ST_TX_FIN;
    }
    return (int)k;
}

int brisk__quic_stream_read(brisk__quic_conn *q, uint64_t id, uint8_t *out, size_t cap,
                            uint64_t *app_err)
{
    brisk__quic_stream *s;
    uint8_t *ring, *bits;
    size_t n = 0, pos;
    int i;
    if (q == NULL || app_err == NULL || (out == NULL && cap != 0)) {
        return BRISK_E_ARG;
    }
    i = find(q, id);
    if (i < 0 || !(q->st[i].flags & ST_RX)) {
        return BRISK_E_ARG;
    }
    s = &q->st[i];
    if (s->flags & ST_RX_RESET) {
        *app_err = s->rx_err; /* 19.4: the peer abandoned the stream */
        s->flags |= ST_RX_DONE;
        maybe_free(q, (unsigned)i);
        return BRISK_E_PEER_ALERT;
    }
    if (s->flags & ST_RX_DONE) {
        return 0;
    }
    ring = rx_ring(q, (unsigned)i);
    bits = rx_bits(q, (unsigned)i);
    pos = s->rx_pos;
    while (n < cap && n < QS_BUF && (bits[pos >> 3] & (1u << (pos & 7)))) {
        out[n++] = ring[pos];
        ring[pos] = 0;
        bits[pos >> 3] &= (uint8_t)~(1u << (pos & 7));
        pos = pos + 1 == QS_BUF ? 0 : pos + 1;
    }
    s->rx_pos = (uint32_t)pos;
    s->rx_read += n;
    q->consumed += n;
    if (n == 0) {
        if (s->rx_final == s->rx_read) {
            s->flags |= ST_RX_DONE; /* FIN consumed */
            maybe_free(q, (unsigned)i);
            return 0;
        }
        return BRISK_E_WANT;
    }
    credit(q, s);
    return (int)n;
}

/* ------------------------------------------------------------------ sending --------------- */

size_t brisk__quic_stream_out(brisk__quic_conn *q, uint8_t *out, size_t room, int ctl_only,
                              brisk__quic_sent *r)
{
    size_t w = 0, need, n, j, pos, hdr;
    uint64_t v, avail, conn;
    unsigned i, d;
    brisk__quic_stream *s;
    int fin;
    /* RESET_STREAM (19.4): code and final size never change once chosen (13.3 MUST NOT) */
    for (i = 0; i < QS_N; i++) {
        s = &q->st[i];
        if (!(s->flags & ST_RST_PEND)) {
            continue;
        }
        need = 1 + qs_vlen(s->id) + qs_vlen(s->tx_err) + qs_vlen(s->tx_hi);
        if (need > room - w) {
            continue;
        }
        out[w++] = 0x04;
        w += brisk__quic_varint_put(out + w, 8, s->id);
        w += brisk__quic_varint_put(out + w, 8, s->tx_err);
        w += brisk__quic_varint_put(out + w, 8, s->tx_hi);
        s->flags &= (uint16_t)~ST_RST_PEND;
        s->reset_pn = r->pn;
        r->flags |= BRISK__QS_RESET;
    }
    if (q->md_pend && 1 + qs_vlen(q->max_data_rx) <= room - w) { /* MAX_DATA (19.9) */
        out[w++] = 0x10;
        w += brisk__quic_varint_put(out + w, 8, q->max_data_rx);
        q->md_pend = 0;
        q->md_pn = r->pn;
        r->flags |= BRISK__QS_MAXDATA;
    }
    for (i = 0; i < QS_N; i++) { /* MAX_STREAM_DATA (19.10) */
        s = &q->st[i];
        if (!(s->flags & ST_MSD_PEND)) {
            continue;
        }
        if (s->rx_final != QS_NONE || (s->flags & (ST_RX_RESET | ST_RX_DONE))) {
            s->flags &= (uint16_t)~ST_MSD_PEND; /* nothing more will come */
            continue;
        }
        need = 1 + qs_vlen(s->id) + qs_vlen(s->rx_max);
        if (need > room - w) {
            continue;
        }
        out[w++] = 0x11;
        w += brisk__quic_varint_put(out + w, 8, s->id);
        w += brisk__quic_varint_put(out + w, 8, s->rx_max);
        s->flags &= (uint16_t)~ST_MSD_PEND;
        s->msd_pn = r->pn;
        r->flags |= BRISK__QS_MSD;
    }
    for (d = 0; d < 2; d++) { /* MAX_STREAMS (19.11) */
        if (q->ms_pend[d] && 1 + qs_vlen(q->my_max_streams[d]) <= room - w) {
            out[w++] = (uint8_t)(0x12 + d);
            w += brisk__quic_varint_put(out + w, 8, q->my_max_streams[d]);
            q->ms_pend[d] = 0;
            q->ms_pn[d] = r->pn;
            r->flags |= BRISK__QS_MAXSTR;
        }
    }
    if (ctl_only) {
        return w;
    }
    /* STREAM (19.8): one frame of the first stream with something to send */
    for (i = 0; i < QS_N; i++) {
        s = &q->st[i];
        if ((s->flags & (ST_TX | ST_STOP)) != ST_TX) {
            continue;
        }
        if (s->ack_hi != s->ack_lo && s->tx_next >= s->ack_lo && s->tx_next < s->ack_hi) {
            s->tx_next = s->ack_hi; /* the acked range above the prefix is not sent again */
        }
        /* 4.1 (MUST NOT): past the stream limit or, for new bytes, the connection limit */
        avail = s->tx_len < s->tx_max ? s->tx_len : s->tx_max;
        if (s->ack_hi != s->ack_lo && s->tx_next < s->ack_lo && s->ack_lo < avail) {
            avail = s->ack_lo; /* a retransmission stops where the acked range starts */
        }
        avail = avail > s->tx_next ? avail - s->tx_next : 0;
        conn = (s->tx_hi > s->tx_next ? s->tx_hi - s->tx_next : 0) + (q->max_data_tx - q->sent_tx);
        avail = avail < conn ? avail : conn;
        fin = (s->flags & (ST_TX_FIN | ST_FIN_SENT)) == ST_TX_FIN;
        if (avail == 0 && !(fin && s->tx_next == s->tx_len)) {
            continue;
        }
        /* type, id, offset when not 0, a length of up to 2 bytes */
        hdr = 1 + qs_vlen(s->id) + (s->tx_next != 0 ? qs_vlen(s->tx_next) : 0) + 2;
        if (hdr > room - w) {
            continue;
        }
        n = room - w - hdr;
        n = avail < n ? (size_t)avail : n;
        fin = fin && s->tx_next + n == s->tx_len;
        if (n == 0 && !fin) {
            continue;
        }
        out[w++] = (uint8_t)(0x08 | (s->tx_next != 0 ? 0x04 : 0) | 0x02 | (fin ? 0x01 : 0));
        w += brisk__quic_varint_put(out + w, 8, s->id);
        if (s->tx_next != 0) {
            w += brisk__quic_varint_put(out + w, 8, s->tx_next);
        }
        w += brisk__quic_varint_put(out + w, 8, n);
        pos = s->tx_pos + (size_t)(s->tx_next - s->tx_base);
        for (j = 0; j < n; j++, pos++) {
            if (pos >= QS_BUF) {
                pos -= QS_BUF;
            }
            out[w++] = tx_ring(q, i)[pos];
        }
        r->slot = (uint8_t)i;
        r->off = s->tx_next;
        r->len = (uint16_t)n;
        if (fin) {
            r->flags |= BRISK__QS_FIN;
            s->flags |= ST_FIN_SENT;
        }
        v = s->tx_next + n;
        if (v > s->tx_hi) {
            q->sent_tx += v - s->tx_hi;
            s->tx_hi = v;
        }
        s->tx_next = v;
        break;
    }
    return w;
}

/* The acked prefix moves to `to`; the freed send-ring bytes are wiped. */
static void tx_advance(brisk__quic_conn *q, unsigned i, uint64_t to)
{
    brisk__quic_stream *s = &q->st[i];
    uint8_t *ring = tx_ring(q, i);
    size_t pos = s->tx_pos;
    while (s->tx_base < to) {
        ring[pos] = 0;
        pos = pos + 1 == QS_BUF ? 0 : pos + 1;
        s->tx_base++;
    }
    s->tx_pos = (uint32_t)pos;
    if (s->tx_next < s->tx_base) {
        s->tx_next = s->tx_base;
    }
}

void brisk__quic_stream_record(brisk__quic_conn *q, const brisk__quic_sent *r)
{
    int acked = (r->flags & BRISK__QS_ACKED) != 0;
    uint64_t end = r->off + r->len;
    brisk__quic_stream *s;
    unsigned i, d;
    if (r->slot < QS_N && (q->st[r->slot].flags & ST_USED)) {
        i = r->slot;
        s = &q->st[i];
        if (acked) {
            if (r->flags & BRISK__QS_FIN) {
                s->flags |= ST_FIN_ACKED;
            }
            if (r->off <= s->tx_base) {
                if (end > s->tx_base) {
                    tx_advance(q, i, end);
                }
            } else if (s->ack_hi == s->ack_lo) {
                s->ack_lo = r->off; /* the one range above the prefix */
                s->ack_hi = end;
            } else if (r->off <= s->ack_hi && end >= s->ack_lo) {
                s->ack_lo = r->off < s->ack_lo ? r->off : s->ack_lo;
                s->ack_hi = end > s->ack_hi ? end : s->ack_hi;
            } else if (r->off < s->tx_next) {
                s->tx_next = r->off; /* no room to remember it: send it again (ponytail) */
            }
            if (s->ack_hi != s->ack_lo && s->ack_lo <= s->tx_base) {
                if (s->ack_hi > s->tx_base) {
                    tx_advance(q, i, s->ack_hi);
                }
                s->ack_lo = s->ack_hi = 0;
            }
        } else if (end > s->tx_base || (r->flags & BRISK__QS_FIN)) {
            /* 13.3: go back to the lowest lost offset (unless the stream was reset) */
            if (r->off < s->tx_next) {
                s->tx_next = r->off > s->tx_base ? r->off : s->tx_base;
            }
            if (r->flags & BRISK__QS_FIN) {
                s->flags &= (uint16_t)~ST_FIN_SENT;
            }
        }
        maybe_free(q, i);
    }
    if (r->flags & BRISK__QS_RESET) {
        for (i = 0; i < QS_N; i++) {
            s = &q->st[i];
            if ((s->flags & ST_USED) && s->reset_pn == r->pn && !(s->flags & ST_RST_ACKED)) {
                if (acked) {
                    s->flags |= ST_RST_ACKED;
                    maybe_free(q, i);
                } else {
                    s->flags |= ST_RST_PEND; /* 13.3: the same frame again */
                }
            }
        }
    }
    if (acked) {
        return;
    }
    /* 13.3: a lost MAX_* is sent again with the current value, unless a newer one went since */
    if ((r->flags & BRISK__QS_MSD)) {
        for (i = 0; i < QS_N; i++) {
            if ((q->st[i].flags & ST_USED) && q->st[i].msd_pn == r->pn) {
                q->st[i].flags |= ST_MSD_PEND;
            }
        }
    }
    if ((r->flags & BRISK__QS_MAXDATA) && q->md_pn == r->pn) {
        q->md_pend = 1;
    }
    if (r->flags & BRISK__QS_MAXSTR) {
        for (d = 0; d < 2; d++) {
            if (q->ms_pn[d] == r->pn) {
                q->ms_pend[d] = 1;
            }
        }
    }
}

#    undef QS_BUF
#    undef QS_SLOT
#    undef QS_N
#    undef QS_NONE

#endif /* BRISK_ENABLE_QUIC */
