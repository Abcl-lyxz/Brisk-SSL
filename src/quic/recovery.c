/* recovery.c - QUIC acknowledgements, loss detection and congestion control, as pure functions
 * over plain structs (RFC 9000 13.2, 19.3; RFC 9002 5-7, A, B). No callbacks, no clock (every
 * call takes now in ms), no malloc, no float, no division, no variable 64-bit shift: every
 * scaling is a loop of constant shifts or a shift/add constant, so 32-bit targets pull in no
 * libgcc helper. RTTs are uint32 ms clamped to 2^24; windows are uint32 bytes.
 *
 * Policy choices (MAY / SHOULD, recorded for the reviewers):
 *   - the ACK Delay of Initial ACKs is ignored (RFC 9002 5.3 MAY);
 *   - the loss of packets sent before the earliest acknowledged one is NOT ignored (7.4 MAY not
 *     taken: a congestion response is always safe);
 *   - persistent congestion looks at one space only (7.6.2 MAY) and at the ranges of the ACK
 *     frame that declared the losses: "no packet between them acknowledged" is decided against
 *     those ranges (a peer that drops old ranges, RFC 9000 13.2.4, can only make it
 *     conservative, since unknown gaps count as acknowledged);
 *   - one probe per PTO expiry (6.2.4 allows two); app-limited = a whole datagram would still
 *     have fit under cwnd when the ACK arrived (7.8: no growth then);
 *   - received PNs: 8 ranges plus a floor; the oldest range is forgotten when a ninth is needed
 *     and PNs below the floor are dropped as duplicates (RFC 9000 13.2.3). A PN that would open
 *     a new range below the lowest one while the table is full is dropped the same way;
 *   - ACK frames never shrink by 13.2.4 (optional): the range table bounds them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_QUIC

#    define QR_NONE    UINT64_MAX
#    define QR_RTT_MAX ((uint32_t)1 << 24)
#    define QR_US_MAX  ((uint64_t)1 << 40) /* ack delay saturation, about 12.7 days in us */
#    define QR_PTO_CAP 16

int64_t brisk__quic_tadd(int64_t t, uint32_t d)
{
    if (t > INT64_MAX - 1 - (int64_t)d) {
        return INT64_MAX - 1;
    }
    return t + (int64_t)d;
}

static size_t rec_vlen(uint64_t v)
{
    return brisk__quic_varint_put(NULL, 0, v);
}

/* ------------------------------------------------------------------ receive side (13.2) --- */

void brisk__quic_rxack_init(brisk__quic_rxack *a)
{
    memset(a, 0, sizeof *a);
    a->ack_due = INT64_MAX;
}

int brisk__quic_rxack_dup(const brisk__quic_rxack *a, uint64_t pn)
{
    unsigned i;
    if (pn < a->floor) {
        return 1; /* 13.2.3: below what we can still tell apart */
    }
    for (i = 0; i < a->n; i++) {
        if (pn >= a->r[i].lo && pn <= a->r[i].hi) {
            return 1; /* 12.3: a duplicate */
        }
    }
    /* full, and pn would open a ninth range below every other: no room to remember it */
    return a->n == BRISK__QUIC_RANGES && pn + 1 < a->r[a->n - 1].lo;
}

int brisk__quic_rxack_add(brisk__quic_rxack *a, uint64_t pn, int ack_eliciting, int64_t now,
                          int64_t max_delay_ms, int immediate)
{
    unsigned i, j;
    int gap, up, down;
    int64_t due;
    if (brisk__quic_rxack_dup(a, pn)) {
        return 1;
    }
    /* 13.2.1: out of order (below the largest) or after a gap (not largest + 1) */
    gap = a->n != 0 && (pn < a->r[0].hi || pn > a->r[0].hi + 1);
    if (a->n == 0 || pn > a->r[0].hi) {
        a->largest_t = now;
    }
    for (i = 0; i < a->n && a->r[i].hi > pn; i++) {
    }
    /* pn sits between r[i-1] (above) and r[i] (below) */
    up = i > 0 && a->r[i - 1].lo == pn + 1;
    down = i < a->n && a->r[i].hi + 1 == pn;
    if (up && down) {
        a->r[i - 1].lo = a->r[i].lo;
        for (j = i; j + 1 < a->n; j++) {
            a->r[j] = a->r[j + 1];
        }
        a->n--;
    } else if (up) {
        a->r[i - 1].lo = pn;
    } else if (down) {
        a->r[i].hi = pn;
    } else {
        if (i == BRISK__QUIC_RANGES) {
            return 1; /* below every range of a full table: _dup already refused it */
        }
        if (a->n == BRISK__QUIC_RANGES) {
            /* forget the oldest range; everything up to it now counts as seen (13.2.3) */
            a->floor = a->r[a->n - 1].hi + 1;
            a->n--;
        }
        for (j = a->n; j > i; j--) {
            a->r[j] = a->r[j - 1];
        }
        a->r[i].lo = a->r[i].hi = pn;
        a->n++;
    }
    if (ack_eliciting) {
        if (a->pending < 255) {
            a->pending++;
        }
        /* 13.2.1 / 13.2.2: at once for Initial / Handshake, a second packet or a gap; else
         * within max_ack_delay */
        due = immediate || a->pending >= 2 || gap
                  ? now
                  : brisk__quic_tadd(now, (uint32_t)(max_delay_ms < 0 ? 0 : max_delay_ms));
        if (due < a->ack_due) {
            a->ack_due = due;
        }
    }
    return 0;
}

size_t brisk__quic_ack_write(const brisk__quic_rxack *a, uint64_t delay_field, uint8_t *out,
                             size_t cap)
{
    size_t size, add, w;
    unsigned k, i;
    if (a->n == 0 || delay_field > BRISK__QUIC_VARINT_MAX) {
        return 0;
    }
    /* type, Largest, Delay, Range Count (<= 7: one byte), First Range */
    size = 1 + rec_vlen(a->r[0].hi) + rec_vlen(delay_field) + 1 + rec_vlen(a->r[0].hi - a->r[0].lo);
    if (size > cap) {
        return 0;
    }
    /* 13.2.3: the newest ranges first; the oldest are dropped when the frame does not fit */
    for (k = 1; k < a->n; k++) {
        add = rec_vlen(a->r[k - 1].lo - a->r[k].hi - 2) + rec_vlen(a->r[k].hi - a->r[k].lo);
        if (size + add > cap) {
            break;
        }
        size += add;
    }
    w = 0;
    out[w++] = 0x02;
    w += brisk__quic_varint_put(out + w, 8, a->r[0].hi);
    w += brisk__quic_varint_put(out + w, 8, delay_field);
    w += brisk__quic_varint_put(out + w, 8, k - 1);
    w += brisk__quic_varint_put(out + w, 8, a->r[0].hi - a->r[0].lo);
    for (i = 1; i < k; i++) {
        /* 19.3.1: Gap = previous smallest - this largest - 2 */
        w += brisk__quic_varint_put(out + w, 8, a->r[i - 1].lo - a->r[i].hi - 2);
        w += brisk__quic_varint_put(out + w, 8, a->r[i].hi - a->r[i].lo);
    }
    return w;
}

uint64_t brisk__quic_ack_delay_field(int64_t ms, unsigned exp)
{
    uint64_t m = QR_RTT_MAX, us;
    if (ms < (int64_t)QR_RTT_MAX) {
        m = ms < 0 ? 0 : (uint64_t)ms;
    }
    us = (m << 10) - (m << 4) - (m << 3); /* m * 1000 */
    while (exp-- != 0) {
        us >>= 1;
    }
    return us;
}

/* ------------------------------------------------------------------ sender state ---------- */

void brisk__quic_rec_init(brisk__quic_rec *r)
{
    unsigned i;
    memset(r, 0, sizeof *r);
    for (i = 0; i < 3; i++) {
        r->largest_acked[i] = QR_NONE;
        r->loss_time[i] = INT64_MAX;
        r->last_elicit[i] = INT64_MIN;
    }
    r->recovery_start = INT64_MIN;
    r->first_sample_t = INT64_MAX;
    r->srtt = 333; /* RFC 9002 6.2.2: kInitialRtt, rttvar = kInitialRtt / 2 */
    r->rttvar = 166;
    /* 7.2: min(10 * max_datagram_size, max(14720, 2 * max_datagram_size)) = 12000 */
    r->cwnd = 12000;
    r->ssthresh = UINT32_MAX;
}

static int outstanding(const brisk__quic_sent *s)
{
    return (s->flags & BRISK__QS_USED) && !(s->flags & (BRISK__QS_ACKED | BRISK__QS_LOST));
}

static int elicit_out(const brisk__quic_rec *r, unsigned lvl)
{
    unsigned i;
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        if (outstanding(&r->s[i]) && r->s[i].lvl == lvl && (r->s[i].flags & BRISK__QS_ELICIT)) {
            return 1;
        }
    }
    return 0;
}

unsigned brisk__quic_rec_free(const brisk__quic_rec *r)
{
    unsigned i, n = 0;
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        n += r->s[i].flags == 0;
    }
    return n;
}

int brisk__quic_rec_on_sent(brisk__quic_rec *r, const brisk__quic_sent *s)
{
    unsigned i;
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        if (r->s[i].flags == 0) {
            r->s[i] = *s;
            r->s[i].flags |= BRISK__QS_USED;
            if (s->flags & BRISK__QS_INFLIGHT) {
                r->in_flight += s->size;
            }
            if (s->flags & BRISK__QS_ELICIT) {
                r->last_elicit[s->lvl] = s->t;
            }
            return BRISK_OK;
        }
    }
    return BRISK_E_WANT;
}

int brisk__quic_rec_can_send(const brisk__quic_rec *r, size_t bytes)
{
    /* 7 (MUST NOT): nothing that would take bytes_in_flight past the window */
    return (uint64_t)r->in_flight + bytes <= r->cwnd;
}

uint32_t brisk__quic_rec_pto(const brisk__quic_rec *r, unsigned lvl, uint32_t peer_max_ack_delay)
{
    /* 6.2.1: smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay, the last only for the
     * application space; kGranularity = 1 ms */
    uint32_t v = r->rttvar << 2;
    return r->srtt + (v < 1 ? 1 : v) + (lvl == 2 ? peer_max_ack_delay : 0);
}

static uint32_t backoff(uint32_t d, unsigned n)
{
    while (n-- != 0) { /* 6.2.1 (MUST): doubles per expiry; constant shifts, saturating */
        d = d > 0x7fffffffu ? UINT32_MAX : d << 1;
    }
    return d;
}

/* Congestion event (B.6): at most one reduction per recovery period (7.3.2). */
static void congestion(brisk__quic_rec *r, int64_t sent_t, int64_t now)
{
    if (sent_t <= r->recovery_start) {
        return; /* sent before the period started: already reduced for it */
    }
    r->recovery_start = now;
    r->ssthresh = r->cwnd >> 1; /* kLossReductionFactor 0.5 */
    r->cwnd = r->ssthresh > BRISK__QUIC_MINWIN ? r->ssthresh : BRISK__QUIC_MINWIN;
    r->ca_acc = 0;
}

/* The ranges of the ACK frame being processed, for 7.6.2's "none acknowledged between". */
typedef struct {
    brisk__quic_range r[BRISK__QUIC_RANGES];
    unsigned n;
    int truncated; /* more ranges than kept: below r[n-1] nothing is known */
} acked_set;

static int acked_between(const acked_set *k, uint64_t a, uint64_t b)
{
    unsigned i;
    for (i = 0; i < k->n; i++) {
        if (k->r[i].lo < b && k->r[i].hi > a) {
            return 1;
        }
    }
    return k->truncated && a < k->r[k->n - 1].lo;
}

/* 7.6: persistent congestion among the packets just declared lost in `lvl` */
static int persistent(const brisk__quic_rec *r, unsigned lvl, uint32_t peer_max_ack_delay,
                      const acked_set *k)
{
    uint32_t v = r->rttvar << 2, dur;
    uint64_t last_pn = 0, prev_pn = 0;
    int64_t start = 0;
    unsigned i, best, seen = 0;
    if (!r->has_sample) {
        return 0;
    }
    /* (srtt + max(4 * rttvar, kGranularity) + max_ack_delay) * kPersistentCongestionThreshold 3 */
    dur = r->srtt + (v < 1 ? 1 : v) + peer_max_ack_delay;
    dur = dur + (dur << 1);
    for (;;) { /* the lost ack-eliciting packets in PN order: at most 32, selection by minimum */
        best = BRISK__QUIC_SENT;
        for (i = 0; i < BRISK__QUIC_SENT; i++) {
            const brisk__quic_sent *s = &r->s[i];
            if ((s->flags & (BRISK__QS_LOST | BRISK__QS_ELICIT)) ==
                    (BRISK__QS_LOST | BRISK__QS_ELICIT) &&
                s->lvl == lvl && s->t > r->first_sample_t && (!seen || s->pn > last_pn) &&
                (best == BRISK__QUIC_SENT || s->pn < r->s[best].pn)) {
                best = i;
            }
        }
        if (best == BRISK__QUIC_SENT) {
            return 0;
        }
        last_pn = r->s[best].pn;
        if (!seen || acked_between(k, prev_pn, last_pn)) {
            start = r->s[best].t; /* a new run: an acknowledged packet lies in between */
        } else if (r->s[best].t - start > (int64_t)dur) {
            return 1;
        }
        prev_pn = last_pn;
        seen = 1;
    }
}

/* A.10 DetectAndRemoveLostPackets for one space; k = the ACK's ranges, NULL from the timer */
static void detect_lost(brisk__quic_rec *r, unsigned lvl, int64_t now, uint32_t peer_max_ack_delay,
                        const acked_set *k)
{
    uint32_t x = r->latest_rtt > r->srtt ? r->latest_rtt : r->srtt, delay;
    uint64_t la = r->largest_acked[lvl];
    int64_t lost_send, last_loss = INT64_MIN, lt;
    unsigned i;
    int any = 0;
    r->loss_time[lvl] = INT64_MAX;
    if (la == QR_NONE) {
        return;
    }
    /* 6.1.2: max(kTimeThreshold 9/8 * max(smoothed_rtt, latest_rtt), kGranularity 1 ms) */
    delay = x + (x >> 3);
    delay = delay < 1 ? 1 : delay;
    lost_send = now - (int64_t)delay;
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        brisk__quic_sent *s = &r->s[i];
        if (!outstanding(s) || s->lvl != lvl || s->pn > la) {
            continue;
        }
        /* 6.1.1: kPacketThreshold 3; 6.1.2: the time threshold */
        if (s->t <= lost_send || la >= s->pn + 3) {
            s->flags |= BRISK__QS_LOST;
            if (s->flags & BRISK__QS_INFLIGHT) {
                r->in_flight -= s->size;
                last_loss = s->t > last_loss ? s->t : last_loss;
                any = 1;
            }
        } else {
            lt = brisk__quic_tadd(s->t, delay); /* 6.1.2 (SHOULD): arm for the rest */
            r->loss_time[lvl] = lt < r->loss_time[lvl] ? lt : r->loss_time[lvl];
        }
    }
    if (!any) {
        return;
    }
    congestion(r, last_loss, now);
    if (k != NULL && persistent(r, lvl, peer_max_ack_delay, k)) {
        /* 7.6.2 (MUST): back to kMinimumWindow; 5.2 (SHOULD): min_rtt = the latest sample */
        r->cwnd = BRISK__QUIC_MINWIN;
        r->recovery_start = INT64_MIN;
        r->ca_acc = 0;
        r->min_rtt = r->latest_rtt;
    }
}

/* RFC 9000 19.3: the ACK Delay field in ms, at the peer's exponent (<= 20), saturating */
uint32_t brisk__quic_ack_delay_ms(uint64_t field, unsigned exp)
{
    uint64_t us = field > QR_US_MAX ? QR_US_MAX : field, ms;
    while (exp-- != 0) {
        us = us >= QR_US_MAX ? QR_US_MAX : us << 1;
    }
    ms = (us >> 10) + (us >> 16) + (us >> 17); /* us / 1000, 0.05% low */
    return ms > QR_RTT_MAX ? QR_RTT_MAX : (uint32_t)ms;
}

/* A.7 UpdateRtt */
static void update_rtt(brisk__quic_rec *r, uint32_t lat, uint32_t ad, int confirmed,
                       uint32_t peer_max_ack_delay, int64_t now)
{
    uint32_t adj = lat, diff;
    r->latest_rtt = lat;
    if (!r->has_sample) {
        /* 5.3: the first sample */
        r->min_rtt = lat;
        r->srtt = lat;
        r->rttvar = lat >> 1;
        r->has_sample = 1;
        r->first_sample_t = now;
        return;
    }
    /* 5.2 (MUST): min_rtt without the ack delay */
    r->min_rtt = lat < r->min_rtt ? lat : r->min_rtt;
    /* 5.3: max_ack_delay bounds the delay once confirmed (MUST), not before (SHOULD) */
    if (confirmed && ad > peer_max_ack_delay) {
        ad = peer_max_ack_delay;
    }
    if (lat >= r->min_rtt + ad) { /* 5.3 (MUST NOT) go below min_rtt */
        adj = lat - ad;
    }
    diff = r->srtt > adj ? r->srtt - adj : adj - r->srtt;
    r->rttvar = (3 * r->rttvar + diff) >> 2;
    r->srtt = (7 * r->srtt + adj) >> 3;
}

#    define QR_GET(v)                                                                              \
        do {                                                                                       \
            if (!brisk__quic_varint_get(&q, end, &(v))) {                                          \
                return BRISK__QERR_FRAME_ENCODING;                                                 \
            }                                                                                      \
        } while (0)

/* Syntax pass (19.3, 19.3.1): 0 or the error; *p moves past the frame. */
static uint64_t ack_syntax(const uint8_t **p, const uint8_t *end, int ecn)
{
    const uint8_t *q = *p;
    uint64_t largest, delay, count, first, gap, len, i, lo;
    QR_GET(largest);
    QR_GET(delay);
    QR_GET(count);
    QR_GET(first);
    if (first > largest) {
        return BRISK__QERR_FRAME_ENCODING; /* 19.3.1: a negative packet number */
    }
    lo = largest - first;
    for (i = 0; i < count; i++) { /* each range takes >= 2 bytes: bounded by the packet */
        QR_GET(gap);
        if (gap > lo || lo - gap < 2) {
            return BRISK__QERR_FRAME_ENCODING; /* largest = smallest - gap - 2 < 0 */
        }
        QR_GET(len);
        if (len > lo - gap - 2) {
            return BRISK__QERR_FRAME_ENCODING;
        }
        lo = lo - gap - 2 - len;
    }
    if (ecn) { /* ECT0, ECT1, ECN-CE counts: parsed and ignored (we never set ECN) */
        QR_GET(gap);
        QR_GET(gap);
        QR_GET(gap);
    }
    *p = q;
    return 0;
}
#    undef QR_GET

typedef struct {
    int64_t largest_t;
    uint32_t acked_bytes;
    int newly, largest_newly, elicit;
} ack_stats;

static void mark_range(brisk__quic_rec *r, unsigned lvl, uint64_t lo, uint64_t hi, uint64_t largest,
                       int cwnd_limited, ack_stats *st, acked_set *k)
{
    unsigned i;
    if (k->n < BRISK__QUIC_RANGES) {
        k->r[k->n].lo = lo;
        k->r[k->n].hi = hi;
        k->n++;
    } else {
        k->truncated = 1;
    }
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        brisk__quic_sent *s = &r->s[i];
        if (!outstanding(s) || s->lvl != lvl || s->pn < lo || s->pn > hi) {
            continue;
        }
        s->flags |= BRISK__QS_ACKED;
        st->newly = 1;
        if (s->pn == largest) {
            st->largest_newly = 1;
            st->largest_t = s->t;
        }
        if (s->flags & BRISK__QS_ELICIT) {
            st->elicit = 1;
        }
        if (!(s->flags & BRISK__QS_INFLIGHT)) {
            continue;
        }
        /* B.5 OnPacketAcked */
        r->in_flight -= s->size;
        if (s->t <= r->recovery_start || !cwnd_limited) {
            continue; /* 7.3.2: no growth in recovery; 7.8: none while app-limited */
        }
        if (r->cwnd < r->ssthresh) {
            r->cwnd += s->size; /* 7.3.1 slow start */
        } else {
            /* 7.3.3 (MUST): at most one max_datagram_size per window acknowledged, by byte
             * counting (no division) */
            r->ca_acc += s->size;
            while (r->ca_acc >= r->cwnd) {
                r->ca_acc -= r->cwnd;
                r->cwnd += BRISK__QUIC_MDS;
            }
        }
    }
}

uint64_t brisk__quic_rec_on_ack(brisk__quic_rec *r, unsigned lvl, int ecn, const uint8_t **p,
                                const uint8_t *end, uint64_t next_pn, unsigned peer_ack_exp,
                                uint32_t peer_max_ack_delay, int confirmed, int64_t now, int *newly)
{
    const uint8_t *q = *p;
    uint64_t largest, delay, count, first, gap, len, i, lo, hi, code;
    ack_stats st;
    acked_set k;
    int cwnd_limited;
    int64_t lat;
    if (newly != NULL) {
        *newly = 0;
    }
    code = ack_syntax(p, end, ecn);
    if (code != 0 || r == NULL) {
        return code;
    }
    /* the syntax pass succeeded: these reads cannot fail */
    brisk__quic_varint_get(&q, end, &largest);
    brisk__quic_varint_get(&q, end, &delay);
    brisk__quic_varint_get(&q, end, &count);
    brisk__quic_varint_get(&q, end, &first);
    if (largest >= next_pn) {
        return BRISK__QERR_PROTOCOL_VIOLATION; /* RFC 9000 13.1 (SHOULD): never sent */
    }
    if (lvl == 1) {
        r->hs_acked = 1; /* 6.2.2.1: the server has validated our address */
    }
    memset(&st, 0, sizeof st);
    memset(&k, 0, sizeof k);
    cwnd_limited = (uint64_t)r->in_flight + BRISK__QUIC_MDS > r->cwnd;
    hi = largest;
    lo = largest - first;
    mark_range(r, lvl, lo, hi, largest, cwnd_limited, &st, &k);
    for (i = 0; i < count; i++) {
        brisk__quic_varint_get(&q, end, &gap);
        brisk__quic_varint_get(&q, end, &len);
        hi = lo - gap - 2;
        lo = hi - len;
        mark_range(r, lvl, lo, hi, largest, cwnd_limited, &st, &k);
    }
    if (r->largest_acked[lvl] == QR_NONE || largest > r->largest_acked[lvl]) {
        r->largest_acked[lvl] = largest;
    }
    if (!st.newly) {
        return 0; /* A.7: nothing newly acknowledged, nothing more to do */
    }
    if (newly != NULL) {
        *newly = 1;
    }
    /* 5.1 (MUST NOT otherwise): a sample only when the largest is newly acknowledged and at
     * least one newly acknowledged packet was ack-eliciting */
    if (st.largest_newly && st.elicit) {
        lat = now - st.largest_t;
        lat = lat<0 ? 0 : lat>(int64_t) QR_RTT_MAX ? (int64_t)QR_RTT_MAX : lat;
        update_rtt(r, (uint32_t)lat, lvl == 0 ? 0 : brisk__quic_ack_delay_ms(delay, peer_ack_exp),
                   confirmed, peer_max_ack_delay, now);
    }
    detect_lost(r, lvl, now, peer_max_ack_delay, &k);
    /* A.7 / 6.2.1: reset the backoff, but a client not on Initial ACKs (the server may not
     * have validated its address yet) */
    if (r->hs_acked || confirmed) {
        r->pto_count = 0;
    }
    return 0;
}

/* A.8 GetPtoTimeAndSpace (the loss-time timer is handled by the callers) */
static int64_t pto_time(const brisk__quic_rec *r, unsigned *lvl, int confirmed, int have_hs_keys,
                        uint32_t peer_max_ack_delay)
{
    uint32_t v = r->rttvar << 2, dur;
    int64_t t = INT64_MAX, tl, anchor = INT64_MIN;
    unsigned l;
    int any = elicit_out(r, 0) || elicit_out(r, 1) || elicit_out(r, 2);
    if (!any && (r->hs_acked || confirmed)) {
        return INT64_MAX; /* A.8: nothing in flight and the peer validated us: no timer */
    }
    dur = backoff(r->srtt + (v < 1 ? 1 : v), r->pto_count);
    if (!any) {
        /* 6.2.2.1 (MUST): the client arms the PTO with nothing in flight until the server
         * validated its address; ponytail: from the last ack-eliciting send, not "now" (the
         * sans-I/O deadline must not move with the query time) */
        for (l = 0; l < 3; l++) {
            anchor = r->last_elicit[l] > anchor ? r->last_elicit[l] : anchor;
        }
        *lvl = have_hs_keys ? 1 : 0;
        return anchor == INT64_MIN ? INT64_MAX : brisk__quic_tadd(anchor, dur);
    }
    for (l = 0; l < 3; l++) {
        if (!elicit_out(r, l)) {
            continue;
        }
        if (l == 2) {
            if (!confirmed) {
                break; /* 6.2.1 (MUST NOT): no application PTO before confirmation */
            }
            v = backoff(peer_max_ack_delay, r->pto_count);
            dur = dur > UINT32_MAX - v ? UINT32_MAX : dur + v;
        }
        tl = brisk__quic_tadd(r->last_elicit[l], dur);
        if (tl < t) {
            t = tl;
            *lvl = l;
        }
    }
    return t;
}

static int64_t loss_armed(const brisk__quic_rec *r, unsigned *lvl)
{
    int64_t t = INT64_MAX;
    unsigned l;
    for (l = 0; l < 3; l++) {
        if (r->loss_time[l] < t) {
            t = r->loss_time[l];
            *lvl = l;
        }
    }
    return t;
}

int64_t brisk__quic_rec_deadline(const brisk__quic_rec *r, unsigned *lvl, int confirmed,
                                 int have_hs_keys, uint32_t peer_max_ack_delay)
{
    unsigned l = 0;
    /* 6.2.1 (MUST NOT): no PTO while the loss-time timer is set */
    int64_t t = loss_armed(r, &l);
    if (t == INT64_MAX) {
        t = pto_time(r, &l, confirmed, have_hs_keys, peer_max_ack_delay);
    }
    *lvl = l;
    return t;
}

unsigned brisk__quic_rec_on_timeout(brisk__quic_rec *r, int64_t now, unsigned *lvl, int confirmed,
                                    int have_hs_keys, uint32_t peer_max_ack_delay)
{
    unsigned l = 0;
    if (loss_armed(r, &l) != INT64_MAX) {
        *lvl = l;
        detect_lost(r, l, now, peer_max_ack_delay, NULL); /* 6.1.2: a loss-time pass */
        return 0;
    }
    if (pto_time(r, &l, confirmed, have_hs_keys, peer_max_ack_delay) == INT64_MAX) {
        *lvl = 0;
        return 0;
    }
    /* 6.2: a PTO declares nothing lost (MUST NOT); 6.2.1: back off; 6.2.4: probe in that space */
    if (r->pto_count < QR_PTO_CAP) {
        r->pto_count++;
    }
    *lvl = l;
    return 1;
}

void brisk__quic_rec_discard(brisk__quic_rec *r, unsigned lvl)
{
    unsigned i;
    /* RFC 9002 6.4 (MUST): the space's packets leave bytes_in_flight; 6.2.2 / A.11: its loss
     * and PTO state is reset */
    for (i = 0; i < BRISK__QUIC_SENT; i++) {
        brisk__quic_sent *s = &r->s[i];
        if ((s->flags & BRISK__QS_USED) && s->lvl == lvl) {
            if (outstanding(s) && (s->flags & BRISK__QS_INFLIGHT)) {
                r->in_flight -= s->size;
            }
            memset(s, 0, sizeof *s);
        }
    }
    r->loss_time[lvl] = INT64_MAX;
    r->last_elicit[lvl] = INT64_MIN;
    r->pto_count = 0;
}

#    undef QR_NONE
#    undef QR_RTT_MAX
#    undef QR_US_MAX
#    undef QR_PTO_CAP

#endif /* BRISK_ENABLE_QUIC */
