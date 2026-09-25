/* api.c - the public QUIC v1 client (brisk_quic_*): sans-I/O glue over brisk__quic_conn and the
 * TLS front half of src/tls/conn.c (RFC 9000, RFC 9001).
 *
 * What lives here is only what the CONNECTION decides and neither engine can: our transport
 * parameters (internal defaults tied to the brisk_config.h knobs, RFC 9000 18.2), the
 * ClientHello over QUIC (no session id, RFC 9001 8.4; TLS 1.3 only, 4.2; the parameters, 8.2;
 * ALPN mandatory, 8.1), CH2 after a HelloRetryRequest, and the "send after every receive" rule
 * of brisk__quic_recv, hidden behind brisk_quic_deadline: every call that may leave a datagram
 * owed makes the deadline "now" until brisk_quic_pull has drained it.
 *
 * Blocking handles (src/os/linux_udp.c) install q->io; the stream calls then wait through it,
 * driving I/O for every stream while one waits. No syscall, malloc or clock here.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <limits.h>

#include "brisk_int.h"

#if BRISK_ENABLE_QUIC

#    define QA_CH_MAX 2048 /* conn.c CONN_CH_MAX: CH1 / CH2 are built in the stream rings */

struct qa_align_probe {
    char c;
    struct brisk_quic x;
};
#    define QA_ALIGN offsetof(struct qa_align_probe, x)

/* The ClientHello scratch: the stream rings, unused until the handshake completes (streams
 * exist only from establishment on; CH2 comes before it). The smallest knob setting leaves
 * 2 * (2 * 1024 + 128) bytes. */
#    if (BRISK_QUIC_MAX_STREAMS * (2 * BRISK_QUIC_STREAM_BUF + BRISK_QUIC_STREAM_BUF / 8)) <       \
        QA_CH_MAX
#        error "QUIC: the stream rings must hold a ClientHello"
#    endif

size_t brisk_quic_size(void)
{
    return (QA_ALIGN - 1) + sizeof(struct brisk_quic) + brisk__tls13_hs_scratch_size() +
           brisk__quic_scratch_size();
}

#    if BRISK_ENABLE_H3
/* 1 if the comma-separated ALPN list offers the exact token "h3" */
static int qa_offers_h3(const char *alpn)
{
    const char *p = alpn;
    while (*p != '\0') {
        const char *e = p;
        while (*e != '\0' && *e != ',') {
            e++;
        }
        if (e - p == 2 && p[0] == 'h' && p[1] == '3') {
            return 1;
        }
        p = *e == ',' ? e + 1 : e;
    }
    return 0;
}
#    endif

/* RFC 9000 18.2: our transport parameters. Every limit is what the memory holds (the
 * brisk__quic_conn_init ceilings): a stream window = one ring, the connection window = all
 * rings. No server-initiated bidi streams: useless to a client-only library (RFC 9114 6.1 makes
 * them an error for HTTP/3 too - here it is STREAM_LIMIT_ERROR). Server uni streams only when
 * the ALPN list offers "h3": RFC 9114 6.2 (MUST) lets the server open 3 (control, QPACK encoder
 * and decoder), each with a ring's worth of credit (>= 1024, SHOULD). Tied to the OFFER, so
 * hq-interop and every other ALPN stay byte-identical and keep all slots - that is a limit
 * sized to what we asked for, not protocol switching. max_udp_payload_size = the UDP driver's
 * receive buffer (18.2: never advertise more than we can receive). */
static void qa_tp(brisk__quic_tp *tp, const uint8_t *scid, const char *alpn)
{
    brisk__quic_tp_default(tp);
    tp->max_idle_timeout = 30000;
    tp->max_udp_payload_size = BRISK__QUIC_RX_MAX;
    tp->initial_max_data = (uint64_t)BRISK_QUIC_MAX_STREAMS * BRISK_QUIC_STREAM_BUF;
    tp->initial_max_stream_data_bidi_local = BRISK_QUIC_STREAM_BUF;
#    if BRISK_ENABLE_H3
    if (qa_offers_h3(alpn)) {
        tp->initial_max_stream_data_uni = BRISK_QUIC_STREAM_BUF;
        tp->initial_max_streams_uni = 3;
    }
#    else
    (void)alpn;
#    endif
    memcpy(tp->iscid, scid, 8); /* 7.3 */
    tp->iscid_len = 8;
}

int brisk__quic_setup(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                      int64_t wall_ms, const uint8_t rnd[BRISK__QUIC_RAND],
                      brisk__x509_anchor_fn sys_anchor, const uint16_t *suites, size_t n_suites,
                      brisk_quic **out)
{
    brisk__quic_tp tp;
    brisk_quic *q;
    uint8_t *m = (uint8_t *)mem, *hs_scratch;
    size_t n = 0;
    int rc;

    if (out != NULL) {
        *out = NULL;
    }
    /* RFC 9001 8.1 (MUST): ALPN is mandatory over QUIC */
    if (mem == NULL || cfg == NULL || host == NULL || rnd == NULL || out == NULL ||
        mem_len < brisk_quic_size() || cfg->alpn == NULL || cfg->alpn[0] == '\0' ||
        (suites == NULL) != (n_suites == 0)) {
        return BRISK_E_ARG;
    }
    m += (QA_ALIGN - ((uintptr_t)m & (QA_ALIGN - 1))) & (QA_ALIGN - 1);
    q = (brisk_quic *)(void *)m;
    hs_scratch = m + sizeof *q;
    memset(q, 0, sizeof *q);
    rc = brisk__conn_core(&q->c, cfg, host, wall_ms, rnd, sys_anchor, 1, hs_scratch);
    qa_tp(&tp, rnd + BRISK__CONN_RAND + 8, cfg->alpn);
    if (rc == BRISK_OK) {
        rc = brisk__quic_tp_write(&tp, q->tp, sizeof q->tp, &n);
    }
    q->c.quic_tp = q->tp;
    q->c.quic_tp_len = n;
    q->c.suites = suites;
    q->c.n_suites = n_suites;
    /* RFC 9000 7.2 (MUST): the first DCID is 8 unpredictable bytes; our SCID 8 more */
    if (rc == BRISK_OK) {
        rc = brisk__quic_conn_init(
            &q->q, &q->c.hs, &tp, rnd + BRISK__CONN_RAND, 8, rnd + BRISK__CONN_RAND + 8, 8,
            hs_scratch + brisk__tls13_hs_scratch_size(), brisk__quic_scratch_size());
    }
    if (rc == BRISK_OK) {
        rc = brisk__conn_next_hello(&q->c, q->q.srings);
        brisk__secure_zero(q->q.srings, QA_CH_MAX);
    }
    if (rc != BRISK_OK) {
        brisk__secure_zero(mem, brisk_quic_size()); /* every setup failure is a caller bug */
        return BRISK_E_ARG;
    }
    q->owe = 1; /* the first Initial */
    *out = q;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ sans-I/O ---------------- */

static void qa_now(brisk_quic *q, int64_t now_ms)
{
    if (now_ms > q->last_now) {
        q->last_now = now_ms;
    }
}

int brisk_quic_feed(brisk_quic *q, void *dgram, size_t len, int64_t now_ms)
{
    int rc;
    if (q == NULL || (dgram == NULL && len != 0) || len > 65527) {
        return BRISK_E_ARG;
    }
    qa_now(q, now_ms);
    q->owe = 1; /* an ACK, a Retry's Initial, CH2 ... (brisk__quic_recv: send after every recv) */
    rc = brisk__quic_recv(&q->q, (uint8_t *)dgram, len, now_ms);
    if (rc != BRISK_OK || q->q.err != 0) {
        brisk__secure_zero(q->c.rnd + 64, 64); /* the ECDHE keys (conn.c rnd layout) */
    } else if (q->c.hs.state == BRISK__HS_WAIT_CH2) {
        /* RFC 9846 4.1.4: CH2 with the same parameters, absorbed before the next send */
        rc = brisk__conn_next_hello(&q->c, q->q.srings);
        brisk__secure_zero(q->q.srings, QA_CH_MAX);
        if (rc != BRISK_OK) {
            /* ponytail: our own fault (a P-256 key the OS layer validated) ends the attempt
             * with APPLICATION_ERROR; an INTERNAL_ERROR close would need an engine hook */
            brisk__quic_close(&q->q, 0);
            rc = BRISK_E_ARG;
        }
    } else {
        brisk__conn_next_hello(&q->c, NULL); /* nothing to build: drops the keys (4.3.8) */
    }
    return rc;
}

size_t brisk_quic_pull(brisk_quic *q, void *out, size_t cap, int64_t now_ms)
{
    size_t n;
    if (q == NULL || out == NULL || cap < BRISK_QUIC_DGRAM_MAX) {
        return 0;
    }
    qa_now(q, now_ms);
    n = brisk__quic_send(&q->q, (uint8_t *)out, cap, now_ms);
    if (n == 0) {
        q->owe = 0;
    }
    return n;
}

int64_t brisk_quic_deadline(const brisk_quic *q)
{
    int64_t t;
    if (q == NULL) {
        return INT64_MAX;
    }
    t = brisk__quic_deadline(&q->q);
    return q->owe && q->last_now < t ? q->last_now : t;
}

int brisk_quic_status(const brisk_quic *q)
{
    if (q == NULL) {
        return BRISK_E_ARG;
    }
    if (q->q.err != 0) {
        return q->q.err;
    }
    return brisk__quic_established(&q->q) ? BRISK_OK : BRISK_E_WANT;
}

uint64_t brisk_quic_error(const brisk_quic *q)
{
    return q != NULL ? q->q.err_code : 0;
}

int brisk_quic_alpn(const brisk_quic *q, const char **name, size_t *len)
{
    const uint8_t *nm = NULL;
    int rc;
    if (name != NULL) {
        *name = NULL;
    }
    if (len != NULL) {
        *len = 0;
    }
    if (q == NULL || name == NULL || len == NULL || !brisk__quic_established(&q->q)) {
        return BRISK_E_ARG;
    }
    rc = brisk__tls13_hs_alpn(&q->c.hs, &nm, len);
    *name = (const char *)nm;
    return rc;
}

int brisk_quic_resumed(const brisk_quic *q)
{
    return q != NULL && brisk__quic_established(&q->q) && brisk__tls13_hs_resumed(&q->c.hs);
}

void brisk_quic_wipe(brisk_quic *q)
{
    if (q != NULL) {
        /* the whole arena: keys, secrets, the engine, both scratch areas, every ring */
        brisk__secure_zero(q,
                           sizeof *q + brisk__tls13_hs_scratch_size() + brisk__quic_scratch_size());
    }
}

int brisk_quic_close(brisk_quic *q, uint64_t app_err)
{
    int rc;
    if (q == NULL) {
        return BRISK_OK;
    }
    if (app_err > BRISK__QUIC_VARINT_MAX) {
        return BRISK_E_ARG; /* RFC 9000 16: a varint - nothing done, the handle stays */
    }
    rc = brisk__quic_close(&q->q, app_err); /* RFC 9000 10.2: immediate close */
    q->owe = 1;
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_FREE); /* the datagram once, then the socket, wipe, free (10.2) */
    }
    return rc;
}

/* ------------------------------------------------------------------ streams ----------------- */

/* A failed connection answers every stream call with its sticky error, not the engine's
 * "no such stream" BRISK_E_ARG. */
static int qa_err(const brisk_quic *q, int rc)
{
    return q->q.err != 0 ? q->q.err : rc;
}

/* Blocking handles: one I/O round (flush, wait for a datagram or the next timer, feed). */
static int qa_wait(brisk_quic *q)
{
    return q->io != NULL ? q->io(q, BRISK__QIO_WAIT) : BRISK_E_WANT;
}

int brisk__quic_wait(brisk_quic *q)
{
    return q != NULL ? qa_wait(q) : BRISK_E_ARG;
}

int64_t brisk_quic_stream_open(brisk_quic *q, int bidi)
{
    int64_t id;
    int rc;
    if (q == NULL) {
        return BRISK_E_ARG;
    }
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_START);
    }
    for (;;) {
        id = brisk__quic_stream_open(&q->q, bidi);
        if (id != BRISK_E_WANT) {
            return id >= 0 ? id : qa_err(q, (int)id);
        }
        rc = qa_wait(q); /* RFC 9000 4.6: until the server's MAX_STREAMS */
        if (rc != BRISK_OK) {
            return rc;
        }
    }
}

int brisk_quic_stream_write(brisk_quic *q, uint64_t id, const void *buf, size_t n, int fin)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
    int r, rc;
    if (q == NULL || (buf == NULL && n != 0)) {
        return BRISK_E_ARG;
    }
    if (n > INT_MAX) {
        n = INT_MAX; /* the count must fit the int result; the FIN waits for the rest */
        fin = 0;
    }
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_START);
    }
    for (;;) {
        r = brisk__quic_stream_write(&q->q, id, p + done, n - done, fin);
        if (r < 0) {
            return qa_err(q, r);
        }
        q->owe = 1; /* new STREAM data (or a FIN) to send */
        done += (size_t)r;
        if (done == n || q->io == NULL) {
            if (q->io != NULL) {
                q->io(q, BRISK__QIO_FLUSH); /* blocking: on the wire when this returns */
            }
            return (int)done;
        }
        if (r > 0) {
            q->io(q, BRISK__QIO_START); /* progress restarts the stall clock */
        }
        rc = qa_wait(q); /* ACKs and MAX_(STREAM_)DATA free the ring - for every stream */
        if (rc != BRISK_OK) {
            return rc == BRISK_E_TIMEOUT && done != 0 ? (int)done : rc;
        }
    }
}

int brisk_quic_stream_read(brisk_quic *q, uint64_t id, void *buf, size_t cap, uint64_t *app_err)
{
    uint64_t e = 0;
    int r, rc;
    if (app_err != NULL) {
        *app_err = 0;
    }
    if (q == NULL || buf == NULL || cap == 0) {
        return BRISK_E_ARG;
    }
    cap = cap > INT_MAX ? INT_MAX : cap;
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_START);
    }
    for (;;) {
        r = brisk__quic_stream_read(&q->q, id, (uint8_t *)buf, cap, &e);
        if (r >= 0) {
            q->owe = 1; /* MAX_STREAM_DATA / MAX_DATA / MAX_STREAMS may be owed now */
            return r;
        }
        if (r != BRISK_E_WANT) {
            if (app_err != NULL) {
                *app_err = e; /* RESET_STREAM's code */
            }
            return qa_err(q, r);
        }
        rc = qa_wait(q);
        if (rc != BRISK_OK) {
            return rc;
        }
    }
}

int brisk_quic_stream_accept(brisk_quic *q, uint64_t *id)
{
    int rc;
    if (id != NULL) {
        *id = 0;
    }
    if (q == NULL || id == NULL) {
        return BRISK_E_ARG;
    }
    if (q->io != NULL) {
        q->io(q, BRISK__QIO_START);
    }
    for (;;) {
        rc = brisk__quic_stream_accept(&q->q, id);
        if (rc != BRISK_E_WANT) {
            return rc;
        }
        if (q->q.err != 0) {
            return q->q.err;
        }
        rc = qa_wait(q);
        if (rc != BRISK_OK) {
            return rc;
        }
    }
}

#    undef QA_CH_MAX
#    undef QA_ALIGN

#endif /* BRISK_ENABLE_QUIC */
