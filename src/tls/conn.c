/* conn.c - the public TLS client connection, sans-I/O (RFC 9846; TLS 1.2 with
 * BRISK_ENABLE_TLS12, offered in the same ClientHello - see src/tls/tls12.c).
 *
 * Glue between the caller's brisk_cfg and the two engines underneath: brisk__tls13_hs (the
 * handshake) and brisk__tls13_conn (records, alerts, close_notify, KeyUpdate). What lives here
 * is only what a CONNECTION decides and neither engine can: which ClientHello to send (CH1 at
 * setup, CH2 after a HelloRetryRequest), which anchors to trust, the ALPN list, and what to do
 * with a ticket going in or coming out. Every protocol check stays in the engines.
 *
 * No syscall, no malloc, no clock, no global state: randomness and wall time arrive as
 * arguments of brisk__conn_setup. The public brisk_conn_init that draws them is in
 * src/os/linux_net.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#define CONN_X25519 0x001d
#define CONN_P256   0x0017
/* The largest ClientHello this connection sends, in every profile: the output queue's
 * profile-independent base. A stored ticket whose identity would push the ClientHello past it
 * is not offered - the handshake goes on without it (4.2.11 makes the PSK an optimisation). */
#define CONN_CH_MAX 2048
#define CONN_RND_X  64  /* x25519 d in rnd[] */
#define CONN_RND_P  96  /* P-256 d */
#define CONN_RND_S  128 /* sign_rand */

struct conn_align_probe {
    char c;
    struct brisk_conn x;
};
#define CONN_ALIGN offsetof(struct conn_align_probe, x)
/* the front half is shared with src/quic/api.c only in a QUIC build; otherwise it stays static
 * (inlined: no size cost for TINY / DEFAULT) */
#if BRISK_ENABLE_QUIC
#    define CONN_SHARED
#else
#    define CONN_SHARED static
#endif

size_t brisk_conn_size(void)
{
    return (CONN_ALIGN - 1) + sizeof(struct brisk_conn) + BRISK__TLS_REC_IN_MAX +
           brisk__tls13_hs_scratch_size();
}

/* ms -> s without a 64-bit division (libgcc's __divdi3 is banned on 32-bit targets): long
 * division by 1000 over four 16-bit limbs, every step in 32 bits. A clock before 1970 is -1:
 * the X.509 time policy treats it like any clock below its floor. */
static int64_t conn_secs(int64_t ms)
{
    uint64_t x, q = 0;
    uint32_t r = 0, d, limb[4];
    int i;
    if (ms < 0) {
        return -1;
    }
    x = (uint64_t)ms;
    limb[0] = (uint32_t)(x >> 48) & 0xffffu;
    limb[1] = (uint32_t)(x >> 32) & 0xffffu;
    limb[2] = (uint32_t)(x >> 16) & 0xffffu;
    limb[3] = (uint32_t)x & 0xffffu;
    for (i = 0; i < 4; i++) {
        d = r << 16 | limb[i]; /* r < 1000, so d < 2^26 */
        q = q << 16 | d / 1000u;
        r = d % 1000u;
    }
    return (int64_t)q;
}

void brisk__conn_set_time(brisk_conn *c, int64_t now_ms)
{
    if (c != NULL) {
        c->now_ms = now_ms;
        c->auth.now = conn_secs(now_ms);
    }
}

int brisk__alpn_encode(const char *list, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0, k;
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (out == NULL || out_len == NULL) {
        return BRISK_E_ARG;
    }
    if (list == NULL) {
        return BRISK_OK;
    }
    for (;;) {
        /* RFC 7301 3.1: ProtocolName<1..2^8-1>, and "empty strings MUST NOT be included" */
        for (k = 0; list[k] != '\0' && list[k] != ','; k++) {
            if (k == 255) {
                return BRISK_E_ARG;
            }
        }
        if (k == 0 || k + 1 > cap - n) {
            return BRISK_E_ARG;
        }
        out[n] = (uint8_t)k;
        memcpy(out + n + 1, list, k);
        n += k + 1;
        if (list[k] == '\0') {
            break;
        }
        list += k + 1;
    }
    *out_len = n;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ trust anchors ----------- */

static int conn_anchor_is(brisk__x509_cert *out, const uint8_t *der, size_t len, const uint8_t *dn,
                          size_t dn_len)
{
    return brisk__x509_parse(out, der, len) == BRISK_OK && out->subject_len == dn_len &&
           memcmp(out->subject, dn, dn_len) == 0;
}

/* RFC 5280 6.1.1 (d): anchors by subject Name. cfg.ca_mem first - DER certificates resolve in
 * place, PEM ones decode into the bundle's scratch - then the file store, whose numbering
 * continues where memory stopped, so both together still see at most BRISK__X509_MAX_ANCHORS
 * requests per level from the walk. A block that does not parse is skipped, as in a bundle; a
 * DER list stops at the first byte that is not a whole TLV. */
int brisk__conn_anchor(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                       brisk__x509_cert *out)
{
    brisk_conn *c = (brisk_conn *)ctx;
    const uint8_t *p, *tlv;
    size_t left, tl, hits = 0;
    brisk__der d;

    if (c == NULL || dn == NULL || out == NULL) {
        return BRISK_E_ARG;
    }
    p = c->cfg.ca_mem;
    left = c->cfg.ca_mem_len;
    if (p != NULL && p[0] == 0x30) {
        brisk__der_init(&d, p, left);
        while (brisk__der_peek(&d) != -1 && brisk__der_tlv(&d, &tlv, &tl) == BRISK_OK) {
            if (conn_anchor_is(out, tlv, tl, dn, dn_len) && hits++ == index) {
                return BRISK_OK;
            }
        }
    } else if (p != NULL) {
        brisk__x509_pem_init(&c->bundle.pem);
        while (brisk__x509_pem_feed(&c->bundle.pem, &p, &left) == 1) {
            if (conn_anchor_is(out, c->bundle.pem.der, c->bundle.pem.der_len, dn, dn_len) &&
                hits++ == index) {
                return BRISK_OK;
            }
        }
    }
    if (c->sys_anchor != NULL) {
        return c->sys_anchor(&c->bundle, dn, dn_len, index - hits, out);
    }
    memset(out, 0, sizeof *out);
    return BRISK_E_ARG;
}

/* ------------------------------------------------------------------ tickets out ------------- */

/* RFC 9846 4.7.1: export inside the engine's callback (the PSK dies when it returns) and hand
 * the blob to the caller. Always 0: a ticket that cannot be exported or stored is only a lost
 * optimisation, never a reason to kill the connection. */
static int conn_on_ticket(void *ctx, const brisk__tls13_ticket *t)
{
    brisk_conn *c = (brisk_conn *)ctx;
    uint8_t blob[BRISK_TICKET_MAX];
    size_t n;
    if (brisk__tls13_ticket_export(t, c->now_ms, c->host, c->host_len, blob, sizeof blob, &n) ==
        BRISK_OK) {
        c->cfg.on_ticket(c->cfg.ticket_ctx, blob, n);
    }
    brisk__secure_zero(blob, sizeof blob);
    return 0;
}

/* ------------------------------------------------------------------ the ClientHello pair ---- */

/* CH1 in START, CH2 in WAIT_CH2 (RFC 9846 4.1.4, 4.2.2: the same random and session id, the
 * HRR's group or - cookie-only HRR - the same share again, the cookie copied exactly). Built in
 * the receive buffer, which is empty at both points (brisk_feed feeds record by record until
 * the ServerHello). CH2 carries CH1's PSK, with a recomputed obfuscated age, unless the HRR's
 * suite has another hash (4.2.2 "removing any PSKs which are incompatible"); the engine
 * enforces both directions. A CH1 that does not fit with the PSK (room for the worst CH2
 * included) is rebuilt without it; one that does not fit without it is BRISK_E_ARG. */
static int conn_hello(brisk_conn *c, uint8_t *buf)
{
    brisk__tls13_hs *hs = &c->hs;
    brisk__tls13_ch_params p;
    brisk__tls13_psk psk;
    uint8_t pub[65];
    int ch2 = hs->state == BRISK__HS_WAIT_CH2, use_psk = 0, rc, quic = 0;
    uint16_t g = ch2 && hs->hrr_group != 0 ? hs->hrr_group : CONN_X25519;
    const uint8_t *priv = c->rnd + (g == CONN_P256 ? CONN_RND_P : CONN_RND_X);
    size_t n = 0;

    memset(&p, 0, sizeof p);
    if (g == CONN_P256) {
        if (brisk__p256_keygen(pub, priv) != BRISK_OK) {
            return BRISK_E_ARG; /* the OS layer draws a valid scalar; this is a local fault */
        }
        p.share_pub_len = 65;
    } else {
        brisk__x25519_base(pub, priv);
        p.share_pub_len = 32;
    }
    p.random = c->rnd;
    p.session_id = c->rnd + 32; /* E.4 compatibility mode over TCP */
    p.session_id_len = 32;
    p.share_group = g;
    p.share_pub = pub;
    p.sni = c->host;
    p.sni_len = c->host_len;
    p.alpn = c->alpn_len != 0 ? c->alpn : NULL;
    p.alpn_len = c->alpn_len;
    p.tls12 = BRISK_ENABLE_TLS12; /* one ClientHello for TLS 1.3 and 1.2 (RFC 9846 4.3.1) */
#if BRISK_ENABLE_QUIC
    quic = c->quic;
    if (quic) {
        p.session_id_len = 0;   /* RFC 9001 8.4 (MUST NOT): no compatibility mode */
        p.tls12 = 0;            /* RFC 9001 4.2 (MUST NOT): TLS 1.3 only */
        p.quic_tp = c->quic_tp; /* 8.2 (MUST) */
        p.quic_tp_len = c->quic_tp_len;
        p.suites = c->suites;
        p.n_suites = c->n_suites;
    }
#endif
    if (ch2 && hs->cookie_len != 0) {
        p.cookie = hs->cookie;
        p.cookie_len = hs->cookie_len;
    }
    /* 4.7.1, 4.3.11.1: a malformed, foreign-host or expired blob is refused by import. The PSK
     * is chosen once, at CH1. CH2 (4.2.2) keeps CH1's PSK unless the HRR's suite has another
     * hash (B.4): re-imported at CH1's time - no second expiry check - with only the
     * obfuscated age moved on by the time since. */
    if (!ch2) {
        c->ch1_ms = c->now_ms;
        use_psk = c->cfg.ticket != NULL &&
                  brisk__tls13_ticket_import(c->cfg.ticket, c->cfg.ticket_len, c->host, c->host_len,
                                             c->now_ms, &psk) == BRISK_OK;
    } else if (hs->psk_offered && (hs->suite == 0x1302) == (hs->psk_suite == 0x1302)) {
        if (brisk__tls13_ticket_import(c->cfg.ticket, c->cfg.ticket_len, c->host, c->host_len,
                                       c->ch1_ms, &psk) != BRISK_OK) {
            return BRISK_E_ARG; /* the caller changed the blob under us */
        }
        if (c->now_ms > c->ch1_ms) {
            psk.obf_age += (uint32_t)(c->now_ms - c->ch1_ms);
        }
        use_psk = 1;
    }
    for (;;) {
        p.psk = use_psk ? &psk : NULL;
        /* 4.3.9: psk_dhe_ke alongside a PSK, and whenever tickets are wanted: the modes also
         * govern the tickets a server issues, and real servers send none without them. 4.2.2:
         * a CH2 that drops CH1's PSK (another hash) keeps the modes - only the PSK may go. */
        p.psk_modes = (uint8_t)(use_psk || c->cfg.on_ticket != NULL || (ch2 && hs->psk_offered));
        rc = brisk__tls13_ch_write(&p, buf, CONN_CH_MAX, &n);
        /* CH1 offers the PSK only if CH2 is sure to fit too: at most a cookie extension and a
         * P-256 share instead of x25519 more (4.2.2 forbids dropping it there). QUIC keeps CH1
         * AND CH2 in one Initial CRYPTO retention buffer (quic/conn.c QC_RET0 == CONN_CH_MAX),
         * so there the pair must fit together. */
        if (rc == BRISK_OK && use_psk && !ch2 &&
            (quic ? n : 0) + n + BRISK__TLS13_COOKIE_MAX + 6 + (65 - 32) > CONN_CH_MAX) {
            rc = BRISK_E_ARG;
        }
        if (rc == BRISK_OK && use_psk && !ch2) {
            rc = brisk__tls13_hs_set_psk(hs, &psk);
        }
#if BRISK_ENABLE_TLS12
        /* the P-256 d a TLS 1.2 ServerKeyExchange may pick (the x25519 d is the share's) */
        if (rc == BRISK_OK && !ch2 && !quic) {
            rc = brisk__tls13_hs_set_tls12_key(hs, c->rnd + CONN_RND_P);
        }
#endif
        if (rc == BRISK_OK) {
            rc = brisk__tls13_hs_client_hello(hs, buf, n, g, priv);
        }
        if (rc == BRISK_OK || !use_psk || ch2) {
            break;
        }
        use_psk = 0;
    }
    brisk__secure_zero(&psk, sizeof psk);
    (void)quic;
    return rc == BRISK_OK ? BRISK_OK : BRISK_E_ARG;
}

/* 4.3.8: both ECDHE private keys die once CH2 is queued or the ServerHello is in */
static void conn_drop_keys(brisk_conn *c)
{
    if (c->hs.state != BRISK__HS_WAIT_SH || c->hs.hrr_seen) {
        brisk__secure_zero(c->rnd + CONN_RND_X, CONN_RND_S - CONN_RND_X);
    }
}

#if BRISK_ENABLE_QUIC
int brisk__conn_next_hello(brisk_conn *c, uint8_t *buf)
{
    int rc = c->hs.state == BRISK__HS_START || c->hs.state == BRISK__HS_WAIT_CH2
                 ? conn_hello(c, buf)
                 : BRISK_OK;
    conn_drop_keys(c);
    return rc;
}
#endif

/* ------------------------------------------------------------------ setup ------------------- */

/* The ONE host string must be acceptable to every consumer (ch_write comment): the SNI writer
 * refuses what is not printable ASCII, and brisk__x509_match_host says BRISK_E_ARG for anything
 * that is not a usable reference identity - checked here with no certificate, so a bad host is
 * a setup error and never a failure in the middle of the handshake. */
static int conn_host_ok(const char *host, size_t *len)
{
    brisk__x509_cert none;
    size_t n = 0;
    while (n < 256 && host[n] != '\0') {
        n++;
    }
    if (n == 0 || n > 255) {
        return 0;
    }
    memset(&none, 0, sizeof none);
    *len = n;
    return brisk__x509_match_host(&none, host, n) != BRISK_E_ARG;
}

CONN_SHARED int brisk__conn_core(brisk_conn *c, const brisk_cfg *cfg, const char *host,
                                 int64_t now_ms, const uint8_t rnd[BRISK__CONN_RAND],
                                 brisk__x509_anchor_fn sys_anchor, int quic, uint8_t *hs_scratch)
{
    brisk__tls13_hs_cfg hc;
    size_t host_len = 0, n = 0;
    int rc;

    if (!conn_host_ok(host, &host_len) || (cfg->ca_mem == NULL) != (cfg->ca_mem_len == 0) ||
        (cfg->client_chain == NULL && cfg->client_chain_len != 0)) {
        return BRISK_E_ARG;
    }
    memset(c, 0, sizeof *c);
    c->fd = -1;
    c->cfg = *cfg;
    memcpy(c->host, host, host_len);
    c->host_len = host_len;
    memcpy(c->rnd, rnd, BRISK__CONN_RAND);
    rc = brisk__alpn_encode(cfg->alpn, c->alpn, sizeof c->alpn, &n);
    c->alpn_len = (uint16_t)n;
    /* ca_mem alone = memory anchors only; ca_file (or neither) adds the file / system store */
    c->sys_anchor = cfg->ca_mem != NULL && cfg->ca_file == NULL ? NULL : sys_anchor;
    c->bundle.path = cfg->ca_file; /* NULL: brisk__os_ca_anchor autodetects on first use */
    c->trust.find_anchor = brisk__conn_anchor;
    c->trust.anchor_ctx = c;
    c->auth.host = c->host;
    c->auth.host_len = host_len;
    c->auth.trust = &c->trust;
    brisk__conn_set_time(c, now_ms);

    memset(&hc, 0, sizeof hc);
    hc.auth = brisk__tls13_auth_x509; /* verification is always on */
    hc.auth_ctx = &c->auth;
    hc.on_ticket = cfg->on_ticket != NULL ? conn_on_ticket : NULL; /* NULL: 4.7.1 ignore */
    hc.ticket_ctx = c;
    hc.client_chain = cfg->client_chain;
    hc.client_chain_len = cfg->client_chain_len;
    hc.client_key = cfg->client_key;
    hc.sign_rand = c->rnd + CONN_RND_S;
    hc.sign = cfg->sign;
    hc.sign_ctx = cfg->sign_ctx;
    hc.quic = (uint8_t)quic;
#if BRISK_ENABLE_QUIC
    c->quic = (uint8_t)quic;
#endif
    if (rc == BRISK_OK) {
        rc = brisk__tls13_hs_init(&c->hs, &hc, hs_scratch, brisk__tls13_hs_scratch_size());
    }
    return rc == BRISK_OK ? BRISK_OK : BRISK_E_ARG;
}

int brisk__conn_setup(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                      int64_t now_ms, const uint8_t rnd[BRISK__CONN_RAND],
                      brisk__x509_anchor_fn sys_anchor, brisk_conn **out)
{
    brisk_conn *c;
    uint8_t *m = (uint8_t *)mem, *rec_in;
    int rc;

    if (out != NULL) {
        *out = NULL;
    }
    if (mem == NULL || cfg == NULL || host == NULL || rnd == NULL || out == NULL ||
        mem_len < brisk_conn_size()) {
        return BRISK_E_ARG;
    }
    /* any caller alignment: round up in place (handshake.c HS_CERT_ALIGN idiom) */
    m += (CONN_ALIGN - ((uintptr_t)m & (CONN_ALIGN - 1))) & (CONN_ALIGN - 1);
    c = (brisk_conn *)(void *)m;
    rec_in = m + sizeof *c;
    rc = brisk__conn_core(c, cfg, host, now_ms, rnd, sys_anchor, 0, rec_in + BRISK__TLS_REC_IN_MAX);
    if (rc == BRISK_OK) {
        rc = brisk__tls13_conn_init(&c->tc, &c->hs, rec_in, BRISK__TLS_REC_IN_MAX);
    }
    if (rc == BRISK_OK) {
        rc = conn_hello(c, c->tc.in);
    }
    if (rc != BRISK_OK) {
        brisk__secure_zero(mem, brisk_conn_size()); /* every setup failure is a caller bug */
        return BRISK_E_ARG;
    }
    *out = c;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ the public calls -------- */

/* Bytes that complete the record header, or the record, in the receive buffer. */
static size_t conn_need(const brisk_conn *c)
{
    const brisk__tls13_conn *t = &c->tc;
    if (t->in_len < BRISK__TLS_REC_HDR) {
        return BRISK__TLS_REC_HDR - t->in_len;
    }
    return BRISK__TLS_REC_HDR + brisk__load_be16(t->in + 3) - t->in_len;
}

int brisk_feed(brisk_conn *c, const void *in, size_t len, size_t *used)
{
    const uint8_t *p = (const uint8_t *)in;
    size_t k, u;
    int rc;

    if (used != NULL) {
        *used = 0;
    }
    if (c == NULL || used == NULL || (in == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    if (len == 0) {
        return c->tc.err;
    }
    do {
        k = len - *used;
        if (c->hs.state == BRISK__HS_WAIT_SH && c->tc.err == 0) {
            /* one record at a time until the ServerHello: after an HRR the receive buffer is
             * then empty, and CH2 is built in it */
            u = conn_need(c);
            k = k < u ? k : u;
        }
        rc = brisk__tls13_conn_feed(&c->tc, p + *used, k, &u);
        *used += u;
        if (rc == BRISK_OK && c->hs.state == BRISK__HS_WAIT_CH2 &&
            conn_hello(c, c->tc.in) != BRISK_OK) {
            /* our own fault, not the peer's: internal_error, never BRISK_E_PROTO (6.2) */
            rc = brisk__tls13_conn_abort(&c->tc, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG);
        }
    } while (rc == BRISK_OK && u != 0 && *used < len);
    conn_drop_keys(c);
    return rc;
}

size_t brisk_pull(brisk_conn *c, void *out, size_t cap)
{
    if (c == NULL || out == NULL) {
        return 0;
    }
    return brisk__tls13_conn_pull(&c->tc, (uint8_t *)out, cap);
}

int brisk_status(const brisk_conn *c)
{
    if (c == NULL) {
        return BRISK_E_ARG;
    }
    if (c->tc.err != 0) {
        return c->tc.err;
    }
    return c->hs.state == BRISK__HS_CONNECTED ? BRISK_OK : BRISK_E_WANT;
}

int brisk_app_read(brisk_conn *c, void *out, size_t cap, size_t *n)
{
    int rc;
    if (n != NULL) {
        *n = 0;
    }
    if (c == NULL || out == NULL || n == NULL || cap == 0) {
        return BRISK_E_ARG;
    }
    rc = brisk__tls13_conn_read(&c->tc, (uint8_t *)out, cap, n);
    if (rc != BRISK_OK || *n != 0 || c->tc.eof) {
        return rc; /* data, the sticky error, or n == 0 after close_notify (6.1) */
    }
    return BRISK_E_WANT;
}

int brisk_app_write(brisk_conn *c, const void *data, size_t len, size_t *used, void *out,
                    size_t cap, size_t *out_len)
{
    if (c == NULL) {
        if (used != NULL) {
            *used = 0;
        }
        if (out_len != NULL) {
            *out_len = 0;
        }
        return BRISK_E_ARG;
    }
    return brisk__tls13_conn_write(&c->tc, (const uint8_t *)data, len, used, (uint8_t *)out, cap,
                                   out_len);
}

int brisk_close_notify(brisk_conn *c)
{
    if (c == NULL) {
        return BRISK_E_ARG;
    }
    /* mid-handshake there is nothing to close cleanly: brisk_status would read OK without a
     * client Finished ever sent. Abandon the handshake with brisk_conn_wipe instead. */
    if (c->tc.err == 0 && c->hs.state != BRISK__HS_CONNECTED) {
        return BRISK_E_ARG;
    }
    return brisk__tls13_conn_close(&c->tc);
}

int brisk_alert(const brisk_conn *c)
{
    if (c == NULL || c->tc.err == 0) {
        return 0;
    }
    return c->tc.err == BRISK_E_PEER_ALERT ? c->tc.peer_alert : c->tc.alert;
}

int brisk_alpn(const brisk_conn *c, const char **name, size_t *len)
{
    const uint8_t *nm = NULL;
    int rc;
    if (name != NULL) {
        *name = NULL;
    }
    if (len != NULL) {
        *len = 0;
    }
    if (c == NULL || name == NULL || len == NULL) {
        return BRISK_E_ARG;
    }
    rc = brisk__tls13_hs_alpn(&c->hs, &nm, len);
    *name = (const char *)nm;
    return rc;
}

int brisk_resumed(const brisk_conn *c)
{
    return c != NULL && brisk__tls13_hs_resumed(&c->hs);
}

int brisk_tls_version(const brisk_conn *c)
{
    if (c == NULL || c->hs.state != BRISK__HS_CONNECTED) {
        return BRISK_E_ARG;
    }
    return brisk__tls13_hs_version(&c->hs);
}

void brisk_conn_wipe(brisk_conn *c)
{
    if (c == NULL) {
        return;
    }
    brisk__tls13_conn_wipe(&c->tc); /* both directions, the engine + its scratch, rec_in */
    brisk__secure_zero(c, sizeof *c);
}

#undef CONN_X25519
#undef CONN_P256
#undef CONN_CH_MAX
#undef CONN_RND_X
#undef CONN_RND_P
#undef CONN_RND_S
#undef CONN_ALIGN
#undef CONN_SHARED
