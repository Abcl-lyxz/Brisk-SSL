/* test_tls13_hs.c - the TLS 1.3 handshake engine (src/tls/handshake.c, RFC 9846 sect 4).
 *
 * Everything replayed here comes from tools/kat.py: the RFC 8448 sect 3/5/6/7 traces (every
 * secret re-derived in Python from the messages alone), a synthetic P-256 / RSA-PSS server for
 * the production authenticator, a mutation table whose alert column cites the RFC 9846 section,
 * and Wycheproof signatures and key shares. Nothing below types a vector by hand.
 *
 * The RFC 8448 server key is RSA-1024 and chains to nothing, so those flows run with a stub
 * authenticator that checks the CertificateVerify content it is handed and says yes; the
 * synthetic flows run with brisk__tls13_auth_x509, which is what production uses. */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct tls13_flow_kat {
    const char *note, *root, *host;
    long long now;
    int flags, alert;
    unsigned g1;
    const char *priv1, *ch1, *hrr;
    unsigned g2;
    const char *priv2, *ch2, *cookie;
    const char *sh, *ee, *cr, *cert, *cv, *sf, *cf;
    const char *s_hs, *c_hs, *s_ap, *c_ap, *exp_ms, *res_ms, *tbs;
    const char *psk; /* resumption PSK (hs_set_psk) under psk_suite; "" = none */
    unsigned psk_suite;
    int resumed;                       /* the ServerHello selects the PSK */
    const char *alpn;                  /* the name EE selects, "" = none */
    const char *cchain, *ckey, *srand; /* mTLS device chain / key / hedging input */
};
struct tls13_rfc_kat {
    const char *hrr, *down1, *down0, *cv_th, *cv_content, *cv_client;
};
struct tls13_chw_kat {
    const char *random, *sid, *suites, *groups, *sigs, *sni;
    unsigned share_group;
    const char *share_pub, *cookie, *ch;
    const char *alpn; /* ProtocolName entries */
    int psk_modes;
    const char *identity; /* "" = no pre_shared_key */
    unsigned obf_age;
    int psk_len;
};
struct tls13_psk_kat {
    const char *nst, *psk, *prefix, *binder_hash, *binder, *ch4, *early, *blob;
    long long issued, now;
    unsigned obf_age;
    const char *ticket, *fresh;
    unsigned lifetime, age_add;
};
struct tls13_mtls_kat {
    const char *note, *chain, *key;
    int ok;
};
struct tls13_der_kat {
    const char *raw, *der, *note;
};
struct tls13_mut_kat {
    int flow, msg;
    const char *bytes;
    int alert;
    const char *note;
};
struct tls13_cv_key {
    unsigned alg;
    const char *key;
};
struct tls13_cv_kat {
    int key;
    unsigned scheme;
    const char *msg, *sig;
    int ok;
};
#include "kat/tls13_trace.inc"
#include "kat/tls13_mut.inc"
#include "kat/tls13_cv.inc"
#include "kat/tls13_psk.inc"

#define NFLOW  (sizeof TLS13_FLOW_KAT / sizeof TLS13_FLOW_KAT[0])
#define F_TIME 1 /* the verdict depends on BRISK_X509_TIME_POLICY */

/* ---------------------------------------------------------------- hex arena ---------------- */
static uint8_t arena[1 << 18];
static size_t arena_used;

static const uint8_t *dec(const char *h, size_t *n)
{
    size_t len = strlen(h) / 2;
    uint8_t *p = arena + arena_used;
    if (len > sizeof arena - arena_used) {
        exit(2);
    }
    *n = t_unhex(h, p, len);
    arena_used += len;
    return p;
}

/* ---------------------------------------------------------------- one flow, decoded -------- */
typedef struct {
    const struct tls13_flow_kat *k;
    const uint8_t *m[7], *priv1, *ch1, *priv2, *ch2, *cookie, *root, *cf, *sec[6], *tbs;
    size_t n_m[7], count, sh_at, ch1_len, ch2_len, cookie_len, root_len, cf_len, hl, tbs_len;
    const uint8_t *psk, *cchain, *ckey, *srand;
    size_t psk_len, cchain_len;
} flow;

static void flow_load(flow *f, const struct tls13_flow_kat *k)
{
    const char *msgs[7];
    size_t i, n;
    memset(f, 0, sizeof *f);
    arena_used = 0;
    f->k = k;
    msgs[0] = k->hrr;
    msgs[1] = k->sh;
    msgs[2] = k->ee;
    msgs[3] = k->cr;
    msgs[4] = k->cert;
    msgs[5] = k->cv;
    msgs[6] = k->sf;
    for (i = 0; i < 7; i++) {
        if (*msgs[i]) {
            f->m[f->count] = dec(msgs[i], &f->n_m[f->count]);
            f->count++;
        }
    }
    f->sh_at = *k->hrr ? 1 : 0;
    f->priv1 = dec(k->priv1, &n);
    f->ch1 = dec(k->ch1, &f->ch1_len);
    f->priv2 = dec(k->priv2, &n);
    f->ch2 = dec(k->ch2, &f->ch2_len);
    f->cookie = dec(k->cookie, &f->cookie_len);
    f->root = dec(k->root, &f->root_len);
    f->cf = dec(k->cf, &f->cf_len);
    f->sec[0] = dec(k->s_hs, &f->hl);
    f->sec[1] = dec(k->c_hs, &n);
    f->sec[2] = dec(k->s_ap, &n);
    f->sec[3] = dec(k->c_ap, &n);
    f->sec[4] = dec(k->exp_ms, &n);
    f->sec[5] = dec(k->res_ms, &n);
    f->tbs = dec(k->tbs, &f->tbs_len);
    f->psk = dec(k->psk, &f->psk_len);
    /* odd offsets: the device chain, key and sign_rand are read unaligned */
    arena_used |= 1;
    f->cchain = dec(k->cchain, &f->cchain_len);
    f->ckey = dec(k->ckey, &n);
    f->srand = dec(k->srand, &n);
}

/* The flow index whose note starts with `head` (rows are appended by kat.py, so never by
 * position). */
static size_t flow_find(const char *head)
{
    size_t i;
    for (i = 0; i < NFLOW; i++) {
        if (strncmp(TLS13_FLOW_KAT[i].note, head, strlen(head)) == 0) {
            return i;
        }
    }
    CHECK(0 && "flow_find: no such row");
    exit(2);
}

/* ---------------------------------------------------------------- callbacks ---------------- */
typedef struct {
    uint8_t sec[4][BRISK_HASH_MAX_LEN];
    size_t len[4];
    unsigned epoch[4];
    int send[4], count;
} capture;

static int on_secret(void *ctx, unsigned epoch, int is_send, uint16_t suite, const uint8_t *s,
                     size_t len)
{
    capture *c = (capture *)ctx;
    (void)suite;
    if (c->count >= 4 || len > BRISK_HASH_MAX_LEN) {
        return 1;
    }
    memcpy(c->sec[c->count], s, len);
    c->len[c->count] = len;
    c->epoch[c->count] = epoch;
    c->send[c->count] = is_send;
    c->count++;
    return 0;
}

typedef struct {
    const uint8_t *want;
    size_t want_len;
    int calls, tbs_ok;
} stub;

/* The RFC 8448 authenticator: checks the 4.5.2 content it is given against the one kat.py
 * rebuilt from the trace messages, then accepts. Production never gets here. */
static int stub_auth(void *ctx, uint16_t version, const brisk__x509_cert *certs, size_t n_certs,
                     uint16_t scheme, const uint8_t *tbs, size_t tbs_len, const uint8_t *sig,
                     size_t sig_len, uint8_t *alert)
{
    (void)version;
    stub *s = (stub *)ctx;
    (void)scheme;
    (void)sig;
    (void)sig_len;
    (void)alert;
    s->calls++;
    s->tbs_ok = n_certs >= 1 && certs[0].raw != NULL && tbs_len == s->want_len &&
                memcmp(tbs, s->want, tbs_len) == 0;
    return BRISK_OK;
}

typedef struct {
    const uint8_t *der;
    size_t len;
} anchor;

static int anchor_fn(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                     brisk__x509_cert *out)
{
    const anchor *a = (const anchor *)ctx;
    (void)dn;
    (void)dn_len;
    return index == 0 ? brisk__x509_parse(out, a->der, a->len) : BRISK_E_ARG;
}

/* ---------------------------------------------------------------- the runner --------------- */
enum { FEED_MSG, FEED_BYTES, FEED_FLIGHT, FEED_CUT };

typedef struct {
    brisk__tls13_hs hs;
    capture cap;
    stub st;
    anchor an;
    brisk__x509_trust trust;
    brisk__tls13_auth_x509_ctx ax;
    uint8_t init[2048], hsk[BRISK__TLS13_OUT_MAX];
    size_t init_len, hsk_len;
} run;

static uint8_t *g_scratch;
static size_t g_scratch_len;
static uint8_t feedbuf[4 + BRISK_TLS_MAX_HS_MSG + 1024];

static void drain(run *r, size_t off)
{
    uint8_t tmp[700 + 8];
    unsigned e = 99;
    size_t n;
    /* a 700-byte cap: a queued ClientHello pair comes out in several pieces */
    while ((n = brisk__tls13_hs_pull(&r->hs, &e, tmp + off, 700)) != 0) {
        if (e == BRISK__EPOCH_INITIAL && n <= sizeof r->init - r->init_len) {
            memcpy(r->init + r->init_len, tmp + off, n);
            r->init_len += n;
        } else if (e == BRISK__EPOCH_HANDSHAKE && n <= sizeof r->hsk - r->hsk_len) {
            memcpy(r->hsk + r->hsk_len, tmp + off, n);
            r->hsk_len += n;
        } else {
            CHECK(0 && "pull: unexpected epoch or overflow");
            return;
        }
    }
}

static int feed(run *r, unsigned epoch, const uint8_t *m, size_t n, int mode, size_t cut,
                size_t off)
{
    uint8_t *p = feedbuf + off;
    size_t i;
    int rc;
    if (n > sizeof feedbuf - off) {
        exit(2);
    }
    memcpy(p, m, n);
    if (mode == FEED_BYTES) {
        for (i = 0; i < n; i++) {
            rc = brisk__tls13_hs_feed(&r->hs, epoch, p + i, 1);
            if (rc != BRISK_OK) {
                return rc;
            }
        }
        return BRISK_OK;
    }
    if (mode == FEED_CUT && cut != 0 && cut < n && (m[0] == 2 || m[0] == 11)) {
        rc = brisk__tls13_hs_feed(&r->hs, epoch, p, cut);
        return rc != BRISK_OK ? rc : brisk__tls13_hs_feed(&r->hs, epoch, p + cut, n - cut);
    }
    return brisk__tls13_hs_feed(&r->hs, epoch, p, n);
}

/* ch copied into buf with its PSK binder (if it ends in one of hl bytes) zeroed. */
static const uint8_t *unbind(uint8_t *buf, const uint8_t *ch, size_t n, size_t hl)
{
    if (n > 1024) {
        exit(2);
    }
    memcpy(buf, ch, n);
    if (hl != 0 && n > hl + 3 && buf[n - hl - 1] == hl &&
        brisk__load_be16(buf + n - hl - 3) == hl + 1) {
        memset(buf + n - hl, 0, hl);
    }
    return buf;
}

/* Replay one flow, message `ov_idx` replaced by ov (ov_idx < 0: none). 0 when every step was
 * accepted; the engine's error code otherwise; 97..99 for a harness-level refusal. */
static int run_flow(run *r, const flow *f, int ov_idx, const uint8_t *ov, size_t ov_len, int mode,
                    size_t cut, size_t off)
{
    static uint8_t flight[4 * (4 + BRISK_TLS_MAX_HS_MSG)], ch[2][1024];
    brisk__tls13_hs_cfg cfg;
    brisk__tls13_psk psk;
    size_t i, j, n, fl;
    const uint8_t *m;
    int rc;

    memset(r, 0, sizeof *r);
    memset(&cfg, 0, sizeof cfg);
    cfg.on_secret = on_secret;
    cfg.secret_ctx = &r->cap;
    if (f->root_len != 0) {
        r->an.der = f->root;
        r->an.len = f->root_len;
        r->trust.find_anchor = anchor_fn;
        r->trust.anchor_ctx = &r->an;
        r->ax.host = f->k->host;
        r->ax.host_len = strlen(f->k->host);
        r->ax.trust = &r->trust;
        r->ax.now = (int64_t)f->k->now;
        cfg.auth = brisk__tls13_auth_x509;
        cfg.auth_ctx = &r->ax;
    } else {
        r->st.want = f->tbs;
        r->st.want_len = f->tbs_len;
        cfg.auth = stub_auth;
        cfg.auth_ctx = &r->st;
    }
    if (f->cchain_len != 0) {
        cfg.client_chain = f->cchain;
        cfg.client_chain_len = f->cchain_len;
        cfg.client_key = f->ckey;
        cfg.sign_rand = f->srand;
    }
    if (brisk__tls13_hs_init(&r->hs, &cfg, g_scratch + (off & 7), g_scratch_len - 8) != BRISK_OK) {
        return 99;
    }
    if (f->psk_len != 0) {
        memset(&psk, 0, sizeof psk);
        memcpy(psk.psk, f->psk, f->psk_len);
        psk.psk_len = (uint8_t)f->psk_len;
        psk.suite = (uint16_t)f->k->psk_suite;
        if (brisk__tls13_hs_set_psk(&r->hs, &psk) != BRISK_OK) {
            return 99;
        }
    }
    /* the caller hands in its ClientHello with a zero binder: the engine computes it */
    if (brisk__tls13_hs_client_hello(&r->hs, unbind(ch[0], f->ch1, f->ch1_len, f->psk_len),
                                     f->ch1_len, (uint16_t)f->k->g1, f->priv1) != BRISK_OK) {
        return 99;
    }
    drain(r, off & 1);
    for (i = 0; i < f->count; i++) {
        unsigned epoch = i <= f->sh_at ? BRISK__EPOCH_INITIAL : BRISK__EPOCH_HANDSHAKE;
        m = (int)i == ov_idx ? ov : f->m[i];
        n = (int)i == ov_idx ? ov_len : f->n_m[i];
        if (mode == FEED_FLIGHT && epoch == BRISK__EPOCH_HANDSHAKE) {
            for (fl = 0, j = i; j < f->count; j++) {
                const uint8_t *mj = (int)j == ov_idx ? ov : f->m[j];
                size_t nj = (int)j == ov_idx ? ov_len : f->n_m[j];
                memcpy(flight + fl, mj, nj);
                fl += nj;
            }
            rc = brisk__tls13_hs_feed(&r->hs, epoch, flight, fl);
            i = f->count;
        } else {
            rc = feed(r, epoch, m, n, mode, cut, off);
        }
        if (rc != BRISK_OK) {
            return rc;
        }
        if (i == 0 && f->sh_at == 1) { /* after the HelloRetryRequest */
            if (r->hs.state != BRISK__HS_WAIT_CH2 ||
                brisk__tls13_hs_client_hello(&r->hs, unbind(ch[1], f->ch2, f->ch2_len, f->psk_len),
                                             f->ch2_len, (uint16_t)f->k->g2,
                                             f->priv2) != BRISK_OK) {
                return 98;
            }
            drain(r, off & 1);
        }
    }
    drain(r, off & 1);
    return BRISK_OK;
}

static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

static int secrets_wiped(const brisk__tls13_hs *hs)
{
    return all_zero(hs->priv, sizeof hs->priv) && all_zero(hs->c_hs, sizeof hs->c_hs) &&
           all_zero(hs->s_hs, sizeof hs->s_hs) && all_zero(hs->ks.secret, sizeof hs->ks.secret) &&
           all_zero(hs->psk, sizeof hs->psk);
}

/* Everything a completed flow must have produced, byte for byte. */
static void check_connected(const run *r, const flow *f, int rc, long idx)
{
    static const unsigned EP[4] = {BRISK__EPOCH_HANDSHAKE, BRISK__EPOCH_HANDSHAKE, BRISK__EPOCH_APP,
                                   BRISK__EPOCH_APP};
    int i;
    CHECKI(rc == BRISK_OK && r->hs.state == BRISK__HS_CONNECTED, idx);
    if (rc != BRISK_OK) {
        return;
    }
    CHECKI(r->cap.count == 4, idx);
    for (i = 0; i < 4 && i < r->cap.count; i++) {
        /* order: s_hs recv, c_hs send, s_ap recv, c_ap send (RFC 9846 7.3) */
        CHECKI(r->cap.epoch[i] == EP[i] && r->cap.send[i] == (i & 1), idx);
        CHECKI(r->cap.len[i] == f->hl && memcmp(r->cap.sec[i], f->sec[i], f->hl) == 0, idx);
    }
    CHECKI(memcmp(r->hs.exp_ms, f->sec[4], f->hl) == 0, idx);
    CHECKI(memcmp(r->hs.res_ms, f->sec[5], f->hl) == 0, idx);
    CHECKI(r->hsk_len == f->cf_len && memcmp(r->hsk, f->cf, f->cf_len) == 0, idx);
    CHECKI(r->init_len == f->ch1_len + f->ch2_len && memcmp(r->init, f->ch1, f->ch1_len) == 0 &&
               memcmp(r->init + f->ch1_len, f->ch2, f->ch2_len) == 0,
           idx);
    CHECKI(secrets_wiped(&r->hs), idx);
    /* A.1: a resumed handshake checks no certificate, so the authenticator is never called */
    CHECKI(brisk__tls13_hs_resumed(&r->hs) == f->k->resumed, idx);
    if (f->k->resumed) {
        CHECKI(r->st.calls == 0, idx);
    } else if (f->root_len == 0) {
        CHECKI(r->st.calls == 1 && r->st.tbs_ok, idx);
    }
    {
        const uint8_t *name;
        size_t nl;
        CHECKI(brisk__tls13_hs_alpn(&r->hs, &name, &nl) == BRISK_OK && nl == strlen(f->k->alpn) &&
                   (nl == 0 || memcmp(name, f->k->alpn, nl) == 0),
               idx);
    }
}

static int flow_expect(const struct tls13_flow_kat *k)
{
#if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
    if (k->flags & F_TIME) {
        return 0;
    }
#endif
    return k->alert;
}

/* ---------------------------------------------------------------- suites ------------------- */
static run R; /* ~1.5 KB of engine state plus buffers; static keeps it off the qemu stack */

static void hs_flows(void)
{
    static const int modes[] = {FEED_MSG, FEED_BYTES, FEED_FLIGHT};
    flow f;
    size_t i, mi, cut, maxcut;
    int rc;

    for (i = 0; i < NFLOW; i++) {
        flow_load(&f, &TLS13_FLOW_KAT[i]);
        if (TLS13_FLOW_KAT[i].alert != 0 || flow_expect(&TLS13_FLOW_KAT[i]) != 0) {
            continue; /* the negative fixture rows run in hs_fixture_negative */
        }
#if !BRISK_ENABLE_MTLS
        if (*TLS13_FLOW_KAT[i].cchain) {
            continue; /* hs_mtls checks that such a build refuses the device chain */
        }
#endif
        for (mi = 0; mi < sizeof modes / sizeof modes[0]; mi++) {
            rc = run_flow(&R, &f, -1, NULL, 0, modes[mi], 0, 0);
            check_connected(&R, &f, rc, (long)(i * 10 + mi));
        }
        /* unaligned: every message fed from buf+1 and buf+3, pulled into out+1 */
        rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 1);
        check_connected(&R, &f, rc, (long)i);
        rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 3);
        check_connected(&R, &f, rc, (long)i);
    }
    /* RFC 8448 sect 3: the ServerHello and the Certificate cut at every possible point. */
    flow_load(&f, &TLS13_FLOW_KAT[0]);
    maxcut = f.n_m[0] > f.n_m[2] ? f.n_m[0] : f.n_m[2];
    for (cut = 1; cut < maxcut; cut++) {
        rc = run_flow(&R, &f, -1, NULL, 0, FEED_CUT, cut, 0);
        check_connected(&R, &f, rc, (long)cut);
    }
}

static void hs_trace_specifics(void)
{
    flow f;
    size_t n;
    const uint8_t *hrr_random;
    int rc;

    /* sect 5: after the HRR the engine waits for CH2 and says how to build it */
    flow_load(&f, &TLS13_FLOW_KAT[1]);
    hrr_random = dec(TLS13_RFC_KAT[0].hrr, &n);
    CHECK(f.n_m[0] > 38 && memcmp(f.m[0] + 6, hrr_random, 32) == 0); /* RFC 9846 4.2.3 value */
    {
        brisk__tls13_hs_cfg cfg;
        memset(&cfg, 0, sizeof cfg);
        memset(&R, 0, sizeof R);
        cfg.auth = stub_auth;
        cfg.auth_ctx = &R.st;
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, f.priv1) ==
              BRISK_OK);
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK);
        CHECK(R.hs.state == BRISK__HS_WAIT_CH2 && R.hs.hrr_group == 0x0017);
        CHECK(R.hs.cookie_len == f.cookie_len && memcmp(R.hs.cookie, f.cookie, f.cookie_len) == 0);
        CHECK(all_zero(R.hs.priv, sizeof R.hs.priv)); /* CH1's share is dead */
        /* CH2 must carry the HRR's group: the sect 5 CH1 (x25519, no cookie) is refused */
        CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, f.priv1) ==
              BRISK_E_ARG);
        /* and nothing may arrive from the server before CH2 */
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[1], 4) == BRISK_E_PROTO &&
              R.hs.alert == BRISK__ALERT_UNEXPECTED_MESSAGE);
    }
    /* sect 6: the CertificateRequest is answered with an empty Certificate, then Finished */
    flow_load(&f, &TLS13_FLOW_KAT[2]);
    rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
    CHECK(rc == BRISK_OK && R.hs.cr_seen);
    CHECK(R.hsk_len > 8 && memcmp(R.hsk, "\x0b\x00\x00\x04\x00\x00\x00\x00", 8) == 0 &&
          R.hsk[8] == 0x14);
    /* sect 7: a 32-byte session id and its echo */
    flow_load(&f, &TLS13_FLOW_KAT[3]);
    rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
    CHECK(rc == BRISK_OK && R.hs.session_id_len == 32);
    /* RFC 8449 4: sect 3's EE record_size_limit (0x4001) is kept; a value below 64 is
     * illegal_parameter */
    flow_load(&f, &TLS13_FLOW_KAT[0]);
    rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
    CHECK(rc == BRISK_OK && R.hs.peer_rsl == 0x4001);
    {
        static uint8_t ee[256];
        size_t k;
        CHECK(f.n_m[1] <= sizeof ee && f.m[1][0] == 0x08);
        memcpy(ee, f.m[1], f.n_m[1]);
        for (k = 4; k + 6 <= f.n_m[1] && memcmp(ee + k, "\x00\x1c\x00\x02", 4) != 0; k++) {
        }
        CHECK(k + 6 <= f.n_m[1]);
        ee[k + 4] = 0;
        ee[k + 5] = 63;
        rc = run_flow(&R, &f, 1, ee, f.n_m[1], FEED_MSG, 0, 0);
        CHECK(rc == BRISK_E_PROTO && R.hs.alert == BRISK__ALERT_ILLEGAL_PARAMETER);
    }
}

static void hs_fixture_negative(void)
{
    flow f;
    size_t i;
    int rc, want;
    for (i = 0; i < NFLOW; i++) {
        if (TLS13_FLOW_KAT[i].alert == 0) {
            continue;
        }
        flow_load(&f, &TLS13_FLOW_KAT[i]);
        want = flow_expect(&TLS13_FLOW_KAT[i]);
        rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
        if (want == 0) {
            check_connected(&R, &f, rc, (long)i);
            continue;
        }
        CHECKI(rc != BRISK_OK && R.hs.state == BRISK__HS_FAILED && R.hs.alert == want, i);
        CHECKI(rc == (want == BRISK__ALERT_DECRYPT_ERROR || want == BRISK__ALERT_BAD_CERTIFICATE ||
                              want == BRISK__ALERT_UNSUPPORTED_CERTIFICATE
                          ? BRISK_E_AUTH
                          : BRISK_E_PROTO),
               i);
        CHECKI(secrets_wiped(&R.hs), i);
    }
}

static void hs_mutations(void)
{
    flow f;
    size_t i, n;
    const uint8_t *ov;
    unsigned e;
    uint8_t one = 0x16;
    int rc;
    for (i = 0; i < sizeof TLS13_MUT_KAT / sizeof TLS13_MUT_KAT[0]; i++) {
        const struct tls13_mut_kat *k = &TLS13_MUT_KAT[i];
        flow_load(&f, &TLS13_FLOW_KAT[k->flow]);
        ov = dec(k->bytes, &n);
        rc = run_flow(&R, &f, k->msg, ov, n, FEED_MSG, 0, 0);
        CHECKI(rc != BRISK_OK && R.hs.state == BRISK__HS_FAILED && R.hs.alert == k->alert, i);
        /* sticky: every later call gives the same answer, nothing is emitted */
        CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, &one, 1) == rc, i);
        CHECKI(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, f.priv1) ==
                   rc,
               i);
        CHECKI(brisk__tls13_hs_pull(&R.hs, &e, R.init, sizeof R.init) == 0, i);
        CHECKI(secrets_wiped(&R.hs), i);
        CHECKI(all_zero(R.hs.out, BRISK__TLS13_OUT_MAX), i); /* the queued CH copy too */
    }
}

/* RFC 9846 5.1: messages never straddle a key change, and each epoch is fed where it belongs. */
static void hs_epochs(void)
{
    flow f;
    brisk__tls13_hs_cfg cfg;
    uint8_t buf[2048], extra = 0x08;
    unsigned e;
    size_t n, i;
    flow_load(&f, &TLS13_FLOW_KAT[0]); /* m: SH EE CERT CV SF */
    memset(&cfg, 0, sizeof cfg);
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;

    for (i = 0; i < 4; i++) {
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, 0x001d, f.priv1) == BRISK_OK);
        if (i == 0) { /* ServerHello at HANDSHAKE */
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[0], f.n_m[0]) ==
                       BRISK_E_PROTO,
                   i);
        } else if (i == 1) { /* EncryptedExtensions at INITIAL */
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK,
                   i);
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[1], f.n_m[1]) ==
                       BRISK_E_PROTO,
                   i);
        } else if (i == 2) { /* SH + EE in one INITIAL feed */
            memcpy(buf, f.m[0], f.n_m[0]);
            memcpy(buf + f.n_m[0], f.m[1], f.n_m[1]);
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, buf, f.n_m[0] + f.n_m[1]) ==
                       BRISK_E_PROTO,
                   i);
        } else { /* bytes after the server Finished in the same HANDSHAKE feed */
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK,
                   i);
            for (n = 1; n < 4; n++) {
                CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[n], f.n_m[n]) ==
                           BRISK_OK,
                       i);
            }
            memcpy(buf, f.m[4], f.n_m[4]);
            buf[f.n_m[4]] = extra;
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, buf, f.n_m[4] + 1) ==
                       BRISK_E_PROTO,
                   i);
        }
        CHECKI(R.hs.alert == BRISK__ALERT_UNEXPECTED_MESSAGE, i);
    }

    /* pull(): the ClientHello and the client Finished are queued together and come out one
     * epoch per call, never mixed. */
    memset(&R, 0, sizeof R);
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
    CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, 0x001d, f.priv1) == BRISK_OK);
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK);
    for (n = 1; n < 5; n++) {
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[n], f.n_m[n]) == BRISK_OK);
    }
    CHECK(R.hs.state == BRISK__HS_CONNECTED);
    n = brisk__tls13_hs_pull(&R.hs, &e, buf, sizeof buf);
    CHECK(n == f.ch1_len && e == BRISK__EPOCH_INITIAL && memcmp(buf, f.ch1, n) == 0);
    n = brisk__tls13_hs_pull(&R.hs, &e, buf, sizeof buf);
    CHECK(n == f.cf_len && e == BRISK__EPOCH_HANDSHAKE && memcmp(buf, f.cf, n) == 0);
    CHECK(brisk__tls13_hs_pull(&R.hs, &e, buf, sizeof buf) == 0);
    /* post-handshake (RFC 9846 4.7): APP bytes are now reassembled like any other message; a
     * message type the connected state does not take (an EncryptedExtensions header, 0x08) is
     * unexpected_message. The post-handshake messages themselves are in test_tls13_rec.c. */
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_APP, &extra, 1) == BRISK_OK);
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_APP, buf, 3) == BRISK_E_PROTO &&
          R.hs.alert == BRISK__ALERT_UNEXPECTED_MESSAGE);
}

static void hs_limits(void)
{
    flow f;
    brisk__tls13_hs_cfg cfg;
    static uint8_t big[4 + 4 + 10 * 1024];
    size_t i, n, der_len, pos;
    uint8_t hdr[4];

    flow_load(&f, &TLS13_FLOW_KAT[0]);
    memset(&cfg, 0, sizeof cfg);
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;
    for (i = 0; i < 3; i++) {
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, 0x001d, f.priv1) == BRISK_OK);
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK);
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[1], f.n_m[1]) == BRISK_OK);
        if (i < 2) {
            /* one past BRISK_TLS_MAX_HS_MSG, and 0xFFFFFF: refused on the header alone, before a
             * body byte is buffered and without any length arithmetic wrapping on 32 bits */
            hdr[0] = 11;
            brisk__store_be24(hdr + 1, i == 0 ? BRISK_TLS_MAX_HS_MSG + 1 : 0xFFFFFF);
            CHECKI(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, hdr, 4) == BRISK_E_PROTO &&
                       R.hs.alert == BRISK__ALERT_ILLEGAL_PARAMETER,
                   i);
            continue;
        }
        /* BRISK__X509_MAX_CHAIN + 1 copies of the trace certificate -> bad_certificate */
        der_len = brisk__load_be24(f.m[2] + 8);
        pos = 8;
        for (n = 0; n <= BRISK__X509_MAX_CHAIN; n++) {
            memcpy(big + pos, f.m[2] + 8, 3 + der_len + 2);
            pos += 3 + der_len + 2;
        }
        big[0] = 11;
        brisk__store_be24(big + 1, (uint32_t)(pos - 4));
        big[4] = 0;
        brisk__store_be24(big + 5, (uint32_t)(pos - 8));
        CHECK(pos <= sizeof big);
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, big, pos) == BRISK_E_AUTH &&
              R.hs.alert == BRISK__ALERT_BAD_CERTIFICATE);
    }
    /* exactly BRISK__X509_MAX_CHAIN is still parsed (the trace cert is accepted by the parser,
     * so the limit above is the only thing that failed) */
    memset(&R, 0, sizeof R);
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
    CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, 0x001d, f.priv1) == BRISK_OK);
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK);
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[1], f.n_m[1]) == BRISK_OK);
    der_len = brisk__load_be24(f.m[2] + 8);
    pos -= 3 + der_len + 2;
    brisk__store_be24(big + 1, (uint32_t)(pos - 4));
    brisk__store_be24(big + 5, (uint32_t)(pos - 8));
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, big, pos) == BRISK_OK &&
          R.hs.state == BRISK__HS_WAIT_CV && R.hs.n_certs == BRISK__X509_MAX_CHAIN);
    /* the certificates point into the kept Certificate message, and the CertificateVerify is
     * reassembled after it rather than over it (hs_feed's in_base) */
    CHECK(R.hs.in_base == pos && R.hs.certs[0].raw == R.hs.in + 11);
}

static void hs_cv(void)
{
    const struct tls13_rfc_kat *r = &TLS13_RFC_KAT[0];
    uint8_t out[98 + BRISK_HASH_MAX_LEN], alert;
    const uint8_t *th, *want, *msg, *sig;
    brisk__x509_cert leaf;
    size_t n, wn, i, mn, sn, checked = 0;
    int rc;

    arena_used = 0;
    th = dec(r->cv_th, &n);
    want = dec(r->cv_content, &wn);
    CHECK(brisk__tls13_cv_content(1, th, n, out) == wn && memcmp(out, want, wn) == 0);
    /* the client-context variant of 4.5.2's worked example */
    want = dec(r->cv_client, &wn);
    CHECK(brisk__tls13_cv_content(0, th, n, out) == wn && memcmp(out, want, wn) == 0);

    for (i = 0; i < sizeof TLS13_CV_KAT / sizeof TLS13_CV_KAT[0]; i++) {
        const struct tls13_cv_kat *k = &TLS13_CV_KAT[i];
        const struct tls13_cv_key *key = &TLS13_CV_KEY[k->key];
#if !BRISK_ENABLE_P384
        if (key->alg == BRISK__X509_KEY_P384) {
            continue;
        }
#endif
        arena_used = 0;
        memset(&leaf, 0, sizeof leaf);
        leaf.key_alg = (uint8_t)key->alg;
        leaf.key = dec(key->key, &leaf.key_len);
        msg = dec(k->msg, &mn);
        sig = dec(k->sig, &sn);
        alert = 0;
        rc = brisk__tls13_cv_verify(&leaf, (uint16_t)k->scheme, msg, mn, sig, sn, &alert);
        CHECKI((rc == BRISK_OK) == (k->ok != 0), i);
        CHECKI(rc == BRISK_OK
                   ? alert == 0
                   : (alert == BRISK__ALERT_DECRYPT_ERROR || alert == BRISK__ALERT_DECODE_ERROR),
               i);
        checked++;
        /* the same key under a certificates-only or mismatched scheme: refused up front */
        if (i % 97 == 0) {
            alert = 0;
            CHECKI(brisk__tls13_cv_verify(&leaf, 0x0401, msg, mn, sig, sn, &alert) == BRISK_E_ARG &&
                       alert == BRISK__ALERT_ILLEGAL_PARAMETER,
                   i);
            alert = 0;
            CHECKI(brisk__tls13_cv_verify(&leaf, key->alg == BRISK__X509_KEY_RSA ? 0x0403 : 0x0804,
                                          msg, mn, sig, sn, &alert) == BRISK_E_ARG &&
                       alert == BRISK__ALERT_ILLEGAL_PARAMETER,
                   i);
        }
    }
    CHECK(checked > 1000);
}

static void u16s(const char *hex, uint16_t *out, size_t *n)
{
    size_t i, len;
    const uint8_t *b = dec(hex, &len);
    for (i = 0; i < len / 2; i++) {
        out[i] = (uint16_t)brisk__load_be16(b + 2 * i);
    }
    *n = len / 2;
}

static void hs_ch_write(void)
{
    uint16_t suites[8], groups[8], sigs[16];
    uint8_t out[1024], priv[32];
    brisk__tls13_ch_params p;
    brisk__tls13_hs_cfg cfg;
    brisk__tls13_psk psk;
    size_t i, len, want_len, n;
    const uint8_t *want;
    int j;

    memset(priv, 0x11, sizeof priv);
    memset(&cfg, 0, sizeof cfg);
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;
    for (i = 0; i < sizeof TLS13_CHW_KAT / sizeof TLS13_CHW_KAT[0]; i++) {
        const struct tls13_chw_kat *k = &TLS13_CHW_KAT[i];
        arena_used = 0;
        memset(&p, 0, sizeof p);
        p.random = dec(k->random, &n);
        p.session_id = dec(k->sid, &p.session_id_len);
        u16s(k->suites, suites, &p.n_suites);
        u16s(k->groups, groups, &p.n_groups);
        u16s(k->sigs, sigs, &p.n_sig_schemes);
        p.suites = suites;
        p.groups = groups;
        p.sig_schemes = sigs;
        p.share_group = (uint16_t)k->share_group;
        p.share_pub = dec(k->share_pub, &p.share_pub_len);
        p.sni = k->sni;
        p.sni_len = strlen(k->sni);
        p.cookie = dec(k->cookie, &p.cookie_len);
        p.alpn = dec(k->alpn, &p.alpn_len);
        p.psk_modes = (uint8_t)k->psk_modes;
        memset(&psk, 0, sizeof psk);
        if (*k->identity) {
            psk.identity = dec(k->identity, &psk.identity_len);
            psk.obf_age = k->obf_age;
            psk.psk_len = (uint8_t)k->psk_len;
            psk.suite = 0x1301;
            p.psk = &psk;
        }
        want = dec(k->ch, &want_len);
        /* byte-exact against the Python builder in tools/kat.py */
        CHECKI(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK && len == want_len &&
                   memcmp(out, want, len) == 0,
               i);
        /* every cap below the size fails without writing past it */
        for (n = 0; n < want_len; n++) {
            out[n] = 0xEE;
            CHECKI(brisk__tls13_ch_write(&p, out, n, &len) == BRISK_E_ARG && len == 0 &&
                       out[n] == 0xEE,
                   n);
        }
        /* round trip: the engine learns exactly the offer the params describe */
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        if (p.psk != NULL) {
            /* 4.3.11: pre_shared_key is last, and absorbing it needs the PSK itself */
            CHECKI(brisk__load_be16(out + len - (4 + 2 + 2 + psk.identity_len + 4 + 2 + 1 + 32)) ==
                       41,
                   i);
            CHECKI(brisk__tls13_hs_client_hello(&R.hs, out, len, p.share_group, priv) ==
                       BRISK_E_ARG,
                   i);
            CHECKI(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_OK, i);
        }
        /* a cookie belongs only in CH2 (RFC 9846 4.3.2) */
        CHECKI(brisk__tls13_hs_client_hello(&R.hs, out, len, p.share_group, priv) ==
                   (p.cookie_len ? BRISK_E_ARG : BRISK_OK),
               i);
        if (p.cookie_len) {
            continue;
        }
        CHECKI(R.hs.n_suites == p.n_suites && R.hs.n_groups == p.n_groups &&
                   R.hs.n_sigs == p.n_sig_schemes && R.hs.session_id_len == p.session_id_len,
               i);
        for (j = 0; j < (int)p.n_sig_schemes; j++) {
            CHECKI(R.hs.offered_sigs[j] == sigs[j], j);
        }
        CHECKI(R.hs.share_group == p.share_group && memcmp(R.hs.priv, priv, 32) == 0, i);
    }

    /* RFC 6066 3: an IP literal is never sent as server_name */
    arena_used = 0;
    {
        const struct tls13_chw_kat *k = &TLS13_CHW_KAT[0];
        uint8_t a[1024];
        size_t alen;
        memset(&p, 0, sizeof p);
        p.random = dec(k->random, &n);
        p.share_group = 0x001d;
        p.share_pub = priv;
        p.share_pub_len = 32;
        p.sni = "192.0.2.1";
        p.sni_len = 9;
        CHECK(brisk__tls13_ch_write(&p, a, sizeof a, &alen) == BRISK_OK);
        p.sni = NULL;
        p.sni_len = 0;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        CHECK(alen == len && memcmp(a, out, len) == 0);
        /* the defaults: TLS 1.3 only, an ECDHE group list, no SHA-1 anywhere */
        memset(&R, 0, sizeof R);
        cfg.quic = 1; /* RFC 9001 8.4: and this CH has an empty session id */
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        /* RFC 9001 8.2: without quic_transport_parameters a QUIC CH is refused */
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x001d, priv) == BRISK_E_ARG);
        p.quic_tp = (const uint8_t *)"\x0f\x00"; /* initial_source_connection_id, empty */
        p.quic_tp_len = 2;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        CHECK(len == alen + 6 && memcmp(out + len - 6, "\x00\x39\x00\x02\x0f\x00", 6) == 0);
        /* RFC 9001 8.1: and without ALPN, which QUIC makes mandatory */
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x001d, priv) == BRISK_E_ARG);
        p.alpn = (const uint8_t *)"\x04mqtt";
        p.alpn_len = 5;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x001d, priv) == BRISK_OK);
        CHECK(R.hs.n_suites == 3 && R.hs.offered_suites[0] == 0x1303 && R.hs.n_groups == 2);
        for (j = 0; j < R.hs.n_sigs; j++) {
            CHECKI((R.hs.offered_sigs[j] >> 8) != 0x02 && R.hs.offered_sigs[j] != 0x0809, j);
        }
        CHECK(R.hs.offered_sigs[0] == 0x0403);
        /* a 32-byte session id over QUIC is refused */
        memset(a, 0x42, 32);
        p.session_id = a;
        p.session_id_len = 32;
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x001d, priv) == BRISK_E_ARG);
        /* 8.2: and the same CH, with its session id, over TCP: MUST NOT carry the extension */
        cfg.quic = 0;
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x001d, priv) == BRISK_E_ARG);
        p.quic_tp = NULL;
        p.quic_tp_len = 0;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x001d, priv) == BRISK_OK);
        /* the share must be in supported_groups, and have its group's length */
        p.groups = groups;
        groups[0] = 0x0017;
        p.n_groups = 1;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
        /* 4.2.8: a group with no ECDHE here (secp384r1) cannot carry an empty share */
        groups[0] = 0x0018;
        p.share_group = 0x0018;
        p.share_pub_len = 0;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
        p.share_group = 0x001d;
        p.groups = NULL;
        p.share_pub_len = 31;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
        /* absorbed with the wrong group for its share: refused */
        p.share_pub_len = 32;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x0017, priv) == BRISK_E_ARG);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len - 1, 0x001d, priv) == BRISK_E_ARG);
        CHECK(R.hs.state == BRISK__HS_START);
        /* RFC 6066 3: the trailing root dot is stripped from host_name; "." alone is refused */
        p.session_id = NULL; /* it points into a, which is reused below */
        p.session_id_len = 0;
        p.sni = "device.example.com";
        p.sni_len = 18;
        CHECK(brisk__tls13_ch_write(&p, a, sizeof a, &alen) == BRISK_OK);
        p.sni = "device.example.com.";
        p.sni_len = 19;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        CHECK(alen == len && memcmp(a, out, len) == 0);
        p.sni = ".";
        p.sni_len = 1;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
        p.sni = NULL;
        p.sni_len = 0;
        /* 4.3.11: an identity that overflows pre_shared_key's extension_data<0..2^16-1> (first
         * row) or the extensions block (second) is refused, never written with a wrapped length */
        {
            static const size_t big[] = {0xffff - 11 - 32 + 1, 0xffff - 11 - 32};
            brisk__tls13_psk bp;
            uint8_t *id = (uint8_t *)calloc(1, big[0]), *wb = (uint8_t *)malloc(0x30000);
            if (id == NULL || wb == NULL) {
                exit(2);
            }
            memset(&bp, 0, sizeof bp);
            bp.identity = id;
            bp.psk_len = 32;
            bp.suite = 0x1301;
            p.psk = &bp;
            p.psk_modes = 1;
            for (n = 0; n < 2; n++) {
                bp.identity_len = big[n];
                len = 1;
                CHECKI(brisk__tls13_ch_write(&p, wb, 0x30000, &len) == BRISK_E_ARG && len == 0, n);
            }
            p.psk = NULL;
            p.psk_modes = 0;
            free(id);
            free(wb);
        }
    }
    /* A ClientHello whose only (so last) extension is a u16 list with empty or 1-byte data: the
     * list prefix sits at or past the end of an exact-size heap buffer, so ASan flags any read
     * of it before the length check. */
    {
        static const uint8_t tails[][5] = {{0x00, 0x0a, 0x00, 0x00},
                                           {0x00, 0x2b, 0x00, 0x00},
                                           {0x00, 0x0d, 0x00, 0x01, 0x00},
                                           {0x00, 0x2b, 0x00, 0x01, 0x02}};
        static const size_t tail_len[] = {4, 4, 5, 5};
        size_t e, t, total;
        uint8_t *m;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        e = 4 + 35 + out[4 + 34];
        e += 2 + brisk__load_be16(out + e) + 2; /* cipher_suites, compression: at ext length */
        for (t = 0; t < 4; t++) {
            total = e + 2 + tail_len[t];
            m = (uint8_t *)malloc(total);
            if (m == NULL) {
                exit(2);
            }
            memcpy(m, out, e);
            m[1] = (uint8_t)((total - 4) >> 16);
            m[2] = (uint8_t)((total - 4) >> 8);
            m[3] = (uint8_t)(total - 4);
            m[e] = 0;
            m[e + 1] = (uint8_t)tail_len[t];
            memcpy(m + e + 2, tails[t], tail_len[t]);
            memset(&R, 0, sizeof R);
            CHECKI(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK, t);
            CHECKI(brisk__tls13_hs_client_hello(&R.hs, m, total, 0x001d, priv) == BRISK_E_ARG, t);
            CHECKI(R.hs.state == BRISK__HS_START, t);
            free(m);
        }
    }
    /* 4.2.8: absorbing a CH whose key share is {secp384r1, empty} is refused, or a matching
     * empty server share would reach the ECDH with no point behind it */
    {
        size_t e, end, k;
        groups[0] = 0x001d;
        groups[1] = 0x0018;
        p.groups = groups;
        p.n_groups = 2;
        CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
        e = 4 + 35 + out[4 + 34];
        e += 2 + brisk__load_be16(out + e) + 2;
        end = e + 2 + brisk__load_be16(out + e);
        CHECK(end == len);
        for (k = e + 2; k + 4 <= end && brisk__load_be16(out + k) != 0x0033;
             k += 4 + brisk__load_be16(out + k + 2)) {
        }
        CHECK(k + 4 + 38 <= end && brisk__load_be16(out + k + 2) == 38);
        memmove(out + k + 10, out + k + 42, end - (k + 42));
        memcpy(out + k + 2, "\x00\x06\x00\x04\x00\x18\x00\x00", 8);
        len -= 32;
        brisk__store_be16(out + e, (uint32_t)(len - e - 2));
        out[1] = (uint8_t)((len - 4) >> 16);
        brisk__store_be16(out + 2, (uint32_t)(len - 4));
        memset(&R, 0, sizeof R);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, out, len, 0x0018, priv) == BRISK_E_ARG);
        CHECK(R.hs.state == BRISK__HS_START);
        p.groups = NULL;
        p.n_groups = 0;
    }
}

/* No path to CONNECTED without an authenticator: deleting the guard in hs_init must fail
 * exactly this row. */
static void hs_init_guard(void)
{
    brisk__tls13_hs_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_E_ARG);
    cfg.auth = stub_auth;
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, brisk__tls13_hs_scratch_size() - 1) ==
          BRISK_E_ARG);
    CHECK(brisk__tls13_hs_init(&R.hs, NULL, g_scratch, g_scratch_len) == BRISK_E_ARG);
}

/* RFC 9001 8.2 through the engine: the sect 3 flow with
 * quic_transport_parameters appended to CH1 (and to the EE where the row needs
 * it). Each check stops at the EE, so the transcript change the new bytes cause
 * never matters. */
typedef struct {
    uint8_t got[16];
    size_t len;
    int calls, rc;
} tp_capture;

static int on_tp(void *ctx, const uint8_t *tp, size_t len)
{
    tp_capture *c = (tp_capture *)ctx;
    c->calls++;
    c->len = len;
    if (len <= sizeof c->got) {
        memcpy(c->got, tp, len);
    }
    return c->rc;
}

/* m plus one extension {type, v} appended to its extension block, whose
 * length field sits at ext_at; the message header is fixed up. */
static size_t add_ext(uint8_t *out, const uint8_t *m, size_t n, size_t ext_at, unsigned type,
                      const uint8_t *v, size_t vl)
{
    memmove(out, m, n);
    brisk__store_be16(out + n, type);
    out[n + 2] = 0;
    out[n + 3] = (uint8_t)vl;
    memcpy(out + n + 4, v, vl);
    brisk__store_be16(out + ext_at, (uint32_t)(brisk__load_be16(out + ext_at) + 4 + vl));
    n += 4 + vl;
    out[1] = (uint8_t)((n - 4) >> 16);
    brisk__store_be16(out + 2, (uint32_t)(n - 4));
    return n;
}

static int tp_run(const flow *f, int quic, const uint8_t *ch, size_t ch_len, const uint8_t *ee,
                  size_t ee_len, tp_capture *c)
{
    brisk__tls13_hs_cfg cfg;
    int rc;
    memset(&cfg, 0, sizeof cfg);
    memset(&R, 0, sizeof R);
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;
    cfg.quic = (uint8_t)quic;
    cfg.on_peer_tp = on_tp;
    cfg.tp_ctx = c;
    if (brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) != BRISK_OK) {
        return 99;
    }
    rc = brisk__tls13_hs_client_hello(&R.hs, ch, ch_len, (uint16_t)f->k->g1, f->priv1);
    if (rc != BRISK_OK) {
        return rc;
    }
    if (brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f->m[0], f->n_m[0]) != BRISK_OK) {
        return 98;
    }
    return brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, ee, ee_len);
}

static void hs_quic_tp(void)
{
    static const uint8_t TP[] = {0x0f, 0x04, 0xde, 0xad, 0xbe, 0xef};
    static uint8_t ch[1024], ee[256];
    flow f;
    tp_capture c;
    size_t ch_len, ee_len, e;
    int rc;

    flow_load(&f, &TLS13_FLOW_KAT[0]);
    CHECK(f.sh_at == 0 && f.ch1[4 + 34] == 0 && f.m[1][0] == 0x08 && f.n_m[1] + 30 <= sizeof ee &&
          f.ch1_len + 30 <= sizeof ch);
    e = 4 + 35;
    e += 2 + brisk__load_be16(f.ch1 + e) + 2; /* cipher_suites, compression: at ext length */
    /* RFC 9001 8.1: over QUIC the CH offers ALPN and the EE answers it */
    ch_len = add_ext(ch, f.ch1, f.ch1_len, e, 57, TP, 2);
    ch_len = add_ext(ch, ch, ch_len, e, 16, (const uint8_t *)"\x00\x05\x04mqtt", 7);
    ee_len = add_ext(ee, f.m[1], f.n_m[1], 4, 57, TP, sizeof TP);
    ee_len = add_ext(ee, ee, ee_len, 4, 16, (const uint8_t *)"\x00\x05\x04mqtt", 7);

    /* QUIC, the server sends it: handed over once, byte-exact, before CONNECTED
     */
    memset(&c, 0, sizeof c);
    rc = tp_run(&f, 1, ch, ch_len, ee, ee_len, &c);
    CHECK(rc == BRISK_OK && R.hs.state == BRISK__HS_WAIT_CERT_CR && c.calls == 1 &&
          c.len == sizeof TP && memcmp(c.got, TP, sizeof TP) == 0);
    /* QUIC, the EE leaves it out: missing_extension (RFC 9001 8.2) */
    memset(&c, 0, sizeof c);
    rc = tp_run(&f, 1, ch, ch_len, f.m[1], f.n_m[1], &c);
    CHECK(rc == BRISK_E_PROTO && R.hs.alert == BRISK__ALERT_MISSING_EXTENSION && c.calls == 0);
    CHECK(secrets_wiped(&R.hs));
    /* the caller refuses the parameters: a local verdict, internal_error,
     * BRISK_E_ARG */
    memset(&c, 0, sizeof c);
    c.rc = 1;
    rc = tp_run(&f, 1, ch, ch_len, ee, ee_len, &c);
    CHECK(rc == BRISK_E_ARG && R.hs.alert == BRISK__ALERT_INTERNAL_ERROR && c.calls == 1);
    /* QUIC without the extension in CH1, TCP with it: the caller's CH is refused
     */
    memset(&c, 0, sizeof c);
    CHECK(tp_run(&f, 1, f.ch1, f.ch1_len, ee, ee_len, &c) == BRISK_E_ARG);
    CHECK(tp_run(&f, 0, ch, ch_len, ee, ee_len, &c) == BRISK_E_ARG);
    /* TCP, an unsolicited echo: unsupported_extension, never handed over */
    rc = tp_run(&f, 0, f.ch1, f.ch1_len, ee, ee_len, &c);
    CHECK(rc == BRISK_E_PROTO && R.hs.alert == BRISK__ALERT_UNSUPPORTED_EXTENSION && c.calls == 0);
}

/* internal_error is a local fault, never blamed on the peer (BRISK_E_ARG, not
 * BRISK_E_PROTO): an on_secret refusal after the ServerHello, and the
 * production authenticator with an unusable reference host or no ctx at all. */
static int refuse_secret(void *ctx, unsigned epoch, int is_send, uint16_t suite, const uint8_t *s,
                         size_t len)
{
    (void)ctx;
    (void)epoch;
    (void)is_send;
    (void)suite;
    (void)s;
    (void)len;
    return 1;
}

static void hs_local_faults(void)
{
    brisk__tls13_hs_cfg cfg;
    flow f;
    size_t i, m;
    int rc, v;

    flow_load(&f, &TLS13_FLOW_KAT[0]);
    memset(&cfg, 0, sizeof cfg);
    memset(&R, 0, sizeof R);
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;
    cfg.on_secret = refuse_secret;
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
    CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, f.priv1) ==
          BRISK_OK);
    rc = brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]);
    CHECK(rc == BRISK_E_ARG && R.hs.alert == BRISK__ALERT_INTERNAL_ERROR);
    CHECK(secrets_wiped(&R.hs));

    for (i = 0; i < NFLOW; i++) { /* the first accepted flow with a real chain */
        if (TLS13_FLOW_KAT[i].alert == 0 && *TLS13_FLOW_KAT[i].root) {
            break;
        }
    }
    CHECK(i < NFLOW);
    if (i == NFLOW) {
        return;
    }
    flow_load(&f, &TLS13_FLOW_KAT[i]);
    for (v = 0; v < 2; v++) {
        memset(&cfg, 0, sizeof cfg);
        memset(&R, 0, sizeof R);
        R.an.der = f.root;
        R.an.len = f.root_len;
        R.trust.find_anchor = anchor_fn;
        R.trust.anchor_ctx = &R.an;
        R.ax.host = ""; /* RFC 9525: an empty reference identity is a caller bug */
        R.ax.host_len = 0;
        R.ax.trust = &R.trust;
        R.ax.now = (int64_t)f.k->now;
        cfg.auth = brisk__tls13_auth_x509;
        cfg.auth_ctx = v == 0 ? &R.ax : NULL;
        CHECKI(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK, v);
        rc = brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, f.priv1);
        for (m = 0; rc == BRISK_OK && m < f.count; m++) {
            rc = brisk__tls13_hs_feed(&R.hs,
                                      m <= f.sh_at ? BRISK__EPOCH_INITIAL : BRISK__EPOCH_HANDSHAKE,
                                      f.m[m], f.n_m[m]);
        }
        CHECKI(rc == BRISK_E_ARG && R.hs.alert == BRISK__ALERT_INTERNAL_ERROR, v);
    }
}
static void hs_wipe_exporter(void)
{
    flow f;
    uint8_t a[32], b[32];
    int rc;
    flow_load(&f, &TLS13_FLOW_KAT[0]);
    rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
    CHECK(rc == BRISK_OK);
    CHECK(brisk__tls13_hs_exporter(&R.hs, "EXPORTER-brisk", (const uint8_t *)"ctx", 3, a, 32) ==
          BRISK_OK);
    CHECK(brisk__tls_ks_exporter(BRISK_HASH_SHA256, f.sec[4], "EXPORTER-brisk",
                                 (const uint8_t *)"ctx", 3, b, 32) == BRISK_OK);
    CHECK(memcmp(a, b, 32) == 0);
    brisk__tls13_hs_wipe(&R.hs);
    CHECK(all_zero((const uint8_t *)&R.hs, sizeof R.hs));
    CHECK(all_zero(g_scratch, g_scratch_len - 8));
    CHECK(brisk__tls13_hs_exporter(&R.hs, "x", NULL, 0, a, 32) == BRISK_E_ARG);
    brisk__tls13_hs_wipe(NULL);
}

/* ---------------------------------------------------------------- M3 line 3
 * ---------------- */
/* Resumption (RFC 9846 4.3.11, 4.7.1), ALPN (RFC 7301), SNI (RFC 6066 3), mTLS
 * (4.5.1, 4.5.2). */

struct ip_kat {
    const char *text, *want, *note;
};
#include "kat/x509_ip.inc"

/* RFC 8448 sect 4: the binder over the published 'ClientHello prefix' (4.3.11.2
 * + 7.1), inputs unaligned; the early secret is HKDF-Extract(0, PSK); a SHA-384
 * self-consistency row. */
static void hs_psk_binder(void)
{
    const struct tls13_psk_kat *k = &TLS13_PSK_KAT[0];
    static uint8_t in[2][64 + 1];
    uint8_t th[48], out[48 + 1], bk[48], fk[48], mac[48];
    const uint8_t *psk, *prefix, *bh, *binder, *early;
    size_t n, pl;
    brisk__tls_ks ks;

    arena_used = 0;
    psk = dec(k->psk, &n);
    CHECK(n == 32);
    prefix = dec(k->prefix, &pl);
    bh = dec(k->binder_hash, &n);
    binder = dec(k->binder, &n);
    early = dec(k->early, &n);
    brisk_sha256(prefix, pl, th);
    CHECK(memcmp(th, bh, 32) == 0);
    memcpy(in[0] + 1, psk, 32);
    memcpy(in[1] + 1, bh, 32);
    CHECK(brisk__tls_psk_binder(BRISK_HASH_SHA256, in[0] + 1, 32, in[1] + 1, out + 1) == BRISK_OK &&
          memcmp(out + 1, binder, 32) == 0);
    CHECK(brisk__tls_ks_init(&ks, BRISK_HASH_SHA256, psk, 32) == BRISK_OK &&
          memcmp(ks.secret, early, 32) == 0);
    brisk__tls_ks_wipe(&ks);
    /* SHA-384: the same composition spelled out with the HKDF primitives */
    memset(in[0], 0xA5, sizeof in[0]);
    memset(th, 0x5A, sizeof th);
    CHECK(brisk__tls_psk_binder(BRISK_HASH_SHA384, in[0], 48, th, out) == BRISK_OK);
    CHECK(brisk__tls_ks_init(&ks, BRISK_HASH_SHA384, in[0], 48) == BRISK_OK);
    brisk_sha384((const uint8_t *)"", 0, mac);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, ks.secret, 48, "res binder", mac, 48, bk,
                                   48) == BRISK_OK);
    CHECK(brisk__tls_finished_mac(BRISK_HASH_SHA384, bk, th, fk) == BRISK_OK &&
          memcmp(fk, out, 48) == 0);
    brisk__tls_ks_wipe(&ks);
    CHECK(brisk__tls_psk_binder((brisk_hash_alg)99, in[0], 48, th, out) == BRISK_E_ARG);
}

typedef struct {
    int calls, export_rc;
    brisk__tls13_ticket t; /* copied inside the callback, psk included */
    uint8_t nonce[256], ticket[512], blob[BRISK_TICKET_MAX];
    size_t blob_len;
    int64_t now;
} tk_cap;

static int tk_cb(void *ctx, const brisk__tls13_ticket *t)
{
    tk_cap *c = (tk_cap *)ctx;
    c->calls++;
    c->t = *t;
    if (t->nonce_len <= sizeof c->nonce && t->ticket_len <= sizeof c->ticket) {
        memcpy(c->nonce, t->nonce, t->nonce_len);
        memcpy(c->ticket, t->ticket, t->ticket_len);
    }
    /* export inside the callback: the PSK is wiped when it returns */
    c->export_rc =
        brisk__tls13_ticket_export(t, c->now, "server", 6, c->blob, sizeof c->blob, &c->blob_len);
    return 0;
}

/* Feed the sect 3 NewSessionTicket into a CONNECTED run: whole, and one byte at
 * a time. */
static void feed_nst(const flow *f, const uint8_t *nst, size_t nn, tk_cap *c, int bytes, long idx)
{
    size_t i;
    int rc = BRISK_OK;
    rc = run_flow(&R, f, -1, NULL, 0, FEED_MSG, 0, 0);
    CHECKI(rc == BRISK_OK, idx);
    R.hs.cfg.on_ticket = tk_cb;
    R.hs.cfg.ticket_ctx = c;
    for (i = 0; rc == BRISK_OK && bytes && i < nn; i++) {
        rc = brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_APP, nst + i, 1);
    }
    if (!bytes) {
        rc = brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_APP, nst, nn);
    }
    CHECKI(rc == BRISK_OK && c->calls == 1, idx);
}

static void hs_ticket_from_nst(void)
{
    const struct tls13_psk_kat *k = &TLS13_PSK_KAT[0];
    static tk_cap c;
    flow f;
    const uint8_t *nst, *psk, *ticket, *blob, *fresh;
    size_t nn, n, tl, bl;
    int bytes;

    for (bytes = 0; bytes < 2; bytes++) {
        flow_load(&f, &TLS13_FLOW_KAT[0]); /* sect 3 */
        nst = dec(k->nst, &nn);
        psk = dec(k->psk, &n);
        ticket = dec(k->ticket, &tl);
        blob = dec(k->blob, &bl);
        memset(&c, 0, sizeof c);
        c.now = (int64_t)k->issued;
        feed_nst(&f, nst, nn, &c, bytes, bytes);
        CHECKI(c.t.lifetime == k->lifetime && c.t.age_add == k->age_add && c.t.nonce_len == 2 &&
                   c.nonce[0] == 0 && c.nonce[1] == 0,
               bytes);
        CHECKI(c.t.ticket_len == tl && memcmp(c.ticket, ticket, tl) == 0, bytes);
        CHECKI(c.t.suite == 0x1301 && c.t.psk_len == 32 && memcmp(c.t.psk, psk, 32) == 0, bytes);
        CHECKI(c.export_rc == BRISK_OK && c.blob_len == bl && memcmp(c.blob, blob, bl) == 0, bytes);
    }
    /* a NST inside the resumed connection yields a fresh PSK from that
     * connection's res master */
    flow_load(&f, &TLS13_FLOW_KAT[flow_find("RFC 8448 sect 4 minus 0-RTT")]);
    nst = dec(k->nst, &nn);
    fresh = dec(k->fresh, &n);
    memset(&c, 0, sizeof c);
    c.now = (int64_t)k->issued;
    feed_nst(&f, nst, nn, &c, 0, 9);
    CHECK(c.t.psk_len == 32 && memcmp(c.t.psk, fresh, 32) == 0);
    /* no hook: the ticket is silently ignored (4.7.1) */
    flow_load(&f, &TLS13_FLOW_KAT[0]);
    nst = dec(k->nst, &nn);
    CHECK(run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0) == BRISK_OK &&
          brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_APP, nst, nn) == BRISK_OK);
}

/* A ticket as the export side sees it, from the sect 3 values. */
static void tk_from_kat(brisk__tls13_ticket *t, const struct tls13_psk_kat *k)
{
    size_t n;
    memset(t, 0, sizeof *t);
    t->lifetime = k->lifetime;
    t->age_add = k->age_add;
    t->ticket = dec(k->ticket, &t->ticket_len);
    memcpy(t->psk, dec(k->psk, &n), 32);
    t->psk_len = 32;
    t->suite = 0x1301;
}

static void hs_ticket_blob(void)
{
    const struct tls13_psk_kat *k = &TLS13_PSK_KAT[0];
    static uint8_t buf[BRISK_TICKET_MAX + 64], big[BRISK_TICKET_MAX + 8];
    brisk__tls13_ticket t;
    brisk__tls13_psk p;
    const uint8_t *blob, *psk, *ticket;
    uint8_t *b = buf + 1; /* odd address */
    size_t bl, n, tl, i;
    int64_t T = (int64_t)k->issued;

    arena_used = 0;
    blob = dec(k->blob, &bl);
    psk = dec(k->psk, &n);
    ticket = dec(k->ticket, &tl);
    memcpy(b, blob, bl);
    /* round trip, and 4.3.11.1's obfuscated age */
    CHECK(brisk__tls13_ticket_import(b, bl, "server", 6, (int64_t)k->now, &p) == BRISK_OK);
    CHECK(p.identity == b + bl - tl && p.identity_len == tl && memcmp(p.identity, ticket, tl) == 0);
    CHECK(p.psk_len == 32 && p.suite == 0x1301 && memcmp(p.psk, psk, 32) == 0);
    CHECK(p.obf_age == k->obf_age);
    CHECK(brisk__tls13_ticket_import(b, bl, "Server", 6, T, &p) == BRISK_OK &&
          p.obf_age == k->age_add);
    CHECK(brisk__tls13_ticket_import(b, bl, "SERVER.", 7, T, &p) == BRISK_OK);
    /* the SNI stored is the one sent: a trailing dot changes nothing */
    tk_from_kat(&t, k);
    CHECK(brisk__tls13_ticket_export(&t, T, "server.", 7, big, sizeof big, &n) == BRISK_OK &&
          n == bl && memcmp(big, blob, bl) == 0);
    /* uint32 wrap: age_add 0xffffffff, 5 ms old -> 4 */
    t.age_add = 0xffffffffu;
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, sizeof big, &n) == BRISK_OK);
    CHECK(brisk__tls13_ticket_import(big, n, "server", 6, T + 5, &p) == BRISK_OK && p.obf_age == 4);

    /* every truncation, a trailing byte, and each malformed field: refused,
     * output wiped */
    for (i = 0; i <= bl; i++) {
        memset(&p, 0xCC, sizeof p);
        memcpy(b, blob, bl);
        b[bl] = 0;
        CHECKI(brisk__tls13_ticket_import(b, i == bl ? bl + 1 : i, "server", 6, T, &p) ==
                       BRISK_E_ARG &&
                   all_zero((const uint8_t *)&p, sizeof p),
               i);
    }
    for (i = 0; i < 7; i++) {
        memcpy(b, blob, bl);
        n = bl;
        switch (i) {
        case 0:
            b[0] = 2;
            break; /* version */
        case 1:
            brisk__store_be16(b + 1, 0x1304);
            break; /* unknown suite */
        case 2:
            b[19] = 48;
            break; /* psk_len != the suite's HashLen */
        case 3:
            brisk__store_be16(b + 1, 0x1302);
            break; /* suite of another hash */
        case 4:
            b[19] = 31;
            break;
        case 5: /* ticket_len 0 */
            n = bl - tl;
            brisk__store_be16(b + n - 2, 0);
            break;
        default:
            brisk__store_be32(b + 11, 0);
            break; /* lifetime 0 */
        }
        memset(&p, 0xCC, sizeof p);
        CHECKI(brisk__tls13_ticket_import(b, n, "server", 6, T, &p) == BRISK_E_ARG &&
                   all_zero((const uint8_t *)&p, sizeof p),
               i);
    }
    memcpy(b, blob, bl);
    CHECK(brisk__tls13_ticket_import(b, bl, "servers", 7, T, &p) == BRISK_E_ARG);
    CHECK(brisk__tls13_ticket_import(b, bl, "other.", 6, T, &p) == BRISK_E_ARG);
    CHECK(brisk__tls13_ticket_import(b, bl, "", 0, T, &p) == BRISK_E_ARG);
    /* the clock: backwards is refused; the age limit is min(lifetime, 604800) s
     * (4.7.1) */
    CHECK(brisk__tls13_ticket_import(b, bl, "server", 6, T - 1, &p) == BRISK_E_ARG);
    CHECK(brisk__tls13_ticket_import(b, bl, "server", 6, T + (int64_t)k->lifetime * 1000 - 1, &p) ==
          BRISK_OK);
    CHECK(brisk__tls13_ticket_import(b, bl, "server", 6, T + (int64_t)k->lifetime * 1000, &p) ==
          BRISK_E_ARG);
    tk_from_kat(&t, k);
    t.lifetime = 700000;
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, sizeof big, &n) == BRISK_OK);
    CHECK(brisk__tls13_ticket_import(big, n, "server", 6, T + 604800000LL - 1, &p) == BRISK_OK);
    CHECK(brisk__tls13_ticket_import(big, n, "server", 6, T + 604800000LL, &p) == BRISK_E_ARG);
    /* issued_ms far away from 32 bits: the be64 field and the 64-bit age both
     * hold */
    CHECK(brisk__tls13_ticket_export(&t, 0x123456789ABCLL, "server", 6, big, sizeof big, &n) ==
          BRISK_OK);
    CHECK(brisk__tls13_ticket_import(big, n, "server", 6, 0x123456789ABCLL + 0x100000000LL, &p) ==
          BRISK_E_ARG); /* 2^32 ms is past 7 days: no truncation to 32 bits */
    CHECK(brisk__tls13_ticket_import(big, n, "server", 6, 0x123456789ABCLL + 1000, &p) ==
              BRISK_OK &&
          p.obf_age == 1000 + k->age_add);

    /* export refusals: lifetime 0, a short cap (out wiped), a too-long SNI, a
     * too-big ticket */
    tk_from_kat(&t, k);
    t.lifetime = 0;
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, sizeof big, &n) == BRISK_E_ARG &&
          n == 0);
    tk_from_kat(&t, k);
    memset(big, 0xEE, sizeof big);
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, bl - 1, &n) == BRISK_E_ARG &&
          n == 0 && all_zero(big, bl - 1) && big[bl - 1] == 0xEE);
    memset(buf, 'a', 256);
    CHECK(brisk__tls13_ticket_export(&t, T, (const char *)buf, 256, big, sizeof big, &n) ==
          BRISK_E_ARG);
    CHECK(brisk__tls13_ticket_export(&t, T, (const char *)buf, 255, big, sizeof big, &n) ==
          BRISK_OK);
    t.ticket = buf;
    t.ticket_len = BRISK_TICKET_MAX;
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, sizeof big, &n) == BRISK_E_ARG);
    t.ticket_len = BRISK_TICKET_MAX - (20 + 32 + 1 + 6 + 2);
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, sizeof big, &n) == BRISK_OK &&
          n == BRISK_TICKET_MAX);
    CHECK(brisk__tls13_ticket_import(big, n + 1, "server", 6, T, &p) == BRISK_E_ARG);
    t.psk_len = 48;
    CHECK(brisk__tls13_ticket_export(&t, T, "server", 6, big, sizeof big, &n) == BRISK_E_ARG);
}

/* A ClientHello from ch_write (with modes, no PSK) plus raw extensions appended
 * in order. */
static size_t ch_plus(uint8_t *out, size_t cap, int modes, const uint16_t *types,
                      const uint8_t *const *vals, const size_t *lens, size_t n)
{
    brisk__tls13_ch_params p;
    static uint8_t pub[32];
    size_t len, e, i;
    const struct tls13_chw_kat *k = &TLS13_CHW_KAT[0];
    memset(&p, 0, sizeof p);
    p.random = dec(k->random, &len);
    p.share_group = 0x001d;
    p.share_pub = pub;
    p.share_pub_len = 32;
    p.psk_modes = (uint8_t)modes;
    if (brisk__tls13_ch_write(&p, out, cap, &len) != BRISK_OK) {
        exit(2);
    }
    e = 4 + 35 + out[4 + 34];
    e += 2 + brisk__load_be16(out + e) + 2;
    for (i = 0; i < n; i++) {
        len = add_ext(out, out, len, e, types[i], vals[i], lens[i]);
    }
    return len;
}

/* hs_client_hello's PSK rules (4.3.9, 4.3.11): each refusal leaves the engine
 * in START. */
static void hs_psk_absorb(void)
{
    static const uint8_t ONE[] = {
        /* one identity "t" age 0, one 32-byte binder */
        0x00, 0x07, 0x00, 0x01, 't', 0, 0, 0, 0, 0x00, 0x21, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0,    0,    0,    0,   0, 0, 0, 0, 0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static uint8_t two[128], b48[128], b31[128];
    static uint8_t ch[1024];
    const uint8_t *vals[3];
    size_t lens[3], len, n;
    uint16_t types[3];
    brisk__tls13_hs_cfg cfg;
    brisk__tls13_psk psk;
    uint8_t priv[32];
    size_t i;

    arena_used = 0;
    memset(priv, 0x11, sizeof priv);
    memset(&cfg, 0, sizeof cfg);
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;
    memset(&psk, 0, sizeof psk);
    memset(psk.psk, 0x33, 32);
    psk.psk_len = 32;
    psk.suite = 0x1301;
    /* two identities + two binders */
    memcpy(two, "\x00\x0e\x00\x01t\x00\x00\x00\x00\x00\x01u\x00\x00\x00\x00\x00\x42\x20", 19);
    memset(two + 19, 0, 32);
    two[51] = 0x20;
    memset(two + 52, 0, 32);
    /* one identity, a 48-byte and a 31-byte binder */
    memcpy(b48, ONE, 11);
    brisk__store_be16(b48 + 9, 49);
    b48[11] = 48;
    memset(b48 + 12, 0, 48);
    memcpy(b31, ONE, 11);
    brisk__store_be16(b31 + 9, 32);
    b31[11] = 31;
    memset(b31 + 12, 0, 31);

    for (i = 0; i < 10; i++) {
        int modes = 1, setpsk = 1, want = BRISK_E_ARG;
        types[0] = 41;
        vals[0] = ONE;
        lens[0] = sizeof ONE;
        n = 1;
        switch (i) {
        case 0:
            want = BRISK_OK;
            break; /* the sanity row */
        case 1:
            setpsk = 0;
            break; /* a PSK the engine was not given */
        case 2:
            vals[0] = two;
            lens[0] = 84;
            break;
        case 3:
            vals[0] = b48;
            lens[0] = 60;
            break;
        case 4:
            vals[0] = b31;
            lens[0] = 43;
            break;
        case 5:
            modes = 0;
            break; /* 4.3.9: no psk_key_exchange_modes */
        case 6:    /* not the last extension */
            types[1] = 21;
            vals[1] = (const uint8_t *)"\x00\x00";
            lens[1] = 2;
            n = 2;
            break;
        case 7:
        case 8: /* modes [psk_ke] and [psk_ke, psk_dhe_ke] */
            modes = 0;
            types[0] = 45;
            vals[0] = (const uint8_t *)(i == 7 ? "\x01\x00" : "\x02\x00\x01");
            lens[0] = i == 7 ? 2 : 3;
            types[1] = 41;
            vals[1] = ONE;
            lens[1] = sizeof ONE;
            n = 2;
            break;
        default: /* a SHA-384 PSK, but no SHA-384 suite on offer */
            psk.suite = 0x1302;
            psk.psk_len = 48;
            vals[0] = b48;
            lens[0] = 60;
            break;
        }
        len = ch_plus(ch, sizeof ch, modes, types, vals, lens, n);
        if (i == 9) { /* only TLS_AES_128_GCM_SHA256 on offer: patch the suite list */
            size_t s = 4 + 35 + ch[4 + 34];
            CHECK(brisk__load_be16(ch + s) == 6);
            brisk__store_be16(ch + s + 6, 0x1303); /* 1303 1301 1303 */
        }
        memset(&R, 0, sizeof R);
        CHECKI(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK, i);
        if (setpsk) {
            CHECKI(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_OK, i);
        }
        CHECKI(brisk__tls13_hs_client_hello(&R.hs, ch, len, 0x001d, priv) == want, i);
        CHECKI(R.hs.state == (want == BRISK_OK ? BRISK__HS_WAIT_SH : BRISK__HS_START), i);
        if (want == BRISK_OK) {
            /* the binder was written into the engine's copy, never into ch */
            CHECKI(all_zero(ch + len - 32, 32) && !all_zero(R.hs.out + len - 32, 32), i);
        }
    }
    /* hs_set_psk: START only, known suite, HashLen matching it */
    psk.suite = 0x1301;
    psk.psk_len = 48;
    CHECK(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_E_ARG);
    memset(&R, 0, sizeof R);
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK);
    CHECK(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_E_ARG);
    psk.suite = 0x1304;
    psk.psk_len = 32;
    CHECK(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_E_ARG);
    CHECK(brisk__tls13_hs_set_psk(NULL, &psk) == BRISK_E_ARG);
    /* RFC 8448 sect 4's own ClientHello carries early_data: refused even with its
     * PSK */
    {
        const struct tls13_psk_kat *k = &TLS13_PSK_KAT[0];
        const uint8_t *ch4 = dec(k->ch4, &len), *pk = dec(k->psk, &n);
        const struct tls13_flow_kat *fk = &TLS13_FLOW_KAT[flow_find("RFC 8448 sect 4 minus")];
        memcpy(psk.psk, pk, 32);
        psk.suite = 0x1301;
        CHECK(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_OK);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, ch4, len, 0x001d, dec(fk->priv1, &n)) ==
                  BRISK_E_ARG &&
              R.hs.state == BRISK__HS_START);
    }
    /* PSK + HRR to SHA-384: a CH2 that still carries the SHA-256 PSK is refused
     * (4.2.2) */
    {
        flow f;
        const uint8_t *ch2p;
        size_t ch2p_len;
        flow_load(&f, &TLS13_FLOW_KAT[flow_find("PSK + HRR to SHA-384")]);
        ch2p = dec(TLS13_FLOW_KAT[flow_find("PSK + HRR (same hash)")].ch2, &ch2p_len);
        memset(&R, 0, sizeof R);
        memcpy(psk.psk, f.psk, 32);
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK &&
              brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_OK &&
              brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, 0x001d, f.priv1) == BRISK_OK &&
              brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK &&
              R.hs.state == BRISK__HS_WAIT_CH2 && R.hs.suite == 0x1302);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, ch2p, ch2p_len, 0x0017, f.priv2) == BRISK_E_ARG &&
              R.hs.state == BRISK__HS_WAIT_CH2);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch2, f.ch2_len, 0x0017, f.priv2) == BRISK_OK &&
              all_zero(R.hs.psk, sizeof R.hs.psk));
    }
}

/* An EncryptedExtensions of {server_name empty, ALPN with raw extension_data
 * d}. */
static size_t ee_alpn(uint8_t *out, const uint8_t *d, size_t dl)
{
    out[0] = 8;
    brisk__store_be24(out + 1, (uint32_t)(2 + 4 + 4 + dl));
    brisk__store_be16(out + 4, (uint32_t)(4 + 4 + dl));
    memcpy(out + 6, "\x00\x00\x00\x00\x00\x10", 6);
    brisk__store_be16(out + 12, (uint32_t)dl);
    memcpy(out + 14, d, dl);
    return 14 + dl;
}

static void hs_alpn(void)
{
    static const struct {
        const char *d;
        size_t dl;
        int alert;
    } EE[] = {
        {"\x00\x05\x04mqtt", 7, 0},
        {"\x00\x03\x02h2", 5, BRISK__ALERT_ILLEGAL_PARAMETER},       /* not offered */
        {"\x00\x0a\x04mqtt\x04mqtt", 12, BRISK__ALERT_DECODE_ERROR}, /* two names */
        {"\x00\x01\x00", 3, BRISK__ALERT_DECODE_ERROR},              /* empty name */
        {"\x00\x06\x04mqtt", 7, BRISK__ALERT_DECODE_ERROR},          /* list length */
        {"\x00\x05\x05mqtt", 7, BRISK__ALERT_DECODE_ERROR},          /* name length */
        {"\x00\x05\x04mqtt\x00", 8, BRISK__ALERT_DECODE_ERROR},      /* trailing */
        {"\x00\x00", 2, BRISK__ALERT_DECODE_ERROR},                  /* empty list */
        {"\x00\x0f\x0ex-amzn-mqtt-ca", 17, 0},
    };
    static uint8_t ee[64], out[1024];
    brisk__tls13_ch_params p;
    flow f;
    size_t i, n, len, idx = flow_find("RFC 8448 sect 4 minus 0-RTT");
    const uint8_t *name;
    int rc;
    uint8_t pub[32] = {0}, list[300];

    for (i = 0; i < sizeof EE / sizeof EE[0]; i++) {
        flow_load(&f, &TLS13_FLOW_KAT[idx]);
        n = ee_alpn(ee, (const uint8_t *)EE[i].d, EE[i].dl);
        rc = run_flow(&R, &f, 1, ee, n, FEED_MSG, 0, 0);
        if (EE[i].alert == 0) {
            /* "mqtt" is the row's own EE (the flow completes); any other accepted name changes
             * the transcript, so the server Finished no longer verifies */
            CHECKI(i == 0 ? rc == BRISK_OK
                          : rc == BRISK_E_AUTH && R.hs.alert == BRISK__ALERT_DECRYPT_ERROR,
                   i);
            continue;
        }
        CHECKI(rc == BRISK_E_PROTO && R.hs.alert == EE[i].alert, i);
    }
    /* ALPN answered when the CH offered none: unsupported_extension (4.3) */
    flow_load(&f, &TLS13_FLOW_KAT[0]);
    n = ee_alpn(ee, (const uint8_t *)"\x00\x05\x04mqtt", 7);
    rc = run_flow(&R, &f, 1, ee, n, FEED_MSG, 0, 0);
    CHECK(rc == BRISK_E_PROTO && R.hs.alert == BRISK__ALERT_UNSUPPORTED_EXTENSION);
    /* hs_alpn before CONNECTED */
    CHECK(brisk__tls13_hs_alpn(&R.hs, &name, &len) == BRISK_E_ARG);

    /* ch_write: empty name, a truncated entry, a list over BRISK__TLS13_ALPN_MAX
     */
    arena_used = 0;
    memset(&p, 0, sizeof p);
    p.random = pub;
    p.share_group = 0x001d;
    p.share_pub = pub;
    p.share_pub_len = 32;
    p.alpn = (const uint8_t *)"\x04mqtt\x00";
    p.alpn_len = 6;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
    p.alpn_len = 4;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
    p.alpn_len = 5;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
    memset(list, 'a', sizeof list);
    list[0] = 255; /* one 255-byte name: 256 bytes, the cap */
    p.alpn = list;
    p.alpn_len = 256;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
    list[0] = 200;
    list[201] = 55; /* 201 + 56 = 257 */
    p.alpn_len = 257;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
    p.alpn = NULL;
    p.alpn_len = 1;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);

    /* QUIC (RFC 9001 8.1): a name outside the offer, and no answer at all, are
     * both no_application_protocol */
    {
        static const uint8_t TP[] = {0x0f, 0x00};
        static uint8_t ch[1024], e2[256];
        tp_capture c;
        size_t ch_len, e2_len, e;
        flow_load(&f, &TLS13_FLOW_KAT[0]);
        e = 4 + 35;
        e += 2 + brisk__load_be16(f.ch1 + e) + 2;
        ch_len = add_ext(ch, f.ch1, f.ch1_len, e, 57, TP, 2);
        ch_len = add_ext(ch, ch, ch_len, e, 16, (const uint8_t *)"\x00\x05\x04mqtt", 7);
        for (i = 0; i < 2; i++) {
            e2_len = add_ext(e2, f.m[1], f.n_m[1], 4, 57, TP, 2);
            if (i == 1) {
                e2_len = add_ext(e2, e2, e2_len, 4, 16, (const uint8_t *)"\x00\x03\x02h2", 5);
            }
            memset(&c, 0, sizeof c);
            rc = tp_run(&f, 1, ch, ch_len, e2, e2_len, &c);
            CHECKI(rc == BRISK_E_PROTO && R.hs.alert == BRISK__ALERT_NO_APPLICATION_PROTOCOL, i);
        }
    }
}

static void hs_sni(void)
{
    static const char BAD[] = {0x00, 0x1f, 0x7f, (char)0x80, ' '};
    brisk__tls13_ch_params p;
    uint8_t pub[32] = {0}, out[1024], plain[1024];
    char host[300];
    size_t len, plain_len, i;

    memset(&p, 0, sizeof p);
    p.random = pub;
    p.share_group = 0x001d;
    p.share_pub = pub;
    p.share_pub_len = 32;
    CHECK(brisk__tls13_ch_write(&p, plain, sizeof plain, &plain_len) == BRISK_OK);
    /* RFC 6066 3: an IP literal (every literal x509_ip.inc accepts) is never sent
     */
    for (i = 0; i < sizeof X509_IP_KAT / sizeof X509_IP_KAT[0]; i++) {
        if (*X509_IP_KAT[i].want == 0) {
            continue;
        }
        p.sni = X509_IP_KAT[i].text;
        p.sni_len = strlen(p.sni);
        CHECKI(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK && len == plain_len &&
                   memcmp(out, plain, len) == 0,
               i);
    }
    /* bytes outside 0x21..0x7e */
    for (i = 0; i < sizeof BAD; i++) {
        memcpy(host, "a.example", 9);
        host[1] = BAD[i];
        p.sni = host;
        p.sni_len = 9;
        CHECKI(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG, i);
    }
    /* 255 bytes OK, 256 refused (the trailing dot does not count) */
    memset(host, 'a', sizeof host);
    p.sni = host;
    p.sni_len = 255;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_OK);
    p.sni_len = 256;
    CHECK(brisk__tls13_ch_write(&p, out, sizeof out, &len) == BRISK_E_ARG);
}

#if BRISK_ENABLE_MTLS
/* ---- mTLS ---- */
typedef struct {
    int calls, rc;
    size_t give_len;
    uint16_t scheme;
    size_t cap;
    uint8_t tbs[160];
    size_t tbs_len;
    const uint8_t *key, *rnd;
} sign_ctx;

static int sign_cb(void *ctx, uint16_t scheme, const uint8_t *tbs, size_t tbs_len, uint8_t *sig,
                   size_t sig_cap, size_t *sig_len)
{
    sign_ctx *s = (sign_ctx *)ctx;
    uint8_t h[32];
    s->calls++;
    s->scheme = scheme;
    s->cap = sig_cap;
    if (tbs_len <= sizeof s->tbs) {
        memcpy(s->tbs, tbs, tbs_len);
        s->tbs_len = tbs_len;
    }
    brisk_sha256(tbs, tbs_len, h);
    if (sig_cap < 64 || brisk__p256_ecdsa_sign(sig, s->key, h, 32, s->rnd, 32) != BRISK_OK) {
        return BRISK_E_ARG;
    }
    *sig_len = s->give_len;
    return s->rc;
}

/* TH(CH..client Certificate) of a flow, from its messages and the client flight
 * in R.hsk */
static void mtls_th(const flow *f, uint8_t th[32])
{
    brisk_hash_ctx c;
    size_t i;
    brisk__hash_init(&c, BRISK_HASH_SHA256);
    brisk__hash_update(&c, BRISK_HASH_SHA256, f->ch1, f->ch1_len);
    for (i = 0; i < f->count; i++) {
        brisk__hash_update(&c, BRISK_HASH_SHA256, f->m[i], f->n_m[i]);
    }
    brisk__hash_update(&c, BRISK_HASH_SHA256, R.hsk, 4 + brisk__load_be24(R.hsk + 1));
    brisk__hash_final(&c, BRISK_HASH_SHA256, th);
}

#endif

static void hs_mtls(void)
{
#if BRISK_ENABLE_MTLS
    static sign_ctx sc;
    brisk__tls13_hs_cfg cfg;
    flow f;
    uint8_t th[32], tbs[160], h[32], pub[65], raw[64];
    size_t idx = flow_find("RFC 8448 sect 6 shape"), n, cl, i, cvl;
    const uint8_t *cv;
    int rc;

    /* the soft-key flight: the CertificateVerify verifies under the device key */
    flow_load(&f, &TLS13_FLOW_KAT[idx]);
    rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
    check_connected(&R, &f, rc, 0);
    cl = 4 + brisk__load_be24(R.hsk + 1);
    cv = R.hsk + cl;
    CHECK(R.hsk[0] == 11 && R.hsk[4] == 0 && cv[0] == 15 && brisk__load_be16(cv + 4) == 0x0403);
    cvl = brisk__load_be16(cv + 6);
    mtls_th(&f, th);
    n = brisk__tls13_cv_content(0, th, 32, tbs);
    brisk_sha256(tbs, n, h);
    CHECK(brisk__p256_keygen(pub, f.ckey) == BRISK_OK &&
          brisk__x509_ecdsa_raw(cv + 8, cvl, 32, raw) == BRISK_OK &&
          brisk__p256_ecdsa_verify(pub, h, 32, raw) == BRISK_OK);

    /* the same flight through a sign callback: byte-identical (same k'), tbs as
     * specified */
    for (i = 0; i < 4; i++) {
        memset(&sc, 0, sizeof sc);
        sc.key = f.ckey;
        sc.rnd = f.srand;
        sc.give_len = i == 2 ? 63 : i == 3 ? 65 : 64;
        sc.rc = i == 1 ? BRISK_E_AUTH : BRISK_OK;
        memset(&R, 0, sizeof R);
        memset(&cfg, 0, sizeof cfg);
        cfg.auth = stub_auth;
        cfg.auth_ctx = &R.st;
        R.st.want = f.tbs;
        R.st.want_len = f.tbs_len;
        cfg.client_chain = f.cchain;
        cfg.client_chain_len = f.cchain_len;
        cfg.sign = sign_cb;
        cfg.sign_ctx = &sc;
        CHECKI(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK, i);
        CHECKI(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, f.priv1) ==
                   BRISK_OK,
               i);
        drain(&R, 0);
        rc = brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]);
        for (n = 1; rc == BRISK_OK && n < f.count; n++) {
            rc = brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[n], f.n_m[n]);
        }
        CHECKI(sc.calls == 1 && sc.scheme == 0x0403 && sc.cap == 64, i);
        if (i != 0) {
            /* a refusal or a wrong length is a local fault: internal_error, nothing
             * emitted */
            CHECKI(rc == BRISK_E_ARG && R.hs.alert == BRISK__ALERT_INTERNAL_ERROR &&
                       secrets_wiped(&R.hs) && all_zero(R.hs.out, BRISK__TLS13_OUT_MAX),
                   i);
            continue;
        }
        drain(&R, 0);
        CHECK(rc == BRISK_OK && R.hsk_len == f.cf_len && memcmp(R.hsk, f.cf, f.cf_len) == 0);
        mtls_th(&f, th);
        n = brisk__tls13_cv_content(0, th, 32, tbs);
        CHECK(sc.tbs_len == n && memcmp(sc.tbs, tbs, n) == 0);
    }

    /* a CR without 0x0403: an empty Certificate, no CertificateVerify, then
     * Finished */
    flow_load(&f, &TLS13_FLOW_KAT[flow_find("RFC 9846 4.5.1: CR without")]);
    rc = run_flow(&R, &f, -1, NULL, 0, FEED_MSG, 0, 0);
    CHECK(rc == BRISK_OK && R.hsk_len == 8 + 4 + 32 &&
          memcmp(R.hsk, "\x0b\x00\x00\x04\x00\x00\x00\x00\x14", 9) == 0);

    /* hs_init: the device chain rows, then the key / sign / sign_rand
     * combinations */
    for (i = 0; i < sizeof TLS13_MTLS_KAT / sizeof TLS13_MTLS_KAT[0]; i++) {
        const struct tls13_mtls_kat *k = &TLS13_MTLS_KAT[i];
        arena_used = 1;
        memset(&cfg, 0, sizeof cfg);
        cfg.auth = stub_auth;
        cfg.client_chain = dec(k->chain, &cfg.client_chain_len);
        cfg.client_key = dec(k->key, &n);
        cfg.sign_rand = f.srand;
        CHECKI(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) ==
                   (k->ok ? BRISK_OK : BRISK_E_ARG),
               i);
    }
    flow_load(&f, &TLS13_FLOW_KAT[idx]);
    for (i = 0; i < 7; i++) {
        static uint8_t bigchain[BRISK_TLS_MAX_CLIENT_CHAIN + 1024];
        memset(&cfg, 0, sizeof cfg);
        cfg.auth = stub_auth;
        cfg.client_chain = f.cchain;
        cfg.client_chain_len = f.cchain_len;
        cfg.client_key = f.ckey;
        cfg.sign_rand = f.srand;
        switch (i) {
        case 0:
            break; /* OK */
        case 1:
            cfg.client_key = NULL;
            break; /* neither key nor sign */
        case 2:
            cfg.sign = sign_cb;
            break; /* both */
        case 3:
            cfg.sign_rand = NULL;
            break; /* soft key without k' */
        case 4:    /* the leaf repeated past BRISK_TLS_MAX_CLIENT_CHAIN */
        case 5:    /* ... and up to it: accepted, however far past the old 2 KB queue */
            cl = 4 + brisk__load_be16(f.cchain + 2);
            for (n = 0; n + cl <= (i == 4 ? sizeof bigchain : BRISK_TLS_MAX_CLIENT_CHAIN);
                 n += cl) {
                memcpy(bigchain + n, f.cchain, cl);
            }
            cfg.client_chain = bigchain;
            cfg.client_chain_len = n;
            break;
        default:
            cfg.client_chain = NULL;
            break; /* a key without a chain */
        }
        CHECKI(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) ==
                   (i == 0 || i == 5 ? BRISK_OK : BRISK_E_ARG),
               i);
    }
#else
    /* no BRISK_ENABLE_MTLS: any client certificate is a configuration error */
    brisk__tls13_hs_cfg cfg;
    flow f;
    flow_load(&f, &TLS13_FLOW_KAT[flow_find("RFC 8448 sect 6 shape")]);
    memset(&cfg, 0, sizeof cfg);
    cfg.auth = stub_auth;
    cfg.client_chain = f.cchain;
    cfg.client_chain_len = f.cchain_len;
    cfg.client_key = f.ckey;
    cfg.sign_rand = f.srand;
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, g_scratch, g_scratch_len) == BRISK_E_ARG);
    (void)TLS13_MTLS_KAT;
#endif
}

static void hs_ecdsa_der(void)
{
#if BRISK_ENABLE_MTLS
    static uint8_t in[65];
    uint8_t out[72 + 1], raw[64];
    const uint8_t *r, *d;
    size_t i, n, dn, got, maxlen = 0;
    for (i = 0; i < sizeof TLS13_DER_KAT / sizeof TLS13_DER_KAT[0]; i++) {
        arena_used = 0;
        r = dec(TLS13_DER_KAT[i].raw, &n);
        d = dec(TLS13_DER_KAT[i].der, &dn);
        memcpy(in + 1, r, 64);
        got = brisk__x509_ecdsa_der(in + 1, out + 1);
        CHECKI(got == dn && memcmp(out + 1, d, dn) == 0, i);
        /* and the decoder takes it back */
        CHECKI(brisk__x509_ecdsa_raw(out + 1, got, 32, raw) == BRISK_OK && memcmp(raw, r, 64) == 0,
               i);
        maxlen = got > maxlen ? got : maxlen;
    }
    CHECK(i > 100 && maxlen == 72);
#else
    (void)TLS13_DER_KAT;
#endif
}

void test_tls13_hs(void)
{
    g_scratch_len = brisk__tls13_hs_scratch_size() + 8;
    g_scratch = (uint8_t *)malloc(g_scratch_len);
    if (g_scratch == NULL) {
        exit(2);
    }
    hs_init_guard();
    hs_flows();
    hs_trace_specifics();
    hs_fixture_negative();
    hs_mutations();
    hs_epochs();
    hs_limits();
    hs_cv();
    hs_ch_write();
    hs_quic_tp();
    hs_local_faults();
    hs_wipe_exporter();
    hs_psk_binder();
    hs_ticket_from_nst();
    hs_ticket_blob();
    hs_psk_absorb();
    hs_alpn();
    hs_sni();
    hs_mtls();
    hs_ecdsa_der();
    free(g_scratch);
    g_scratch = NULL;
}

/* The constant-time run for tests/test_ct.c: the RFC 8448 sect 3 handshake with the ECDHE
 * private key marked secret, so `dev.py ct` reports any branch or index on it or on anything
 * derived from it (the shared secret, every key-schedule stage, the Finished MACs). Nothing
 * secret is compared here: the outputs are declassified only after the engine is done. */
void tls13_hs_ct_run(void)
{
    flow f;
    brisk__tls13_hs_cfg cfg;
    uint8_t priv[32], *scratch;
    size_t len = brisk__tls13_hs_scratch_size(), i;

    scratch = (uint8_t *)malloc(len);
    if (scratch == NULL) {
        exit(2);
    }
    flow_load(&f, &TLS13_FLOW_KAT[0]);
    memcpy(priv, f.priv1, sizeof priv);
    BRISK__CT_SECRET(priv, sizeof priv);
    memset(&cfg, 0, sizeof cfg);
    memset(&R, 0, sizeof R);
    R.st.want = f.tbs;
    R.st.want_len = f.tbs_len;
    cfg.auth = stub_auth;
    cfg.auth_ctx = &R.st;
    CHECK(brisk__tls13_hs_init(&R.hs, &cfg, scratch, len) == BRISK_OK);
    CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, 0x001d, priv) == BRISK_OK);
    CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK);
    for (i = 1; i < f.count; i++) {
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[i], f.n_m[i]) == BRISK_OK);
    }
    CHECK(R.hs.state == BRISK__HS_CONNECTED);
    drain(&R, 0);
    BRISK__CT_PUBLIC(R.hsk, sizeof R.hsk); /* the client Finished goes on the wire */
    CHECK(R.hsk_len == f.cf_len && memcmp(R.hsk, f.cf, f.cf_len) == 0);
    brisk__tls13_hs_wipe(&R.hs);

    /* Resumed (RFC 9846 4.3.11): the PSK is secret - the binder, the early secret and every
     * stage after it must not branch on it. Then mTLS: the device key d and the hedging input
     * k' are secret through the ECDSA sign (the CertificateVerify goes on the wire). */
    for (i = 0; i < 2; i++) {
        brisk__tls13_psk psk;
        uint8_t key[32], rnd[32];
        size_t m;
        flow_load(&f, &TLS13_FLOW_KAT[flow_find(i == 0 ? "RFC 8448 sect 4 minus 0-RTT"
                                                       : "RFC 8448 sect 6 shape")]);
        memset(&cfg, 0, sizeof cfg);
        memset(&R, 0, sizeof R);
        R.st.want = f.tbs;
        R.st.want_len = f.tbs_len;
        cfg.auth = stub_auth;
        cfg.auth_ctx = &R.st;
#if BRISK_ENABLE_MTLS
        if (i == 1) {
            memcpy(key, f.ckey, 32);
            memcpy(rnd, f.srand, 32);
            cfg.client_chain = f.cchain;
            cfg.client_chain_len = f.cchain_len;
            cfg.client_key = key;
            cfg.sign_rand = rnd;
        }
#else
        if (i == 1) {
            break;
        }
#endif
        CHECK(brisk__tls13_hs_init(&R.hs, &cfg, scratch, len) == BRISK_OK);
        /* hs_init's keygen(d) == leaf check ran on a public copy; now d is secret */
        BRISK__CT_SECRET(key, sizeof key);
        BRISK__CT_SECRET(rnd, sizeof rnd);
        if (i == 0) {
            memset(&psk, 0, sizeof psk);
            memcpy(psk.psk, f.psk, f.psk_len);
            psk.psk_len = (uint8_t)f.psk_len;
            psk.suite = (uint16_t)f.k->psk_suite;
            BRISK__CT_SECRET(psk.psk, sizeof psk.psk);
            CHECK(brisk__tls13_hs_set_psk(&R.hs, &psk) == BRISK_OK);
        }
        memcpy(priv, f.priv1, sizeof priv);
        BRISK__CT_SECRET(priv, sizeof priv);
        CHECK(brisk__tls13_hs_client_hello(&R.hs, f.ch1, f.ch1_len, (uint16_t)f.k->g1, priv) ==
              BRISK_OK);
        drain(&R, 0);
        BRISK__CT_PUBLIC(R.init, sizeof R.init); /* the binder goes on the wire */
        CHECK(R.init_len == f.ch1_len && memcmp(R.init, f.ch1, f.ch1_len) == 0);
        CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_INITIAL, f.m[0], f.n_m[0]) == BRISK_OK);
        for (m = 1; m < f.count; m++) {
            CHECK(brisk__tls13_hs_feed(&R.hs, BRISK__EPOCH_HANDSHAKE, f.m[m], f.n_m[m]) ==
                  BRISK_OK);
        }
        CHECK(R.hs.state == BRISK__HS_CONNECTED);
        drain(&R, 0);
        BRISK__CT_PUBLIC(R.hsk, sizeof R.hsk);
        CHECK(R.hsk_len == f.cf_len && memcmp(R.hsk, f.cf, f.cf_len) == 0);
        brisk__tls13_hs_wipe(&R.hs);
    }
    free(scratch);
}
