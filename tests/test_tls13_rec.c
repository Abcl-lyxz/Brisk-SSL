/* test_tls13_rec.c - the TLS 1.3 record layer and connection driver (src/tls/record.c, RFC 9846
 * sect 5) plus the engine's post-handshake messages (4.7).
 *
 * Every record, key, nonce and message below comes from tools/kat.py: all RFC 8448 sect 3-7
 * records re-sealed there from their payloads, the RFC 9001 A.5 nonce, and generated rows for
 * what no trace covers (ChaCha20 / AES-256 records, "traffic upd" chains, padding, the size
 * limits, invalid inner plaintexts, NewSessionTicket and KeyUpdate bodies). Records the SERVER
 * sends in the driver tests are sealed here with brisk__tls_rec_seal, which the KAT rows pin
 * byte for byte first; everything the CLIENT sends is compared against a kat.py row. */
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
    const char *psk;
    unsigned psk_suite;
    int resumed;
    const char *alpn, *cchain, *ckey, *srand;
};
struct tls13_rfc_kat {
    const char *hrr, *down1, *down0, *cv_th, *cv_content, *cv_client;
};
struct tls13_chw_kat {
    const char *random, *sid, *suites, *groups, *sigs, *sni;
    unsigned share_group;
    const char *share_pub, *cookie, *ch;
    const char *alpn;
    int psk_modes;
    const char *identity;
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
struct tls13_rec_kat {
    const char *name;
    int sec, side, idx; /* RFC 8448 section, 0 client / 1 server, order per side; sec 0 = ours */
    unsigned suite;     /* 0 = unprotected */
    const char *secret, *key, *iv;
    unsigned long long seq;
    unsigned type, ver, pad;
    const char *payload, *record;
    int alert; /* 0: valid; else what rec_open must say */
};
struct tls13_nonce_kat {
    const char *iv;
    unsigned long long seq;
    const char *nonce;
};
struct tls13_hsmsg_kat {
    const char *name, *msg;
    int alert;
    unsigned lifetime, age_add, max_early;
    const char *nonce, *ticket;
};
#include "kat/tls13_trace.inc"
#include "kat/tls13_mut.inc"
#include "kat/tls13_record.inc"
#include "kat/tls13_psk.inc"

#define NREC   (sizeof TLS13_REC_KAT / sizeof TLS13_REC_KAT[0])
#define NHS    (sizeof TLS13_HSMSG_KAT / sizeof TLS13_HSMSG_KAT[0])
#define CAP    (BRISK__TLS_REC_IN_MAX + 64)
#define SIDE_C 0
#define SIDE_S 1

/* ---------------------------------------------------------------- hex arena ---------------- */
static uint8_t arena[1 << 20];
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

static const struct tls13_rec_kat *rrow(const char *name)
{
    size_t i;
    for (i = 0; i < NREC; i++) {
        if (strcmp(TLS13_REC_KAT[i].name, name) == 0) {
            return &TLS13_REC_KAT[i];
        }
    }
    exit(2); /* a row the generator no longer emits: the harness is out of date */
}

static const struct tls13_hsmsg_kat *hrow(const char *name)
{
    size_t i;
    for (i = 0; i < NHS; i++) {
        if (strcmp(TLS13_HSMSG_KAT[i].name, name) == 0) {
            return &TLS13_HSMSG_KAT[i];
        }
    }
    exit(2);
}

static const struct tls13_flow_kat *flow_of(int sec)
{
    static const int IDX[8] = {-1, -1, -1, 0, -1, 1, 2, 3}; /* kat.py tls13_traces() order */
    const struct tls13_flow_kat *f = &TLS13_FLOW_KAT[IDX[sec]];
    if (strncmp(f->note, "RFC 8448 sect ", 14) != 0 || f->note[14] - '0' != sec) {
        exit(2);
    }
    return f;
}

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

/* A direction keyed from a row's (or a flow's) secret. */
static int dir_from(brisk__tls_dir *d, unsigned epoch, unsigned suite, const char *secret_hex)
{
    size_t n;
    const uint8_t *s = dec(secret_hex, &n);
    return brisk__tls_dir_init(d, epoch, (uint16_t)suite, s, n);
}

/* ---------------------------------------------------------------- one record, both ways ---- */
static uint8_t big[2 * CAP], big2[2 * CAP];

static void rec_kat(void)
{
    static const size_t OFF[4] = {0, 1, 3, 5};
    brisk__tls_dir d;
    brisk__gcm_key g;
    size_t i, o, n, pl_len, rec_len, k_len, iv_len, out_len, len;
    const uint8_t *pl, *rec, *key, *iv;
    uint8_t type, alert, *p;
    int rc;

    for (i = 0; i < NREC; i++) {
        const struct tls13_rec_kat *r = &TLS13_REC_KAT[i];
        arena_used = 0;
        pl = dec(r->payload, &pl_len);
        rec = dec(r->record, &rec_len);
        key = dec(r->key, &k_len);
        iv = dec(r->iv, &iv_len);
        memset(&d, 0, sizeof d);
        if (r->suite != 0) {
            /* RFC 9846 7.3: key and iv exactly as the trace / kat.py expanded them */
            CHECKI(dir_from(&d, BRISK__EPOCH_APP, r->suite, r->secret) == BRISK_OK, i);
            CHECKI(iv_len == 12 && memcmp(d.iv, iv, 12) == 0, i);
            if (r->suite == 0x1303) {
                CHECKI(k_len == 32 && memcmp(d.k.chacha, key, 32) == 0, i);
            } else {
                memset(&g, 0, sizeof g);
                CHECKI(brisk__gcm_init(&g, key, k_len) == BRISK_OK, i);
                CHECKI(memcmp(&g, &d.k.gcm, sizeof g) == 0, i);
            }
        }
        for (o = 0; o < 4; o++) {
            /* seal, at every alignment, once from a separate buffer and once in place */
            if (r->alert == 0) {
                d.seq = r->seq;
                memset(big, 0xEE, rec_len + 16);
                rc = brisk__tls_rec_seal(&d, (uint8_t)r->type, (uint16_t)r->ver, pl, pl_len, r->pad,
                                         big + OFF[o], rec_len + OFF[o], &out_len);
                CHECKI(rc == BRISK_OK && out_len == rec_len &&
                           memcmp(big + OFF[o], rec, rec_len) == 0,
                       i);
                CHECKI(r->suite == 0 || d.seq == r->seq + 1, i);
                memcpy(big + OFF[o] + 5, pl, pl_len);
                d.seq = r->seq;
                rc = brisk__tls_rec_seal(&d, (uint8_t)r->type, (uint16_t)r->ver, big + OFF[o] + 5,
                                         pl_len, r->pad, big + OFF[o], rec_len, &out_len);
                CHECKI(rc == BRISK_OK && memcmp(big + OFF[o], rec, rec_len) == 0, i);
            }
            /* open in place */
            p = big2 + OFF[o];
            memcpy(p, rec, rec_len);
            d.seq = r->seq;
            rc = brisk__tls_rec_open(&d, p, rec_len, &type, &len, &alert);
            if (r->alert == 0) {
                CHECKI(rc == BRISK_OK && alert == 0 && type == r->type && len == pl_len, i);
                CHECKI(memcmp(p + 5, pl, pl_len) == 0, i);
                CHECKI(r->suite == 0 || d.seq == r->seq + 1, i);
            } else {
                CHECKI(rc ==
                           (r->alert == BRISK__ALERT_BAD_RECORD_MAC ? BRISK_E_AUTH : BRISK_E_PROTO),
                       i);
                CHECKI(alert == r->alert && len == 0, i);
                CHECKI(d.seq == r->seq || r->alert != BRISK__ALERT_BAD_RECORD_MAC, i);
                if (r->alert == BRISK__ALERT_BAD_RECORD_MAC ||
                    (r->suite != 0 && rec_len - 5 <= BRISK__TLS_MAX_CIPHER)) {
                    /* nothing of a rejected protected record survives: a failed tag wipes the
                     * whole body, a rejected inner plaintext its plaintext */
                    n = r->alert == BRISK__ALERT_BAD_RECORD_MAC ? rec_len - 5 : rec_len - 5 - 16;
                    CHECKI(all_zero(p + 5, n), i);
                }
            }
        }
        brisk__tls_dir_wipe(&d);
    }
}

/* ---------------------------------------------------------------- nonce, dir,
 * seal guards -- */
static void rec_nonce(void)
{
    size_t i, n;
    uint8_t out[12];
    for (i = 0; i < sizeof TLS13_NONCE_KAT / sizeof TLS13_NONCE_KAT[0]; i++) {
        arena_used = 0;
        brisk__tls_nonce(dec(TLS13_NONCE_KAT[i].iv, &n), TLS13_NONCE_KAT[i].seq, out);
        CHECKI(memcmp(out, dec(TLS13_NONCE_KAT[i].nonce, &n), 12) == 0, i);
    }
}

static void rec_dir(void)
{
    static const char *const CHAIN[4] = {"upd s_ap g", "upd c_ap g", "upd 384 g", "upd chacha g"};
    char name[32];
    brisk__tls_dir d, e;
    uint8_t buf[128], type, alert;
    size_t i, g, n, len, pre;
    const uint8_t *s;

    arena_used = 0;
    /* 7.2: every generation of every chain - key, iv, secret - and each one opens
     * its record */
    for (i = 0; i < 4; i++) {
        memset(&d, 0, sizeof d);
        pre = strlen(CHAIN[i]);
        for (g = 0; g < 4; g++) {
            const struct tls13_rec_kat *r;
            memcpy(name, CHAIN[i], pre);
            name[pre] = (char)('0' + g);
            name[pre + 1] = 0;
            r = rrow(name);
            if (g == 0) {
                CHECKI(dir_from(&d, BRISK__EPOCH_APP, r->suite, r->secret) == BRISK_OK, i);
            } else {
                d.seq = 77;
                CHECKI(brisk__tls_dir_update(&d) == BRISK_OK && d.n_updates == g && d.seq == 0, i);
            }
            memset(&e, 0, sizeof e);
            CHECKI(dir_from(&e, BRISK__EPOCH_APP, r->suite, r->secret) == BRISK_OK, i);
            e.n_updates = d.n_updates;
            CHECKI(memcmp(&d, &e, sizeof d) == 0, i * 10 + g); /* the old secret is gone */
            s = dec(r->record, &n);
            memcpy(buf, s, n);
            CHECKI(brisk__tls_rec_open(&d, buf, n, &type, &len, &alert) == BRISK_OK && type == 23 &&
                       len == 50,
                   i * 10 + g);
            brisk__tls_dir_wipe(&e);
        }
        brisk__tls_dir_wipe(&d);
        CHECKI(all_zero(&d, sizeof d), i);
    }
    /* init / update guards */
    s = dec(rrow("upd s_ap g0")->secret, &n);
    memset(&d, 0x55, sizeof d);
    CHECK(brisk__tls_dir_init(&d, BRISK__EPOCH_APP, 0x1304, s, n) == BRISK_E_ARG &&
          all_zero(&d, sizeof d));
    CHECK(brisk__tls_dir_init(&d, BRISK__EPOCH_APP, 0x1302, s, n) == BRISK_E_ARG); /* 32 != 48 */
    CHECK(brisk__tls_dir_update(&d) == BRISK_E_ARG);                               /* no suite */
    CHECK(brisk__tls_dir_init(&d, BRISK__EPOCH_HANDSHAKE, 0x1301, s, n) == BRISK_OK);
    CHECK(brisk__tls_dir_update(&d) == BRISK_E_ARG); /* 7.2 is APP only */
    /* the secret may alias d->secret */
    memset(&e, 0, sizeof e);
    CHECK(brisk__tls_dir_init(&e, BRISK__EPOCH_APP, 0x1301, s, n) == BRISK_OK);
    CHECK(brisk__tls_dir_init(&d, BRISK__EPOCH_APP, 0x1301, d.secret, n) == BRISK_OK &&
          memcmp(&d, &e, sizeof d) == 0);

    /* seal guards: nothing written and seq unchanged on every refusal */
    memset(buf, 0xAB, sizeof buf);
    d.seq = UINT64_MAX;
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, s, 8, 0, buf, sizeof buf, &len) == BRISK_E_ARG &&
          len == 0 && d.seq == UINT64_MAX && buf[0] == 0xAB);
    d.seq = 5;
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, s, 8, 0, buf, 5 + 8 + 1 + 16 - 1, &len) ==
              BRISK_E_ARG &&
          d.seq == 5 && buf[0] == 0xAB);
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, s, 8, BRISK__TLS_MAX_INNER - 8, buf, sizeof buf,
                              &len) == BRISK_E_ARG);
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, s, 8, (size_t)-1, buf, sizeof buf, &len) ==
          BRISK_E_ARG); /* a pad that would wrap size_t */
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, s, 8, 0, buf, 5 + 8 + 1 + 16, &len) == BRISK_OK &&
          len == 30 && d.seq == 6);
    /* an empty record from in == NULL (the documented contract; no NULL reaches memmove) */
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, NULL, 0, 3, buf, sizeof buf, &len) == BRISK_OK &&
          len == 5 + 1 + 3 + 16 && d.seq == 7);
    memset(&e, 0, sizeof e);
    CHECK(brisk__tls_rec_seal(&e, 22, 0x0303, NULL, 0, 0, buf, sizeof buf, &len) == BRISK_OK &&
          len == 5 && buf[0] == 22 && buf[3] == 0 && buf[4] == 0);
    d.seq = 5;
    CHECK(brisk__tls_rec_seal(&d, 23, 0x0303, s, 8, 0, buf, sizeof buf, &len) == BRISK_OK);
    /* the receive side never wraps either (5.3) */
    d.seq = UINT64_MAX;
    CHECK(brisk__tls_rec_open(&d, buf, len, &type, &n, &alert) == BRISK_E_PROTO &&
          alert == BRISK__ALERT_UNEXPECTED_MESSAGE);
    CHECK(brisk__tls_rec_open(&d, buf, len - 1, &type, &n, &alert) == BRISK_E_ARG);
    memset(&e, 0, sizeof e);
    CHECK(brisk__tls_rec_seal(&e, 22, 0x0303, s, 8, 1, buf, sizeof buf, &len) == BRISK_E_ARG);
    brisk__tls_dir_wipe(&d);
    brisk__tls_dir_wipe(&e);
    brisk__tls_dir_wipe(NULL);
}

/* ---------------------------------------------------------------- the
 * connection ----------- */
typedef struct {
    brisk__tls13_hs hs;
    brisk__tls13_conn c;
    int tk_calls, tk_ret;
    brisk__tls13_ticket tk;
    uint8_t tk_nonce[256], tk_ticket[512];
} conn_t;

static conn_t C;
static uint8_t *g_scratch, *g_in;
static size_t g_scratch_len;
static uint8_t app[1 << 16], wire[1 << 16], out2[1 << 16];
static size_t app_len;

static int yes(void *ctx, uint16_t version, const brisk__x509_cert *certs, size_t n_certs,
               uint16_t scheme, const uint8_t *tbs, size_t tbs_len, const uint8_t *sig,
               size_t sig_len, uint8_t *alert)
{
    (void)version;
    (void)ctx;
    (void)certs;
    (void)n_certs;
    (void)scheme;
    (void)tbs;
    (void)tbs_len;
    (void)sig;
    (void)sig_len;
    (void)alert;
    return BRISK_OK;
}

static int on_ticket(void *ctx, const brisk__tls13_ticket *t)
{
    conn_t *c = (conn_t *)ctx;
    c->tk_calls++;
    c->tk = *t;
    if (t->nonce_len <= sizeof c->tk_nonce && t->ticket_len <= sizeof c->tk_ticket) {
        memcpy(c->tk_nonce, t->nonce, t->nonce_len);
        memcpy(c->tk_ticket, t->ticket, t->ticket_len);
    }
    return c->tk_ret;
}

/* A fresh connection on RFC 8448 section `sec`'s ClientHello; the receive
 * buffer at g_in + off. */
static int conn_start(int sec, size_t off, int want_tickets)
{
    const struct tls13_flow_kat *k = flow_of(sec);
    brisk__tls13_hs_cfg cfg;
    const uint8_t *ch, *priv;
    size_t ch_len, n;

    memset(&C, 0, sizeof C);
    memset(&cfg, 0, sizeof cfg);
    cfg.auth = yes;
    if (want_tickets) {
        cfg.on_ticket = on_ticket;
        cfg.ticket_ctx = &C;
    }
    ch = dec(k->ch1, &ch_len);
    priv = dec(k->priv1, &n);
    app_len = 0;
    if (brisk__tls13_hs_init(&C.hs, &cfg, g_scratch, g_scratch_len) != BRISK_OK ||
        brisk__tls13_conn_init(&C.c, &C.hs, g_in + off, CAP) != BRISK_OK ||
        brisk__tls13_hs_client_hello(&C.hs, ch, ch_len, (uint16_t)k->g1, priv) != BRISK_OK) {
        return 99;
    }
    return 0;
}

/* Feed n bytes in chunks of at most `chunk`, draining application data as it
 * appears. */
static int feed_all(const uint8_t *p, size_t n, size_t chunk)
{
    size_t k, used, got;
    int rc;
    while (n != 0) {
        k = n < chunk ? n : chunk;
        rc = brisk__tls13_conn_feed(&C.c, p, k, &used);
        if (used > k || C.c.in_len > C.c.in_cap) {
            return 96;
        }
        p += used;
        n -= used;
        do {
            brisk__tls13_conn_read(&C.c, app + app_len, 7, &got);
            app_len += got;
        } while (got != 0);
        if (rc != BRISK_OK) {
            return rc;
        }
        if (used == 0) {
            return 97; /* no progress */
        }
    }
    return BRISK_OK;
}

static int feed_row(const char *name)
{
    size_t n;
    const uint8_t *r = dec(rrow(name)->record, &n);
    return feed_all(r, n, n);
}

static int pull_is(const char *name)
{
    size_t n, got = brisk__tls13_conn_pull(&C.c, wire, sizeof wire);
    const uint8_t *r = dec(rrow(name)->record, &n);
    return got == n && memcmp(wire, r, n) == 0;
}

/* RFC 8448 sect 3 up to CONNECTED with the client Finished pulled. */
static int connect3(size_t off)
{
    if (conn_start(3, off, 1) != 0 || !pull_is("8448s3 client 0") ||
        feed_row("8448s3 server 0") != BRISK_OK || feed_row("8448s3 server 1") != BRISK_OK ||
        !pull_is("8448s3 client 1") || C.hs.state != BRISK__HS_CONNECTED) {
        return 1;
    }
    return 0;
}

/* The server's side: records sealed under the trace's s_ap (then s_ap_N via
 * dir_update). */
static brisk__tls_dir SD;
static void srv_key(const char *row)
{
    CHECK(dir_from(&SD, BRISK__EPOCH_APP, 0x1301, rrow(row)->secret) == BRISK_OK);
}
static size_t srv(uint8_t *out, uint8_t type, const uint8_t *m, size_t n)
{
    size_t len = 0;
    CHECK(brisk__tls_rec_seal(&SD, type, 0x0303, m, n, 0, out, 2 * CAP, &len) == BRISK_OK);
    return len;
}

/* The one fatal alert the client sent, opened with `secret_hex`'s key at seq 0
 * (NULL: plain). */
static int alert_is(const char *secret_hex, uint8_t desc)
{
    brisk__tls_dir d;
    size_t n = brisk__tls13_conn_pull(&C.c, wire, sizeof wire), len;
    uint8_t type, alert;
    int ok;
    memset(&d, 0, sizeof d);
    if (secret_hex != NULL && dir_from(&d, 0, 0x1301, secret_hex) != BRISK_OK) {
        return 0;
    }
    ok = n >= 7 && brisk__tls_rec_open(&d, wire, n, &type, &len, &alert) == BRISK_OK &&
         type == BRISK__CT_ALERT && len == 2 && wire[5] == 2 && wire[6] == desc &&
         (secret_hex != NULL || n == 7);
    brisk__tls_dir_wipe(&d);
    /* 6.2: exactly one, then silence, keys gone */
    return ok && brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0 && C.c.alert_sent &&
           all_zero(&C.c.wr, sizeof C.c.wr) && all_zero(&C.c.rd, sizeof C.c.rd);
}

static void conn_trace3(void)
{
    static const size_t OFF[4] = {0, 1, 3, 5};
    const struct tls13_hsmsg_kat *h;
    size_t o, n, used, out_len, pl_len;
    const uint8_t *pl;

    for (o = 0; o < 4; o++) {
        arena_used = 0;
        CHECKI(connect3(OFF[o]) == 0, o);
        /* NewSessionTicket (4.7.1), before the client ever wrote */
        CHECKI(feed_row("8448s3 server 2") == BRISK_OK && C.tk_calls == 1, o);
        h = hrow("nst 8448s3");
        CHECKI(C.tk.lifetime == 30 && C.tk.lifetime == h->lifetime && C.tk.age_add == h->age_add &&
                   C.tk.max_early_data == 0x400,
               o);
        pl = dec(h->nonce, &n);
        CHECKI(C.tk.nonce_len == n && memcmp(C.tk_nonce, pl, n) == 0, o);
        pl = dec(h->ticket, &n);
        CHECKI(C.tk.ticket_len == n && memcmp(C.tk_ticket, pl, n) == 0, o);
        /* 4.7.1: the resumption PSK the callback saw is RFC 8448 sect 4's */
        pl = dec(TLS13_PSK_KAT[0].psk, &n);
        CHECKI(C.tk.psk_len == n && C.tk.suite == 0x1301 && memcmp(C.tk.psk, pl, n) == 0, o);
        /* application data, both ways */
        pl = dec(rrow("8448s3 client 2")->payload, &pl_len);
        CHECKI(brisk__tls13_conn_write(&C.c, pl, pl_len, &used, out2 + OFF[o], sizeof out2 - 8,
                                       &out_len) == BRISK_OK &&
                   used == pl_len,
               o);
        pl = dec(rrow("8448s3 client 2")->record, &n);
        CHECKI(out_len == n && memcmp(out2 + OFF[o], pl, n) == 0, o);
        CHECKI(feed_row("8448s3 server 3") == BRISK_OK, o);
        pl = dec(rrow("8448s3 server 3")->payload, &n);
        CHECKI(app_len == n && memcmp(app, pl, n) == 0, o);
        /* close_notify, both ways (6.1) */
        CHECKI(brisk__tls13_conn_close(&C.c) == BRISK_OK && pull_is("8448s3 client 3"), o);
        CHECKI(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0, o);
        CHECKI(brisk__tls13_conn_write(&C.c, pl, 1, &used, wire, sizeof wire, &out_len) ==
                   BRISK_E_ARG,
               o);
        CHECKI(feed_row("8448s3 server 4") == BRISK_OK && C.c.eof, o);
        CHECKI(brisk__tls13_conn_read(&C.c, app, sizeof app, &n) == BRISK_OK && n == 0, o);
        /* anything after close_notify is taken and ignored, garbage included */
        memset(wire, 0x99, 100);
        CHECKI(brisk__tls13_conn_feed(&C.c, wire, 100, &used) == BRISK_OK && used == 100, o);
        brisk__tls13_conn_wipe(&C.c);
        CHECKI(all_zero(&C.c, sizeof C.c) && all_zero(g_in + OFF[o], CAP), o);
        CHECKI(all_zero(&C.hs, sizeof C.hs), o);
    }
}

/* The whole sect 3 server byte stream in every 2-way split, byte by byte and in
 * random chunks: the same outcome every time. */
static void conn_split(void)
{
    static uint8_t s[2048];
    static const char *const ROWS[5] = {"8448s3 server 0", "8448s3 server 1", "8448s3 server 2",
                                        "8448s3 server 3", "8448s3 server 4"};
    size_t i, n, tot = 0, cut, pl_len, mark;
    const uint8_t *r, *pl;
    uint32_t x = 20260923u;
    int rc;

    arena_used = 0;
    for (i = 0; i < 5; i++) {
        r = dec(rrow(ROWS[i])->record, &n);
        memcpy(s + tot, r, n);
        tot += n;
    }
    pl = dec(rrow("8448s3 server 3")->payload, &pl_len);
    mark = arena_used;
    for (cut = 0; cut <= tot + 2; cut++) {
        CHECKI(conn_start(3, cut & 7, 1) == 0 && pull_is("8448s3 client 0"), cut);
        if (cut == tot + 1) {
            rc = feed_all(s, tot, 1);
        } else if (cut == tot + 2) {
            rc = 0;
            for (i = 0; i < tot && rc == 0; i += n) {
                x = x * 1103515245u + 12345u;
                n = 1 + ((x >> 16) & 255);
                n = n < tot - i ? n : tot - i;
                rc = feed_all(s + i, n, n);
            }
        } else {
            rc = cut == 0 ? BRISK_OK : feed_all(s, cut, tot);
            rc = rc != 0 || cut == tot ? rc : feed_all(s + cut, tot - cut, tot);
        }
        CHECKI(rc == BRISK_OK && C.c.eof && C.tk_calls == 1 && app_len == pl_len &&
                   memcmp(app, pl, pl_len) == 0,
               cut);
        /* the client Finished was owed all along, under c_hs, and nothing overtook
         * it */
        CHECKI(pull_is("8448s3 client 1"), cut);
        brisk__tls13_conn_wipe(&C.c);
        arena_used = mark;
    }
}

/* sect 5 (HRR: CH1 0x0301, CH2 0x0303) and sect 7 (compat-mode CCS both ways).
 */
static void conn_hrr_compat(void)
{
    const struct tls13_flow_kat *k;
    const uint8_t *ch2, *priv2, *a, *b;
    size_t n, na, nb, got;

    arena_used = 0;
    k = flow_of(5);
    CHECK(conn_start(5, 1, 0) == 0 && pull_is("8448s5 client 0"));
    CHECK(feed_row("8448s5 server 0") == BRISK_OK && C.hs.state == BRISK__HS_WAIT_CH2);
    ch2 = dec(k->ch2, &n);
    priv2 = dec(k->priv2, &na);
    CHECK(brisk__tls13_hs_client_hello(&C.hs, ch2, n, (uint16_t)k->g2, priv2) == BRISK_OK);
    CHECK(pull_is("8448s5 client 1"));
    CHECK(feed_row("8448s5 server 1") == BRISK_OK && feed_row("8448s5 server 2") == BRISK_OK);
    CHECK(pull_is("8448s5 client 2"));
    CHECK(brisk__tls13_conn_close(&C.c) == BRISK_OK && pull_is("8448s5 client 3"));
    CHECK(feed_row("8448s5 server 3") == BRISK_OK && C.c.eof);
    brisk__tls13_conn_wipe(&C.c);

    /* sect 7: the server's CCS after its SH is dropped unopened; ours goes out
     * exactly once, right before the first protected record */
    CHECK(conn_start(7, 3, 0) == 0 && pull_is("8448s7 client 0"));
    CHECK(feed_row("8448s7 server 0") == BRISK_OK && feed_row("8448s7 server 1") == BRISK_OK &&
          feed_row("8448s7 server 2") == BRISK_OK);
    a = dec(rrow("8448s7 client 1")->record, &na);
    b = dec(rrow("8448s7 client 2")->record, &nb);
    got = brisk__tls13_conn_pull(&C.c, wire, sizeof wire);
    CHECK(got == na + nb && memcmp(wire, a, na) == 0 && memcmp(wire + na, b, nb) == 0);
    CHECK(brisk__tls13_conn_close(&C.c) == BRISK_OK && pull_is("8448s7 client 3"));
    CHECK(feed_row("8448s7 server 3") == BRISK_OK && C.c.eof);
    /* the Finished split over two records by a small out: the CCS precedes only the first */
    CHECK(conn_start(7, 0, 0) == 0 && pull_is("8448s7 client 0"));
    CHECK(feed_row("8448s7 server 0") == BRISK_OK && feed_row("8448s7 server 1") == BRISK_OK &&
          feed_row("8448s7 server 2") == BRISK_OK);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, 6 + 5 + 10 + 1 + 16) == 38 && wire[0] == 20 &&
          wire[6] == 23);
    got = brisk__tls13_conn_pull(&C.c, wire, sizeof wire);
    CHECK(got == 5 + (nb - 5 - 17 - 10) + 1 + 16 && wire[0] == 23);
    brisk__tls13_conn_wipe(&C.c);
}

/* Framing, CCS, interleaving and plaintext-after-keys failures, with the alert
 * they send. */
static void conn_framing(void)
{
    static const uint8_t CCS_OK[6] = {20, 3, 3, 0, 1, 1}, CCS_2[6] = {20, 3, 3, 0, 1, 2},
                         CCS_LEN2[7] = {20, 3, 3, 0, 2, 1, 1}, APP_PLAIN[6] = {23, 3, 3, 0, 1, 0},
                         CLOSE_PLAIN[7] = {21, 3, 3, 0, 2, 1, 0},
                         HF_PLAIN[7] = {21, 3, 3, 0, 2, 2, 40},
                         UC_PLAIN[7] = {21, 3, 3, 0, 2, 1, 90}, CN[2] = {1, 0};
    static const char *const HDR_ONLY[4] = {"gen plain overflow", "gen plain type 24",
                                            "gen plain type 0", "gen plain type 255"};
    static const uint8_t HDR_ALERT[4] = {22, 10, 10, 10};
    static uint8_t rec[2048];
    const uint8_t *r, *m;
    size_t i, n, used, nm;

    arena_used = 0;
    /* before any key: header-time checks, before one body byte is buffered */
    for (i = 0; i < 4; i++) {
        CHECKI(conn_start(3, i, 0) == 0 && pull_is("8448s3 client 0"), i);
        r = dec(rrow(HDR_ONLY[i])->record, &n);
        CHECKI(brisk__tls13_conn_feed(&C.c, r, 5, &used) == BRISK_E_PROTO && used == 5 &&
                   C.c.alert == HDR_ALERT[i],
               i);
        CHECKI(alert_is(NULL, HDR_ALERT[i]), i);
        CHECKI(brisk__tls13_conn_feed(&C.c, r, 5, &used) == BRISK_E_PROTO && used == 0, i);
    }
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    r = dec(rrow("gen plain empty handshake")->record, &n);
    CHECK(feed_all(r, n, n) == BRISK_E_PROTO && alert_is(NULL, 10));
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    CHECK(feed_all(APP_PLAIN, 6, 6) == BRISK_E_PROTO && alert_is(NULL, 10));
    /* CCS: {1} after the CH is dropped (E.4), any other shape is
     * unexpected_message */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    CHECK(feed_all(CCS_OK, 6, 6) == BRISK_OK && feed_all(CCS_OK, 6, 1) == BRISK_OK);
    CHECK(feed_all(CCS_2, 6, 6) == BRISK_E_PROTO && alert_is(NULL, 10));
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    CHECK(feed_all(CCS_LEN2, 7, 7) == BRISK_E_PROTO && alert_is(NULL, 10));
    /* a peer's fatal alert before the SH: reported, never answered */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    CHECK(feed_all(HF_PLAIN, 7, 7) == BRISK_E_PEER_ALERT && C.c.peer_alert == 40);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0);

    /* 6.1: a closure alert before CONNECTED cancels the handshake - never a clean EOF */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    CHECK(feed_all(CLOSE_PLAIN, 7, 7) == BRISK_E_PEER_ALERT && C.c.peer_alert == 0 && !C.c.eof);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0 &&
          all_zero(&C.c.rd, sizeof C.c.rd) && all_zero(&C.c.wr, sizeof C.c.wr));
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    CHECK(feed_all(UC_PLAIN, 7, 7) == BRISK_E_PEER_ALERT && C.c.peer_alert == 90);
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0") &&
          feed_row("8448s3 server 0") == BRISK_OK);
    CHECK(dir_from(&SD, BRISK__EPOCH_HANDSHAKE, 0x1301, flow_of(3)->s_hs) == BRISK_OK);
    n = srv(rec, BRISK__CT_ALERT, CN, 2);
    CHECK(feed_all(rec, n, n) == BRISK_E_PEER_ALERT && C.c.peer_alert == 0 && !C.c.eof &&
          C.hs.state != BRISK__HS_CONNECTED);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0);

    /* failing ON the ServerHello (a suite never offered): no key yet, plaintext
     * alert */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    r = dec(rrow("8448s3 server 0")->record, &n);
    memcpy(rec, r, n);
    rec[5 + 4 + 2 + 32 + 1 + 1] = 0x04; /* TLS_AES_128_CCM_SHA256: not in our ClientHello */
    CHECK(feed_all(rec, n, n) != BRISK_OK && C.c.alert != 0);
    CHECK(alert_is(NULL, C.c.alert));
    /* SH + one byte in the same record (5.1): c_hs is on by then, so the alert is
     * protected */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0"));
    memcpy(rec, r, n);
    rec[n] = 8;
    brisk__store_be16(rec + 3, (uint32_t)(n - 5 + 1));
    CHECK(feed_all(rec, n + 1, n + 1) == BRISK_E_PROTO && C.c.alert == 10);
    CHECK(alert_is(flow_of(3)->c_hs, 10));
    /* after the SH plaintext is dead: a plaintext close_notify is NOT EOF
     * (truncation) */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0") &&
          feed_row("8448s3 server 0") == BRISK_OK);
    CHECK(feed_all(CLOSE_PLAIN, 7, 7) == BRISK_E_PROTO && !C.c.eof);
    CHECK(alert_is(flow_of(3)->c_hs, 10));
    /* application data under the handshake key */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0") &&
          feed_row("8448s3 server 0") == BRISK_OK);
    CHECK(dir_from(&SD, BRISK__EPOCH_HANDSHAKE, 0x1301, flow_of(3)->s_hs) == BRISK_OK);
    n = srv(rec, BRISK__CT_APP, APP_PLAIN, 1);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && alert_is(flow_of(3)->c_hs, 10));
    /* KeyUpdate before the server Finished (4.7.3) */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0") &&
          feed_row("8448s3 server 0") == BRISK_OK);
    CHECK(dir_from(&SD, BRISK__EPOCH_HANDSHAKE, 0x1301, flow_of(3)->s_hs) == BRISK_OK);
    m = dec(hrow("ku0")->msg, &nm);
    n = srv(rec, BRISK__CT_HANDSHAKE, m, nm);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 10);
    /* server Finished + NST in one record: nothing may follow a key change's last
     * message */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0") &&
          feed_row("8448s3 server 0") == BRISK_OK);
    CHECK(dir_from(&SD, BRISK__EPOCH_HANDSHAKE, 0x1301, flow_of(3)->s_hs) == BRISK_OK);
    r = dec(rrow("8448s3 server 1")->payload, &n);
    memcpy(out2, r, n);
    m = dec(hrow("nst 8448s3")->msg, &nm);
    memcpy(out2 + n, m, nm);
    n = srv(rec, BRISK__CT_HANDSHAKE, out2, n + nm);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 10);
    /* CCS once CONNECTED */
    CHECK(connect3(0) == 0);
    CHECK(feed_all(CCS_OK, 6, 6) == BRISK_E_PROTO && C.c.alert == 10);
    /* protected length over 2^14 + 256, from the header */
    CHECK(connect3(0) == 0);
    r = dec(rrow("gen overflow cipher")->record, &n);
    CHECK(brisk__tls13_conn_feed(&C.c, r, 5, &used) == BRISK_E_PROTO && C.c.alert == 22);
    CHECK(alert_is(flow_of(3)->c_ap, 22));
    brisk__tls13_conn_wipe(&C.c);
}

/* Deprotection failures in the connection: bad_record_mac, BRISK_E_AUTH, a
 * protected alert. */
static void conn_auth(void)
{
    /* the wrong-epoch-key row ("mut s_hs key") is rec_kat's: in a live connection that record
     * is simply valid. A flipped outer type turns the record into plaintext handshake after
     * the keys, which the connection refuses before any AEAD call (5, unexpected_message). */
    static const char *const MUT[8] = {"mut aad type", "mut aad version hi", "mut aad version lo",
                                       "mut ct first", "mut ct last",        "mut tag first",
                                       "mut tag last", "mut replay seq 2"};
    size_t i;
    uint8_t want;
    arena_used = 0;
    for (i = 0; i < 8; i++) {
        want = i == 0 ? BRISK__ALERT_UNEXPECTED_MESSAGE : BRISK__ALERT_BAD_RECORD_MAC;
        CHECKI(connect3(i & 3) == 0 && feed_row("8448s3 server 2") == BRISK_OK, i);
        if (i == 7) { /* replay: the seq-1 record twice */
            CHECKI(feed_row("8448s3 server 3") == BRISK_OK, i);
        }
        CHECKI(feed_row(MUT[i]) == (i == 0 ? BRISK_E_PROTO : BRISK_E_AUTH) && C.c.alert == want, i);
        CHECKI(all_zero(g_in + (i & 3), CAP), i);
        CHECKI(alert_is(flow_of(3)->c_ap, want), i);
    }
    /* seq skipped: the seq-1 record where seq 0 is due */
    CHECK(connect3(0) == 0 && feed_row("8448s3 server 3") == BRISK_E_AUTH);
    brisk__tls13_conn_wipe(&C.c);
}

/* Alerts from the peer (RFC 9846 6). */
static void conn_alerts(void)
{
    static const uint8_t CN2[2] = {2, 0}, UC[2] = {1, 90}, HF[2] = {2, 40}, UNK[2] = {1, 200},
                         A3[3] = {1, 0, 0};
    static uint8_t rec[512];
    size_t n, used, out_len;
    const uint8_t *pl;

    arena_used = 0;
    pl = dec(rrow("8448s3 server 3")->payload, &n);
    /* close_notify with level fatal is still a closure alert (the level is
     * ignored) */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_ALERT, CN2, 2);
    CHECK(feed_all(rec, n, n) == BRISK_OK && C.c.eof && all_zero(&C.c.rd, sizeof C.c.rd));
    /* our write side survives the peer's close (6.1) */
    CHECK(brisk__tls13_conn_write(&C.c, pl, 5, &used, wire, sizeof wire, &out_len) == BRISK_OK &&
          used == 5 && out_len == 5 + 5 + 1 + 16);
    /* user_canceled: keep going */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_ALERT, UC, 2);
    n += srv(rec + n, BRISK__CT_APP, pl, 10);
    CHECK(feed_all(rec, n, n) == BRISK_OK && !C.c.eof && app_len == 10 && C.c.err == 0);
    /* fatal ones, known and unknown: reported, keys gone, nothing sent back */
    CHECK(connect3(1) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_ALERT, HF, 2);
    CHECK(feed_all(rec, n, n) == BRISK_E_PEER_ALERT && C.c.peer_alert == 40);
    CHECK(all_zero(&C.c.rd, sizeof C.c.rd) && all_zero(&C.c.wr, sizeof C.c.wr) &&
          all_zero(C.c.pend, sizeof C.c.pend));
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0);
    CHECK(brisk__tls13_conn_write(&C.c, pl, 5, &used, wire, sizeof wire, &out_len) ==
          BRISK_E_PEER_ALERT);
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_ALERT, UNK, 2);
    CHECK(feed_all(rec, n, n) == BRISK_E_PEER_ALERT && C.c.peer_alert == 200);
    /* one Alert per record, exactly two bytes (5.1) */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_ALERT, A3, 1);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && alert_is(flow_of(3)->c_ap, 50));
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_ALERT, A3, 3);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 50);
    /* an alert in the middle of a handshake message (5.1 interleave) */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, dec(hrow("nst 8448s3")->msg, &used), 10);
    n += srv(rec + n, BRISK__CT_ALERT, CN2, 2);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 10 && !C.c.eof);
    /* 6.1: our close_notify is the last record - a later receive failure sends no alert */
    CHECK(connect3(0) == 0 && feed_row("8448s3 server 2") == BRISK_OK &&
          brisk__tls13_conn_close(&C.c) == BRISK_OK);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) != 0 && C.c.close == 2);
    CHECK(feed_row("mut tag last") == BRISK_E_AUTH && C.c.alert == BRISK__ALERT_BAD_RECORD_MAC);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0 && all_zero(&C.c.wr, sizeof C.c.wr));
    /* ... and application data there too */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, dec(hrow("nst 8448s3")->msg, &used), 10);
    n += srv(rec + n, BRISK__CT_APP, pl, 10);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 10 && app_len == 0);
    brisk__tls13_conn_wipe(&C.c);
}

/* Every post-handshake message row as one record under s_ap, plus splits and
 * batches. */
static void conn_post_hs(void)
{
    static uint8_t rec[4096];
    size_t i, n, nm, nn;
    const uint8_t *m, *x;

    for (i = 0; i < NHS; i++) {
        const struct tls13_hsmsg_kat *h = &TLS13_HSMSG_KAT[i];
        arena_used = 0;
        CHECKI(connect3(0) == 0, i);
        srv_key("8448s3 server 2");
        m = dec(h->msg, &nm);
        n = srv(rec, BRISK__CT_HANDSHAKE, m, nm);
        CHECKI(feed_all(rec, n, n) == (h->alert == 0 ? BRISK_OK : BRISK_E_PROTO), i);
        CHECKI(C.c.alert == h->alert, i);
        if (h->alert == 0 && m[0] == 4) {
            CHECKI(C.tk_calls == 1 && C.tk.lifetime == h->lifetime && C.tk.age_add == h->age_add &&
                       C.tk.max_early_data == h->max_early,
                   i);
            x = dec(h->nonce, &nn);
            CHECKI(C.tk.nonce_len == nn && memcmp(C.tk_nonce, x, nn) == 0, i);
            x = dec(h->ticket, &nn);
            CHECKI(C.tk.ticket_len == nn && memcmp(C.tk_ticket, x, nn) == 0, i);
        }
        if (h->alert != 0) {
            CHECKI(C.tk_calls == 0 && alert_is(flow_of(3)->c_ap, (uint8_t)h->alert), i);
        }
    }
    arena_used = 0;
    m = dec(hrow("nst 8448s3")->msg, &nm);
    /* split across 2 and 3 records, two in one record, then app data still flows
     */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, m, 3);
    n += srv(rec + n, BRISK__CT_HANDSHAKE, m + 3, nm - 3);
    n += srv(rec + n, BRISK__CT_HANDSHAKE, m, 100);
    n += srv(rec + n, BRISK__CT_HANDSHAKE, m + 100, 50);
    n += srv(rec + n, BRISK__CT_HANDSHAKE, m + 150, nm - 150);
    memcpy(out2, m, nm);
    memcpy(out2 + nm, m, nm);
    n += srv(rec + n, BRISK__CT_HANDSHAKE, out2, 2 * nm);
    n += srv(rec + n, BRISK__CT_APP, m, 20);
    CHECK(feed_all(rec, n, 13) == BRISK_OK && C.tk_calls == 4 && app_len == 20);
    /* no callback: parsed and ignored */
    CHECK(conn_start(3, 0, 0) == 0 && pull_is("8448s3 client 0") &&
          feed_row("8448s3 server 0") == BRISK_OK && feed_row("8448s3 server 1") == BRISK_OK);
    CHECK(feed_row("8448s3 server 2") == BRISK_OK && C.tk_calls == 0 && C.c.err == 0);
    /* a callback that refuses: internal_error, a local fault */
    CHECK(connect3(0) == 0);
    C.tk_ret = 1;
    CHECK(feed_row("8448s3 server 2") == BRISK_E_ARG &&
          alert_is(flow_of(3)->c_ap, BRISK__ALERT_INTERNAL_ERROR));
    /* RFC 9001 6: never a TLS KeyUpdate over QUIC (the engine refuses it; test
     * hook) */
    CHECK(connect3(0) == 0);
    C.hs.cfg.quic = 1;
    srv_key("8448s3 server 2");
    x = dec(hrow("ku0")->msg, &nn);
    n = srv(rec, BRISK__CT_HANDSHAKE, x, nn);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 10);
    /* RFC 9001 4.6.1: over QUIC early_data must be 0xffffffff (test hook, as above) */
    CHECK(connect3(0) == 0);
    C.hs.cfg.quic = 1;
    CHECK(feed_row("8448s3 server 2") == BRISK_E_PROTO && C.c.alert == 47 && C.tk_calls == 0);
    for (i = 0; i < 2; i++) {
        CHECKI(connect3(0) == 0, i);
        C.hs.cfg.quic = 1;
        srv_key("8448s3 server 2");
        x = dec(hrow(i == 0 ? "nst early_data quic" : "nst no ext")->msg, &nn);
        n = srv(rec, BRISK__CT_HANDSHAKE, x, nn);
        CHECKI(feed_all(rec, n, n) == BRISK_OK && C.tk_calls == 1 &&
                   C.tk.max_early_data == (i == 0 ? 0xffffffffu : 0),
               i);
    }
    /* KeyUpdate + a trailing byte in the same record (5.1) */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    x = dec(hrow("ku0")->msg, &nn);
    memcpy(out2, x, nn);
    out2[nn] = 4;
    n = srv(rec, BRISK__CT_HANDSHAKE, out2, nn + 1);
    CHECK(feed_all(rec, n, n) == BRISK_E_PROTO && C.c.alert == 10);
    brisk__tls13_conn_wipe(&C.c);
}

/* KeyUpdate both ways (4.7.3, 7.2) and the 5.5 / 5.3 limits through test hooks.
 */
static void conn_key_update(void)
{
    static uint8_t rec[4096];
    const uint8_t *ku0, *ku1, *pl, *a, *b;
    size_t n, nk, na, nb, used, out_len, pl_len, i, k;

    arena_used = 0;
    ku0 = dec(hrow("ku0")->msg, &nk);
    ku1 = dec(hrow("ku1")->msg, &nk);
    pl = dec(rrow("drv c app g1 seq 0")->payload, &pl_len);
    /* receive: KU(0), then the next record opens under s_ap_1 from seq 0 */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, ku0, nk);
    CHECK(feed_all(rec, n, n) == BRISK_OK && C.c.rd.n_updates == 1 && C.c.rd.seq == 0);
    CHECK(feed_row("upd s_ap g1") == BRISK_OK && app_len == 50 && memcmp(app, pl, 50) == 0);
    CHECK(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, sizeof wire, &out_len) == BRISK_OK &&
          out_len == 72 && C.c.wr.n_updates == 0); /* update_not_requested: no answer */
    /* ... and a record still under the old key is bad_record_mac */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, ku0, nk);
    n += srv(rec + n, BRISK__CT_APP, pl, 50);
    CHECK(feed_all(rec, n, n) == BRISK_E_AUTH && C.c.alert == BRISK__ALERT_BAD_RECORD_MAC);

    /* update_requested: KU(0) under the OLD c_ap, then app data under c_ap_1 at
     * seq 0; three requests while silent get one answer */
    a = dec(rrow("drv c ku0 g0 seq 0")->record, &na);
    b = dec(rrow("drv c app g1 seq 0")->record, &nb);
    for (i = 1; i <= 3; i++) {
        CHECKI(connect3(0) == 0, i);
        srv_key("8448s3 server 2");
        for (k = n = 0; k < i; k++) {
            n += srv(rec + n, BRISK__CT_HANDSHAKE, ku1, nk);
            CHECK(brisk__tls_dir_update(&SD) == BRISK_OK);
        }
        CHECKI(feed_all(rec, n, n) == BRISK_OK && C.c.ku_owe && C.c.rd.n_updates == i, i);
        CHECKI(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, sizeof wire, &out_len) ==
                       BRISK_OK &&
                   used == 50 && out_len == na + nb && memcmp(wire, a, na) == 0 &&
                   memcmp(wire + na, b, nb) == 0,
               i);
        CHECKI(C.c.wr.n_updates == 1 && !C.c.ku_owe, i);
    }
    /* the answer also goes out through conn_pull */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, ku1, nk);
    CHECK(feed_all(rec, n, n) == BRISK_OK);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == na && memcmp(wire, a, na) == 0);
    /* after our close_notify nothing more goes out, not even an owed KeyUpdate (6.1) */
    CHECK(brisk__tls13_conn_close(&C.c) == BRISK_OK &&
          brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 24);
    CHECK(brisk__tls_dir_update(&SD) == BRISK_OK);
    n = srv(rec, BRISK__CT_HANDSHAKE, ku1, nk);
    CHECK(feed_all(rec, n, n) == BRISK_OK && brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0);
    /* out too small for the owed KeyUpdate: nothing consumed, nothing overtakes
     * it */
    CHECK(connect3(0) == 0);
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, ku1, nk);
    CHECK(feed_all(rec, n, n) == BRISK_OK);
    CHECK(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, na - 1, &out_len) == BRISK_OK &&
          used == 0 && out_len == 0 && C.c.ku_owe && C.c.wr.seq == 0);

    /* 5.5: at 2^24 records the client rekeys on its own */
    CHECK(connect3(0) == 0);
    C.c.wr.seq = BRISK__TLS_REKEY_SEQ - 1;
    a = dec(rrow("drv c app g0 seq rekey-1")->record, &na);
    CHECK(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, sizeof wire, &out_len) == BRISK_OK &&
          out_len == na && memcmp(wire, a, na) == 0);
    a = dec(rrow("drv c ku0 g0 seq rekey")->record, &na);
    CHECK(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, sizeof wire, &out_len) == BRISK_OK &&
          out_len == na + nb && memcmp(wire, a, na) == 0 && memcmp(wire + na, b, nb) == 0);
    /* 4.7.3: at the 2^48-1 update cap a request is ignored */
    CHECK(connect3(0) == 0);
    C.c.wr.n_updates = ((uint64_t)1 << 48) - 1;
    srv_key("8448s3 server 2");
    n = srv(rec, BRISK__CT_HANDSHAKE, ku1, nk);
    CHECK(feed_all(rec, n, n) == BRISK_OK);
    a = dec(rrow("8448s3 client 2")->record, &na);
    CHECK(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, sizeof wire, &out_len) == BRISK_OK &&
          out_len == na && memcmp(wire, a, na) == 0 && !C.c.ku_owe);
    /* ... and at the 5.5 limit it cannot rekey: terminate (internal_error, a
     * local choice) */
    C.c.wr.seq = BRISK__TLS_REKEY_SEQ;
    CHECK(brisk__tls13_conn_write(&C.c, pl, 50, &used, wire, sizeof wire, &out_len) ==
              BRISK_E_ARG &&
          used == 0 && C.c.alert == BRISK__ALERT_INTERNAL_ERROR);
    /* 5.3: the receive counter never wraps */
    CHECK(connect3(0) == 0);
    C.c.rd.seq = UINT64_MAX;
    CHECK(feed_row("8448s3 server 2") == BRISK_E_PROTO && C.c.alert == 10);
    brisk__tls13_conn_wipe(&C.c);
}

/* RFC 8449 4: the peer's record_size_limit caps the TLSInnerPlaintext we send.
 */
static void conn_rsl(void)
{
    static const struct {
        uint16_t rsl;
        size_t content;
    } T[4] = {{64, 63}, {0, 16384}, {16385, 16384}, {65535, 16384}};
    static uint8_t data[40000];
    brisk__tls_dir d;
    size_t i, n, used, out_len, off, rl, len, tot;
    uint8_t type, alert;

    arena_used = 0;
    for (i = 0; i < sizeof data; i++) {
        data[i] = (uint8_t)(i * 7 + 1);
    }
    for (i = 0; i < 4; i++) {
        CHECKI(connect3(0) == 0, i);
        C.hs.peer_rsl = T[i].rsl; /* test hook: as if EncryptedExtensions had carried it */
        n = T[i].rsl == 64 ? 1000 : 20000;
        CHECKI(brisk__tls13_conn_write(&C.c, data, n, &used, out2, sizeof out2, &out_len) ==
                       BRISK_OK &&
                   used == n,
               i);
        memset(&d, 0, sizeof d);
        CHECKI(dir_from(&d, BRISK__EPOCH_APP, 0x1301, flow_of(3)->c_ap) == BRISK_OK, i);
        for (off = tot = 0; off + 5 <= out_len; off += rl) {
            rl = 5 + (size_t)brisk__load_be16(out2 + off + 3);
            CHECKI(brisk__tls_rec_open(&d, out2 + off, rl, &type, &len, &alert) == BRISK_OK &&
                       type == 23 && memcmp(out2 + off + 5, data + tot, len) == 0,
                   i);
            CHECKI(len == T[i].content || tot + len == n, i);
            tot += len;
        }
        CHECKI(off == out_len && tot == n, i);
        brisk__tls_dir_wipe(&d);
    }
    /* out cap below one record: nothing consumed */
    CHECK(connect3(0) == 0);
    CHECK(brisk__tls13_conn_write(&C.c, data, 10, &used, out2, 5 + 1 + 16, &out_len) == BRISK_OK &&
          used == 0 && out_len == 0 && C.c.wr.seq == 0);
    CHECK(brisk__tls13_conn_write(&C.c, data, 10, &used, out2, 5 + 2 + 16, &out_len) == BRISK_OK &&
          used == 1 && out_len == 23);
    /* RFC 8449 4, receive side: our own limit (test hook: as if the ClientHello offered 64)
     * binds the server once it answered in EE; a TLSInnerPlaintext of 65 is record_overflow,
     * 64 passes, and without the server's answer nothing is enforced. */
    for (i = 0; i < 3; i++) {
        CHECKI(connect3(0) == 0, i);
        C.hs.own_rsl = 64;
        C.hs.peer_rsl = i == 2 ? 0 : 0x4001;
        srv_key("8448s3 server 2");
        n = srv(out2, BRISK__CT_APP, data, i == 0 ? 63 : 64);
        CHECKI(feed_all(out2, n, n) == (i == 1 ? BRISK_E_PROTO : BRISK_OK), i);
        CHECKI(i == 1 ? alert_is(flow_of(3)->c_ap, BRISK__ALERT_RECORD_OVERFLOW)
                      : app_len == (i == 0 ? 63u : 64u),
               i);
    }
    brisk__tls13_conn_wipe(&C.c);
    /* the ClientHello's record_size_limit is parsed: below 64 is a caller error (RFC 8449 4) */
    {
        const struct tls13_flow_kat *k = flow_of(3);
        static const uint8_t RSL[6] = {0, 28, 0, 2, 0x40, 0x01};
        brisk__tls13_hs_cfg cfg;
        const uint8_t *ch = dec(k->ch1, &n), *priv = dec(k->priv1, &len);
        memcpy(out2, ch, n);
        for (off = 0; off + 6 <= n && memcmp(out2 + off, RSL, 6) != 0; off++) {
        }
        CHECK(off + 6 <= n);
        memset(&cfg, 0, sizeof cfg);
        cfg.auth = yes;
        for (i = 0; i < 2; i++) {
            out2[off + 4] = 0;
            out2[off + 5] = (uint8_t)(i == 0 ? 63 : 64);
            CHECKI(brisk__tls13_hs_init(&C.hs, &cfg, g_scratch, g_scratch_len) == BRISK_OK, i);
            CHECKI(brisk__tls13_hs_client_hello(&C.hs, out2, n, (uint16_t)k->g1, priv) ==
                           (i == 0 ? BRISK_E_ARG : BRISK_OK) &&
                       C.hs.own_rsl == (i == 0 ? 0 : 64),
                   i);
        }
        brisk__tls13_hs_wipe(&C.hs);
    }
}

static void conn_guards(void)
{
    size_t used, n;
    uint8_t b[8] = {0};
    arena_used = 0;
    CHECK(brisk__tls13_conn_init(&C.c, &C.hs, g_in, BRISK__TLS_REC_IN_MAX - 1) == BRISK_E_ARG);
    CHECK(brisk__tls13_conn_init(NULL, &C.hs, g_in, CAP) == BRISK_E_ARG);
    CHECK(brisk__tls13_conn_init(&C.c, NULL, g_in, CAP) == BRISK_E_ARG);
    CHECK(brisk__tls13_conn_feed(NULL, b, 1, &used) == BRISK_E_ARG);
    CHECK(brisk__tls13_conn_pull(NULL, b, 8) == 0);
    /* application data before CONNECTED is a caller error */
    CHECK(conn_start(3, 0, 0) == 0);
    CHECK(brisk__tls13_conn_write(&C.c, b, 1, &used, wire, sizeof wire, &n) == BRISK_E_ARG);
    /* the ClientHello record does not fit: nothing emitted, it comes out whole
     * later */
    CHECK(brisk__tls13_conn_pull(&C.c, wire, 5) == 0 && pull_is("8448s3 client 0"));
    /* 6.1: close_notify mid-handshake (under c_hs), then the server's flight completes: the
     * client Finished it queues must never follow the close_notify */
    CHECK(feed_row("8448s3 server 0") == BRISK_OK && brisk__tls13_conn_close(&C.c) == BRISK_OK);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) != 0 && C.c.close == 2);
    CHECK(feed_row("8448s3 server 1") == BRISK_OK && C.hs.state == BRISK__HS_CONNECTED);
    CHECK(brisk__tls13_conn_pull(&C.c, wire, sizeof wire) == 0);
    brisk__tls13_conn_wipe(&C.c);
    brisk__tls13_conn_wipe(NULL);
}

void test_tls13_rec(void)
{
    (void)TLS13_MTLS_KAT; /* tls13_psk.inc is shared with test_tls13_hs.c */
    (void)TLS13_DER_KAT;
    g_scratch_len = brisk__tls13_hs_scratch_size();
    g_scratch = (uint8_t *)malloc(g_scratch_len);
    g_in = (uint8_t *)malloc(CAP + 8);
    if (g_scratch == NULL || g_in == NULL) {
        exit(2);
    }
    rec_nonce();
    rec_kat();
    rec_dir();
    conn_guards();
    conn_trace3();
    conn_hrr_compat();
    conn_framing();
    conn_auth();
    conn_alerts();
    conn_post_hs();
    conn_key_update();
    conn_rsl();
    conn_split();
    brisk__tls_dir_wipe(&SD);
    free(g_scratch);
    free(g_in);
    g_scratch = g_in = NULL;
}

/* The constant-time run for tests/test_ct.c: the traffic secret marked secret
 * through dir_init, dir_update, rec_seal and rec_open; only the wire bytes are
 * declassified. */
void tls13_rec_ct_run(void)
{
    uint8_t secret[32], rec[128], type, alert;
    brisk__tls_dir w, r;
    size_t n, len, sl;
    const uint8_t *pl;

    arena_used = 0;
    memcpy(secret, dec(rrow("upd c_ap g0")->secret, &sl), 32);
    pl = dec(rrow("upd c_ap g0")->payload, &n);
    BRISK__CT_SECRET(secret, sizeof secret);
    memset(&w, 0, sizeof w);
    memset(&r, 0, sizeof r);
    CHECK(brisk__tls_dir_init(&w, BRISK__EPOCH_APP, 0x1301, secret, 32) == BRISK_OK);
    CHECK(brisk__tls_dir_init(&r, BRISK__EPOCH_APP, 0x1301, secret, 32) == BRISK_OK);
    CHECK(brisk__tls_dir_update(&w) == BRISK_OK && brisk__tls_dir_update(&r) == BRISK_OK);
    CHECK(brisk__tls_rec_seal(&w, 23, 0x0303, pl, n, 3, rec, sizeof rec, &len) == BRISK_OK);
    BRISK__CT_PUBLIC(rec, len); /* the record goes on the wire */
    CHECK(brisk__tls_rec_open(&r, rec, len, &type, &n, &alert) == BRISK_OK && n == 50);
    rec[len - 1] ^= 1;
    r.seq = 0;
    CHECK(brisk__tls_rec_open(&r, rec, len, &type, &n, &alert) == BRISK_E_AUTH);
    brisk__tls_dir_wipe(&w);
    brisk__tls_dir_wipe(&r);
    brisk__secure_zero(secret, sizeof secret);
    CHECK(sl == 32);
}
