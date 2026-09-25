/* test_conn.c - the public connection API, sans-I/O (src/tls/conn.c): brisk__conn_setup (the
 * seam brisk_conn_init wraps on Linux) and then ONLY the public calls - brisk_feed, brisk_pull,
 * brisk_status, brisk_app_read, brisk_app_write, brisk_close_notify, brisk_alert, brisk_alpn,
 * brisk_resumed, brisk_conn_wipe. Runs on every preset, the mingw host included.
 *
 * Every flow is a tools/kat.py row whose CH1 is the LIBRARY-DEFAULT ClientHello for
 * device.example.com: the tls13_fixture rows of tls13_trace.inc and the public-API rows of
 * tls13_conn.inc (HRR, cookie-only HRR, ALPN, resumption, mTLS). TLS13_CONN_RND is the 160-byte
 * draw (random | session_id | x25519 d | P-256 d | sign_rand) that makes the connection
 * reproduce each row's ClientHellos and client flight byte for byte. The server side is sealed
 * here with brisk__tls_rec_seal, whose output test_tls13_rec.c pins against kat.py rows.
 *
 * The default offer includes ecdsa_secp384r1_sha384 only with BRISK_ENABLE_P384, so the replays
 * need it (every CI preset is DEFAULT). It also offers TLS 1.2 with BRISK_ENABLE_TLS12 (M5), so
 * the replays take the rows generated for that ClientHello (TLS13_CONNFX_KAT, TLS13_CONN_KAT);
 * a BRISK_ENABLE_TLS12=0 build replays the pre-M5 ClientHello (the tls13_trace.inc fixture rows,
 * TLS13_CONN13_KAT) byte for byte, which is what proves that offer unchanged. */
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
struct tls13_rec_kat {
    const char *name;
    int sec, side, idx;
    unsigned suite;
    const char *secret, *key, *iv;
    unsigned long long seq;
    unsigned type, ver, pad;
    const char *payload, *record;
    int alert;
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
#include "kat/tls13_conn.inc"
#include "kat/tls13_psk.inc"
#include "kat/tls13_record.inc"
#include "kat/tls13_trace.inc"

#if BRISK_ENABLE_TLS12
#    define FX_KAT   TLS13_CONNFX_KAT
#    define CONN_KAT TLS13_CONN_KAT
#else
#    define FX_KAT   TLS13_FLOW_KAT
#    define CONN_KAT TLS13_CONN13_KAT
#endif
#define NFLOW  (sizeof FX_KAT / sizeof FX_KAT[0])
#define NCONN  (sizeof CONN_KAT / sizeof CONN_KAT[0])
#define HOST   "device.example.com"
#define F_TIME 1 /* kat.py TLS13_F_TIME */

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

static const struct tls13_flow_kat *row(const char *prefix)
{
    size_t i, n = strlen(prefix);
    for (i = 0; i < NFLOW; i++) {
        if (strncmp(FX_KAT[i].note, prefix, n) == 0) {
            return &FX_KAT[i];
        }
    }
    for (i = 0; i < NCONN; i++) {
        if (strncmp(CONN_KAT[i].note, prefix, n) == 0) {
            return &CONN_KAT[i];
        }
    }
    exit(2); /* a row the generator no longer emits: the harness is out of date */
}

/* ---------------------------------------------------------------- the server's side -------- */
static uint8_t RND[BRISK__CONN_RAND];
static uint8_t *g_mem; /* brisk_conn_size() + 8, so the connection can sit at any offset */
static size_t g_size;
static brisk_conn *C;
static uint8_t wire[1 << 15], srv[1 << 15], app[1 << 15], tmp[1 << 15];
static size_t app_len;

static unsigned sh_suite(const uint8_t *sh)
{
    return brisk__load_be16(sh + 4 + 35 + sh[4 + 34]);
}

static int dir_from(brisk__tls_dir *d, unsigned epoch, unsigned suite, const char *secret_hex)
{
    size_t n;
    const uint8_t *s = dec(secret_hex, &n);
    memset(d, 0, sizeof *d);
    return brisk__tls_dir_init(d, epoch, (uint16_t)suite, s, n);
}

/* One handshake message in one plaintext record (RFC 9846 5.1). */
static size_t plain(uint8_t *out, const char *msg_hex)
{
    size_t n;
    const uint8_t *m = dec(msg_hex, &n);
    out[0] = BRISK__CT_HANDSHAKE;
    out[1] = 3;
    out[2] = 3;
    brisk__store_be16(out + 3, (uint32_t)n);
    memcpy(out + 5, m, n);
    return 5 + n;
}

/* The server's flight after its hello: SH in the clear, then EE [CR] [Cert CV] SF in one record
 * under s_hs. Returns the bytes written at out. */
static size_t flight(const struct tls13_flow_kat *k, uint8_t *out)
{
    const char *parts[5];
    brisk__tls_dir d;
    size_t n, i, tot = 0, len = 0;
    const uint8_t *m;
    unsigned suite;

    n = plain(out, k->sh);
    suite = sh_suite(out + 5);
    parts[0] = k->ee;
    parts[1] = k->cr;
    parts[2] = k->cert;
    parts[3] = k->cv;
    parts[4] = k->sf;
    for (i = 0; i < 5; i++) {
        m = dec(parts[i], &len);
        memcpy(tmp + tot, m, len);
        tot += len;
    }
    if (dir_from(&d, BRISK__EPOCH_HANDSHAKE, suite, k->s_hs) != BRISK_OK ||
        brisk__tls_rec_seal(&d, BRISK__CT_HANDSHAKE, 0x0303, tmp, tot, 0, out + n, sizeof srv - n,
                            &len) != BRISK_OK) {
        exit(2);
    }
    brisk__tls_dir_wipe(&d);
    return n + len;
}

/* The row's configuration: its anchor in memory (DER), nothing else. */
static brisk_cfg cfg_of(const struct tls13_flow_kat *k)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    size_t n;
    cfg.ca_mem = dec(k->root, &n);
    cfg.ca_mem_len = n;
    return cfg;
}

static int setup(const struct tls13_flow_kat *k, size_t off, const brisk_cfg *cfg, int64_t now_ms)
{
    memset(g_mem, 0, g_size + 8);
    app_len = 0;
    return brisk__conn_setup(g_mem + off, g_size, cfg, k->host, now_ms, RND, NULL, &C);
}

static int64_t now_of(const struct tls13_flow_kat *k)
{
    return (int64_t)k->now * 1000;
}

/* brisk_pull == the record(s) carrying `msg_hex` in the clear, header version `ver`. */
static int pull_hello(const char *msg_hex, unsigned ver)
{
    size_t n, got = brisk_pull(C, wire, sizeof wire);
    const uint8_t *m = dec(msg_hex, &n);
    return got == 5 + n && wire[0] == BRISK__CT_HANDSHAKE && brisk__load_be16(wire + 1) == ver &&
           brisk__load_be16(wire + 3) == n && memcmp(wire + 5, m, n) == 0;
}

/* Feed n bytes in chunks of at most `chunk`, draining application data after every call. */
static int feed(const uint8_t *p, size_t n, size_t chunk)
{
    size_t k, used, got;
    int rc;
    while (n != 0) {
        k = n < chunk ? n : chunk;
        rc = brisk_feed(C, p, k, &used);
        if (used > k) {
            return 96;
        }
        p += used;
        n -= used;
        while (brisk_app_read(C, app + app_len, 7, &got) == BRISK_OK && got != 0) {
            app_len += got;
        }
        if (rc != BRISK_OK) {
            return rc;
        }
        if (used == 0) {
            return 97; /* no progress */
        }
    }
    return BRISK_OK;
}

/* Whole records in wire[0..n): CCS skipped, the rest opened with d; the handshake payloads are
 * concatenated into tmp. Returns the payload length, or (size_t)-1 on a partial/bad record. */
static size_t open_flight(brisk__tls_dir *d, uint8_t *w, size_t n, size_t *tot)
{
    size_t off = 0, rl, len;
    uint8_t type, alert;
    while (off < n) {
        if (n - off < 5 || n - off < 5 + (rl = brisk__load_be16(w + off + 3))) {
            return (size_t)-1;
        }
        if (w[off] != BRISK__CT_CCS) {
            if (brisk__tls_rec_open(d, w + off, 5 + rl, &type, &len, &alert) != BRISK_OK ||
                type != BRISK__CT_HANDSHAKE) {
                return (size_t)-1;
            }
            memcpy(tmp + *tot, w + off + 5, len);
            *tot += len;
        } else if (rl != 1 || w[off + 5] != 1) {
            return (size_t)-1;
        }
        off += 5 + rl;
    }
    return *tot;
}

static int flight_is(const struct tls13_flow_kat *k, unsigned suite, size_t cap)
{
    brisk__tls_dir d;
    size_t n, tot = 0, cf_len;
    const uint8_t *cf = dec(k->cf, &cf_len);
    int ok = dir_from(&d, BRISK__EPOCH_HANDSHAKE, suite, k->c_hs) == BRISK_OK;
    while (ok && (n = brisk_pull(C, wire + 1, cap)) != 0) {
        ok = n <= cap && open_flight(&d, wire + 1, n, &tot) != (size_t)-1;
    }
    brisk__tls_dir_wipe(&d);
    return ok && tot == cf_len && memcmp(tmp, cf, cf_len) == 0;
}

/* One record the client sealed, opened under `d`: its type and content must be as given. */
static int client_rec(brisk__tls_dir *d, const uint8_t *w, size_t n, uint8_t type, const void *want,
                      size_t want_len)
{
    uint8_t t, alert;
    size_t len;
    memcpy(tmp, w, n);
    return n >= 5 && brisk__load_be16(tmp + 3) == n - 5 &&
           brisk__tls_rec_open(d, tmp, n, &t, &len, &alert) == BRISK_OK && t == type &&
           len == want_len && memcmp(tmp + 5, want, want_len) == 0;
}

/* The single fatal alert (RFC 9846 6.2) under `secret_hex` (NULL: plaintext), then silence. */
static int alert_is(const char *secret_hex, unsigned suite, int desc)
{
    brisk__tls_dir d;
    const uint8_t a[2] = {2, (uint8_t)desc};
    size_t n = brisk_pull(C, wire, sizeof wire);
    int ok;
    memset(&d, 0, sizeof d);
    ok = (secret_hex == NULL || dir_from(&d, BRISK__EPOCH_HANDSHAKE, suite, secret_hex) == 0) &&
         client_rec(&d, wire, n, BRISK__CT_ALERT, a, 2);
    brisk__tls_dir_wipe(&d);
    return ok && brisk_pull(C, wire, sizeof wire) == 0 && brisk_alert(C) == desc;
}

#if BRISK_ENABLE_P384
/* ---------------------------------------------------------------- whole flows --------------- */

/* A row's happy path through the public API, feeding the server in `chunk`-byte pieces; the
 * connection sits at g_mem + off. 0, or the number of the step that failed. */
static int happy(const struct tls13_flow_kat *k, size_t off, size_t chunk, const brisk_cfg *cfg)
{
    static const uint8_t PING[4] = {'p', 'i', 'n', 'g'}, PONG[5] = {'p', 'o', 'n', 'g', '!'},
                         CN[2] = {1, 0};
    brisk__tls_dir cw, sw;
    size_t n, used, out_len;
    unsigned suite;
    const char *name;
    int step = 0;

    /* the caller resets the arena: cfg may point into it */
    if (setup(k, off, cfg, now_of(k)) != BRISK_OK) {
        return 1;
    }
    if (brisk_status(C) != BRISK_E_WANT || !pull_hello(k->ch1, 0x0301)) {
        return 2; /* 5.1: 0x0301 on the initial ClientHello */
    }
    if (*k->hrr) {
        n = plain(srv, k->hrr);
        if (feed(srv, n, chunk) != BRISK_OK || !pull_hello(k->ch2, 0x0303)) {
            return 3; /* 4.1.4 / 4.2.2: CH2 byte for byte, 0x0303 */
        }
    }
    n = flight(k, srv);
    suite = sh_suite(srv + 5);
    if (feed(srv, n, chunk) != BRISK_OK || brisk_status(C) != BRISK_OK) {
        return 4;
    }
    if (!flight_is(k, suite, sizeof wire - 1)) {
        return 5; /* compat CCS + [Certificate CertificateVerify] Finished under c_hs */
    }
    if (brisk_resumed(C) != k->resumed || brisk_alpn(C, &name, &n) != BRISK_OK ||
        n != strlen(k->alpn) || (n != 0 && memcmp(name, k->alpn, n) != 0)) {
        return 6;
    }
    if (dir_from(&cw, BRISK__EPOCH_APP, suite, k->c_ap) != BRISK_OK ||
        dir_from(&sw, BRISK__EPOCH_APP, suite, k->s_ap) != BRISK_OK) {
        return 7;
    }
    /* application data both ways, odd buffer offsets */
    step = brisk_app_write(C, PING, sizeof PING, &used, wire + 3, sizeof wire - 3, &out_len) ==
                       BRISK_OK &&
                   used == sizeof PING &&
                   client_rec(&cw, wire + 3, out_len, BRISK__CT_APP, PING, sizeof PING)
               ? 0
               : 8;
    if (step == 0 && (brisk__tls_rec_seal(&sw, BRISK__CT_APP, 0x0303, PONG, sizeof PONG, 0, srv + 1,
                                          sizeof srv - 1, &n) != BRISK_OK ||
                      feed(srv + 1, n, chunk) != BRISK_OK || app_len != sizeof PONG ||
                      memcmp(app, PONG, sizeof PONG) != 0)) {
        step = 9;
    }
    /* close_notify both ways (6.1) */
    if (step == 0 &&
        (brisk_close_notify(C) != BRISK_OK ||
         !client_rec(&cw, wire, brisk_pull(C, wire, sizeof wire), BRISK__CT_ALERT, CN, 2))) {
        step = 10;
    }
    if (step == 0 && (brisk__tls_rec_seal(&sw, BRISK__CT_ALERT, 0x0303, CN, 2, 0, srv, sizeof srv,
                                          &n) != BRISK_OK ||
                      feed(srv, n, chunk) != BRISK_OK ||
                      brisk_app_read(C, app, 5, &used) != BRISK_OK || used != 0)) {
        step = 11;
    }
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);
    brisk_conn_wipe(C);
    if (step == 0 && !all_zero(g_mem, g_size + 8)) {
        step = 12; /* every key, the scratch and rec_in are gone */
    }
    return step;
}

static void conn_full(void)
{
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    brisk_cfg cfg;
    size_t n;
    const uint8_t *rogue;
    static uint8_t anchors[2048];

    arena_used = 0;
    cfg = cfg_of(k);
    CHECK(happy(k, 0, 1 << 20, &cfg) == 0);
    /* PEM anchors from memory (brisk__x509_pem_feed), resolved through the same lookup */
    cfg.ca_mem = (const uint8_t *)TLS13_CONN_ROOT_PEM;
    cfg.ca_mem_len = strlen(TLS13_CONN_ROOT_PEM);
    CHECK(happy(k, 3, 1 << 20, &cfg) == 0);
    /* two anchors with the root's Name, the rogue one first: the walk asks for index 0, fails,
     * then index 1 (RFC 5280 6.1: every candidate is tried) */
    arena_used = 0;
    rogue = dec(row("RFC 5280 6.1: the anchor shares")->root, &n);
    memcpy(anchors, rogue, n);
    cfg = cfg_of(k);
    memcpy(anchors + n, cfg.ca_mem, cfg.ca_mem_len);
    cfg.ca_mem = anchors;
    cfg.ca_mem_len += n;
    CHECK(happy(k, 5, 1 << 20, &cfg) == 0);
}

static int fake_sys_calls;
static size_t fake_sys_index;
/* A file store holding only the fixture root, to check the numbering after memory hits. */
static int fake_sys(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                    brisk__x509_cert *out)
{
    size_t n;
    const uint8_t *r = dec(row("fixture: P-256 leaf")->root, &n);
    (void)ctx;
    fake_sys_calls++;
    fake_sys_index = index;
    if (index != 0 || brisk__x509_parse(out, r, n) != BRISK_OK || out->subject_len != dn_len ||
        memcmp(out->subject, dn, dn_len) != 0) {
        memset(out, 0, sizeof *out);
        return BRISK_E_ARG;
    }
    return BRISK_OK;
}

static void conn_trust(void)
{
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf"),
                                *bad = row("RFC 5280 6.1: the anchor shares");
    brisk_cfg cfg = BRISK_DEFAULTS;
    size_t n;
    int i;

    /* ca_mem (rogue) + ca_file: memory index 0 fails, the file store gets index 0 next */
    for (i = 0; i < 3; i++) {
        arena_used = 0;
        cfg = cfg_of(bad);
        cfg.ca_file = i == 2 ? NULL : "fake";
        if (i == 1) {
            cfg.ca_mem = NULL;
            cfg.ca_mem_len = 0;
        }
        fake_sys_calls = 0;
        memset(g_mem, 0, g_size + 8);
        CHECKI(brisk__conn_setup(g_mem, g_size, &cfg, HOST, now_of(k), RND, fake_sys, &C) ==
                   BRISK_OK,
               i);
        CHECKI(brisk_pull(C, wire, sizeof wire) != 0, i);
        n = flight(k, srv);
        CHECKI(brisk_feed(C, srv, n, &n) == (i == 2 ? BRISK_E_AUTH : BRISK_OK), i);
        /* ca_mem alone means memory only: the store is never consulted (i == 2) */
        CHECKI(fake_sys_calls == (i == 2 ? 0 : 1) && fake_sys_index == 0, i);
        brisk_conn_wipe(C);
    }
}

static void conn_suites(void)
{
    static const char *const ROWS[3] = {"fixture: TLS_AES_256_GCM", "fixture: TLS_CHACHA20",
                                        "fixture: RSA-2049"};
    brisk_cfg cfg;
    size_t i;
    for (i = 0; i < 3; i++) {
        arena_used = 0;
        cfg = cfg_of(row(ROWS[i]));
        CHECKI(happy(row(ROWS[i]), i & 3, 1 << 20, &cfg) == 0, i);
    }
    /* every public-API row except mTLS (conn_mtls) and resumption (conn_psk_in) */
    for (i = 0; i < 3; i++) {
        arena_used = 0;
        cfg = cfg_of(&CONN_KAT[i]);
        if (i == 2) {
            cfg.alpn = "mqtt,h2";
        }
        CHECKI(happy(&CONN_KAT[i], 1, 1 << 20, &cfg) == 0, 10 + i);
    }
}

static void conn_negative_rows(void)
{
    const struct tls13_flow_kat *k;
    brisk_cfg cfg;
    size_t i, n, used, out_len;
    int want;

    for (i = 0; i < NFLOW; i++) {
        k = &FX_KAT[i];
        if (k->alert == 0 || strcmp(k->host, HOST) != 0) {
            continue;
        }
#    if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
        if (k->flags & F_TIME) {
            continue; /* no clock policy: that row connects */
        }
#    endif
        arena_used = 0;
        cfg = cfg_of(k);
        want = k->alert == 42 || k->alert == 43 || k->alert == 48 || k->alert == 51 ? BRISK_E_AUTH
                                                                                    : BRISK_E_PROTO;
        CHECKI(setup(k, i & 3, &cfg, now_of(k)) == BRISK_OK && pull_hello(k->ch1, 0x0301), i);
        n = flight(k, srv);
        CHECKI(brisk_feed(C, srv, n, &used) == want, i);
        /* sticky everywhere, and exactly one fatal alert under c_hs */
        CHECKI(brisk_feed(C, srv, 1, &used) == want && used == 0 && brisk_status(C) == want, i);
        CHECKI(brisk_app_write(C, "x", 1, &used, wire, sizeof wire, &out_len) == want, i);
        CHECKI(alert_is(k->c_hs, sh_suite(srv + 5), k->alert), i);
        brisk_conn_wipe(C);
        CHECKI(all_zero(g_mem, g_size + 8), i);
    }
}

static void conn_split(void)
{
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    static const size_t OFF[4] = {0, 1, 3, 5};
    brisk_cfg cfg;
    size_t chunk;
    uint32_t x = 20260923u;

    for (chunk = 1; chunk <= 72; chunk++) {
        arena_used = 0;
        cfg = cfg_of(k);
        if (chunk > 64) { /* random chunk sizes, 1..300 */
            x = x * 1103515245u + 12345u;
            CHECKI(happy(k, OFF[chunk & 3], 1 + ((x >> 16) % 300u), &cfg) == 0, chunk);
        } else {
            CHECKI(happy(k, OFF[chunk & 3], chunk, &cfg) == 0, chunk);
        }
    }
    /* HRR: CH2 is built in the receive buffer, whatever the split */
    for (chunk = 1; chunk <= 7; chunk += 3) {
        arena_used = 0;
        cfg = cfg_of(&CONN_KAT[0]);
        CHECKI(happy(&CONN_KAT[0], chunk & 3, chunk, &cfg) == 0, 100 + chunk);
    }
}

static void conn_pull_cap(void)
{
    static const size_t CAPS[6] = {0, 1, 5, 6, 38, 64};
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    brisk_cfg cfg;
    size_t i, n;

    for (i = 0; i < 6; i++) {
        arena_used = 0;
        cfg = cfg_of(k);
        CHECKI(setup(k, 0, &cfg, now_of(k)) == BRISK_OK && pull_hello(k->ch1, 0x0301), i);
        n = flight(k, srv);
        CHECKI(brisk_feed(C, srv, n, &n) == BRISK_OK && brisk_status(C) == BRISK_OK, i);
        if (CAPS[i] < 28) { /* no room for any record: nothing, and nothing lost */
            CHECKI(brisk_pull(C, wire, CAPS[i]) == 0, i);
            CHECKI(flight_is(k, 0x1301, sizeof wire - 1), i);
        } else { /* whole records only, reassembled over several pulls */
            CHECKI(flight_is(k, 0x1301, CAPS[i]), i);
        }
        brisk_conn_wipe(C);
    }
}

static void conn_closure_early(void)
{
    static const uint8_t CN_PLAIN[7] = {21, 3, 3, 0, 2, 1, 0},
                         UC_PLAIN[7] = {21, 3, 3, 0, 2, 1, 90};
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    brisk__tls_dir d;
    brisk_cfg cfg;
    size_t i, n, used;
    uint8_t a[2];

    for (i = 0; i < 4; i++) {
        arena_used = 0;
        cfg = cfg_of(k);
        CHECKI(setup(k, 0, &cfg, now_of(k)) == BRISK_OK && pull_hello(k->ch1, 0x0301), i);
        if (i < 2) { /* before the ServerHello, in the clear */
            memcpy(srv, i == 0 ? CN_PLAIN : UC_PLAIN, 7);
            n = 7;
        } else { /* after it, under s_hs, before the server Finished */
            n = plain(srv, k->sh);
            a[0] = 1;
            a[1] = i == 2 ? 0 : 90;
            CHECKI(dir_from(&d, BRISK__EPOCH_HANDSHAKE, 0x1301, k->s_hs) == BRISK_OK, i);
            CHECKI(brisk__tls_rec_seal(&d, BRISK__CT_ALERT, 0x0303, a, 2, 0, srv + n,
                                       sizeof srv - n, &used) == BRISK_OK,
                   i);
            n += used;
            brisk__tls_dir_wipe(&d);
        }
        /* 6.1: a closure alert before the handshake completed is the peer's abort, never EOF */
        CHECKI(brisk_feed(C, srv, n, &used) == BRISK_E_PEER_ALERT, i);
        CHECKI(brisk_status(C) == BRISK_E_PEER_ALERT && brisk_alert(C) == (i & 1 ? 90 : 0), i);
        CHECKI(brisk_app_read(C, app, 1, &used) == BRISK_E_PEER_ALERT, i);
        CHECKI(brisk_pull(C, wire, sizeof wire) == 0, i); /* 6.2: nothing is sent back */
        brisk_conn_wipe(C);
    }
}

static void conn_hrr(void)
{
    static const uint8_t CCS[6] = {20, 3, 3, 0, 1, 1};
    const struct tls13_flow_kat *k;
    brisk_cfg cfg;
    size_t n, used;
    uint8_t zero_p256[BRISK__CONN_RAND];

    /* HRR + the server's compat CCS in one feed call */
    arena_used = 0;
    k = &CONN_KAT[0];
    cfg = cfg_of(k);
    CHECK(setup(k, 0, &cfg, now_of(k)) == BRISK_OK && pull_hello(k->ch1, 0x0301));
    n = plain(srv, k->hrr);
    memcpy(srv + n, CCS, sizeof CCS);
    /* ... and the first 3 bytes of the ServerHello record too: CH2 must not be built over
     * a partial record in the receive buffer */
    used = flight(k, srv + n + sizeof CCS);
    CHECK(brisk_feed(C, srv, n + sizeof CCS + 3, &n) == BRISK_OK &&
          n == 5 + strlen(k->hrr) / 2 + 9);
    CHECK(pull_hello(k->ch2, 0x0303) && brisk_pull(C, wire, sizeof wire) == 0);
    CHECK(brisk_feed(C, srv + n, used - 3, &used) == BRISK_OK && brisk_status(C) == BRISK_OK);
    CHECK(flight_is(k, 0x1301, sizeof wire - 1));
    /* the x25519 and P-256 slices are wiped once CH2 is queued */
    CHECK(all_zero((const uint8_t *)C + offsetof(struct brisk_conn, rnd) + 64, 64));
    brisk_conn_wipe(C);

    /* an internal fault building CH2 (a P-256 slice that is no scalar, only reachable through
     * the seam) is internal_error + BRISK_E_ARG, never BRISK_E_PROTO (6.2) */
    memcpy(zero_p256, RND, sizeof RND);
    memset(zero_p256 + 96, 0, 32);
    arena_used = 0;
    memset(g_mem, 0, g_size + 8);
#    if BRISK_ENABLE_TLS12
    /* ... and with TLS 1.2 offered the slice is the ServerKeyExchange's P-256 d from the start,
     * so the fault is a setup error (BRISK_E_ARG, memory wiped) */
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, now_of(k), zero_p256, NULL, &C) ==
              BRISK_E_ARG &&
          all_zero(g_mem, g_size + 8));
    (void)used;
#    else
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, now_of(k), zero_p256, NULL, &C) ==
              BRISK_OK &&
          pull_hello(k->ch1, 0x0301));
    n = plain(srv, k->hrr);
    CHECK(brisk_feed(C, srv, n, &used) == BRISK_E_ARG && brisk_status(C) == BRISK_E_ARG);
    CHECK(alert_is(NULL, 0, 80));
    brisk_conn_wipe(C);
#    endif
}

static int tk_calls;
static uint8_t tk_blob[BRISK_TICKET_MAX];
static size_t tk_len;
static void on_ticket(void *ctx, const uint8_t *blob, size_t len)
{
    CHECK(ctx == (void *)&tk_calls && len <= sizeof tk_blob);
    tk_calls++;
    memcpy(tk_blob, blob, len);
    tk_len = len;
}

/* Up to CONNECTED on row k (no HRR, suite 0x1301), the client flight pulled. */
static int connect_row(const struct tls13_flow_kat *k, const brisk_cfg *cfg)
{
    size_t n;
    if (setup(k, 1, cfg, now_of(k)) != BRISK_OK || !pull_hello(k->ch1, 0x0301)) {
        return 1;
    }
    n = flight(k, srv);
    return brisk_feed(C, srv, n, &n) != BRISK_OK || !flight_is(k, 0x1301, sizeof wire - 1);
}

static int connect_p256(const brisk_cfg *cfg)
{
    return connect_row(row("fixture: P-256 leaf"), cfg);
}

static const uint8_t *ch_ext(const uint8_t *w, size_t n, unsigned type, size_t *len);

/* RFC 9846 4.3.9: psk_key_exchange_modes also governs the tickets a server may issue - without
 * it real servers (OpenSSL, BoringSSL) send none, so resumption could never start. The first
 * ClientHello carries it exactly when on_ticket is set. Tickets then reach on_ticket; the
 * resumed row is used so that its (modes-carrying) CH1 matches byte for byte. */
static void conn_ticket(void)
{
    const struct tls13_flow_kat *k = row("fixture: resumed from a ticket blob");
    brisk__tls_dir sw;
    brisk__tls13_psk psk;
    brisk_cfg cfg;
    size_t n, nm, used, el;
    const uint8_t *m;
    int i;

    for (i = 0; i < 2; i++) {
        arena_used = 0;
        cfg = cfg_of(k);
        if (i == 1) {
            cfg.on_ticket = on_ticket;
            cfg.ticket_ctx = &tk_calls;
        }
        CHECKI(setup(k, 0, &cfg, now_of(k)) == BRISK_OK, i);
        n = brisk_pull(C, wire, sizeof wire);
        m = ch_ext(wire, n, 45, &el);
        CHECKI(i == 0 ? m == NULL : m != NULL && el == 2 && m[0] == 1 && m[1] == 1, i);
        brisk_conn_wipe(C);
    }
    for (i = 0; i < 3; i++) {
        arena_used = 0;
        cfg = cfg_of(k);
        cfg.ticket = dec(TLS13_CONN_BLOB, &cfg.ticket_len);
        if (i != 1) {
            cfg.on_ticket = on_ticket;
            cfg.ticket_ctx = &tk_calls;
        }
        tk_calls = 0;
        CHECKI(connect_row(k, &cfg) == 0, i);
        CHECKI(dir_from(&sw, BRISK__EPOCH_APP, 0x1301, k->s_ap) == BRISK_OK, i);
        if (i < 2) { /* RFC 8448 sect 3's NewSessionTicket, sealed under this s_ap */
            size_t j;
            for (j = 0; strcmp(TLS13_HSMSG_KAT[j].name, "nst 8448s3") != 0; j++) {
            }
            m = dec(TLS13_HSMSG_KAT[j].msg, &nm);
        } else { /* a ticket that cannot fit a blob: export fails, nobody notices (4.7.1) */
            m = dec(TLS13_CONN_NST_LONG, &nm);
        }
        CHECKI(brisk__tls_rec_seal(&sw, BRISK__CT_HANDSHAKE, 0x0303, m, nm, 0, srv, sizeof srv,
                                   &n) == BRISK_OK,
               i);
        CHECKI(brisk__tls_rec_seal(&sw, BRISK__CT_APP, 0x0303, m, 9, 0, srv + n, sizeof srv - n,
                                   &used) == BRISK_OK,
               i);
        CHECKI(feed(srv, n + used, 1 << 20) == BRISK_OK && brisk_status(C) == BRISK_OK, i);
        CHECKI(app_len == 9 && tk_calls == (i == 0), i); /* the connection lives on */
        if (i == 0) {
            /* the blob imports for this host only (4.7.1) */
            CHECK(brisk__tls13_ticket_import(tk_blob, tk_len, HOST, strlen(HOST), now_of(k),
                                             &psk) == BRISK_OK &&
                  psk.suite == 0x1301 && psk.psk_len == 32);
            CHECK(brisk__tls13_ticket_import(tk_blob, tk_len, "other.example.com", 17, now_of(k),
                                             &psk) == BRISK_E_ARG);
        }
        brisk__tls_dir_wipe(&sw);
        brisk_conn_wipe(C);
    }
    brisk__secure_zero(&psk, sizeof psk);
}

static void conn_psk_in(void)
{
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf"), *r = &CONN_KAT[3];
    static uint8_t big_ticket[1900], blob[BRISK_TICKET_MAX];
    brisk__tls13_ticket t;
    brisk_cfg cfg;
    size_t blob_len = 0;
    int i;

    /* a valid blob for this host: resumed, pre_shared_key last with the engine's binder */
    arena_used = 0;
    cfg = cfg_of(r);
    cfg.ticket = dec(TLS13_CONN_BLOB, &cfg.ticket_len);
    CHECK(happy(r, 0, 1 << 20, &cfg) == 0);
    /* not offered, the CH is the plain default one: another host's blob (RFC 8448 "server"),
     * garbage, expired (now past the 7200 s lifetime), too large to fit the ClientHello */
    memset(&t, 0, sizeof t);
    memset(big_ticket, 0x5A, sizeof big_ticket);
    t.lifetime = 3600;
    t.age_add = 1;
    t.ticket = big_ticket;
    t.ticket_len = sizeof big_ticket;
    t.psk_len = 32;
    t.suite = 0x1301;
    memset(t.psk, 7, 32);
    CHECK(brisk__tls13_ticket_export(&t, now_of(k) - 1000, HOST, strlen(HOST), blob, sizeof blob,
                                     &blob_len) == BRISK_OK);
    for (i = 0; i < 4; i++) {
        int64_t now = now_of(k);
        arena_used = 0;
        cfg = cfg_of(k);
        if (i == 0) {
            cfg.ticket = dec(TLS13_PSK_KAT[0].blob, &cfg.ticket_len);
        } else if (i == 1) {
            cfg.ticket = (const uint8_t *)TLS13_CONN_ROOT_PEM;
            cfg.ticket_len = 64;
        } else if (i == 2) {
            cfg.ticket = dec(TLS13_CONN_BLOB, &cfg.ticket_len);
            now += 7200 * 1000;
        } else {
            cfg.ticket = blob;
            cfg.ticket_len = blob_len;
        }
        CHECKI(setup(k, 0, &cfg, now) == BRISK_OK && pull_hello(k->ch1, 0x0301), i);
        brisk_conn_wipe(C);
    }
    CHECK(happy(k, 0, 1 << 20, &cfg) == 0); /* and the oversized one still connects */
}

/* Extension `type` in the ClientHello record at w[0..n): its data and *len, or NULL. */
static const uint8_t *ch_ext(const uint8_t *w, size_t n, unsigned type, size_t *len)
{
    size_t i = 5 + 4 + 2 + 32, end;
    i += 1 + w[i];                    /* legacy_session_id */
    i += 2 + brisk__load_be16(w + i); /* cipher_suites */
    i += 1 + w[i];                    /* legacy_compression_methods */
    end = i + 2 + brisk__load_be16(w + i);
    for (i += 2; end <= n && i + 4 <= end; i += 4 + brisk__load_be16(w + i + 2)) {
        if (brisk__load_be16(w + i) == type) {
            *len = brisk__load_be16(w + i + 2);
            return w + i + 4;
        }
    }
    return NULL;
}

/* The first row's HRR (-> secp256r1, suite 0x1301) with a BRISK__TLS13_COOKIE_MAX cookie: the
 * largest CH2 this client builds. As one plaintext record at out. */
static size_t big_hrr(uint8_t *out)
{
    static const uint8_t EXT[16] = {0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 0x17, 0, 44, 1, 2};
    size_t n;
    const uint8_t *m = dec(CONN_KAT[0].hrr, &n);
    uint8_t *p = out + 5;
    memcpy(p, m, 74); /* type | length | version | random | session_id(32) | suite | 0 */
    brisk__store_be16(p + 74, 16 + 2 + BRISK__TLS13_COOKIE_MAX);
    memcpy(p + 76, EXT, 16);
    brisk__store_be16(p + 92, BRISK__TLS13_COOKIE_MAX);
    memset(p + 94, 0xC0, BRISK__TLS13_COOKIE_MAX);
    n = 94 + BRISK__TLS13_COOKIE_MAX;
    p[1] = 0;
    brisk__store_be16(p + 2, (uint32_t)(n - 4));
    out[0] = BRISK__CT_HANDSHAKE;
    out[1] = 3;
    out[2] = 3;
    brisk__store_be16(out + 3, (uint32_t)n);
    return 5 + n;
}

/* RFC 9846 4.2.2: CH2 keeps CH1's PSK (a hash-compatible HRR suite) with only the obfuscated
 * age recomputed - even with the largest cookie and a P-256 share, and even when the ticket
 * expired in between. A ticket so large that the worst CH2 would not fit is kept out of CH1. */
static void conn_hrr_psk(void)
{
    const struct tls13_flow_kat *k = &CONN_KAT[0];
    static uint8_t ticket[2048], blob[BRISK_TICKET_MAX];
    const size_t L = strlen(k->ch1) / 2, TMAX = 2048 - 295 - 53 - L; /* CH1 + PSK = L+T+53 */
    const size_t T[4] = {100, 100, TMAX, TMAX + 1};
    const uint8_t *e;
    brisk__tls13_ticket t;
    brisk_cfg cfg;
    size_t i, n, blob_len, el;
    uint32_t age1 = 0;
    int64_t now = now_of(k);

    for (i = 0; i < 4; i++) {
        arena_used = 0;
        memset(&t, 0, sizeof t);
        memset(ticket, 0x5A, sizeof ticket);
        t.lifetime = 3600;
        t.age_add = 1;
        t.ticket = ticket;
        t.ticket_len = T[i];
        t.psk_len = 32;
        t.suite = 0x1301;
        memset(t.psk, 7, 32);
        CHECKI(brisk__tls13_ticket_export(&t, now - 1000, k->host, strlen(k->host), blob,
                                          sizeof blob, &blob_len) == BRISK_OK,
               i);
        cfg = cfg_of(k);
        cfg.ticket = blob;
        cfg.ticket_len = blob_len;
        CHECKI(setup(k, 0, &cfg, now) == BRISK_OK, i);
        n = brisk_pull(C, wire, sizeof wire);
        e = ch_ext(wire, n, 41, &el);
        if (i == 3) {
            CHECKI(e == NULL && n == 5 + L, i); /* the worst CH2 would not fit: not offered */
            brisk_conn_wipe(C);
            continue;
        }
        CHECKI(e != NULL && n == 5 + L + T[i] + 53, i);
        age1 = brisk__load_be32(e + 4 + T[i]);
        if (i == 1) { /* the ticket's lifetime runs out between CH1 and CH2 */
            brisk__conn_set_time(C, now + 3600 * 1000);
        }
        n = big_hrr(srv);
        CHECKI(brisk_feed(C, srv, n, &n) == BRISK_OK && brisk_status(C) == BRISK_E_WANT, i);
        n = brisk_pull(C, wire, sizeof wire);
        CHECKI(n == 5 + L + T[i] + 53 + 262 + 33 && ch_ext(wire, n, 45, &el) != NULL, i);
        e = ch_ext(wire, n, 41, &el);
        CHECKI(e != NULL && brisk__load_be32(e + 4 + T[i]) - age1 == (i == 1 ? 3600000u : 0u), i);
        brisk_conn_wipe(C);
    }
}

static void conn_alpn(void)
{
    static char name256[300], big[400];
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    static const char *const BAD[5] = {"", ",", "a,,b", "a,", ",a"};
    brisk_cfg cfg;
    uint8_t out[BRISK__TLS13_ALPN_MAX];
    size_t i, n;
    const char *name;

    CHECK(brisk__alpn_encode("mqtt,h2", out, sizeof out, &n) == BRISK_OK && n == 8 &&
          memcmp(out, "\x04mqtt\x02h2", 8) == 0);
    CHECK(brisk__alpn_encode(NULL, out, sizeof out, &n) == BRISK_OK && n == 0);
    memset(name256, 'a', 255);
    CHECK(brisk__alpn_encode(name256, out, sizeof out, &n) == BRISK_OK && n == 256);
    name256[255] = 'a'; /* a 256-byte name */
    CHECK(brisk__alpn_encode(name256, out, sizeof out, &n) == BRISK_E_ARG && n == 0);
    memset(big, 'b', 302);
    big[100] = ',';
    big[201] = ','; /* three 100-byte names: 303 bytes encoded, over the 256 cap */
    CHECK(brisk__alpn_encode(big, out, sizeof out, &n) == BRISK_E_ARG);
    for (i = 0; i < 7; i++) {
        arena_used = 0;
        cfg = cfg_of(k);
        cfg.alpn = i < 5 ? BAD[i] : i == 5 ? name256 : big;
        CHECKI(setup(k, 0, &cfg, now_of(k)) == BRISK_E_ARG && C == NULL, i);
        CHECKI(all_zero(g_mem, g_size + 8), i);
    }
    /* none asked, none answered; asked and answered (the ALPN row in conn_suites) */
    arena_used = 0;
    cfg = cfg_of(k);
    CHECK(setup(k, 0, &cfg, now_of(k)) == BRISK_OK);
    CHECK(brisk_alpn(C, &name, &n) == BRISK_E_ARG); /* before CONNECTED */
    brisk_conn_wipe(C);
    arena_used = 0;
    cfg = cfg_of(k);
    CHECK(connect_p256(&cfg) == 0 && brisk_alpn(C, &name, &n) == BRISK_OK && n == 0);
    brisk_conn_wipe(C);
}

#    if BRISK_ENABLE_MTLS
static int sign_calls;
static int dev_sign(void *ctx, uint16_t scheme, const uint8_t *tbs, size_t tbs_len, uint8_t *sig,
                    size_t sig_cap, size_t *sig_len)
{
    const struct tls13_flow_kat *r = &CONN_KAT[4];
    uint8_t h[32], key[32], srand[32];
    size_t n;
    int rc;
    (void)ctx;
    sign_calls++;
    if (scheme != 0x0403 || sig_cap < 64) {
        return BRISK_E_ARG;
    }
    /* what a secure element holding the device key would do; the same hedge input as the
     * library's own signer so the CertificateVerify matches the row byte for byte */
    t_unhex(r->ckey, key, 32);
    t_unhex(r->srand, srand, 32);
    brisk_sha256(tbs, tbs_len, h);
    rc = brisk__p256_ecdsa_sign(sig, key, h, 32, srand, 32);
    brisk__secure_zero(key, sizeof key);
    *sig_len = 64;
    n = rc == BRISK_OK ? 0 : 1;
    return n == 0 ? BRISK_OK : BRISK_E_AUTH;
}
#    endif

static void conn_mtls(void)
{
#    if BRISK_ENABLE_MTLS
    const struct tls13_flow_kat *r = &CONN_KAT[4];
    brisk_cfg cfg;
    size_t n;
    int i;
    for (i = 0; i < 2; i++) {
        arena_used = 0;
        cfg = cfg_of(r);
        cfg.client_chain = dec(r->cchain, &cfg.client_chain_len);
        if (i == 0) {
            cfg.client_key = dec(r->ckey, &n);
        } else {
            cfg.sign = dev_sign;
        }
        sign_calls = 0;
        /* the CertificateVerify is signed with sign_rand = the rnd slice (RFC 6979 3.6), and
         * happy() checks the whole memory is zero after brisk_conn_wipe */
        CHECKI(happy(r, (size_t)i, 1 << 20, &cfg) == 0 && sign_calls == i, i);
    }
#    else
    (void)dec;
#    endif
}
#endif /* BRISK_ENABLE_P384 */

static int no_sign(void *ctx, uint16_t scheme, const uint8_t *tbs, size_t tbs_len, uint8_t *sig,
                   size_t sig_cap, size_t *sig_len)
{
    (void)ctx;
    (void)scheme;
    (void)tbs;
    (void)tbs_len;
    (void)sig;
    (void)sig_cap;
    (void)sig_len;
    return BRISK_E_ARG;
}

static void conn_args(void)
{
    static char h256[257];
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    static const char *const HOSTS[5] = {"", "a b",
                                         "a\x01"
                                         "b",
                                         ".", "*.example.com"};
    static const uint8_t KEY[32] = {1};
    brisk_cfg cfg = BRISK_DEFAULTS, z = BRISK_DEFAULTS;
    size_t i, used, n;
    uint8_t b[8];
    const char *name;

    arena_used = 0;
    memset(g_mem, 0, g_size + 8);
    C = (brisk_conn *)g_mem;
    CHECK(brisk__conn_setup(NULL, g_size, &z, HOST, 0, RND, NULL, &C) == BRISK_E_ARG && C == NULL);
    CHECK(brisk__conn_setup(g_mem, g_size, NULL, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
    CHECK(brisk__conn_setup(g_mem, g_size, &z, NULL, 0, RND, NULL, &C) == BRISK_E_ARG);
    CHECK(brisk__conn_setup(g_mem, g_size, &z, HOST, 0, NULL, NULL, &C) == BRISK_E_ARG);
    CHECK(brisk__conn_setup(g_mem, g_size, &z, HOST, 0, RND, NULL, NULL) == BRISK_E_ARG);
    CHECK(brisk__conn_setup(g_mem, g_size - 1, &z, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
    CHECK(all_zero(g_mem, g_size + 8));
    memset(h256, 'a', 256);
    CHECK(brisk__conn_setup(g_mem, g_size, &z, h256, 0, RND, NULL, &C) == BRISK_E_ARG);
    h256[255] = '\0'; /* 255 bytes, but a 255-byte label is no host name (63 max) */
    CHECK(brisk__conn_setup(g_mem, g_size, &z, h256, 0, RND, NULL, &C) == BRISK_E_ARG);
    for (i = 0; i < 5; i++) {
        CHECKI(brisk__conn_setup(g_mem, g_size, &z, HOSTS[i], 0, RND, NULL, &C) == BRISK_E_ARG &&
                   C == NULL && all_zero(g_mem, g_size + 8),
               i);
    }
    /* configuration bugs: half-set buffers, client_key AND sign, a key without a chain */
    cfg.ca_mem = b;
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
    cfg = z;
    cfg.client_chain_len = 5;
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
    cfg = z;
    cfg.client_key = KEY;
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
    cfg = z;
    cfg.client_chain = dec(CONN_KAT[4].cchain, &cfg.client_chain_len);
    cfg.client_key = dec(CONN_KAT[4].ckey, &n);
#if BRISK_ENABLE_MTLS
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, 0, RND, NULL, &C) == BRISK_OK);
    brisk_conn_wipe(C);
#endif
    cfg.sign = no_sign; /* client_key AND a callback */
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
    cfg.sign = NULL;
#if !BRISK_ENABLE_MTLS
    /* a build without mTLS refuses any client certificate */
    CHECK(brisk__conn_setup(g_mem, g_size, &cfg, HOST, 0, RND, NULL, &C) == BRISK_E_ARG);
#endif
    CHECK(all_zero(g_mem, g_size + 8));
    /* the zero config is valid, an IP literal host too (no SNI, RFC 6066 3) */
    CHECK(brisk__conn_setup(g_mem + 1, g_size, &z, HOST, 0, RND, NULL, &C) == BRISK_OK);
    CHECK(brisk_status(C) == BRISK_E_WANT && brisk_alert(C) == 0 && brisk_resumed(C) == 0);
    CHECK(brisk_app_read(C, b, sizeof b, &used) == BRISK_E_WANT && used == 0);
    /* no close_notify mid-handshake: status must not turn OK without a client Finished */
    CHECK(brisk_close_notify(C) == BRISK_E_ARG && brisk_status(C) == BRISK_E_WANT);
    CHECK(brisk_app_write(C, b, 1, &used, wire, sizeof wire, &n) == BRISK_E_ARG);
    CHECK(brisk_alpn(C, &name, &n) == BRISK_E_ARG && name == NULL && n == 0);
    brisk_conn_wipe(C);
    CHECK(brisk__conn_setup(g_mem, g_size, &z, "192.0.2.1", 0, RND, NULL, &C) == BRISK_OK);
    brisk_conn_wipe(C);
    /* NULL-safety of every public call */
    CHECK(brisk_feed(NULL, b, 1, &used) == BRISK_E_ARG && brisk_pull(NULL, b, 8) == 0);
    CHECK(brisk_status(NULL) == BRISK_E_ARG && brisk_alert(NULL) == 0 && brisk_resumed(NULL) == 0);
    CHECK(brisk_app_read(NULL, b, 8, &used) == BRISK_E_ARG);
    CHECK(brisk_app_write(NULL, b, 1, &used, wire, 8, &n) == BRISK_E_ARG && used == 0 && n == 0);
    CHECK(brisk_close_notify(NULL) == BRISK_E_ARG && brisk_alpn(NULL, &name, &n) == BRISK_E_ARG);
    brisk_conn_wipe(NULL);
    (void)k;
}

/* Shared with test_sock.c: the P-256 fixture as a server byte stream. */
const uint8_t *t_conn_rnd(void)
{
    return RND;
}

size_t t_conn_server(uint8_t *out, t_conn_fixture *f)
{
    const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
    size_t n;
    arena_used = 0;
    t_unhex(TLS13_CONN_RND, RND, sizeof RND); /* the sock suite runs on its own too */
    f->root = dec(k->root, &f->root_len);
    f->host = k->host;
    f->now_ms = now_of(k);
    f->c_ap = k->c_ap;
    f->s_ap = k->s_ap;
    f->ch_len = 5 + strlen(k->ch1) / 2;
    f->flight_len = 6 + 5 + strlen(k->cf) / 2 + 1 + 16;
    n = flight(k, srv);
    memcpy(out, srv, n);
    return n;
}

void test_conn(void)
{
    size_t n;
    (void)TLS13_RFC_KAT;
#if BRISK_ENABLE_TLS12
    (void)TLS13_CONN13_KAT;
#else
    (void)TLS13_CONNFX_KAT;
    (void)TLS13_CONN_KAT;
#endif
    (void)TLS13_CHW_KAT;
    (void)TLS13_MTLS_KAT;
    (void)TLS13_DER_KAT;
    (void)TLS13_REC_KAT;
    (void)TLS13_NONCE_KAT;
    (void)TLS13_CONN_NOW_MS;
    t_unhex(TLS13_CONN_RND, RND, sizeof RND);
    g_size = brisk_conn_size();
    g_mem = (uint8_t *)malloc(g_size + 8);
    if (g_mem == NULL) {
        exit(2);
    }
    /* the fixture rows and TLS13_CONN_RND agree on random / session id / x25519 d */
    arena_used = 0;
    {
        const struct tls13_flow_kat *k = row("fixture: P-256 leaf");
        const uint8_t *ch = dec(k->ch1, &n), *priv = dec(k->priv1, &n);
        CHECK(memcmp(RND, ch + 6, 32) == 0 && memcmp(RND + 32, ch + 39, 32) == 0 &&
              memcmp(RND + 64, priv, 32) == 0 && TLS13_CONN_NOW_MS == now_of(k));
    }
    conn_args();
#if BRISK_ENABLE_P384
    conn_full();
    conn_trust();
    conn_suites();
    conn_negative_rows();
    conn_pull_cap();
    conn_closure_early();
    conn_hrr();
    conn_ticket();
    conn_psk_in();
    conn_hrr_psk();
    conn_alpn();
    conn_mtls();
    conn_split();
#endif
    free(g_mem);
    g_mem = NULL;
}
