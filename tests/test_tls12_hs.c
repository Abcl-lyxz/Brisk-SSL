/* test_tls12_hs.c - TLS 1.2 through the public connection (M5): brisk__conn_setup, then only
 * brisk_feed / brisk_pull / brisk_status / brisk_app_* / brisk_alert / brisk_alpn /
 * brisk_tls_version. Every row of tests/kat/tls12_conn.inc starts from the library's default
 * ClientHello (TLS 1.3 + 1.2 in one), which must come out byte for byte from the 160 bytes of
 * TLS12_CONN_RND; the server flight is fed coalesced, one message per record and byte by byte;
 * the client flight ([Certificate] CKE [CV], CCS, Finished) is compared byte for byte; negative
 * rows must end in exactly their alert. Record-layer rules the rows cannot express (the CCS gate,
 * HelloRequest after the handshake, app data before the Finished, the record cap) are checked
 * here directly, on the first row. The server side is sealed with brisk__tls12_dir_init +
 * brisk__tls_rec_seal, pinned by test_tls12_rec.c against tools/kat.py.
 *
 * MUTATION MAP (each guard disabled, its row fails; checked 2026-09-24): tls12.c - EMS /
 * renegotiation_info required ("no extended_main_secret", "no renegotiation_info"), the
 * renegotiated_connection length ("not empty"), the session_id echo, is_hrr/hrr_seen ("HRR
 * random"), curve_type, the uncompressed-point test ("hybrid point is refused before the (bad)
 * signature"), ec_point_formats, duplicate extensions, "not offered" ("ALPN answered although
 * none was offered"), the leaf key type ("RSA leaf on ECDHE_ECDSA"), the ServerHelloDone
 * length, the Finished ct_memeq ("verify_data flipped"), the CCS state/fragment gate
 * (ccs_gate); record.c - the CCS body test, app data before the Finished, the one-shot
 * HelloRequest answer (post_handshake), the 6.2.3 length bound and the header-version AAD
 * (test_tls12_rec.c); handshake.c - th256 kept under 1.2 ("mTLS on a SHA-384 suite"); hkdf.c -
 * the A(i) chain (test_tls12_prf.c). One guard is redundant by construction and survives: the
 * SKE "scheme offered" test, because every scheme sig12_scheme accepts is in the default offer
 * (it would bite only for a caller-built ClientHello with a shorter list). */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct tls12_flow_kat {
    const char *note;
    int alert, fail_at, flags;
    const char *ch, *s1, *c1, *cfin, *sfin;
    unsigned suite;
    const char *ckey, *civ, *skey, *siv, *alpn, *sel;
    int mtls;
};
#include "kat/tls12_conn.inc"
#include "kat/mtls_key.inc"

#define NROW   (sizeof TLS12_FLOW_KAT / sizeof TLS12_FLOW_KAT[0])
#define HOST   "device.example.com"
#define F_TIME 1 /* kat.py TLS13_F_TIME */

static uint8_t RND[BRISK__CONN_RAND];
static uint8_t *g_mem;
static size_t g_size;
static brisk_conn *C;
static uint8_t root[2048], chain[4096], dkey[32];
static size_t root_len, chain_len;

#if !BRISK_ENABLE_TLS12 || BRISK_ENABLE_P384 /* the flow rows need a P-384 root */
static uint8_t wire[1 << 15], srv[1 << 15], hx[1 << 15];

typedef struct {
    uint8_t ch[1024], s1[1 << 13], c1[1 << 13], cfin[16], sfin[32];
    size_t ch_len, s1_len, c1_len, cfin_len, sfin_len;
    uint8_t ck[32], ci[12], sk[32], si[12];
    size_t kl, il;
} row;
static row R;

static void load(const struct tls12_flow_kat *k)
{
    R.ch_len = t_unhex(k->ch, R.ch, sizeof R.ch);
    R.s1_len = t_unhex(k->s1, R.s1, sizeof R.s1);
    R.c1_len = t_unhex(k->c1, R.c1, sizeof R.c1);
    R.cfin_len = t_unhex(k->cfin, R.cfin, sizeof R.cfin);
    R.sfin_len = t_unhex(k->sfin, R.sfin, sizeof R.sfin);
    R.kl = t_unhex(k->ckey, R.ck, sizeof R.ck);
    R.il = t_unhex(k->civ, R.ci, sizeof R.ci);
    t_unhex(k->skey, R.sk, sizeof R.sk);
    t_unhex(k->siv, R.si, sizeof R.si);
}

static int setup(const struct tls12_flow_kat *k, size_t off, brisk_sign_fn sign)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    cfg.ca_mem = root;
    cfg.ca_mem_len = root_len;
    cfg.alpn = *k->alpn ? k->alpn : NULL;
    if (k->mtls) {
        cfg.client_chain = chain;
        cfg.client_chain_len = chain_len;
        if (sign != NULL) {
            cfg.sign = sign;
        } else {
            cfg.client_key = dkey;
        }
    }
    memset(g_mem, 0, g_size + 8);
    return brisk__conn_setup(g_mem + off, g_size, &cfg, HOST, TLS12_CONN_NOW_MS, RND, NULL, &C);
}

static size_t plain(uint8_t *out, uint8_t type, const uint8_t *m, size_t n)
{
    out[0] = type;
    out[1] = 3;
    out[2] = 3;
    brisk__store_be16(out + 3, (uint32_t)n);
    memmove(out + 5, m, n);
    return 5 + n;
}

#endif

#if BRISK_ENABLE_TLS12 && BRISK_ENABLE_P384
/* Feed n bytes in chunks of at most `chunk`. */
static int feed(const uint8_t *p, size_t n, size_t chunk)
{
    size_t k, used;
    int rc;
    while (n != 0) {
        k = n < chunk ? n : chunk;
        rc = brisk_feed(C, p, k, &used);
        if (rc != BRISK_OK) {
            return rc;
        }
        if (used == 0) {
            return 97;
        }
        p += used;
        n -= used;
    }
    return BRISK_OK;
}

/* The server's first flight in `mode`: 0 one record, 1 one record per message, 2 one record
 * fed byte by byte. */
static int feed_s1(const uint8_t *s1, size_t n, int mode)
{
    size_t off = 0, m, w = 0;
    if (mode == 1) {
        while (off < n) {
            m = 4 + brisk__load_be24(s1 + off + 1);
            w += plain(srv + w, BRISK__CT_HANDSHAKE, s1 + off, m);
            off += m;
        }
        return feed(srv, w, 1 << 20);
    }
    w = plain(srv, BRISK__CT_HANDSHAKE, s1, n);
    return feed(srv, w, mode == 2 ? 1 : 1 << 20);
}

static int err_of(int alert)
{
    return alert == 42 || alert == 43 || alert == 48 || alert == 51 ? BRISK_E_AUTH
           : alert == 80                                            ? BRISK_E_ARG
                                                                    : BRISK_E_PROTO;
}

/* 1.2 directions from the row's key block */
static void dirs(brisk__tls_dir *cw, brisk__tls_dir *sw, unsigned suite)
{
    CHECK(brisk__tls12_dir_init(cw, (uint16_t)suite, R.ck, R.kl, R.ci, R.il) == BRISK_OK);
    CHECK(brisk__tls12_dir_init(sw, (uint16_t)suite, R.sk, R.kl, R.si, R.il) == BRISK_OK);
}

/* One record the client sealed under d: type and content must be as given. */
static int client_rec(brisk__tls_dir *d, const uint8_t *w, size_t n, uint8_t type, const void *want,
                      size_t want_len)
{
    uint8_t t, alert;
    size_t len;
    memcpy(hx, w, n);
    return n >= 5 && brisk__load_be16(hx + 3) == n - 5 &&
           brisk__tls_rec_open(d, hx, n, &t, &len, &alert) == BRISK_OK && t == type &&
           len == want_len && memcmp(hx + 5, want, want_len) == 0;
}

/* The single fatal alert, in the clear (before our keys) or under d, then silence. */
static int fatal_is(brisk__tls_dir *d, int desc)
{
    const uint8_t a[2] = {2, (uint8_t)desc};
    size_t n = brisk_pull(C, wire, sizeof wire);
    int ok = d != NULL ? client_rec(d, wire, n, BRISK__CT_ALERT, a, 2)
                       : n == 7 && wire[0] == 21 && wire[5] == 2 && wire[6] == desc;
    return ok && brisk_pull(C, wire, sizeof wire) == 0 && brisk_alert(C) == desc;
}

/* Up to the client flight: CH pulled and checked, s1 fed, the flight pulled and checked. 0 or
 * the failing step. */
static int to_flight(const struct tls12_flow_kat *k, size_t off, int mode, brisk__tls_dir *cw)
{
    size_t n, i = 0, rl;
    if (setup(k, off, NULL) != BRISK_OK) {
        return 1;
    }
    n = brisk_pull(C, wire, sizeof wire);
    if (n != 5 + R.ch_len || wire[0] != 22 || brisk__load_be16(wire + 1) != 0x0301 ||
        memcmp(wire + 5, R.ch, R.ch_len) != 0) {
        return 2; /* RFC 9846 4.3.1 / 5.1: the combined ClientHello, byte for byte */
    }
    if (feed_s1(R.s1, R.s1_len, mode) != BRISK_OK || brisk_status(C) != BRISK_E_WANT) {
        return 3;
    }
    n = brisk_pull(C, wire, sizeof wire);
    /* plaintext [Certificate] CKE [CV] (version 0x0303), the mandatory CCS, the Finished */
    rl = brisk__load_be16(wire + 3);
    if (n < 5 || wire[0] != 22 || brisk__load_be16(wire + 1) != 0x0303 || rl != R.c1_len ||
        memcmp(wire + 5, R.c1, R.c1_len) != 0) {
        return 4;
    }
    i = 5 + rl;
    if (n - i < 6 || memcmp(wire + i, "\x14\x03\x03\x00\x01\x01", 6) != 0) {
        return 5;
    }
    i += 6;
    if (!client_rec(cw, wire + i, n - i, BRISK__CT_HANDSHAKE, R.cfin, R.cfin_len)) {
        return 6;
    }
    return brisk_pull(C, wire, sizeof wire) == 0 ? 0 : 7;
}

/* CCS + the server Finished sealed under sw, in one feed. */
static size_t ccs_fin(brisk__tls_dir *sw, uint8_t *out)
{
    size_t n = plain(out, BRISK__CT_CCS, (const uint8_t *)"\x01", 1), k = 0;
    CHECK(brisk__tls_rec_seal(sw, BRISK__CT_HANDSHAKE, 0x0303, R.sfin, R.sfin_len, 0, out + n,
                              sizeof srv - n, &k) == BRISK_OK);
    return n + k;
}

static int happy(const struct tls12_flow_kat *k, size_t off, int mode)
{
    static const uint8_t PING[4] = {'p', 'i', 'n', 'g'}, PONG[5] = {'p', 'o', 'n', 'g', '!'},
                         CN[2] = {1, 0};
    brisk__tls_dir cw, sw;
    size_t n, used, out_len;
    const char *name;
    int step;
    uint8_t got[8];

    dirs(&cw, &sw, k->suite);
    step = to_flight(k, off, mode, &cw);
    if (step == 0) {
        n = ccs_fin(&sw, srv);
        if (feed(srv, n, mode == 2 ? 1 : 1 << 20) != BRISK_OK || brisk_status(C) != BRISK_OK) {
            step = 10;
        }
    }
    if (step == 0 && (brisk_tls_version(C) != 0x0303 || brisk_resumed(C) != 0 ||
                      brisk_alpn(C, &name, &n) != BRISK_OK || n != strlen(k->sel) ||
                      (n != 0 && memcmp(name, k->sel, n) != 0))) {
        step = 11;
    }
    if (step == 0 &&
        (brisk_app_write(C, PING, 4, &used, wire + 1, sizeof wire - 1, &out_len) != BRISK_OK ||
         used != 4 || !client_rec(&cw, wire + 1, out_len, BRISK__CT_APP, PING, 4))) {
        step = 12;
    }
    if (step == 0) {
        CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_APP, 0x0303, PONG, 5, 0, srv + 3, sizeof srv - 3,
                                  &n) == BRISK_OK);
        if (feed(srv + 3, n, mode == 2 ? 1 : 1 << 20) != BRISK_OK ||
            brisk_app_read(C, got, sizeof got, &used) != BRISK_OK || used != 5 ||
            memcmp(got, PONG, 5) != 0) {
            step = 13;
        }
    }
    if (step == 0 &&
        (brisk_close_notify(C) != BRISK_OK ||
         !client_rec(&cw, wire, brisk_pull(C, wire, sizeof wire), BRISK__CT_ALERT, CN, 2))) {
        step = 14;
    }
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);
    brisk_conn_wipe(C);
    if (step == 0) {
        for (n = 0; n < g_size + 8 && g_mem[n] == 0; n++) {
        }
        step = n == g_size + 8 ? 0 : 15;
    }
    return step;
}

static void rows(void)
{
    brisk__tls_dir cw, sw;
    size_t i, n, used;
    int mode, want;

    for (i = 0; i < NROW; i++) {
        const struct tls12_flow_kat *k = &TLS12_FLOW_KAT[i];
#    if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
        if (k->flags & F_TIME) {
            continue;
        }
#    endif
#    if !BRISK_ENABLE_MTLS
        if (k->mtls && strstr(k->note, "mTLS") != NULL) {
            continue; /* no device chain in this build */
        }
#    endif
        load(k);
        if (k->alert == 0) {
            for (mode = 0; mode < 3; mode++) {
                CHECKI(happy(k, (i + (size_t)mode) & 7, mode) == 0, i * 10 + (size_t)mode);
            }
#    if BRISK_ENABLE_MTLS
            if (k->mtls) { /* M9: the same Certificate message out of a PEM client_chain */
                chain_len = t_unhex(KEY_MTLS_CHAIN[1].chain, chain, sizeof chain);
                CHECKI(happy(k, i & 7, 0) == 0, i);
                chain_len = t_unhex(TLS12_CONN_CCHAIN, chain, sizeof chain);
            }
#    endif
            continue;
        }
        want = err_of(k->alert);
        /* brisk.h BRISK_E_INSECURE: a server below the floor, not a broken one */
        if (strstr(k->note, "no extended_main_secret") != NULL ||
            strstr(k->note, "no renegotiation_info") != NULL ||
            strstr(k->note, "legacy_version 0300") != NULL ||
            strstr(k->note, "legacy_version 0301") != NULL ||
            strstr(k->note, "legacy_version 0302") != NULL) {
            want = BRISK_E_INSECURE;
        }
        if (k->fail_at == 2) { /* the server Finished */
            dirs(&cw, &sw, k->suite);
            CHECKI(to_flight(k, i & 7, 0, &cw) == 0, i);
            n = ccs_fin(&sw, srv);
            CHECKI(brisk_feed(C, srv, n, &used) == want && brisk_status(C) == want, i);
            CHECKI(fatal_is(&cw, k->alert), i);
            brisk__tls_dir_wipe(&cw);
            brisk__tls_dir_wipe(&sw);
            brisk_conn_wipe(C);
            continue;
        }
        for (mode = 0; mode < 2; mode++) {
            CHECKI(setup(k, i & 7, NULL) == BRISK_OK, i);
            n = brisk_pull(C, wire, sizeof wire);
            CHECKI(n == 5 + R.ch_len && memcmp(wire + 5, R.ch, R.ch_len) == 0, i);
            CHECKI(feed_s1(R.s1, R.s1_len, mode) == want, i * 10 + (size_t)mode);
            /* sticky, and exactly one fatal alert in the clear (no keys yet) */
            CHECKI(brisk_feed(C, srv, 1, &used) == want && brisk_status(C) == want, i);
            CHECKI(fatal_is(NULL, k->alert), i * 10 + (size_t)mode);
            brisk_conn_wipe(C);
        }
    }
}

/* ---------------------------------------------------------------- the record-layer rules ---- */

/* The base row (ECDHE-ECDSA-AES128-GCM, x25519) up to the client flight, keys in cw / sw. */
static void base(brisk__tls_dir *cw, brisk__tls_dir *sw)
{
    load(&TLS12_FLOW_KAT[0]);
    dirs(cw, sw, TLS12_FLOW_KAT[0].suite);
    CHECK(to_flight(&TLS12_FLOW_KAT[0], 1, 0, cw) == 0);
}

static int fails_with(const uint8_t *in, size_t n, int alert)
{
    size_t used;
    return brisk_feed(C, in, n, &used) == err_of(alert) && brisk_alert(C) == alert;
}

static void ccs_gate(void)
{
    const struct tls12_flow_kat *k = &TLS12_FLOW_KAT[0];
    static const uint8_t CCS2[6] = {20, 3, 3, 0, 1, 2}, CCSL[7] = {20, 3, 3, 0, 2, 1, 1},
                         CCS[6] = {20, 3, 3, 0, 1, 1};
    brisk__tls_dir cw, sw;
    size_t n, m;
    int i;

    load(k);
    /* a CCS right after the ServerHello (an abbreviated handshake) and one before the
     * ServerHelloDone - the CVE-2014-0224 shape: keys would be installed before the main
     * secret exists */
    for (i = 0; i < 2; i++) {
        CHECKI(setup(k, 0, NULL) == BRISK_OK && brisk_pull(C, wire, sizeof wire) != 0, i);
        m = i == 0 ? 4 + brisk__load_be24(R.s1 + 1) : R.s1_len - 4; /* SH / all but SHD */
        n = plain(srv, BRISK__CT_HANDSHAKE, R.s1, m);
        memcpy(srv + n, CCS, sizeof CCS);
        CHECKI(fails_with(srv, n + sizeof CCS, 10) && fatal_is(NULL, 10), i);
        brisk_conn_wipe(C);
    }
    /* after our Finished: a CCS with body {2}, of 2 bytes, or while a handshake fragment is
     * pending; two CCS; a Finished without CCS; app data between CCS and Finished */
    for (i = 0; i < 6; i++) {
        base(&cw, &sw);
        switch (i) {
        case 0:
            memcpy(srv, CCS2, sizeof CCS2);
            n = sizeof CCS2;
            break;
        case 1:
            memcpy(srv, CCSL, sizeof CCSL);
            n = sizeof CCSL;
            break;
        case 2: /* two bytes of a handshake header, then the CCS */
            n = plain(srv, BRISK__CT_HANDSHAKE, R.sfin, 2);
            memcpy(srv + n, CCS, sizeof CCS);
            n += sizeof CCS;
            break;
        case 3:
            n = ccs_fin(&sw, srv);
            memmove(srv + 6, srv, n);
            memcpy(srv, CCS, sizeof CCS);
            n += 6;
            break;
        case 4:
            n = plain(srv, BRISK__CT_HANDSHAKE, R.sfin, R.sfin_len);
            break;
        default:
            memcpy(srv, CCS, sizeof CCS);
            CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_APP, 0x0303, (const uint8_t *)"x", 1, 0,
                                      srv + 6, sizeof srv - 6, &n) == BRISK_OK);
            n += 6;
            break;
        }
        CHECKI(fails_with(srv, n, 10), i);
        brisk_conn_wipe(C);
        brisk__tls_dir_wipe(&cw);
        brisk__tls_dir_wipe(&sw);
    }
}

/* After CONNECTED on the base row. */
static void connected(brisk__tls_dir *cw, brisk__tls_dir *sw)
{
    size_t n;
    base(cw, sw);
    n = ccs_fin(sw, srv);
    CHECK(feed(srv, n, 1 << 20) == BRISK_OK && brisk_status(C) == BRISK_OK);
}

static void post_handshake(void)
{
    static const uint8_t HR[4] = {0, 0, 0, 0}, NR[2] = {1, 100}, W112[2] = {1, 112},
                         NST[10] = {4, 0, 0, 6, 0, 0, 0, 1, 0, 0};
    brisk__tls_dir cw, sw;
    size_t n, used, out_len;
    uint8_t got[4];

    /* RFC 5746 4.2: the first HelloRequest gets one warning no_renegotiation, the second none,
     * and the connection goes on */
    connected(&cw, &sw);
    CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_HANDSHAKE, 0x0303, HR, 4, 0, srv, sizeof srv, &n) ==
          BRISK_OK);
    CHECK(feed(srv, n, 1 << 20) == BRISK_OK && brisk_status(C) == BRISK_OK);
    CHECK(client_rec(&cw, wire, brisk_pull(C, wire, sizeof wire), BRISK__CT_ALERT, NR, 2));
    CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_HANDSHAKE, 0x0303, HR, 4, 0, srv, sizeof srv, &n) ==
          BRISK_OK);
    CHECK(feed(srv, n, 1 << 20) == BRISK_OK && brisk_pull(C, wire, sizeof wire) == 0);
    CHECK(brisk_app_write(C, "ok", 2, &used, wire, sizeof wire, &out_len) == BRISK_OK &&
          client_rec(&cw, wire, out_len, BRISK__CT_APP, "ok", 2));
    CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_APP, 0x0303, (const uint8_t *)"yes", 3, 0, srv,
                              sizeof srv, &n) == BRISK_OK);
    CHECK(feed(srv, n, 1 << 20) == BRISK_OK && brisk_app_read(C, got, 4, &used) == BRISK_OK &&
          used == 3);
    brisk_conn_wipe(C);
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);

    /* any other post-handshake handshake message (a NewSessionTicket) is unexpected_message */
    connected(&cw, &sw);
    CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_HANDSHAKE, 0x0303, NST, sizeof NST, 0, srv, sizeof srv,
                              &n) == BRISK_OK);
    CHECK(fails_with(srv, n, 10) && fatal_is(&cw, 10));
    brisk_conn_wipe(C);
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);

    /* RFC 5246 7.2 kept fail closed: a warning other than close_notify / user_canceled ends
     * the connection (BRISK_E_PEER_ALERT), and nothing is sent back */
    connected(&cw, &sw);
    CHECK(brisk__tls_rec_seal(&sw, BRISK__CT_ALERT, 0x0303, W112, 2, 0, srv, sizeof srv, &n) ==
          BRISK_OK);
    CHECK(brisk_feed(C, srv, n, &used) == BRISK_E_PEER_ALERT && brisk_alert(C) == 112 &&
          brisk_pull(C, wire, sizeof wire) == 0);
    brisk_conn_wipe(C);
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);

    /* RFC 9325 4.4 (local cap, no KeyUpdate in 1.2): at 2^24 records the write is refused and
     * close_notify goes out instead */
    connected(&cw, &sw);
    C->tc.wr.seq = (uint64_t)1 << 24;
    cw.seq = (uint64_t)1 << 24;
    CHECK(brisk_app_write(C, "x", 1, &used, wire, sizeof wire, &out_len) == BRISK_E_ARG &&
          used == 0 && client_rec(&cw, wire, out_len, BRISK__CT_ALERT, "\x01\x00", 2));
    brisk_conn_wipe(C);
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);
}

/* A HelloRetryRequest commits the server to TLS 1.3: a TLS 1.2 ServerHello after it is
 * illegal_parameter. A HelloRequest before the ServerHello is unexpected_message. */
static void hrr_then_12(void)
{
    static const uint8_t HR[4] = {0, 0, 0, 0};
    uint8_t h[4 + 84], *p = h;
    size_t n;
    load(&TLS12_FLOW_KAT[0]);
    CHECK(setup(&TLS12_FLOW_KAT[0], 0, NULL) == BRISK_OK && brisk_pull(C, wire, sizeof wire) != 0);
    p[0] = 2;
    brisk__store_be24(p + 1, 84);
    brisk__store_be16(p + 4, 0x0303);
    brisk_sha256("HelloRetryRequest", 17, p + 6); /* RFC 9846 4.2.3 */
    p[38] = 32;
    memcpy(p + 39, R.ch + 39, 32); /* echo the session id */
    brisk__store_be16(p + 71, 0x1301);
    p[73] = 0;
    memcpy(p + 74, "\x00\x0c\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x02\x00\x17", 14);
    n = plain(srv, BRISK__CT_HANDSHAKE, h, sizeof h);
    CHECK(feed(srv, n, 1 << 20) == BRISK_OK && brisk_pull(C, wire, sizeof wire) != 0);
    n = plain(srv, BRISK__CT_HANDSHAKE, R.s1, 4 + brisk__load_be24(R.s1 + 1));
    CHECK(fails_with(srv, n, 47));
    brisk_conn_wipe(C);

    CHECK(setup(&TLS12_FLOW_KAT[0], 0, NULL) == BRISK_OK && brisk_pull(C, wire, sizeof wire) != 0);
    n = plain(srv, BRISK__CT_HANDSHAKE, HR, 4);
    CHECK(fails_with(srv, n, 10) && fatal_is(NULL, 10));
    brisk_conn_wipe(C);
}

#    if BRISK_ENABLE_MTLS
static int sign_calls;
static int dev_sign(void *ctx, uint16_t scheme, const uint8_t *tbs, size_t tbs_len, uint8_t *sig,
                    size_t sig_cap, size_t *sig_len)
{
    (void)ctx;
    (void)scheme;
    (void)tbs;
    (void)tbs_len;
    (void)sig;
    (void)sig_cap;
    (void)sig_len;
    sign_calls++;
    return BRISK_E_ARG;
}

/* mTLS over TLS 1.2 with a sign callback: internal_error, never a silent empty Certificate */
static void mtls_sign_cb(void)
{
    size_t i, used;
    for (i = 0; i < NROW; i++) {
        const struct tls12_flow_kat *k = &TLS12_FLOW_KAT[i];
        if (k->mtls && k->alert == 0 && strstr(k->note, "mTLS on") != NULL) {
            load(k);
            sign_calls = 0;
            CHECK(setup(k, 0, dev_sign) == BRISK_OK && brisk_pull(C, wire, sizeof wire) != 0);
            used = plain(srv, BRISK__CT_HANDSHAKE, R.s1, R.s1_len);
            CHECK(fails_with(srv, used, 80) && sign_calls == 0 && fatal_is(NULL, 80));
            brisk_conn_wipe(C);
            return;
        }
    }
    CHECK(0);
}
#    endif

/* The constant-time run (test_ct -> `dev.py ct`): the ECDHE private keys, the device key and the
 * hedging input secret through a whole TLS 1.2 handshake - PRF, extended main secret, key block,
 * CertificateVerify, Finished compare, record seal / open - on an x25519 mTLS SHA-384 row and a
 * secp256r1 row. Everything the client puts on the wire is declassified before the test reads it.
 */
static void ct_flow(const struct tls12_flow_kat *k)
{
    brisk__tls_dir cw, sw;
    size_t n, used, out_len;
    load(k);
    t_unhex(TLS12_CONN_RND, RND, sizeof RND);
    BRISK__CT_SECRET(RND + 64, 96); /* x25519 d | P-256 d | sign_rand */
    /* before setup: the key is parsed and keygen'd there (M9), and only the resulting point is
     * declassified, so the copy the CertificateVerify signs with is secret all the way */
    BRISK__CT_SECRET(dkey, sizeof dkey);
    CHECK(setup(k, 0, NULL) == BRISK_OK);
    n = brisk_pull(C, wire, sizeof wire);
    BRISK__CT_PUBLIC(wire, n);
    CHECK(n == 5 + R.ch_len);
    CHECK(feed_s1(R.s1, R.s1_len, 0) == BRISK_OK);
    n = brisk_pull(C, wire, sizeof wire);
    BRISK__CT_PUBLIC(wire, n); /* CKE, CV, CCS, the sealed Finished */
    CHECK(n > R.c1_len && memcmp(wire + 5, R.c1, R.c1_len) == 0);
    dirs(&cw, &sw, k->suite);
    cw.seq = 1; /* seq 0 was our Finished */
    n = ccs_fin(&sw, srv);
    CHECK(feed(srv, n, 1 << 20) == BRISK_OK && brisk_status(C) == BRISK_OK);
    CHECK(brisk_app_write(C, "ct", 2, &used, wire, sizeof wire, &out_len) == BRISK_OK);
    BRISK__CT_PUBLIC(wire, out_len);
    CHECK(client_rec(&cw, wire, out_len, BRISK__CT_APP, "ct", 2));
    brisk_conn_wipe(C);
    brisk__tls_dir_wipe(&cw);
    brisk__tls_dir_wipe(&sw);
    BRISK__CT_PUBLIC(RND, sizeof RND);
    BRISK__CT_PUBLIC(dkey, sizeof dkey);
}

static void ct_rec_prf(void)
{
    uint8_t sec[48], kb[88], rec[64], type, alert;
    brisk__tls_dir w, r;
    size_t n, len;
    unsigned s;
    static const uint16_t SUITES[2] = {0xC02C, 0xCCA9};
    memset(sec, 0x5C, sizeof sec);
    BRISK__CT_SECRET(sec, sizeof sec);
    CHECK(brisk__tls12_prf(BRISK_HASH_SHA384, sec, 48, "key expansion", R.ck, 32, NULL, 0, kb,
                           sizeof kb) == BRISK_OK);
    for (s = 0; s < 2; s++) {
        size_t kl = 32, il = s == 0 ? 4 : 12;
        CHECK(brisk__tls12_dir_init(&w, SUITES[s], kb, kl, kb + 64, il) == BRISK_OK);
        CHECK(brisk__tls12_dir_init(&r, SUITES[s], kb, kl, kb + 64, il) == BRISK_OK);
        CHECK(brisk__tls_rec_seal(&w, 23, 0x0303, sec, 20, 0, rec, sizeof rec, &n) == BRISK_OK);
        BRISK__CT_PUBLIC(rec, n); /* the record goes on the wire */
        CHECK(brisk__tls_rec_open(&r, rec, n, &type, &len, &alert) == BRISK_OK && len == 20);
        rec[n - 1] ^= 1;
        r.seq = 0;
        CHECK(brisk__tls_rec_open(&r, rec, n, &type, &len, &alert) == BRISK_E_AUTH);
        brisk__tls_dir_wipe(&w);
        brisk__tls_dir_wipe(&r);
    }
    brisk__secure_zero(kb, sizeof kb);
}

void tls12_ct_run(void)
{
    size_t i;
    root_len = t_unhex(TLS12_CONN_ROOT, root, sizeof root);
    chain_len = t_unhex(TLS12_CONN_CCHAIN, chain, sizeof chain);
    t_unhex(TLS12_CONN_DKEY, dkey, sizeof dkey);
    g_size = brisk_conn_size();
    g_mem = (uint8_t *)malloc(g_size + 8);
    if (g_mem == NULL) {
        exit(2);
    }
    for (i = 0; i < NROW; i++) {
        const struct tls12_flow_kat *k = &TLS12_FLOW_KAT[i];
        if (k->alert == 0 && (strstr(k->note, "mTLS on a SHA-384") != NULL ||
                              strstr(k->note, "AES128-GCM-SHA256, secp256r1") != NULL ||
                              strstr(k->note, "rsa_pkcs1_sha512") != NULL)) {
#    if !BRISK_ENABLE_MTLS
            if (k->mtls) {
                continue;
            }
#    endif
            ct_flow(k);
        }
    }
    ct_rec_prf();
    free(g_mem);
    g_mem = NULL;
}
#else
void tls12_ct_run(void)
{
}
#endif /* BRISK_ENABLE_TLS12 && BRISK_ENABLE_P384 */

void test_tls12_hs(void)
{
    (void)KEY_MTLS;
    (void)KEY_MTLS_CHAIN;
    (void)KEY_MTLS_BIG_OK;
    (void)KEY_MTLS_BIG_OVER;
    t_unhex(TLS12_CONN_RND, RND, sizeof RND);
    root_len = t_unhex(TLS12_CONN_ROOT, root, sizeof root);
    chain_len = t_unhex(TLS12_CONN_CCHAIN, chain, sizeof chain);
    t_unhex(TLS12_CONN_DKEY, dkey, sizeof dkey);
    g_size = brisk_conn_size();
    g_mem = (uint8_t *)malloc(g_size + 8);
    if (g_mem == NULL) {
        exit(2);
    }
#if BRISK_ENABLE_TLS12 && BRISK_ENABLE_P384
    /* the default offer has ecdsa_secp384r1_sha384 only with P-384 (every DEFAULT build) */
    rows();
    ccs_gate();
    post_handshake();
    hrr_then_12();
#    if BRISK_ENABLE_MTLS
    mtls_sign_cb();
#    endif
#elif !BRISK_ENABLE_TLS12
    {
        /* a TLS 1.3-only build: the same TLS 1.2 ServerHello is protocol_version, after the
         * sentinel test (RFC 9846 4.2.3, E.1) */
        size_t n, used;
        (void)hx;
        load(&TLS12_FLOW_KAT[0]);
        CHECK(setup(&TLS12_FLOW_KAT[0], 0, NULL) == BRISK_OK);
        n = brisk_pull(C, wire, sizeof wire);
        CHECK(n != 0 && n != 5 + R.ch_len); /* no TLS 1.2 in the offer */
        n = plain(srv, BRISK__CT_HANDSHAKE, R.s1, 4 + brisk__load_be24(R.s1 + 1));
        CHECK(brisk_feed(C, srv, n, &used) == BRISK_E_PROTO && brisk_alert(C) == 70);
        brisk_conn_wipe(C);
    }
#else
    CHECK(1);
#endif
    free(g_mem);
    g_mem = NULL;
}
