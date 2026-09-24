/* test_quic.c - QUIC v1 (M6): varints, packet numbers, Initial secrets and keys, header parsing,
 * packet + header protection, transport parameters, frames, CRYPTO reassembly and whole client
 * handshakes replayed byte for byte (tests/kat/quic_*.inc, tools/kat.py). The connection scripts
 * in quic_conn.inc drive brisk__quic_send / brisk__quic_recv; see quic_conn_vectors() for the op
 * letters. The whole file sits inside #if BRISK_ENABLE_QUIC; other profiles run an empty suite.
 */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_QUIC

struct quic_varint_kat {
    const char *hex;
    uint64_t v;
    int minimal;
    const char *note;
};
struct quic_pn_kat {
    uint64_t largest, truncated;
    unsigned nbits;
    uint64_t pn;
    const char *note;
};
struct quic_pnlen_kat {
    uint64_t pn, largest_acked;
    unsigned len;
    const char *note;
};
struct quic_pkt_kat {
    const char *pkt;
    uint16_t suite;
    const char *secret, *hdr, *pt;
    uint64_t pn, largest;
    unsigned short_len;
    int expect; /* 0 opens, 1 header discarded, 2 AEAD failure, 4 reserved bits, 5 other version */
    const char *note;
};
struct quic_tp_kat {
    const char *tp;
    int valid;
    uint64_t v[11];
    const char *odcid, *iscid, *rscid, *reset;
    unsigned flags; /* 1 odcid 2 iscid 4 retry_scid 8 reset token 16 no migration 32 pref addr */
    const char *note;
};
struct quic_frame_kat {
    const char *payload;
    unsigned level;
    uint64_t err;
    const char *note;
};
#    define QC_OPS 16 /* QUIC_CONN_OPS in tools/kat.py */
struct quic_conn_kat {
    const char *note;
    uint16_t suite;
    const char *ops[QC_OPS];
};
struct quic_gcm_kat {
    const char *secret;
    uint64_t pn;
    const char *hdr, *pt, *packet;
};

struct label_kat {
    int bits;
    const char *secret, *label, *ctx, *out;
};

#    include "kat/expand_label.inc"
#    include "kat/quic_conn.inc"
#    include "kat/quic_frames.inc"
#    include "kat/quic_gcm.inc"
#    include "kat/quic_pkt.inc"
#    include "kat/quic_pn.inc"
#    include "kat/quic_tp.inc"
#    include "kat/quic_varint.inc"

#    define N(a)   (sizeof(a) / sizeof((a)[0]))
#    define NONE   UINT64_MAX
#    define BUF    1600
#    define CANARY 0x5a

static uint8_t g_buf[BUF + 8], g_want[BUF], g_tmp[BUF];

static int is_zero(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

/* ---------------------------------------------------------------- varints, PNs ----------- */

static void test_varint(void)
{
    static const uint64_t B[] = {
        0, 63, 64, 16383, 16384, (1u << 30) - 1, 1u << 30, BRISK__QUIC_VARINT_MAX};
    uint8_t enc[9];
    const uint8_t *p;
    uint64_t v;
    size_t i, n, off, cut;
    for (i = 0; i < N(QUIC_VARINT_KAT); i++) {
        const struct quic_varint_kat *k = &QUIC_VARINT_KAT[i];
        for (off = 0; off < 4; off++) {
            n = t_unhex(k->hex, g_buf + off, 16);
            p = g_buf + off;
            CHECKI(brisk__quic_varint_get(&p, g_buf + off + n, &v) == 1 && v == k->v &&
                       p == g_buf + off + n,
                   i);
            /* truncated at every prefix: 0, and the pointer does not move */
            for (cut = 0; cut < n; cut++) {
                p = g_buf + off;
                CHECKI(brisk__quic_varint_get(&p, g_buf + off + cut, &v) == 0 && p == g_buf + off,
                       i);
            }
        }
        if (k->minimal) {
            memset(enc, CANARY, sizeof enc);
            CHECKI(brisk__quic_varint_put(enc, 8, k->v) == n && memcmp(enc, g_buf + 3, n) == 0 &&
                       (n == 8 || enc[n] == CANARY),
                   i);
            CHECKI(brisk__quic_varint_put(NULL, 0, k->v) == n, i);    /* measure */
            CHECKI(brisk__quic_varint_put(enc, n - 1, k->v) == 0, i); /* cap too small */
        }
    }
    for (i = 0; i < N(B); i++) {
        n = brisk__quic_varint_put(enc + 1, 8, B[i]);
        p = enc + 1;
        CHECKI(n != 0 && brisk__quic_varint_get(&p, enc + 1 + n, &v) == 1 && v == B[i], i);
    }
    CHECK(brisk__quic_varint_put(enc, 8, BRISK__QUIC_VARINT_MAX + 1) == 0);
    CHECK(brisk__quic_varint_put(NULL, 0, BRISK__QUIC_VARINT_MAX + 1) == 0);
    p = NULL;
    CHECK(brisk__quic_varint_get(&p, NULL, &v) == 0);
}

static void test_pn(void)
{
    size_t i;
    for (i = 0; i < N(QUIC_PN_KAT); i++) {
        const struct quic_pn_kat *k = &QUIC_PN_KAT[i];
        CHECKI(brisk__quic_pn_decode(k->largest, k->truncated, k->nbits) == k->pn, i);
    }
    for (i = 0; i < N(QUIC_PNLEN_KAT); i++) {
        const struct quic_pnlen_kat *k = &QUIC_PNLEN_KAT[i];
        CHECKI(brisk__quic_pn_len(k->pn, k->largest_acked) == k->len, i);
    }
}

/* ---------------------------------------------------------------- keys ------------------- */

static void test_keys(void)
{
    static const uint8_t DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    uint8_t c[32], s[32], want[32], sec[48];
    brisk__quic_keys k, fill;
    size_t i, found = 0;
    /* RFC 9001 A.1 via A.2 / A.3: the client and server Initial secrets */
    CHECK(brisk__quic_initial_secrets(DCID, 8, c, s) == BRISK_OK);
    t_unhex(QUIC_GCM_KAT[0].secret, want, 32);
    CHECK(memcmp(c, want, 32) == 0);
    t_unhex(QUIC_GCM_KAT[1].secret, want, 32);
    CHECK(memcmp(s, want, 32) == 0);
    CHECK(brisk__quic_initial_secrets(DCID, 0, c, s) == BRISK_E_ARG);
    CHECK(brisk__quic_initial_secrets(DCID, 21, c, s) == BRISK_E_ARG);
    /* 5.1: hp and key lengths by suite; the iv of A.1 ("quic iv" of client in) */
    CHECK(brisk__quic_keys_init(&k, 0x1301, c, 32) == BRISK_OK && k.suite == 0x1301 &&
          k.hp.aes.nr == 10 && k.k.gcm.aes.nr == 10);
    for (i = 0; i < N(LABEL_KAT); i++) { /* RFC 9001 A.1 "quic iv" of the client secret */
        if (strcmp(LABEL_KAT[i].label, "quic iv") == 0 &&
            strcmp(LABEL_KAT[i].secret, QUIC_GCM_KAT[0].secret) == 0) {
            t_unhex(LABEL_KAT[i].out, want, 12);
            found++;
        }
    }
    CHECK(found == 1);
    CHECK(memcmp(k.iv, want, 12) == 0);
    memset(sec, 7, sizeof sec);
    CHECK(brisk__quic_keys_init(&k, 0x1302, sec, 48) == BRISK_OK && k.hp.aes.nr == 14 &&
          k.k.gcm.aes.nr == 14);
    CHECK(brisk__quic_keys_init(&k, 0x1303, sec, 32) == BRISK_OK && k.suite == 0x1303);
    /* nothing written on a bad call */
    memset(&fill, 0xAA, sizeof fill);
    memcpy(&k, &fill, sizeof k);
    CHECK(brisk__quic_keys_init(&k, 0x1304, sec, 32) == BRISK_E_ARG);
    CHECK(brisk__quic_keys_init(&k, 0x1302, sec, 32) == BRISK_E_ARG);
    CHECK(brisk__quic_keys_init(&k, 0x1301, sec, 48) == BRISK_E_ARG);
    CHECK(memcmp(&k, &fill, sizeof k) == 0);
    brisk__quic_keys_wipe(&k);
    CHECK(is_zero(&k, sizeof k));
    brisk__quic_keys_wipe(NULL);
}

/* ---------------------------------------------------------------- packets ---------------- */

static void test_packets(void)
{
    static uint8_t pkt[BUF], hdr[64], pt[BUF], secret[48];
    size_t i, off, plen, hlen, ptlen, slen, po, pl, cut;
    brisk__quic_hdr h;
    brisk__quic_keys k;
    uint64_t pn;
    uint8_t first;
    int rc;
    for (i = 0; i < N(QUIC_PKT_KAT); i++) {
        const struct quic_pkt_kat *v = &QUIC_PKT_KAT[i];
        plen = t_unhex(v->pkt, pkt, sizeof pkt);
        hlen = t_unhex(v->hdr, hdr, sizeof hdr);
        ptlen = t_unhex(v->pt, pt, sizeof pt);
        slen = t_unhex(v->secret, secret, sizeof secret);
        CHECKI(brisk__quic_keys_init(&k, v->suite, secret, slen) == BRISK_OK, i);
        for (off = 0; off < 4; off++) {
            memcpy(g_buf + off, pkt, plen);
            rc = brisk__quic_hdr_parse(g_buf + off, plen, v->short_len, &h);
            if (v->expect == 1) {
                CHECKI(rc == BRISK_E_PROTO, i);
                continue;
            }
            CHECKI(rc == BRISK_OK && h.pkt_len <= plen, i);
            if (rc != BRISK_OK) {
                continue;
            }
            if (v->expect == 5) {
                CHECKI(h.version != BRISK__QUIC_V1, i);
                continue;
            }
            CHECKI(h.type == BRISK__QPKT_1RTT || h.version == BRISK__QUIC_V1, i);
            rc = brisk__quic_open(&k, g_buf + off, h.pn_off, h.pkt_len, v->largest, &first, &pn,
                                  &po, &pl);
            if (v->expect == 2) {
                /* dropped, and the payload wiped in place */
                CHECKI(rc == BRISK_E_AUTH, i);
                continue;
            }
            CHECKI(rc == BRISK_OK && po == hlen && pl == ptlen && pn == v->pn && first == hdr[0] &&
                       memcmp(g_buf + off, hdr, hlen) == 0 && memcmp(g_buf + off + po, pt, pl) == 0,
                   i);
            CHECKI(((first & ((first & 0x80) ? 0x0c : 0x18)) != 0) == (v->expect == 4), i);
            /* a flip anywhere after the header byte: E_AUTH with the payload zeroed */
            if (v->expect == 0 && off == 1) {
                memcpy(g_tmp, pkt, plen);
                g_tmp[h.pkt_len - 17] ^= 1;
                CHECKI(brisk__quic_open(&k, g_tmp, h.pn_off, h.pkt_len, v->largest, &first, &pn,
                                        &po, &pl) == BRISK_E_AUTH &&
                           is_zero(g_tmp + po, pl),
                       i);
                /* 5.4.2: one byte short of a full sample */
                CHECKI(brisk__quic_open(&k, g_tmp, h.pn_off, h.pn_off + 19, v->largest, &first, &pn,
                                        &po, &pl) == BRISK_E_PROTO,
                       i);
            }
            if (v->expect != 0) {
                continue;
            }
            /* seal, byte exact, at an unaligned offset, with a canary after the tag */
            memset(g_buf, CANARY, sizeof g_buf);
            memcpy(g_buf + off, hdr, hlen - ((hdr[0] & 3) + 1));
            memcpy(g_buf + off + hlen, pt, ptlen);
            CHECKI(brisk__quic_keys_init(&k, v->suite, secret, slen) == BRISK_OK, i);
            CHECKI(brisk__quic_seal(&k, g_buf + off, h.pn_off, (hdr[0] & 3) + 1, v->pn, ptlen) ==
                           BRISK_OK &&
                       memcmp(g_buf + off, pkt, h.pkt_len) == 0 &&
                       g_buf[off + h.pkt_len] == CANARY && k.n_sealed == 1,
                   i);
        }
        if (v->expect == 0 && (pkt[0] & 0x80)) {
            /* every truncation of a long header packet is a discard (Length past the end) */
            h.pkt_len = 0;
            CHECKI(brisk__quic_hdr_parse(pkt, plen, 0, &h) == BRISK_OK, i);
            for (cut = 0; cut < h.pkt_len; cut++) {
                CHECKI(brisk__quic_hdr_parse(pkt, cut, 0, &h) == BRISK_E_PROTO, cut);
            }
        }
        brisk__quic_keys_wipe(&k);
    }
    /* seal's own argument checks */
    memset(secret, 1, 32);
    CHECK(brisk__quic_keys_init(&k, 0x1301, secret, 32) == BRISK_OK);
    memset(g_buf, 0, sizeof g_buf);
    g_buf[0] = 0x40;
    CHECK(brisk__quic_seal(&k, g_buf, 1, 1, 0, 2) == BRISK_E_ARG); /* 1 + 2 < 4: no sample */
    CHECK(brisk__quic_seal(&k, g_buf, 1, 5, 0, 8) == BRISK_E_ARG);
    CHECK(brisk__quic_seal(&k, g_buf, 1, 4, BRISK__QUIC_VARINT_MAX + 1, 8) == BRISK_E_ARG);
    k.n_sealed = (uint64_t)1 << 23; /* RFC 9001 6.6 confidentiality limit */
    CHECK(brisk__quic_seal(&k, g_buf, 1, 4, 0, 8) == BRISK_E_ARG);
    k.n_sealed = ((uint64_t)1 << 23) - 1;
    CHECK(brisk__quic_seal(&k, g_buf, 1, 4, 0, 8) == BRISK_OK);
    k.n_sealed = 0;
    CHECK(brisk__quic_seal(&k, g_buf, 1, 4, 0, 8) == BRISK_E_ARG); /* 5.3: the same nonce again */
    CHECK(brisk__quic_seal(&k, g_buf, 1, 4, 1, 8) == BRISK_OK);
    CHECK(brisk__quic_pn_decode(0, 0, 0) == UINT64_MAX && brisk__quic_pn_decode(0, 0, 33) == UINT64_MAX &&
          brisk__quic_pn_decode(0, 0, 12) == UINT64_MAX);
    brisk__quic_keys_wipe(&k);
    CHECK(brisk__quic_seal(&k, g_buf, 1, 4, 0, 8) == BRISK_E_ARG); /* no key installed */
    /* a 1-RTT header uses our SCID length; the short header needs room for a sample */
    memset(g_buf, 0, 40);
    g_buf[0] = 0x41;
    CHECK(brisk__quic_hdr_parse(g_buf, 1 + 8 + 20, 8, &h) == BRISK_OK &&
          h.type == BRISK__QPKT_1RTT && h.pn_off == 9 && h.dcid_len == 8);
    CHECK(brisk__quic_hdr_parse(g_buf, 1 + 8 + 19, 8, &h) == BRISK_E_PROTO);
    g_buf[0] = 0x01; /* fixed bit 0 */
    CHECK(brisk__quic_hdr_parse(g_buf, 1 + 8 + 20, 8, &h) == BRISK_E_PROTO);
}

/* ---------------------------------------------------------------- transport parameters --- */

static void test_tp(void)
{
    uint8_t cid[20], out[256];
    brisk__quic_tp tp, tp2;
    size_t i, n, off, cut, cl;
    int rc;
    for (i = 0; i < N(QUIC_TP_KAT); i++) {
        const struct quic_tp_kat *k = &QUIC_TP_KAT[i];
        for (off = 0; off < 4; off++) {
            n = t_unhex(k->tp, g_buf + off, BUF);
            rc = brisk__quic_tp_parse(n ? g_buf + off : NULL, n, &tp);
            if (!k->valid) {
                CHECKI(rc == BRISK_E_PROTO && is_zero(&tp, sizeof tp), i);
                continue;
            }
            CHECKI(rc == BRISK_OK, i);
            CHECKI(tp.max_idle_timeout == k->v[0] && tp.max_udp_payload_size == k->v[1] &&
                       tp.initial_max_data == k->v[2] &&
                       tp.initial_max_stream_data_bidi_local == k->v[3] &&
                       tp.initial_max_stream_data_bidi_remote == k->v[4] &&
                       tp.initial_max_stream_data_uni == k->v[5] &&
                       tp.initial_max_streams_bidi == k->v[6] &&
                       tp.initial_max_streams_uni == k->v[7] && tp.ack_delay_exponent == k->v[8] &&
                       tp.max_ack_delay == k->v[9] && tp.active_connection_id_limit == k->v[10],
                   i);
            CHECKI(tp.has_odcid == !!(k->flags & 1) && tp.has_iscid == !!(k->flags & 2) &&
                       tp.has_retry_scid == !!(k->flags & 4) &&
                       tp.has_reset_token == !!(k->flags & 8) &&
                       tp.disable_active_migration == !!(k->flags & 16) &&
                       tp.has_pref_addr == !!(k->flags & 32),
                   i);
            cl = t_unhex(k->odcid, cid, sizeof cid);
            CHECKI(tp.odcid_len == cl && memcmp(tp.odcid, cid, cl) == 0, i);
            cl = t_unhex(k->iscid, cid, sizeof cid);
            CHECKI(tp.iscid_len == cl && memcmp(tp.iscid, cid, cl) == 0, i);
            cl = t_unhex(k->rscid, cid, sizeof cid);
            CHECKI(tp.retry_scid_len == cl && memcmp(tp.retry_scid, cid, cl) == 0, i);
            if (k->flags & 8) {
                t_unhex(k->reset, cid, 16);
                CHECKI(memcmp(tp.reset_token, cid, 16) == 0, i);
            }
        }
        /* every truncation: parsed or refused, never read past the end (ASan), zeroed if refused */
        n = t_unhex(k->tp, g_buf, BUF);
        for (cut = 0; cut < n; cut++) {
            memcpy(g_tmp, g_buf, cut);
            rc = brisk__quic_tp_parse(g_tmp, cut, &tp);
            CHECKI(rc == BRISK_OK || (rc == BRISK_E_PROTO && is_zero(&tp, sizeof tp)), i);
        }
    }
    /* tp_write: ids in order, defaults omitted, the server-only ones refused, round trip */
    brisk__quic_tp_default(&tp);
    tp.max_idle_timeout = 30000;
    tp.initial_max_data = BRISK__QUIC_VARINT_MAX;
    tp.initial_max_streams_bidi = (uint64_t)1 << 60;
    tp.ack_delay_exponent = 0;
    tp.max_udp_payload_size = 1200;
    tp.active_connection_id_limit = 8;
    tp.disable_active_migration = 1;
    tp.iscid_len = 8;
    memset(tp.iscid, 0x42, 8);
    tp.has_iscid = 1; /* what the parser reports for it */
    CHECK(brisk__quic_tp_write(&tp, out, sizeof out, &n) == BRISK_OK);
    CHECK(brisk__quic_tp_parse(out, n, &tp2) == BRISK_OK && memcmp(&tp, &tp2, sizeof tp) == 0);
    CHECK(!tp2.has_odcid && !tp2.has_retry_scid && !tp2.has_reset_token && !tp2.has_pref_addr);
    CHECK(brisk__quic_tp_write(&tp, out, n - 1, &cl) == BRISK_E_ARG && cl == 0);
    brisk__quic_tp_default(&tp2); /* only initial_source_connection_id, empty */
    CHECK(brisk__quic_tp_write(&tp2, out, sizeof out, &n) == BRISK_OK && n == 2 && out[0] == 0x0f &&
          out[1] == 0);
    tp2.has_odcid = 1;
    CHECK(brisk__quic_tp_write(&tp2, out, sizeof out, &n) == BRISK_E_ARG && n == 0);
    brisk__quic_tp_default(&tp2);
    tp2.has_retry_scid = 1;
    CHECK(brisk__quic_tp_write(&tp2, out, sizeof out, &n) == BRISK_E_ARG);
    brisk__quic_tp_default(&tp2);
    tp2.has_reset_token = 1;
    CHECK(brisk__quic_tp_write(&tp2, out, sizeof out, &n) == BRISK_E_ARG);
    brisk__quic_tp_default(&tp2);
    tp2.has_pref_addr = 1;
    CHECK(brisk__quic_tp_write(&tp2, out, sizeof out, &n) == BRISK_E_ARG);
    brisk__quic_tp_default(&tp2);
    tp2.ack_delay_exponent = 21;
    CHECK(brisk__quic_tp_write(&tp2, out, sizeof out, &n) == BRISK_E_ARG);
    CHECK(brisk__quic_tp_parse(NULL, 0, &tp2) == BRISK_OK && tp2.max_ack_delay == 25);
}

static void test_frames(void)
{
    size_t i, n;
    uint64_t e;
    for (i = 0; i < N(QUIC_FRAME_KAT); i++) {
        const struct quic_frame_kat *k = &QUIC_FRAME_KAT[i];
        n = t_unhex(k->payload, g_buf + (i & 3), BUF);
        e = brisk__quic_frames(NULL, k->level, g_buf + (i & 3), n);
        CHECKI(e == k->err, i);
    }
    /* 32-bit: a CRYPTO length beyond SIZE_MAX is refused against the packet, never truncated */
    t_unhex("0600c000000100000000"
            "78",
            g_buf, BUF);
    CHECK(brisk__quic_frames(NULL, 0, g_buf, 11) == BRISK__QERR_FRAME_ENCODING);
}

/* ---------------------------------------------------------------- the connection --------- */

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

static const uint16_t SUITES[] = {0x1303, 0x1301, 0x1302};
static const uint16_t GROUPS[] = {0x001d, 0x0017};
static const uint16_t SIGS[] = {0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601};

typedef struct {
    brisk__tls13_hs hs;
    brisk__quic_conn q;
    anchor an;
    brisk__x509_trust trust;
    brisk__tls13_auth_x509_ctx ax;
    brisk__tls13_ch_params p;
    uint8_t root[1024], rnd[32], x_priv[32], x_pub[32], p_priv[32], p_pub[65], dcid[8], scid[8];
    uint8_t ctp[128], ch[1024];
    size_t ctp_len;
} rig;

static rig R;
static uint8_t *g_hs_scratch, *g_q_scratch;

/* A fresh client: engine + connection, CH1 absorbed. 0 on success. */
static int rig_start(void)
{
    brisk__tls13_hs_cfg cfg;
    brisk__quic_tp tp;
    uint8_t want[1024];
    size_t n, wn;
    memset(&R, 0, sizeof R);
    memset(&cfg, 0, sizeof cfg);
    R.an.len = t_unhex(QUIC_CONN_ROOT, R.root, sizeof R.root);
    R.an.der = R.root;
    R.trust.find_anchor = anchor_fn;
    R.trust.anchor_ctx = &R.an;
    R.ax.host = "device.example.com";
    R.ax.host_len = 18;
    R.ax.trust = &R.trust;
    R.ax.now = (int64_t)QUIC_CONN_NOW;
    cfg.auth = brisk__tls13_auth_x509;
    cfg.auth_ctx = &R.ax;
    cfg.quic = 1;
    t_unhex(QUIC_CONN_RND, R.rnd, 32);
    t_unhex(QUIC_CONN_X25519, R.x_priv, 32);
    t_unhex(QUIC_CONN_P256, R.p_priv, 32);
    t_unhex(QUIC_CONN_DCID, R.dcid, 8);
    t_unhex(QUIC_CONN_SCID, R.scid, 8);
    brisk__x25519_base(R.x_pub, R.x_priv);
    if (brisk__p256_keygen(R.p_pub, R.p_priv) != BRISK_OK ||
        brisk__tls13_hs_init(&R.hs, &cfg, g_hs_scratch, brisk__tls13_hs_scratch_size()) !=
            BRISK_OK ||
        brisk__quic_conn_init(&R.q, &R.hs, R.dcid, 8, R.scid, 8, g_q_scratch,
                              brisk__quic_scratch_size()) != BRISK_OK) {
        return 1;
    }
    /* RFC 9000 18.2 / 7.3: our parameters, initial_source_connection_id = our SCID */
    brisk__quic_tp_default(&tp);
    tp.max_idle_timeout = 30000;
    tp.initial_max_data = 1u << 20;
    tp.initial_max_streams_bidi = 16;
    memcpy(tp.iscid, R.scid, 8);
    tp.iscid_len = 8;
    wn = t_unhex(QUIC_CONN_CTP, want, sizeof want);
    if (brisk__quic_tp_write(&tp, R.ctp, sizeof R.ctp, &R.ctp_len) != BRISK_OK || R.ctp_len != wn ||
        memcmp(R.ctp, want, wn) != 0) {
        return 2;
    }
    /* RFC 9001 8.4 empty session id, 8.1 ALPN, 8.2 the parameters, 4.2 TLS 1.3 only */
    R.p.random = R.rnd;
    R.p.suites = SUITES;
    R.p.n_suites = N(SUITES);
    R.p.groups = GROUPS;
    R.p.n_groups = N(GROUPS);
    R.p.sig_schemes = SIGS;
    R.p.n_sig_schemes = N(SIGS);
    R.p.share_group = 0x001d;
    R.p.share_pub = R.x_pub;
    R.p.share_pub_len = 32;
    R.p.sni = "device.example.com";
    R.p.sni_len = 18;
    R.p.alpn = (const uint8_t *)"\x02h3";
    R.p.alpn_len = 3;
    R.p.quic_tp = R.ctp;
    R.p.quic_tp_len = R.ctp_len;
    wn = t_unhex(QUIC_CONN_CH1, want, sizeof want);
    if (brisk__tls13_ch_write(&R.p, R.ch, sizeof R.ch, &n) != BRISK_OK || n != wn ||
        memcmp(R.ch, want, n) != 0) {
        return 3;
    }
    return brisk__tls13_hs_client_hello(&R.hs, R.ch, n, 0x001d, R.x_priv) == BRISK_OK ? 0 : 4;
}

/* RFC 9001 4.9 / 6.6 hygiene: every key and secret in q and the engine is gone */
static int all_wiped(void)
{
    return is_zero(R.q.rx, sizeof R.q.rx) && is_zero(R.q.tx, sizeof R.q.tx) &&
           is_zero(&R.hs, sizeof R.hs) &&
           is_zero(R.q.ring, BRISK_QUIC_CRYPTO_BUF + (BRISK_QUIC_CRYPTO_BUF + 7) / 8);
}

static void run_ops(size_t idx)
{
    const struct quic_conn_kat *k = &QUIC_CONN_KAT[idx];
    size_t j, n, wn, off = idx & 3;
    const char *op;
    int rc;
    CHECKI(rig_start() == 0, idx);
    for (j = 0; j < QC_OPS && (op = k->ops[j]) != NULL; j++) {
        switch (op[0]) {
        case 'C':
            wn = t_unhex(op + 1, g_want, sizeof g_want);
            memset(g_buf, CANARY, sizeof g_buf);
            n = brisk__quic_send(&R.q, g_buf + off, BUF, 0);
            CHECKI(n == wn && memcmp(g_buf + off, g_want, n) == 0 && g_buf[off + n] == CANARY,
                   idx * 100 + j);
            break;
        case 'S':
        case 'F':
            n = t_unhex(op + 1, g_buf + off, BUF);
            rc = brisk__quic_recv(&R.q, g_buf + off, n, 0);
            CHECKI(op[0] == 'S' ? rc == BRISK_OK : rc != BRISK_OK, idx * 100 + j);
            break;
        case 'E':
            CHECKI(R.q.err != 0 && R.q.err_code == strtoull(op + 1, NULL, 16) && all_wiped() &&
                       brisk__quic_recv(&R.q, g_buf, 0, 0) == R.q.err &&
                       !brisk__quic_established(&R.q),
                   idx * 100 + j);
            break;
        case 'K':
        case 'k':
            CHECKI(brisk__quic_established(&R.q) == (op[0] == 'K'), idx * 100 + j);
            break;
        case 'I':
        case 'W':
            n = op[0] == 'I' ? 0 : 1;
            CHECKI(is_zero(&R.q.rx[n], sizeof R.q.rx[n]) && is_zero(&R.q.tx[n], sizeof R.q.tx[n]),
                   idx * 100 + j);
            break;
        case 'O':
            CHECKI(R.q.n_opened == strtoull(op + 1, NULL, 10), idx * 100 + j);
            break;
        case 'A':
            CHECKI(R.q.auth_fail == strtoull(op + 1, NULL, 10), idx * 100 + j);
            break;
        case 'H': /* RFC 9846 4.1.4 / RFC 9000 17.2.2: CH2 with the HRR's group and cookie */
            CHECKI(R.hs.state == BRISK__HS_WAIT_CH2, idx * 100 + j);
            R.p.share_group = R.hs.hrr_group ? R.hs.hrr_group : 0x001d;
            R.p.share_pub = R.p.share_group == 0x0017 ? R.p_pub : R.x_pub;
            R.p.share_pub_len = R.p.share_group == 0x0017 ? 65 : 32;
            R.p.cookie = R.hs.cookie_len ? R.hs.cookie : NULL;
            R.p.cookie_len = R.hs.cookie_len;
            CHECKI(brisk__tls13_ch_write(&R.p, R.ch, sizeof R.ch, &n) == BRISK_OK &&
                       brisk__tls13_hs_client_hello(
                           &R.hs, R.ch, n, R.p.share_group,
                           R.p.share_group == 0x0017 ? R.p_priv : R.x_priv) == BRISK_OK,
                   idx * 100 + j);
            break;
        case 'R': /* a 1-RTT receive key in place before the handshake completes */
            n = t_unhex(op + 1, g_tmp, 64);
            CHECKI(brisk__quic_keys_init(&R.q.rx[2], k->suite, g_tmp, n) == BRISK_OK,
                   idx * 100 + j);
            break;
        case 'L': /* RFC 9001 6.6: one short of the AES-GCM integrity limit */
            R.q.auth_fail = ((uint64_t)1 << 52) - 1;
            break;
        default:
            CHECKI(0 && "unknown op", idx * 100 + j);
        }
    }
    brisk__tls13_hs_wipe(&R.hs);
}

static void test_conn_scripts(void)
{
    size_t i;
    for (i = 0; i < N(QUIC_CONN_KAT); i++) {
        run_ops(i);
    }
    /* init argument checks */
    CHECK(rig_start() == 0);
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, R.dcid, 7, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG); /* 7.2: >= 8 */
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, R.dcid, 8, R.scid, 21, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG);
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, R.dcid, 8, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size() - 1) == BRISK_E_ARG);
    R.hs.cfg.quic = 0;
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, R.dcid, 8, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG);
    CHECK(brisk__quic_send(&R.q, g_buf, 1199, 0) == 0); /* 14.1: never a short Initial */
    brisk__tls13_hs_wipe(&R.hs);
}

/* A client whose ServerHello is processed: the Handshake level is current. */
static int rig_after_sh(void)
{
    size_t n;
    if (rig_start() != 0 || brisk__quic_send(&R.q, g_buf, BUF, 0) < 1200) {
        return 1;
    }
    n = t_unhex(QUIC_CONN_S_INIT, g_buf, BUF);
    return brisk__quic_recv(&R.q, g_buf, n, 0) == BRISK_OK && R.q.rx_level == 1 ? 0 : 2;
}

static size_t crypto_frame(uint8_t *out, uint64_t off, const uint8_t *d, size_t n)
{
    size_t i = 0;
    out[i++] = 0x06;
    i += brisk__quic_varint_put(out + i, 8, off);
    i += brisk__quic_varint_put(out + i, 8, n);
    if (d != NULL) {
        memcpy(out + i, d, n);
    } else {
        memset(out + i, 0, n);
    }
    return i + n;
}

/* RFC 9000 7.5 / 19.6, RFC 9001 4.1.3: the CRYPTO stream in any split and order */
static void test_crypto_reassembly(void)
{
    static uint8_t flight[4096], sh[256], fr[BRISK_QUIC_CRYPTO_BUF + 32];
    static size_t perm[4096];
    size_t fl, shl, mode, i, j, n, t;
    uint32_t lcg = 12345;
    uint64_t e;
    fl = t_unhex(QUIC_CONN_FLIGHT, flight, sizeof flight);
    shl = t_unhex(QUIC_CONN_SH, sh, sizeof sh);
    for (mode = 0; mode < 4; mode++) {
        CHECKI(rig_after_sh() == 0, mode);
        for (i = 0; i < fl; i++) {
            perm[i] = mode == 1 ? fl - 1 - i : i;
        }
        if (mode >= 2) { /* shuffled */
            for (i = fl - 1; i > 0; i--) {
                lcg = lcg * 1103515245u + 12345u;
                j = (lcg >> 8) % (i + 1);
                t = perm[i];
                perm[i] = perm[j];
                perm[j] = t;
            }
        }
        e = 0;
        for (i = 0; i < fl && e == 0; i++) {
            /* mode 3: 3-byte frames, each sent twice (overlaps and duplicates) */
            size_t len = mode == 3 ? (perm[i] + 3 <= fl ? 3 : fl - perm[i]) : 1;
            n = crypto_frame(fr, perm[i], flight + perm[i], len);
            e = brisk__quic_frames(&R.q, 1, fr, n);
            if (mode == 3 && e == 0 && R.hs.state != BRISK__HS_CONNECTED) {
                e = brisk__quic_frames(&R.q, 1, fr, n);
            }
        }
        CHECKI(e == 0 && R.hs.state == BRISK__HS_CONNECTED && R.q.crx[1] == fl, mode);
        brisk__tls13_hs_wipe(&R.hs);
    }
    /* 7.5: out-of-order data up to exactly the buffer, then one byte more */
    CHECK(rig_after_sh() == 0);
    n = crypto_frame(fr, 1, NULL, BRISK_QUIC_CRYPTO_BUF - 1);
    CHECK(brisk__quic_frames(&R.q, 1, fr, n) == 0);
    n = crypto_frame(fr, 1, NULL, BRISK_QUIC_CRYPTO_BUF);
    CHECK(brisk__quic_frames(&R.q, 1, fr, n) == BRISK__QERR_CRYPTO_BUFFER_EXCEEDED);
    brisk__tls13_hs_wipe(&R.hs);
    /* 4.1.3: a previous level - within what was received ignored, past it PROTOCOL_VIOLATION */
    CHECK(rig_after_sh() == 0 && R.q.crx[0] == shl);
    n = crypto_frame(fr, 0, sh, shl);
    CHECK(brisk__quic_frames(&R.q, 0, fr, n) == 0);
    n = crypto_frame(fr, shl - 1, sh, 1);
    CHECK(brisk__quic_frames(&R.q, 0, fr, n) == 0);
    n = crypto_frame(fr, shl, sh, 1);
    CHECK(brisk__quic_frames(&R.q, 0, fr, n) == BRISK__QERR_PROTOCOL_VIOLATION);
    /* a later level than the current one cannot be decrypted, so it is a violation too */
    n = crypto_frame(fr, 0, sh, 1);
    CHECK(brisk__quic_frames(&R.q, 2, fr, n) == BRISK__QERR_PROTOCOL_VIOLATION);
    brisk__tls13_hs_wipe(&R.hs);
}

/* ---------------------------------------------------------------- constant time ---------- */

/* Under `dev.py ct` (valgrind): seal and open with secret-marked key material for AES-128-GCM,
 * AES-256-GCM and ChaCha20-Poly1305. Only return codes are compared: the plaintext derives
 * from the key, and a memcmp on it would be the test's own branch. */
void quic_ct_run(void)
{
    static const uint16_t S[3] = {0x1301, 0x1302, 0x1303};
    uint8_t secret[48], pkt[96], first;
    brisk__quic_keys k;
    uint64_t pn;
    size_t i, po, pl;
    for (i = 0; i < 3; i++) {
        size_t sl = S[i] == 0x1302 ? 48 : 32;
        memset(secret, 0x3c + (int)i, sizeof secret);
        BRISK__CT_SECRET(secret, sizeof secret);
        CHECK(brisk__quic_keys_init(&k, S[i], secret, sl) == BRISK_OK);
        memset(pkt, 0x11, sizeof pkt);
        pkt[0] = 0xe3; /* Handshake, 4-byte PN */
        brisk__store_be32(pkt + 1, BRISK__QUIC_V1);
        pkt[5] = 0;
        pkt[6] = 0;
        brisk__store_be16(pkt + 7, 0x4000 | (4 + 40 + 16));
        CHECK(brisk__quic_seal(&k, pkt, 9, 4, 0x1234567, 40) == BRISK_OK);
        BRISK__CT_PUBLIC(pkt, sizeof pkt); /* what goes on the wire */
        memcpy(g_buf, pkt, sizeof pkt);
        CHECK(brisk__quic_open(&k, pkt, 9, 9 + 4 + 40 + 16, 0x1234560, &first, &pn, &po, &pl) ==
              BRISK_OK);
        memcpy(pkt, g_buf, sizeof pkt);
        pkt[60] ^= 1;
        CHECK(brisk__quic_open(&k, pkt, 9, 9 + 4 + 40 + 16, 0x1234560, &first, &pn, &po, &pl) ==
              BRISK_E_AUTH);
        CHECK(memcmp(g_buf, pkt, 13) == 0); /* the protected header is back */
        brisk__quic_keys_wipe(&k);
    }
}

void test_quic(void)
{
    g_hs_scratch = (uint8_t *)malloc(brisk__tls13_hs_scratch_size());
    g_q_scratch = (uint8_t *)malloc(brisk__quic_scratch_size());
    if (g_hs_scratch == NULL || g_q_scratch == NULL) {
        CHECK(0 && "malloc");
        return;
    }
    test_varint();
    test_pn();
    test_keys();
    test_packets();
    test_tp();
    test_frames();
    test_conn_scripts();
    test_crypto_reassembly();
    quic_ct_run();
    free(g_hs_scratch);
    free(g_q_scratch);
}

#else /* !BRISK_ENABLE_QUIC */

void quic_ct_run(void)
{
}

void test_quic(void)
{
    CHECK(1); /* QUIC is compiled out in this profile */
}

#endif
