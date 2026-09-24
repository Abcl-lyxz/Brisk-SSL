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
#    define QC_OPS 32 /* QUIC_CONN_OPS in tools/kat.py */
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

struct quic_rec_kat {
    char op;
    long long a[6];
    const char *hex;
    long long want[16];
    const char *note;
};
struct quic_rx_kat {
    long long pn;
    int elicit;
    long long now, maxd;
    int imm;
    long long delay;
    unsigned cap;
    long long want[6];
    const char *ack, *note;
};
struct quic_ackdelay_kat {
    long long ms;
    unsigned exp;
    unsigned long long field;
    unsigned ms_back;
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
#    include "kat/quic_rec.inc"
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
    CHECK(brisk__quic_pn_decode(0, 0, 0) == UINT64_MAX &&
          brisk__quic_pn_decode(0, 0, 33) == UINT64_MAX &&
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
    /* 18.2 layout: preferred_address keeps its CID (sequence 1, 5.1.1) and reset token */
    memset(out, 0, 47);
    out[0] = 0x0d;
    out[1] = 45;
    out[2 + 24] = 4;
    memset(out + 2 + 25, 0x5c, 4);
    memset(out + 2 + 29, 0xa7, 16);
    CHECK(brisk__quic_tp_parse(out, 47, &tp2) == BRISK_OK && tp2.has_pref_addr &&
          tp2.pref_cid_len == 4 && tp2.pref_cid[0] == 0x5c && tp2.pref_cid[3] == 0x5c &&
          tp2.pref_token[0] == 0xa7 && tp2.pref_token[15] == 0xa7);
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

/* ---------------------------------------------------------------- recovery (RFC 9002) ----- */

/* quic_rec.inc: scripts over one brisk__quic_rec; after every op the whole state is compared
 * with PyRec's (see quic_rec_vectors() for the op letters). ACKED / LOST records are then
 * freed, as the connection does. */
static void test_rec(void)
{
    static brisk__quic_rec r;
    int confirmed = 0, have_hs = 0;
    unsigned exp = 3, lvl, i, dlv = 0;
    uint32_t mad = 25;
    size_t k, n;
    for (k = 0; k < N(QUIC_REC_KAT); k++) {
        const struct quic_rec_kat *v = &QUIC_REC_KAT[k];
        long long got[16];
        uint64_t acked = 0, lost = 0, la;
        const uint8_t *p;
        brisk__quic_sent s;
        long long ret = 0, olvl = 0;
        switch (v->op) {
        case 'n':
            brisk__quic_rec_init(&r);
            confirmed = have_hs = 0;
            exp = 3;
            mad = 25;
            break;
        case 'c':
            confirmed = (int)v->a[0];
            have_hs = (int)v->a[1];
            exp = (unsigned)v->a[2];
            mad = (uint32_t)v->a[3];
            break;
        case 's':
            memset(&s, 0, sizeof s);
            s.pn = (uint64_t)v->a[0];
            s.lvl = (uint8_t)v->a[1];
            s.t = v->a[2];
            s.size = (uint16_t)v->a[3];
            s.flags = (uint16_t)(v->a[4] | BRISK__QS_USED);
            s.slot = BRISK__QS_NONE;
            ret = brisk__quic_rec_on_sent(&r, &s);
            break;
        case 'a':
            n = t_unhex(v->hex, g_buf + (k & 3), BUF);
            p = g_buf + (k & 3);
            ret = (long long)brisk__quic_rec_on_ack(&r, (unsigned)v->a[0], (int)v->a[3], &p, p + n,
                                                    (uint64_t)v->a[2], exp, mad, confirmed, v->a[1],
                                                    NULL);
            CHECKI(ret != 0 || p == g_buf + (k & 3) + n, k); /* consumed exactly */
            break;
        case 'x':
            ret = brisk__quic_rec_on_timeout(&r, v->a[0], &lvl, confirmed, have_hs, mad);
            olvl = lvl;
            break;
        case 'd':
            brisk__quic_rec_discard(&r, (unsigned)v->a[0]);
            break;
        case 'z':
            r.srtt = (uint32_t)v->a[0];
            r.rttvar = (uint32_t)v->a[1];
            r.min_rtt = (uint32_t)v->a[2];
            r.has_sample = (uint8_t)v->a[3];
            r.first_sample_t = v->a[4];
            break;
        case 'p':
            ret = brisk__quic_rec_can_send(&r, (size_t)v->a[0]);
            break;
        default:
            CHECKI(0 && "unknown op", k);
        }
        if (v->op == 'a' || v->op == 'x') {
            for (i = 0; i < BRISK__QUIC_SENT; i++) {
                if (r.s[i].flags & (BRISK__QS_ACKED | BRISK__QS_LOST)) {
                    if (r.s[i].flags & BRISK__QS_ACKED) {
                        acked |= (uint64_t)1 << r.s[i].pn;
                    } else {
                        lost |= (uint64_t)1 << r.s[i].pn;
                    }
                    memset(&r.s[i], 0, sizeof r.s[i]);
                }
            }
        }
        la = r.largest_acked[v->op == 'a' ? (unsigned)v->a[0] : 0];
        got[0] = ret;
        got[1] = olvl;
        got[2] = r.srtt;
        got[3] = r.rttvar;
        got[4] = r.min_rtt;
        got[5] = r.latest_rtt;
        got[6] = r.cwnd;
        got[7] = r.ssthresh;
        got[8] = r.in_flight;
        got[9] = r.pto_count;
        got[10] = (long long)acked;
        got[11] = (long long)lost;
        got[12] = brisk__quic_rec_deadline(&r, &dlv, confirmed, have_hs, mad);
        got[13] = dlv;
        got[14] = r.has_sample;
        got[15] = la == NONE ? -1 : (long long)la;
        for (i = 0; i < 16; i++) {
            CHECKI(got[i] == v->want[i], (long)(k * 100 + i));
        }
    }
    /* the record table: 32, then BRISK_E_WANT (the sender stops sending ack-eliciting) */
    brisk__quic_rec_init(&r);
    for (i = 0; i <= BRISK__QUIC_SENT; i++) {
        brisk__quic_sent s;
        memset(&s, 0, sizeof s);
        s.pn = i;
        s.flags = BRISK__QS_USED | BRISK__QS_ELICIT;
        CHECKI(brisk__quic_rec_on_sent(&r, &s) == (i < BRISK__QUIC_SENT ? BRISK_OK : BRISK_E_WANT),
               i);
    }
    CHECK(brisk__quic_rec_free(&r) == 0 && brisk__quic_tadd(INT64_MAX - 5, 10) == INT64_MAX - 1 &&
          brisk__quic_tadd(-5, 10) == 5);
}

/* quic_rec.inc QUIC_RX_KAT: received-PN ranges and the ACK frames they give (RFC 9000 13.2) */
static void test_rxack(void)
{
    static brisk__quic_rxack a;
    uint8_t want[80];
    size_t k, n, wn, off;
    unsigned i;
    for (k = 0; k < N(QUIC_ACKDELAY_KAT); k++) {
        const struct quic_ackdelay_kat *v = &QUIC_ACKDELAY_KAT[k];
        if (v->ms != 0 || v->field == 0) { /* the rows that start from a time in ms */
            CHECKI(brisk__quic_ack_delay_field(v->ms, v->exp) == v->field, k);
        }
        CHECKI(brisk__quic_ack_delay_ms(v->field, v->exp) == v->ms_back, k);
    }
    for (k = 0; k < N(QUIC_RX_KAT); k++) {
        const struct quic_rx_kat *v = &QUIC_RX_KAT[k];
        long long got[6];
        if (v->pn < 0) {
            brisk__quic_rxack_init(&a);
            continue;
        }
        got[0] = brisk__quic_rxack_add(&a, (uint64_t)v->pn, v->elicit, v->now, v->maxd, v->imm);
        got[1] = a.n;
        got[2] = (long long)a.floor;
        got[3] = a.pending;
        got[4] = a.ack_due;
        got[5] = a.largest_t;
        for (i = 0; i < 6; i++) {
            CHECKI(got[i] == v->want[i], (long)(k * 10 + i));
        }
        CHECKI(brisk__quic_rxack_dup(&a, (uint64_t)v->pn) == 1, k); /* now seen, or dropped */
        off = k & 3;
        wn = t_unhex(v->ack, want, sizeof want);
        memset(g_buf, CANARY, 96);
        n = brisk__quic_ack_write(&a, (uint64_t)v->delay, g_buf + off, v->cap);
        CHECKI(n == wn && memcmp(g_buf + off, want, n) == 0 && g_buf[off + n] == CANARY, k);
    }
    brisk__quic_rxack_init(&a);
    CHECK(brisk__quic_ack_write(&a, 0, g_buf, 64) == 0); /* nothing to acknowledge */
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

/* Our transport parameters (tools/kat.py quic_conn_vectors MY / ctp): the windows fit the rings. */
static void my_tp(brisk__quic_tp *tp)
{
    brisk__quic_tp_default(tp);
    tp->max_idle_timeout = 30000;
    tp->initial_max_data = 8192;
    tp->initial_max_stream_data_bidi_local = 4096;
    tp->initial_max_stream_data_uni = 4096;
    tp->initial_max_streams_uni = 2;
    memcpy(tp->iscid, R.scid, 8);
    tp->iscid_len = 8;
}

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
    my_tp(&tp);
    if (brisk__p256_keygen(R.p_pub, R.p_priv) != BRISK_OK ||
        brisk__tls13_hs_init(&R.hs, &cfg, g_hs_scratch, brisk__tls13_hs_scratch_size()) !=
            BRISK_OK ||
        brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 8, g_q_scratch,
                              brisk__quic_scratch_size()) != BRISK_OK) {
        return 1;
    }
    /* RFC 9000 18.2 / 7.3: our parameters, initial_source_connection_id = our SCID */
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

/* RFC 9001 4.9 / 6.6 hygiene: every key and secret in q and the engine is gone, and so is every
 * plaintext copy: the kept 1-RTT secrets, the stream rings, the CRYPTO ring, the records. */
static int all_wiped(void)
{
    return is_zero(R.q.rx, sizeof R.q.rx) && is_zero(R.q.tx, sizeof R.q.tx) &&
           is_zero(&R.hs, sizeof R.hs) && is_zero(R.q.ap_secret, sizeof R.q.ap_secret) &&
           is_zero(R.q.st, sizeof R.q.st) && is_zero(&R.q.rec, sizeof R.q.rec) &&
           is_zero(R.q.path_resp, sizeof R.q.path_resp) &&
           is_zero(R.q.ring, BRISK_QUIC_CRYPTO_BUF + (BRISK_QUIC_CRYPTO_BUF + 7) / 8) &&
           is_zero(R.q.srings, (size_t)BRISK_QUIC_MAX_STREAMS *
                                   (2 * BRISK_QUIC_STREAM_BUF + BRISK_QUIC_STREAM_BUF / 8));
}

/* The memory invariant FLOW_CONTROL_ERROR depends on (stream.c): what we advertise never
 * passes what the application consumed plus the ring / the connection window. */
static int credit_ok(void)
{
    unsigned i;
    for (i = 0; i < BRISK_QUIC_MAX_STREAMS; i++) {
        const brisk__quic_stream *s = &R.q.st[i];
        if (s->flags != 0 &&
            (s->rx_max > s->rx_read + BRISK_QUIC_STREAM_BUF || s->rx_hi > s->rx_max)) {
            return 0;
        }
    }
    return !R.q.established || R.q.max_data_rx <= R.q.consumed + R.q.my_tp.initial_max_data;
}

static long long num(const char **p)
{
    char *e;
    long long v = strtoll(*p, &e, 10);
    *p = *e == ':' ? e + 1 : e;
    return v;
}

static size_t hexf(const char **p, uint8_t *out, size_t cap)
{
    static char tmp[2 * 4096 + 2];
    size_t n = 0;
    while ((*p)[n] != '\0' && (*p)[n] != ':' && n < sizeof tmp - 1) {
        tmp[n] = (*p)[n];
        n++;
    }
    tmp[n] = '\0';
    *p += n + ((*p)[n] == ':');
    return t_unhex(tmp, out, cap);
}

static int has(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn)
{
    size_t i;
    for (i = 0; i + nn <= hn; i++) {
        if (memcmp(hay + i, needle, nn) == 0) {
            return 1;
        }
    }
    return 0;
}

/* P op: the next datagram's 1-RTT packet, opened the way the server would. 1 if it went to
 * dcid and holds needle. */
static int peek_1rtt(size_t n, const uint8_t *dcid, size_t dl, const uint8_t *needle, size_t nn,
                     uint64_t *largest)
{
    brisk__quic_keys k;
    brisk__quic_hdr h;
    uint64_t pn;
    size_t off = 0, po, pl;
    uint8_t first;
    int ok = 0;
    while (off < n && brisk__quic_hdr_parse(g_buf + off, n - off, dl, &h) == BRISK_OK &&
           h.type != BRISK__QPKT_1RTT) {
        off += h.pkt_len;
    }
    if (off >= n || h.type != BRISK__QPKT_1RTT || h.dcid_len != dl ||
        memcmp(h.dcid, dcid, dl) != 0 ||
        brisk__quic_keys_init(&k, R.q.tx[2].suite, R.q.ap_secret[1], R.q.ap_len) != BRISK_OK) {
        return 0;
    }
    if (brisk__quic_open(&k, g_buf + off, h.pn_off, h.pkt_len, *largest, &first, &pn, &po, &pl) ==
        BRISK_OK) {
        *largest = pn;
        ok = has(g_buf + off + po, pl, needle, nn);
    }
    brisk__quic_keys_wipe(&k);
    return ok;
}

/* The first nops ops of script idx (all of them: QC_OPS); the engine is left as it is. */
static void run_ops_n(size_t idx, size_t nops)
{
    const struct quic_conn_kat *k = &QUIC_CONN_KAT[idx];
    size_t j, n, wn, off = idx & 3, dl;
    const char *op, *p;
    int64_t now = 0;
    uint64_t v, largest = NONE, sid, err;
    long long want, id;
    uint8_t dc[20];
    int rc;
    CHECKI(rig_start() == 0, idx);
    for (j = 0; j < nops && (op = k->ops[j]) != NULL; j++) {
        long tag = (long)(idx * 100 + j);
        p = op + 1;
        switch (op[0]) {
        case 'C':
        case 'c':
            wn = t_unhex(op + 1, g_want, sizeof g_want);
            memset(g_buf, CANARY, sizeof g_buf);
            n = brisk__quic_send(&R.q, g_buf + off, BUF, now);
            CHECKI(op[0] == 'c' ||
                       (n == wn && memcmp(g_buf + off, g_want, n) == 0 && g_buf[off + n] == CANARY),
                   tag);
            break;
        case 'S':
        case 'F':
            n = t_unhex(op + 1, g_buf + off, BUF);
            rc = brisk__quic_recv(&R.q, g_buf + off, n, now);
            CHECKI(op[0] == 'S' ? rc == BRISK_OK : rc != BRISK_OK, tag);
            break;
        case 'E':
            CHECKI(R.q.err != 0 && R.q.err_code == strtoull(op + 1, NULL, 16) && all_wiped() &&
                       brisk__quic_recv(&R.q, g_buf, 0, now) == R.q.err &&
                       !brisk__quic_established(&R.q),
                   tag);
            break;
        case 'K':
        case 'k':
            CHECKI(brisk__quic_established(&R.q) == (op[0] == 'K'), tag);
            break;
        case 'I':
        case 'W':
            n = op[0] == 'I' ? 0 : 1;
            CHECKI(is_zero(&R.q.rx[n], sizeof R.q.rx[n]) && is_zero(&R.q.tx[n], sizeof R.q.tx[n]),
                   tag);
            break;
        case 'O':
            CHECKI(R.q.n_opened == strtoull(op + 1, NULL, 10), tag);
            break;
        case 'A':
            CHECKI(R.q.auth_fail == strtoull(op + 1, NULL, 10), tag);
            break;
        case 'H': /* RFC 9846 4.1.4 / RFC 9000 17.2.2: CH2 with the HRR's group and cookie */
            CHECKI(R.hs.state == BRISK__HS_WAIT_CH2, tag);
            R.p.share_group = R.hs.hrr_group ? R.hs.hrr_group : 0x001d;
            R.p.share_pub = R.p.share_group == 0x0017 ? R.p_pub : R.x_pub;
            R.p.share_pub_len = R.p.share_group == 0x0017 ? 65 : 32;
            R.p.cookie = R.hs.cookie_len ? R.hs.cookie : NULL;
            R.p.cookie_len = R.hs.cookie_len;
            CHECKI(brisk__tls13_ch_write(&R.p, R.ch, sizeof R.ch, &n) == BRISK_OK &&
                       brisk__tls13_hs_client_hello(
                           &R.hs, R.ch, n, R.p.share_group,
                           R.p.share_group == 0x0017 ? R.p_priv : R.x_priv) == BRISK_OK,
                   tag);
            break;
        case 'R': /* a 1-RTT receive key in place before the handshake completes */
            n = t_unhex(op + 1, g_tmp, 64);
            CHECKI(brisk__quic_keys_init(&R.q.rx[2], k->suite, g_tmp, n) == BRISK_OK, tag);
            break;
        case 'L': /* RFC 9001 6.6: one short of the AES-GCM integrity limit */
            R.q.auth_fail = ((uint64_t)1 << 52) - 1;
            break;
        case 'T':
            now = strtoll(op + 1, NULL, 10);
            break;
        case 'D':
            CHECKI(brisk__quic_deadline(&R.q) ==
                       (strcmp(op + 1, "none") == 0 ? INT64_MAX : strtoll(op + 1, NULL, 10)),
                   tag);
            break;
        case 'G':
            CHECKI(R.q.rec.cwnd == strtoull(op + 1, NULL, 10), tag);
            break;
        case 'o':
            p = op + 2;
            want = num(&p);
            CHECKI(brisk__quic_stream_open(&R.q, op[1] == 'b') == want, tag);
            break;
        case 'w': {
            static uint8_t wr[4096];
            id = num(&p);
            rc = (int)num(&p);
            n = hexf(&p, wr, sizeof wr);
            want = num(&p);
            CHECKI(brisk__quic_stream_write(&R.q, (uint64_t)id, wr, n, rc) == want, tag);
            break;
        }
        case 'r': {
            static uint8_t rd[4096];
            id = num(&p);
            want = num(&p);
            wn = hexf(&p, g_want, BUF);
            rc = brisk__quic_stream_read(&R.q, (uint64_t)id, rd, sizeof rd, &err);
            CHECKI(rc == want && (rc <= 0 || ((size_t)rc == wn && memcmp(rd, g_want, wn) == 0)),
                   tag);
            break;
        }
        case 'a':
            want = strtoll(op + 1, NULL, 10);
            rc = brisk__quic_stream_accept(&R.q, &sid);
            CHECKI(want < 0 ? rc == want : rc == BRISK_OK && sid == (uint64_t)want, tag);
            break;
        case 'X':
            CHECKI(brisk__quic_close(&R.q, strtoull(op + 1, NULL, 16)) == BRISK_OK, tag);
            break;
        case 'f':
            v = strtoull(op + 1, (char **)&p, 16);
            p++;
            n = hexf(&p, g_buf + off, BUF);
            CHECKI(brisk__quic_frames(&R.q, 2, g_buf + off, n) == v, tag);
            break;
        case 'P':
            want = num(&p);
            dl = hexf(&p, dc, sizeof dc);
            wn = hexf(&p, g_want, BUF);
            n = brisk__quic_send(&R.q, g_buf, BUF, now);
            CHECKI(n >= (size_t)want && peek_1rtt(n, dc, dl, g_want, wn, &largest), tag);
            break;
        case 'p':
            CHECKI(brisk__quic_send(&R.q, g_buf, BUF, now) == 0, tag);
            break;
        case 'Q':
            v = (uint64_t)strtoll(op + 4, NULL, 10);
            if (op[1] == 'm' && op[2] == 'd') {
                CHECKI(R.q.max_data_tx == v, tag);
            } else if (op[1] == 's') {
                CHECKI(R.q.peer_max_streams[op[2] == 'u'] == v, tag);
            } else { /* Qt0: stream 0's send limit */
                CHECKI(R.q.st[0].id == 0 && R.q.st[0].tx_max == v, tag);
            }
            break;
        default:
            CHECKI(0 && "unknown op", tag);
        }
        CHECKI(credit_ok(), tag); /* the invariant sweep, after every op */
    }
}

static void run_ops(size_t idx)
{
    run_ops_n(idx, QC_OPS);
    brisk__tls13_hs_wipe(&R.hs);
}

/* An established, confirmed connection: the prefix of the stateful-frame scripts. */
static int rig_established(void)
{
    size_t i;
    for (i = 0; i < N(QUIC_CONN_KAT); i++) {
        if (strncmp(QUIC_CONN_KAT[i].note, "19.8 (MUST): STREAM on local bidi 8", 35) == 0) {
            run_ops_n(i, 5);
            return R.q.established && R.q.confirmed ? 0 : 1;
        }
    }
    return 2;
}

static void no_ack_owed(void)
{
    R.q.rxa[2].pending = 0;
    R.q.rxa[2].ack_due = INT64_MAX;
}

/* RFC 9002 7 / 7.5 / 7.7 and RFC 9000 10.1 on a live connection */
static void test_conn_timers(void)
{
    unsigned i;
    uint8_t d[4];
    int64_t t;
    size_t n;
    /* 7 (MUST NOT): new data waits for the window; 7.5: a probe goes anyway and counts */
    CHECK(rig_established() == 0);
    no_ack_owed();
    CHECK(brisk__quic_stream_open(&R.q, 1) == 0 &&
          brisk__quic_stream_write(&R.q, 0, (const uint8_t *)"abc", 3, 0) == 3);
    R.q.rec.in_flight = R.q.rec.cwnd - 1199;
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, 0) == 0);
    R.q.rec.in_flight = R.q.rec.cwnd - 1200;
    n = brisk__quic_send(&R.q, g_buf, BUF, 0);
    CHECK(n > 0 && R.q.rec.in_flight == R.q.rec.cwnd - 1200 + n);
    CHECK(brisk__quic_stream_write(&R.q, 0, (const uint8_t *)"d", 1, 0) == 1 &&
          brisk__quic_send(&R.q, g_buf, BUF, 0) == 0);
    R.q.probe[2] = 1;
    t = R.q.rec.in_flight;
    n = brisk__quic_send(&R.q, g_buf, BUF, 0);
    CHECK(n > 0 && R.q.rec.in_flight == (uint32_t)t + n && R.q.probe[2] == 0);
    /* 6.2.4 / RFC 9000 8.2.2 (MUST): an owed probe or PATH_RESPONSE is due now */
    CHECK(brisk__quic_deadline(&R.q) > R.q.now);
    R.q.probe[1] = 1;
    CHECK(brisk__quic_deadline(&R.q) == R.q.now);
    R.q.probe[1] = 0;
    R.q.n_path_resp = 1;
    R.q.rec.in_flight = 0;
    CHECK(brisk__quic_deadline(&R.q) == R.q.now);
    R.q.n_path_resp = 0;
    brisk__tls13_hs_wipe(&R.hs);
    /* 6.2.4 (MUST): the last two sent records are the probes', new data never takes them */
    CHECK(rig_established() == 0);
    no_ack_owed();
    CHECK(brisk__quic_stream_open(&R.q, 1) == 0 &&
          brisk__quic_stream_write(&R.q, 0, (const uint8_t *)"abc", 3, 0) == 3);
    for (i = 0; brisk__quic_rec_free(&R.q.rec) > 2; i++) {
        R.q.rec.s[i].flags = BRISK__QS_USED;
    }
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, 0) == 0);
    R.q.probe[2] = 2;
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, 0) > 0 && brisk__quic_rec_free(&R.q.rec) == 1);
    CHECK(brisk__quic_stream_write(&R.q, 0, (const uint8_t *)"d", 1, 0) == 1 &&
          brisk__quic_send(&R.q, g_buf, BUF, 0) > 0 && brisk__quic_rec_free(&R.q.rec) == 0 &&
          R.q.probe[2] == 0);
    brisk__tls13_hs_wipe(&R.hs);
    /* 7.7: at most 12000 bytes per ms without an ACK; the deadline is the next ms */
    CHECK(rig_established() == 0);
    no_ack_owed();
    CHECK(brisk__quic_stream_open(&R.q, 1) == 0 &&
          brisk__quic_stream_write(&R.q, 0, (const uint8_t *)"abc", 3, 0) == 3);
    R.q.burst_t = R.q.now;
    R.q.burst_bytes = 12000;
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, R.q.now) == 0 &&
          brisk__quic_deadline(&R.q) == R.q.now + 1);
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, R.q.now + 1) > 0);
    brisk__tls13_hs_wipe(&R.hs);
    /* 10.1: min(ours, the peer's) = 30000 ms from the last packet; expiry closes silently */
    CHECK(rig_established() == 0);
    no_ack_owed();
    t = brisk__quic_deadline(&R.q);
    CHECK(t == R.q.idle_start + 30000);
    CHECK(brisk__quic_recv(&R.q, d, 0, t - 1) == BRISK_OK);
    CHECK(brisk__quic_recv(&R.q, d, 0, t) == BRISK_E_TIMEOUT && R.q.err_code == 0 && all_wiped() &&
          brisk__quic_send(&R.q, g_buf, BUF, t) == 0 && brisk__quic_deadline(&R.q) == INT64_MAX);
    brisk__tls13_hs_wipe(&R.hs);
    /* 10.1 (MUST): never below 3 * PTO */
    CHECK(rig_established() == 0);
    no_ack_owed();
    R.q.my_tp.max_idle_timeout = 1;
    CHECK(brisk__quic_deadline(&R.q) ==
          R.q.idle_start + 3 * (int64_t)brisk__quic_rec_pto(&R.q.rec, 2, 25));
    /* time: a clock that steps back is clamped; near INT64_MAX the deadline saturates */
    CHECK(brisk__quic_recv(&R.q, d, 0, 50) == BRISK_OK &&
          brisk__quic_recv(&R.q, d, 0, 10) == BRISK_OK && R.q.now == 50);
    R.q.idle_start = INT64_MAX - 10;
    CHECK(brisk__quic_deadline(&R.q) == INT64_MAX - 1);
    brisk__tls13_hs_wipe(&R.hs);
    /* 10.2.3: an application close once established: 0x1d in 1-RTT, nothing else */
    CHECK(rig_established() == 0 && brisk__quic_close(&R.q, 0x77) == BRISK_OK && all_wiped() &&
          brisk__quic_close(&R.q, 1) == BRISK_E_ARG);
    n = brisk__quic_send(&R.q, g_buf, BUF, 0);
    CHECK(n > 0 && n < 100 && (g_buf[0] & 0xc0) == 0x40 &&
          brisk__quic_send(&R.q, g_buf, BUF, 0) == 0);
    brisk__tls13_hs_wipe(&R.hs);
}

static size_t stream_frame(uint8_t *out, uint64_t id, uint64_t off, const uint8_t *d, size_t n,
                           int fin)
{
    size_t i = 0;
    out[i++] = (uint8_t)(0x0e | (fin ? 1 : 0)); /* STREAM with offset and length */
    i += brisk__quic_varint_put(out + i, 8, id);
    i += brisk__quic_varint_put(out + i, 8, off);
    i += brisk__quic_varint_put(out + i, 8, n);
    memcpy(out + i, d, n);
    return i + n;
}

/* RFC 9000 2.2 / 4: stream data in any split and order, across the ring wrap, FIN in an empty
 * frame, reads of every size; the send side's short write and its flow-control stall */
static void test_stream_io(void)
{
    static uint8_t data[8000], got[8000], fr[64];
    size_t i, n, have = 0, cap = 1, perm[4000], t, lim;
    uint64_t err;
    uint32_t lcg = 777;
    int rc;
    for (i = 0; i < sizeof data; i++) {
        data[i] = (uint8_t)(i * 31 + (i >> 8));
    }
    CHECK(rig_established() == 0);
    /* 3000 bytes of the server's uni stream 3 as 1-byte frames, last byte first */
    for (i = 3000; i-- > 0;) {
        n = stream_frame(fr, 3, i, data + i, 1, 0);
        CHECKI(brisk__quic_frames(&R.q, 2, fr, n) == 0, i);
    }
    while ((rc = brisk__quic_stream_read(&R.q, 3, got + have, cap, &err)) > 0) {
        have += (size_t)rc;
        cap = cap % 17 + 1;
    }
    CHECK(rc == BRISK_E_WANT && have == 3000 && memcmp(got, data, 3000) == 0 && credit_ok());
    for (i = 0; i < BRISK_QUIC_MAX_STREAMS && R.q.st[i].id != 3; i++) {
    }
    lim = i < BRISK_QUIC_MAX_STREAMS ? (size_t)R.q.st[i].rx_max : 0; /* MAX_STREAM_DATA'd */
    CHECK(lim > BRISK_QUIC_STREAM_BUF && lim <= 3000 + BRISK_QUIC_STREAM_BUF && lim - 3000 <= 4000);
    /* reading moved the window: up to the new limit (the ring wraps), 3-byte frames shuffled,
     * each sent twice, overlapping; then FIN alone in an empty frame */
    for (i = 0; i < lim - 3000; i++) {
        perm[i] = 3000 + i;
    }
    for (i = lim - 3000 - 1; i > 0; i--) {
        lcg = lcg * 1103515245u + 12345u;
        t = perm[i];
        perm[i] = perm[(lcg >> 8) % (i + 1)];
        perm[(lcg >> 8) % (i + 1)] = t;
    }
    for (i = 0; i < lim - 3000; i++) {
        n = perm[i] + 3 <= lim ? 3 : lim - perm[i];
        n = stream_frame(fr, 3, perm[i], data + perm[i], n, 0);
        CHECKI(brisk__quic_frames(&R.q, 2, fr, n) == 0 && brisk__quic_frames(&R.q, 2, fr, n) == 0,
               i);
    }
    n = stream_frame(fr, 3, lim, data, 0, 1);
    CHECK(brisk__quic_frames(&R.q, 2, fr, n) == 0 && credit_ok());
    while ((rc = brisk__quic_stream_read(&R.q, 3, got + have, 4096, &err)) > 0) {
        have += (size_t)rc;
    }
    CHECK(rc == 0 && have == lim && memcmp(got, data, lim) == 0);
    CHECK(brisk__quic_stream_read(&R.q, 3, got, 1, &err) == BRISK_E_ARG); /* slot freed */
    /* send side: a write past the ring is short; the peer's stream limit stalls it */
    CHECK(brisk__quic_stream_open(&R.q, 1) == 0 &&
          brisk__quic_stream_write(&R.q, 0, data, 5000, 1) == BRISK_QUIC_STREAM_BUF);
    R.q.st[0].tx_max = 10; /* as if the server had allowed 10 bytes */
    R.q.rxa[2].pending = 0;
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, 0) > 0 && R.q.st[0].tx_next == 10 &&
          brisk__quic_send(&R.q, g_buf, BUF, 0) == 0);
    n = 0;
    fr[n++] = 0x11; /* MAX_STREAM_DATA 0, 2000 */
    n += brisk__quic_varint_put(fr + n, 8, 0);
    n += brisk__quic_varint_put(fr + n, 8, 2000);
    CHECK(brisk__quic_frames(&R.q, 2, fr, n) == 0 && brisk__quic_send(&R.q, g_buf, BUF, 0) > 0 &&
          R.q.st[0].tx_next > 10);
    brisk__tls13_hs_wipe(&R.hs);
}

/* The packet builder's PN length (RFC 9000 17.1 / A.2): the RFC's two examples drive the
 * 1-RTT header, and a 1-byte PN with a 1-byte PING is padded for the sample (RFC 9001 5.4.2). */
static void test_pn_builder(void)
{
    brisk__quic_keys k;
    brisk__quic_hdr h;
    uint64_t pn;
    size_t i, n, po, pl;
    uint8_t first;
    for (i = 0; i < 3; i++) {
        const struct quic_pnlen_kat *v = &QUIC_PNLEN_KAT[i < 2 ? i : 0];
        CHECKI(rig_established() == 0, i);
        R.q.rxa[2].pending = 0; /* no ACK in the way */
        R.q.rxa[2].ack_due = INT64_MAX;
        if (i < 2) {
            R.q.tx_pn[2] = v->pn;
            R.q.rec.largest_acked[2] = v->largest_acked;
            CHECKI(brisk__quic_stream_open(&R.q, 1) == 0 &&
                       brisk__quic_stream_write(&R.q, 0, (const uint8_t *)"x", 1, 1) == 1,
                   i);
        } else {
            R.q.tx_pn[2] = 5;
            R.q.rec.largest_acked[2] = 4;
            R.q.probe[2] = 1;
        }
        n = brisk__quic_send(&R.q, g_buf, BUF, 0);
        CHECKI(brisk__quic_hdr_parse(g_buf, n, 8, &h) == BRISK_OK && h.type == BRISK__QPKT_1RTT &&
                   brisk__quic_keys_init(&k, R.q.tx[2].suite, R.q.ap_secret[1], R.q.ap_len) ==
                       BRISK_OK &&
                   brisk__quic_open(&k, g_buf, h.pn_off, n, R.q.tx_pn[2] - 2, &first, &pn, &po,
                                    &pl) == BRISK_OK,
               i);
        if (i < 2) {
            CHECKI((first & 3) + 1u == v->len && pn == v->pn, i);
        } else {
            /* 1-byte PN + PING + 2 PADDING: exactly the 4 bytes the sample needs */
            CHECKI((first & 3) == 0 && pn == 5 && n == 1 + 8 + 1 + 3 + 16 && pl == 3 &&
                       g_buf[po] == 0x01 && g_buf[po + 1] == 0 && g_buf[po + 2] == 0,
                   i);
        }
        brisk__quic_keys_wipe(&k);
        brisk__tls13_hs_wipe(&R.hs);
    }
}

static void test_conn_scripts(void)
{
    brisk__quic_tp tp;
    size_t i;
    for (i = 0; i < N(QUIC_CONN_KAT); i++) {
        run_ops(i);
    }
    /* init argument checks */
    CHECK(rig_start() == 0);
    my_tp(&tp);
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 7, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG); /* 7.2: >= 8 */
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 21, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG);
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size() - 1) == BRISK_E_ARG);
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, NULL, R.dcid, 8, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG);
    /* 7.3: initial_source_connection_id must be our SCID */
    tp.iscid[7] ^= 1;
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG);
    my_tp(&tp);
    tp.iscid_len = 7;
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 8, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_E_ARG);
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 7, g_q_scratch,
                                brisk__quic_scratch_size()) == BRISK_OK); /* both 7 bytes */
    /* the limits the rings must back */
    for (i = 0; i < 10; i++) {
        my_tp(&tp);
        switch (i) {
        case 0:
            tp.initial_max_stream_data_bidi_local = BRISK_QUIC_STREAM_BUF + 1;
            break;
        case 1:
            tp.initial_max_stream_data_bidi_remote = BRISK_QUIC_STREAM_BUF + 1;
            break;
        case 2:
            tp.initial_max_stream_data_uni = BRISK_QUIC_STREAM_BUF + 1;
            break;
        case 3:
            tp.initial_max_data = (uint64_t)BRISK_QUIC_MAX_STREAMS * BRISK_QUIC_STREAM_BUF + 1;
            break;
        case 4:
            tp.initial_max_streams_bidi = 1;
            tp.initial_max_streams_uni = BRISK_QUIC_MAX_STREAMS;
            break;
        case 5:
            tp.initial_max_streams_bidi = (uint64_t)1 << 60; /* no wrap in the sum */
            tp.initial_max_streams_uni = 0;
            break;
        case 6:
            tp.active_connection_id_limit = BRISK__QUIC_CIDS + 1;
            break;
        case 7:
            tp.active_connection_id_limit = 1;
            break;
        case 8: /* exactly at every limit: accepted */
            tp.initial_max_stream_data_bidi_local = BRISK_QUIC_STREAM_BUF;
            tp.initial_max_stream_data_bidi_remote = BRISK_QUIC_STREAM_BUF;
            tp.initial_max_stream_data_uni = BRISK_QUIC_STREAM_BUF;
            tp.initial_max_data = (uint64_t)BRISK_QUIC_MAX_STREAMS * BRISK_QUIC_STREAM_BUF;
            tp.initial_max_streams_bidi = 1;
            tp.initial_max_streams_uni = BRISK_QUIC_MAX_STREAMS - 1;
            tp.active_connection_id_limit = BRISK__QUIC_CIDS;
            break;
        default:
            tp.ack_delay_exponent = 21;
            break;
        }
        CHECKI(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 8, g_q_scratch,
                                     brisk__quic_scratch_size()) ==
                   (i == 8 ? BRISK_OK : BRISK_E_ARG),
               i);
    }
    my_tp(&tp);
    R.hs.cfg.quic = 0;
    CHECK(brisk__quic_conn_init(&R.q, &R.hs, &tp, R.dcid, 8, R.scid, 8, g_q_scratch,
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
    int64_t dl;
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
    /* RFC 9002 6.2.2.1 (MUST): ClientHello acked, only ACKs owed; the first Handshake packet
     * drops the Initial space, yet the anti-deadlock PTO stays armed and sends a probe */
    CHECK(rig_after_sh() == 0 && brisk__quic_rxack_add(&R.q.rxa[1], 0, 1, R.q.now, 25, 1) == 0);
    t = brisk__quic_send(&R.q, g_buf, BUF, R.q.now);
    CHECK(t >= 1200);
    CHECK(R.q.tx[0].suite == 0);
    CHECK(brisk__quic_rec_free(&R.q.rec) == BRISK__QUIC_SENT - 1);
    dl = brisk__quic_deadline(&R.q);
    CHECKI(dl < R.q.now + 5000, (int)(dl - R.q.now));
    CHECK(brisk__quic_send(&R.q, g_buf, BUF, dl) > 0 &&
          brisk__quic_rec_free(&R.q.rec) == BRISK__QUIC_SENT - 2);
    brisk__tls13_hs_wipe(&R.hs);
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
    test_rec();
    test_rxack();
    test_conn_scripts();
    test_pn_builder();
    test_conn_timers();
    test_stream_io();
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
