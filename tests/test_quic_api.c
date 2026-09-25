/* test_quic_api.c - the public QUIC API (src/quic/api.c, src/os/linux_udp.c; M6 item 4).
 *
 * brisk__quic_setup is fed QUIC_API_RND (tools/kat.py quic_api_vectors) and must emit the Python
 * model's datagrams byte for byte: the first Initial (our transport parameters, ALPN hq-interop,
 * no session id, TLS 1.3 only), the Finished flight after the server's (coalesced, split and
 * reordered), CH2 after a HelloRetryRequest, the Initial after a Retry, the resumed ClientHello
 * and the CONNECTION_CLOSE of an ALPN failure. 1-RTT server packets past the handshake are
 * sealed here with the KAT's server application secret. The blocking driver runs over an
 * AF_UNIX datagram socketpair with a fork()ed server (Linux only).
 * The whole file sits inside #if BRISK_ENABLE_QUIC; other profiles run an empty suite. */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_QUIC

#    include "kat/quic_api.inc"

#    ifdef __linux__
#        include <errno.h>
#        include <netinet/in.h>
#        include <poll.h>
#        include <sys/socket.h>
#        include <sys/wait.h>
#        include <unistd.h>
#    endif

#    define HOST "device.example.com"
/* the byte-exact rows assume the default knobs (our TPs are derived from them) */
#    define KNOBS_DEFAULT (BRISK_QUIC_MAX_STREAMS == 8 && BRISK_QUIC_STREAM_BUF == 4096)

static uint8_t g_root[1024], g_rnd[BRISK__QUIC_RAND], g_d[1600 + 8], g_w[1600], g_tmp[4096];
static size_t g_root_len;
static uint8_t *g_mem;
static size_t g_size;
static brisk__quic_keys g_sap; /* the server's 1-RTT send keys */
static uint64_t g_spn;         /* its next packet number */

static brisk_cfg cfg_ok(void)
{
    brisk_cfg c;
    memset(&c, 0, sizeof c);
    c.alpn = "hq-interop";
    c.ca_mem = g_root;
    c.ca_mem_len = g_root_len;
    return c;
}

static brisk_quic *setup_off(const brisk_cfg *cfg, size_t off)
{
    brisk_quic *q = NULL;
    memset(g_mem, 0x5a, g_size + 8);
    if (brisk__quic_setup(g_mem + off, g_size, cfg, HOST, QUIC_API_NOW, g_rnd, NULL, NULL, 0, &q) !=
        BRISK_OK) {
        return NULL;
    }
    return q;
}

static brisk_quic *setup(void)
{
    brisk_cfg c = cfg_ok();
    return setup_off(&c, 0);
}

/* the next datagram equals the KAT hex */
static int pull_is(brisk_quic *q, const char *hex, int64_t now)
{
    size_t wn = t_unhex(hex, g_w, sizeof g_w), n;
    memset(g_d, 0xcc, sizeof g_d);
    n = brisk_quic_pull(q, g_d + 1, 1600, now);
    return n == wn && memcmp(g_d + 1, g_w, n) == 0 && g_d[1 + n] == 0xcc;
}

/* feed KAT hex at an odd address */
static int feed_hex(brisk_quic *q, const char *hex, int64_t now)
{
    size_t n = t_unhex(hex, g_d + 3, 1600);
    return brisk_quic_feed(q, g_d + 3, n, now);
}

static int feed2(brisk_quic *q, const char *a, const char *b, int64_t now)
{
    size_t n = t_unhex(a, g_d + 1, 1600);
    n += t_unhex(b, g_d + 1 + n, 1600 - n);
    return brisk_quic_feed(q, g_d + 1, n, now);
}

/* A 1-RTT server packet (RFC 9000 17.3.1) to our SCID carrying payload, sealed with S_AP. */
static size_t srv_1rtt(uint8_t *out, const uint8_t *payload, size_t n)
{
    size_t i = 0;
    out[i++] = 0x41; /* short header, fixed bit, key phase 0, 2-byte PN */
    memcpy(out + i, g_rnd + BRISK__CONN_RAND + 8, 8);
    i += 8;
    memcpy(out + i + 2, payload, n);
    if (brisk__quic_seal(&g_sap, out, i, 2, g_spn++, n) != BRISK_OK) {
        return 0;
    }
    return i + 2 + n + 16;
}

static int feed_1rtt(brisk_quic *q, const uint8_t *payload, size_t n, int64_t now)
{
    size_t k = srv_1rtt(g_d + 1, payload, n);
    return k != 0 ? brisk_quic_feed(q, g_d + 1, k, now) : -100;
}

static void drain(brisk_quic *q, int64_t now)
{
    while (brisk_quic_pull(q, g_d, 1600, now) != 0) {
    }
}

/* an established connection (the coalesced flight), our Finished flight pulled */
static void srv_keys(void)
{
    uint8_t sec[32];
    t_unhex(QUIC_API_S_AP, sec, sizeof sec);
    brisk__quic_keys_init(&g_sap, 0x1301, sec, 32);
    g_spn = 0;
}

static brisk_quic *established(void)
{
    brisk_quic *q = setup();
    srv_keys();
    if (q == NULL || brisk_quic_pull(q, g_d, 1600, 0) != 1200 ||
        feed2(q, QUIC_API_S_INIT, QUIC_API_S_HS, 0) != BRISK_OK || brisk_quic_status(q) != 0) {
        return NULL;
    }
    drain(q, 0);
    return q;
}

static int confirm(brisk_quic *q, int64_t now)
{
    static const uint8_t done[] = {0x1e, 0x00, 0x00};
    int rc = feed_1rtt(q, done, sizeof done, now);
    drain(q, now);
    return rc == BRISK_OK && q->q.confirmed;
}

static size_t varint(uint8_t *p, uint64_t v)
{
    return brisk__quic_varint_put(p, 8, v);
}

/* ---------------------------------------------------------------- init ------------------ */

static void test_init(void)
{
    brisk_cfg c = cfg_ok();
    brisk_quic *q = (brisk_quic *)1;
    char longhost[300];
    size_t i;
    int bad;
    /* NULLs; *out NULL on every failure */
    CHECK(brisk__quic_setup(NULL, g_size, &c, HOST, 0, g_rnd, NULL, NULL, 0, &q) == BRISK_E_ARG &&
          q == NULL);
    CHECK(brisk__quic_setup(g_mem, g_size, NULL, HOST, 0, g_rnd, NULL, NULL, 0, &q) == BRISK_E_ARG);
    CHECK(brisk__quic_setup(g_mem, g_size, &c, NULL, 0, g_rnd, NULL, NULL, 0, &q) == BRISK_E_ARG);
    CHECK(brisk__quic_setup(g_mem, g_size, &c, HOST, 0, g_rnd, NULL, NULL, 0, NULL) == BRISK_E_ARG);
    CHECK(brisk__quic_setup(g_mem, g_size - 1, &c, HOST, 0, g_rnd, NULL, NULL, 0, &q) ==
              BRISK_E_ARG &&
          q == NULL);
    /* RFC 9001 8.1 (MUST): ALPN mandatory - none at all is refused before memory is touched;
     * "," fails the list encoding (then the arena is wiped) */
    for (i = 0; i < 3; i++) {
        c = cfg_ok();
        c.alpn = i == 0 ? NULL : i == 1 ? "" : ",";
        memset(g_mem, 0x5a, g_size);
        q = (brisk_quic *)1;
        CHECKI(brisk__quic_setup(g_mem, g_size, &c, HOST, 0, g_rnd, NULL, NULL, 0, &q) ==
                       BRISK_E_ARG &&
                   q == NULL && (i == 2 || (g_mem[0] == 0x5a && g_mem[g_size / 2] == 0x5a)),
               i);
    }
    /* bad host / ca_mem mismatch: E_ARG and the memory wiped */
    memset(longhost, 'a', sizeof longhost);
    longhost[256] = '\0';
    for (i = 0; i < 4; i++) {
        const char *h = i == 0 ? "" : i == 1 ? longhost : i == 2 ? "dev\x01ice" : HOST;
        c = cfg_ok();
        if (i == 3) {
            c.ca_mem_len = 0;
        }
        memset(g_mem, 0x5a, g_size);
        q = (brisk_quic *)1;
        bad = brisk__quic_setup(g_mem, g_size, &c, h, 0, g_rnd, NULL, NULL, 0, &q) == BRISK_E_ARG;
        CHECKI(bad && q == NULL && (i == 0 || i == 3 || g_mem[g_size / 2] == 0), i);
    }
    /* any alignment */
    c = cfg_ok();
    for (i = 1; i < 8; i += 2) {
        CHECKI(setup_off(&c, i) != NULL, i);
    }
    /* a suites list without a count and the reverse */
    CHECK(brisk__quic_setup(g_mem, g_size, &c, HOST, 0, g_rnd, NULL, NULL, 1, &q) == BRISK_E_ARG);
}

/* ---------------------------------------------------------------- handshakes ------------ */

static void test_handshake(void)
{
    brisk_quic *q;
    const char *name;
    size_t len;
    int v;
    uint8_t d[1600];
    q = setup();
    CHECK(q != NULL && brisk_quic_deadline(q) <= 0 && brisk_quic_status(q) == BRISK_E_WANT);
    CHECK(brisk_quic_pull(q, d, BRISK_QUIC_DGRAM_MAX - 1, 0) == 0);
    /* RFC 9001 8.1-8.4 / RFC 9000 14.1: CH1 in a 1200-byte Initial */
    CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_INIT1, 0));
    CHECK(brisk_quic_pull(q, d, sizeof d, 0) == 0 && brisk_quic_deadline(q) > 0 &&
          brisk_quic_deadline(q) != INT64_MAX); /* the PTO timer */
    CHECK(brisk_quic_alpn(q, &name, &len) == BRISK_E_ARG);
    /* three deliveries of the same flight: coalesced, split, reordered (the Handshake packet
     * before its keys is dropped, RFC 9001 5.7 - the server's retransmission then lands) */
    for (v = 0; v < 3; v++) {
        q = setup();
        CHECKI(brisk_quic_pull(q, d, sizeof d, 0) == 1200, v);
        if (v == 0) {
            CHECKI(feed2(q, QUIC_API_S_INIT, QUIC_API_S_HS, 5) == BRISK_OK, v);
        } else {
            if (v == 2) {
                CHECKI(feed_hex(q, QUIC_API_S_HS, 5) == BRISK_OK &&
                           brisk_quic_status(q) == BRISK_E_WANT,
                       v);
            }
            CHECKI(feed_hex(q, QUIC_API_S_INIT, 5) == BRISK_OK &&
                       brisk_quic_status(q) == BRISK_E_WANT && brisk_quic_deadline(q) <= 5,
                   v);
            CHECKI(feed_hex(q, QUIC_API_S_HS, 5) == BRISK_OK, v);
        }
        CHECKI(brisk_quic_status(q) == BRISK_OK && brisk_quic_deadline(q) <= 5, v);
        CHECKI(!KNOBS_DEFAULT || pull_is(q, QUIC_API_FIN1, 5), v);
        CHECKI(brisk_quic_alpn(q, &name, &len) == BRISK_OK && len == 10 &&
                   memcmp(name, "hq-interop", 10) == 0 && brisk_quic_resumed(q) == 0,
               v);
        /* nothing owed any more: the deadline is the engine's */
        drain(q, 5);
        CHECKI(brisk_quic_deadline(q) > 5 && brisk_quic_deadline(q) == brisk__quic_deadline(&q->q),
               v);
    }
    /* RFC 9846 4.1.4: HRR -> CH2 (same TPs, the cookie) before the next send */
    q = setup();
    CHECK(brisk_quic_pull(q, d, sizeof d, 0) == 1200 && feed_hex(q, QUIC_API_S_HRR, 1) == 0 &&
          brisk_quic_deadline(q) <= 1);
    CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_CH2DG, 1));
    CHECK(feed_hex(q, QUIC_API_S_HRR_FL, 2) == BRISK_OK && brisk_quic_status(q) == BRISK_OK);
    CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_HRR_FIN, 2));
    /* QUIC keeps CH1 + CH2 in one 2048-byte Initial retention buffer: a ticket too big for the
     * pair is not offered (plain CH1), so the HRR still yields CH2 instead of a local failure */
    {
        static uint8_t big_id[800], blob[BRISK_TICKET_MAX];
        brisk__tls13_ticket t;
        brisk_cfg c = cfg_ok();
        memset(&t, 0, sizeof t);
        memset(big_id, 0x5A, sizeof big_id);
        t.lifetime = 3600;
        t.age_add = 1;
        t.ticket = big_id;
        t.ticket_len = sizeof big_id;
        t.psk_len = 32;
        t.suite = 0x1301;
        memset(t.psk, 7, 32);
        CHECK(brisk__tls13_ticket_export(&t, QUIC_API_NOW - 1000, HOST, strlen(HOST), blob,
                                         sizeof blob, &c.ticket_len) == BRISK_OK);
        c.ticket = blob;
        q = setup_off(&c, 0);
        CHECK(q != NULL && (!KNOBS_DEFAULT || pull_is(q, QUIC_API_INIT1, 0)));
        CHECK(KNOBS_DEFAULT || brisk_quic_pull(q, d, sizeof d, 0) == 1200);
        CHECK(feed_hex(q, QUIC_API_S_HRR, 1) == 0 && brisk_quic_status(q) == BRISK_E_WANT);
        CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_CH2DG, 1));
        CHECK(KNOBS_DEFAULT || brisk_quic_pull(q, d, sizeof d, 1) != 0);
        CHECK(brisk_quic_status(q) == BRISK_E_WANT); /* CH2 was queued, not a local failure */
    }
    /* RFC 9000 17.2.5: Retry -> the token-bearing Initial is owed at once */
    q = setup();
    CHECK(brisk_quic_pull(q, d, sizeof d, 0) == 1200);
    drain(q, 0);
    CHECK(brisk_quic_deadline(q) > 3 && feed_hex(q, QUIC_API_S_RETRY, 3) == BRISK_OK &&
          brisk_quic_deadline(q) <= 3);
    CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_RETRY_INIT, 3));
    CHECK(feed_hex(q, QUIC_API_S_RETRY_FL, 4) == BRISK_OK && brisk_quic_status(q) == BRISK_OK);
    CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_RETRY_FIN, 4));
    /* RFC 9001 8.1: no ALPN / an unoffered one -> no_application_protocol (0x0178), one close */
    for (v = 0; v < 2; v++) {
        q = setup();
        CHECKI(brisk_quic_pull(q, d, sizeof d, 0) == 1200 &&
                   feed_hex(q, v ? QUIC_API_S_BADALPN : QUIC_API_S_NOALPN, 1) != BRISK_OK &&
                   brisk_quic_status(q) < 0 && brisk_quic_status(q) != BRISK_E_WANT &&
                   brisk_quic_error(q) == 0x178 && brisk_quic_deadline(q) <= 1,
               v);
        CHECKI(!KNOBS_DEFAULT || pull_is(q, v ? QUIC_API_CC_BADALPN : QUIC_API_CC_NOALPN, 1), v);
        CHECKI(brisk_quic_pull(q, d, sizeof d, 1) == 0 &&
                   brisk_quic_status(q) == brisk_quic_status(q) &&
                   feed_hex(q, QUIC_API_S_INIT, 2) == brisk_quic_status(q),
               v);
    }
}

/* ---------------------------------------------------------------- resumption ------------ */

static int g_tickets;
static size_t g_ticket_len;
static void on_ticket(void *ctx, const uint8_t *blob, size_t len)
{
    (void)ctx;
    (void)blob;
    g_tickets++;
    g_ticket_len = len;
}

static void test_resumption(void)
{
    static uint8_t blob[512], nstf[512];
    brisk_cfg c = cfg_ok();
    brisk_quic *q;
    size_t n, k;
    /* RFC 9846 4.2.11: a ticket for this host -> pre_shared_key; resumed flight */
    c.ticket = blob;
    c.ticket_len = t_unhex(QUIC_API_BLOB, blob, sizeof blob);
    q = setup_off(&c, 0);
    CHECK(q != NULL && (!KNOBS_DEFAULT || pull_is(q, QUIC_API_PSK_INIT, 0)));
    CHECK(feed_hex(q, QUIC_API_S_PSK, 1) == BRISK_OK && brisk_quic_status(q) == BRISK_OK &&
          brisk_quic_resumed(q) == 1);
    CHECK(!KNOBS_DEFAULT || pull_is(q, QUIC_API_PSK_FIN, 1));
    /* a foreign-host ticket is not offered: the plain CH1 */
    c.ticket_len = t_unhex(QUIC_API_BLOB_OTHER, blob, sizeof blob);
    q = setup_off(&c, 0);
    CHECK(q != NULL && (!KNOBS_DEFAULT || pull_is(q, QUIC_API_INIT1, 0)));
    /* RFC 9001 4.5: a NewSessionTicket in 1-RTT CRYPTO reaches on_ticket */
    c = cfg_ok();
    c.on_ticket = on_ticket;
    q = setup_off(&c, 0);
    srv_keys();
    CHECK(q != NULL && brisk_quic_pull(q, g_d, 1600, 0) == 1200 &&
          feed2(q, QUIC_API_S_INIT, QUIC_API_S_HS, 0) == BRISK_OK);
    drain(q, 0);
    n = t_unhex(QUIC_API_NST, g_tmp, sizeof g_tmp);
    k = 0;
    nstf[k++] = 0x06; /* CRYPTO at offset 0 */
    k += varint(nstf + k, 0);
    k += varint(nstf + k, n);
    memcpy(nstf + k, g_tmp, n);
    k += n;
    g_tickets = 0;
    CHECK(feed_1rtt(q, nstf, k, 1) == BRISK_OK && g_tickets == 1 && g_ticket_len > 0 &&
          brisk_quic_status(q) == BRISK_OK && brisk_quic_deadline(q) <= 1);
}

/* ---------------------------------------------------------------- streams --------------- */

static void test_streams(void)
{
    static const uint8_t req[] = "GET /index.html\r\n";
    uint8_t fr[128], out[64], *odd = out + 1;
    uint64_t err;
    size_t k, got;
    int64_t id;
    int r;
    brisk_quic *q = established();
    CHECK(q != NULL && confirm(q, 1));
    if (q == NULL) {
        return;
    }
    /* RFC 9000 2.1: ours bidi 0, 4; the server allows 2 (4.6) */
    CHECK(brisk_quic_stream_open(q, 1) == 0 && brisk_quic_stream_open(q, 1) == 4 &&
          brisk_quic_stream_open(q, 1) == BRISK_E_WANT);
    k = 0;
    fr[k++] = 0x12; /* MAX_STREAMS bidi 3 */
    k += varint(fr + k, 3);
    CHECK(feed_1rtt(q, fr, k, 2) == BRISK_OK && brisk_quic_stream_open(q, 1) == 8);
    drain(q, 2);
    /* the contract: a write owes a datagram now */
    CHECK(brisk_quic_deadline(q) > 2 &&
          brisk_quic_stream_write(q, 0, req, sizeof req - 1, 1) == (int)sizeof req - 1 &&
          brisk_quic_deadline(q) <= 2 && brisk_quic_pull(q, g_d, 1600, 2) > 0);
    drain(q, 2);
    /* the response, read one byte at a time into an odd address */
    k = 0;
    fr[k++] = 0x0f; /* STREAM off len fin */
    k += varint(fr + k, 0);
    k += varint(fr + k, 0);
    k += varint(fr + k, 5);
    memcpy(fr + k, "hello", 5);
    k += 5;
    CHECK(feed_1rtt(q, fr, k, 3) == BRISK_OK);
    drain(q, 3);
    got = 0;
    while ((r = brisk_quic_stream_read(q, 0, odd + got, 1, &err)) > 0) {
        got += (size_t)r;
        CHECK(brisk_quic_deadline(q) <= 3); /* reading may owe MAX_STREAM_DATA */
    }
    CHECK(r == 0 && got == 5 && memcmp(odd, "hello", 5) == 0);
    r = brisk_quic_stream_read(q, 0, odd, 1, &err);
    CHECK(r == 0 || r == BRISK_E_ARG);
    /* nothing yet on 4: E_WANT; RESET_STREAM -> E_PEER_ALERT + the code (RFC 9000 19.4) */
    CHECK(brisk_quic_stream_read(q, 4, odd, 8, &err) == BRISK_E_WANT);
    k = 0;
    fr[k++] = 0x04;
    k += varint(fr + k, 4);
    k += varint(fr + k, 0x99);
    k += varint(fr + k, 0);
    CHECK(feed_1rtt(q, fr, k, 4) == BRISK_OK);
    err = 0;
    CHECK(brisk_quic_stream_read(q, 4, odd, 8, &err) == BRISK_E_PEER_ALERT && err == 0x99);
    /* STOP_SENDING -> write E_PEER_ALERT (19.5) */
    k = 0;
    fr[k++] = 0x05;
    k += varint(fr + k, 8);
    k += varint(fr + k, 0x77);
    CHECK(feed_1rtt(q, fr, k, 5) == BRISK_OK &&
          brisk_quic_stream_write(q, 8, "x", 1, 0) == BRISK_E_PEER_ALERT);
    /* ids that are not ours to use */
    CHECK(brisk_quic_stream_write(q, (uint64_t)1 << 62, "x", 1, 0) == BRISK_E_ARG &&
          brisk_quic_stream_read(q, (uint64_t)1 << 62, odd, 1, &err) == BRISK_E_ARG &&
          brisk_quic_stream_read(q, 1, odd, 1, &err) == BRISK_E_ARG &&
          brisk_quic_stream_write(q, 3, "x", 1, 0) == BRISK_E_ARG &&
          brisk_quic_stream_read(q, 12, NULL, 1, &err) == BRISK_E_ARG &&
          brisk_quic_stream_read(q, 12, odd, 0, &err) == BRISK_E_ARG);
    /* cap past INT_MAX (32-bit size_t included) is clamped, never negative */
    id = brisk_quic_stream_open(q, 1);
    CHECK(id == BRISK_E_WANT || id >= 0);
    CHECK(brisk_quic_stream_accept(q, &err) == BRISK_E_WANT);
    k = 0;
    fr[k++] = 0x12;
    k += varint(fr + k, 8);
    CHECK(feed_1rtt(q, fr, k, 6) == BRISK_OK);
    id = brisk_quic_stream_open(q, 1);
    CHECK(id > 8);
    k = 0;
    fr[k++] = 0x0a; /* STREAM len, offset 0 */
    k += varint(fr + k, (uint64_t)id);
    k += varint(fr + k, 1);
    fr[k++] = 'z';
    CHECK(feed_1rtt(q, fr, k, 7) == BRISK_OK &&
          brisk_quic_stream_read(q, (uint64_t)id, odd, (size_t)-1, &err) == 1 && odd[0] == 'z');
    CHECK(brisk_quic_stream_read(q, (uint64_t)id, odd, (size_t)INT_MAX + 1u, &err) == BRISK_E_WANT);
}

/* RFC 9000 4.6: finished slots come back - 10 * MAX_STREAMS sequential request / response */
static void test_recycle(void)
{
    uint8_t fr[64];
    uint64_t err, largest;
    int64_t id, want = 0, now = 2;
    size_t k;
    int i, ok = 1;
    brisk_quic *q = established();
    CHECK(q != NULL && confirm(q, 1));
    if (q == NULL) {
        return;
    }
    for (i = 0; i < 10 * BRISK_QUIC_MAX_STREAMS && ok; i++, now++) {
        id = brisk_quic_stream_open(q, 1);
        ok = id == want && brisk_quic_stream_write(q, (uint64_t)id, "x", 1, 1) == 1;
        drain(q, now);
        largest = q->q.tx_pn[2] - 1;
        k = 0;
        fr[k++] = 0x02; /* ACK everything we sent */
        k += varint(fr + k, largest);
        k += varint(fr + k, 0);
        k += varint(fr + k, 0);
        k += varint(fr + k, largest);
        fr[k++] = 0x0b; /* STREAM len fin, offset 0 */
        k += varint(fr + k, (uint64_t)id);
        k += varint(fr + k, 1);
        fr[k++] = 'y';
        fr[k++] = 0x12; /* MAX_STREAMS: one more */
        k += varint(fr + k, (uint64_t)i + 3);
        ok = ok && feed_1rtt(q, fr, k, now) == BRISK_OK &&
             brisk_quic_stream_read(q, (uint64_t)id, fr, 8, &err) == 1 &&
             brisk_quic_stream_read(q, (uint64_t)id, fr, 8, &err) == 0;
        drain(q, now);
        want += 4;
        CHECKI(ok, i);
    }
    CHECK(brisk_quic_status(q) == BRISK_OK);
}

/* Every slot finished but our FINs not ACKed yet: open waits (E_WANT - blocking: qa_wait), it
 * is not a caller mistake (E_ARG); the ACK frees the slots. */
static void test_slots_busy(void)
{
    uint8_t fr[64];
    uint64_t err, largest;
    int64_t id;
    size_t k;
    int i, ok = 1;
    brisk_quic *q = established();
    CHECK(q != NULL && confirm(q, 1));
    if (q == NULL) {
        return;
    }
    k = 0;
    fr[k++] = 0x12; /* MAX_STREAMS bidi: plenty - the slots are the limit */
    k += varint(fr + k, 100);
    CHECK(feed_1rtt(q, fr, k, 2) == BRISK_OK);
    for (i = 0; i < BRISK_QUIC_MAX_STREAMS && ok; i++) {
        id = brisk_quic_stream_open(q, 1);
        ok = id == 4 * i && brisk_quic_stream_write(q, (uint64_t)id, "x", 1, 1) == 1;
        drain(q, 2);
        k = 0;
        fr[k++] = 0x0b; /* the whole response, no ACK */
        k += varint(fr + k, (uint64_t)id);
        k += varint(fr + k, 1);
        fr[k++] = 'y';
        ok = ok && feed_1rtt(q, fr, k, 2) == BRISK_OK &&
             brisk_quic_stream_read(q, (uint64_t)id, fr, 8, &err) == 1 &&
             brisk_quic_stream_read(q, (uint64_t)id, fr, 8, &err) == 0;
        drain(q, 2);
    }
    CHECK(ok);
    CHECK(brisk_quic_stream_open(q, 1) == BRISK_E_WANT && brisk_quic_status(q) == BRISK_OK);
    largest = q->q.tx_pn[2] - 1;
    k = 0;
    fr[k++] = 0x02; /* ACK everything we sent */
    k += varint(fr + k, largest);
    k += varint(fr + k, 0);
    k += varint(fr + k, 0);
    k += varint(fr + k, largest);
    CHECK(feed_1rtt(q, fr, k, 3) == BRISK_OK &&
          brisk_quic_stream_open(q, 1) == 4 * BRISK_QUIC_MAX_STREAMS);
}

/* ---------------------------------------------------------------- endings --------------- */

static int open_1rtt(size_t n, uint8_t *first, const uint8_t **pl, size_t *pll, int next)
{
    brisk__quic_keys k;
    brisk__quic_hdr h;
    uint8_t sec[32];
    uint64_t pn;
    size_t po;
    int rc;
    t_unhex(QUIC_API_C_AP, sec, 32);
    rc = brisk__quic_hdr_parse(g_d, n, 8, &h) == BRISK_OK && h.type == BRISK__QPKT_1RTT &&
         brisk__quic_keys_init(&k, 0x1301, sec, 32) == BRISK_OK &&
         (!next || brisk__quic_keys_next(&k, &k, sec, 32) == BRISK_OK) &&
         brisk__quic_open(&k, g_d, h.pn_off, h.pkt_len, 0, first, &pn, &po, pll) == BRISK_OK;
    *pl = g_d + po;
    brisk__quic_keys_wipe(&k);
    return rc;
}

static void test_close(void)
{
    const uint8_t *pl;
    uint8_t first, fr[32], d[1600];
    uint64_t err;
    size_t n, pll, k;
    brisk_quic *q = established();
    CHECK(q != NULL && confirm(q, 1));
    if (q == NULL) {
        return;
    }
    /* RFC 9000 16: a code past 2^62-1 is refused, nothing done */
    CHECK(brisk_quic_close(q, (uint64_t)1 << 62) == BRISK_E_ARG && brisk_quic_status(q) == 0);
    /* 10.2: established -> CONNECTION_CLOSE 0x1d with our code in 1-RTT */
    CHECK(brisk_quic_close(q, 0x100) == BRISK_OK && brisk_quic_deadline(q) <= 1);
    n = brisk_quic_pull(q, g_d, 1600, 2);
    CHECK(n > 0 && open_1rtt(n, &first, &pl, &pll, 0) && pll >= 3 && pl[0] == 0x1d &&
          pl[1] == 0x41 && pl[2] == 0x00);
    CHECK(brisk_quic_pull(q, d, sizeof d, 2) == 0 && brisk_quic_status(q) == BRISK_E_ARG &&
          brisk_quic_error(q) == 0x100 && brisk_quic_close(q, 1) == BRISK_E_ARG);
    CHECK(brisk_quic_close(NULL, 0) == BRISK_OK);
    /* 10.2.3: before the handshake -> APPLICATION_ERROR 0x0c, in an Initial */
    q = setup();
    CHECK(brisk_quic_close(q, 0x42) == BRISK_OK && brisk_quic_error(q) == 0x0c &&
          brisk_quic_pull(q, d, sizeof d, 0) == 1200 && brisk_quic_pull(q, d, sizeof d, 0) == 0);
    /* the peer's CONNECTION_CLOSE (10.2.2): E_PEER_ALERT, its code, nothing sent */
    q = established();
    k = 0;
    fr[k++] = 0x1d;
    k += varint(fr + k, 0x33);
    fr[k++] = 0;
    CHECK(q != NULL && feed_1rtt(q, fr, k, 1) == BRISK_E_PEER_ALERT &&
          brisk_quic_status(q) == BRISK_E_PEER_ALERT && brisk_quic_error(q) == 0x33 &&
          brisk_quic_pull(q, d, sizeof d, 1) == 0);
    /* a stateless reset (10.3): 43 bytes ending in the token */
    q = established();
    memset(d, 0x6b, 43);
    d[0] = 0x4b;
    t_unhex(QUIC_API_RESET, d + 27, 16);
    CHECK(q != NULL && brisk_quic_feed(q, d, 43, 2) == BRISK_E_PEER_ALERT &&
          brisk_quic_status(q) == BRISK_E_PEER_ALERT && brisk_quic_error(q) == 0);
    /* the idle timeout (10.1): silence past 30 s */
    q = established();
    CHECK(q != NULL && brisk_quic_deadline(q) <= 40000);
    CHECK(brisk_quic_pull(q, d, sizeof d, 40000) == 0 && brisk_quic_status(q) == BRISK_E_IO &&
          brisk_quic_deadline(q) == INT64_MAX);
    /* ... and every call says so: E_TIMEOUT would mean "harmless, call again" (a busy loop) */
    CHECK(q != NULL && brisk_quic_stream_read(q, 0, d, 8, NULL) == BRISK_E_IO &&
          brisk_quic_stream_write(q, 0, "x", 1, 0) == BRISK_E_IO &&
          brisk_quic_stream_open(q, 1) == BRISK_E_IO &&
          brisk_quic_stream_accept(q, &err) == BRISK_E_IO);
#    ifdef __linux__
    CHECK(brisk_quic_poll(q, 0) == BRISK_E_IO); /* src/os: Linux only */
#    endif
    /* datagram bounds */
    CHECK(brisk_quic_feed(q, d, 65528, 0) == BRISK_E_ARG &&
          brisk_quic_feed(NULL, d, 1, 0) == BRISK_E_ARG &&
          brisk_quic_feed(q, NULL, 1, 0) == BRISK_E_ARG && brisk_quic_pull(NULL, d, 1600, 0) == 0 &&
          brisk_quic_status(NULL) == BRISK_E_ARG);
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

static void test_wipe(void)
{
    brisk_quic *q = established();
    size_t n;
    CHECK(q != NULL && brisk_quic_stream_open(q, 1) == 0 &&
          brisk_quic_stream_write(q, 0, "secret", 6, 0) == 6);
    if (q == NULL) {
        return;
    }
    n = sizeof *q + brisk__tls13_hs_scratch_size() + brisk__quic_scratch_size();
    brisk_quic_wipe(q);
    CHECK(all_zero((const uint8_t *)q, n));
    brisk_quic_wipe(NULL);
}

/* ---------------------------------------------------------------- seams ----------------- */

static unsigned g_kl[8], g_nkl;
static void keylog(void *ctx, const uint8_t *cr, unsigned epoch, int is_send, const uint8_t *s,
                   size_t len)
{
    (void)s;
    if (ctx == &g_nkl && cr != NULL && len == 32 && g_nkl < 8) {
        g_kl[g_nkl++] = epoch << 1 | (unsigned)is_send;
    }
}

static void test_seams(void)
{
    uint8_t fr[32];
    size_t k, n;
    const uint8_t *pl;
    uint8_t first;
    uint64_t largest;
    int64_t t;
    brisk_quic *q = setup();
    unsigned i, hs = 0, ap = 0;
    CHECK(q != NULL);
    if (q == NULL) {
        return;
    }
    q->q.keylog = keylog;
    q->q.keylog_ctx = &g_nkl;
    q->q.keylog_random = q->c.rnd;
    g_nkl = 0;
    CHECK(brisk_quic_pull(q, g_d, 1600, 0) == 1200 &&
          feed2(q, QUIC_API_S_INIT, QUIC_API_S_HS, 0) == BRISK_OK);
    for (i = 0; i < g_nkl; i++) {
        hs += (g_kl[i] >> 1) == BRISK__EPOCH_HANDSHAKE && ap == 0;
        ap += (g_kl[i] >> 1) == BRISK__EPOCH_APP;
    }
    CHECK(g_nkl == 4 && hs == 2 && ap == 2);
    drain(q, 0);
    /* RFC 9001 6.1 (MUST NOT): not before confirmation, nor before an ACK of this phase */
    CHECK(brisk__quic_key_update(&q->q) == BRISK_E_WANT);
    srv_keys();
    CHECK(confirm(q, 1) && brisk__quic_key_update(&q->q) == BRISK_E_WANT);
    CHECK(brisk_quic_stream_open(q, 1) == 0 && brisk_quic_stream_write(q, 0, "a", 1, 0) == 1);
    drain(q, 2);
    largest = q->q.tx_pn[2] - 1;
    k = 0;
    fr[k++] = 0x02;
    k += varint(fr + k, largest);
    k += varint(fr + k, 0);
    k += varint(fr + k, 0);
    k += varint(fr + k, largest);
    CHECK(feed_1rtt(q, fr, k, 3) == BRISK_OK);
    drain(q, 3);
    /* the first phase: the ACK alone allows it (6.5's 3 * PTO wait follows an update) */
    t = 4;
    CHECK(brisk__quic_key_update(&q->q) == BRISK_OK && q->q.key_phase == 1);
    CHECK(brisk_quic_stream_write(q, 0, "b", 1, 0) == 1);
    n = brisk_quic_pull(q, g_d, 1600, t);
    CHECK(n > 0 && open_1rtt(n, &first, &pl, &k, 1) && (first & 0x04) != 0);
    CHECK(brisk__quic_key_update(&q->q) == BRISK_E_WANT &&
          brisk__quic_key_update(NULL) == BRISK_E_ARG);
}

/* ---------------------------------------------------------------- blocking -------------- */

#    ifdef __linux__
enum { B_SERVE, B_SILENT, B_OVERSIZE };

static void serve(int fd, int mode)
{
    uint8_t d[2048], fr[64];
    size_t n, k;
    struct pollfd p;
    p.fd = fd;
    p.events = POLLIN;
    if (recv(fd, d, sizeof d, 0) <= 0 || mode == B_SILENT) {
        sleep(1); /* alive past the client's timeout: a closed peer would be ECONNREFUSED */
        _exit(0);
    }
    n = t_unhex(QUIC_API_S_INIT, d, sizeof d);
    n += t_unhex(QUIC_API_S_HS, d + n, sizeof d - n);
    if (mode == B_OVERSIZE) {
        memset(d + n, 0, 1500 - n); /* a datagram past our 1472-byte buffer (RFC 9000 14) */
        n = 1500;
    }
    send(fd, d, n, 0);
    if (mode == B_OVERSIZE) {
        sleep(1);
        _exit(0);
    }
    /* our Finished flight, then the request on stream 0 (it must exist before we answer) */
    for (k = 0; k < 2; k++) {
        if (poll(&p, 1, 3000) <= 0 || recv(fd, d, sizeof d, 0) <= 0) {
            _exit(1);
        }
    }
    k = 0;
    fr[k++] = 0x1e; /* HANDSHAKE_DONE */
    fr[k++] = 0x0b;
    fr[k++] = 0x00;
    fr[k++] = 0x02;
    fr[k++] = 'h';
    fr[k++] = 'i';
    n = srv_1rtt(d, fr, k);
    send(fd, d, n, 0);
    /* stay up until the line goes quiet: exiting on the client's ACK (sent while it polls)
     * would turn its next datagram into ECONNREFUSED under a slow emulator */
    while (poll(&p, 1, 500) > 0 && recv(fd, d, sizeof d, 0) > 0) {
    }
    _exit(0);
}

static int fork_server(int mode, int *cfd, pid_t *pid)
{
    int sv[2];
    uint8_t sec[32];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        return 0;
    }
    t_unhex(QUIC_API_S_AP, sec, sizeof sec);
    brisk__quic_keys_init(&g_sap, 0x1301, sec, 32);
    g_spn = 0;
    *pid = fork();
    if (*pid == 0) {
        close(sv[0]);
        serve(sv[1], mode);
    }
    close(sv[1]);
    *cfd = sv[0];
    return *pid > 0;
}

static void test_blocking(void)
{
    brisk_cfg c = cfg_ok();
    brisk_quic *q = (brisk_quic *)1;
    uint8_t buf[16];
    uint64_t err;
    int fd, st;
    pid_t pid;
    int64_t t0;
    /* a round trip */
    CHECK(fork_server(B_SERVE, &fd, &pid));
    c.timeout_ms = 5000;
    CHECK(brisk__quic_connect_fd(&c, HOST, fd, g_rnd, QUIC_API_NOW, &q) == BRISK_OK && q != NULL);
    if (q != NULL) {
        CHECK(brisk_quic_stream_open(q, 1) == 0 &&
              brisk_quic_stream_write(q, 0, "GET /\r\n", 7, 1) == 7);
        CHECK(brisk_quic_stream_read(q, 0, buf, sizeof buf, &err) == 2 && buf[0] == 'h' &&
              brisk_quic_stream_read(q, 0, buf, sizeof buf, &err) == 0);
        t0 = brisk__os_mono_ms();
        CHECK(brisk_quic_poll(q, 50) == BRISK_OK && brisk__os_mono_ms() - t0 >= 50);
        CHECK(brisk_quic_close(q, 0) == BRISK_OK);
    }
    waitpid(pid, &st, 0);
    /* no answer: E_TIMEOUT within timeout_ms, *out NULL */
    CHECK(fork_server(B_SILENT, &fd, &pid));
    c.timeout_ms = 300;
    q = (brisk_quic *)1;
    t0 = brisk__os_mono_ms();
    CHECK(brisk__quic_connect_fd(&c, HOST, fd, g_rnd, QUIC_API_NOW, &q) == BRISK_E_TIMEOUT &&
          q == NULL && brisk__os_mono_ms() - t0 < 3000);
    waitpid(pid, &st, 0);
    /* an oversize datagram is dropped (MSG_TRUNC), never fed truncated */
    CHECK(fork_server(B_OVERSIZE, &fd, &pid));
    c.timeout_ms = 500;
    q = (brisk_quic *)1;
    CHECK(brisk__quic_connect_fd(&c, HOST, fd, g_rnd, QUIC_API_NOW, &q) == BRISK_E_TIMEOUT &&
          q == NULL);
    waitpid(pid, &st, 0);
    /* RFC 9001 8.1 before anything else */
    c.alpn = NULL;
    CHECK(brisk_quic_connect(&c, "localhost", 443, &q) == BRISK_E_ARG && q == NULL);
    CHECK(brisk_quic_init(g_mem, g_size, &c, HOST, &q) == BRISK_E_ARG && q == NULL);
    c.alpn = "hq-interop";
    CHECK(brisk_quic_init(g_mem, g_size, &c, HOST, &q) == BRISK_OK && q != NULL &&
          brisk_quic_pull(q, g_d, 1600, 0) == 1200 && brisk_quic_poll(q, 10) == BRISK_E_WANT &&
          brisk_quic_poll(NULL, 10) == BRISK_E_ARG);
    brisk_quic_wipe(q);
}

/* RFC 9000 14.2.1 / 21: a (forged) ICMP error only loses a datagram. The kernel reports one on
 * the connected socket as EMSGSIZE (Fragmentation Needed), EHOSTUNREACH, EACCES ... - none may
 * end the connection. And PMTUDISC_PROBE: a forged PMTU below 1200 never reaches our sends. */
static void test_udp_errors(void)
{
    static const int lost[] = {EAGAIN,      EWOULDBLOCK,  EINTR,        ENOBUFS,    EMSGSIZE,
                               ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, EACCES,     ENOPROTOOPT,
                               EHOSTDOWN,   ENETDOWN,     EPERM,        ECONNRESET, ENOMEM};
    static const int fatal[] = {EBADF, ENOTSOCK, EFAULT, EINVAL, EDESTADDRREQ, ENOTCONN};
    size_t i;
    int fd = -1, v = -1;
    socklen_t vl = sizeof v;
    for (i = 0; i < sizeof lost / sizeof lost[0]; i++) {
        CHECKI(brisk__os_udp_fatal(lost[i]) == 0, (int)i);
    }
    for (i = 0; i < sizeof fatal / sizeof fatal[0]; i++) {
        CHECKI(brisk__os_udp_fatal(fatal[i]) == 1, (int)i);
    }
    CHECK(brisk__os_udp_connect("127.0.0.1", 9, &fd) == BRISK_OK && fd >= 0);
    if (fd >= 0) {
        CHECK(getsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v, &vl) == 0 && v == IP_PMTUDISC_PROBE);
        close(fd);
    }
}
#    endif

void test_quic_api(void)
{
    g_root_len = t_unhex(QUIC_API_ROOT, g_root, sizeof g_root);
    t_unhex(QUIC_API_RND, g_rnd, sizeof g_rnd);
    g_size = brisk_quic_size();
    g_mem = (uint8_t *)malloc(g_size + 16);
    if (g_mem == NULL) {
        CHECK(0);
        return;
    }
    test_init();
    test_handshake();
    test_resumption();
    test_streams();
    test_recycle();
    test_slots_busy();
    test_close();
    test_wipe();
    test_seams();
#    ifdef __linux__
    test_blocking();
    test_udp_errors();
#    endif
    free(g_mem);
}

#else
void test_quic_api(void)
{
    CHECK(1);
}
#endif
