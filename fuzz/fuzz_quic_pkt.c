/* fuzz_quic_pkt.c - libFuzzer / AFL++ entry point for QUIC v1 datagrams (M6).
 *
 *   python tools/dev.py fuzz quic_pkt    # clang + ASan/UBSan, seeded from quic_pkt.inc
 *
 * The input is one UDP datagram. Every coalesced packet goes through brisk__quic_hdr_parse (both
 * 0- and 8-byte short-header DCIDs), then brisk__quic_open under the RFC 9001 A.1 Initial keys
 * (client and server side, so the A.2 / A.3 seeds decrypt), then - when it opens - the frame
 * parser at every level. What is hunted is the length arithmetic: Length vs the datagram, the
 * sample offset, the PN length, varints, CRYPTO / STREAM / ACK bounds. Then the same bytes go in
 * as the 1-RTT frames of an established connection (stateful(): streams, flow control, CIDs,
 * ACKs against sent packets), with reads, writes and a send after them.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#ifndef BRISK_ENABLE_QUIC
#    define BRISK_ENABLE_QUIC 1 /* FULL only; dev.py passes the same -D to src/quic/ */
#endif
#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* The stateful half (M6 item 2): the input as the 1-RTT frames of an established connection -
 * stream state and limits, flow control, final sizes, NEW_CONNECTION_ID / retire, ACK ranges
 * against sent records, PATH_CHALLENGE - then a read, a write and a send so the replies
 * (RESET_STREAM, MAX_*, RETIRE, PATH_RESPONSE, ACK) are built too. The engine is a zeroed
 * brisk__tls13_hs: nothing here needs the handshake. Aborts when the flow-control memory
 * invariant (stream.c) breaks. */
static void stateful(const uint8_t *data, size_t size)
{
    static brisk__tls13_hs hs;
    static brisk__quic_conn q;
    static uint8_t *scratch, out[1500], rd[256];
    static const uint8_t SCID[8] = {1, 2, 3, 4, 5, 6, 7, 8}, SECRET[32] = {9};
    static const uint8_t DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    brisk__quic_tp tp;
    uint64_t err, id;
    unsigned i;
    if (scratch == NULL && (scratch = (uint8_t *)malloc(brisk__quic_scratch_size())) == NULL) {
        abort();
    }
    memset(&hs, 0, sizeof hs);
    hs.cfg.quic = 1;
    brisk__quic_tp_default(&tp); /* the test suite's client parameters */
    tp.max_idle_timeout = 30000;
    tp.initial_max_data = 8192;
    tp.initial_max_stream_data_bidi_local = 4096;
    tp.initial_max_stream_data_uni = 4096;
    tp.initial_max_streams_uni = 2;
    memcpy(tp.iscid, SCID, 8);
    tp.iscid_len = 8;
    if (brisk__quic_conn_init(&q, &hs, &tp, DCID, 8, SCID, 8, scratch,
                              brisk__quic_scratch_size()) != BRISK_OK ||
        brisk__quic_keys_init(&q.tx[2], 0x1301, SECRET, 32) != BRISK_OK) {
        abort();
    }
    q.peer_tp.initial_max_data = 1u << 20;
    q.peer_tp.initial_max_stream_data_bidi_remote = 65536;
    q.peer_tp.initial_max_streams_bidi = 4;
    q.peer_tp.initial_max_streams_uni = 4;
    q.established = q.confirmed = 1;
    q.dcid_len = 8;
    q.cids[0].used = 1;
    q.cids[0].len = 8;
    memcpy(q.cids[0].cid, q.dcid, 8);
    brisk__quic_streams_init(&q);
    (void)brisk__quic_stream_open(&q, 1);
    (void)brisk__quic_stream_write(&q, 0, (const uint8_t *)"GET /", 5, 1);
    for (i = 0; i < 3; i++) { /* three records in flight for ACK frames to hit */
        (void)brisk__quic_send(&q, out, sizeof out, (int64_t)i);
        (void)brisk__quic_stream_write(&q, 0, (const uint8_t *)"x", 1, 0);
    }
    (void)brisk__quic_frames(&q, 2, data, size);
    for (i = 0; i < BRISK_QUIC_MAX_STREAMS; i++) {
        const brisk__quic_stream *st = &q.st[i];
        if (st->flags != 0 &&
            (st->rx_max > st->rx_read + BRISK_QUIC_STREAM_BUF || st->rx_hi > st->rx_max)) {
            abort();
        }
        if (st->flags != 0) {
            (void)brisk__quic_stream_read(&q, st->id, rd, sizeof rd, &err);
        }
    }
    while (brisk__quic_stream_accept(&q, &id) == BRISK_OK) {
        (void)brisk__quic_stream_read(&q, id, rd, sizeof rd, &err);
    }
    if (q.max_data_rx > q.consumed + tp.initial_max_data) {
        abort();
    }
    (void)brisk__quic_send(&q, out, sizeof out, 100);
    (void)brisk__quic_deadline(&q);
    brisk__quic_keys_wipe(&q.tx[2]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    static brisk__quic_keys keys[2];
    static int ready;
    brisk__quic_hdr h;
    uint8_t *buf, *pkt, c[32], s[32], first;
    uint64_t pn;
    size_t off, po, pl, k, sl;
    if (!ready) {
        if (brisk__quic_initial_secrets(DCID, 8, c, s) != BRISK_OK ||
            brisk__quic_keys_init(&keys[0], 0x1301, c, 32) != BRISK_OK ||
            brisk__quic_keys_init(&keys[1], 0x1301, s, 32) != BRISK_OK) {
            abort();
        }
        ready = 1;
    }
    buf = (uint8_t *)malloc(size ? size : 1);
    pkt = (uint8_t *)malloc(size ? size : 1);
    if (buf == NULL || pkt == NULL) {
        abort();
    }
    for (sl = 0; sl <= 8; sl += 8) {
        memcpy(buf, data, size);
        off = 0;
        while (off < size && brisk__quic_hdr_parse(buf + off, size - off, sl, &h) == BRISK_OK) {
            if (h.pkt_len == 0 || h.pkt_len > size - off) {
                abort(); /* the parser promised a length inside the datagram */
            }
            if (h.type == BRISK__QPKT_1RTT || (h.version == BRISK__QUIC_V1 && h.type != 3)) {
                for (k = 0; k < 2; k++) {
                    memcpy(pkt, buf + off, h.pkt_len);
                    if (brisk__quic_open(&keys[k], pkt, h.pn_off, h.pkt_len, UINT64_MAX, &first,
                                         &pn, &po, &pl) == BRISK_OK) {
                        if (po + pl + 16 != h.pkt_len) {
                            abort();
                        }
                        (void)brisk__quic_frames(NULL, 0, pkt + po, pl);
                        (void)brisk__quic_frames(NULL, 2, pkt + po, pl);
                    }
                }
            }
            (void)brisk__quic_frames(NULL, 2, buf + off, h.pkt_len); /* the parser on raw bytes */
            off += h.pkt_len;
        }
    }
    free(buf);
    free(pkt);
    stateful(data, size);
    return 0;
}
