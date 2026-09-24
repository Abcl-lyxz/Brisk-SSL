/* fuzz_quic_pkt.c - libFuzzer / AFL++ entry point for QUIC v1 datagrams (M6).
 *
 *   python tools/dev.py fuzz quic_pkt    # clang + ASan/UBSan, seeded from quic_pkt.inc
 *
 * The input is one UDP datagram. Every coalesced packet goes through brisk__quic_hdr_parse (both
 * 0- and 8-byte short-header DCIDs), then brisk__quic_open under the RFC 9001 A.1 Initial keys
 * (client and server side, so the A.2 / A.3 seeds decrypt), then - when it opens - the frame
 * parser at every level. What is hunted is the length arithmetic: Length vs the datagram, the
 * sample offset, the PN length, varints, CRYPTO / STREAM / ACK bounds.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#ifndef BRISK_ENABLE_QUIC
#    define BRISK_ENABLE_QUIC 1 /* FULL only; dev.py passes the same -D to src/quic/ */
#endif
#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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
    return 0;
}
