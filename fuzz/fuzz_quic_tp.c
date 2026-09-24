/* fuzz_quic_tp.c - libFuzzer / AFL++ entry point for QUIC transport parameters (RFC 9000 18).
 *
 *   python tools/dev.py fuzz quic_tp    # clang + ASan/UBSan, seeded from quic_tp.inc
 *
 * The input is a server's quic_transport_parameters extension_data. brisk__quic_tp_parse must
 * either accept it or zero the struct; what it accepts, minus the server-only parameters, must
 * write back through brisk__quic_tp_write and parse again to the same values.
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
    static const brisk__quic_tp ZERO;
    brisk__quic_tp tp, back;
    uint8_t out[512];
    size_t n;
    if (brisk__quic_tp_parse(data, size, &tp) != BRISK_OK) {
        if (memcmp(&tp, &ZERO, sizeof tp) != 0) {
            abort(); /* refused parameters leave nothing behind */
        }
        return 0;
    }
    tp.has_odcid = tp.has_retry_scid = tp.has_reset_token = tp.has_pref_addr = 0;
    memset(tp.odcid, 0, sizeof tp.odcid);
    memset(tp.retry_scid, 0, sizeof tp.retry_scid);
    memset(tp.reset_token, 0, sizeof tp.reset_token);
    tp.odcid_len = tp.retry_scid_len = 0;
    tp.has_iscid = 1; /* always written, so always parsed back */
    if (brisk__quic_tp_write(&tp, out, sizeof out, &n) != BRISK_OK ||
        brisk__quic_tp_parse(out, n, &back) != BRISK_OK || memcmp(&tp, &back, sizeof tp) != 0) {
        abort();
    }
    return 0;
}
