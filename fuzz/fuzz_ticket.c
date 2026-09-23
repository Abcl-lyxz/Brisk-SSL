/* fuzz_ticket.c - libFuzzer / AFL++ entry point for the resumption ticket blob parser.
 *
 *   python tools/dev.py fuzz ticket    # clang + ASan/UBSan, seeded from tls13_ticket_fuzz.inc
 *
 * brisk__tls13_ticket_import is the one parser of bytes the caller stored (flash, a file), so it
 * is hostile input. The oracle: the verdict is BRISK_OK or BRISK_E_ARG; an accepted blob's
 * identity lies inside the input and its PSK has the suite's HashLen; a refused one leaves the
 * output all zero. Accepted blobs must also survive an export -> import round trip unchanged.
 * The SNI is fixed ("server", the seed's) and the clock sits 5 s after the seed's issue time.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t blob[BRISK_TICKET_MAX];
    brisk__tls13_psk p;
    brisk__tls13_ticket t;
    const uint8_t *z;
    size_t i, n;
    int64_t now = 1758600005000LL;
    int rc = brisk__tls13_ticket_import(data, size, "server", 6, now, &p);

    if (rc != BRISK_OK) {
        if (rc != BRISK_E_ARG) {
            abort();
        }
        for (z = (const uint8_t *)&p, i = 0; i < sizeof p; i++) {
            if (z[i] != 0) {
                abort();
            }
        }
        return 0;
    }
    if (p.identity < data || p.identity + p.identity_len != data + size || p.identity_len == 0 ||
        (p.psk_len != 32 && p.psk_len != 48)) {
        abort();
    }
    /* round trip: re-issued at `now`, everything after issued_ms must come back unchanged */
    memset(&t, 0, sizeof t);
    t.lifetime = brisk__load_be32(data + 11);
    t.age_add = brisk__load_be32(data + 15);
    t.ticket = p.identity;
    t.ticket_len = p.identity_len;
    memcpy(t.psk, p.psk, p.psk_len);
    t.psk_len = p.psk_len;
    t.suite = p.suite;
    /* the blob's own SNI bytes, which may differ from "server" in case only */
    if (brisk__tls13_ticket_export(&t, now, (const char *)data + 21 + p.psk_len,
                                   data[20 + p.psk_len], blob, sizeof blob, &n) != BRISK_OK ||
        n != size || memcmp(blob + 11, data + 11, size - 11) != 0) {
        abort();
    }
    return 0;
}
