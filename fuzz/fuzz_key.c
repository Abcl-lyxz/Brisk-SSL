/* fuzz_key.c - libFuzzer / AFL++ entry point for the device key decoder (src/x509/key.c) and the
 * strict one-shot PEM decoder it shares with a PEM client_chain (src/x509/bundle.c).
 *
 *   python tools/dev.py fuzz key --seconds 60
 *
 * The input is cfg.client_key as-is. Oracles, besides memory safety and termination:
 *   - brisk__x509_p256_key: OK implies d is a valid scalar (keygen(d) succeeds); a failure
 *     leaves d all-zero; the same input parsed twice gives the same answer and the same d.
 *   - brisk__x509_pem_block over "CERTIFICATE" (the client_chain loop): the size pass (out NULL)
 *     counts exactly what the write pass writes and ends at the same offset, *off only moves
 *     forward and stays <= len, and the loop ends (every OK with a block moves *off).
 * Seeds: every key.inc row (tools/kat.py key_vectors), PEM text and DER alike, as hex.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t out[8192];

static int zero32(const uint8_t *p)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < 32; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t d1[32], d2[32], pub[65];
    size_t off = 0, off1, prev, n1, n2;
    int r1, r2;

    memset(d1, 0x5a, sizeof d1);
    memset(d2, 0xa5, sizeof d2);
    r1 = brisk__x509_p256_key(d1, data, size);
    r2 = brisk__x509_p256_key(d2, data, size);
    if ((r1 != BRISK_OK && r1 != BRISK_E_ARG) || r1 != r2 || memcmp(d1, d2, sizeof d1) != 0) {
        abort();
    }
    if (r1 == BRISK_OK ? brisk__p256_keygen(pub, d1) != BRISK_OK : !zero32(d1)) {
        abort();
    }
    for (;;) {
        prev = off;
        off1 = off;
        r1 = brisk__x509_pem_block(data, size, &off1, "CERTIFICATE", NULL, 0, &n1);
        r2 = brisk__x509_pem_block(data, size, &off, "CERTIFICATE", out, sizeof out, &n2);
        if (r2 != BRISK_OK) {
            if (n2 != 0) {
                abort();
            }
            break;
        }
        if (r1 != BRISK_OK || n1 != n2 || off1 != off || off > size || (n2 == 0 && off != size)) {
            abort();
        }
        if (n2 == 0) {
            break;
        }
        if (off <= prev) {
            abort(); /* a block always moves *off: the loop terminates */
        }
    }
    return 0;
}
