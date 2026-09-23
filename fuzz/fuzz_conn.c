/* fuzz_conn.c - libFuzzer / AFL++ entry point for the public connection (src/tls/conn.c).
 *
 *   python tools/dev.py fuzz conn    # clang + ASan/UBSan, seeded from tls13_conn_fuzz.inc
 *
 * Every run is a fresh brisk__conn_setup with the fixture's randomness, clock and in-memory
 * anchor (tools/kat.py tls13_conn), so the seeds - whole server streams: [HRR] SH in the clear,
 * EE..SF under s_hs - drive a real handshake, HRR -> CH2 rebuilt in the receive buffer, the
 * record-at-a-time feeding before the ServerHello, the certificate check and the client flight.
 * The first input octet is the feed chunk size (0 = everything at once); the rest is the
 * server's byte stream, fed through brisk_feed with brisk_pull / brisk_app_read in between.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#include "brisk_int.h"

struct tls13_fuzz_seed {
    const char *hex, *note;
};
#include "../tests/kat/tls13_conn_fuzz.inc"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int nib(char c)
{
    return c <= '9' ? c - '0' : c - 'a' + 10;
}

static void unhex(const char *h, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)(nib(h[2 * i]) << 4 | nib(h[2 * i + 1]));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t *mem, rnd[BRISK__CONN_RAND], root[2048], out[4096], rd[512];
    static size_t root_len, mem_len;
    brisk_cfg cfg = BRISK_DEFAULTS;
    brisk_conn *c;
    size_t chunk, k, used, n;
    int rc = BRISK_OK, first_err = 0;

    if (mem == NULL) {
        mem_len = brisk_conn_size();
        mem = (uint8_t *)malloc(mem_len);
        root_len = (sizeof TLS13_CONN_FUZZ_ROOT - 1) / 2;
        if (mem == NULL || root_len > sizeof root) {
            abort();
        }
        unhex(TLS13_CONN_FUZZ_RND, rnd, sizeof rnd);
        unhex(TLS13_CONN_FUZZ_ROOT, root, root_len);
        (void)TLS13_CONN_FUZZ_SEED;
    }
    if (size < 1) {
        return 0;
    }
    cfg.ca_mem = root;
    cfg.ca_mem_len = root_len;
    if (brisk__conn_setup(mem, mem_len, &cfg, "device.example.com", TLS13_CONN_FUZZ_NOW_MS, rnd,
                          NULL, &c) != BRISK_OK) {
        abort();
    }
    chunk = data[0] != 0 ? data[0] : size;
    data++;
    size--;
    while (brisk_pull(c, out, sizeof out) != 0) {
    }
    while (size != 0) {
        k = chunk < size ? chunk : size;
        rc = brisk_feed(c, data, k, &used);
        if (used > k) {
            abort();
        }
        if (first_err != 0 && rc != first_err) {
            abort(); /* failure must be sticky */
        }
        if (rc != BRISK_OK) {
            first_err = rc;
        }
        data += used;
        size -= used;
        while (brisk_pull(c, out, sizeof out) != 0) {
        }
        while (brisk_app_read(c, rd, sizeof rd, &n) == BRISK_OK && n != 0) {
        }
        if (rc != BRISK_OK || used == 0) {
            break;
        }
    }
    if (brisk_status(c) == BRISK_OK) {
        brisk_app_write(c, rd, 16, &used, out, sizeof out, &n);
        brisk_close_notify(c);
        brisk_pull(c, out, sizeof out);
    }
    brisk_conn_wipe(c);
    return 0;
}
