/* fuzz_tls13_rec.c - libFuzzer / AFL++ entry point for the TLS 1.3 record layer + connection.
 *
 *   python tools/dev.py fuzz tls13_rec    # clang + ASan/UBSan, seeded from tls13_rec_fuzz.inc
 *
 * The connection starts CONNECTED with RFC 8448 sect 3's server application traffic secret as
 * its receive key (and, so alerts and KeyUpdate answers get sealed, as its send key too). The
 * first input octet is the feed chunk size (0 = everything at once); the rest is the server's
 * byte stream: framing, deprotection, the inner-plaintext scan, post-handshake messages,
 * alerts and KeyUpdate are all reachable from the seeds (NST, app data, close_notify). What is
 * hunted is the length arithmetic in the receive buffer; ASan's redzones do the real work.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#include "brisk_int.h"

struct tls13_fuzz_seed {
    const char *hex, *note;
};
#include "../tests/kat/tls13_rec_fuzz.inc"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int yes(void *ctx, uint16_t version, const brisk__x509_cert *certs, size_t n_certs,
               uint16_t scheme, const uint8_t *tbs, size_t tbs_len, const uint8_t *sig,
               size_t sig_len, uint8_t *alert)
{
    (void)version;
    (void)ctx;
    (void)certs;
    (void)n_certs;
    (void)scheme;
    (void)tbs;
    (void)tbs_len;
    (void)sig;
    (void)sig_len;
    (void)alert;
    return BRISK_OK;
}

static int nib(char c)
{
    return c <= '9' ? c - '0' : c - 'a' + 10;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t *scratch, *rec_in, out[BRISK__TLS_REC_IN_MAX + 64], rd[4096];
    static brisk__tls13_hs hs;
    static brisk__tls13_conn c;
    brisk__tls13_hs_cfg cfg = {NULL, NULL, yes, NULL, 0, NULL, NULL, NULL, NULL};
    uint8_t s_ap[32];
    size_t i, chunk, k, used, n;
    int rc = BRISK_OK, first_err = 0;

    if (scratch == NULL) {
        scratch = (uint8_t *)malloc(brisk__tls13_hs_scratch_size());
        rec_in = (uint8_t *)malloc(BRISK__TLS_REC_IN_MAX);
        if (scratch == NULL || rec_in == NULL) {
            abort();
        }
    }
    if (size < 1) {
        return 0;
    }
    for (i = 0; i < 32; i++) {
        s_ap[i] =
            (uint8_t)(nib(TLS13_REC_FUZZ_S_AP[2 * i]) << 4 | nib(TLS13_REC_FUZZ_S_AP[2 * i + 1]));
    }
    if (brisk__tls13_hs_init(&hs, &cfg, scratch, brisk__tls13_hs_scratch_size()) != BRISK_OK ||
        brisk__tls13_conn_init(&c, &hs, rec_in, BRISK__TLS_REC_IN_MAX) != BRISK_OK ||
        brisk__tls_dir_init(&c.rd, BRISK__EPOCH_APP, 0x1301, s_ap, 32) != BRISK_OK ||
        brisk__tls_dir_init(&c.wr, BRISK__EPOCH_APP, 0x1301, s_ap, 32) != BRISK_OK) {
        abort();
    }
    hs.state = BRISK__HS_CONNECTED; /* harness shortcut: skip the handshake */
    hs.in_epoch = BRISK__EPOCH_APP;
    chunk = data[0] != 0 ? data[0] : size;
    data++;
    size--;
    while (size != 0) {
        k = chunk < size ? chunk : size;
        rc = brisk__tls13_conn_feed(&c, data, k, &used);
        if (used > k || c.in_len > c.in_cap || c.app_off + c.app_len > c.in_cap) {
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
        do {
            brisk__tls13_conn_read(&c, rd, sizeof rd, &n);
        } while (n != 0);
        if (rc != BRISK_OK || (used == 0 && c.app_len == 0)) {
            break;
        }
    }
    while (brisk__tls13_conn_pull(&c, out, sizeof out) != 0) {
    }
    if (rc == BRISK_OK && !c.eof) {
        brisk__tls13_conn_write(&c, s_ap, sizeof s_ap, &used, out, sizeof out, &n);
    }
    brisk__tls13_conn_wipe(&c);
    return 0;
}
