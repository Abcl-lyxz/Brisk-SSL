/* fuzz_tls13_hs.c - libFuzzer / AFL++ entry point for the TLS 1.3 handshake engine.
 *
 *   python tools/dev.py fuzz tls13_hs    # clang + ASan/UBSan, seeded from tls13_trace.inc
 *
 * A fixed ClientHello (built here with brisk__tls13_ch_write, x25519 share) is absorbed, then the
 * input is the server's byte stream: the first octet says how many of the rest go in at INITIAL
 * (the ServerHello), everything after that is fed at HANDSHAKE in chunks whose sizes also come
 * from the input, so reassembly across feed() calls is fuzzed together with the parsers. The
 * authenticator says yes to everything, so the Certificate, CertificateVerify and Finished
 * parsers are all reachable; the Finished MAC itself cannot be forged, which is fine - what is
 * hunted here is the length arithmetic, and ASan's redzones do the real work.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int yes(void *ctx, const brisk__x509_cert *certs, size_t n_certs, uint16_t scheme,
               const uint8_t *tbs, size_t tbs_len, const uint8_t *sig, size_t sig_len,
               uint8_t *alert)
{
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t *scratch;
    static brisk__tls13_hs hs;
    uint8_t ch[512], priv[32], pub[32], rnd[32], out[256];
    brisk__tls13_hs_cfg cfg = {NULL, NULL, yes, NULL, 0, NULL, NULL, NULL, NULL};
    brisk__tls13_ch_params p;
    size_t ch_len, first, chunk;
    unsigned epoch;
    int rc;

    if (scratch == NULL) {
        scratch = (uint8_t *)malloc(brisk__tls13_hs_scratch_size());
        if (scratch == NULL) {
            abort();
        }
    }
    if (size < 1) {
        return 0;
    }
    memset(priv, 0x42, sizeof priv);
    memset(rnd, 0x17, sizeof rnd);
    brisk__x25519_base(pub, priv);
    memset(&p, 0, sizeof p);
    p.random = rnd;
    p.share_group = 0x001d;
    p.share_pub = pub;
    p.share_pub_len = sizeof pub;
    p.sni = "device.example.com";
    p.sni_len = 18;
    if (brisk__tls13_ch_write(&p, ch, sizeof ch, &ch_len) != BRISK_OK ||
        brisk__tls13_hs_init(&hs, &cfg, scratch, brisk__tls13_hs_scratch_size()) != BRISK_OK ||
        brisk__tls13_hs_client_hello(&hs, ch, ch_len, 0x001d, priv) != BRISK_OK) {
        abort();
    }
    first = data[0];
    data++;
    size--;
    if (first > size) {
        first = size;
    }
    rc = brisk__tls13_hs_feed(&hs, BRISK__EPOCH_INITIAL, data, first);
    data += first;
    size -= first;
    while (rc == BRISK_OK && size != 0) {
        chunk = 1 + (size_t)(data[0] & 0x3f) * 37; /* 1..2332 bytes per call */
        if (chunk > size) {
            chunk = size;
        }
        rc = brisk__tls13_hs_feed(&hs, BRISK__EPOCH_HANDSHAKE, data, chunk);
        data += chunk;
        size -= chunk;
    }
    while (brisk__tls13_hs_pull(&hs, &epoch, out, sizeof out) != 0) {
    }
    if (rc != BRISK_OK && rc != BRISK_E_PROTO && rc != BRISK_E_AUTH) {
        abort();
    }
    if (rc != BRISK_OK && (hs.state != BRISK__HS_FAILED || hs.alert == 0)) {
        abort(); /* every failure names an alert */
    }
    brisk__tls13_hs_wipe(&hs);
    return 0;
}
