/* test_tls12_rec.c - the TLS 1.2 AEAD record framing of src/tls/record.c (RFC 5246 6.2.3.3,
 * RFC 5288 3, RFC 7905 2): brisk__tls12_dir_init + brisk__tls_rec_seal / _open against the
 * generated rows of tests/kat/tls12_record.inc, at every buffer alignment, in place, and every
 * failure mode with its exact alert and the plaintext wiped. */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_TLS12
struct tls12_rec_kat {
    const char *name;
    unsigned suite;
    const char *key, *iv;
    unsigned long long seq;
    unsigned type;
    const char *payload, *record, *sha;
    int kind; /* 0 seal + open, 1 a 2^14 record (SHA-256 of it), 2 open only (explicit != seq) */
};
#    include "kat/tls12_record.inc"

#    define NREC (sizeof TLS12_REC_KAT / sizeof TLS12_REC_KAT[0])
static uint8_t buf[(1 << 14) + 2112], pay[(1 << 14) + 8], want[(1 << 14) + 64];

static int dir_of(brisk__tls_dir *d, const struct tls12_rec_kat *k, uint64_t seq)
{
    uint8_t key[32], iv[12];
    size_t kl = t_unhex(k->key, key, sizeof key), il = t_unhex(k->iv, iv, sizeof iv);
    int rc = brisk__tls12_dir_init(d, (uint16_t)k->suite, key, kl, iv, il);
    d->seq = seq;
    return rc;
}

static size_t payload_of(const struct tls12_rec_kat *k, uint8_t *p)
{
    size_t i;
    if (k->kind == 1) {
        for (i = 0; i < (1u << 14); i++) {
            p[i] = (uint8_t)i;
        }
        return 1u << 14;
    }
    return t_unhex(k->payload, p, sizeof pay);
}

static void rec_rows(void)
{
    brisk__tls_dir d;
    size_t i, off, pl, rl, n, len;
    uint8_t type, alert, h[32];

    for (i = 0; i < NREC; i++) {
        const struct tls12_rec_kat *k = &TLS12_REC_KAT[i];
        off = i & 7;
        pl = payload_of(k, pay);
        rl = k->kind == 1 ? 0 : t_unhex(k->record, want, sizeof want);
        if (k->kind != 2) { /* seal in place: in == out + 5 */
            CHECKI(dir_of(&d, k, k->seq) == BRISK_OK, i);
            memcpy(buf + off + 5, pay, pl);
            CHECKI(brisk__tls_rec_seal(&d, (uint8_t)k->type, 0x0303, buf + off + 5, pl, 0,
                                       buf + off, sizeof buf - off, &n) == BRISK_OK,
                   i);
            CHECKI(d.seq == k->seq + 1, i);
            if (k->kind == 1) {
                brisk_sha256(buf + off, n, h);
                t_unhex(k->sha, want, 32);
                CHECKI(memcmp(h, want, 32) == 0, i);
                rl = n;
                memcpy(want, buf + off, n);
            } else {
                CHECKI(n == rl && memcmp(buf + off, want, rl) == 0, i);
            }
            /* the GCM nonce_explicit on the wire is the sequence number (RFC 5288 3 MAY) */
            if (k->suite != 0xCCA8 && k->suite != 0xCCA9) {
                CHECKI(brisk__load_be32(buf + off + 5) == (uint32_t)(k->seq >> 32) &&
                           brisk__load_be32(buf + off + 9) == (uint32_t)k->seq,
                       i);
            }
        }
        /* open at another alignment */
        off = (i + 3) & 7;
        memcpy(buf + off, want, rl);
        CHECKI(dir_of(&d, k, k->seq) == BRISK_OK, i);
        CHECKI(brisk__tls_rec_open(&d, buf + off, rl, &type, &len, &alert) == BRISK_OK &&
                   type == k->type && len == pl && memcmp(buf + off + 5, pay, pl) == 0 &&
                   d.seq == k->seq + 1,
               i);
        brisk__tls_dir_wipe(&d);
    }
}

/* One mutated copy of a small row's record must fail with `want_alert`, content wiped. */
static int open_fails(const struct tls12_rec_kat *k, const uint8_t *rec, size_t rl, int alert_want,
                      int err_want)
{
    brisk__tls_dir d;
    uint8_t type, alert;
    size_t len, i;
    int rc, zero = 1;
    memcpy(buf, rec, rl);
    if (dir_of(&d, k, k->seq) != BRISK_OK) {
        return 0;
    }
    rc = brisk__tls_rec_open(&d, buf, rl, &type, &len, &alert);
    for (i = 5; i < rl && err_want == BRISK_E_AUTH; i++) {
        zero &= buf[i] == 0;
    }
    brisk__tls_dir_wipe(&d);
    return rc == err_want && alert == alert_want && zero;
}

static void rec_invalid(void)
{
    static uint8_t rec[(1 << 14) + 2100];
    brisk__tls_dir d;
    size_t i, rl, n, ex, j;
    uint8_t type, alert, key[32], iv[12];
    const struct tls12_rec_kat *k;

    for (i = 0; i < NREC; i++) {
        k = &TLS12_REC_KAT[i];
        if (k->kind != 0 || k->seq != 1 || k->type != 22) {
            continue;
        }
        ex = k->suite == 0xCCA8 || k->suite == 0xCCA9 ? 0 : 8;
        rl = t_unhex(k->record, rec, sizeof rec);
        /* 5288 3 / 6.2.3.3: every AEAD failure is bad_record_mac - tag, explicit nonce,
         * ciphertext, and each AAD field (type, version) */
        for (j = 0; j < 5; j++) {
            size_t at = j == 0   ? rl - 1
                        : j == 1 ? 5 + (ex ? 3 : 0)
                        : j == 2 ? 5 + ex + 2
                        : j == 3 ? 0
                                 : 2;
            if (j == 1 && ex == 0) {
                continue;
            }
            rec[at] ^= j == 3 ? 1 : 0x10;
            CHECKI(open_fails(k, rec, rl, BRISK__ALERT_BAD_RECORD_MAC, BRISK_E_AUTH), i * 8 + j);
            rec[at] ^= j == 3 ? 1 : 0x10;
        }
        /* the length (AAD): one byte shorter, header adjusted */
        brisk__store_be16(rec + 3, (uint32_t)(rl - 6));
        CHECKI(open_fails(k, rec, rl - 1, BRISK__ALERT_BAD_RECORD_MAC, BRISK_E_AUTH), i);
        /* too short to hold nonce_explicit + tag: the same bad_record_mac, never another code */
        brisk__store_be16(rec + 3, (uint32_t)(ex + 15));
        CHECKI(open_fails(k, rec, 5 + ex + 15, BRISK__ALERT_BAD_RECORD_MAC, BRISK_E_AUTH), i);
        brisk__store_be16(rec + 3, 0);
        CHECKI(open_fails(k, rec, 5, BRISK__ALERT_BAD_RECORD_MAC, BRISK_E_AUTH), i);
        /* 6.2.3: 2^14 + 2048 + 1 -> record_overflow; locally anything above 2^14 + 8 + 16 */
        memset(rec + 5, 0, (1 << 14) + 2049);
        brisk__store_be16(rec + 3, (1u << 14) + 2049);
        CHECKI(
            open_fails(k, rec, 5 + (1 << 14) + 2049, BRISK__ALERT_RECORD_OVERFLOW, BRISK_E_PROTO),
            i);
        brisk__store_be16(rec + 3, (uint32_t)((1u << 14) + ex + 17));
        CHECKI(open_fails(k, rec, 5 + (1 << 14) + ex + 17, BRISK__ALERT_RECORD_OVERFLOW,
                          BRISK_E_PROTO),
               i);
        /* 6.1: the receive sequence number never wraps */
        rl = t_unhex(k->record, rec, sizeof rec);
        memcpy(buf, rec, rl);
        CHECKI(dir_of(&d, k, UINT64_MAX) == BRISK_OK, i);
        CHECKI(brisk__tls_rec_open(&d, buf, rl, &type, &n, &alert) == BRISK_E_PROTO &&
                   alert == BRISK__ALERT_UNEXPECTED_MESSAGE && d.seq == UINT64_MAX,
               i);
        /* ... nor the send one: refused, nothing written, seq unchanged */
        memset(buf, 0x77, 64);
        CHECKI(brisk__tls_rec_seal(&d, 23, 0x0303, rec, 4, 0, buf, sizeof buf, &n) == BRISK_E_ARG &&
                   n == 0 && d.seq == UINT64_MAX && buf[0] == 0x77,
               i);
        /* no padding in TLS 1.2; no fragment above 2^14 (6.2.1) */
        d.seq = 0;
        CHECKI(brisk__tls_rec_seal(&d, 23, 0x0303, rec, 4, 1, buf, sizeof buf, &n) == BRISK_E_ARG,
               i);
        CHECKI(brisk__tls_rec_seal(&d, 23, 0x0303, pay, (1u << 14) + 1, 0, buf, sizeof buf, &n) ==
                   BRISK_E_ARG,
               i);
        /* a cap one byte short */
        CHECKI(brisk__tls_rec_seal(&d, 23, 0x0303, rec, 4, 0, buf, 5 + ex + 4 + 16 - 1, &n) ==
                   BRISK_E_ARG,
               i);
        /* 6.2.1: a zero-length handshake / alert / CCS fragment is unexpected_message; zero-length
         * application data is legal */
        CHECKI(brisk__tls_rec_seal(&d, 22, 0x0303, NULL, 0, 0, rec, sizeof rec, &rl) == BRISK_OK,
               i);
        d.seq = 0;
        CHECKI(brisk__tls_rec_open(&d, rec, rl, &type, &n, &alert) == BRISK_E_PROTO &&
                   alert == BRISK__ALERT_UNEXPECTED_MESSAGE,
               i);
        brisk__tls_dir_wipe(&d);
        /* dir_init: a TLS 1.3 suite, wrong key or iv lengths -> BRISK_E_ARG, d wiped */
        n = t_unhex(k->key, key, sizeof key);
        j = t_unhex(k->iv, iv, sizeof iv);
        memset(&d, 0x33, sizeof d);
        CHECKI(brisk__tls12_dir_init(&d, 0x1301, key, 16, iv, 12) == BRISK_E_ARG && d.suite == 0 &&
                   d.seq == 0,
               i);
        memset(&d, 0x33, sizeof d);
        CHECKI(brisk__tls12_dir_init(&d, (uint16_t)k->suite, key, n - 1, iv, j) == BRISK_E_ARG &&
                   d.suite == 0,
               i);
        CHECKI(brisk__tls12_dir_init(&d, (uint16_t)k->suite, key, n, iv, j + 1) == BRISK_E_ARG &&
                   d.suite == 0,
               i);
    }
}

void test_tls12_rec(void)
{
    rec_rows();
    rec_invalid();
}
#else
void test_tls12_rec(void)
{
    CHECK(1); /* BRISK_ENABLE_TLS12 is off */
}
#endif
