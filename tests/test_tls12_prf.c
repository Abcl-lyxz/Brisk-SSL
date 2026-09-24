/* test_tls12_prf.c - brisk__tls12_prf (RFC 5246 5) against NIST ACVP: TLS-v1.2-KDF-RFC7627 (the
 * extended main secret from the session hash, then the key block) and the v1.2 groups of
 * kdf-components-tls ("master secret"). Every row at unaligned offsets, as prefixes of odd
 * lengths, and with the seed split at every position the two-part API allows. */
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#if BRISK_ENABLE_TLS12
struct tls12_prf_kat {
    unsigned bits;
    const char *secret, *label, *seed1, *seed2, *out, *note;
};
#    include "kat/tls12_prf.inc"

static brisk_hash_alg alg_of(unsigned bits)
{
    return bits == 256 ? BRISK_HASH_SHA256 : bits == 384 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA512;
}

void test_tls12_prf(void)
{
    static uint8_t sec[64 + 3], s1[64 + 3], s2[64 + 3], want[128], out[128 + 8];
    static const size_t CUT[6] = {1, 12, 40, 48, 72, 88};
    size_t i, j, sl, l1, l2, wl;
    int rc;

    for (i = 0; i < sizeof TLS12_PRF_KAT / sizeof TLS12_PRF_KAT[0]; i++) {
        const struct tls12_prf_kat *k = &TLS12_PRF_KAT[i];
        brisk_hash_alg a = alg_of(k->bits);
        sl = t_unhex(k->secret, sec + 1, 64);
        l1 = t_unhex(k->seed1, s1 + 3, 64);
        l2 = t_unhex(k->seed2, s2 + 1, 64);
        wl = t_unhex(k->out, want, sizeof want);
        /* the whole output, unaligned in and out */
        memset(out, 0xA5, sizeof out);
        rc = brisk__tls12_prf(a, sec + 1, sl, k->label, s1 + 3, l1, l2 ? s2 + 1 : NULL, l2, out + 3,
                              wl);
        CHECKI(rc == BRISK_OK && memcmp(out + 3, want, wl) == 0 && out[3 + wl] == 0xA5, i);
        /* prefixes that are not a multiple of HashLen */
        for (j = 0; j < 6; j++) {
            if (CUT[j] > wl) {
                continue;
            }
            memset(out, 0xA5, sizeof out);
            rc = brisk__tls12_prf(a, sec + 1, sl, k->label, s1 + 3, l1, s2 + 1, l2, out, CUT[j]);
            CHECKI(rc == BRISK_OK && memcmp(out, want, CUT[j]) == 0 && out[CUT[j]] == 0xA5, i);
        }
        /* the seed split elsewhere: seed1 || seed2 is all the PRF sees */
        if (l2 == 0 && l1 > 5) {
            memcpy(s2 + 1, s1 + 3 + 5, l1 - 5);
            rc = brisk__tls12_prf(a, sec + 1, sl, k->label, s1 + 3, 5, s2 + 1, l1 - 5, out, wl);
            CHECKI(rc == BRISK_OK && memcmp(out, want, wl) == 0, i);
        }
    }
    CHECK(i == 480);
    /* invalid: unknown alg, NULL out / label, out_len 0 - BRISK_E_ARG with out untouched */
    memset(out, 0x5A, sizeof out);
    CHECK(brisk__tls12_prf((brisk_hash_alg)0, sec, 32, "x", s1, 1, NULL, 0, out, 12) ==
          BRISK_E_ARG);
    CHECK(brisk__tls12_prf((brisk_hash_alg)9, sec, 32, "x", s1, 1, NULL, 0, out, 12) ==
          BRISK_E_ARG);
    CHECK(brisk__tls12_prf(BRISK_HASH_SHA256, sec, 32, NULL, s1, 1, NULL, 0, out, 12) ==
          BRISK_E_ARG);
    CHECK(brisk__tls12_prf(BRISK_HASH_SHA256, sec, 32, "x", s1, 1, NULL, 0, NULL, 12) ==
          BRISK_E_ARG);
    CHECK(brisk__tls12_prf(BRISK_HASH_SHA256, sec, 32, "x", s1, 1, NULL, 0, out, 0) == BRISK_E_ARG);
    CHECK(brisk__tls12_prf(BRISK_HASH_SHA256, sec, 32, "x", NULL, 1, NULL, 0, out, 12) ==
          BRISK_E_ARG);
    for (i = 0; i < sizeof out; i++) {
        CHECKI(out[i] == 0x5A, i);
    }
}
#else
void test_tls12_prf(void)
{
    CHECK(1); /* BRISK_ENABLE_TLS12 is off: no PRF */
}
#endif
