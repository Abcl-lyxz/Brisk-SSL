/* test_hash.c - SHA-2, HMAC, HKDF, HKDF-Expand-Label against official vectors (tests/kat/SOURCES.md).
 * Every vector also runs with unaligned input/output buffers and split/streamed updates, which is
 * where byte-order, alignment and buffering bugs show up on MIPS/ARM/PPC under qemu. */
#include <stdio.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

struct hash_kat {
    int bits;
    const char *msg, *md;
};
struct monte_kat {
    int bits;
    const char *seed;
    const char *md[100];
};
struct million_kat {
    int bits;
    const char *md;
};
struct hmac_kat {
    int bits;
    const char *key, *msg, *tag;
    int valid;
};
struct hkdf_kat {
    int bits;
    const char *ikm, *salt, *info;
    size_t size;
    const char *okm;
    int valid;
    const char *prk; /* "" when the source gives no PRK */
};
struct extract_kat {
    int bits;
    const char *salt, *ikm, *prk;
};
struct label_kat {
    int bits;
    const char *secret, *label, *ctx, *out;
};

#include "kat/sha2.inc"
#include "kat/sha2_monte.inc"
#include "kat/sha2_million.inc"
#include "kat/hmac.inc"
#include "kat/hkdf.inc"
#include "kat/hkdf_extract.inc"
#include "kat/expand_label.inc"

#define N(a) (sizeof(a) / sizeof((a)[0]))
#define BUF  20000 /* largest vector: 255 * 64 byte HKDF output */

static uint8_t A[BUF + 16], B[BUF + 16], C[BUF + 16], D[BUF + 16];

static brisk_hash_alg alg_of(int bits)
{
    return bits == 256 ? BRISK_HASH_SHA256 : bits == 384 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA512;
}

static void hash_oneshot(int bits, const uint8_t *m, size_t n, uint8_t *out)
{
    if (bits == 256) {
        brisk_sha256(m, n, out);
    } else if (bits == 384) {
        brisk_sha384(m, n, out);
    } else {
        brisk_sha512(m, n, out);
    }
}

/* generic dispatch, two updates split at k */
static void hash_split(int bits, const uint8_t *m, size_t n, size_t k, uint8_t *out)
{
    brisk_hash_ctx c;
    brisk_hash_alg a = alg_of(bits);
    brisk__hash_init(&c, a);
    brisk__hash_update(&c, a, m, k);
    brisk__hash_update(&c, a, m + k, n - k);
    brisk__hash_final(&c, a, out);
}

static void hash_bytewise(int bits, const uint8_t *m, size_t n, uint8_t *out)
{
    brisk_hash_ctx c;
    brisk_hash_alg a = alg_of(bits);
    size_t i;
    brisk__hash_init(&c, a);
    for (i = 0; i < n; i++) {
        brisk__hash_update(&c, a, m + i, 1);
    }
    brisk__hash_final(&c, a, out);
}

static void sha2_kat(void)
{
    static const size_t cuts[] = {1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129};
    size_t i, k, n, hl, off;
    for (i = 0; i < N(SHA2_KAT); i++) {
        const struct hash_kat *v = &SHA2_KAT[i];
        uint8_t *m = A + (off = i % 8), *out = B + (7 - off); /* every alignment, in and out */
        n = t_unhex(v->msg, m, BUF);
        hl = t_unhex(v->md, C, BUF);
        hash_oneshot(v->bits, m, n, out);
        CHECKI(memcmp(out, C, hl) == 0, i);
        if (n <= 300) {
            for (k = 0; k <= n; k++) {
                hash_split(v->bits, m, n, k, out);
                CHECKI(memcmp(out, C, hl) == 0, i);
            }
            if (i % 16 == 0) {
                hash_bytewise(v->bits, m, n, out);
                CHECKI(memcmp(out, C, hl) == 0, i);
            }
        } else {
            for (k = 0; k < N(cuts); k++) {
                hash_split(v->bits, m, n, cuts[k], out);
                CHECKI(memcmp(out, C, hl) == 0, i);
            }
        }
    }
}

/* NIST SHAVS 6.4 Monte Carlo: MD_i = H(MD_{i-3} || MD_{i-2} || MD_{i-1}), 1000 steps per checkpoint */
static void sha2_monte(void)
{
    size_t i, j, it, hl;
    uint8_t md[4][BRISK_HASH_MAX_LEN], m[3 * BRISK_HASH_MAX_LEN], want[BRISK_HASH_MAX_LEN];
    for (i = 0; i < N(SHA2_MONTE); i++) {
        const struct monte_kat *v = &SHA2_MONTE[i];
        hl = t_unhex(v->seed, md[2], sizeof md[2]);
        for (j = 0; j < 100; j++) {
            memcpy(md[0], md[2], hl);
            memcpy(md[1], md[2], hl);
            for (it = 0; it < 1000; it++) {
                memcpy(m, md[0], hl);
                memcpy(m + hl, md[1], hl);
                memcpy(m + 2 * hl, md[2], hl);
                hash_oneshot(v->bits, m, 3 * hl, md[3]);
                memcpy(md[0], md[1], hl);
                memcpy(md[1], md[2], hl);
                memcpy(md[2], md[3], hl);
            }
            t_unhex(v->md[j], want, sizeof want);
            CHECKI(memcmp(md[2], want, hl) == 0, j);
        }
    }
}

/* FIPS 180-4 example: one million 'a', fed in irregular chunk sizes */
static void sha2_million(void)
{
    size_t i, done, chunk;
    uint8_t out[BRISK_HASH_MAX_LEN], want[BRISK_HASH_MAX_LEN];
    memset(A, 'a', 1024); /* chunk sizes below reach 1003 */
    for (i = 0; i < N(SHA2_MILLION); i++) {
        brisk_hash_ctx c;
        brisk_hash_alg a = alg_of(SHA2_MILLION[i].bits);
        size_t hl = t_unhex(SHA2_MILLION[i].md, want, sizeof want);
        brisk__hash_init(&c, a);
        for (done = 0, chunk = 1; done < 1000000; done += chunk, chunk = chunk % 997 + 7) {
            if (chunk > 1000000 - done) {
                chunk = 1000000 - done;
            }
            brisk__hash_update(&c, a, A, chunk);
        }
        brisk__hash_final(&c, a, out);
        CHECKI(memcmp(out, want, hl) == 0, i);
    }
}

static void hmac_kat(void)
{
    size_t i, kl, ml, tl, off;
    for (i = 0; i < N(HMAC_KAT); i++) {
        const struct hmac_kat *v = &HMAC_KAT[i];
        brisk_hash_alg a = alg_of(v->bits);
        uint8_t *key = A + (off = i % 8), *msg = B + (7 - off), *out = D + off;
        brisk_hmac_ctx c;
        kl = t_unhex(v->key, key, BUF);
        ml = t_unhex(v->msg, msg, BUF);
        tl = t_unhex(v->tag, C, BUF);
        CHECKI(brisk_hmac(a, key, kl, msg, ml, out) == BRISK_OK, i);
        CHECKI((memcmp(out, C, tl) == 0) == v->valid, i);
        /* streamed in two parts */
        CHECKI(brisk_hmac_init(&c, a, key, kl) == BRISK_OK, i);
        brisk_hmac_update(&c, msg, ml / 3);
        brisk_hmac_update(&c, msg + ml / 3, ml - ml / 3);
        brisk_hmac_final(&c, out);
        CHECKI((memcmp(out, C, tl) == 0) == v->valid, i);
    }
}

static void hkdf_kat(void)
{
    size_t i, il, sl, nl, ol, pl;
    uint8_t prk[BRISK_HASH_MAX_LEN], want_prk[BRISK_HASH_MAX_LEN];
    for (i = 0; i < N(HKDF_KAT); i++) {
        const struct hkdf_kat *v = &HKDF_KAT[i];
        brisk_hash_alg a = alg_of(v->bits);
        size_t hl = brisk_hash_len(a);
        int rc;
        il = t_unhex(v->ikm, A, BUF);
        sl = t_unhex(v->salt, B, BUF);
        nl = t_unhex(v->info, C + 1, BUF); /* unaligned info */
        ol = t_unhex(v->okm, D + 8, BUF);  /* expected okm kept out of the way */
        CHECKI(brisk__hkdf_extract(a, B, sl, A, il, prk) == BRISK_OK, i);
        if (v->prk[0]) {
            pl = t_unhex(v->prk, want_prk, sizeof want_prk);
            CHECKI(pl == hl && memcmp(prk, want_prk, hl) == 0, i);
        }
        rc = brisk__hkdf_expand(a, prk, hl, C + 1, nl, A + 3, v->size);
        if (v->valid) {
            CHECKI(rc == BRISK_OK && ol == v->size && memcmp(A + 3, D + 8, ol) == 0, i);
        } else {
            CHECKI(rc != BRISK_OK || memcmp(A + 3, D + 8, ol) != 0, i);
        }
    }
}

static void extract_kat(void)
{
    size_t i, sl, il;
    uint8_t prk[BRISK_HASH_MAX_LEN], want[BRISK_HASH_MAX_LEN];
    for (i = 0; i < N(EXTRACT_KAT); i++) {
        const struct extract_kat *v = &EXTRACT_KAT[i];
        brisk_hash_alg a = alg_of(v->bits);
        sl = t_unhex(v->salt, A, BUF);
        il = t_unhex(v->ikm, B, BUF);
        t_unhex(v->prk, want, sizeof want);
        CHECKI(brisk__hkdf_extract(a, sl ? A : NULL, sl, B, il, prk) == BRISK_OK, i);
        CHECKI(memcmp(prk, want, brisk_hash_len(a)) == 0, i);
    }
}

static void label_kat(void)
{
    size_t i, sl, cl, ol;
    for (i = 0; i < N(LABEL_KAT); i++) {
        const struct label_kat *v = &LABEL_KAT[i];
        brisk_hash_alg a = alg_of(v->bits);
        sl = t_unhex(v->secret, A, BUF);
        cl = t_unhex(v->ctx, B + 3, BUF);
        ol = t_unhex(v->out, C, BUF);
        CHECKI(brisk__hkdf_expand_label(a, A, sl, v->label, B + 3, cl, D + 5, ol) == BRISK_OK, i);
        CHECKI(memcmp(D + 5, C, ol) == 0, i);
    }
}

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

static void edge_cases(void)
{
    static const char empty256[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    uint8_t out[BRISK_HASH_MAX_LEN], want[BRISK_HASH_MAX_LEN], prk[32];
    char label[256];
    brisk_sha256_ctx s;
    brisk_sha512_ctx s5;
    brisk_hmac_ctx h;

    /* NULL with zero length is a valid empty message */
    brisk_sha256(NULL, 0, out);
    t_unhex(empty256, want, sizeof want);
    CHECK(memcmp(out, want, 32) == 0);
    CHECK(brisk_hmac(BRISK_HASH_SHA256, NULL, 0, NULL, 0, out) == BRISK_OK);

    /* invalid algorithms */
    CHECK(brisk_hash_len((brisk_hash_alg)0) == 0);
    CHECK(brisk_hash_len((brisk_hash_alg)4) == 0);
    CHECK(brisk_hmac_init(&h, (brisk_hash_alg)7, "k", 1) == BRISK_E_ARG);
    CHECK(brisk_hmac((brisk_hash_alg)0, "k", 1, "m", 1, out) == BRISK_E_ARG);
    CHECK(brisk__hkdf_expand((brisk_hash_alg)9, want, 32, NULL, 0, out, 32) == BRISK_E_ARG);

    /* HKDF length limit: 255 * HashLen (RFC 5869 2.3) */
    memset(prk, 7, sizeof prk);
    CHECK(brisk__hkdf_expand(BRISK_HASH_SHA256, prk, 32, NULL, 0, A, 255 * 32) == BRISK_OK);
    CHECK(brisk__hkdf_expand(BRISK_HASH_SHA256, prk, 32, NULL, 0, A, 255 * 32 + 1) == BRISK_E_ARG);
    CHECK(brisk__hkdf_expand(BRISK_HASH_SHA256, prk, 32, NULL, 0, A, 0) == BRISK_OK);

    /* expand in place: out aliases prk */
    memcpy(B, prk, 32);
    CHECK(brisk__hkdf_expand(BRISK_HASH_SHA256, prk, 32, (const uint8_t *)"x", 1, C, 32) == BRISK_OK);
    CHECK(brisk__hkdf_expand(BRISK_HASH_SHA256, B, 32, (const uint8_t *)"x", 1, B, 32) == BRISK_OK);
    CHECK(memcmp(B, C, 32) == 0);

    /* HkdfLabel field limits (RFC 9846 7.1): "tls13 " + label <= 255, context <= 255 */
    memset(label, 'a', sizeof label);
    label[249] = '\0';
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, prk, 32, label, NULL, 0, out, 32) == BRISK_OK);
    label[249] = 'a';
    label[250] = '\0';
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, prk, 32, label, NULL, 0, out, 32) == BRISK_E_ARG);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, prk, 32, "key", A, 255, out, 16) == BRISK_OK);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, prk, 32, "key", A, 256, out, 16) == BRISK_E_ARG);

    /* final() wipes the context (it held message-derived state) */
    brisk_sha256_init(&s);
    brisk_sha256_update(&s, "secret", 6);
    brisk_sha256_final(&s, out);
    CHECK(all_zero(&s, sizeof s));
    brisk_sha384_init(&s5);
    brisk_sha384_update(&s5, "secret", 6);
    brisk_sha384_final(&s5, out);
    CHECK(all_zero(&s5, sizeof s5));
    CHECK(brisk_hmac_init(&h, BRISK_HASH_SHA512, "key", 3) == BRISK_OK);
    brisk_hmac_final(&h, out);
    CHECK(all_zero(&h, sizeof h));

    /* version / build info */
    CHECK(strcmp(brisk_version(), BRISK_SSL_VERSION_STRING) == 0);
    CHECK(strstr(brisk_build_info(), "profile=") != NULL);
}

void test_hash(void)
{
    sha2_kat();
    sha2_monte();
    sha2_million();
    hmac_kat();
    hkdf_kat();
    extract_kat();
    label_kat();
    edge_cases();
}
