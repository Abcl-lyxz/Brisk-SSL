/* test_knobs.c - the brisk_config.h knobs. Algorithms (AESGCM, AES256, CHACHA, X25519,
 * P256_KX, RSA): the default ClientHello offers exactly the suites, groups and signature schemes
 * this build has, and every entry point refuses one it does not - a caller's own suite list, a
 * key share, a TLS 1.2 suite, the public AEAD. PEM / SYSTEM_CA: a trust source the build lacks is
 * BRISK_E_ARG at setup. Runs in every build: the normal suite checks the all-on build, and
 * `dev.py amalg` builds this file alone (-DT_KNOBS_MAIN) once per knob off,
 * where the replayed-transcript suites cannot run because the ClientHello bytes differ.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

#define N(a) (sizeof(a) / sizeof((a)[0]))

/* What each code point needs. Order is irrelevant here; handshake.c owns the preference. */
typedef struct {
    uint16_t id;
    int on;
} knob_row;

/* clang-format off */
static const knob_row SUITES[] = {
    {0x1301, BRISK_ENABLE_AESGCM},
    {0x1302, BRISK_ENABLE_AES256},
    {0x1303, BRISK_ENABLE_CHACHA},
    /* TLS 1.2 (offered only with BRISK_ENABLE_TLS12) */
    {0xC02B, BRISK_ENABLE_TLS12 && BRISK_ENABLE_AESGCM},
    {0xC02F, BRISK_ENABLE_TLS12 && BRISK_ENABLE_AESGCM && BRISK_ENABLE_RSA},
    {0xC02C, BRISK_ENABLE_TLS12 && BRISK_ENABLE_AES256},
    {0xC030, BRISK_ENABLE_TLS12 && BRISK_ENABLE_AES256 && BRISK_ENABLE_RSA},
    {0xCCA9, BRISK_ENABLE_TLS12 && BRISK_ENABLE_CHACHA},
    {0xCCA8, BRISK_ENABLE_TLS12 && BRISK_ENABLE_CHACHA && BRISK_ENABLE_RSA}};
/* clang-format on */
static const knob_row GROUPS[] = {{0x001d, BRISK_ENABLE_X25519}, {0x0017, BRISK_ENABLE_P256_KX}};
static const knob_row SIGS[] = {{0x0403, 1},
                                {0x0503, BRISK_ENABLE_P384},
                                {0x0804, BRISK_ENABLE_RSA},
                                {0x0805, BRISK_ENABLE_RSA},
                                {0x0806, BRISK_ENABLE_RSA},
                                {0x0401, BRISK_ENABLE_RSA},
                                {0x0501, BRISK_ENABLE_RSA},
                                {0x0601, BRISK_ENABLE_RSA}};

#define DEF_GROUP (BRISK_ENABLE_X25519 ? 0x001d : 0x0017)

/* The u16 list at d (2-byte length prefix) holds exactly the enabled rows of t, each once. */
static void check_list(const uint8_t *d, const knob_row *t, size_t n)
{
    size_t ll = brisk__load_be16(d), i, j, want = 0;
    for (i = 0; i < n; i++) {
        want += (size_t)(t[i].on != 0);
    }
    CHECK(ll == 2 * want);
    for (j = 0; j < ll / 2; j++) {
        uint16_t v = (uint16_t)brisk__load_be16(d + 2 + 2 * j);
        int seen = 0;
        for (i = 0; i < n; i++) {
            seen |= t[i].id == v && t[i].on;
        }
        CHECKI(seen, v);
    }
}

static size_t write_ch(const uint16_t *suites, size_t n_suites, uint16_t group, uint8_t *out,
                       size_t cap, int *rc)
{
    static const uint8_t z[65] = {4};
    brisk__tls13_ch_params p;
    size_t n = 0;
    memset(&p, 0, sizeof p);
    p.random = z;
    p.share_group = group;
    p.share_pub = z;
    p.share_pub_len = group == 0x001d ? 32 : 65;
    p.suites = suites;
    p.n_suites = n_suites;
    p.groups = suites != NULL ? &p.share_group : NULL; /* a caller's own list: just the share */
    p.n_groups = suites != NULL;
    p.tls12 = suites == NULL && BRISK_ENABLE_TLS12;
    *rc = brisk__tls13_ch_write(&p, out, cap, &n);
    return n;
}

static void offer(void)
{
    uint8_t ch[1024];
    const uint8_t *b, *e;
    size_t n, i;
    int rc, groups = 0, sigs = 0;

    n = write_ch(NULL, 0, DEF_GROUP, ch, sizeof ch, &rc);
    CHECK(rc == BRISK_OK);
    if (rc != BRISK_OK) {
        return;
    }
    b = ch + 4 + 2 + 32;
    b += 1 + b[0]; /* legacy_session_id */
    check_list(b, SUITES, N(SUITES));
    b += 2 + brisk__load_be16(b);
    b += 1 + b[0]; /* legacy_compression_methods */
    e = b + 2 + brisk__load_be16(b);
    CHECK(e == ch + n);
    for (b += 2; b + 4 <= e; b += 4 + brisk__load_be16(b + 2)) {
        if (brisk__load_be16(b) == 0x000a) {
            check_list(b + 4, GROUPS, N(GROUPS));
            groups = 1;
        } else if (brisk__load_be16(b) == 0x000d) {
            check_list(b + 4, SIGS, N(SIGS));
            sigs = 1;
        }
    }
    CHECK(groups && sigs);

    /* a key share on a group this build does not have: with the default group list, and with
     * a caller's own list that names it */
    for (i = 0; i < N(GROUPS); i++) {
        write_ch(NULL, 0, GROUPS[i].id, ch, sizeof ch, &rc);
        CHECKI((rc == BRISK_OK) == GROUPS[i].on, GROUPS[i].id);
        write_ch(&SUITES[BRISK_ENABLE_CHACHA ? 2 : 0].id, 1, GROUPS[i].id, ch, sizeof ch, &rc);
        CHECKI((rc == BRISK_OK) == GROUPS[i].on, GROUPS[i].id);
    }
}

/* A caller's own suite list naming a suite this build does not have: the ClientHello is written
 * (ch_write copies lists as given), but the engine refuses to send it. */
static void own_suites(void)
{
    static uint8_t scratch[4 + BRISK_TLS_MAX_HS_MSG + 8192 + BRISK_TLS_MAX_CLIENT_CHAIN];
    static brisk__tls13_hs hs;
    brisk__tls13_auth_x509_ctx ax = {"a.example", 9, NULL, 0};
    brisk__tls13_hs_cfg cfg;
    uint8_t ch[1024], priv[32] = {1};
    size_t i, n;
    int rc;

    memset(&cfg, 0, sizeof cfg);
    cfg.auth = brisk__tls13_auth_x509;
    cfg.auth_ctx = &ax;
    for (i = 0; i < 3; i++) { /* the TLS 1.3 rows */
        n = write_ch(&SUITES[i].id, 1, DEF_GROUP, ch, sizeof ch, &rc);
        CHECKI(rc == BRISK_OK, i);
        CHECKI(brisk__tls13_hs_init(&hs, &cfg, scratch, sizeof scratch) == BRISK_OK, i);
        rc = brisk__tls13_hs_client_hello(&hs, ch, n, DEF_GROUP, priv);
        CHECKI((rc == BRISK_OK) == SUITES[i].on, SUITES[i].id);
    }
#if BRISK_ENABLE_TLS12
    for (i = 3; i < N(SUITES); i++) {
        CHECKI(brisk__tls12_suite(SUITES[i].id, NULL, NULL, NULL, NULL) == SUITES[i].on,
               SUITES[i].id);
    }
#endif
}

#if BRISK_ENABLE_CRYPTO_API
static void aead_api(void)
{
    static const struct {
        int alg, on;
        size_t klen;
    } A[] = {{BRISK_AEAD_AES128_GCM, BRISK_ENABLE_AESGCM, 16},
             {BRISK_AEAD_AES256_GCM, BRISK_ENABLE_AES256, 32},
             {BRISK_AEAD_CHACHA20_POLY1305, BRISK_ENABLE_CHACHA, 32}};
    uint8_t key[32] = {0}, nonce[12] = {0}, buf[4] = {0}, tag[16];
    size_t i;
    for (i = 0; i < N(A); i++) {
        int rc = brisk_aead_seal((brisk_aead_alg)A[i].alg, key, A[i].klen, nonce, NULL, 0, buf, 4,
                                 buf, tag);
        CHECKI((rc == BRISK_OK) == A[i].on && (rc == BRISK_OK || rc == BRISK_E_ARG), A[i].alg);
    }
}
#endif

/* PEM / SYSTEM_CA: what the build lacks is BRISK_E_ARG at setup, never a weaker trust store.
 * The setup parses no anchor, so any bytes stand in for the certificates. */
static int dummy_anchor(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                        brisk__x509_cert *out)
{
    (void)ctx, (void)dn, (void)dn_len, (void)index, (void)out;
    return BRISK_E_ARG;
}

static void trust_setup(void)
{
    static const uint8_t der[] = {0x30, 0x00}, pem[] = "-----BEGIN CERTIFICATE-----";
    uint8_t rnd[BRISK__CONN_RAND];
    size_t size = brisk_conn_size();
    void *mem = malloc(size);
    brisk_conn *c;
    brisk_cfg cfg;
    memset(rnd, 0x11, sizeof rnd); /* every slice a valid key, the P-256 d included */
    if (mem == NULL) {
        CHECK(0);
        return;
    }
    memset(&cfg, 0, sizeof cfg); /* no anchors named: the system store */
    CHECK((brisk__conn_setup(mem, size, &cfg, "a.example", 0, rnd, dummy_anchor, &c) == BRISK_OK) ==
          BRISK_ENABLE_SYSTEM_CA);
    cfg.ca_file = "/etc/ssl/cert.pem";
    CHECK((brisk__conn_setup(mem, size, &cfg, "a.example", 0, rnd, dummy_anchor, &c) == BRISK_OK) ==
          BRISK_ENABLE_PEM);
    cfg.ca_file = NULL;
    cfg.ca_mem = pem;
    cfg.ca_mem_len = sizeof pem - 1;
    CHECK((brisk__conn_setup(mem, size, &cfg, "a.example", 0, rnd, dummy_anchor, &c) == BRISK_OK) ==
          BRISK_ENABLE_PEM);
    cfg.ca_mem = der;
    cfg.ca_mem_len = sizeof der;
    CHECK(brisk__conn_setup(mem, size, &cfg, "a.example", 0, rnd, dummy_anchor, &c) == BRISK_OK);
    free(mem);
}

/* brisk_build_info names every knob that is off, so a shipped image says what it lacks */
static void build_info(void)
{
    static const struct {
        const char *tag;
        int on;
    } K[] = {{" -aesgcm", BRISK_ENABLE_AESGCM},       {" -aes256", BRISK_ENABLE_AES256},
             {" -chacha", BRISK_ENABLE_CHACHA},       {" -x25519", BRISK_ENABLE_X25519},
             {" -p256_kx", BRISK_ENABLE_P256_KX},     {" -rsa", BRISK_ENABLE_RSA},
             {" -tickets", BRISK_ENABLE_TICKETS},     {" -pem", BRISK_ENABLE_PEM},
             {" -system_ca", BRISK_ENABLE_SYSTEM_CA}, {" -custom_io", BRISK_ENABLE_CUSTOM_IO}};
    size_t i;
    for (i = 0; i < N(K); i++) {
        CHECKI((strstr(brisk_build_info(), K[i].tag) != NULL) == !K[i].on, i);
    }
}

void test_knobs(void)
{
    build_info();
    trust_setup();
    offer();
    own_suites();
#if BRISK_ENABLE_CRYPTO_API
    aead_api();
#endif
}

#ifdef T_KNOBS_MAIN
long t_checks, t_fails;

void t_check(int ok, const char *file, int line, const char *what, long idx)
{
    t_checks++;
    if (!ok && ++t_fails <= 25) {
        fprintf(stderr, "FAIL %s:%d: %s [%ld]\n", file, line, what, idx);
    }
}

int main(void)
{
    test_knobs();
    printf("knobs    %s (%ld checks)\n", t_fails ? "FAILED" : "ok", t_checks);
    return t_fails || t_checks == 0;
}
#endif

#undef N
#undef DEF_GROUP
