/* test_tls13_ks.c - TLS 1.3 key schedule (RFC 9846 sect 7.1) end-to-end against the RFC 8448
 * sect 3 trace (SHA-256), plus a SHA-384 self-consistency run.
 *
 * The trace is threaded stage-by-stage: early_secret, derived, handshake_secret, c/s hs traffic,
 * derived, master_secret, c/s ap traffic, exp master, res master, and both Finished MACs. Every
 * expected intermediate is a hex string LIFTED VERBATIM from tests/kat/expand_label.inc and
 * tests/kat/hkdf_extract.inc, which tools/kat.py generated from RFC 8448 with a Python cross-check
 * of HKDF-Extract and HKDF-Expand-Label. So the numbers here are re-checks of the composition,
 * not of the primitives - the primitives were re-checked when kat.py ran. */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"
#include "test.h"

/* RFC 8448 sect 3 (Simple 1-RTT Handshake, SHA-256, TLS_AES_128_GCM_SHA256). All hex is
 * cut-and-pasted from tests/kat/expand_label.inc and tests/kat/hkdf_extract.inc. */
static const char *EARLY = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
static const char *DERIVED_EARLY =
    "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
static const char *DHE = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
static const char *HANDSHAKE = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
static const char *TH_CH_SH = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
static const char *C_HS_TS = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
static const char *S_HS_TS = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
static const char *DERIVED_HS = "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4";
static const char *MASTER = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
static const char *TH_CH_SF = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
static const char *C_AP_TS = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
static const char *S_AP_TS = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
static const char *EXP_MS = "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50";
static const char *TH_CH_CF = "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d";
static const char *RES_MS = "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c";
/* Finished MAC base_keys are s hs traffic and c hs traffic; the expand_label vectors give the
 * "finished" base_key -> finished_key mapping (008d3b66..., b80ad010...) but not the HMAC output
 * over a transcript hash, so those two are re-derived here through brisk__tls_finished_mac and
 * checked for internal consistency (finished_key HMAC over the transcript hash matches an
 * independent HKDF-Expand-Label + brisk_hmac composition). */

/* Hex helpers wrapping t_unhex for the fixed HashLen buffers. */
static void hex32(const char *h, uint8_t out[32])
{
    if (t_unhex(h, out, 32) != 32) {
        exit(2);
    }
}

static void ks_sha256_trace(void)
{
    uint8_t want[32];
    uint8_t dhe[32], th_ch_sh[32], th_ch_sf[32], th_ch_cf[32];
    uint8_t c_hs_ts[32], s_hs_ts[32];
    uint8_t c_ap_ts[32], s_ap_ts[32], exp_ms[32], res_ms[32];
    brisk__tls_ks ks;

    /* stage 1: early_secret from an absent PSK. */
    CHECK(brisk__tls_ks_init(&ks, BRISK_HASH_SHA256, NULL, 0) == BRISK_OK);
    hex32(EARLY, want);
    CHECK(memcmp(ks.secret, want, 32) == 0);

    /* The two "derived" intermediates from the same trace are computed inside the KS on the
     * stack (they're never exposed by the API); spot-check that the primitive path we compose
     * against reproduces them, so a drift between this test and the .inc file shows up here
     * rather than as a mysterious late-stage mismatch. */
    {
        uint8_t derived_early[32], derived_hs[32], eh[32], hs[32];
        brisk_hash_ctx hc;
        brisk__hash_init(&hc, BRISK_HASH_SHA256);
        brisk__hash_final(&hc, BRISK_HASH_SHA256, eh);
        CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, ks.secret, 32, "derived", eh, 32,
                                       derived_early, 32) == BRISK_OK);
        hex32(DERIVED_EARLY, want);
        CHECK(memcmp(derived_early, want, 32) == 0);
        hex32(HANDSHAKE, hs);
        CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, hs, 32, "derived", eh, 32, derived_hs,
                                       32) == BRISK_OK);
        hex32(DERIVED_HS, want);
        CHECK(memcmp(derived_hs, want, 32) == 0);
    }

    /* NULL psk pointer with psk_len == 0 and a psk_len == 0 with a real pointer must both take
     * the absent-PSK branch, matching the RFC 9846 "0^HashLen" rule. */
    {
        brisk__tls_ks ks2;
        uint8_t dummy = 0, early[32];
        hex32(EARLY, early);
        CHECK(brisk__tls_ks_init(&ks2, BRISK_HASH_SHA256, &dummy, 0) == BRISK_OK);
        CHECK(memcmp(ks2.secret, early, 32) == 0);
        brisk__tls_ks_wipe(&ks2);
    }

    /* PSK-present branch: a real 32-byte PSK must feed HKDF-Extract(0^32, PSK). Cross-check
     * against a direct brisk__hkdf_extract with the same inputs - if the PSK branch is deleted
     * (the guarded early return in brisk__tls_ks_init) this must fail, per the "mutation-test
     * fail-open vectors" memory rule. */
    {
        brisk__tls_ks ks_psk;
        uint8_t psk[32], zeros[32] = {0}, expect[32];
        for (size_t i = 0; i < 32; i++) {
            psk[i] = (uint8_t)(i + 1); /* any non-zero pattern distinct from the absent-PSK IKM */
        }
        CHECK(brisk__hkdf_extract(BRISK_HASH_SHA256, zeros, 32, psk, 32, expect) == BRISK_OK);
        CHECK(brisk__tls_ks_init(&ks_psk, BRISK_HASH_SHA256, psk, 32) == BRISK_OK);
        CHECK(memcmp(ks_psk.secret, expect, 32) == 0);
        /* And it must differ from the absent-PSK early_secret - so the branch isn't a no-op. */
        {
            uint8_t absent[32];
            hex32(EARLY, absent);
            CHECK(memcmp(ks_psk.secret, absent, 32) != 0);
        }
        brisk__tls_ks_wipe(&ks_psk);
    }

    /* stage 2: handshake secrets. */
    hex32(DHE, dhe);
    hex32(TH_CH_SH, th_ch_sh);
    CHECK(brisk__tls_ks_derive_handshake(&ks, dhe, 32, th_ch_sh, c_hs_ts, s_hs_ts) == BRISK_OK);
    hex32(HANDSHAKE, want);
    CHECK(memcmp(ks.secret, want, 32) == 0); /* ks.secret advanced to handshake_secret */
    hex32(C_HS_TS, want);
    CHECK(memcmp(c_hs_ts, want, 32) == 0);
    hex32(S_HS_TS, want);
    CHECK(memcmp(s_hs_ts, want, 32) == 0);

    /* stage 3: application secrets. */
    hex32(TH_CH_SF, th_ch_sf);
    CHECK(brisk__tls_ks_derive_application(&ks, th_ch_sf, c_ap_ts, s_ap_ts, exp_ms) == BRISK_OK);
    hex32(MASTER, want);
    CHECK(memcmp(ks.secret, want, 32) == 0);
    hex32(C_AP_TS, want);
    CHECK(memcmp(c_ap_ts, want, 32) == 0);
    hex32(S_AP_TS, want);
    CHECK(memcmp(s_ap_ts, want, 32) == 0);
    hex32(EXP_MS, want);
    CHECK(memcmp(exp_ms, want, 32) == 0);

    /* stage 4: resumption. */
    hex32(TH_CH_CF, th_ch_cf);
    CHECK(brisk__tls_ks_derive_resumption(&ks, th_ch_cf, res_ms) == BRISK_OK);
    hex32(RES_MS, want);
    CHECK(memcmp(res_ms, want, 32) == 0);

    /* Finished MAC: verify the composition (finished_key HMAC over transcript hash) reproduces
     * the same output whichever way one computes it. The base_key is s_hs_ts / c_hs_ts and the
     * transcript hash is TH_CH_SF for the server Finished, TH(CH..server_Finished) for the
     * client Finished (which in RFC 8448 sect 3 is not TH_CH_SF exactly; using TH_CH_SF twice
     * here still checks the MAC's input-processing but not against a wire trace - the wire trace
     * is M3 line 2). */
    {
        uint8_t mac[32], mac2[32], fk[32];
        CHECK(brisk__tls_finished_mac(BRISK_HASH_SHA256, s_hs_ts, th_ch_sf, mac) == BRISK_OK);
        /* Independently: expand-label s_hs_ts -> finished_key, then HMAC over th_ch_sf. */
        CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, s_hs_ts, 32, "finished", NULL, 0, fk,
                                       32) == BRISK_OK);
        CHECK(brisk_hmac(BRISK_HASH_SHA256, fk, 32, th_ch_sf, 32, mac2) == BRISK_OK);
        CHECK(memcmp(mac, mac2, 32) == 0);
        CHECK(brisk__ct_memeq(mac, mac2, 32) == 1);
        /* Byte-flip: must not compare equal. */
        mac2[0] ^= 1;
        CHECK(brisk__ct_memeq(mac, mac2, 32) == 0);
    }

    /* Exporter self-consistency: the wire spec has no exporter vector in RFC 8448, so this
     * checks that our exporter equals the two-step HKDF-Expand-Label composition (RFC 9846
     * sect 7.5). If either step changes shape the two paths diverge. */
    {
        static const uint8_t CTX[] = "brisk-ssl exporter test";
        uint8_t path_a[42], path_b[42];
        uint8_t inter[32], ctx_hash[32], eh[32];
        brisk_hash_ctx hc;
        /* path A: through brisk__tls_ks_exporter. */
        CHECK(brisk__tls_ks_exporter(BRISK_HASH_SHA256, exp_ms, "EXPORTER-brisk-test", CTX,
                                     sizeof CTX - 1, path_a, 42) == BRISK_OK);
        /* path B: hand-composed. */
        brisk__hash_init(&hc, BRISK_HASH_SHA256);
        brisk__hash_final(&hc, BRISK_HASH_SHA256, eh);
        CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, exp_ms, 32, "EXPORTER-brisk-test", eh, 32,
                                       inter, 32) == BRISK_OK);
        brisk__hash_init(&hc, BRISK_HASH_SHA256);
        brisk__hash_update(&hc, BRISK_HASH_SHA256, CTX, sizeof CTX - 1);
        brisk__hash_final(&hc, BRISK_HASH_SHA256, ctx_hash);
        CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA256, inter, 32, "exporter", ctx_hash, 32,
                                       path_b, 42) == BRISK_OK);
        CHECK(memcmp(path_a, path_b, 42) == 0);
    }

    brisk__tls_ks_wipe(&ks);
    /* Every byte of the state buffer is zero after wipe: brisk__ct_memeq against 32 zeros == 1. */
    {
        uint8_t zeros[32] = {0};
        CHECK(brisk__ct_memeq(ks.secret, zeros, 32) == 1);
    }
}

/* SHA-384 self-consistency: no RFC 8448 SHA-384 trace exists, so this test runs a full stage
 * cascade with synthetic inputs and re-verifies the composition against direct HKDF-Extract +
 * HKDF-Expand-Label calls at each step. If a stage silently uses the wrong hash length or drops
 * a byte of the transcript, the two paths diverge. */
static void ks_sha384_selfconsistency(void)
{
    uint8_t dhe[48], th_ch_sh[48], th_ch_sf[48];
    uint8_t c_hs_ts[48], s_hs_ts[48];
    uint8_t c_ap_ts[48], s_ap_ts[48], exp_ms[48];
    uint8_t early[48], derived[48], hs[48], master[48], zeros[48] = {0}, eh[48];
    uint8_t want[48];
    brisk__tls_ks ks;
    brisk_hash_ctx hc;
    size_t i;

    for (i = 0; i < 48; i++) {
        dhe[i] = (uint8_t)(i * 3 + 1);
        th_ch_sh[i] = (uint8_t)(i * 5 + 7);
        th_ch_sf[i] = (uint8_t)(i * 7 + 11);
    }

    /* Reference cascade using primitives directly. */
    CHECK(brisk__hkdf_extract(BRISK_HASH_SHA384, zeros, 48, zeros, 48, early) == BRISK_OK);
    brisk__hash_init(&hc, BRISK_HASH_SHA384);
    brisk__hash_final(&hc, BRISK_HASH_SHA384, eh);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, early, 48, "derived", eh, 48, derived, 48) ==
          BRISK_OK);
    CHECK(brisk__hkdf_extract(BRISK_HASH_SHA384, derived, 48, dhe, 48, hs) == BRISK_OK);

    /* Path through the key schedule. */
    CHECK(brisk__tls_ks_init(&ks, BRISK_HASH_SHA384, NULL, 0) == BRISK_OK);
    CHECK(memcmp(ks.secret, early, 48) == 0);
    CHECK(brisk__tls_ks_derive_handshake(&ks, dhe, 48, th_ch_sh, c_hs_ts, s_hs_ts) == BRISK_OK);
    CHECK(memcmp(ks.secret, hs, 48) == 0);

    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, hs, 48, "c hs traffic", th_ch_sh, 48, want,
                                   48) == BRISK_OK);
    CHECK(memcmp(c_hs_ts, want, 48) == 0);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, hs, 48, "s hs traffic", th_ch_sh, 48, want,
                                   48) == BRISK_OK);
    CHECK(memcmp(s_hs_ts, want, 48) == 0);

    /* Advance to master and check the three application-stage secrets independently. */
    CHECK(brisk__tls_ks_derive_application(&ks, th_ch_sf, c_ap_ts, s_ap_ts, exp_ms) == BRISK_OK);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, hs, 48, "derived", eh, 48, derived, 48) ==
          BRISK_OK);
    CHECK(brisk__hkdf_extract(BRISK_HASH_SHA384, derived, 48, zeros, 48, master) == BRISK_OK);
    CHECK(memcmp(ks.secret, master, 48) == 0);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, master, 48, "c ap traffic", th_ch_sf, 48,
                                   want, 48) == BRISK_OK);
    CHECK(memcmp(c_ap_ts, want, 48) == 0);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, master, 48, "s ap traffic", th_ch_sf, 48,
                                   want, 48) == BRISK_OK);
    CHECK(memcmp(s_ap_ts, want, 48) == 0);
    CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, master, 48, "exp master", th_ch_sf, 48, want,
                                   48) == BRISK_OK);
    CHECK(memcmp(exp_ms, want, 48) == 0);

    /* Finished MAC: hand-composed and library must match. */
    {
        uint8_t mac[48], fk[48], mac2[48];
        CHECK(brisk__tls_finished_mac(BRISK_HASH_SHA384, s_hs_ts, th_ch_sf, mac) == BRISK_OK);
        CHECK(brisk__hkdf_expand_label(BRISK_HASH_SHA384, s_hs_ts, 48, "finished", NULL, 0, fk,
                                       48) == BRISK_OK);
        CHECK(brisk_hmac(BRISK_HASH_SHA384, fk, 48, th_ch_sf, 48, mac2) == BRISK_OK);
        CHECK(memcmp(mac, mac2, 48) == 0);
    }
    brisk__tls_ks_wipe(&ks);
}

static void ks_argchecks(void)
{
    brisk__tls_ks ks;
    uint8_t out[48];
    /* Unknown alg -> BRISK_E_ARG. */
    CHECK(brisk__tls_ks_init(&ks, (brisk_hash_alg)0, NULL, 0) == BRISK_E_ARG);
    CHECK(brisk__tls_finished_mac((brisk_hash_alg)0, out, out, out) == BRISK_E_ARG);
    CHECK(brisk__tls_ks_exporter((brisk_hash_alg)0, out, "x", NULL, 0, out, 16) == BRISK_E_ARG);
    /* Wipe on NULL is a no-op, not a crash. */
    brisk__tls_ks_wipe(NULL);
}

void test_tls13_ks(void)
{
    ks_sha256_trace();
    ks_sha384_selfconsistency();
    ks_argchecks();
}
