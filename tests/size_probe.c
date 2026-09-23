/* size_probe.c - references every public/internal entry point so the linker keeps them;
 * tools/dev.py reads the resulting map file to report per-module flash/RAM. Never run in tests. */
#include "brisk_int.h"

int main(int argc, char **argv)
{
    uint8_t out[64];
    brisk_hash_alg alg = (brisk_hash_alg)(argc % 3 + 1);
    (void)argv;
    brisk_sha256(argv, 8, out);
    brisk_sha384(argv, 8, out);
    brisk_sha512(argv, 8, out);
    brisk_hmac(alg, out, 32, out, 32, out);
    brisk__hkdf_extract(alg, out, 32, out, 32, out);
    brisk__hkdf_expand_label(alg, out, 32, "derived", out, 32, out, 32);
    brisk__chacha20(out, 1, out + 32, out, out, 5);
    brisk__chacha20_poly1305_seal(out, out + 32, out, 5, out, 16, out, out + 48);
    brisk__chacha20_poly1305_open(out, out + 32, out, 5, out, 16, out, out + 48);
    {
        brisk__aes_key k;
        brisk__aes_init(&k, out, (size_t)argc * 16);
        brisk__aes_encrypt(&k, out, out);
        brisk__aes_ctr32(&k, out + 16, out, 33, out);
    }
    {
        brisk__gcm_key g;
        brisk__gcm_init(&g, out, (size_t)argc * 16);
        brisk__gcm_seal(&g, out, out, 5, out, 16, out, out + 48);
        brisk__gcm_open(&g, out, out, 5, out, 16, out, out + 48);
    }
    brisk__x25519(out, out + 32, out);
    brisk__x25519_base(out, out + 32);
    {
        uint8_t pt[65];
        brisk__p256_keygen(pt, out);
        brisk__p256_ecdh(out, out + 32, pt);
        brisk__p256_ecdsa_verify(pt, out, 32, out);
        brisk__p256_scalar_valid(out);
        brisk__p256_scalar_reduce(out, out + 32);
        brisk__p256_scalar_add(out, out + 32, out);
        brisk__p256_scalar_mul(out, out + 32, out);
        brisk__p256_scalar_inv(out, out + 32);
#if BRISK_ENABLE_MTLS
        brisk__p256_ecdsa_sign(out, out + 32, pt, 32, pt + 32, 32);
#endif
    }
#if BRISK_ENABLE_P384
    {
        uint8_t pt97[97], sig96[96]; /* sig is 96 bytes: `out` is 64 and would be over-read */
        memset(pt97, 0x04, sizeof pt97);
        memset(sig96, 0x11, sizeof sig96);
        brisk__p384_ecdsa_verify(pt97, out, 48, sig96);
    }
#endif
    {
        uint32_t m[BRISK__BN_MAX_LIMBS], x[BRISK__BN_MAX_LIMBS], t[2 * BRISK__BN_MAX_LIMBS];
        /* out still holds whatever the P-256 block left there: force it odd and top-bit set so
         * decode_mod accepts it, and decode x from a shorter string so x < m holds too. */
        out[0] |= 0x80;
        out[31] |= 1;
        brisk__bn_decode_mod(m, BRISK__BN_MAX_BITS, out, 32);
        brisk__bn_decode_into(x, m, out + 1, 31);
        brisk__bn_encode(out, 32, x);
        brisk__bn_lt(x, m);
        brisk__bn_add(x, m, 1);
        brisk__bn_sub(x, m, 1);
        brisk__bn_mont_mul(x, x, m, m, brisk__bn_ninv31(m));
        brisk__bn_to_mont(x, m);
        brisk__bn_from_mont(x, m, brisk__bn_ninv31(m), t);
        brisk__bn_modpow_pub(x, out, 3, m, t);
        brisk__rsa_pkcs1_verify(out, 32, out, 3, alg, out, 32, out, 32);
        brisk__rsa_pss_verify(out, 32, out, 3, alg, 32, out, 32, out, 32);
    }
    {
        brisk__der c, body;
        const uint8_t *v;
        size_t n;
        uint32_t u;
        unsigned unused;
        int flag;
        brisk__der_walk(out, sizeof out);
        brisk__der_init(&c, out, sizeof out);
        brisk__der_enter(&c, BRISK__DER_SEQUENCE, &body);
        brisk__der_value(&body, BRISK__DER_OCTET_STRING, &v, &n);
        brisk__der_tlv(&body, &v, &n);
        brisk__der_skip(&body);
        brisk__der_bool(&body, &flag);
        brisk__der_null(&body);
        brisk__der_oid(&body, &v, &n);
        brisk__der_int(&body, &v, &n);
        brisk__der_unsigned(&body, &v, &n);
        brisk__der_uint(&body, &u);
        brisk__der_bitstring(&body, &v, &n, &unused);
        brisk__der_close(&c, &body);
        brisk__der_fail(&c);
        brisk__der_end(&c);
    }
    {
        brisk__x509_cert xc;
        int64_t when;
        brisk__x509_trust trust;
        brisk__x509_parse(&xc, out, sizeof out);
        brisk__x509_time(BRISK__DER_UTC_TIME, out, sizeof out, &when);
#ifdef __linux__
        trust.find_anchor = brisk__os_ca_anchor;
#else
        trust.find_anchor = NULL;
#endif
        trust.anchor_ctx = NULL;
        trust.pins = (const uint8_t (*)[BRISK_SHA256_LEN])out;
        /* 1, not argc: `pins` aims at a 64-byte buffer, so anything above 2 would make
         * pinned() read past it if this probe were ever RUN under a sanitizer. */
        trust.n_pins = 1;
        brisk__x509_chain_verify(&xc, 1, when, &trust);
        brisk__x509_time_ok(&xc, when);
        brisk__x509_signed_by(&xc, &xc);
        brisk__x509_match_host(&xc, "a.example", 9);
        brisk__x509_parse_ip("192.0.2.1", 9, out);
    }
#ifdef __linux__
    brisk__os_random(out, 32);
    {
        static brisk__x509_bundle bundle; /* 2 KB: the probe reports it as linux_ca's RAM */
        brisk__x509_cert anchor;
        brisk__os_ca_path();
        brisk__os_ca_anchor(&bundle, out, 8, 0, &anchor);
    }
#endif
    {
        brisk__x509_pem pem;
        const uint8_t *p = out;
        size_t left = sizeof out;
        brisk__x509_pem_init(&pem);
        brisk__x509_pem_feed(&pem, &p, &left);
    }
    {
        brisk__tls_ks ks;
        brisk__tls_ks_init(&ks, alg, NULL, 0);
        brisk__tls_ks_derive_handshake(&ks, out, 32, out, out, out + 32);
        brisk__tls_ks_derive_application(&ks, out, out, out + 16, out + 32);
        brisk__tls_ks_derive_resumption(&ks, out, out);
        brisk__tls_finished_mac(alg, out, out, out);
        brisk__tls_ks_exporter(alg, out, "exp", out, 8, out, 32);
        brisk__tls_ks_wipe(&ks);
    }
    {
        /* the handshake engine; its scratch is the probe's own BSS, not the library's RAM */
        static uint8_t scratch[4 + BRISK_TLS_MAX_HS_MSG + 8192 + BRISK_TLS_MAX_CLIENT_CHAIN];
        static brisk__tls13_hs hs;
        brisk__tls13_auth_x509_ctx ax = {"a.example", 9, NULL, 0};
        brisk__tls13_hs_cfg cfg = {NULL, NULL, brisk__tls13_auth_x509, &ax, 0, NULL, NULL,
                                   NULL, NULL};
        brisk__tls13_ch_params p;
        size_t n;
        unsigned e;
        memset(&p, 0, sizeof p);
        p.random = out;
        p.share_group = 0x001d;
        p.share_pub = out;
        p.share_pub_len = 32;
        brisk__tls13_ch_write(&p, out, sizeof out, &n);
        brisk__tls13_hs_init(&hs, &cfg, scratch, sizeof scratch);
        brisk__tls13_hs_client_hello(&hs, out, n, 0x001d, out);
        brisk__tls13_hs_feed(&hs, 0, out, n);
        brisk__tls13_hs_pull(&hs, &e, out, sizeof out);
        brisk__tls13_hs_exporter(&hs, "e", out, 1, out, 32);
        {
            /* resumption (ticket blob + PSK offer) and the ALPN answer */
            static brisk__tls13_psk psk;
            static brisk__tls13_ticket tk;
            const uint8_t *name;
            brisk__tls13_ticket_import(out, sizeof out, "a", 1, 5, &psk);
            brisk__tls13_ticket_export(&tk, 5, "a", 1, out, sizeof out, &n);
            brisk__tls13_hs_set_psk(&hs, &psk);
            brisk__tls13_hs_alpn(&hs, &name, &n);
            out[1] = (uint8_t)brisk__tls13_hs_resumed(&hs);
        }
        {
            /* the record layer + connection driver over the same engine */
            static uint8_t rec_in[BRISK__TLS_REC_IN_MAX];
            static brisk__tls13_conn conn;
            size_t used;
            brisk__tls13_conn_init(&conn, &hs, rec_in, sizeof rec_in);
            brisk__tls13_conn_feed(&conn, out, n, &used);
            brisk__tls13_conn_read(&conn, out, sizeof out, &used);
            brisk__tls13_conn_write(&conn, out, 8, &used, out, sizeof out, &n);
            brisk__tls13_conn_close(&conn);
            brisk__tls13_conn_pull(&conn, out, sizeof out);
            brisk__tls13_conn_wipe(&conn);
        }
        brisk__tls13_hs_wipe(&hs);
        (void)brisk__tls13_hs_scratch_size();
    }
    return out[0] + (brisk_build_info()[0] == brisk_version()[0]) +
           brisk__ct_memeq(out, out + 1, 8);
}
