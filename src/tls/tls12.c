/* tls12.c - the TLS 1.2 client half of the handshake engine (M5), sans-I/O.
 *
 * SPECIFICATIONS. RFC 9846 obsoletes RFC 5246 / 7627 / 8422 / 5077 but does not restate the TLS
 * 1.2 wire formats, so the mechanics here cite the documents that define them: RFC 5246 (the
 * protocol), RFC 7627 (extended main secret, renamed by RFC 9846 1.4 / D), RFC 8422 (ECDHE and
 * ECDSA), RFC 5746 (renegotiation_info), RFC 5288 / 5289 / 7905 (the AEAD suites) and RFC 9325
 * (the TLS 1.2 recommendations). RFC 9846 is cited for what it still says about TLS 1.2: the
 * downgrade sentinels (4.2.3, checked in handshake.c BEFORE this file is entered), the version
 * rules (4.3.1, E) and the signature scheme rules (4.3.3).
 *
 * POLICY (all fail closed): full handshakes only, ECDHE (x25519 / secp256r1) + AEAD only,
 * extended_main_secret and renegotiation_info REQUIRED, no resumption (a session_id echo is
 * refused), no renegotiation, no CertificateStatus, no NewSessionTicket, no compression.
 *
 * SECRETS: the two ECDHE private keys, the preliminary (pre-master) secret, the extended main
 * secret, the key block and the verify_data under computation. None reaches a branch or an
 * index; the PRF loop counts depend on public lengths only; the server Finished is compared with
 * brisk__ct_memeq; X25519 all-zero and P-256 point validity are public verdicts (x25519.c /
 * p256.c). Every secret is wiped as soon as it is used, and by brisk__hs_fail on any failure.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_TLS12

enum {
    T12_HELLO_REQUEST = 0,
    T12_CERTIFICATE = 11,
    T12_SERVER_KEY_EXCHANGE = 12,
    T12_CERTIFICATE_REQUEST = 13,
    T12_SERVER_HELLO_DONE = 14,
    T12_CERTIFICATE_VERIFY = 15,
    T12_CLIENT_KEY_EXCHANGE = 16,
    T12_FINISHED = 20
};

/* The only extensions a TLS 1.2 ServerHello may carry here (RFC 5246 7.4.1.4: each one the answer
 * to something offered). Bit positions for the duplicate check. */
static const uint16_t SH12_EXT[5] = {0xff01, 23, 11, 16, 0};

int brisk__tls12_suite(uint16_t suite, brisk_hash_alg *prf, size_t *key_len, size_t *iv_len,
                       uint8_t *ecdsa)
{
    /* RFC 5289 3.2 (PRF hash), RFC 5288 3 (fixed_iv_length 4), RFC 7905 2 (12, 32-byte key) */
    brisk_hash_alg h = suite == 0xC02C || suite == 0xC030 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA256;
    size_t kl = suite == 0xC02B || suite == 0xC02F ? 16u : 32u;
    size_t il = suite == 0xCCA8 || suite == 0xCCA9 ? 12u : 4u;
    if (suite != 0xC02B && suite != 0xC02C && suite != 0xC02F && suite != 0xC030 &&
        suite != 0xCCA8 && suite != 0xCCA9) {
        return 0;
    }
    if (prf != NULL) {
        *prf = h;
    }
    if (key_len != NULL) {
        *key_len = kl;
    }
    if (iv_len != NULL) {
        *iv_len = il;
    }
    if (ecdsa != NULL) {
        *ecdsa = (uint8_t)(suite == 0xC02B || suite == 0xC02C || suite == 0xCCA9);
    }
    return 1;
}

/* A server below the security floor (brisk.h BRISK_E_INSECURE): the same fatal alert as any
 * refusal, but the caller learns that it was a policy refusal, not a broken peer. */
static int tls12_insecure(brisk__tls13_hs *hs, uint8_t alert)
{
    brisk__hs_fail(hs, alert);
    hs->err = BRISK_E_INSECURE;
    return hs->err;
}

/* RFC 5246 7.4.1.3 + RFC 9846 4.2.3 / E: a ServerHello without supported_versions whose random
 * carries no downgrade sentinel (handshake.c checked that first). */
int brisk__tls12_on_sh(brisk__tls13_hs *hs, const uint8_t *m, size_t n, const uint8_t *ext,
                       size_t ext_len, int is_hrr)
{
    const uint8_t *b = m + 4, *p = ext, *end = ext + ext_len, *d;
    size_t sid_len = b[34], i = 35 + sid_len, dl, k;
    uint16_t suite = (uint16_t)brisk__load_be16(b + i), t;
    unsigned seen = 0, bit;
    int r;

    /* E.1 / E.5, RFC 8996: exactly 0x0303. 0x0300-0x0302 are not acceptable; 0x0304 or above
     * without supported_versions is not a version this client offered either. */
    if (brisk__load_be16(b) != 0x0303) {
        return brisk__load_be16(b) < 0x0303 && b[0] == 3
                   ? tls12_insecure(hs, BRISK__ALERT_PROTOCOL_VERSION) /* RFC 8996 */
                   : brisk__hs_fail(hs, BRISK__ALERT_PROTOCOL_VERSION);
    }
    /* local (RFC 9846 4.1.4 / 4.2.4): a HelloRetryRequest committed the server to TLS 1.3, and
     * the HRR random is no TLS 1.2 random */
    if (is_hrr || hs->hrr_seen) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    /* 7.4.1.3: a suite the client offered (RFC 9846 9.3: and can finish); compression null */
    if (!brisk__tls12_suite(suite, NULL, NULL, NULL, NULL) ||
        !brisk__hs_in_list(hs->offered_suites, hs->n_suites, suite) || b[i + 2] != 0) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    /* 7.4.1.3: an echo of our session_id means resumption, which is never offered (local) */
    if (sid_len != 0 && sid_len == hs->session_id_len &&
        memcmp(b + 35, hs->session_id, sid_len) == 0) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    while ((r = brisk__hs_ext_next(&p, end, &t, &d, &dl)) == 1) {
        for (k = 0; k < 5 && SH12_EXT[k] != t; k++) {
        }
        /* 7.4.1.4: only answers to what the client offered for TLS 1.2 - anything else (a TLS
         * 1.3 key_share / pre_shared_key, record_size_limit, session_ticket, status_request, an
         * unknown type) is unsupported_extension, even if the CH carried it for TLS 1.3 */
        if (k == 5 || !brisk__hs_in_list(hs->offered_ext, hs->n_ext, t)) {
            return brisk__hs_fail(hs, BRISK__ALERT_UNSUPPORTED_EXTENSION);
        }
        bit = 1u << k;
        if (seen & bit) { /* 7.4.1.4: at most one of each type (local alert) */
            return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        seen |= bit;
        if ((t == 0 || t == 23) && dl != 0) { /* RFC 6066 3; RFC 7627 5.1: both empty */
            return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        if (t == 0xff01) { /* RFC 5746 3.4: opaque renegotiated_connection<0..255> */
            if (dl < 1 || d[0] != dl - 1) {
                return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
            }
            if (dl != 1) { /* 3.4: MUST abort unless it is zero-length */
                return brisk__hs_fail(hs, BRISK__ALERT_HANDSHAKE_FAILURE);
            }
        }
        if (t == 11) { /* RFC 8422 5.2: ECPointFormat ec_point_format_list<1..2^8-1> */
            if (dl < 2 || d[0] != dl - 1) {
                return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
            }
            if (memchr(d + 1, 0, d[0]) == NULL) { /* MUST contain uncompressed */
                return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
            }
        }
        if (t == 16 && (k = brisk__hs_alpn_check(hs, d, dl)) != 0) { /* RFC 7301 3.1 */
            return brisk__hs_fail(hs, (uint8_t)k);
        }
    }
    if (r < 0) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    /* RFC 7627 5.2 / RFC 9325 3.5: without the extended main secret the handshake is refused;
     * RFC 9325 3.5: a server that does not acknowledge renegotiation_info MUST be refused too */
    if (!(seen & 2u) || !(seen & 1u)) {
        return tls12_insecure(hs, BRISK__ALERT_HANDSHAKE_FAILURE);
    }
    brisk__secure_zero(hs->psk, sizeof hs->psk); /* a ticket offered for TLS 1.3 is dead */
    hs->psk_len = 0;
    hs->version = 0x0303;
    hs->suite = suite;
    memcpy(hs->srand, b + 2, 32);
    brisk__hs_th_add(hs, m, n);
    hs->state = BRISK__HS_WAIT12_CERT;
    return BRISK_OK;
}

/* RFC 5246 7.4.2: ASN.1Cert certificate_list<0..2^24-1>, each ASN.1Cert<1..2^24-1>. */
static int t12_on_cert(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    const uint8_t *b = m + 4, *p, *end = m + n;
    size_t bl = n - 4, len, count = 0;
    uint8_t ecdsa = 0;
    unsigned key;

    if (bl < 3 || brisk__load_be24(b) != bl - 3 || bl == 3) {
        return brisk__hs_fail(hs,
                              BRISK__ALERT_DECODE_ERROR); /* 7.4.2: the server's MUST be there */
    }
    for (p = b + 3; p != end; p += len) {
        if ((size_t)(end - p) < 3) {
            return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        len = brisk__load_be24(p);
        p += 3;
        if (len == 0 || len > (size_t)(end - p)) {
            return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        if (count == BRISK__X509_MAX_CHAIN) {
            return brisk__hs_fail(hs, BRISK__ALERT_BAD_CERTIFICATE); /* local limit */
        }
        /* parsed in place: the structs point into this message, kept (in_base) until the
         * ServerKeyExchange signature is checked */
        if (brisk__x509_parse(&hs->certs[count++], p, len) != BRISK_OK) {
            return brisk__hs_fail(hs, BRISK__ALERT_BAD_CERTIFICATE);
        }
    }
    /* 7.4.2 / RFC 8422 5.3: the leaf key must fit the key exchange - ECDSA for ECDHE_ECDSA, RSA
     * for ECDHE_RSA */
    brisk__tls12_suite(hs->suite, NULL, NULL, NULL, &ecdsa);
    key = hs->certs[0].key_alg;
    if (ecdsa ? key != BRISK__X509_KEY_P256 && key != BRISK__X509_KEY_P384
              : key != BRISK__X509_KEY_RSA) {
        return brisk__hs_fail(hs, BRISK__ALERT_UNSUPPORTED_CERTIFICATE);
    }
    hs->n_certs = count;
    brisk__hs_th_add(hs, m, n);
    hs->in_base = n;
    hs->state = BRISK__HS_WAIT12_SKE;
    return BRISK_OK;
}

/* RFC 8422 5.4: ServerECDHParams {ECParameters {curve_type, namedcurve}, ECPoint public} and
 * the signature over client_random || server_random || params (RFC 5246 7.4.3). */
static int t12_on_ske(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    uint8_t tbs[64 + 4 + 65], pre[32], alert = 0;
    const uint8_t *b = m + 4;
    size_t bl = n - 4, pl, want, rest, sl;
    uint16_t group, scheme;
    int rc;

    if (bl < 4) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    group = (uint16_t)brisk__load_be16(b + 1);
    pl = b[3];
    want = group == 0x001d ? 32u : group == 0x0017 ? 65u : 0u;
    /* 5.4: named_curve(3) only, a group we offered (RFC 8422 5.1) */
    if (b[0] != 3 || want == 0 || !brisk__hs_in_list(hs->offered_groups, hs->n_groups, group)) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    if (pl > bl - 4) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    /* 5.4.1 / RFC 7748 6.1: the exact uncompressed encoding - 32 bytes for x25519, 0x04 || X || Y
     * for secp256r1; compressed, hybrid, short, long or empty points are refused */
    if (pl != want || (group == 0x0017 && b[4] != 4)) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    rest = bl - 4 - pl;
    if (rest < 4) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    scheme = (uint16_t)brisk__load_be16(b + 4 + pl);
    sl = brisk__load_be16(b + 6 + pl);
    if (sl != rest - 4) { /* a trailing byte, or a short signature */
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    /* RFC 5246 7.4.1.4.1 / RFC 9846 4.3.3: a scheme the client offered (never SHA-1) */
    if (!brisk__hs_in_list(hs->offered_sigs, hs->n_sigs, scheme)) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    memcpy(tbs, hs->crand, 32);
    memcpy(tbs + 32, hs->srand, 32);
    memcpy(tbs + 64, b, 4 + pl);
    /* chain, host, keyUsage / EKU and the signature: the same authenticator as TLS 1.3, with the
     * TLS 1.2 scheme rules. The signature is verified BEFORE the point is used (RFC 8422 5.4). */
    rc = hs->cfg.auth(hs->cfg.auth_ctx, 0x0303, hs->certs, hs->n_certs, scheme, tbs, 68 + pl,
                      b + 8 + pl, sl, &alert);
    if (rc != BRISK_OK) {
        if (alert == 0) {
            alert = rc == BRISK_E_AUTH ? BRISK__ALERT_DECRYPT_ERROR : BRISK__ALERT_BAD_CERTIFICATE;
        }
        return brisk__hs_fail(hs, alert);
    }
    /* RFC 8422 5.10 / 5.11, RFC 7748 6.1: the preliminary secret is the X coordinate / X25519
     * output with its leading zeros kept; an all-zero X25519 result and an invalid P-256 point
     * MUST abort. The x25519 d is the ClientHello key_share key, never used for DH before (the
     * server did not pick TLS 1.3); both private keys die here. */
    if (group == 0x001d) {
        rc = brisk__x25519(pre, hs->priv, b + 4);
        brisk__x25519_base(hs->kx_pub, hs->priv);
        hs->kx_pub_len = 32;
    } else {
        rc = brisk__p256_ecdh(pre, hs->priv_p256, b + 4);
        if (rc == BRISK_OK && brisk__p256_keygen(hs->kx_pub, hs->priv_p256) != BRISK_OK) {
            rc = BRISK_E_ARG;
        }
        hs->kx_pub_len = 65;
    }
    brisk__secure_zero(hs->priv, sizeof hs->priv);
    brisk__secure_zero(hs->priv_p256, sizeof hs->priv_p256);
    memcpy(hs->main, pre, 32);
    brisk__secure_zero(pre, sizeof pre);
    if (rc != BRISK_OK) {
        return brisk__hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    brisk__hs_th_add(hs, m, n);
    hs->n_certs = 0;
    hs->in_base = 0; /* the Certificate may now be overwritten */
    hs->state = BRISK__HS_WAIT12_CR_SHD;
    return BRISK_OK;
}

/* RFC 5246 7.4.4: ClientCertificateType certificate_types<1..2^8-1>, SignatureAndHashAlgorithm
 * supported_signature_algorithms<2..2^16-2>, DistinguishedName certificate_authorities
 * <0..2^16-1>. The CAs are not acted on (one device chain). */
static int t12_on_cr(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    const uint8_t *b = m + 4;
    size_t bl = n - 4, i, sl, j;

    if (bl < 1 || b[0] == 0 || bl - 1 < (size_t)b[0] + 2) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    i = 1 + (size_t)b[0];
    sl = brisk__load_be16(b + i);
    if (sl < 2 || (sl & 1) != 0 || sl > bl - i - 2) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    for (j = 0; j < sl; j += 2) {
        hs->cr_sig_ok |= (uint8_t)(brisk__load_be16(b + i + 2 + j) == 0x0403);
    }
    i += 2 + sl;
    if (bl - i < 2 || brisk__load_be16(b + i) != bl - i - 2) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    hs->cr_send = (uint8_t)(memchr(b + 1, 64, b[0]) != NULL); /* ecdsa_sign, RFC 8422 5.5 */
    brisk__hs_th_add(hs, m, n);
    hs->cr_seen = 1;
    hs->state = BRISK__HS_WAIT12_SHD;
    return BRISK_OK;
}

/* The client flight after ServerHelloDone (RFC 5246 7.3, 7.4.6-7.4.9): [Certificate]
 * ClientKeyExchange [CertificateVerify] queued at INITIAL, the keys, then the Finished in the
 * second run - which the record layer seals under the new key after its mandatory CCS. */
static int t12_on_shd(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    static const uint8_t EMPTY_CERT[7] = {T12_CERTIFICATE, 0, 0, 3, 0, 0, 0};
    uint8_t th[BRISK_HASH_MAX_LEN], ms[48], kb[2 * (32 + 12)], k[32 + 12], fin[4 + 12], *q;
    brisk_hash_alg prf = BRISK_HASH_SHA256;
    size_t kl = 0, il = 0;
    int rc = BRISK_OK, send = 0;

    if (n != 4) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR); /* 7.4.5: empty */
    }
    brisk__hs_th_add(hs, m, n);
    brisk__tls12_suite(hs->suite, &prf, &kl, &il, NULL);
    if (hs->cr_seen) {
#    if BRISK_ENABLE_MTLS
        /* 7.4.6 / RFC 8422 5.5: the device chain only for ecdsa_sign + ecdsa_secp256r1_sha256 */
        send = hs->cfg.client_chain != NULL && hs->cr_send && hs->cr_sig_ok;
        if (send && hs->cfg.client_key == NULL) {
            /* the brisk_sign_fn contract is "raw to-be-signed bytes", and the TLS 1.2
             * CertificateVerify signs the whole (never buffered) transcript: fail closed with
             * internal_error rather than drop the client certificate silently */
            return brisk__hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
        }
        if (send) {
            size_t cl =
                brisk__hs_chain_entries(hs->cfg.client_chain, hs->cfg.client_chain_len, NULL, 0, 0);
            q = cl != 0 ? brisk__hs_reserve(hs, BRISK__EPOCH_INITIAL, 7 + cl) : NULL;
            if (q == NULL) {
                return brisk__hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
            }
            q[0] = T12_CERTIFICATE;
            brisk__store_be24(q + 1, (uint32_t)(3 + cl));
            brisk__store_be24(q + 4, (uint32_t)cl);
            if (brisk__hs_chain_entries(hs->cfg.client_chain, hs->cfg.client_chain_len, q + 7, cl,
                                        0) != cl) {
                return brisk__hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR); /* changed (LIFETIMES) */
            }
            brisk__hs_th_add(hs, q, 7 + cl);
        }
#    endif
        /* 7.4.6: no suitable certificate - "MUST send a certificate message containing no
         * certificates" */
        if (!send && !brisk__hs_queue(hs, BRISK__EPOCH_INITIAL, EMPTY_CERT, sizeof EMPTY_CERT)) {
            return brisk__hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
        }
    }
    /* RFC 8422 5.7: ClientKeyExchange = ECPoint ecdh_Yc<1..2^8-1> */
    q = brisk__hs_reserve(hs, BRISK__EPOCH_INITIAL, 5u + hs->kx_pub_len);
    if (q == NULL) {
        return brisk__hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
    }
    q[0] = T12_CLIENT_KEY_EXCHANGE;
    brisk__store_be24(q + 1, 1u + hs->kx_pub_len);
    q[4] = hs->kx_pub_len;
    memcpy(q + 5, hs->kx_pub, hs->kx_pub_len);
    brisk__hs_th_add(hs, q, 5u + hs->kx_pub_len);
    /* RFC 7627 4: main_secret = PRF(pre_master_secret, "extended master secret",
     * session_hash)[0..47], session_hash = Hash(CH .. ClientKeyExchange) in the PRF's hash */
    brisk__hs_th_snap(hs, th);
    rc = brisk__tls12_prf(prf, hs->main, 32, "extended master secret", th, brisk_hash_len(prf),
                          NULL, 0, ms, sizeof ms);
    memcpy(hs->main, ms, sizeof ms);
    brisk__secure_zero(ms, sizeof ms);
#    if BRISK_ENABLE_MTLS
    if (rc == BRISK_OK && send) {
        /* 7.4.8: ecdsa_secp256r1_sha256 over handshake_messages CH..CKE - SHA-256 whatever the
         * suite's PRF hash, hence th256 was kept running (th_add under TLS 1.2) */
        uint8_t raw[64], cv[8 + 72];
        brisk_hash_ctx c = hs->th256;
        size_t dl;
        brisk__hash_final(&c, BRISK_HASH_SHA256, th);
        rc = brisk__p256_ecdsa_sign(raw, hs->cfg.client_key, th, 32, hs->cfg.sign_rand, 32);
        BRISK__CT_PUBLIC(raw, sizeof raw); /* r || s goes on the wire */
        if (rc == BRISK_OK) {
            dl = brisk__x509_ecdsa_der(raw, cv + 8);
            cv[0] = T12_CERTIFICATE_VERIFY;
            brisk__store_be24(cv + 1, (uint32_t)(4 + dl));
            brisk__store_be16(cv + 4, 0x0403);
            brisk__store_be16(cv + 6, (uint32_t)dl);
            rc = brisk__hs_queue(hs, BRISK__EPOCH_INITIAL, cv, 8 + dl) ? BRISK_OK : BRISK_E_ARG;
        }
        brisk__secure_zero(raw, sizeof raw);
    }
#    endif
    /* RFC 5246 6.3: key_block = PRF(main, "key expansion", server_random || client_random):
     * client_write_key | server_write_key | client_write_IV | server_write_IV (no MAC keys) */
    if (rc == BRISK_OK) {
        rc = brisk__tls12_prf(prf, hs->main, 48, "key expansion", hs->srand, 32, hs->crand, 32, kb,
                              2 * (kl + il));
    }
    /* 7.4.9: verify_data = PRF(main, "client finished", Hash(handshake_messages))[0..11] */
    if (rc == BRISK_OK) {
        brisk__hs_th_snap(hs, th);
        fin[0] = T12_FINISHED;
        fin[1] = 0;
        fin[2] = 0;
        fin[3] = 12;
        rc = brisk__tls12_prf(prf, hs->main, 48, "client finished", th, brisk_hash_len(prf), NULL,
                              0, fin + 4, 12);
    }
    if (rc == BRISK_OK && !brisk__hs_queue(hs, BRISK__EPOCH_HANDSHAKE, fin, sizeof fin)) {
        rc = BRISK_E_ARG;
    }
    /* hand the keys over: send (installed after the plaintext run, then the CCS), receive
     * (waiting for the server's CCS). secret = key || iv. */
    if (rc == BRISK_OK && hs->cfg.on_secret != NULL) {
        memcpy(k, kb, kl);
        memcpy(k + kl, kb + 2 * kl, il);
        rc = hs->cfg.on_secret(hs->cfg.secret_ctx, BRISK__EPOCH_APP, 1, hs->suite, k, kl + il);
        if (rc == 0) {
            memcpy(k, kb + kl, kl);
            memcpy(k + kl, kb + 2 * kl + il, il);
            rc = hs->cfg.on_secret(hs->cfg.secret_ctx, BRISK__EPOCH_APP, 0, hs->suite, k, kl + il);
        }
        rc = rc == 0 ? BRISK_OK : BRISK_E_ARG;
    }
    brisk__secure_zero(kb, sizeof kb);
    brisk__secure_zero(k, sizeof k);
    brisk__secure_zero(fin, sizeof fin);
    brisk__secure_zero(th, sizeof th);
    if (rc != BRISK_OK) {
        return brisk__hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
    }
    hs->state = BRISK__HS_WAIT12_CCS;
    return BRISK_OK;
}

/* RFC 5246 7.4.9: the server's verify_data over everything up to and including our Finished. */
static int t12_on_fin(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    uint8_t th[BRISK_HASH_MAX_LEN], vd[12];
    brisk_hash_alg prf = BRISK_HASH_SHA256;
    int ok, rc;

    if (n != 4 + 12) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    brisk__tls12_suite(hs->suite, &prf, NULL, NULL, NULL);
    brisk__hs_th_snap(hs, th);
    rc = brisk__tls12_prf(prf, hs->main, 48, "server finished", th, brisk_hash_len(prf), NULL, 0,
                          vd, sizeof vd);
    ok = rc == BRISK_OK && brisk__ct_memeq(vd, m + 4, 12);
    BRISK__CT_PUBLIC(&ok, sizeof ok); /* the verdict the alert reveals anyway */
    brisk__secure_zero(vd, sizeof vd);
    brisk__secure_zero(hs->main, sizeof hs->main); /* no resumption, no exporter: done */
    if (!ok) {
        return brisk__hs_fail(hs, BRISK__ALERT_DECRYPT_ERROR);
    }
    hs->state = BRISK__HS_CONNECTED;
    return BRISK_OK;
}

int brisk__tls12_dispatch(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    /* RFC 5246 7.4.1.1: HelloRequest is empty; mid-handshake it is ignored and never hashed; in
     * CONNECTED the record layer answers the first one with no_renegotiation (RFC 5746 4.2,
     * RFC 9325 3.5 - renegotiation is never performed) */
    if (m[0] == T12_HELLO_REQUEST) {
        if (n != 4) {
            return brisk__hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        if (hs->state == BRISK__HS_CONNECTED) {
            hs->ku |= 4;
        }
        return BRISK_OK;
    }
    switch (hs->state) {
    case BRISK__HS_WAIT12_CERT:
        if (m[0] == T12_CERTIFICATE) {
            return t12_on_cert(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT12_SKE: /* 7.3: ECDHE always sends it */
        if (m[0] == T12_SERVER_KEY_EXCHANGE) {
            return t12_on_ske(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT12_CR_SHD:
        if (m[0] == T12_CERTIFICATE_REQUEST) {
            return t12_on_cr(hs, m, n);
        }
        /* fall through */
    case BRISK__HS_WAIT12_SHD:
        if (m[0] == T12_SERVER_HELLO_DONE) {
            return t12_on_shd(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT12_FIN: /* 7.4.9: only after the CCS (brisk__tls12_on_ccs) */
        if (m[0] == T12_FINISHED) {
            return t12_on_fin(hs, m, n);
        }
        break;
    default:
        break;
    }
    /* 7.3: anything else, or anything out of order - CertificateStatus, NewSessionTicket,
     * EncryptedExtensions, KeyUpdate, a Finished before the CCS, any post-handshake message */
    return brisk__hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE);
}

int brisk__tls12_on_ccs(brisk__tls13_hs *hs)
{
    if (hs->state == BRISK__HS_FAILED) {
        return hs->err;
    }
    /* RFC 5246 7.1 / 7.4.9: only right before the server Finished, after our Finished was
     * queued, and never inside a fragmented handshake message */
    if (hs->version != 0x0303 || hs->state != BRISK__HS_WAIT12_CCS || hs->in_len != 0) {
        return brisk__hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE);
    }
    hs->state = BRISK__HS_WAIT12_FIN;
    hs->in_epoch = BRISK__EPOCH_APP;
    return BRISK_OK;
}

#else
typedef int brisk__tls12_empty_tu; /* ISO C: no empty translation unit */
#endif
