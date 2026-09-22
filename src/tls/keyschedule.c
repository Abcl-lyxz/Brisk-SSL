/* keyschedule.c - TLS 1.3 key schedule (RFC 9846 sect 7.1) and Finished MAC (sect 4.5.3).
 *
 * All composition: brisk__hkdf_extract and brisk__hkdf_expand_label do the work; this module
 * threads them in the order the spec names, wipes the intermediate secrets, and exposes the
 * four traffic secrets a record layer needs (RFC 9846 sect 7.3, and RFC 9001 sect 5.1 for QUIC).
 *
 * NOTHING SECRET REACHES A BRANCH here: the branches are on the requested algorithm (public), a
 * NULL PSK pointer (public), or the return codes of the primitives (public). The Finished MAC
 * compare that the handshake engine performs is a brisk__ct_memeq on the output of
 * brisk__tls_finished_mac, not on state kept by this module.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* HashLen zero octets; large enough for the widest hash the library carries (SHA-512 = 64,
 * BRISK_HASH_MAX_LEN). The key-schedule uses this for the salt of HKDF-Extract(0^HashLen, ...)
 * (RFC 9846 sect 7.1) and for the empty-PSK IKM in the early-secret step. Static const so the
 * whole compilation unit shares one copy - the M8 amalgamation folds this and it stays
 * BRISK_HASH_MAX_LEN bytes of .rodata. */
static const uint8_t ZEROS[BRISK_HASH_MAX_LEN] = {0};

/* Hash(""), computed on the stack. RFC 9846 sect 7.1 says the Messages argument of Derive-Secret
 * is empty for the two "derived" stages, so its Transcript-Hash is the hash of the empty string -
 * which is a compile-time constant per algorithm but naming it here would cost bytes for a value
 * the caller reaches twice per handshake. Kept inline. */
static void empty_hash(brisk_hash_alg alg, uint8_t *out)
{
    brisk_hash_ctx c;
    brisk__hash_init(&c, alg);
    brisk__hash_final(&c, alg, out);
}

/* Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, TH(Messages), HashLen)
 * (RFC 9846 sect 7.1). `th` is HashLen bytes and MUST already be Transcript-Hash(Messages); the
 * caller (this file or the handshake engine) owns the transcript. */
static int derive_secret(brisk_hash_alg alg, const uint8_t *secret, const char *label,
                         const uint8_t *th, uint8_t *out)
{
    size_t hl = brisk_hash_len(alg);
    return brisk__hkdf_expand_label(alg, secret, hl, label, th, hl, out, hl);
}

int brisk__tls_ks_init(brisk__tls_ks *ks, brisk_hash_alg alg, const uint8_t *psk, size_t psk_len)
{
    size_t hl = brisk_hash_len(alg);
    if (!hl) {
        return BRISK_E_ARG;
    }
    ks->alg = alg;
    /* early_secret = HKDF-Extract(0^HashLen, PSK|0^HashLen). RFC 9846 sect 7.1: when no PSK is in
     * use, PSK is HashLen zeros - the caller can pass NULL to say that, and we feed ZEROS in
     * without a per-caller allocation. The extract result is HashLen bytes and fits ks->secret. */
    if (psk == NULL || psk_len == 0) {
        return brisk__hkdf_extract(alg, ZEROS, hl, ZEROS, hl, ks->secret);
    }
    return brisk__hkdf_extract(alg, ZEROS, hl, psk, psk_len, ks->secret);
}

int brisk__tls_ks_derive_handshake(brisk__tls_ks *ks, const uint8_t *dhe, size_t dhe_len,
                                   const uint8_t *th_ch_sh, uint8_t *c_hs_ts, uint8_t *s_hs_ts)
{
    uint8_t derived[BRISK_HASH_MAX_LEN];
    uint8_t hs[BRISK_HASH_MAX_LEN];
    uint8_t eh[BRISK_HASH_MAX_LEN];
    size_t hl = brisk_hash_len(ks->alg);
    int rc;

    empty_hash(ks->alg, eh);
    /* derived = Derive-Secret(early_secret, "derived", "") */
    rc = derive_secret(ks->alg, ks->secret, "derived", eh, derived);
    if (rc) {
        goto out;
    }
    /* handshake_secret = HKDF-Extract(derived, DHE) */
    rc = brisk__hkdf_extract(ks->alg, derived, hl, dhe, dhe_len, hs);
    if (rc) {
        goto out;
    }
    /* c hs traffic / s hs traffic over TH(CH..SH) */
    rc = derive_secret(ks->alg, hs, "c hs traffic", th_ch_sh, c_hs_ts);
    if (rc) {
        goto out;
    }
    rc = derive_secret(ks->alg, hs, "s hs traffic", th_ch_sh, s_hs_ts);
    if (rc) {
        goto out;
    }
    /* Advance ks->secret to handshake_secret for the next stage. */
    memcpy(ks->secret, hs, hl);
out:
    brisk__secure_zero(derived, sizeof derived);
    brisk__secure_zero(hs, sizeof hs);
    brisk__secure_zero(eh, sizeof eh);
    return rc;
}

int brisk__tls_ks_derive_application(brisk__tls_ks *ks, const uint8_t *th_ch_sf, uint8_t *c_ap_ts,
                                     uint8_t *s_ap_ts, uint8_t *exporter_ms)
{
    uint8_t derived[BRISK_HASH_MAX_LEN];
    uint8_t master[BRISK_HASH_MAX_LEN];
    uint8_t eh[BRISK_HASH_MAX_LEN];
    size_t hl = brisk_hash_len(ks->alg);
    int rc;

    empty_hash(ks->alg, eh);
    /* derived = Derive-Secret(handshake_secret, "derived", "") */
    rc = derive_secret(ks->alg, ks->secret, "derived", eh, derived);
    if (rc) {
        goto out;
    }
    /* master_secret = HKDF-Extract(derived, 0^HashLen) */
    rc = brisk__hkdf_extract(ks->alg, derived, hl, ZEROS, hl, master);
    if (rc) {
        goto out;
    }
    /* c ap traffic / s ap traffic / exp master, all over TH(CH..server Finished) */
    rc = derive_secret(ks->alg, master, "c ap traffic", th_ch_sf, c_ap_ts);
    if (rc) {
        goto out;
    }
    rc = derive_secret(ks->alg, master, "s ap traffic", th_ch_sf, s_ap_ts);
    if (rc) {
        goto out;
    }
    rc = derive_secret(ks->alg, master, "exp master", th_ch_sf, exporter_ms);
    if (rc) {
        goto out;
    }
    /* Advance ks->secret to master_secret for the resumption stage. */
    memcpy(ks->secret, master, hl);
out:
    brisk__secure_zero(derived, sizeof derived);
    brisk__secure_zero(master, sizeof master);
    brisk__secure_zero(eh, sizeof eh);
    return rc;
}

int brisk__tls_ks_derive_resumption(brisk__tls_ks *ks, const uint8_t *th_ch_cf, uint8_t *res_ms)
{
    /* resumption_master_secret = Derive-Secret(master_secret, "res master", CH..client Finished).
     */
    return derive_secret(ks->alg, ks->secret, "res master", th_ch_cf, res_ms);
}

int brisk__tls_finished_mac(brisk_hash_alg alg, const uint8_t *base_key,
                            const uint8_t *transcript_hash, uint8_t *out)
{
    uint8_t fin_key[BRISK_HASH_MAX_LEN];
    size_t hl = brisk_hash_len(alg);
    int rc;
    if (!hl) {
        return BRISK_E_ARG;
    }
    /* finished_key = HKDF-Expand-Label(base_key, "finished", "", HashLen) */
    rc = brisk__hkdf_expand_label(alg, base_key, hl, "finished", NULL, 0, fin_key, hl);
    if (rc) {
        brisk__secure_zero(fin_key, sizeof fin_key);
        return rc;
    }
    /* verify_data = HMAC(finished_key, transcript_hash) */
    rc = brisk_hmac(alg, fin_key, hl, transcript_hash, hl, out);
    brisk__secure_zero(fin_key, sizeof fin_key);
    return rc;
}

int brisk__tls_ks_exporter(brisk_hash_alg alg, const uint8_t *exporter_ms, const char *label,
                           const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len)
{
    /* RFC 9846 sect 7.5:
     *   TLS-Exporter(label, ctx, L) =
     *       HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter", Hash(ctx), L)
     * where Secret is the exporter_master_secret. */
    uint8_t inter[BRISK_HASH_MAX_LEN];
    uint8_t ctx_hash[BRISK_HASH_MAX_LEN];
    uint8_t eh[BRISK_HASH_MAX_LEN];
    brisk_hash_ctx hc;
    size_t hl = brisk_hash_len(alg);
    int rc;
    if (!hl) {
        return BRISK_E_ARG;
    }
    /* Derive-Secret(exporter_master, label, "") = HKDF-Expand-Label(., label, Hash(""), HashLen) */
    empty_hash(alg, eh);
    rc = brisk__hkdf_expand_label(alg, exporter_ms, hl, label, eh, hl, inter, hl);
    if (rc) {
        goto out;
    }
    /* Hash(ctx) - ctx_len == 0 is legal (ctx may be NULL then). */
    brisk__hash_init(&hc, alg);
    if (ctx_len) {
        brisk__hash_update(&hc, alg, ctx, ctx_len);
    }
    brisk__hash_final(&hc, alg, ctx_hash);
    /* HKDF-Expand-Label(inter, "exporter", Hash(ctx), out_len) */
    rc = brisk__hkdf_expand_label(alg, inter, hl, "exporter", ctx_hash, hl, out, out_len);
out:
    brisk__secure_zero(inter, sizeof inter);
    brisk__secure_zero(ctx_hash, sizeof ctx_hash);
    brisk__secure_zero(eh, sizeof eh);
    return rc;
}

void brisk__tls_ks_wipe(brisk__tls_ks *ks)
{
    if (ks) {
        brisk__secure_zero(ks->secret, sizeof ks->secret);
        ks->alg = 0;
    }
}
