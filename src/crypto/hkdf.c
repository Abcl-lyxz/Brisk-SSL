/* hkdf.c - HMAC (RFC 2104), HKDF (RFC 5869), TLS 1.3 HKDF-Expand-Label (RFC 9846 7.1).
 *
 * Every buffer that held key material is wiped before returning.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

int brisk_hmac_init(brisk_hmac_ctx *c, brisk_hash_alg alg, const void *key, size_t key_len)
{
    uint8_t k[128], pad[128];
    size_t bl = brisk__hash_block_len(alg), i;
    if (bl == 0) {
        return BRISK_E_ARG;
    }
    memset(k, 0, bl);
    if (key_len > bl) { /* RFC 2104 2: keys longer than a block are hashed first */
        brisk__hash_init(&c->inner, alg);
        brisk__hash_update(&c->inner, alg, key, key_len);
        brisk__hash_final(&c->inner, alg, k);
    } else if (key_len) {
        memcpy(k, key, key_len);
    }
    for (i = 0; i < bl; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    }
    brisk__hash_init(&c->inner, alg);
    brisk__hash_update(&c->inner, alg, pad, bl);
    for (i = 0; i < bl; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    brisk__hash_init(&c->outer, alg);
    brisk__hash_update(&c->outer, alg, pad, bl);
    c->alg = (int)alg;
    brisk__secure_zero(k, sizeof k);
    brisk__secure_zero(pad, sizeof pad);
    return BRISK_OK;
}

void brisk_hmac_update(brisk_hmac_ctx *c, const void *data, size_t len)
{
    brisk__hash_update(&c->inner, (brisk_hash_alg)c->alg, data, len);
}

void brisk_hmac_final(brisk_hmac_ctx *c, uint8_t *out)
{
    brisk_hash_alg alg = (brisk_hash_alg)c->alg;
    uint8_t ih[BRISK_HASH_MAX_LEN];
    brisk__hash_final(&c->inner, alg, ih);
    brisk__hash_update(&c->outer, alg, ih, brisk_hash_len(alg));
    brisk__hash_final(&c->outer, alg, out);
    brisk__secure_zero(ih, sizeof ih);
    brisk__secure_zero(c, sizeof *c);
}

int brisk_hmac(brisk_hash_alg alg, const void *key, size_t key_len, const void *data, size_t len,
               uint8_t *out)
{
    brisk_hmac_ctx c;
    int rc = brisk_hmac_init(&c, alg, key, key_len);
    if (rc) {
        return rc;
    }
    brisk_hmac_update(&c, data, len);
    brisk_hmac_final(&c, out);
    return BRISK_OK;
}

int brisk__hkdf_extract(brisk_hash_alg alg, const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    /* An empty salt as an HMAC key is zero-padded to a block, identical to HashLen zero bytes. */
    return brisk_hmac(alg, salt, salt_len, ikm, ikm_len, prk);
}

int brisk__hkdf_expand(brisk_hash_alg alg, const uint8_t *prk, size_t prk_len, const uint8_t *info,
                       size_t info_len, uint8_t *out, size_t out_len)
{
    brisk_hmac_ctx keyed, c;
    uint8_t t[BRISK_HASH_MAX_LEN], ctr = 1;
    size_t hl = brisk_hash_len(alg), tl = 0, n;
    if (hl == 0 || out_len > 255 * hl) {
        return BRISK_E_ARG;
    }
    brisk_hmac_init(&keyed, alg, prk, prk_len); /* prk is not read again: out may alias it */
    while (out_len) {                           /* T(i) = HMAC(PRK, T(i-1) | info | i) */
        c = keyed;
        brisk_hmac_update(&c, t, tl);
        brisk_hmac_update(&c, info, info_len);
        brisk_hmac_update(&c, &ctr, 1);
        brisk_hmac_final(&c, t);
        tl = hl;
        n = out_len < hl ? out_len : hl;
        memcpy(out, t, n);
        out += n;
        out_len -= n;
        ctr++;
    }
    brisk__secure_zero(&keyed, sizeof keyed);
    brisk__secure_zero(t, sizeof t);
    return BRISK_OK;
}

int brisk__hkdf_expand_label(brisk_hash_alg alg, const uint8_t *secret, size_t secret_len,
                             const char *label, const uint8_t *context, size_t context_len,
                             uint8_t *out, size_t out_len)
{
    /* struct { uint16 length; opaque label<7..255> = "tls13 " + Label; opaque context<0..255>; } */
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t ll = strlen(label), n = 0;
    int rc;
    if (6 + ll > 255 || context_len > 255 || out_len > 0xffff) {
        return BRISK_E_ARG;
    }
    info[n++] = (uint8_t)(out_len >> 8);
    info[n++] = (uint8_t)out_len;
    info[n++] = (uint8_t)(6 + ll);
    memcpy(info + n, "tls13 ", 6);
    memcpy(info + n + 6, label, ll);
    n += 6 + ll;
    info[n++] = (uint8_t)context_len;
    if (context_len) {
        memcpy(info + n, context, context_len);
    }
    n += context_len;
    rc = brisk__hkdf_expand(alg, secret, secret_len, info, n, out, out_len);
    brisk__secure_zero(info, n); /* context may be a transcript hash of secret-dependent data */
    return rc;
}

#if BRISK_ENABLE_TLS12
int brisk__tls12_prf(brisk_hash_alg alg, const uint8_t *secret, size_t secret_len,
                     const char *label, const uint8_t *seed1, size_t seed1_len,
                     const uint8_t *seed2, size_t seed2_len, uint8_t *out, size_t out_len)
{
    /* RFC 5246 5: PRF(secret, label, seed) = P_<hash>(secret, label || seed), where
     * A(0) = label || seed, A(i) = HMAC(secret, A(i-1)) and the output is
     * HMAC(secret, A(1) || label || seed) || HMAC(secret, A(2) || label || seed) || ... cut to
     * out_len. The label and both seed parts are streamed, never concatenated. The loop count
     * depends only on out_len and the hash (public); every intermediate is wiped. */
    brisk_hmac_ctx keyed, c;
    uint8_t a[BRISK_HASH_MAX_LEN], t[BRISK_HASH_MAX_LEN];
    size_t hl = brisk_hash_len(alg), ll, n;

    if (hl == 0 || out == NULL || out_len == 0 || label == NULL || (secret == NULL && secret_len) ||
        (seed1 == NULL && seed1_len) || (seed2 == NULL && seed2_len)) {
        return BRISK_E_ARG;
    }
    ll = strlen(label);
    brisk_hmac_init(&keyed, alg, secret, secret_len); /* secret is not read again */
    c = keyed;                                        /* A(1) = HMAC(secret, label || seed) */
    brisk_hmac_update(&c, label, ll);
    brisk_hmac_update(&c, seed1, seed1_len);
    brisk_hmac_update(&c, seed2, seed2_len);
    brisk_hmac_final(&c, a);
    for (;;) {
        c = keyed;
        brisk_hmac_update(&c, a, hl);
        brisk_hmac_update(&c, label, ll);
        brisk_hmac_update(&c, seed1, seed1_len);
        brisk_hmac_update(&c, seed2, seed2_len);
        brisk_hmac_final(&c, t);
        n = out_len < hl ? out_len : hl;
        memcpy(out, t, n);
        out += n;
        out_len -= n;
        if (out_len == 0) {
            break;
        }
        c = keyed; /* A(i+1) = HMAC(secret, A(i)) */
        brisk_hmac_update(&c, a, hl);
        brisk_hmac_final(&c, a);
    }
    brisk__secure_zero(&keyed, sizeof keyed);
    brisk__secure_zero(a, sizeof a);
    brisk__secure_zero(t, sizeof t);
    return BRISK_OK;
}
#endif
