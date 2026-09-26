/* api.c - the public crypto API (BRISK_ENABLE_CRYPTO_API): thin wrappers over the primitives the
 * TLS stack runs, adding only what a caller outside the library needs: key-length checks and a
 * wipe of every expanded key. The calls that draw randomness (brisk_random, the keygens,
 * brisk_p256_sign) live in src/os/linux_rand.c, since src/os/ is linked on Linux only.
 * Contracts are in include/brisk.h; the primitives' own ones in src/brisk_int.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_CRYPTO_API

/* seal != 0: writes stag. seal == 0: checks otag. */
static int aead(int seal, brisk_aead_alg alg, const uint8_t *key, size_t key_len,
                const uint8_t nonce[12], const void *aad, size_t aad_len, const void *in,
                size_t len, void *out, uint8_t *stag, const uint8_t *otag)
{
    const uint8_t *a = (const uint8_t *)aad, *i = (const uint8_t *)in;
    uint8_t *o = (uint8_t *)out;
    brisk__gcm_key k;
    int rc;
    if (alg == BRISK_AEAD_CHACHA20_POLY1305) {
        if (key_len != BRISK__CHACHA20_KEY_LEN) {
            return BRISK_E_ARG;
        }
        return seal ? brisk__chacha20_poly1305_seal(key, nonce, a, aad_len, i, len, o, stag)
                    : brisk__chacha20_poly1305_open(key, nonce, a, aad_len, i, len, o, otag);
    }
    if (!((alg == BRISK_AEAD_AES128_GCM && key_len == 16) ||
          (alg == BRISK_AEAD_AES256_GCM && key_len == 32))) {
        return BRISK_E_ARG;
    }
    rc = brisk__gcm_init(&k, key, key_len);
    if (rc == BRISK_OK) {
        rc = seal ? brisk__gcm_seal(&k, nonce, a, aad_len, i, len, o, stag)
                  : brisk__gcm_open(&k, nonce, a, aad_len, i, len, o, otag);
    }
    brisk__secure_zero(&k, sizeof k);
    return rc;
}

int brisk_aead_seal(brisk_aead_alg alg, const uint8_t *key, size_t key_len,
                    const uint8_t nonce[BRISK_AEAD_NONCE_LEN], const void *aad, size_t aad_len,
                    const void *in, size_t len, void *out, uint8_t tag[BRISK_AEAD_TAG_LEN])
{
    return aead(1, alg, key, key_len, nonce, aad, aad_len, in, len, out, tag, NULL);
}

int brisk_aead_open(brisk_aead_alg alg, const uint8_t *key, size_t key_len,
                    const uint8_t nonce[BRISK_AEAD_NONCE_LEN], const void *aad, size_t aad_len,
                    const void *in, size_t len, void *out, const uint8_t tag[BRISK_AEAD_TAG_LEN])
{
    return aead(0, alg, key, key_len, nonce, aad, aad_len, in, len, out, NULL, tag);
}

int brisk_hkdf_extract(brisk_hash_alg alg, const void *salt, size_t salt_len, const void *ikm,
                       size_t ikm_len, uint8_t *prk)
{
    return brisk__hkdf_extract(alg, (const uint8_t *)salt, salt_len, (const uint8_t *)ikm, ikm_len,
                               prk);
}

int brisk_hkdf_expand(brisk_hash_alg alg, const uint8_t *prk, size_t prk_len, const void *info,
                      size_t info_len, uint8_t *out, size_t out_len)
{
    if (prk_len < brisk_hash_len(alg)) { /* RFC 5869 2.3: PRK is at least HashLen octets */
        return BRISK_E_ARG;
    }
    return brisk__hkdf_expand(alg, prk, prk_len, (const uint8_t *)info, info_len, out, out_len);
}

int brisk_x25519(uint8_t shared[BRISK_X25519_LEN], const uint8_t priv[BRISK_X25519_LEN],
                 const uint8_t peer[BRISK_X25519_LEN])
{
    return brisk__x25519(shared, priv, peer);
}

int brisk_p256_ecdh(uint8_t shared[BRISK_P256_SHARED_LEN], const uint8_t priv[BRISK_P256_PRIV_LEN],
                    const uint8_t peer[BRISK_P256_PUB_LEN])
{
    return brisk__p256_ecdh(shared, priv, peer);
}

int brisk_p256_verify(const uint8_t pub[BRISK_P256_PUB_LEN], const uint8_t *hash, size_t hash_len,
                      const uint8_t sig[BRISK_P256_SIG_LEN])
{
    return brisk__p256_ecdsa_verify(pub, hash, hash_len, sig);
}

#    if BRISK_ENABLE_P384
int brisk_p384_verify(const uint8_t pub[BRISK_P384_PUB_LEN], const uint8_t *hash, size_t hash_len,
                      const uint8_t sig[BRISK_P384_SIG_LEN])
{
    return brisk__p384_ecdsa_verify(pub, hash, hash_len, sig);
}
#    endif

int brisk_rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                           brisk_hash_alg alg, const uint8_t *hash, size_t hash_len,
                           const uint8_t *sig, size_t sig_len)
{
    return brisk__rsa_pkcs1_verify(n, n_len, e, e_len, alg, hash, hash_len, sig, sig_len);
}

int brisk_rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                         brisk_hash_alg alg, size_t salt_len, const uint8_t *hash, size_t hash_len,
                         const uint8_t *sig, size_t sig_len)
{
    return brisk__rsa_pss_verify(n, n_len, e, e_len, alg, salt_len, hash, hash_len, sig, sig_len);
}

#endif /* BRISK_ENABLE_CRYPTO_API */
