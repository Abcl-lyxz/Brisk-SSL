/* packet.c - QUIC v1 packets: varints (RFC 9000 16), packet numbers (17.1, A.2, A.3), long and
 * short headers (17.2, 17.3), Initial secrets (RFC 9001 5.2), key/iv/hp (5.1) and packet +
 * header protection (5.3, 5.4). Stateless; the connection (conn.c) owns every counter.
 *
 * RFC 9001 9.5 (MUST): header protection removal, packet number recovery and packet protection
 * removal run without a timing side channel on the packet number or its length. brisk__quic_open
 * unmasks a fixed 4 bytes and selects the PN bytes with masks, decodes the PN without a branch
 * and always runs the AEAD; the one value it declassifies is the PN length, because the AEAD's
 * payload length differs with it (inherent - every implementation does this). The mask itself
 * depends only on the (public) sample and the hp key through the constant-time AES / ChaCha20.
 *
 * 32-bit targets: every 64-bit operation is an add, a compare, a mask or a CONSTANT shift, so no
 * libgcc helper (__udivdi3, __ashldi3, ...) is pulled in; variable shifts are 32-bit only.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_QUIC

/* ------------------------------------------------------------------ varints (RFC 9000 16) --- */

size_t brisk__quic_varint_put(uint8_t *p, size_t cap, uint64_t v)
{
    size_t n = v <= 63                       ? 1
               : v <= 16383                  ? 2
               : v <= 0x3fffffff             ? 4
               : v <= BRISK__QUIC_VARINT_MAX ? 8
                                             : 0;
    if (n == 0 || p == NULL || cap < n) {
        return p == NULL ? n : 0; /* p == NULL: measure only */
    }
    if (n == 1) {
        p[0] = (uint8_t)v;
    } else if (n == 2) {
        brisk__store_be16(p, (uint32_t)v | 0x4000u);
    } else if (n == 4) {
        brisk__store_be32(p, (uint32_t)v | 0x80000000u);
    } else {
        brisk__store_be64(p, v | ((uint64_t)0xc0 << 56));
    }
    return n;
}

int brisk__quic_varint_get(const uint8_t **p, const uint8_t *end, uint64_t *v)
{
    const uint8_t *q = *p;
    size_t n, i;
    uint64_t x;
    if (q == NULL || q >= end) {
        return 0;
    }
    n = (size_t)1 << (q[0] >> 6); /* the 2 MSBs give the length (16) */
    if ((size_t)(end - q) < n) {
        return 0;
    }
    x = q[0] & 0x3f;
    for (i = 1; i < n; i++) {
        x = (x << 8) | q[i];
    }
    *v = x;
    *p = q + n;
    return 1;
}

/* ------------------------------------------------------------------ packet numbers -------- */

/* all-ones if a < b, else 0 (unsigned, no branch) */
static uint64_t lt64(uint64_t a, uint64_t b)
{
    uint64_t m = (uint64_t)0 - ((a ^ ((a ^ b) | ((a - b) ^ b))) >> 63);
    BRISK__CT_BARRIER(m);
    return m;
}

/* RFC 9000 A.3 with pn_win given: candidate = (expected & ~mask) | truncated, moved one window
 * up or down towards expected, never past 2^62. "candidate <= expected - hwin" is written
 * candidate + hwin <= expected so it cannot underflow. */
static uint64_t pn_decode_win(uint64_t largest, uint64_t truncated, uint64_t win)
{
    uint64_t expected = largest + 1, hwin = win >> 1;
    uint64_t cand = (expected & ~(win - 1)) | truncated;
    uint64_t up = ~lt64(expected, cand + hwin) & lt64(cand, ((uint64_t)1 << 62) - win);
    uint64_t down = lt64(expected + hwin, cand) & ~lt64(cand, win) & ~up;
    return cand + (win & up) - (win & down);
}

uint64_t brisk__quic_pn_decode(uint64_t largest, uint64_t truncated, unsigned nbits)
{
    if (nbits != 8 && nbits != 16 && nbits != 24 && nbits != 32) {
        return UINT64_MAX;
    }
    /* 1 << nbits for nbits 8..32 without a variable 64-bit shift */
    return pn_decode_win(largest, truncated, (uint64_t)((uint32_t)1 << (nbits - 1)) << 1);
}

unsigned brisk__quic_pn_len(uint64_t pn, uint64_t largest_acked)
{
    uint64_t twice;
    /* 17.1: the full width until the space is acknowledged */
    if (largest_acked == UINT64_MAX || pn <= largest_acked) {
        return 4;
    }
    /* A.2: at least one bit more than log2 of the unacknowledged range, i.e. twice it fits */
    twice = (pn - largest_acked) << 1;
    return twice <= 0x100 ? 1 : twice <= 0x10000 ? 2 : twice <= 0x1000000 ? 3 : 4;
}

/* ------------------------------------------------------------------ keys (RFC 9001 5) ------ */

int brisk__quic_initial_secrets(const uint8_t *dcid, size_t dcid_len, uint8_t client[32],
                                uint8_t server[32])
{
    /* RFC 9001 5.2: initial_salt for QUIC v1 */
    static const uint8_t SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    uint8_t init[32];
    int rc;
    if (dcid == NULL || dcid_len < 1 || dcid_len > BRISK__QUIC_MAX_CID || client == NULL ||
        server == NULL) {
        return BRISK_E_ARG;
    }
    rc = brisk__hkdf_extract(BRISK_HASH_SHA256, SALT, sizeof SALT, dcid, dcid_len, init);
    if (rc == BRISK_OK) {
        rc =
            brisk__hkdf_expand_label(BRISK_HASH_SHA256, init, 32, "client in", NULL, 0, client, 32);
    }
    if (rc == BRISK_OK) {
        rc =
            brisk__hkdf_expand_label(BRISK_HASH_SHA256, init, 32, "server in", NULL, 0, server, 32);
    }
    brisk__secure_zero(init, sizeof init);
    return rc;
}

int brisk__quic_keys_init(brisk__quic_keys *k, uint16_t suite, const uint8_t *secret, size_t len)
{
    /* 5.1: the suite's hash; key and hp are the AEAD key length (5.4.3 / 5.4.4) */
    brisk_hash_alg alg = suite == 0x1302 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA256;
    size_t kl = suite == 0x1301 ? 16 : 32;
    uint8_t key[32], hp[32];
    int rc;
    if (k == NULL || secret == NULL || (suite != 0x1301 && suite != 0x1302 && suite != 0x1303) ||
        len != brisk_hash_len(alg)) {
        return BRISK_E_ARG;
    }
    brisk__quic_keys_wipe(k);
    rc = brisk__hkdf_expand_label(alg, secret, len, "quic key", NULL, 0, key, kl);
    if (rc == BRISK_OK) {
        rc = brisk__hkdf_expand_label(alg, secret, len, "quic iv", NULL, 0, k->iv, 12);
    }
    if (rc == BRISK_OK) {
        rc = brisk__hkdf_expand_label(alg, secret, len, "quic hp", NULL, 0, hp, kl);
    }
    if (rc == BRISK_OK && suite == 0x1303) {
        memcpy(k->k.chacha, key, 32);
        memcpy(k->hp.chacha, hp, 32);
    } else if (rc == BRISK_OK) {
        rc = brisk__gcm_init(&k->k.gcm, key, kl);
        if (rc == BRISK_OK) {
            rc = brisk__aes_init(&k->hp.aes, hp, kl);
        }
    }
    brisk__secure_zero(key, sizeof key);
    brisk__secure_zero(hp, sizeof hp);
    if (rc != BRISK_OK) {
        brisk__quic_keys_wipe(k);
        return rc;
    }
    k->suite = suite;
    return BRISK_OK;
}

void brisk__quic_keys_wipe(brisk__quic_keys *k)
{
    if (k != NULL) {
        brisk__secure_zero(k, sizeof *k);
    }
}

/* ------------------------------------------------------------------ headers (17.2, 17.3) -- */

int brisk__quic_hdr_parse(const uint8_t *d, size_t len, size_t short_dcid_len, brisk__quic_hdr *h)
{
    const uint8_t *p, *end;
    uint64_t v;
    size_t i;
    if (h == NULL) {
        return BRISK_E_ARG;
    }
    memset(h, 0, sizeof *h);
    if (d == NULL || len < 1) {
        return BRISK_E_PROTO;
    }
    h->first = d[0];
    if (!(d[0] & 0x80)) {
        /* 17.3.1: fixed bit 1 (else discard); the DCID length is ours; room for a sample */
        if (!(d[0] & 0x40) || short_dcid_len > BRISK__QUIC_MAX_CID ||
            len < 1 + short_dcid_len + 20) {
            return BRISK_E_PROTO;
        }
        h->type = BRISK__QPKT_1RTT;
        h->dcid = d + 1;
        h->dcid_len = (uint8_t)short_dcid_len;
        h->pn_off = 1 + short_dcid_len;
        h->pkt_len = len;
        return BRISK_OK;
    }
    /* 17.2 / RFC 8999 5.1: first byte, version, DCID length + DCID, SCID length + SCID */
    if (len < 7) {
        return BRISK_E_PROTO;
    }
    h->version = brisk__load_be32(d + 1);
    i = 5;
    h->dcid_len = d[i++];
    /* 17.2: in v1 a CID longer than 20 bytes means discard */
    if ((h->version == BRISK__QUIC_V1 && h->dcid_len > BRISK__QUIC_MAX_CID) ||
        len - i < (size_t)h->dcid_len + 1) {
        return BRISK_E_PROTO;
    }
    h->dcid = d + i;
    i += h->dcid_len;
    h->scid_len = d[i++];
    if ((h->version == BRISK__QUIC_V1 && h->scid_len > BRISK__QUIC_MAX_CID) ||
        len - i < h->scid_len) {
        return BRISK_E_PROTO;
    }
    h->scid = d + i;
    i += h->scid_len;
    h->pkt_len = len;
    if (h->version != BRISK__QUIC_V1) {
        /* Version Negotiation (17.2.1) or a version we do not speak: the invariants only, and
         * the connection drops it (VN is M6 item 3) */
        h->type = h->version == 0 ? BRISK__QPKT_VN : (uint8_t)((d[0] >> 4) & 3);
        return BRISK_OK;
    }
    if (!(d[0] & 0x40)) {
        return BRISK_E_PROTO; /* 17.2: fixed bit 0 -> discard */
    }
    h->type = (uint8_t)((d[0] >> 4) & 3);
    if (h->type == BRISK__QPKT_RETRY) {
        return BRISK_OK; /* dropped by the connection (M6 item 3) */
    }
    p = d + i;
    end = d + len;
    if (h->type == BRISK__QPKT_INITIAL) {
        /* 17.2.2: Token Length (i) + Token */
        if (!brisk__quic_varint_get(&p, end, &v) || v > (uint64_t)(end - p)) {
            return BRISK_E_PROTO;
        }
        h->token = p;
        h->token_len = (size_t)v;
        p += h->token_len;
    }
    /* 17.2: Length covers the packet number and the payload; a sample needs 4 + 16 bytes
     * after pn_offset (RFC 9001 5.4.2) */
    if (!brisk__quic_varint_get(&p, end, &v) || v > (uint64_t)(end - p) || v < 20) {
        return BRISK_E_PROTO;
    }
    h->pn_off = (size_t)(p - d);
    h->pkt_len = h->pn_off + (size_t)v;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ protection (5.3, 5.4) - */

/* 5.4.3 / 5.4.4: five mask bytes from the 16-byte sample */
static void hp_mask(const brisk__quic_keys *k, const uint8_t *sample, uint8_t mask[5])
{
    static const uint8_t ZERO5[5];
    uint8_t blk[16];
    if (k->suite == 0x1303) {
        /* counter = the first 4 sample bytes LITTLE-endian, nonce = the other 12 */
        brisk__chacha20(k->hp.chacha, brisk__load_le32(sample), sample + 4, ZERO5, mask, 5);
        return;
    }
    brisk__aes_encrypt(&k->hp.aes, sample, blk);
    memcpy(mask, blk, 5);
    brisk__secure_zero(blk, sizeof blk);
}

/* 5.3: nonce = iv XOR the 62-bit packet number, left-padded to 12 bytes */
static void make_nonce(const brisk__quic_keys *k, uint64_t pn, uint8_t nonce[12])
{
    size_t i;
    memcpy(nonce, k->iv, 4);
    brisk__store_be64(nonce + 4, pn);
    for (i = 4; i < 12; i++) {
        nonce[i] ^= k->iv[i];
    }
}

int brisk__quic_seal(brisk__quic_keys *k, uint8_t *pkt, size_t pn_off, unsigned pn_len, uint64_t pn,
                     size_t payload_len)
{
    uint8_t nonce[12], mask[5];
    size_t hl = pn_off + pn_len, i;
    int rc;
    /* 5.4.2: pn_len + payload >= 4 so a full sample exists. 6.6: at most 2^23 packets per
     * AES-GCM key (the ChaCha20 limit is above the PN space). */
    if (k == NULL || pkt == NULL || k->suite == 0 || pn_len < 1 || pn_len > 4 ||
        pn > BRISK__QUIC_VARINT_MAX || pn < k->next_pn || pn_len + payload_len < 4 ||
        (k->suite != 0x1303 && k->n_sealed >= ((uint64_t)1 << 23))) {
        return BRISK_E_ARG;
    }
    pkt[0] = (uint8_t)((pkt[0] & ~3u) | (pn_len - 1)); /* 17.2 / 17.3.1: the PN length bits */
    for (i = 0; i < pn_len; i++) {
        pkt[pn_off + i] = (uint8_t)((uint32_t)pn >> (8 * (pn_len - 1 - i)));
    }
    make_nonce(k, pn, nonce);
    if (k->suite == 0x1303) {
        rc = brisk__chacha20_poly1305_seal(k->k.chacha, nonce, pkt, hl, pkt + hl, payload_len,
                                           pkt + hl, pkt + hl + payload_len);
    } else {
        rc = brisk__gcm_seal(&k->k.gcm, nonce, pkt, hl, pkt + hl, payload_len, pkt + hl,
                             pkt + hl + payload_len);
    }
    brisk__secure_zero(nonce, sizeof nonce);
    if (rc != BRISK_OK) {
        return rc;
    }
    /* 5.4.1: header protection over the protected payload: 4 (long) or 5 (short) low bits of
     * byte 0 and the PN bytes; sample at pn_offset + 4 (5.4.2) */
    hp_mask(k, pkt + pn_off + 4, mask);
    pkt[0] ^= mask[0] & ((pkt[0] & 0x80) ? 0x0f : 0x1f);
    for (i = 0; i < pn_len; i++) {
        pkt[pn_off + i] ^= mask[1 + i];
    }
    brisk__secure_zero(mask, sizeof mask);
    k->n_sealed++;
    k->next_pn = pn + 1;
    return BRISK_OK;
}

int brisk__quic_open(const brisk__quic_keys *k, uint8_t *pkt, size_t pn_off, size_t pkt_len,
                     uint64_t largest, uint8_t *first, uint64_t *pn, size_t *payload_off,
                     size_t *payload_len)
{
    uint8_t mask[5], nonce[12], save[5], b0;
    uint32_t full, tpn = 0, pl, m, n;
    uint64_t win = 0, p;
    size_t hl, ctl, i;
    int rc;
    if (k == NULL || pkt == NULL || first == NULL || pn == NULL || payload_off == NULL ||
        payload_len == NULL || k->suite == 0 || pn_off > pkt_len) {
        return BRISK_E_ARG;
    }
    /* 5.4.2 (MUST): a packet too short for a full sample is discarded */
    if (pkt_len - pn_off < 20) {
        return BRISK_E_PROTO;
    }
    /* the protected header goes back on failure: no hp mask output is left in the buffer */
    save[0] = pkt[0];
    memcpy(save + 1, pkt + pn_off, 4);
    hp_mask(k, pkt + pn_off + 4, mask);
    b0 = (uint8_t)(pkt[0] ^ (mask[0] & ((pkt[0] & 0x80) ? 0x0f : 0x1f)));
    pl = (uint32_t)(b0 & 3) + 1;
    /* 9.5: unmask a fixed 4 bytes, then select the truncated PN and its window with masks */
    full = brisk__load_be32(pkt + pn_off) ^ brisk__load_be32(mask + 1);
    for (n = 1; n <= 4; n++) {
        uint32_t x = pl ^ n;
        m = (uint32_t)0 - (1 ^ ((x | ((uint32_t)0 - x)) >> 31)); /* all-ones iff pl == n */
        BRISK__CT_BARRIER(m);
        tpn |= (full >> (32 - 8 * n)) & m;
        win |= ((uint64_t)((uint32_t)1 << (8 * n - 1)) << 1) & (((uint64_t)m << 32) | m);
    }
    p = pn_decode_win(largest, tpn, win);
    for (i = 0; i < 4; i++) {
        /* 0xff for the pl PN bytes, 0 for the ciphertext after them */
        uint8_t sel = (uint8_t)((uint32_t)0 - (((uint32_t)i - pl) >> 31));
        pkt[pn_off + i] ^= mask[1 + i] & sel;
    }
    pkt[0] = b0;
    brisk__secure_zero(mask, sizeof mask);
    /* the payload offset moves with the PN length: that much is inherent (see the file head) */
    BRISK__CT_PUBLIC(&pl, sizeof pl);
    hl = pn_off + pl;
    ctl = pkt_len - hl - 16;
    make_nonce(k, p, nonce);
    if (k->suite == 0x1303) {
        rc = brisk__chacha20_poly1305_open(k->k.chacha, nonce, pkt, hl, pkt + hl, ctl, pkt + hl,
                                           pkt + hl + ctl);
    } else {
        rc = brisk__gcm_open(&k->k.gcm, nonce, pkt, hl, pkt + hl, ctl, pkt + hl, pkt + hl + ctl);
    }
    brisk__secure_zero(nonce, sizeof nonce);
    if (rc != BRISK_OK) {
        pkt[0] = save[0];
        memcpy(pkt + pn_off, save + 1, pl); /* the payload after them stays wiped */
        brisk__secure_zero(save, sizeof save);
        return BRISK_E_AUTH; /* 5.5: drop; the AEAD wiped the payload */
    }
    brisk__secure_zero(save, sizeof save);
    BRISK__CT_PUBLIC(&p, sizeof p); /* authenticated: the receiver's to know */
    BRISK__CT_PUBLIC(&b0, sizeof b0);
    *first = b0;
    *pn = p;
    *payload_off = hl;
    *payload_len = ctl;
    return BRISK_OK;
}

#endif /* BRISK_ENABLE_QUIC */
