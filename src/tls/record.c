/* record.c - TLS 1.3 record layer over TCP (RFC 9846 sect 5) and the sans-I/O connection that
 * drives the handshake engine over it; with BRISK_ENABLE_TLS12 also the TLS 1.2 AEAD framing
 * (RFC 5246 6.2.3.3, RFC 5288 3, RFC 7905 2), its ChangeCipherSpec gate (RFC 5246 7.1) and the
 * HelloRequest answer (RFC 5746 4.2).
 *
 * The contract (failure, local alert choices, constant time) is documented on the tls/record.c
 * block of src/brisk_int.h. This file is the framing, the protection and the connection logic.
 *
 * LENGTHS. Every header length is checked against its limit from the 5-byte header, before a
 * single body byte is buffered; the seal size 5 + len + 1 + pad + 16 is bound-checked term by
 * term (pad <= MAX_INNER - 1 - len) so a 32-bit size_t cannot wrap. Records are opened in place
 * in the caller's buffer at any alignment: headers and nonces go through brisk__load/store_be*.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#define REC_TAG  16
#define REC_OVER (BRISK__TLS_REC_HDR + 1 + REC_TAG) /* a protected record around its content */
#define REC_MAX_UPDATES (((uint64_t)1 << 48) - 1)   /* 4.7.3: the sender's epoch cap */

static brisk_hash_alg rec_alg(uint16_t suite)
{
    return suite == 0x1302 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA256;
}

/* 7.3 key length for the three TLS 1.3 AEAD suites this library speaks, 0 for anything else. */
static size_t rec_key_len(uint16_t suite)
{
    return suite == 0x1301 ? 16 : (suite == 0x1302 || suite == 0x1303) ? 32 : 0;
}

#if BRISK_ENABLE_TLS12
#    define REC12(suite)     brisk__tls12_suite(suite, NULL, NULL, NULL, NULL)
#    define REC12_MAX_CIPHER (16384u + 2048) /* RFC 5246 6.2.3 */
#    define REC12_EXPLICIT   8               /* RFC 5288 3: GCM nonce_explicit */
#else
#    define REC12(suite) 0
#endif

/* ------------------------------------------------------------------ one direction ---------- */

void brisk__tls_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12])
{
    uint8_t s[8];
    size_t i;
    brisk__store_be64(s, seq); /* 5.3: left-padded to iv_length, then XOR - no branch on iv */
    memcpy(nonce, iv, 12);
    for (i = 0; i < 8; i++) {
        nonce[4 + i] ^= s[i];
    }
}

void brisk__tls_dir_wipe(brisk__tls_dir *d)
{
    if (d != NULL) {
        brisk__secure_zero(d, sizeof *d);
    }
}

int brisk__tls_dir_init(brisk__tls_dir *d, unsigned epoch, uint16_t suite, const uint8_t *secret,
                        size_t len)
{
    uint8_t s[BRISK_HASH_MAX_LEN], key[32];
    size_t kl = rec_key_len(suite);
    brisk_hash_alg alg = rec_alg(suite);
    int rc;

    if (d == NULL || secret == NULL) {
        return BRISK_E_ARG;
    }
    if (kl == 0 || len != brisk_hash_len(alg)) {
        brisk__tls_dir_wipe(d);
        return BRISK_E_ARG;
    }
    memcpy(s, secret, len); /* secret may live in d, which is wiped next */
    brisk__tls_dir_wipe(d);
    rc = brisk__hkdf_expand_label(alg, s, len, "key", NULL, 0, key, kl);
    if (rc == BRISK_OK) {
        rc = brisk__hkdf_expand_label(alg, s, len, "iv", NULL, 0, d->iv, sizeof d->iv);
    }
    if (rc == BRISK_OK) {
        if (suite == 0x1303) {
            memcpy(d->k.chacha, key, sizeof d->k.chacha);
        } else {
            rc = brisk__gcm_init(&d->k.gcm, key, kl);
        }
    }
    if (rc == BRISK_OK) {
        memcpy(d->secret, s, len);
        d->suite = suite;
        d->epoch = (uint8_t)epoch;
    } else {
        brisk__tls_dir_wipe(d);
    }
    brisk__secure_zero(s, sizeof s);
    brisk__secure_zero(key, sizeof key);
    return rc;
}

#if BRISK_ENABLE_TLS12
int brisk__tls12_dir_init(brisk__tls_dir *d, uint16_t suite, const uint8_t *key, size_t key_len,
                          const uint8_t *iv, size_t iv_len)
{
    size_t kl = 0, il = 0;
    int rc = BRISK_OK;
    if (d == NULL) {
        return BRISK_E_ARG;
    }
    brisk__tls_dir_wipe(d);
    if (key == NULL || iv == NULL || !brisk__tls12_suite(suite, NULL, &kl, &il, NULL) ||
        key_len != kl || iv_len != il) {
        return BRISK_E_ARG;
    }
    if (il == 12) {
        memcpy(d->k.chacha, key, sizeof d->k.chacha);
    } else {
        rc = brisk__gcm_init(&d->k.gcm, key, kl);
    }
    if (rc != BRISK_OK) {
        brisk__tls_dir_wipe(d);
        return rc;
    }
    memcpy(d->iv, iv, il); /* GCM: the 4-byte salt in iv[0..4) (RFC 5288 3) */
    d->suite = suite;
    d->epoch = BRISK__EPOCH_APP;
    return BRISK_OK;
}

/* RFC 5246 6.2.3.3: additional_data = seq_num || type || version || length (of the PLAINTEXT);
 * type and version as in the record header (on receive: as received, so a changed version byte
 * fails the tag like any other header bit) */
static void rec12_aad(const brisk__tls_dir *d, const uint8_t *hdr, size_t len, uint8_t aad[13])
{
    brisk__store_be64(aad, d->seq);
    memcpy(aad + 8, hdr, 3);
    brisk__store_be16(aad + 11, (uint32_t)len);
}

static int rec12_seal(brisk__tls_dir *d, uint8_t type, const uint8_t *in, size_t len, size_t pad,
                      uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t aad[13], nonce[12], *p;
    size_t ex = d->suite == 0xCCA8 || d->suite == 0xCCA9 ? 0 : REC12_EXPLICIT;
    int rc;

    /* 6.2.1: fragments of at most 2^14; 6.1: the sequence number never wraps; no padding */
    if (pad != 0 || len > BRISK__TLS_MAX_PLAIN || d->seq == UINT64_MAX ||
        cap < BRISK__TLS_REC_HDR + ex + REC_TAG || cap - BRISK__TLS_REC_HDR - ex - REC_TAG < len) {
        return BRISK_E_ARG;
    }
    p = out + BRISK__TLS_REC_HDR + ex;
    if (len != 0) {
        memmove(p, in, len);
    }
    out[0] = type; /* 6.2.3.3: the real type and version, in the clear */
    out[1] = 3;
    out[2] = 3;
    rec12_aad(d, out, len, aad);
    if (ex != 0) { /* RFC 5288 3: nonce_explicit MAY be the sequence number - unique per key */
        memcpy(nonce, d->iv, 4);
        brisk__store_be64(nonce + 4, d->seq);
        memcpy(out + BRISK__TLS_REC_HDR, nonce + 4, ex);
        rc = brisk__gcm_seal(&d->k.gcm, nonce, aad, sizeof aad, p, len, p, p + len);
    } else { /* RFC 7905 2: nonce = fixed_iv XOR the left-padded sequence number */
        brisk__tls_nonce(d->iv, d->seq, nonce);
        rc = brisk__chacha20_poly1305_seal(d->k.chacha, nonce, aad, sizeof aad, p, len, p, p + len);
    }
    brisk__secure_zero(nonce, sizeof nonce);
    if (rc != BRISK_OK) {
        return rc;
    }
    brisk__store_be16(out + 3, (uint32_t)(ex + len + REC_TAG));
    d->seq++;
    *out_len = BRISK__TLS_REC_HDR + ex + len + REC_TAG;
    return BRISK_OK;
}

static int rec12_open(brisk__tls_dir *d, uint8_t *rec, size_t n, uint8_t *type, size_t *len,
                      uint8_t *alert)
{
    uint8_t aad[13], nonce[12], *p = rec + BRISK__TLS_REC_HDR;
    size_t ex = d->suite == 0xCCA8 || d->suite == 0xCCA9 ? 0 : REC12_EXPLICIT, m;
    int rc;

    /* 6.2.3: TLSCiphertext.length MUST NOT exceed 2^14 + 2048 (record_overflow); no AEAD record
     * of a 2^14 fragment is longer than 2^14 + 8 + 16, so anything above that is one too */
    if (n > REC12_MAX_CIPHER || n > BRISK__TLS_MAX_PLAIN + ex + REC_TAG) {
        *alert = BRISK__ALERT_RECORD_OVERFLOW;
        return BRISK_E_PROTO;
    }
    if (d->seq == UINT64_MAX) {
        *alert = BRISK__ALERT_UNEXPECTED_MESSAGE; /* 6.1 MUST NOT wrap: local choice */
        return BRISK_E_PROTO;
    }
    /* RFC 5288 3: "MUST send bad_record_mac for all types of failures", a fragment too short to
     * hold the explicit nonce and the tag included - one indistinguishable outcome */
    if (n < ex + REC_TAG) {
        brisk__secure_zero(p, n);
        *alert = BRISK__ALERT_BAD_RECORD_MAC;
        return BRISK_E_AUTH;
    }
    m = n - ex - REC_TAG;
    rec12_aad(d, rec, m, aad);
    if (ex != 0) { /* the explicit part comes from the wire, never assumed equal to seq */
        memcpy(nonce, d->iv, 4);
        memcpy(nonce + 4, p, ex);
        rc = brisk__gcm_open(&d->k.gcm, nonce, aad, sizeof aad, p + ex, m, p + ex, p + ex + m);
    } else {
        brisk__tls_nonce(d->iv, d->seq, nonce);
        rc = brisk__chacha20_poly1305_open(d->k.chacha, nonce, aad, sizeof aad, p, m, p, p + m);
    }
    brisk__secure_zero(nonce, sizeof nonce);
    if (rc != BRISK_OK) {
        brisk__secure_zero(p, n);
        *alert = BRISK__ALERT_BAD_RECORD_MAC;
        return BRISK_E_AUTH;
    }
    d->seq++;
    if (ex != 0) {
        memmove(p, p + ex, m); /* the content at rec + 5, as for every other record */
    }
    BRISK__CT_PUBLIC(p, m); /* authenticated: the peer's message (see brisk_int.h) */
    /* 6.2.1 (after the ex bound above this cannot exceed 2^14; kept as the rule it is) */
    if (m > BRISK__TLS_MAX_PLAIN) {
        brisk__secure_zero(p, m);
        *alert = BRISK__ALERT_RECORD_OVERFLOW;
        return BRISK_E_PROTO;
    }
    /* 6.2.1: zero-length handshake, alert or CCS fragments MUST NOT be sent */
    if (rec[0] < BRISK__CT_CCS || rec[0] > BRISK__CT_APP || (m == 0 && rec[0] != BRISK__CT_APP)) {
        brisk__secure_zero(p, m);
        *alert = BRISK__ALERT_UNEXPECTED_MESSAGE;
        return BRISK_E_PROTO;
    }
    *type = rec[0];
    *len = m;
    return BRISK_OK;
}
#endif

int brisk__tls_dir_update(brisk__tls_dir *d)
{
    uint8_t next[BRISK_HASH_MAX_LEN];
    brisk_hash_alg alg;
    size_t hl;
    uint64_t n;
    int rc;

    if (d == NULL || d->suite == 0 || d->epoch != BRISK__EPOCH_APP) {
        return BRISK_E_ARG;
    }
    alg = rec_alg(d->suite);
    hl = brisk_hash_len(alg);
    n = d->n_updates + 1;
    /* 7.2: application_traffic_secret_N+1 = HKDF-Expand-Label(N, "traffic upd", "", Hash.length);
     * dir_init then replaces N, its key and its iv (the SHOULD-delete of 7.2) */
    rc = brisk__hkdf_expand_label(alg, d->secret, hl, "traffic upd", NULL, 0, next, hl);
    if (rc == BRISK_OK) {
        rc = brisk__tls_dir_init(d, BRISK__EPOCH_APP, d->suite, next, hl);
    }
    if (rc == BRISK_OK) {
        d->n_updates = n;
    } else {
        brisk__tls_dir_wipe(d);
    }
    brisk__secure_zero(next, sizeof next);
    return rc;
}

int brisk__tls_rec_seal(brisk__tls_dir *d, uint8_t type, uint16_t legacy_ver, const uint8_t *in,
                        size_t len, size_t pad, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t nonce[12];
    size_t body;
    int rc;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (d == NULL || out == NULL || out_len == NULL || (in == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    if (d->suite == 0) { /* 5.1: TLSPlaintext, written directly onto the wire */
        if (pad != 0 || len > BRISK__TLS_MAX_PLAIN || cap < BRISK__TLS_REC_HDR ||
            cap - BRISK__TLS_REC_HDR < len) {
            return BRISK_E_ARG;
        }
        if (len != 0) { /* C99 7.21.1: no NULL to memmove, even for 0 bytes */
            memmove(out + BRISK__TLS_REC_HDR, in, len);
        }
        out[0] = type;
        brisk__store_be16(out + 1, legacy_ver);
        brisk__store_be16(out + 3, (uint32_t)len);
        *out_len = BRISK__TLS_REC_HDR + len;
        return BRISK_OK;
    }
#if BRISK_ENABLE_TLS12
    if (REC12(d->suite)) {
        return rec12_seal(d, type, in, len, pad, out, cap, out_len);
    }
#endif
    /* 5.4: the whole TLSInnerPlaintext <= 2^14 + 1; 5.3: the sequence number never wraps */
    if (len > BRISK__TLS_MAX_INNER - 1 || pad > BRISK__TLS_MAX_INNER - 1 - len ||
        d->seq == UINT64_MAX) {
        return BRISK_E_ARG;
    }
    body = len + 1 + pad;
    if (cap < BRISK__TLS_REC_HDR + REC_TAG || cap - BRISK__TLS_REC_HDR - REC_TAG < body) {
        return BRISK_E_ARG;
    }
    if (len != 0) {
        memmove(out + BRISK__TLS_REC_HDR, in, len);
    }
    out[BRISK__TLS_REC_HDR + len] = type;
    memset(out + BRISK__TLS_REC_HDR + len + 1, 0, pad); /* 5.4: padding MUST be zeros */
    /* 5.2: opaque_type application_data, legacy_record_version 0x0303, AAD = this header */
    out[0] = BRISK__CT_APP;
    out[1] = 3;
    out[2] = 3;
    brisk__store_be16(out + 3, (uint32_t)(body + REC_TAG));
    brisk__tls_nonce(d->iv, d->seq, nonce);
    if (d->suite == 0x1303) {
        rc = brisk__chacha20_poly1305_seal(d->k.chacha, nonce, out, BRISK__TLS_REC_HDR,
                                           out + BRISK__TLS_REC_HDR, body, out + BRISK__TLS_REC_HDR,
                                           out + BRISK__TLS_REC_HDR + body);
    } else {
        rc = brisk__gcm_seal(&d->k.gcm, nonce, out, BRISK__TLS_REC_HDR, out + BRISK__TLS_REC_HDR,
                             body, out + BRISK__TLS_REC_HDR, out + BRISK__TLS_REC_HDR + body);
    }
    brisk__secure_zero(nonce, sizeof nonce);
    if (rc != BRISK_OK) {
        return rc; /* unreachable: body is far below either AEAD's limit */
    }
    d->seq++;
    *out_len = BRISK__TLS_REC_HDR + body + REC_TAG;
    return BRISK_OK;
}

int brisk__tls_rec_open(brisk__tls_dir *d, uint8_t *rec, size_t rec_len, uint8_t *type, size_t *len,
                        uint8_t *alert)
{
    uint8_t nonce[12], *p;
    size_t n, i;
    int rc;

    if (d == NULL || rec == NULL || type == NULL || len == NULL || alert == NULL ||
        rec_len < BRISK__TLS_REC_HDR || rec_len - BRISK__TLS_REC_HDR != brisk__load_be16(rec + 3)) {
        return BRISK_E_ARG;
    }
    *type = 0;
    *len = 0;
    *alert = 0;
    p = rec + BRISK__TLS_REC_HDR;
    n = rec_len - BRISK__TLS_REC_HDR;
    if (d->suite == 0) {
        if (n > BRISK__TLS_MAX_PLAIN) {
            *alert = BRISK__ALERT_RECORD_OVERFLOW; /* 5.1 */
            return BRISK_E_PROTO;
        }
        /* 5: an unknown record type; 5.1 / 5.4: zero-length handshake / alert (and CCS) */
        if (rec[0] < BRISK__CT_CCS || rec[0] > BRISK__CT_APP ||
            (n == 0 && rec[0] != BRISK__CT_APP)) {
            *alert = BRISK__ALERT_UNEXPECTED_MESSAGE;
            return BRISK_E_PROTO;
        }
        *type = rec[0];
        *len = n;
        return BRISK_OK;
    }
#if BRISK_ENABLE_TLS12
    if (REC12(d->suite)) {
        return rec12_open(d, rec, n, type, len, alert);
    }
#endif
    if (n > BRISK__TLS_MAX_CIPHER) {
        *alert = BRISK__ALERT_RECORD_OVERFLOW; /* 5.2 */
        return BRISK_E_PROTO;
    }
    if (d->seq == UINT64_MAX) {
        *alert = BRISK__ALERT_UNEXPECTED_MESSAGE; /* 5.3 MUST NOT wrap: local choice, see header */
        return BRISK_E_PROTO;
    }
    if (n < REC_TAG) { /* cannot even hold the tag: the same failure as a bad one */
        brisk__secure_zero(p, n);
        *alert = BRISK__ALERT_BAD_RECORD_MAC;
        return BRISK_E_AUTH;
    }
    n -= REC_TAG;
    brisk__tls_nonce(d->iv, d->seq, nonce);
    if (d->suite == 0x1303) {
        rc = brisk__chacha20_poly1305_open(d->k.chacha, nonce, rec, BRISK__TLS_REC_HDR, p, n, p,
                                           p + n);
    } else {
        rc = brisk__gcm_open(&d->k.gcm, nonce, rec, BRISK__TLS_REC_HDR, p, n, p, p + n);
    }
    brisk__secure_zero(nonce, sizeof nonce);
    if (rc != BRISK_OK) {
        brisk__secure_zero(p, n + REC_TAG); /* the AEAD zeroed the plaintext; the tag too */
        *alert = BRISK__ALERT_BAD_RECORD_MAC;
        return BRISK_E_AUTH;
    }
    d->seq++;
    /* Authenticated: this is the peer's message, public to this layer from here on (see the
     * CONSTANT TIME note in brisk_int.h). */
    BRISK__CT_PUBLIC(p, n);
    if (n > BRISK__TLS_MAX_INNER) {
        brisk__secure_zero(p, n);
        *alert = BRISK__ALERT_RECORD_OVERFLOW; /* 5.4: the full TLSInnerPlaintext */
        return BRISK_E_PROTO;
    }
    /* 5.4: scan from the end, within the AEAD output only, for the first non-zero octet */
    for (i = n; i != 0 && p[i - 1] == 0; i--) {
    }
    /* none (all zero); a protected CCS or an unknown inner type (5); a zero-length handshake or
     * alert (5.4) - all unexpected_message. Zero-length application data is legal. */
    if (i == 0 || p[i - 1] < BRISK__CT_ALERT || p[i - 1] > BRISK__CT_APP ||
        (i == 1 && p[0] != BRISK__CT_APP)) {
        brisk__secure_zero(p, n);
        *alert = BRISK__ALERT_UNEXPECTED_MESSAGE;
        return BRISK_E_PROTO;
    }
    *type = p[i - 1];
    *len = i - 1;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ the connection -------- */

/* Forget everything but the send key: the receive key, a pending send secret, the engine (and
 * with it every secret it held: exporter, resumption) and whatever sits in the receive buffer. */
static void conn_forget(brisk__tls13_conn *c)
{
    brisk__tls_dir_wipe(&c->rd);
    brisk__secure_zero(c->pend, sizeof c->pend);
    c->pend_epoch = 0;
#if BRISK_ENABLE_TLS12
    brisk__secure_zero(c->rpend, sizeof c->rpend);
    c->rpend_set = 0;
#endif
    brisk__tls13_hs_wipe(c->hs);
    brisk__secure_zero(c->in, c->in_cap);
    c->in_len = c->app_len = c->app_off = 0;
}

/* A local fatal condition (6.2): one alert, queued for conn_pull, and nothing else after it. */
static int conn_fail(brisk__tls13_conn *c, uint8_t alert, int err)
{
    if (c->err == 0) {
        c->alert = alert;
        c->err = err;
        conn_forget(c);
    }
    return c->err;
}

/* The peer's fatal alert (6, 6.2): report it, forget every secret, never answer it. */
static int conn_peer_fatal(brisk__tls13_conn *c, uint8_t desc)
{
    conn_forget(c);
    brisk__tls_dir_wipe(&c->wr);
    c->peer_alert = desc;
    c->alert_sent = 1;
    c->err = BRISK_E_PEER_ALERT;
    return c->err;
}

/* Install the pending send secret once no engine output of an earlier epoch is left to seal:
 * c_hs after the ClientHello, c_ap after the client Finished (4, the on_secret contract). */
static int conn_flush_pend(brisk__tls13_conn *c)
{
    const brisk__tls13_hs *hs = c->hs;
    int rc;
    /* TLS 1.2: the new send key protects the Finished itself, the engine's second output run
     * (RFC 5246 7.4.9), so it installs once the plaintext run before it has been sealed */
    if (c->pend_epoch == 0 || (c->pend_epoch == BRISK__EPOCH_APP && !REC12(c->pend_suite)
                                   ? hs->out_off != hs->out_len
                                   : hs->out_off < hs->out_split)) {
        return BRISK_OK;
    }
#if BRISK_ENABLE_TLS12
    if (REC12(c->pend_suite)) {
        size_t kl = 0, il = 0;
        brisk__tls12_suite(c->pend_suite, NULL, &kl, &il, NULL);
        rc = brisk__tls12_dir_init(&c->wr, c->pend_suite, c->pend, kl, c->pend + kl, il);
        brisk__secure_zero(c->pend, sizeof c->pend);
        c->pend_epoch = 0;
        return rc;
    }
#endif
    rc = brisk__tls_dir_init(&c->wr, c->pend_epoch, c->pend_suite, c->pend,
                             brisk_hash_len(rec_alg(c->pend_suite)));
    brisk__secure_zero(c->pend, sizeof c->pend);
    c->pend_epoch = 0;
    return rc;
}

int brisk__tls13_conn_on_secret(void *ctx, unsigned epoch, int is_send, uint16_t suite,
                                const uint8_t *secret, size_t len)
{
    brisk__tls13_conn *c = (brisk__tls13_conn *)ctx;
#if BRISK_ENABLE_TLS12
    /* TLS 1.2: secret = key || fixed_iv (RFC 5246 6.3). The receive key waits for the server's
     * ChangeCipherSpec (7.1), never installed before it. */
    if (!is_send && REC12(suite)) {
        if (c->rpend_set || len > sizeof c->rpend) {
            return 1;
        }
        memcpy(c->rpend, secret, len);
        c->rpend_suite = suite;
        c->rpend_set = 1;
        return 0;
    }
#endif
    if (!is_send) {
        return brisk__tls_dir_init(&c->rd, epoch, suite, secret, len) != BRISK_OK;
    }
    if (c->pend_epoch != 0 || len > sizeof c->pend) {
        return 1; /* one slot: a second send secret before the first drained is a caller bug */
    }
    memcpy(c->pend, secret, len);
    c->pend_suite = suite;
    c->pend_epoch = (uint8_t)epoch;
    return conn_flush_pend(c) != BRISK_OK;
}

int brisk__tls13_conn_init(brisk__tls13_conn *c, brisk__tls13_hs *hs, uint8_t *rec_in, size_t cap)
{
    if (c == NULL || hs == NULL || rec_in == NULL || cap < BRISK__TLS_REC_IN_MAX) {
        return BRISK_E_ARG;
    }
    memset(c, 0, sizeof *c);
    c->hs = hs;
    c->in = rec_in;
    c->in_cap = cap;
    hs->cfg.on_secret = brisk__tls13_conn_on_secret;
    hs->cfg.secret_ctx = c;
    return BRISK_OK;
}

/* One complete record at c->in. */
static int conn_record(brisk__tls13_conn *c, size_t rlen)
{
    brisk__tls13_hs *hs = c->hs;
    uint8_t *r = c->in, type, alert;
    size_t n = rlen - BRISK__TLS_REC_HDR;
    int rc;

#if BRISK_ENABLE_TLS12
    if (r[0] == BRISK__CT_CCS && hs->version == 0x0303) {
        /* RFC 5246 7.1: {0x01} in the clear, exactly once, and only where the protocol puts
         * it - after our Finished was queued (the engine's WAIT12_CCS) with no handshake
         * fragment pending (a message MUST NOT span it). Anything else - early, a second one, a
         * protected one, a wrong body - is unexpected_message: installing keys on an early CCS
         * is the CVE-2014-0224 class. */
        size_t kl = 0, il = 0;
        if (n != 1 || r[5] != 1 || c->rd.suite != 0 || !c->rpend_set) {
            return conn_fail(c, BRISK__ALERT_UNEXPECTED_MESSAGE, BRISK_E_PROTO);
        }
        rc = brisk__tls12_on_ccs(hs);
        if (rc != BRISK_OK) {
            return conn_fail(c, hs->alert, rc);
        }
        brisk__tls12_suite(c->rpend_suite, NULL, &kl, &il, NULL);
        rc = brisk__tls12_dir_init(&c->rd, c->rpend_suite, c->rpend, kl, c->rpend + kl, il);
        brisk__secure_zero(c->rpend, sizeof c->rpend);
        c->rpend_set = 0;
        return rc == BRISK_OK ? BRISK_OK : conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG);
    }
#endif
    if (r[0] == BRISK__CT_CCS) {
        /* 5, E.4: {0x01} unprotected, after the ClientHello and before the server Finished, is
         * dropped before any decryption attempt; any other CCS is unexpected_message */
        if (n == 1 && r[5] == 1 && hs->state != BRISK__HS_START &&
            hs->state < BRISK__HS_CONNECTED) {
            return BRISK_OK;
        }
        return conn_fail(c, BRISK__ALERT_UNEXPECTED_MESSAGE, BRISK_E_PROTO);
    }
    /* 5.1: application data is always protected; once the receive key is on, nothing but the
     * CCS above may arrive in the clear - a plaintext alert there would let anyone on the path
     * forge a close_notify (truncation) or kill the session. */
    if (REC12(c->rd.suite) ? 0 : (r[0] == BRISK__CT_APP) != (c->rd.suite != 0)) {
        return conn_fail(c, BRISK__ALERT_UNEXPECTED_MESSAGE, BRISK_E_PROTO);
    }
    rc = brisk__tls_rec_open(&c->rd, r, rlen, &type, &n, &alert);
    if (rc != BRISK_OK) {
        return conn_fail(c, alert ? alert : BRISK__ALERT_INTERNAL_ERROR, rc);
    }
    /* RFC 8449 4: once both sides sent record_size_limit (the server's answer is in EE, so
     * this covers every protected record after it), a TLSInnerPlaintext - content, type and
     * padding, i.e. the ciphertext minus the tag - above our advertised limit MUST be
     * record_overflow. */
    if (c->rd.suite != 0 && hs->own_rsl != 0 && hs->peer_rsl != 0 &&
        rlen - BRISK__TLS_REC_HDR - REC_TAG > hs->own_rsl) {
        return conn_fail(c, BRISK__ALERT_RECORD_OVERFLOW, BRISK_E_PROTO);
    }
    r += BRISK__TLS_REC_HDR;
    if (type == BRISK__CT_HANDSHAKE) {
        /* exactly one record per hs_feed: the engine's "nothing after SH / Finished / KeyUpdate
         * in the same call" check is then the 5.1 record-boundary rule */
        rc = brisk__tls13_hs_feed(hs, c->rd.epoch, r, n);
        if (rc != BRISK_OK) {
            return conn_fail(c, hs->alert, rc);
        }
        if (hs->ku & 1) { /* 4.7.3: the next record MUST be under the new key */
            hs->ku &= (uint8_t)~1u;
            if (brisk__tls_dir_update(&c->rd) != BRISK_OK) {
                return conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG);
            }
        }
        if (hs->ku & 2) { /* update_requested: several while silent get one answer */
            hs->ku &= (uint8_t)~2u;
            c->ku_owe = 1;
        }
#if BRISK_ENABLE_TLS12
        if (hs->ku & 4) { /* a TLS 1.2 HelloRequest in CONNECTED: only the first is answered */
            hs->ku &= (uint8_t)~4u;
            c->hr = c->hr == 0 ? 1 : c->hr;
        }
#endif
        return BRISK_OK;
    }
    if (hs->in_len != 0) {
        return conn_fail(c, BRISK__ALERT_UNEXPECTED_MESSAGE, BRISK_E_PROTO); /* 5.1 interleave */
    }
    if (type == BRISK__CT_ALERT) {
        if (n != 2) {
            return conn_fail(c, BRISK__ALERT_DECODE_ERROR, BRISK_E_PROTO); /* 5.1: one Alert */
        }
        /* 6: the level is ignored; close_notify and user_canceled are closure alerts, every
         * other value - unknown ones too - is fatal */
        if (hs->state != BRISK__HS_CONNECTED &&
            (r[1] == BRISK__ALERT_CLOSE_NOTIFY || r[1] == BRISK__ALERT_USER_CANCELED)) {
            /* 6.1: a closure alert before the handshake is done cancels it - never a clean EOF
             * on a connection that was never authenticated */
            return conn_peer_fatal(c, r[1]);
        }
        if (r[1] == BRISK__ALERT_CLOSE_NOTIFY) {
            c->eof = 1; /* 6.1: later bytes are ignored, the write side stays open */
            brisk__tls_dir_wipe(&c->rd);
            return BRISK_OK;
        }
        if (r[1] == BRISK__ALERT_USER_CANCELED) {
            return BRISK_OK; /* 6.1: keep reading until the close_notify that should follow */
        }
        return conn_peer_fatal(c, r[1]);
    }
    if (type != BRISK__CT_APP || c->rd.epoch != BRISK__EPOCH_APP ||
        hs->state != BRISK__HS_CONNECTED) {
        /* 5: application data under the handshake keys, before the handshake is done (TLS 1.2:
         * between the server's CCS and its Finished) */
        return conn_fail(c, BRISK__ALERT_UNEXPECTED_MESSAGE, BRISK_E_PROTO);
    }
    c->app_off = BRISK__TLS_REC_HDR;
    c->app_len = n; /* zero-length application data delivers nothing (5.4) */
    return BRISK_OK;
}

int brisk__tls13_conn_feed(brisk__tls13_conn *c, const uint8_t *in, size_t len, size_t *used)
{
    size_t take, rlen, n;
    uint8_t t;
    int rc;

    if (used != NULL) {
        *used = 0;
    }
    if (c == NULL || used == NULL || (in == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    if (c->err != 0) {
        return c->err;
    }
    while (len != 0) {
        if (c->eof) { /* 6.1: anything after close_notify is taken and ignored, never opened */
            *used += len;
            break;
        }
        if (c->app_len != 0) {
            break; /* conn_read first: the plaintext lives in the receive buffer */
        }
        if (c->in_len < BRISK__TLS_REC_HDR) {
            take = BRISK__TLS_REC_HDR - c->in_len < len ? BRISK__TLS_REC_HDR - c->in_len : len;
            memcpy(c->in + c->in_len, in, take);
            c->in_len += take;
            in += take;
            len -= take;
            *used += take;
            if (c->in_len < BRISK__TLS_REC_HDR) {
                break;
            }
            /* the header alone decides, before one body byte is buffered: 5 unknown type,
             * 5.1 / 5.2 length limit. legacy_record_version is ignored (5.1). */
            t = c->in[0];
            n = brisk__load_be16(c->in + 3);
            if (t < BRISK__CT_CCS || t > BRISK__CT_APP) {
                return conn_fail(c, BRISK__ALERT_UNEXPECTED_MESSAGE, BRISK_E_PROTO);
            }
            /* TLS 1.2 protects every type, so any of them may carry the AEAD expansion;
             * rec12_open applies the tighter 6.2.3 bound */
            if (n > ((t == BRISK__CT_APP || REC12(c->rd.suite)) && c->rd.suite != 0
                         ? BRISK__TLS_MAX_CIPHER
                         : BRISK__TLS_MAX_PLAIN)) {
                return conn_fail(c, BRISK__ALERT_RECORD_OVERFLOW, BRISK_E_PROTO);
            }
        }
        rlen = BRISK__TLS_REC_HDR + brisk__load_be16(c->in + 3);
        take = rlen - c->in_len < len ? rlen - c->in_len : len;
        memcpy(c->in + c->in_len, in, take);
        c->in_len += take;
        in += take;
        len -= take;
        *used += take;
        if (c->in_len < rlen) {
            break;
        }
        c->in_len = 0;
        rc = conn_record(c, rlen);
        if (rc != BRISK_OK) {
            return rc;
        }
    }
    return BRISK_OK;
}

int brisk__tls13_conn_read(brisk__tls13_conn *c, uint8_t *out, size_t cap, size_t *n)
{
    size_t k;
    if (n != NULL) {
        *n = 0;
    }
    if (c == NULL || n == NULL || (out == NULL && cap != 0)) {
        return BRISK_E_ARG;
    }
    if (c->app_len == 0) {
        return c->err;
    }
    k = c->app_len < cap ? c->app_len : cap;
    memcpy(out, c->in + c->app_off, k);
    c->app_off += k;
    c->app_len -= k;
    *n = k;
    return BRISK_OK;
}

/* Content bytes per protected record: RFC 8449 4 caps the whole TLSInnerPlaintext (content +
 * type + padding) at the peer's record_size_limit; a value above 2^14 + 1 is clamped (MAY abort;
 * clamping interoperates). The engine only accepts values >= 64. */
static size_t conn_send_max(const brisk__tls13_conn *c)
{
    size_t rsl = c->hs->peer_rsl;
    return (rsl == 0 || rsl > BRISK__TLS_MAX_INNER ? BRISK__TLS_MAX_INNER : rsl) - 1;
}

/* The owed KeyUpdate(update_not_requested), under the OLD key, then the send key rotates
 * (4.7.3). Also sent unsolicited at the 5.5 threshold. 0 when nothing is owed or it does not
 * fit (ku_owe stays set, and nothing else may be sealed before it). */
static size_t conn_ku(brisk__tls13_conn *c, uint8_t *out, size_t cap)
{
    static const uint8_t KU0[5] = {24, 0, 0, 1, 0};
    size_t k;
    if (c->err != 0 || c->close == 2 || c->wr.epoch != BRISK__EPOCH_APP || REC12(c->wr.suite)) {
        return 0; /* 6.1: nothing at all after our close_notify; TLS 1.2 has no KeyUpdate */
    }
    if (c->wr.seq >= BRISK__TLS_REKEY_SEQ) {
        c->ku_owe = 1;
    }
    if (!c->ku_owe) {
        return 0;
    }
    if (c->wr.n_updates >= REC_MAX_UPDATES) {
        if (c->wr.seq < BRISK__TLS_REKEY_SEQ) {
            c->ku_owe = 0; /* 4.7.3: SHOULD ignore update_requested at the epoch cap */
        } else {
            conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG); /* 5.5: cannot rekey */
        }
        return 0;
    }
    if (brisk__tls_rec_seal(&c->wr, BRISK__CT_HANDSHAKE, 0x0303, KU0, sizeof KU0, 0, out, cap,
                            &k) != BRISK_OK) {
        return 0;
    }
    c->ku_owe = 0;
    if (brisk__tls_dir_update(&c->wr) != BRISK_OK) {
        conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG);
    }
    return k;
}

size_t brisk__tls13_conn_pull(brisk__tls13_conn *c, uint8_t *out, size_t cap)
{
    static const uint8_t CCS[6] = {BRISK__CT_CCS, 3, 3, 0, 1, 1};
    brisk__tls13_hs *hs;
    uint8_t a[2];
    size_t tot = 0, over, ccs, room, n, k;
    unsigned e = 0;

    if (c == NULL || out == NULL) {
        return 0;
    }
    if (c->err != 0) { /* 6.2: exactly one fatal alert, under the current send key */
        a[0] = 2;
        a[1] = c->alert;
        if (c->alert_sent || c->close == 2 ||
            brisk__tls_rec_seal(&c->wr, BRISK__CT_ALERT, 0x0303, a, 2, 0, out, cap, &k) !=
                BRISK_OK) {
            if (c->close == 2) { /* 6.1: nothing at all after our close_notify */
                brisk__tls_dir_wipe(&c->wr);
            }
            return 0;
        }
        c->alert_sent = 1;
        brisk__tls_dir_wipe(&c->wr);
        return k;
    }
    if (c->close == 2) {
        return 0; /* 6.1: nothing after our close_notify, not even a late handshake flight */
    }
    hs = c->hs;
    for (;;) {
        if (conn_flush_pend(c) != BRISK_OK) {
            conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG);
            return tot;
        }
        if (hs->out_off == hs->out_len) {
            break;
        }
        over = c->wr.suite != 0 ? REC_OVER + (REC12(c->wr.suite) ? 7u : 0u) : BRISK__TLS_REC_HDR;
        /* E.4: a 32-byte legacy_session_id means compatibility mode - one dummy CCS right before
         * the first protected record */
        /* RFC 5246 7.1 / 7.4.9: in TLS 1.2 the CCS before the Finished is mandatory */
        ccs = c->wr.suite != 0 && !c->ccs_sent && (hs->session_id_len != 0 || REC12(c->wr.suite))
                  ? sizeof CCS
                  : 0;
        if (cap - tot <= over + ccs) {
            break;
        }
        room = cap - tot - over - ccs;
        n = c->wr.suite != 0 ? conn_send_max(c) : BRISK__TLS_MAX_PLAIN;
        n = brisk__tls13_hs_pull(hs, &e, out + tot + ccs + BRISK__TLS_REC_HDR, room < n ? room : n);
        if (n == 0 || e != c->wr.epoch) {
            conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG); /* engine/key disagree */
            return tot;
        }
        if (ccs != 0) {
            memcpy(out + tot, CCS, sizeof CCS);
            c->ccs_sent = 1;
            tot += ccs;
        }
        /* 5.1: 0x0301 only on an initial ClientHello, 0x0303 on CH2 and everything else */
        if (brisk__tls_rec_seal(
                &c->wr, BRISK__CT_HANDSHAKE,
                e == BRISK__EPOCH_INITIAL && !hs->hrr_seen && hs->version == 0 ? 0x0301 : 0x0303,
                out + tot + BRISK__TLS_REC_HDR, n, 0, out + tot, cap - tot, &k) != BRISK_OK) {
            conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG); /* room was checked */
            return tot;
        }
        tot += k;
    }
    if (hs->out_off != hs->out_len || c->pend_epoch != 0) {
        return tot; /* the flight did not fit: nothing may overtake it */
    }
    tot += conn_ku(c, out + tot, cap - tot);
#if BRISK_ENABLE_TLS12
    if (c->hr == 1 && c->close == 0 && c->err == 0) {
        /* RFC 5746 4.2 / RFC 5246 7.4.1.1: renegotiation refused with a warning
         * no_renegotiation(100), once per connection - later HelloRequests are ignored, so a
         * peer cannot make us produce unbounded output */
        a[0] = 1;
        a[1] = 100;
        if (brisk__tls_rec_seal(&c->wr, BRISK__CT_ALERT, 0x0303, a, 2, 0, out + tot, cap - tot,
                                &k) == BRISK_OK) {
            c->hr = 2;
            tot += k;
        }
    }
#endif
    if (c->close == 1 && !c->ku_owe && c->err == 0) { /* 6.1: close_notify, level warning */
        a[0] = 1;
        a[1] = BRISK__ALERT_CLOSE_NOTIFY;
        if (brisk__tls_rec_seal(&c->wr, BRISK__CT_ALERT, 0x0303, a, 2, 0, out + tot, cap - tot,
                                &k) == BRISK_OK) {
            c->close = 2;
            tot += k;
        }
    }
    return tot;
}

int brisk__tls13_conn_write(brisk__tls13_conn *c, const uint8_t *data, size_t len, size_t *used,
                            uint8_t *out, size_t cap, size_t *out_len)
{
    size_t tot, n, k, max, over;

    if (used != NULL) {
        *used = 0;
    }
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (c == NULL || used == NULL || out == NULL || out_len == NULL || (data == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    if (c->err != 0) {
        return c->err;
    }
    if (c->hs->state != BRISK__HS_CONNECTED || c->close != 0) {
        return BRISK_E_ARG; /* 6.1: no application data after our close_notify */
    }
    tot = brisk__tls13_conn_pull(c, out, cap); /* the client Finished, an owed KeyUpdate */
    max = conn_send_max(c);
    /* 1.3: header + type + tag; 1.2 GCM: header + nonce_explicit + tag (RFC 5288 3) */
    over = REC_OVER + (REC12(c->wr.suite) ? 7u : 0u);
    while (*used < len && c->err == 0) {
#if BRISK_ENABLE_TLS12
        if (REC12(c->wr.suite) && c->wr.seq >= BRISK__TLS_REKEY_SEQ) {
            /* no KeyUpdate in TLS 1.2: at the RFC 9325 4.4 AEAD limit (local: 2^24 records,
             * as for TLS 1.3) the connection is closed cleanly instead */
            c->close = c->close == 0 ? 1 : c->close;
            tot += brisk__tls13_conn_pull(c, out + tot, cap - tot);
            *out_len = tot;
            return BRISK_E_ARG;
        }
#endif
        tot += conn_ku(c, out + tot, cap - tot); /* 5.5 threshold */
        if (c->err != 0 || c->ku_owe || c->pend_epoch != 0 || c->wr.epoch != BRISK__EPOCH_APP ||
            cap - tot <= over) {
            break; /* out is full, or something is owed that must go first */
        }
        n = len - *used;
        n = n < max ? n : max;
        n = n < cap - tot - over ? n : cap - tot - over;
        if (brisk__tls_rec_seal(&c->wr, BRISK__CT_APP, 0x0303, data + *used, n, 0, out + tot,
                                cap - tot, &k) != BRISK_OK) {
            conn_fail(c, BRISK__ALERT_INTERNAL_ERROR, BRISK_E_ARG);
            break;
        }
        tot += k;
        *used += n;
    }
    *out_len = tot;
    return c->err;
}

int brisk__tls13_conn_close(brisk__tls13_conn *c)
{
    if (c == NULL) {
        return BRISK_E_ARG;
    }
    if (c->err != 0) {
        return c->err;
    }
    if (c->close == 0) {
        c->close = 1;
    }
    return BRISK_OK;
}

int brisk__tls13_conn_abort(brisk__tls13_conn *c, uint8_t alert, int err)
{
    return conn_fail(c, alert, err);
}

void brisk__tls13_conn_wipe(brisk__tls13_conn *c)
{
    if (c == NULL) {
        return;
    }
    brisk__tls_dir_wipe(&c->rd);
    brisk__tls_dir_wipe(&c->wr);
    brisk__secure_zero(c->pend, sizeof c->pend);
#if BRISK_ENABLE_TLS12
    brisk__secure_zero(c->rpend, sizeof c->rpend);
#endif
    brisk__tls13_hs_wipe(c->hs);
    if (c->in != NULL) {
        brisk__secure_zero(c->in, c->in_cap);
    }
    brisk__secure_zero(c, sizeof *c);
}

#undef REC_TAG
#undef REC_OVER
#undef REC_MAX_UPDATES
#undef REC12
#if BRISK_ENABLE_TLS12
#    undef REC12_MAX_CIPHER
#    undef REC12_EXPLICIT
#endif
