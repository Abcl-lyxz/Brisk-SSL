/* handshake.c - TLS 1.3 client handshake engine (RFC 9846 sect 4), sans-I/O.
 *
 * The contract (states, epochs, secrets, alerts, the known post-handshake gap) is documented on
 * the tls/handshake.c block of src/brisk_int.h. This file is the parser and the state machine.
 *
 * WHAT IS PUBLIC AND WHAT IS NOT. Every byte of every handshake message is public: the parser
 * branches on all of them. The secrets are the ECDHE private key, the (EC)DHE shared secret, the
 * key-schedule stages and the four traffic secrets; none of them reaches a branch or an index
 * here. The two verdicts that do are public by design and declassified where they are made: the
 * all-zero X25519 result (x25519.c) and the server Finished compare below, which is
 * brisk__ct_memeq over HashLen and always ends in decrypt_error, never in a secret-dependent
 * alert.
 *
 * LENGTHS. Every uint16/uint24 read goes through brisk__load_be16/24 (byte access, any
 * endianness, any alignment) and is compared against what remains BEFORE any addition, so a
 * 0xFFFFFF length cannot wrap a 32-bit size_t.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* Handshake message types (RFC 9846 4). */
enum {
    HS_CLIENT_HELLO = 1,
    HS_SERVER_HELLO = 2,
    HS_NEW_SESSION_TICKET = 4,
    HS_ENCRYPTED_EXTENSIONS = 8,
    HS_CERTIFICATE = 11,
    HS_CERTIFICATE_REQUEST = 13,
    HS_CERTIFICATE_VERIFY = 15,
    HS_FINISHED = 20,
    HS_KEY_UPDATE = 24,
    HS_MESSAGE_HASH = 254
};

/* Extension types (RFC 9846 4.3). */
enum {
    EXT_SERVER_NAME = 0,
    EXT_SUPPORTED_GROUPS = 10,
    EXT_SIGNATURE_ALGORITHMS = 13,
    EXT_ALPN = 16,
    EXT_PADDING = 21,
    EXT_RECORD_SIZE_LIMIT = 28,
    EXT_SESSION_TICKET = 35,
    EXT_PSK = 41,
    EXT_EARLY_DATA = 42,
    EXT_SUPPORTED_VERSIONS = 43,
    EXT_COOKIE = 44,
    EXT_PSK_MODES = 45,
    EXT_KEY_SHARE = 51,
    EXT_QUIC_TP = 57,
    EXT_RENEGOTIATION_INFO = 0xff01
};

enum { GROUP_X25519 = 0x001d, GROUP_P256 = 0x0017 };

/* Where each extension RFC 9846 4.3 Table 1 recognises may appear in a SERVER message. An
 * extension outside this table is one this client does not recognise: in a CertificateRequest
 * it is ignored (4.4.2), and in any other server message it can only be the echo of something
 * the ClientHello offered, which this engine refuses (see hs_client_hello's allow-list). */
enum { IN_SH = 1, IN_HRR = 2, IN_EE = 4, IN_CR = 8, IN_CT = 16, IN_NST = 32 };
static const struct {
    uint16_t type;
    uint8_t where;
} EXT_TABLE[] = {{0, IN_EE | IN_CR},
                 {5, IN_CR | IN_CT},
                 {10, IN_EE},
                 {13, IN_CR},
                 {14, IN_EE},
                 {15, IN_EE},
                 {16, IN_EE},
                 {19, IN_EE},
                 {20, IN_EE},
                 {21, 0},
                 {27, IN_CR},
                 {28, IN_EE},
                 {34, IN_CR | IN_CT},
                 {39, IN_EE},
                 {41, IN_SH},
                 {42, IN_EE | IN_NST},
                 {43, IN_SH | IN_HRR},
                 {44, IN_HRR},
                 {45, 0},
                 {47, IN_CR},
                 {48, IN_CR},
                 {49, 0},
                 {50, IN_CR},
                 {51, IN_SH | IN_HRR},
                 {52, IN_CR | IN_CT},
                 {55, IN_EE},
                 {56, IN_EE},
                 {57, IN_EE},
                 {58, IN_EE},
                 {64768, 0},
                 {65037, IN_HRR | IN_EE}};

/* What a ClientHello handed to hs_client_hello may carry: the extensions this engine either
 * processes or can safely refuse the echo of. Anything else is a caller bug (BRISK_E_ARG),
 * because the engine would otherwise accept a server answer it never checks. The RFC 8448
 * ClientHellos need session_ticket, renegotiation_info, psk_key_exchange_modes, padding and
 * record_size_limit; the server may echo only the last one (EE, range-checked and kept in
 * peer_rsl), ALPN (EE, checked against the offer) and pre_shared_key (SH, 4.3.11). early_data is
 * never allowed: no 0-RTT (docs/ARCHITECTURE.md). */
static const uint16_t CH_ALLOWED[] = {EXT_SERVER_NAME,
                                      EXT_SUPPORTED_GROUPS,
                                      EXT_SIGNATURE_ALGORITHMS,
                                      EXT_ALPN,
                                      EXT_PSK,
                                      EXT_PADDING,
                                      EXT_RECORD_SIZE_LIMIT,
                                      EXT_SESSION_TICKET,
                                      EXT_SUPPORTED_VERSIONS,
                                      EXT_COOKIE,
                                      EXT_PSK_MODES,
                                      EXT_KEY_SHARE,
                                      EXT_QUIC_TP,
                                      EXT_RENEGOTIATION_INFO};

/* The library's default offer (brisk_int.h, brisk__tls13_ch_params). ChaCha20 first: AES here
 * is bitsliced software on every target (docs/ARCHITECTURE.md). */
static const uint16_t DEF_SUITES[] = {0x1303, 0x1301, 0x1302};
static const uint16_t DEF_GROUPS[] = {GROUP_X25519, GROUP_P256};
static const uint16_t DEF_SIGS[] = {0x0403,
#if BRISK_ENABLE_P384
                                    0x0503,
#endif
                                    0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601};

/* A CertificateVerify is at most scheme(2) + len(2) + the widest signature this build checks:
 * RSA at BRISK_RSA_MAX_BITS. A DER ECDSA-Sig-Value at P-384 is ~104 bytes, far below. */
#define HS_CV_MAX (4 + 4 + BRISK_RSA_MAX_BITS / 8)
#define HS_IN_CAP (4 + BRISK_TLS_MAX_HS_MSG + HS_CV_MAX)

struct hs_align_probe {
    char c;
    brisk__x509_cert x;
};
#define HS_CERT_ALIGN offsetof(struct hs_align_probe, x)

/* ------------------------------------------------------------------ small helpers ---------- */

static brisk_hash_alg hs_alg(uint16_t suite)
{
    return suite == 0x1302 ? BRISK_HASH_SHA384 : BRISK_HASH_SHA256; /* RFC 9846 B.4 */
}

static int hs_known_suite(uint16_t s)
{
    return s == 0x1301 || s == 0x1302 || s == 0x1303;
}

static size_t hs_share_len(uint16_t group)
{
    return group == GROUP_X25519 ? 32u : group == GROUP_P256 ? 65u : 0u; /* 4.3.8.2, RFC 7748 */
}

static int hs_in_list(const uint16_t *list, size_t n, uint16_t v)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (list[i] == v) {
            return 1;
        }
    }
    return 0;
}

static int hs_ext_index(uint16_t type)
{
    size_t i;
    for (i = 0; i < sizeof EXT_TABLE / sizeof EXT_TABLE[0]; i++) {
        if (EXT_TABLE[i].type == type) {
            return (int)i;
        }
    }
    return -1;
}

/* One step over an extension block: 1 with type, data and dlen set, 0 at the end, -1 malformed. */
static int hs_ext_next(const uint8_t **p, const uint8_t *end, uint16_t *type, const uint8_t **data,
                       size_t *dlen)
{
    size_t left = (size_t)(end - *p), n;
    if (left == 0) {
        return 0;
    }
    if (left < 4) {
        return -1;
    }
    n = brisk__load_be16(*p + 2);
    if (n > left - 4) {
        return -1;
    }
    *type = (uint16_t)brisk__load_be16(*p);
    *data = *p + 4;
    *dlen = n;
    *p += 4 + n;
    return 1;
}

/* The first extension of `type` in a block: 1 found, 0 absent, -1 the block is malformed. */
static int hs_ext_find(const uint8_t *p, size_t n, uint16_t type, const uint8_t **data,
                       size_t *dlen)
{
    const uint8_t *end = p + n;
    uint16_t t;
    int r;
    while ((r = hs_ext_next(&p, end, &t, data, dlen)) == 1) {
        if (t == type) {
            return 1;
        }
    }
    return r;
}

/* RFC 9846 4.3 rules for an extension block the SERVER sent in message kind `where`: well
 * formed (decode_error), at most one of each type (a local illegal_parameter - the RFC says MUST
 * NOT but names no alert), offered by the client unless it is the HRR cookie
 * (unsupported_extension), and allowed in this message by Table 1 (illegal_parameter). In a
 * CertificateRequest the extensions are requests, so the "offered" rule does not apply and
 * unrecognised ones are ignored (4.4.2). Returns 0 or the alert. */
static uint8_t hs_ext_check(const brisk__tls13_hs *hs, const uint8_t *p, size_t n, unsigned where)
{
    const uint8_t *end = p + n, *d;
    uint32_t seen = 0;
    uint16_t t;
    size_t dl;
    int r, idx;
    while ((r = hs_ext_next(&p, end, &t, &d, &dl)) == 1) {
        idx = hs_ext_index(t);
        if (idx >= 0) {
            if (seen & ((uint32_t)1 << idx)) {
                return BRISK__ALERT_ILLEGAL_PARAMETER;
            }
            seen |= (uint32_t)1 << idx;
        }
        if (where == IN_CR) {
            if (idx >= 0 && !(EXT_TABLE[idx].where & IN_CR)) {
                return BRISK__ALERT_ILLEGAL_PARAMETER;
            }
            continue;
        }
        if (!hs_in_list(hs->offered_ext, hs->n_ext, t) && !(where == IN_HRR && t == EXT_COOKIE)) {
            return BRISK__ALERT_UNSUPPORTED_EXTENSION;
        }
        if (idx < 0 || !(EXT_TABLE[idx].where & where)) {
            return BRISK__ALERT_ILLEGAL_PARAMETER;
        }
    }
    return r < 0 ? BRISK__ALERT_DECODE_ERROR : 0;
}

/* ------------------------------------------------------------------ transcript ------------ */

/* RFC 9846 4.1. Until a ServerHello or HRR picks the suite, both hashes run. */
static void th_add(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    if (hs->suite == 0 || hs_alg(hs->suite) == BRISK_HASH_SHA256) {
        brisk__hash_update(&hs->th256, BRISK_HASH_SHA256, m, n);
    }
    if (hs->suite == 0 || hs_alg(hs->suite) == BRISK_HASH_SHA384) {
        brisk__hash_update(&hs->th384, BRISK_HASH_SHA384, m, n);
    }
}

/* Transcript-Hash of everything added so far, by finalising a copy. */
static void th_snap(const brisk__tls13_hs *hs, uint8_t *out)
{
    brisk_hash_alg alg = hs_alg(hs->suite);
    brisk_hash_ctx c = alg == BRISK_HASH_SHA384 ? hs->th384 : hs->th256;
    brisk__hash_final(&c, alg, out);
}

/* The suite is known: keep only its hash. */
static void th_pick(brisk__tls13_hs *hs, uint16_t suite)
{
    hs->suite = suite;
    if (hs_alg(suite) == BRISK_HASH_SHA384) {
        brisk__secure_zero(&hs->th256, sizeof hs->th256);
    } else {
        brisk__secure_zero(&hs->th384, sizeof hs->th384);
    }
}

/* ------------------------------------------------------------------ failure / output ------- */

static void hs_wipe_secrets(brisk__tls13_hs *hs)
{
    brisk__secure_zero(hs->priv, sizeof hs->priv);
    brisk__secure_zero(hs->c_hs, sizeof hs->c_hs);
    brisk__secure_zero(hs->s_hs, sizeof hs->s_hs);
    brisk__secure_zero(hs->ks.secret, sizeof hs->ks.secret);
    brisk__secure_zero(hs->psk, sizeof hs->psk);
}

static int hs_fail(brisk__tls13_hs *hs, uint8_t alert)
{
    hs_wipe_secrets(hs);
    brisk__secure_zero(hs->exp_ms, sizeof hs->exp_ms);
    brisk__secure_zero(hs->res_ms, sizeof hs->res_ms);
    brisk__secure_zero(hs->out, BRISK__TLS13_OUT_MAX); /* the queued CH / client flight */
    hs->out_len = hs->out_off = hs->out_split = 0;
    hs->n_certs = 0;
    hs->state = BRISK__HS_FAILED;
    hs->alert = alert;
    /* internal_error is only ever raised for a local fault - a callback that refused, an
     * unusable reference host, a NULL auth ctx - never for something the peer sent. */
    hs->err =
        (alert == BRISK__ALERT_BAD_CERTIFICATE || alert == BRISK__ALERT_UNSUPPORTED_CERTIFICATE ||
         alert == BRISK__ALERT_UNKNOWN_CA || alert == BRISK__ALERT_DECRYPT_ERROR)
            ? BRISK_E_AUTH
        : alert == BRISK__ALERT_INTERNAL_ERROR ? BRISK_E_ARG
                                               : BRISK_E_PROTO;
    return hs->err;
}

/* Queue a message for pull() and add it to the transcript. Epochs only move forward, so the
 * queue is one INITIAL run [0, out_split) followed by one HANDSHAKE run [out_split, out_len). */
static uint8_t *hs_reserve(brisk__tls13_hs *hs, unsigned epoch, size_t n)
{
    uint8_t *p = hs->out + hs->out_len;
    if (n > BRISK__TLS13_OUT_MAX - hs->out_len) {
        return NULL;
    }
    hs->out_len += n;
    if (epoch == BRISK__EPOCH_INITIAL) {
        hs->out_split = hs->out_len;
    }
    return p;
}

static int hs_queue(brisk__tls13_hs *hs, unsigned epoch, const uint8_t *m, size_t n)
{
    uint8_t *p = hs_reserve(hs, epoch, n);
    if (p == NULL) {
        return 0;
    }
    memcpy(p, m, n);
    th_add(hs, p, n);
    return 1;
}

static int hs_export(brisk__tls13_hs *hs, unsigned epoch, int is_send, const uint8_t *secret)
{
    if (hs->cfg.on_secret == NULL) {
        return 1;
    }
    return hs->cfg.on_secret(hs->cfg.secret_ctx, epoch, is_send, hs->suite, secret,
                             brisk_hash_len(hs_alg(hs->suite))) == 0;
}

/* ------------------------------------------------------------------ ServerHello / HRR ------ */

/* HelloRetryRequest (RFC 9846 4.2.4) after the common ServerHello checks. */
static int hs_on_hrr(brisk__tls13_hs *hs, const uint8_t *m, size_t n, const uint8_t *ext,
                     size_t ext_len, uint16_t suite)
{
    uint8_t h[BRISK_HASH_MAX_LEN + 4];
    const uint8_t *d;
    size_t dl, hl = brisk_hash_len(hs_alg(suite));
    uint16_t group = 0;
    int have_ks, have_cookie;

    have_ks = hs_ext_find(ext, ext_len, EXT_KEY_SHARE, &d, &dl) == 1;
    if (have_ks) {
        if (dl != 2) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        group = (uint16_t)brisk__load_be16(d);
        /* 4.3.8: offered in supported_groups, and not a group CH1 already had a share for. */
        if (!hs_in_list(hs->offered_groups, hs->n_groups, group) || group == hs->share_group) {
            return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
        }
        if (hs_share_len(group) == 0) {
            /* Offered by a caller-built ClientHello, but no ECDHE here can answer it. */
            return hs_fail(hs, BRISK__ALERT_HANDSHAKE_FAILURE);
        }
    }
    have_cookie = hs_ext_find(ext, ext_len, EXT_COOKIE, &d, &dl) == 1;
    if (have_cookie) {
        /* 4.3.2: opaque cookie<1..2^16-1>, exactly filling the extension. */
        if (dl < 3 || brisk__load_be16(d) != dl - 2) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        if (dl - 2 > BRISK__TLS13_COOKIE_MAX) {
            return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER); /* local limit, see the #define */
        }
        memcpy(hs->cookie, d + 2, dl - 2);
        hs->cookie_len = (uint16_t)(dl - 2);
    }
    if (!have_ks && !have_cookie) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER); /* 4.2.4: would change nothing */
    }

    /* 4.1: ClientHello1 becomes message_hash(254) || 00 00 HashLen || Hash(ClientHello1). */
    th_pick(hs, suite);
    h[0] = HS_MESSAGE_HASH;
    h[1] = 0;
    h[2] = 0;
    h[3] = (uint8_t)hl;
    th_snap(hs, h + 4);
    brisk__hash_init(hs_alg(suite) == BRISK_HASH_SHA384 ? &hs->th384 : &hs->th256, hs_alg(suite));
    th_add(hs, h, 4 + hl);
    th_add(hs, m, n);

    brisk__secure_zero(hs->priv, sizeof hs->priv); /* CH1's share is dead */
    hs->hrr_group = group;
    hs->hrr_seen = 1;
    hs->state = BRISK__HS_WAIT_CH2;
    return BRISK_OK;
}

static int hs_on_sh(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    static const uint8_t HRR_LABEL[] = "HelloRetryRequest";
    uint8_t hrr_random[32], th[BRISK_HASH_MAX_LEN], dhe[32];
    const uint8_t *b = m + 4, *ext, *d, *sid;
    size_t bl = n - 4, sid_len, ext_len, dl, i;
    uint16_t suite, group;
    int is_hrr, rc, psk;
    uint8_t alert;

    /* legacy_version(2) random(32) session_id<0..32> cipher_suite(2) compression(1)
     * extensions<6..2^16-1> (4.2.3), exactly filling the message. A TLS 1.2-or-older
     * ServerHello may omit extensions entirely (RFC 5246 7.4.1.3): that parses as "no
     * supported_versions" so it reaches the downgrade-sentinel test below. */
    if (bl < 35 || b[34] > 32 || bl - 35 < (size_t)b[34] + 3) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    sid = b + 35;
    sid_len = b[34];
    i = 35 + sid_len;
    suite = (uint16_t)brisk__load_be16(b + i);
    ext = b + bl;
    ext_len = 0;
    if (bl - i != 3) {
        if (bl - i < 5) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        ext_len = brisk__load_be16(b + i + 3);
        ext = b + i + 5;
    }
    if ((bl - i != 3 && ext_len != bl - i - 5) || hs_ext_find(ext, ext_len, 0xffff, &d, &dl) < 0) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }

    /* 4.2.3: examine the random first; the HRR value is SHA-256("HelloRetryRequest"). */
    brisk_sha256(HRR_LABEL, sizeof HRR_LABEL - 1, hrr_random);
    is_hrr = memcmp(b + 2, hrr_random, 32) == 0;
    if (is_hrr && hs->hrr_seen) {
        return hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE); /* 4.2.4: a second HRR */
    }

    /* 4.3.1: supported_versions before anything else; legacy_version is ignored for it. */
    if (hs_ext_find(ext, ext_len, EXT_SUPPORTED_VERSIONS, &d, &dl) != 1) {
        /* A TLS 1.2 (or older) answer. The downgrade sentinels MUST be checked first (4.2.3);
         * M5 inserts its TLS 1.2 branch AFTER this test, never before it. */
        if (memcmp(b + 2 + 24, "DOWNGRD", 7) == 0 && b[2 + 31] <= 1) {
            return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
        }
        return hs_fail(hs, BRISK__ALERT_PROTOCOL_VERSION); /* local: no TLS 1.2 until M5 */
    }
    if (dl != 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (brisk__load_be16(d) != 0x0304) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER); /* not offered, or below 1.3 */
    }
    if (brisk__load_be16(b) != 0x0303) {
        return hs_fail(hs, BRISK__ALERT_PROTOCOL_VERSION);
    }
    if (sid_len != hs->session_id_len || memcmp(sid, hs->session_id, sid_len) != 0) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    if (!hs_in_list(hs->offered_suites, hs->n_suites, suite) ||
        (hs->hrr_seen && suite != hs->suite)) { /* 4.2.4: the SH keeps the HRR's suite */
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    if (b[i + 2] != 0) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    alert = hs_ext_check(hs, ext, ext_len, is_hrr ? IN_HRR : IN_SH);
    if (alert) {
        return hs_fail(hs, alert);
    }
    if (is_hrr) {
        return hs_on_hrr(hs, m, n, ext, ext_len, suite);
    }

    /* 4.3.11: the server's pre_shared_key is exactly uint16 selected_identity (hs_ext_check
     * already refused it unless the ClientHello offered one). It MUST be an identity we sent
     * (one, index 0) under a suite of the PSK's hash; psk_dhe_ke is the only mode offered
     * (4.3.9), so a selected PSK without key_share is illegal_parameter as well. */
    psk = hs_ext_find(ext, ext_len, EXT_PSK, &d, &dl) == 1;
    if (psk && dl != 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (psk && (brisk__load_be16(d) != 0 || hs_alg(suite) != hs_alg(hs->psk_suite) ||
                hs_ext_find(ext, ext_len, EXT_KEY_SHARE, &d, &dl) != 1)) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    /* 4.3.8: exactly one KeyShareEntry, in the group of the client's share (which after an HRR
     * is the HRR's selected_group, enforced when CH2 was absorbed). */
    if (hs_ext_find(ext, ext_len, EXT_KEY_SHARE, &d, &dl) != 1) {
        return hs_fail(hs, BRISK__ALERT_MISSING_EXTENSION); /* local: 9.2 names no alert */
    }
    if (dl < 4 || brisk__load_be16(d + 2) != dl - 4) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    group = (uint16_t)brisk__load_be16(d);
    /* 4.2.8: key_exchange<1..2^16-1>, a valid encoding for a group this engine can finish */
    if (group != hs->share_group || hs_share_len(group) == 0 || dl - 4 != hs_share_len(group)) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }

    if (!hs->hrr_seen) {
        th_pick(hs, suite);
    }
    th_add(hs, m, n);
    th_snap(hs, th);
    /* 7.4.2: the shared secret; an all-zero X25519 result and an invalid P-256 point (4.3.8.2)
     * both MUST abort. Both verdicts are public (x25519.c / p256.c). */
    rc = group == GROUP_X25519 ? brisk__x25519(dhe, hs->priv, d + 4)
         : group == GROUP_P256 ? brisk__p256_ecdh(dhe, hs->priv, d + 4)
                               : BRISK_E_ARG;
    brisk__secure_zero(hs->priv, sizeof hs->priv);
    if (rc != BRISK_OK) {
        brisk__secure_zero(dhe, sizeof dhe);
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    /* 7.1: early_secret = HKDF-Extract(0, PSK) only when the PSK was selected; otherwise this is
     * a full handshake and the certificate path runs. The PSK is dead either way. */
    rc = brisk__tls_ks_init(&hs->ks, hs_alg(suite), psk ? hs->psk : NULL, psk ? hs->psk_len : 0u);
    brisk__secure_zero(hs->psk, sizeof hs->psk);
    hs->psk_ok = (uint8_t)psk;
    if (rc == BRISK_OK) {
        rc = brisk__tls_ks_derive_handshake(&hs->ks, dhe, sizeof dhe, th, hs->c_hs, hs->s_hs);
    }
    brisk__secure_zero(dhe, sizeof dhe);
    if (rc != BRISK_OK || !hs_export(hs, BRISK__EPOCH_HANDSHAKE, 0, hs->s_hs) ||
        !hs_export(hs, BRISK__EPOCH_HANDSHAKE, 1, hs->c_hs)) {
        return hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
    }
    hs->in_epoch = BRISK__EPOCH_HANDSHAKE;
    hs->state = BRISK__HS_WAIT_EE;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ server parameters ----- */

static int hs_on_ee(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    const uint8_t *b = m + 4, *p, *d, *tp = NULL;
    size_t bl = n - 4, dl, tp_len = 0, off;
    uint16_t t;
    uint8_t alert;

    if (bl < 2 || brisk__load_be16(b) != bl - 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    alert = hs_ext_check(hs, b + 2, bl - 2, IN_EE);
    if (alert) {
        return hs_fail(hs, alert); /* 4.4.1: forbidden extensions are illegal_parameter */
    }
    p = b + 2;
    while (hs_ext_next(&p, b + bl, &t, &d, &dl) == 1) {
        /* server_name: RFC 6066 3, the answer's extension_data is empty. record_size_limit:
         * RFC 8449 4, a uint16; below 64 MUST be illegal_parameter; kept in peer_rsl for the
         * record layer. supported_groups MUST NOT be acted on before the handshake completes
         * (4.3.7) and is ignored. ALPN is not in CH_ALLOWED until M3 line 3 checks the answer
         * against the offer, so it can only arrive here unsolicited (hs_ext_check). */
        if ((t == EXT_SERVER_NAME && dl != 0) || (t == EXT_RECORD_SIZE_LIMIT && dl != 2)) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        if (t == EXT_RECORD_SIZE_LIMIT) {
            if (brisk__load_be16(d) < 64) {
                return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
            }
            hs->peer_rsl = (uint16_t)brisk__load_be16(d);
        }
        if (t == EXT_QUIC_TP) {
            tp = d; /* RFC 9001 8.2; only offered, so only accepted, when cfg.quic is set */
            tp_len = dl;
        }
        if (t == EXT_ALPN) {
            /* RFC 7301 3.1: the answer is a ProtocolNameList of EXACTLY one non-empty name,
             * filling the extension; it must be a name we offered - no alert is named for that,
             * illegal_parameter is the local choice over TCP, and RFC 9001 8.1 makes it
             * no_application_protocol over QUIC. */
            if (dl < 4 || brisk__load_be16(d) != dl - 2 || d[2] == 0 || d[2] != dl - 3) {
                return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
            }
            for (off = 0; off < hs->alpn_len; off += 1 + (size_t)hs->alpn[off]) {
                if (hs->alpn[off] == d[2] && memcmp(hs->alpn + off + 1, d + 3, d[2]) == 0) {
                    break;
                }
            }
            if (off >= hs->alpn_len) {
                return hs_fail(hs, hs->cfg.quic ? BRISK__ALERT_NO_APPLICATION_PROTOCOL
                                                : BRISK__ALERT_ILLEGAL_PARAMETER);
            }
            hs->alpn_sel_off = (uint16_t)(off + 1);
            hs->alpn_sel_len = d[2];
        }
    }
    /* RFC 9001 8.2: EE without quic_transport_parameters over QUIC is missing_extension. The
     * value is handed over here, the only moment it is in memory; its contents are the QUIC
     * layer's to judge (RFC 9000 7.4) - a refusal is a local verdict, internal_error. */
    if (hs->cfg.quic && tp == NULL) {
        return hs_fail(hs, BRISK__ALERT_MISSING_EXTENSION);
    }
    /* RFC 9001 8.1: over QUIC the server MUST select an application protocol */
    if (hs->cfg.quic && hs->alpn_sel_len == 0) {
        return hs_fail(hs, BRISK__ALERT_NO_APPLICATION_PROTOCOL);
    }
    if (tp != NULL && hs->cfg.on_peer_tp != NULL &&
        hs->cfg.on_peer_tp(hs->cfg.tp_ctx, tp, tp_len) != 0) {
        return hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
    }
    th_add(hs, m, n);
    /* A.1: a PSK handshake has no Certificate/CertificateVerify, and 4.4.2 forbids a
     * CertificateRequest in it - both are unexpected_message from WAIT_FIN. */
    hs->state = hs->psk_ok ? BRISK__HS_WAIT_FIN : BRISK__HS_WAIT_CERT_CR;
    return BRISK_OK;
}

static int hs_on_cr(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    const uint8_t *b = m + 4, *d;
    size_t bl = n - 4, dl, el;
    uint8_t alert;
    int r;

    /* certificate_request_context<0..2^8-1> extensions<0..2^16-1> (4.4.2) */
    if (bl < 1 || bl - 1 < (size_t)b[0] + 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    el = brisk__load_be16(b + 1 + b[0]);
    if (el != bl - 3 - b[0]) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (b[0] != 0) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER); /* zero length in the handshake */
    }
    alert = hs_ext_check(hs, b + 3, el, IN_CR);
    if (alert) {
        return hs_fail(hs, alert);
    }
    r = hs_ext_find(b + 3, el, EXT_SIGNATURE_ALGORITHMS, &d, &dl);
    if (r != 1) {
        return hs_fail(hs, BRISK__ALERT_MISSING_EXTENSION); /* "MUST be specified" */
    }
    /* 4.3.3: SignatureScheme supported_signature_algorithms<2..2^16-2> */
    if (dl < 4 || brisk__load_be16(d) != dl - 2 || (dl & 1) != 0) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    /* 4.5.2: our CertificateVerify scheme must be one the server listed. certificate_authorities,
     * oid_filters and signature_algorithms_cert are parsed (hs_ext_check) but not acted on:
     * there is one device chain, and 4.3.5 lets a client ignore filters it does not act on. */
    for (el = 2; el < dl; el += 2) {
        hs->cr_sig_ok |= (uint8_t)(brisk__load_be16(d + el) == 0x0403);
    }
    th_add(hs, m, n);
    hs->cr_seen = 1;
    hs->state = BRISK__HS_WAIT_CERT;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ authentication -------- */

static int hs_on_cert(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    const uint8_t *b = m + 4, *p, *end, *xd;
    size_t bl = n - 4, len, el, xl, count = 0;

    /* certificate_request_context<0..2^8-1> CertificateEntry certificate_list<0..2^24-1> */
    if (bl < 1 || bl - 1 < (size_t)b[0] + 3) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (brisk__load_be24(b + 1 + b[0]) != bl - 4 - b[0]) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (b[0] != 0) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER); /* 4.5.1: server auth => empty */
    }
    if (bl == 4) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR); /* 4.5.1.3: an empty certificate_list */
    }
    /* Pass 1, structure only: cert_data<1..2^24-1> extensions<0..2^16-1> per entry. */
    for (p = b + 4, end = b + bl; p != end; p += len + 2 + el) {
        if ((size_t)(end - p) < 3) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        len = brisk__load_be24(p);
        p += 3;
        if (len == 0 || (size_t)(end - p) < 2 || len > (size_t)(end - p) - 2) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        el = brisk__load_be16(p + len);
        if (el > (size_t)(end - p) - len - 2) {
            return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
        }
        if (el != 0) {
            /* 4.5.1: entry extensions answer ClientHello ones; this client requests none
             * (status_request and friends are refused at absorb), so any is unsolicited. */
            if (hs_ext_find(p + len + 2, el, 0xffff, &xd, &xl) < 0) {
                return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
            }
            return hs_fail(hs, BRISK__ALERT_UNSUPPORTED_EXTENSION);
        }
        if (++count > BRISK__X509_MAX_CHAIN) {
            return hs_fail(hs, BRISK__ALERT_BAD_CERTIFICATE); /* local limit, fail closed */
        }
    }
    /* Pass 2: parse in place. The structs point into this message, which stays in the
     * reassembly buffer until the CertificateVerify has been checked (hs_feed's in_base). */
    for (p = m + 8, count = 0; p != m + n; p += len + 2) {
        len = brisk__load_be24(p);
        p += 3;
        if (brisk__x509_parse(&hs->certs[count++], p, len) != BRISK_OK) {
            return hs_fail(hs, BRISK__ALERT_BAD_CERTIFICATE);
        }
    }
    hs->n_certs = count;
    th_add(hs, m, n);
    hs->in_base = n;
    hs->state = BRISK__HS_WAIT_CV;
    return BRISK_OK;
}

static int hs_on_cv(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    uint8_t th[BRISK_HASH_MAX_LEN], tbs[98 + BRISK_HASH_MAX_LEN], alert = 0;
    const uint8_t *b = m + 4;
    size_t bl = n - 4, tbs_len;
    uint16_t scheme;
    int rc;

    if (bl < 4 || brisk__load_be16(b + 2) != bl - 4) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    scheme = (uint16_t)brisk__load_be16(b);
    /* 4.5.2: a scheme the client offered; 4.3.3: never rsa_pkcs1_* (certificates only), never
     * SHA-1 (0x02xx) or SHA-224 (0x03xx). The auth function refuses what it cannot verify. */
    if (!hs_in_list(hs->offered_sigs, hs->n_sigs, scheme) || (scheme & 0xff) == 0x01 ||
        (scheme >> 8) == 0x02 || (scheme >> 8) == 0x03) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    th_snap(hs, th);
    tbs_len = brisk__tls13_cv_content(1, th, brisk_hash_len(hs_alg(hs->suite)), tbs);
    rc = hs->cfg.auth(hs->cfg.auth_ctx, hs->certs, hs->n_certs, scheme, tbs, tbs_len, b + 4, bl - 4,
                      &alert);
    if (rc != BRISK_OK) {
        if (alert == 0) {
            alert = rc == BRISK_E_AUTH ? BRISK__ALERT_DECRYPT_ERROR : BRISK__ALERT_BAD_CERTIFICATE;
        }
        return hs_fail(hs, alert);
    }
    th_add(hs, m, n);
    hs->n_certs = 0;
    hs->in_base = 0; /* the Certificate message may now be overwritten */
    hs->state = BRISK__HS_WAIT_FIN;
    return BRISK_OK;
}

#if BRISK_ENABLE_MTLS
/* The CertificateEntry list of the device chain (4.4.2): per certificate cert_data<1..2^24-1>
 * and empty extensions (4.5.1: client entry extensions only answer CR extensions, and we answer
 * none). Returns its length, written to out when non-NULL; 0 if the chain is not a sequence of
 * DER TLVs (refused at hs_init, so never at handshake time). */
static size_t hs_chain_entries(const uint8_t *chain, size_t len, uint8_t *out)
{
    brisk__der c;
    const uint8_t *tlv;
    size_t tl, n = 0;
    brisk__der_init(&c, chain, len);
    while (brisk__der_peek(&c) != -1) {
        if (brisk__der_tlv(&c, &tlv, &tl) != BRISK_OK) {
            return 0;
        }
        if (out != NULL) {
            brisk__store_be24(out + n, (uint32_t)tl);
            memcpy(out + n + 3, tlv, tl);
            out[n + 3 + tl] = 0;
            out[n + 4 + tl] = 0;
        }
        n += 3 + tl + 2;
    }
    return brisk__der_err(&c) == BRISK_OK ? n : 0;
}
#endif

/* The answer to a CertificateRequest (RFC 9846 4.5.1, 4.5.2), queued at HANDSHAKE before the
 * client Finished: the device chain and a CertificateVerify, or - no chain, or 0x0403 not in the
 * CR's signature_algorithms - an empty Certificate and nothing else. The context echoes the CR's,
 * which is empty in the main handshake. BRISK_OK or a local fault (internal_error). */
static int hs_client_auth(brisk__tls13_hs *hs)
{
    static const uint8_t EMPTY_CERT[8] = {HS_CERTIFICATE, 0, 0, 4, 0, 0, 0, 0};
#if BRISK_ENABLE_MTLS
    uint8_t th[BRISK_HASH_MAX_LEN], tbs[98 + BRISK_HASH_MAX_LEN], raw[64], cv[8 + 72], *q;
    size_t n, tbs_len, sig_len = 0;
    int rc;

    if (hs->cfg.client_chain != NULL && hs->cr_sig_ok) {
        n = hs_chain_entries(hs->cfg.client_chain, hs->cfg.client_chain_len, NULL);
        q = n != 0 ? hs_reserve(hs, BRISK__EPOCH_HANDSHAKE, 8 + n) : NULL;
        if (q == NULL) {
            return BRISK_E_ARG; /* the ClientHello was never pulled: see hs_cfg.client_chain */
        }
        q[0] = HS_CERTIFICATE;
        brisk__store_be24(q + 1, (uint32_t)(4 + n));
        q[4] = 0;
        brisk__store_be24(q + 5, (uint32_t)n);
        hs_chain_entries(hs->cfg.client_chain, hs->cfg.client_chain_len, q + 8);
        th_add(hs, q, 8 + n);
        /* 4.5.2: ecdsa_secp256r1_sha256 over the client context string || TH(CH..Certificate) */
        th_snap(hs, th);
        tbs_len = brisk__tls13_cv_content(0, th, brisk_hash_len(hs_alg(hs->suite)), tbs);
        if (hs->cfg.client_key != NULL) {
            /* hedged RFC 6979 (3.6) with the caller's fresh k'; a BRISK_E_AUTH from the
             * fault self-check is fatal, never retried (a glitched signature leaks d) */
            brisk_sha256(tbs, tbs_len, th);
            rc = brisk__p256_ecdsa_sign(raw, hs->cfg.client_key, th, 32, hs->cfg.sign_rand, 32);
        } else {
            rc = hs->cfg.sign(hs->cfg.sign_ctx, 0x0403, tbs, tbs_len, raw, sizeof raw, &sig_len);
            if (rc == BRISK_OK && sig_len != sizeof raw) {
                rc = BRISK_E_ARG;
            }
        }
        BRISK__CT_PUBLIC(raw, sizeof raw); /* r || s goes on the wire */
        if (rc == BRISK_OK) {
            n = brisk__x509_ecdsa_der(raw, cv + 8);
            cv[0] = HS_CERTIFICATE_VERIFY;
            brisk__store_be24(cv + 1, (uint32_t)(4 + n));
            brisk__store_be16(cv + 4, 0x0403);
            brisk__store_be16(cv + 6, (uint32_t)n);
            rc = hs_queue(hs, BRISK__EPOCH_HANDSHAKE, cv, 8 + n) ? BRISK_OK : BRISK_E_ARG;
        }
        brisk__secure_zero(raw, sizeof raw);
        brisk__secure_zero(th, sizeof th);
        return rc;
    }
#endif
    return hs_queue(hs, BRISK__EPOCH_HANDSHAKE, EMPTY_CERT, sizeof EMPTY_CERT) ? BRISK_OK
                                                                               : BRISK_E_ARG;
}

static int hs_on_fin(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    uint8_t th[BRISK_HASH_MAX_LEN], mac[4 + BRISK_HASH_MAX_LEN];
    uint8_t c_ap[BRISK_HASH_MAX_LEN], s_ap[BRISK_HASH_MAX_LEN];
    brisk_hash_alg alg = hs_alg(hs->suite);
    size_t hl = brisk_hash_len(alg);
    int ok, rc;

    if (n - 4 != hl) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR); /* 4.5.3: verify_data is HashLen */
    }
    th_snap(hs, th);
    rc = brisk__tls_finished_mac(alg, hs->s_hs, th, mac);
    ok = rc == BRISK_OK && brisk__ct_memeq(mac, m + 4, hl);
    BRISK__CT_PUBLIC(&ok, sizeof ok); /* the verdict the alert reveals anyway */
    brisk__secure_zero(mac, sizeof mac);
    if (!ok) {
        return hs_fail(hs, BRISK__ALERT_DECRYPT_ERROR);
    }
    th_add(hs, m, n);
    th_snap(hs, th); /* TH(CH..server Finished): the application secrets (7.1) */
    rc = brisk__tls_ks_derive_application(&hs->ks, th, c_ap, s_ap, hs->exp_ms);

    /* Client flight (4.5, A.1): Certificate [+ CertificateVerify] iff one was requested, then
     * Finished over TH(CH..SF[..Certificate[..CertificateVerify]]) (4.5.3). */
    if (rc == BRISK_OK && hs->cr_seen) {
        rc = hs_client_auth(hs);
    }
    if (rc == BRISK_OK) {
        th_snap(hs, th);
        mac[0] = HS_FINISHED;
        mac[1] = 0;
        mac[2] = 0;
        mac[3] = (uint8_t)hl;
        rc = brisk__tls_finished_mac(alg, hs->c_hs, th, mac + 4);
    }
    if (rc == BRISK_OK && !hs_queue(hs, BRISK__EPOCH_HANDSHAKE, mac, 4 + hl)) {
        rc = BRISK_E_ARG;
    }
    if (rc == BRISK_OK) {
        th_snap(hs, th);
        rc = brisk__tls_ks_derive_resumption(&hs->ks, th, hs->res_ms);
    }
    if (rc == BRISK_OK &&
        (!hs_export(hs, BRISK__EPOCH_APP, 0, s_ap) || !hs_export(hs, BRISK__EPOCH_APP, 1, c_ap))) {
        rc = BRISK_E_ARG;
    }
    brisk__secure_zero(mac, sizeof mac);
    brisk__secure_zero(c_ap, sizeof c_ap);
    brisk__secure_zero(s_ap, sizeof s_ap);
    if (rc != BRISK_OK) {
        return hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
    }
    hs_wipe_secrets(hs); /* c_hs, s_hs and the master secret are done with */
    hs->in_epoch = BRISK__EPOCH_APP;
    hs->state = BRISK__HS_CONNECTED;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ post-handshake -------- */

/* NewSessionTicket (RFC 9846 4.7.1): parsed strictly even when nobody wants it, then handed to
 * cfg.on_ticket or silently ignored. Not part of the transcript. */
static int hs_on_nst(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    const uint8_t *b = m + 4, *p, *end, *exts, *d, *d2;
    size_t bl = n - 4, i, dl, dl2;
    brisk__tls13_ticket tk;
    uint16_t type;
    int r;

    memset(&tk, 0, sizeof tk);
    /* ticket_lifetime(4) ticket_age_add(4) ticket_nonce<0..255> ticket<1..2^16-1>
     * extensions<0..2^16-2>, every length checked against what remains before it is used */
    if (bl < 9 || bl - 9 < (size_t)b[8] + 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    tk.lifetime = brisk__load_be32(b);
    tk.age_add = brisk__load_be32(b + 4);
    tk.nonce_len = b[8];
    tk.nonce = b + 9;
    i = 9 + tk.nonce_len;
    tk.ticket_len = brisk__load_be16(b + i);
    if (tk.ticket_len == 0 || bl - i - 2 < tk.ticket_len + 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    tk.ticket = b + i + 2;
    i += 2 + tk.ticket_len;
    if (brisk__load_be16(b + i) != bl - i - 2) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR); /* short, or trailing bytes */
    }
    exts = p = b + i + 2;
    end = b + bl;
    while ((r = hs_ext_next(&p, end, &type, &d, &dl)) == 1) {
        /* 4.3: at most one of each type, known or not (the prefix already parsed cleanly) */
        if (hs_ext_find(exts, (size_t)(d - 4 - exts), type, &d2, &dl2) == 1) {
            return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
        }
        /* 4.3: a recognised extension not specified for NST (Table 1: only early_data) MUST
         * abort with illegal_parameter; unrecognised ones are ignored. No "offered" rule: NST
         * extensions are not responses. */
        r = hs_ext_index(type);
        if (r >= 0 && !(EXT_TABLE[r].where & IN_NST)) {
            return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
        }
        if (type == EXT_EARLY_DATA) { /* max_early_data_size */
            if (dl != 4) {
                return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
            }
            tk.max_early_data = brisk__load_be32(d);
            /* RFC 9001 4.6.1: over QUIC any value but 0xffffffff is PROTOCOL_VIOLATION; the
             * QUIC layer (M6) must map this alert to that error, not to CRYPTO_ERROR */
            if (hs->cfg.quic && tk.max_early_data != 0xffffffffu) {
                return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
            }
        }
    }
    if (r < 0) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (hs->cfg.on_ticket == NULL) {
        return BRISK_OK; /* 4.7.1: a client that does not resume silently ignores the ticket */
    }
    /* 4.7.1: PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
     * HashLen), usable only under a suite of the same hash - hence the suite goes with it. */
    tk.suite = hs->suite;
    tk.psk_len = brisk_hash_len(hs_alg(hs->suite));
    r = brisk__hkdf_expand_label(hs_alg(hs->suite), hs->res_ms, tk.psk_len, "resumption", tk.nonce,
                                 tk.nonce_len, tk.psk, tk.psk_len);
    if (r == BRISK_OK) {
        r = hs->cfg.on_ticket(hs->cfg.ticket_ctx, &tk);
    }
    brisk__secure_zero(tk.psk, sizeof tk.psk);
    if (r != 0) {
        return hs_fail(hs, BRISK__ALERT_INTERNAL_ERROR);
    }
    return BRISK_OK;
}

/* KeyUpdate (RFC 9846 4.7.3). The record layer rotates its receive key after the record that
 * carried it (hs_feed refuses bytes after it in the same call) and answers update_requested. */
static int hs_on_ku(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    if (hs->cfg.quic) {
        return hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE); /* RFC 9001 6: error 0x010a */
    }
    if (n != 5) {
        return hs_fail(hs, BRISK__ALERT_DECODE_ERROR);
    }
    if (m[4] > 1) {
        return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
    }
    hs->ku |= (uint8_t)(1 | (m[4] << 1));
    return BRISK_OK;
}

static int hs_dispatch(brisk__tls13_hs *hs, const uint8_t *m, size_t n)
{
    switch (hs->state) {
    case BRISK__HS_WAIT_SH:
        if (m[0] == HS_SERVER_HELLO) {
            return hs_on_sh(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT_EE:
        if (m[0] == HS_ENCRYPTED_EXTENSIONS) {
            return hs_on_ee(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT_CERT_CR:
        if (m[0] == HS_CERTIFICATE_REQUEST) {
            return hs_on_cr(hs, m, n);
        }
        /* fall through */
    case BRISK__HS_WAIT_CERT:
        if (m[0] == HS_CERTIFICATE) {
            return hs_on_cert(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT_CV:
        if (m[0] == HS_CERTIFICATE_VERIFY) {
            return hs_on_cv(hs, m, n);
        }
        break;
    case BRISK__HS_WAIT_FIN:
        if (m[0] == HS_FINISHED) {
            return hs_on_fin(hs, m, n);
        }
        break;
    case BRISK__HS_CONNECTED:
        /* 4.7: a CertificateRequest is unexpected too - post_handshake_auth is never offered */
        if (m[0] == HS_NEW_SESSION_TICKET) {
            return hs_on_nst(hs, m, n);
        }
        if (m[0] == HS_KEY_UPDATE) {
            return hs_on_ku(hs, m, n);
        }
        break;
    default:
        break;
    }
    return hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE); /* RFC 9846 4, Appendix A.1 */
}

/* ------------------------------------------------------------------ public entry points ---- */

size_t brisk__tls13_hs_scratch_size(void)
{
    return HS_IN_CAP + (HS_CERT_ALIGN - 1) + BRISK__X509_MAX_CHAIN * sizeof(brisk__x509_cert) +
           BRISK__TLS13_OUT_MAX;
}

#if BRISK_ENABLE_MTLS
/* The device chain, checked once as configuration (RFC 9846 4.5.1.2): every certificate parses,
 * the leaf is P-256 and may sign (digitalSignature when keyUsage is present), the key is the
 * leaf's, and the chain is within BRISK_TLS_MAX_CLIENT_CHAIN (the 2048-byte base of the output
 * queue covers the 5 bytes per entry, CertificateVerify and Finished). */
static int hs_client_cfg_ok(const brisk__tls13_hs_cfg *cfg)
{
    brisk__x509_cert x;
    brisk__der c;
    const uint8_t *tlv;
    uint8_t pub[65];
    size_t tl, n = hs_chain_entries(cfg->client_chain, cfg->client_chain_len, NULL);
    int first = 1;

    if ((cfg->client_key != NULL) == (cfg->sign != NULL) ||
        (cfg->client_key != NULL && cfg->sign_rand == NULL) || n == 0 ||
        cfg->client_chain_len > BRISK_TLS_MAX_CLIENT_CHAIN ||
        n > BRISK__TLS13_OUT_MAX - (8 + 8 + 72 + 4 + BRISK_HASH_MAX_LEN)) {
        return 0;
    }
    brisk__der_init(&c, cfg->client_chain, cfg->client_chain_len);
    while (brisk__der_peek(&c) != -1) {
        if (brisk__der_tlv(&c, &tlv, &tl) != BRISK_OK ||
            brisk__x509_parse(&x, tlv, tl) != BRISK_OK) {
            return 0;
        }
        if (first) {
            first = 0;
            if (x.key_alg != BRISK__X509_KEY_P256 || x.key_len != sizeof pub ||
                (x.key_usage != 0 && !(x.key_usage & BRISK__X509_KU_DIGITAL_SIGNATURE))) {
                return 0;
            }
            if (cfg->client_key != NULL && (brisk__p256_keygen(pub, cfg->client_key) != BRISK_OK ||
                                            memcmp(pub, x.key, sizeof pub) != 0)) {
                return 0; /* the point is public; only keygen touches d, in constant time */
            }
        }
    }
    return 1;
}
#endif

int brisk__tls13_hs_init(brisk__tls13_hs *hs, const brisk__tls13_hs_cfg *cfg, uint8_t *scratch,
                         size_t scratch_len)
{
    uint8_t *c;
    if (hs == NULL || cfg == NULL || cfg->auth == NULL || scratch == NULL ||
        scratch_len < brisk__tls13_hs_scratch_size()) {
        return BRISK_E_ARG; /* no path to CONNECTED without an authenticator */
    }
    if (cfg->client_chain != NULL || cfg->client_key != NULL || cfg->sign != NULL) {
#if BRISK_ENABLE_MTLS
        if (cfg->client_chain == NULL || !hs_client_cfg_ok(cfg)) {
            return BRISK_E_ARG;
        }
#else
        return BRISK_E_ARG; /* a build without BRISK_ENABLE_MTLS has no client certificate */
#endif
    }
    memset(hs, 0, sizeof *hs);
    hs->cfg = *cfg;
    hs->scratch = scratch;
    hs->scratch_len = scratch_len;
    hs->in = scratch;
    hs->in_cap = HS_IN_CAP;
    /* The certificate array needs the struct's alignment (int64_t, pointers): round up in place
     * rather than trusting the caller's buffer, which is only promised to be uint8_t. */
    c = scratch + HS_IN_CAP;
    c += (HS_CERT_ALIGN - ((uintptr_t)c & (HS_CERT_ALIGN - 1))) & (HS_CERT_ALIGN - 1);
    hs->certs = (brisk__x509_cert *)(void *)c;
    hs->out = c + BRISK__X509_MAX_CHAIN * sizeof(brisk__x509_cert);
    brisk__hash_init(&hs->th256, BRISK_HASH_SHA256);
    brisk__hash_init(&hs->th384, BRISK_HASH_SHA384);
    hs->state = BRISK__HS_START;
    hs->in_epoch = BRISK__EPOCH_INITIAL;
    return BRISK_OK;
}

/* The parsed offer of one ClientHello, committed only once the whole message checked out. */
typedef struct {
    uint16_t ext[BRISK__TLS13_MAX_OFFER_EXT], suites[BRISK__TLS13_MAX_OFFER_SUITES];
    uint16_t groups[BRISK__TLS13_MAX_OFFER_GROUPS], sigs[BRISK__TLS13_MAX_OFFER_SIGS];
    size_t n_ext, n_suites, n_groups, n_sigs;
    const uint8_t *cookie, *alpn;
    size_t cookie_len, alpn_len;
    size_t binder_len; /* 0 = no pre_shared_key; else the one binder's length, at the very end */
    uint16_t rsl;      /* our record_size_limit, 0 = not offered */
    int tls13, share, modes;
} hs_offer;

/* A uint16 list<2..> exactly filling `len` bytes at d (after its own length prefix of `pre`
 * bytes), copied into out[max]. 0 on any structural error or overflow. */
static int hs_u16_list(const uint8_t *d, size_t len, size_t pre, uint16_t *out, size_t max,
                       size_t *n)
{
    size_t i, cnt, ll;
    if (len < pre) { /* before reading the prefix: d may sit at the end of the buffer */
        return 0;
    }
    ll = pre == 1 ? d[0] : brisk__load_be16(d);
    if (ll != len - pre || ll < 2 || (ll & 1) != 0 || ll / 2 > max) {
        return 0;
    }
    cnt = ll / 2;
    for (i = 0; i < cnt; i++) {
        out[i] = (uint16_t)brisk__load_be16(d + pre + 2 * i);
    }
    *n = cnt;
    return 1;
}

static int hs_parse_ch(const uint8_t *ch, size_t ch_len, uint16_t share_group, int quic,
                       hs_offer *o)
{
    const uint8_t *b = ch + 4, *p, *end, *d;
    size_t bl, i, dl, k;
    uint16_t t, v[4];

    memset(o, 0, sizeof *o);
    if (ch_len < 4 + 35 || ch[0] != HS_CLIENT_HELLO || brisk__load_be24(ch + 1) != ch_len - 4) {
        return 0;
    }
    bl = ch_len - 4;
    /* legacy_version 0x0303, random, legacy_session_id: 32 bytes over TCP (E.4), empty over
     * QUIC (RFC 9001 8.4), and nothing in between is legal for this engine. */
    if (brisk__load_be16(b) != 0x0303 || (b[34] != 0 && b[34] != 32) || (quic && b[34] != 0)) {
        return 0;
    }
    i = 35 + (size_t)b[34];
    /* cipher_suites<2..2^16-2>, bounds first: the list is read only once it is known to fit */
    if (bl < i + 2 || bl - i - 2 < brisk__load_be16(b + i) ||
        !hs_u16_list(b + i, 2 + (size_t)brisk__load_be16(b + i), 2, o->suites,
                     BRISK__TLS13_MAX_OFFER_SUITES, &o->n_suites)) {
        return 0;
    }
    for (k = 0; k < o->n_suites; k++) {
        if (!hs_known_suite(o->suites[k])) {
            return 0; /* the server could pick it, and there is no key schedule for it */
        }
    }
    i += 2 + brisk__load_be16(b + i);
    /* legacy_compression_methods: exactly one byte, 0 (4.2.2) */
    if (bl - i < 4 || b[i] != 1 || b[i + 1] != 0 || brisk__load_be16(b + i + 2) != bl - i - 4) {
        return 0;
    }
    p = b + i + 4;
    end = b + bl;
    while (p != end) {
        if (hs_ext_next(&p, end, &t, &d, &dl) != 1 ||
            !hs_in_list(CH_ALLOWED, sizeof CH_ALLOWED / sizeof CH_ALLOWED[0], t) ||
            hs_in_list(o->ext, o->n_ext, t) || o->n_ext == BRISK__TLS13_MAX_OFFER_EXT) {
            return 0;
        }
        o->ext[o->n_ext++] = t;
        switch (t) {
        case EXT_SUPPORTED_GROUPS:
            if (!hs_u16_list(d, dl, 2, o->groups, BRISK__TLS13_MAX_OFFER_GROUPS, &o->n_groups)) {
                return 0;
            }
            break;
        case EXT_SIGNATURE_ALGORITHMS:
            if (!hs_u16_list(d, dl, 2, o->sigs, BRISK__TLS13_MAX_OFFER_SIGS, &o->n_sigs)) {
                return 0;
            }
            break;
        case EXT_SUPPORTED_VERSIONS:
            if (!hs_u16_list(d, dl, 1, v, 4, &k) || !hs_in_list(v, k, 0x0304)) {
                return 0;
            }
            o->tls13 = 1;
            break;
        case EXT_KEY_SHARE:
            /* KeyShareClientHello with exactly one entry, the one the private key belongs to */
            if (dl < 6 || brisk__load_be16(d) != dl - 2 || brisk__load_be16(d + 2) != share_group ||
                brisk__load_be16(d + 4) != dl - 6 || hs_share_len(share_group) == 0 ||
                dl - 6 != hs_share_len(share_group)) {
                return 0;
            }
            o->share = 1;
            break;
        case EXT_RECORD_SIZE_LIMIT:
            /* RFC 8449 4: a uint16, never below 64; kept so the record layer can enforce it */
            if (dl != 2 || brisk__load_be16(d) < 64) {
                return 0;
            }
            o->rsl = (uint16_t)brisk__load_be16(d);
            break;
        case EXT_COOKIE:
            if (dl < 3 || brisk__load_be16(d) != dl - 2) {
                return 0;
            }
            o->cookie = d + 2;
            o->cookie_len = dl - 2;
            break;
        case EXT_ALPN:
            /* RFC 7301 3.1: ProtocolNameList<2..2^16-1> of non-empty names, within our cap */
            if (dl < 3 || brisk__load_be16(d) != dl - 2 || dl - 2 > BRISK__TLS13_ALPN_MAX) {
                return 0;
            }
            for (k = 2; k < dl; k += 1 + (size_t)d[k]) {
                if (d[k] == 0 || d[k] > dl - k - 1) {
                    return 0;
                }
            }
            o->alpn = d + 2;
            o->alpn_len = dl - 2;
            break;
        case EXT_PSK_MODES:
            if (dl != 2 || d[0] != 1 || d[1] != 1) {
                return 0; /* 4.3.9: [psk_dhe_ke] only - psk_ke has no forward secrecy */
            }
            o->modes = 1;
            break;
        case EXT_PSK:
            /* 4.3.11: the LAST extension, exactly one identity<1..> + age, exactly one binder
             * (its length is checked against the PSK's HashLen by the caller) */
            if (p != end || dl < 2 + 2 + 1 + 4 + 2 + 1) {
                return 0;
            }
            k = brisk__load_be16(d);
            if (k > dl - 2 - 3 || k < 7 || brisk__load_be16(d + 2) != k - 6) {
                return 0;
            }
            if (brisk__load_be16(d + 2 + k) != dl - 4 - k || d[4 + k] != dl - 5 - k ||
                d[4 + k] < 32) {
                return 0;
            }
            o->binder_len = d[4 + k];
            break;
        default:
            break;
        }
    }
    /* supported_versions is REQUIRED; signature_algorithms for certificate authentication, and
     * supported_groups with key_share for (EC)DHE (RFC 9846 9.2). RFC 9001 8.2: over QUIC the
     * client MUST send quic_transport_parameters, and MUST NOT send it over TCP. */
    /* 4.3.9: a PSK needs psk_key_exchange_modes. RFC 9001 8.1: over QUIC, ALPN is mandatory. */
    return o->tls13 && o->share && o->n_sigs && o->n_groups &&
           hs_in_list(o->groups, o->n_groups, share_group) &&
           (quic != 0) == hs_in_list(o->ext, o->n_ext, EXT_QUIC_TP) &&
           (o->binder_len == 0 || o->modes) && (!quic || o->alpn != NULL);
}

/* 4.3.11.2: the binder over Transcript-Hash(prefix || Truncate(ch)) in the PSK's hash, from a
 * fresh context in CH1 and from a copy of the post-HRR transcript in CH2 (4.2.2); Truncate drops
 * the binders list, whose length fields stay counted. */
static int hs_binder(const brisk__tls13_hs *hs, const uint8_t *ch, size_t ch_len, uint8_t *out)
{
    brisk_hash_alg alg = hs_alg(hs->psk_suite);
    uint8_t th[BRISK_HASH_MAX_LEN];
    brisk_hash_ctx c;
    if (hs->state == BRISK__HS_START) {
        brisk__hash_init(&c, alg);
    } else {
        c = alg == BRISK_HASH_SHA384 ? hs->th384 : hs->th256;
    }
    brisk__hash_update(&c, alg, ch, ch_len - 3 - hs->psk_len);
    brisk__hash_final(&c, alg, th);
    return brisk__tls_psk_binder(alg, hs->psk, hs->psk_len, th, out);
}

int brisk__tls13_hs_client_hello(brisk__tls13_hs *hs, const uint8_t *ch, size_t ch_len,
                                 uint16_t share_group, const uint8_t *share_priv)
{
    uint8_t binder[BRISK_HASH_MAX_LEN], *q;
    hs_offer o;
    size_t k;
    if (hs == NULL || ch == NULL || share_priv == NULL) {
        return BRISK_E_ARG;
    }
    if (hs->state == BRISK__HS_FAILED) {
        return hs->err;
    }
    if ((hs->state != BRISK__HS_START && hs->state != BRISK__HS_WAIT_CH2) ||
        !hs_parse_ch(ch, ch_len, share_group, hs->cfg.quic, &o) ||
        ch_len > BRISK__TLS13_OUT_MAX - hs->out_len) {
        return BRISK_E_ARG;
    }
    if (hs->state == BRISK__HS_START) {
        if (o.cookie != NULL) {
            return BRISK_E_ARG; /* 4.3.2: never a cookie in an initial ClientHello */
        }
        hs->session_id_len = ch[4 + 34];
        memcpy(hs->session_id, ch + 4 + 35, hs->session_id_len);
    } else {
        /* 4.2.2: the same ClientHello, with key_share replaced by the HRR's group and the
         * cookie copied exactly when the HRR sent one. */
        if (ch[4 + 34] != hs->session_id_len ||
            memcmp(ch + 4 + 35, hs->session_id, hs->session_id_len) != 0 ||
            share_group != (hs->hrr_group ? hs->hrr_group : hs->share_group) ||
            o.cookie_len != hs->cookie_len ||
            (o.cookie_len && memcmp(o.cookie, hs->cookie, o.cookie_len) != 0) ||
            !hs_in_list(o.suites, o.n_suites, hs->suite)) {
            return BRISK_E_ARG;
        }
    }
    if (o.binder_len != 0) {
        /* 4.3.11: only the PSK the engine was given (hs_set_psk; dropped when CH1 lacked it), a
         * binder of its HashLen, and a suite of its hash on offer - after an HRR, the HRR's
         * suite: one of another hash means CH2 MUST drop the PSK (4.2.2). */
        if (hs->psk_len == 0 || o.binder_len != hs->psk_len) {
            return BRISK_E_ARG;
        }
        for (k = 0; k < o.n_suites; k++) {
            if (hs_alg(o.suites[k]) == hs_alg(hs->psk_suite)) {
                break;
            }
        }
        if (k == o.n_suites ||
            (hs->state == BRISK__HS_WAIT_CH2 && hs_alg(hs->suite) != hs_alg(hs->psk_suite)) ||
            hs_binder(hs, ch, ch_len, binder) != BRISK_OK) {
            return BRISK_E_ARG;
        }
    } else {
        brisk__secure_zero(hs->psk, sizeof hs->psk);
        hs->psk_len = 0;
    }
    hs->psk_offered = (uint8_t)(o.binder_len != 0);
    if (o.alpn_len != 0) {
        memcpy(hs->alpn, o.alpn, o.alpn_len);
    }
    hs->alpn_len = (uint16_t)o.alpn_len;
    memcpy(hs->offered_ext, o.ext, sizeof o.ext);
    memcpy(hs->offered_suites, o.suites, sizeof o.suites);
    memcpy(hs->offered_groups, o.groups, sizeof o.groups);
    memcpy(hs->offered_sigs, o.sigs, sizeof o.sigs);
    hs->n_ext = (uint8_t)o.n_ext;
    hs->own_rsl = o.rsl;
    hs->n_suites = (uint8_t)o.n_suites;
    hs->n_groups = (uint8_t)o.n_groups;
    hs->n_sigs = (uint8_t)o.n_sigs;
    hs->share_group = share_group;
    memcpy(hs->priv, share_priv, sizeof hs->priv);
    q = hs_reserve(hs, BRISK__EPOCH_INITIAL, ch_len); /* room was checked above */
    memcpy(q, ch, ch_len);
    if (hs->psk_offered) { /* the binder goes into OUR copy; the caller's bytes stay const */
        memcpy(q + ch_len - hs->psk_len, binder, hs->psk_len);
        brisk__secure_zero(binder, sizeof binder);
    }
    th_add(hs, q, ch_len);
    hs->state = BRISK__HS_WAIT_SH;
    return BRISK_OK;
}

int brisk__tls13_hs_feed(brisk__tls13_hs *hs, unsigned epoch, const uint8_t *in, size_t len)
{
    uint8_t *m;
    size_t need, take, body;
    int rc;

    if (hs == NULL || (in == NULL && len != 0)) {
        return BRISK_E_ARG;
    }
    if (hs->state == BRISK__HS_FAILED) {
        return hs->err;
    }
    if (len == 0) {
        return BRISK_OK;
    }
    /* RFC 9846 5.1: messages MUST NOT span a key change, and nothing is expected before the
     * ClientHello or between an HRR and CH2. After the handshake the epoch is APP (4.7). */
    if (epoch != hs->in_epoch || hs->state == BRISK__HS_START || hs->state == BRISK__HS_WAIT_CH2) {
        return hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE);
    }
    while (len != 0) {
        m = hs->in + hs->in_base;
        if (hs->in_len < 4) {
            take = 4 - hs->in_len < len ? 4 - hs->in_len : len;
            memcpy(m + hs->in_len, in, take);
            hs->in_len += take;
            in += take;
            len -= take;
            if (hs->in_len < 4) {
                break;
            }
            /* The length is checked against the buffer BEFORE a single body byte is taken.
             * illegal_parameter is a local choice for an implementation limit (OpenSSL uses the
             * same for "excessive message size"); the RFC names none. */
            body = brisk__load_be24(m + 1);
            if (body > BRISK_TLS_MAX_HS_MSG || body > hs->in_cap - hs->in_base - 4) {
                return hs_fail(hs, BRISK__ALERT_ILLEGAL_PARAMETER);
            }
        }
        need = 4 + brisk__load_be24(m + 1) - hs->in_len;
        take = need < len ? need : len;
        memcpy(m + hs->in_len, in, take);
        hs->in_len += take;
        in += take;
        len -= take;
        if (take < need) {
            break;
        }
        body = hs->in_len;
        hs->in_len = 0;
        rc = hs_dispatch(hs, m, body);
        if (rc != BRISK_OK) {
            return rc;
        }
        /* 5.1: nothing may follow a message that precedes a key change - SH, server Finished,
         * KeyUpdate - in the same record, which is what one hs_feed call is over TCP */
        if (len != 0 && (hs->in_epoch != epoch || hs->state == BRISK__HS_WAIT_CH2 ||
                         (hs->state == BRISK__HS_CONNECTED && m[0] == HS_KEY_UPDATE))) {
            return hs_fail(hs, BRISK__ALERT_UNEXPECTED_MESSAGE);
        }
    }
    return BRISK_OK;
}

size_t brisk__tls13_hs_pull(brisk__tls13_hs *hs, unsigned *epoch, uint8_t *out, size_t cap)
{
    size_t avail, n;
    unsigned e;
    if (hs == NULL || epoch == NULL || out == NULL || hs->state == BRISK__HS_FAILED ||
        hs->out_off == hs->out_len) {
        return 0;
    }
    if (hs->out_off < hs->out_split) {
        e = BRISK__EPOCH_INITIAL;
        avail = hs->out_split - hs->out_off;
    } else {
        e = BRISK__EPOCH_HANDSHAKE;
        avail = hs->out_len - hs->out_off;
    }
    n = avail < cap ? avail : cap;
    memcpy(out, hs->out + hs->out_off, n);
    hs->out_off += n;
    if (hs->out_off == hs->out_len) {
        hs->out_off = hs->out_len = hs->out_split = 0;
    }
    if (n != 0) {
        *epoch = e;
    }
    return n;
}

int brisk__tls13_hs_exporter(const brisk__tls13_hs *hs, const char *label, const uint8_t *ctx,
                             size_t ctx_len, uint8_t *out, size_t out_len)
{
    if (hs == NULL || hs->state != BRISK__HS_CONNECTED) {
        return BRISK_E_ARG;
    }
    return brisk__tls_ks_exporter(hs_alg(hs->suite), hs->exp_ms, label, ctx, ctx_len, out, out_len);
}

int brisk__tls13_hs_set_psk(brisk__tls13_hs *hs, const brisk__tls13_psk *psk)
{
    if (hs == NULL || psk == NULL || hs->state != BRISK__HS_START || !hs_known_suite(psk->suite) ||
        psk->psk_len != brisk_hash_len(hs_alg(psk->suite))) {
        return BRISK_E_ARG;
    }
    memcpy(hs->psk, psk->psk, psk->psk_len);
    hs->psk_len = psk->psk_len;
    hs->psk_suite = psk->suite;
    return BRISK_OK;
}

int brisk__tls13_hs_alpn(const brisk__tls13_hs *hs, const uint8_t **name, size_t *len)
{
    if (hs == NULL || name == NULL || len == NULL || hs->state != BRISK__HS_CONNECTED) {
        return BRISK_E_ARG;
    }
    *name = hs->alpn_sel_len ? hs->alpn + hs->alpn_sel_off : NULL;
    *len = hs->alpn_sel_len;
    return BRISK_OK;
}

int brisk__tls13_hs_resumed(const brisk__tls13_hs *hs)
{
    return hs != NULL && hs->psk_ok;
}

void brisk__tls13_hs_wipe(brisk__tls13_hs *hs)
{
    if (hs == NULL) {
        return;
    }
    if (hs->scratch != NULL) {
        brisk__secure_zero(hs->scratch, hs->scratch_len);
    }
    brisk__secure_zero(hs, sizeof *hs);
}

/* ------------------------------------------------------------------ ClientHello builder ---- */

typedef struct {
    uint8_t *b;
    size_t n, cap;
    int ok;
} hs_wr;

static void w_put(hs_wr *w, const void *d, size_t n)
{
    if (!w->ok || n > w->cap - w->n) {
        w->ok = 0;
        return;
    }
    if (n != 0) {
        memcpy(w->b + w->n, d, n);
    }
    w->n += n;
}

static void w_u8(hs_wr *w, unsigned v)
{
    uint8_t b = (uint8_t)v;
    w_put(w, &b, 1);
}

static void w_u16(hs_wr *w, unsigned v)
{
    uint8_t b[2];
    brisk__store_be16(b, v);
    w_put(w, b, 2);
}

/* Reserve a length field of `width` bytes; hs_wr_close fills it with what follows. */
static size_t w_open(hs_wr *w, size_t width)
{
    static const uint8_t z[3] = {0, 0, 0};
    w_put(w, z, width);
    return w->n;
}

static void w_close(hs_wr *w, size_t at, size_t width)
{
    size_t len = w->n - at;
    if (!w->ok) {
        return;
    }
    /* a length that does not fit its prefix fails closed, never truncates */
    if ((width == 1 && len > 0xff) || (width == 2 && len > 0xffff) || len > 0xffffff) {
        w->ok = 0;
        return;
    }
    if (width == 1) {
        w->b[at - 1] = (uint8_t)len;
    } else if (width == 2) {
        brisk__store_be16(w->b + at - 2, (uint32_t)len);
    } else {
        brisk__store_be24(w->b + at - 3, (uint32_t)len);
    }
}

static void w_u16_list(hs_wr *w, unsigned ext, const uint16_t *v, size_t n)
{
    size_t a, b, i;
    w_u16(w, ext);
    a = w_open(w, 2);
    b = w_open(w, 2);
    for (i = 0; i < n; i++) {
        w_u16(w, v[i]);
    }
    w_close(w, b, 2);
    w_close(w, a, 2);
}

int brisk__tls13_ch_write(const brisk__tls13_ch_params *p, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    const uint16_t *suites, *groups, *sigs;
    size_t n_suites, n_groups, n_sigs, msg, exts, a, b, i, sni_len;
    uint8_t ip[16];
    hs_wr w;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (p == NULL || out == NULL || out_len == NULL || p->random == NULL ||
        (p->session_id_len != 0 && p->session_id_len != 32) ||
        (p->session_id_len != 0 && p->session_id == NULL) || p->share_pub == NULL ||
        hs_share_len(p->share_group) == 0 || p->share_pub_len != hs_share_len(p->share_group) ||
        (p->cookie_len != 0 && p->cookie == NULL) || p->cookie_len > BRISK__TLS13_COOKIE_MAX ||
        (p->sni_len != 0 && p->sni == NULL) || p->sni_len > BRISK__X509_MAX_NAME ||
        (p->quic_tp_len != 0 && p->quic_tp == NULL)) {
        return BRISK_E_ARG;
    }
    /* RFC 6066 3: HostName MUST NOT carry the trailing root dot (match_host strips it too), and
     * is ASCII: printable, no space - an IDN arrives as A-labels. */
    sni_len = p->sni_len;
    if (sni_len != 0 && p->sni[sni_len - 1] == '.') {
        if (--sni_len == 0) {
            return BRISK_E_ARG;
        }
    }
    for (i = 0; i < sni_len; i++) {
        if ((uint8_t)p->sni[i] < 0x21 || (uint8_t)p->sni[i] > 0x7e) {
            return BRISK_E_ARG;
        }
    }
    /* RFC 7301 3.1: ProtocolName<1..2^8-1> entries, none empty, none truncated; a local cap on
     * the list. 4.3.9 + 4.3.11: a PSK needs psk_key_exchange_modes, one identity, a binder of
     * the PSK's HashLen. */
    if ((p->alpn_len != 0 && p->alpn == NULL) || p->alpn_len > BRISK__TLS13_ALPN_MAX) {
        return BRISK_E_ARG;
    }
    for (i = 0; i < p->alpn_len; i += 1 + (size_t)p->alpn[i]) {
        if (p->alpn[i] == 0 || p->alpn[i] > p->alpn_len - i - 1) {
            return BRISK_E_ARG;
        }
    }
    if (p->psk != NULL &&
        (!p->psk_modes || p->psk->identity == NULL || p->psk->identity_len == 0 ||
         /* 4.3.11: extension_data<0..2^16-1> also holds 2+2+4 list/age bytes and 2+1+HashLen of
          * binders */
         p->psk->identity_len > 0xffff - 11 - (size_t)p->psk->psk_len || (p->psk->psk_len != 32 && p->psk->psk_len != 48))) {
        return BRISK_E_ARG;
    }
    suites = p->suites ? p->suites : DEF_SUITES;
    n_suites = p->suites ? p->n_suites : sizeof DEF_SUITES / sizeof DEF_SUITES[0];
    groups = p->groups ? p->groups : DEF_GROUPS;
    n_groups = p->groups ? p->n_groups : sizeof DEF_GROUPS / sizeof DEF_GROUPS[0];
    sigs = p->sig_schemes ? p->sig_schemes : DEF_SIGS;
    n_sigs = p->sig_schemes ? p->n_sig_schemes : sizeof DEF_SIGS / sizeof DEF_SIGS[0];
    /* 4.3.8: the share's group is one supported_groups lists; no empty lists (9.2). */
    if (n_suites == 0 || n_groups == 0 || n_sigs == 0 || n_suites > 64 || n_groups > 64 ||
        n_sigs > 64 || !hs_in_list(groups, n_groups, p->share_group)) {
        return BRISK_E_ARG;
    }

    w.b = out;
    w.n = 0;
    w.cap = cap;
    w.ok = 1;
    w_u8(&w, HS_CLIENT_HELLO);
    msg = w_open(&w, 3);
    w_u16(&w, 0x0303);
    w_put(&w, p->random, 32);
    w_u8(&w, (unsigned)p->session_id_len);
    w_put(&w, p->session_id, p->session_id_len);
    a = w_open(&w, 2);
    for (i = 0; i < n_suites; i++) {
        w_u16(&w, suites[i]);
    }
    w_close(&w, a, 2);
    w_u8(&w, 1); /* legacy_compression_methods = [null] */
    w_u8(&w, 0);
    exts = w_open(&w, 2);
    /* RFC 6066 3: host_name only, never an IP literal (brisk__x509_parse_ip is the one place
     * that decides what is an address, RFC 9525 7.4). */
    if (sni_len != 0 && brisk__x509_parse_ip(p->sni, sni_len, ip) == 0) {
        w_u16(&w, EXT_SERVER_NAME);
        a = w_open(&w, 2);
        b = w_open(&w, 2);
        w_u8(&w, 0);
        w_u16(&w, (unsigned)sni_len);
        w_put(&w, p->sni, sni_len);
        w_close(&w, b, 2);
        w_close(&w, a, 2);
    }
    w_u16_list(&w, EXT_SUPPORTED_GROUPS, groups, n_groups);
    w_u16_list(&w, EXT_SIGNATURE_ALGORITHMS, sigs, n_sigs);
    if (p->alpn_len != 0) { /* RFC 7301 3.1 */
        w_u16(&w, EXT_ALPN);
        a = w_open(&w, 2);
        b = w_open(&w, 2);
        w_put(&w, p->alpn, p->alpn_len);
        w_close(&w, b, 2);
        w_close(&w, a, 2);
    }
    w_u16(&w, EXT_SUPPORTED_VERSIONS); /* 4.3.1: exactly TLS 1.3 */
    w_u16(&w, 3);
    w_u8(&w, 2);
    w_u16(&w, 0x0304);
    if (p->cookie_len != 0) {
        w_u16(&w, EXT_COOKIE);
        a = w_open(&w, 2);
        b = w_open(&w, 2);
        w_put(&w, p->cookie, p->cookie_len);
        w_close(&w, b, 2);
        w_close(&w, a, 2);
    }
    if (p->psk_modes) { /* 4.3.9: [psk_dhe_ke] only, never psk_ke */
        w_u16(&w, EXT_PSK_MODES);
        w_u16(&w, 2);
        w_u8(&w, 1);
        w_u8(&w, 1);
    }
    w_u16(&w, EXT_KEY_SHARE);
    a = w_open(&w, 2);
    b = w_open(&w, 2);
    w_u16(&w, p->share_group);
    w_u16(&w, (unsigned)p->share_pub_len);
    w_put(&w, p->share_pub, p->share_pub_len);
    w_close(&w, b, 2);
    w_close(&w, a, 2);
    if (p->quic_tp != NULL) { /* RFC 9001 8.2 */
        w_u16(&w, EXT_QUIC_TP);
        a = w_open(&w, 2);
        w_put(&w, p->quic_tp, p->quic_tp_len);
        w_close(&w, a, 2);
    }
    if (p->psk != NULL) {
        /* 4.3.11: pre_shared_key MUST be the last extension. One PskIdentity {identity,
         * obfuscated_ticket_age}, one binder of HashLen zeros that hs_client_hello fills. */
        w_u16(&w, EXT_PSK);
        a = w_open(&w, 2);
        b = w_open(&w, 2);
        w_u16(&w, (unsigned)p->psk->identity_len);
        w_put(&w, p->psk->identity, p->psk->identity_len);
        w_u16(&w, (unsigned)(p->psk->obf_age >> 16));
        w_u16(&w, (unsigned)(p->psk->obf_age & 0xffff));
        w_close(&w, b, 2);
        w_u16(&w, 1u + p->psk->psk_len);
        w_u8(&w, p->psk->psk_len);
        for (i = 0; i < p->psk->psk_len; i++) {
            w_u8(&w, 0);
        }
        w_close(&w, a, 2);
    }
    w_close(&w, exts, 2);
    w_close(&w, msg, 3);
    if (!w.ok) {
        return BRISK_E_ARG;
    }
    *out_len = w.n;
    return BRISK_OK;
}

/* ------------------------------------------------------------------ CertificateVerify ----- */

size_t brisk__tls13_cv_content(int is_server, const uint8_t *th, size_t hl, uint8_t *out)
{
    static const char SERVER[] = "TLS 1.3, server CertificateVerify";
    static const char CLIENT[] = "TLS 1.3, client CertificateVerify";
    memset(out, 0x20, 64);
    memcpy(out + 64, is_server ? SERVER : CLIENT, sizeof SERVER); /* NUL included: the 0x00 */
    memcpy(out + 64 + sizeof SERVER, th, hl);
    return 64 + sizeof SERVER + hl;
}

/* The key type and digest a CertificateVerify scheme demands (RFC 9846 4.3.3). 0 = not one this
 * build verifies in a CertificateVerify. */
static unsigned cv_scheme(uint16_t scheme, brisk_hash_alg *alg, uint8_t *family)
{
    *family = BRISK__X509_SIG_RSA_PSS;
    switch (scheme) {
    case 0x0403:
        *alg = BRISK_HASH_SHA256;
        *family = BRISK__X509_SIG_ECDSA;
        return BRISK__X509_KEY_P256;
#if BRISK_ENABLE_P384
    case 0x0503:
        *alg = BRISK_HASH_SHA384;
        *family = BRISK__X509_SIG_ECDSA;
        return BRISK__X509_KEY_P384;
#endif
    case 0x0804:
        *alg = BRISK_HASH_SHA256;
        return BRISK__X509_KEY_RSA;
    case 0x0805:
        *alg = BRISK_HASH_SHA384;
        return BRISK__X509_KEY_RSA;
    case 0x0806:
        *alg = BRISK_HASH_SHA512;
        return BRISK__X509_KEY_RSA;
    default:
        return 0;
    }
}

int brisk__tls13_cv_verify(const brisk__x509_cert *leaf, uint16_t scheme, const uint8_t *tbs,
                           size_t tbs_len, const uint8_t *sig, size_t sig_len, uint8_t *alert)
{
    brisk__x509_cert child;
    uint8_t raw[96], family;
    brisk_hash_alg alg = BRISK_HASH_SHA256;
    unsigned key = cv_scheme(scheme, &alg, &family);
    int rc;

    if (key == 0 || leaf == NULL || leaf->key_alg != key) {
        *alert = BRISK__ALERT_ILLEGAL_PARAMETER; /* 4.3.3: the scheme binds curve and hash */
        return BRISK_E_ARG;
    }
    if (family == BRISK__X509_SIG_ECDSA &&
        brisk__x509_ecdsa_raw(sig, sig_len, key == BRISK__X509_KEY_P256 ? 32 : 48, raw) !=
            BRISK_OK) {
        *alert = BRISK__ALERT_DECODE_ERROR;
        return BRISK_E_AUTH;
    }
    /* brisk__x509_signed_by already owns "hash this with that, verify under this key", so the
     * CertificateVerify rides on it as a certificate whose TBS is the 4.5.2 content. The PSS
     * salt length is hLen (4.3.3), never anything the peer said. */
    memset(&child, 0, sizeof child);
    child.tbs = tbs;
    child.tbs_len = tbs_len;
    child.sig = sig;
    child.sig_len = sig_len;
    child.sig_alg = family;
    child.sig_hash = (uint8_t)alg;
    child.sig_salt_len = (uint8_t)brisk_hash_len(alg);
    rc = brisk__x509_signed_by(&child, leaf);
    if (rc == BRISK_OK) {
        return BRISK_OK;
    }
    /* BRISK_E_AUTH: 4.5.2 "MUST abort with decrypt_error". BRISK_E_ARG: the scheme/key fit was
     * established above and the signature DER too, so what is left is the key itself. */
    *alert = rc == BRISK_E_AUTH ? BRISK__ALERT_DECRYPT_ERROR : BRISK__ALERT_BAD_CERTIFICATE;
    return rc == BRISK_E_AUTH ? BRISK_E_AUTH : BRISK_E_ARG;
}

int brisk__tls13_auth_x509(void *ctx, const brisk__x509_cert *certs, size_t n_certs,
                           uint16_t scheme, const uint8_t *tbs, size_t tbs_len, const uint8_t *sig,
                           size_t sig_len, uint8_t *alert)
{
    const brisk__tls13_auth_x509_ctx *a = (const brisk__tls13_auth_x509_ctx *)ctx;
    brisk_hash_alg alg;
    uint8_t family;
    int rc;

    if (a == NULL || certs == NULL || n_certs == 0) {
        *alert = BRISK__ALERT_INTERNAL_ERROR;
        return BRISK_E_ARG;
    }
    if (cv_scheme(scheme, &alg, &family) != certs[0].key_alg ||
        cv_scheme(scheme, &alg, &family) == 0) {
        *alert = BRISK__ALERT_ILLEGAL_PARAMETER; /* before any bignum work */
        return BRISK_E_ARG;
    }
    rc = brisk__x509_chain_verify(certs, n_certs, a->now, a->trust);
    if (rc != BRISK_OK) {
        *alert = rc == BRISK_E_AUTH ? BRISK__ALERT_BAD_CERTIFICATE
                                    : BRISK__ALERT_UNSUPPORTED_CERTIFICATE;
        return BRISK_E_AUTH;
    }
    rc = brisk__x509_match_host(&certs[0], a->host, a->host_len);
    if (rc != BRISK_OK) {
        /* BRISK_E_ARG is the caller's reference identifier, not the peer. */
        *alert = rc == BRISK_E_AUTH ? BRISK__ALERT_BAD_CERTIFICATE : BRISK__ALERT_INTERNAL_ERROR;
        return rc;
    }
    if ((certs[0].key_usage != 0 && !(certs[0].key_usage & BRISK__X509_KU_DIGITAL_SIGNATURE)) ||
        (certs[0].eku != 0 && !(certs[0].eku & (BRISK__X509_EKU_SERVER | BRISK__X509_EKU_ANY)))) {
        *alert = BRISK__ALERT_UNSUPPORTED_CERTIFICATE;
        return BRISK_E_AUTH;
    }
    return brisk__tls13_cv_verify(&certs[0], scheme, tbs, tbs_len, sig, sig_len, alert);
}

#undef HS_CV_MAX
#undef HS_IN_CAP
#undef HS_CERT_ALIGN
