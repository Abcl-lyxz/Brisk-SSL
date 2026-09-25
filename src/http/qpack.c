/* qpack.c - QPACK field compression for HTTP/3 (RFC 9204), STATIC TABLE ONLY.
 *
 * We advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 and SETTINGS_QPACK_BLOCKED_STREAMS = 0 (by
 * omitting both: 0 is their default, RFC 9204 5). With MaxTableCapacity 0 the server's encoder
 * can never insert (3.2.3: capacity <= our maximum; 3.2.2: an entry larger than the capacity is
 * an error), so MaxEntries = 0 and every valid field section has Required Insert Count 0: no
 * section blocks (2.1.2), none needs a Section Acknowledgment (4.4.1), and we open no encoder or
 * decoder stream of our own (4.2 MAY). What remains is stateless, so there is no table memory.
 *
 * DECODER (4.5). The prefix must be Required Insert Count 0 and Sign 0 (any Delta Base: with
 * RIC 0 the Base is irrelevant). Only three field line forms can be valid: indexed static
 * (4.5.2, T=1), literal with static name reference (4.5.4, T=1) and literal with literal name
 * (4.5.6). Every dynamic or post-Base reference names an absolute index >= RIC = 0, which 2.2.3
 * makes QPACK_DECOMPRESSION_FAILED, as is a static index >= 99 (3.1). Integers are the full
 * 62-bit range of 4.1.1 (a legal Delta Base can be huge); strings are 4.1.2 with the HPACK
 * Huffman code (huffman.c). A local limit (a field larger than the scratch, a section larger
 * than max_list) is reported apart from a coding error: HTTP/3 aborts only that request for it.
 *
 * ENCODER. Prefix 00 00, then the static table where it matches exactly, else a literal with a
 * static name reference, else a literal name; never Huffman and never the dynamic table - no
 * compression-oracle surface (7.1), the same policy as hpack.c. The N bit marks the fields
 * RFC 9204 7.1.3 / RFC 7541 7.1.3 call sensitive (the caller's BRISK__HPACK_NEVER_INDEXED).
 *
 * INSTRUCTION STREAMS. The server's encoder stream may only ever carry Set Dynamic Table
 * Capacity 0 (4.3.1); any insert or duplicate is QPACK_ENCODER_STREAM_ERROR (3.2.2, 2.2.3). Its
 * decoder stream may only carry Stream Cancellation (ignored); a Section Acknowledgment or an
 * Insert Count Increment refers to state we never created (4.4.1, 4.4.3):
 * QPACK_DECODER_STREAM_ERROR.
 *
 * No 64-bit division or variable 64-bit shift (32-bit targets): integers are rebuilt with
 * constant 7-bit shifts. Every loop is bounded by the input length or the table size.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_H3

#    include <string.h>

/* RFC 9204 Appendix A, index 0..98: "name\0value\0" per entry. Checked byte for byte against the
 * RFC by tools/kat.py (check_qpack_source_constants), and against pylsqpack when installed. */
/* clang-format off */
static const char qp_static[] =
    ":authority\0" "\0"                                                                   /* 0 */
    ":path\0" "/\0"                                                                       /* 1 */
    "age\0" "0\0"                                                                         /* 2 */
    "content-disposition\0" "\0"                                                          /* 3 */
    "content-length\0" "0\0"                                                              /* 4 */
    "cookie\0" "\0"                                                                       /* 5 */
    "date\0" "\0"                                                                         /* 6 */
    "etag\0" "\0"                                                                         /* 7 */
    "if-modified-since\0" "\0"                                                            /* 8 */
    "if-none-match\0" "\0"                                                                /* 9 */
    "last-modified\0" "\0"                                                                /* 10 */
    "link\0" "\0"                                                                         /* 11 */
    "location\0" "\0"                                                                     /* 12 */
    "referer\0" "\0"                                                                      /* 13 */
    "set-cookie\0" "\0"                                                                   /* 14 */
    ":method\0" "CONNECT\0"                                                               /* 15 */
    ":method\0" "DELETE\0"                                                                /* 16 */
    ":method\0" "GET\0"                                                                   /* 17 */
    ":method\0" "HEAD\0"                                                                  /* 18 */
    ":method\0" "OPTIONS\0"                                                               /* 19 */
    ":method\0" "POST\0"                                                                  /* 20 */
    ":method\0" "PUT\0"                                                                   /* 21 */
    ":scheme\0" "http\0"                                                                  /* 22 */
    ":scheme\0" "https\0"                                                                 /* 23 */
    ":status\0" "103\0"                                                                   /* 24 */
    ":status\0" "200\0"                                                                   /* 25 */
    ":status\0" "304\0"                                                                   /* 26 */
    ":status\0" "404\0"                                                                   /* 27 */
    ":status\0" "503\0"                                                                   /* 28 */
    "accept\0" "*/*\0"                                                                    /* 29 */
    "accept\0" "application/dns-message\0"                                                /* 30 */
    "accept-encoding\0" "gzip, deflate, br\0"                                             /* 31 */
    "accept-ranges\0" "bytes\0"                                                           /* 32 */
    "access-control-allow-headers\0" "cache-control\0"                                    /* 33 */
    "access-control-allow-headers\0" "content-type\0"                                     /* 34 */
    "access-control-allow-origin\0" "*\0"                                                 /* 35 */
    "cache-control\0" "max-age=0\0"                                                       /* 36 */
    "cache-control\0" "max-age=2592000\0"                                                 /* 37 */
    "cache-control\0" "max-age=604800\0"                                                  /* 38 */
    "cache-control\0" "no-cache\0"                                                        /* 39 */
    "cache-control\0" "no-store\0"                                                        /* 40 */
    "cache-control\0" "public, max-age=31536000\0"                                        /* 41 */
    "content-encoding\0" "br\0"                                                           /* 42 */
    "content-encoding\0" "gzip\0"                                                         /* 43 */
    "content-type\0" "application/dns-message\0"                                          /* 44 */
    "content-type\0" "application/javascript\0"                                           /* 45 */
    "content-type\0" "application/json\0"                                                 /* 46 */
    "content-type\0" "application/x-www-form-urlencoded\0"                                /* 47 */
    "content-type\0" "image/gif\0"                                                        /* 48 */
    "content-type\0" "image/jpeg\0"                                                       /* 49 */
    "content-type\0" "image/png\0"                                                        /* 50 */
    "content-type\0" "text/css\0"                                                         /* 51 */
    "content-type\0" "text/html; charset=utf-8\0"                                         /* 52 */
    "content-type\0" "text/plain\0"                                                       /* 53 */
    "content-type\0" "text/plain;charset=utf-8\0"                                         /* 54 */
    "range\0" "bytes=0-\0"                                                                /* 55 */
    "strict-transport-security\0" "max-age=31536000\0"                                    /* 56 */
    "strict-transport-security\0" "max-age=31536000; includesubdomains\0"                 /* 57 */
    "strict-transport-security\0" "max-age=31536000; includesubdomains; preload\0"        /* 58 */
    "vary\0" "accept-encoding\0"                                                          /* 59 */
    "vary\0" "origin\0"                                                                   /* 60 */
    "x-content-type-options\0" "nosniff\0"                                                /* 61 */
    "x-xss-protection\0" "1; mode=block\0"                                                /* 62 */
    ":status\0" "100\0"                                                                   /* 63 */
    ":status\0" "204\0"                                                                   /* 64 */
    ":status\0" "206\0"                                                                   /* 65 */
    ":status\0" "302\0"                                                                   /* 66 */
    ":status\0" "400\0"                                                                   /* 67 */
    ":status\0" "403\0"                                                                   /* 68 */
    ":status\0" "421\0"                                                                   /* 69 */
    ":status\0" "425\0"                                                                   /* 70 */
    ":status\0" "500\0"                                                                   /* 71 */
    "accept-language\0" "\0"                                                              /* 72 */
    "access-control-allow-credentials\0" "FALSE\0"                                        /* 73 */
    "access-control-allow-credentials\0" "TRUE\0"                                         /* 74 */
    "access-control-allow-headers\0" "*\0"                                                /* 75 */
    "access-control-allow-methods\0" "get\0"                                              /* 76 */
    "access-control-allow-methods\0" "get, post, options\0"                               /* 77 */
    "access-control-allow-methods\0" "options\0"                                          /* 78 */
    "access-control-expose-headers\0" "content-length\0"                                  /* 79 */
    "access-control-request-headers\0" "content-type\0"                                   /* 80 */
    "access-control-request-method\0" "get\0"                                             /* 81 */
    "access-control-request-method\0" "post\0"                                            /* 82 */
    "alt-svc\0" "clear\0"                                                                 /* 83 */
    "authorization\0" "\0"                                                                /* 84 */
    "content-security-policy\0" "script-src 'none'; object-src 'none'; base-uri 'none'\0" /* 85 */
    "early-data\0" "1\0"                                                                  /* 86 */
    "expect-ct\0" "\0"                                                                    /* 87 */
    "forwarded\0" "\0"                                                                    /* 88 */
    "if-range\0" "\0"                                                                     /* 89 */
    "origin\0" "\0"                                                                       /* 90 */
    "purpose\0" "prefetch\0"                                                              /* 91 */
    "server\0" "\0"                                                                       /* 92 */
    "timing-allow-origin\0" "*\0"                                                         /* 93 */
    "upgrade-insecure-requests\0" "1\0"                                                   /* 94 */
    "user-agent\0" "\0"                                                                   /* 95 */
    "x-forwarded-for\0" "\0"                                                              /* 96 */
    "x-frame-options\0" "deny\0"                                                          /* 97 */
    "x-frame-options\0" "sameorigin\0";                                                   /* 98 */
/* clang-format on */
#    define QP_STATIC_N 99u
#    define QP_MAX      (((uint64_t)1 << 62) - 1) /* 4.1.1: QUIC's varint range */

    /* Static entry idx (0..98): name and value inside the blob. */
    static void qp_static_get(uint64_t idx, const uint8_t **n, size_t *nl, const uint8_t **v,
                              size_t *vl)
{
    const char *p = qp_static;
    uint64_t i;
    for (i = 0; i < idx; i++) {
        p += strlen(p) + 1;
        p += strlen(p) + 1;
    }
    *n = (const uint8_t *)p;
    *nl = strlen(p);
    p += *nl + 1;
    *v = (const uint8_t *)p;
    *vl = strlen(p);
}

int brisk__qpack_int_decode(const uint8_t *p, size_t len, unsigned n, uint64_t *v, size_t *used)
{
    uint64_t pv, c = 0;
    size_t k, j;
    unsigned mask;

    if (!p || !v || !used || n < 1 || n > 8) {
        return BRISK_E_ARG;
    }
    if (len == 0) {
        return BRISK_E_WANT;
    }
    mask = (1u << n) - 1u; /* the flag bits above the prefix are the caller's */
    pv = p[0] & mask;
    if (pv < mask) {
        *v = pv;
        *used = 1;
        return BRISK_OK;
    }
    /* 4.1.1 / RFC 7541 5.1: the value may reach 2^62-1, which takes 9 continuation octets; a
     * 10th (redundant zeros) is tolerated, an 11th is an encoding past our limit - "MUST be
     * treated as a decoding error" whatever it would add */
    for (k = 1; k <= 10; k++) {
        if (k >= len) {
            return BRISK_E_WANT;
        }
        if (!(p[k] & 0x80)) {
            break;
        }
    }
    if (k > 10) {
        return BRISK_E_PROTO;
    }
    /* Horner from the most significant group down: constant shifts only, and c stays <= 2^62-1
     * (checked before each shift, so nothing wraps) */
    for (j = k; j >= 1; j--) {
        if (c > (QP_MAX >> 7)) {
            return BRISK_E_PROTO;
        }
        c = (c << 7) | (uint64_t)(p[j] & 0x7f);
    }
    if (c > QP_MAX - pv) {
        return BRISK_E_PROTO;
    }
    *v = pv + c;
    *used = k + 1;
    return BRISK_OK;
}

/* A 4.1.2 string literal at blk[*p] whose length has an n-bit prefix (7 for values, 3 for a
 * literal name) with the H flag just above it, decoded into dst (cap). *p moves past it.
 * BRISK_E_PROTO = a coding error (truncated, runs past the section, bad Huffman);
 * BRISK__QPACK_E_LIMIT = a well-formed string that does not fit cap. */
static int qp_str(const uint8_t *blk, size_t len, size_t *p, unsigned n, uint8_t *dst, size_t cap,
                  size_t *out)
{
    uint64_t sl;
    size_t used, start = *p, k;
    if (brisk__qpack_int_decode(blk + start, len - start, n, &sl, &used) != BRISK_OK) {
        return BRISK_E_PROTO;
    }
    *p += used;
    if (sl > (uint64_t)(len - *p)) {
        return BRISK_E_PROTO; /* runs past the field section */
    }
    k = (size_t)sl;
    if (blk[start] & (1u << n)) { /* H */
        if (brisk__huff_decode(blk + *p, k, dst, cap, out) != BRISK_OK) {
            /* EOS / padding (RFC 7541 5.2 MUSTs, 9204 4.1.2) or only our buffer? */
            return brisk__huff_len(blk + *p, k, out) != BRISK_OK ? BRISK_E_PROTO
                                                                 : BRISK__QPACK_E_LIMIT;
        }
    } else {
        if (k > cap) {
            return BRISK__QPACK_E_LIMIT;
        }
        memcpy(dst, blk + *p, k);
        *out = k;
    }
    *p += k;
    return BRISK_OK;
}

int brisk__qpack_decode(const uint8_t *blk, size_t len, uint8_t *scratch, size_t scratch_cap,
                        size_t max_list, brisk__hpack_field_fn fn, void *ctx)
{
    size_t p = 0, list = 0, used, nl = 0, vl = 0;
    uint64_t v;
    int rc;

    if ((!blk && len) || !scratch || !fn) {
        return BRISK_E_ARG;
    }
    /* 4.5.1.1: Required Insert Count. MaxEntries = 0 -> FullRange = 0: any encoded value but 0
     * "could not have been produced" - MUST be QPACK_DECOMPRESSION_FAILED */
    if (brisk__qpack_int_decode(blk, len, 8, &v, &used) != BRISK_OK || v != 0) {
        return BRISK_E_PROTO;
    }
    p = used;
    /* 4.5.1.2: Sign + Delta Base. With RIC 0, Sign 1 means RIC <= Delta Base: MUST be invalid;
     * Sign 0 allows any Delta Base (the Base is never used without the dynamic table) */
    if (p >= len || (blk[p] & 0x80) ||
        brisk__qpack_int_decode(blk + p, len - p, 7, &v, &used) != BRISK_OK) {
        return BRISK_E_PROTO;
    }
    p += used;
    while (p < len) {
        uint8_t b = blk[p];
        unsigned flags = 0;
        if (b & 0x80) {
            /* 4.5.2 Indexed Field Line: 1 T index(6+). T = 0 is the dynamic table: 2.2.3 */
            if (!(b & 0x40) ||
                brisk__qpack_int_decode(blk + p, len - p, 6, &v, &used) != BRISK_OK ||
                v >= QP_STATIC_N) {
                return BRISK_E_PROTO; /* 3.1: static index past the table */
            }
            p += used;
            {
                const uint8_t *sn, *sv;
                qp_static_get(v, &sn, &nl, &sv, &vl);
                if (nl > scratch_cap || vl > scratch_cap - nl) {
                    return BRISK__QPACK_E_LIMIT;
                }
                memcpy(scratch, sn, nl);
                memcpy(scratch + nl, sv, vl);
            }
        } else if (b & 0x40) {
            /* 4.5.4 Literal Field Line with Name Reference: 01 N T index(4+), value(7+) */
            const uint8_t *sn, *sv;
            size_t svl;
            if (!(b & 0x10) ||
                brisk__qpack_int_decode(blk + p, len - p, 4, &v, &used) != BRISK_OK ||
                v >= QP_STATIC_N) {
                return BRISK_E_PROTO;
            }
            flags = (b & 0x20) ? BRISK__HPACK_NEVER_INDEXED : 0;
            p += used;
            qp_static_get(v, &sn, &nl, &sv, &svl);
            if (nl > scratch_cap) {
                return BRISK__QPACK_E_LIMIT;
            }
            memcpy(scratch, sn, nl);
            if ((rc = qp_str(blk, len, &p, 7, scratch + nl, scratch_cap - nl, &vl)) != BRISK_OK) {
                return rc;
            }
        } else if (b & 0x20) {
            /* 4.5.6 Literal Field Line with Literal Name: 001 N H len(3+) name, value(7+) */
            flags = (b & 0x10) ? BRISK__HPACK_NEVER_INDEXED : 0;
            if ((rc = qp_str(blk, len, &p, 3, scratch, scratch_cap, &nl)) != BRISK_OK ||
                (rc = qp_str(blk, len, &p, 7, scratch + nl, scratch_cap - nl, &vl)) != BRISK_OK) {
                return rc;
            }
        } else {
            /* 4.5.3 Indexed Field Line with Post-Base Index (0001) and 4.5.5 Literal Field Line
             * with Post-Base Name Reference (0000): absolute index >= Base >= RIC = 0, an entry
             * that cannot exist (2.2.3 MUST) */
            return BRISK_E_PROTO;
        }
        /* RFC 9114 4.2.2 SETTINGS_MAX_FIELD_SECTION_SIZE: n + v + 32 per field, our limit */
        if (nl + vl > max_list || max_list - (nl + vl) < 32 || list > max_list - (nl + vl) - 32) {
            return BRISK__QPACK_E_LIMIT;
        }
        list += nl + vl + 32;
        rc = fn(ctx, scratch, nl, scratch + nl, vl, flags);
        if (rc != 0) {
            return rc;
        }
    }
    return BRISK_OK;
}

/* ---------------------------------------------------------------------------------- encoder */

/* 4.1.1 prefixed integer, minimal; flags fill the bits above the n-bit prefix. -1 when full. */
static int qp_put_int(uint8_t *out, size_t cap, size_t *pos, unsigned flags, unsigned n, size_t v)
{
    size_t mx = ((size_t)1 << n) - 1;
    if (*pos >= cap) {
        return -1;
    }
    if (v < mx) {
        out[(*pos)++] = (uint8_t)(flags | v);
        return 0;
    }
    out[(*pos)++] = (uint8_t)(flags | mx);
    v -= mx;
    for (;;) {
        if (*pos >= cap) {
            return -1;
        }
        if (v < 128) {
            out[(*pos)++] = (uint8_t)v;
            return 0;
        }
        out[(*pos)++] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
}

/* 4.1.2 string, H = 0 always; flags / n as qp_put_int */
static int qp_put_str(uint8_t *out, size_t cap, size_t *pos, unsigned flags, unsigned n,
                      const uint8_t *s, size_t len)
{
    if (qp_put_int(out, cap, pos, flags, n, len) || len > cap - *pos) {
        return -1;
    }
    if (len) {
        memcpy(out + *pos, s, len);
    }
    *pos += len;
    return 0;
}

/* One field line at out[*pos]; -1 when out is full. The field is already validated. */
static int qp_put_field(const brisk__hpack_field *f, uint8_t *out, size_t cap, size_t *pos)
{
    uint64_t k;
    size_t exact = QP_STATIC_N, name = QP_STATIC_N;
    int never = (f->flags & BRISK__HPACK_NEVER_INDEXED) != 0;
    for (k = 0; k < QP_STATIC_N; k++) {
        const uint8_t *sn, *sv;
        size_t snl, svl;
        qp_static_get(k, &sn, &snl, &sv, &svl);
        if (snl == f->name_len && memcmp(sn, f->name, snl) == 0) {
            if (name == QP_STATIC_N) {
                name = (size_t)k; /* the lowest index with that name */
            }
            if (svl == f->value_len && (svl == 0 || memcmp(sv, f->value, svl) == 0)) {
                exact = (size_t)k;
                break;
            }
        }
    }
    if (exact != QP_STATIC_N && !never) {
        return qp_put_int(out, cap, pos, 0xc0, 6, exact); /* 4.5.2, T = 1 */
    }
    if (name != QP_STATIC_N) {
        if (qp_put_int(out, cap, pos, never ? 0x70 : 0x50, 4, name)) { /* 4.5.4: 01 N T=1 */
            return -1;
        }
    } else if (qp_put_str(out, cap, pos, never ? 0x30 : 0x20, 3, f->name, f->name_len)) {
        return -1; /* 4.5.6: 001 N H=0 len(3+) */
    }
    return qp_put_str(out, cap, pos, 0, 7, f->value, f->value_len);
}

int brisk__qpack_encode(const brisk__hpack_field *f, size_t n, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    size_t pos = 0, i;
    if (!out_len) {
        return BRISK_E_ARG;
    }
    *out_len = 0;
    if ((!f && n) || (!out && cap)) {
        return BRISK_E_ARG;
    }
    for (i = 0; i < n; i++) { /* validate everything first: a failed call emits nothing */
        if (!brisk__hpack_field_ok(f[i].name, f[i].name_len, f[i].value, f[i].value_len)) {
            return BRISK_E_ARG;
        }
    }
    /* 4.5.1: Required Insert Count 0, Sign 0, Delta Base 0 */
    if (qp_put_int(out, cap, &pos, 0, 8, 0) || qp_put_int(out, cap, &pos, 0, 7, 0)) {
        return BRISK_E_ARG;
    }
    for (i = 0; i < n; i++) {
        if (qp_put_field(&f[i], out, cap, &pos)) {
            return BRISK_E_ARG;
        }
    }
    *out_len = pos;
    return BRISK_OK;
}

int brisk__qpack_encode_field(const brisk__hpack_field *f, uint8_t *out, size_t cap,
                              size_t *out_len)
{
    size_t pos = 0;
    if (!out_len) {
        return BRISK_E_ARG;
    }
    *out_len = 0;
    if (!f || (!out && cap) ||
        !brisk__hpack_field_ok(f->name, f->name_len, f->value, f->value_len) ||
        qp_put_field(f, out, cap, &pos)) {
        return BRISK_E_ARG;
    }
    *out_len = pos;
    return BRISK_OK;
}

/* ------------------------------------------------------------------- instruction streams */

int brisk__qpack_enc_stream(const uint8_t *in, size_t len, size_t *used, uint64_t *err)
{
    size_t i;
    if ((!in && len) || !used || !err) {
        return BRISK_E_ARG;
    }
    *used = 0;
    *err = 0;
    for (i = 0; i < len; i++) {
        /* 4.3.1 Set Dynamic Table Capacity (001 + 5-bit prefix): 0 fits only in the one octet
         * 0x20; anything larger exceeds our SETTINGS_QPACK_MAX_TABLE_CAPACITY 0 (MUST be an
         * error). 4.3.2 / 4.3.3 inserts (1..., 01...): the entry exceeds capacity 0 (3.2.2
         * MUST). 4.3.4 Duplicate (000...): no entry exists to duplicate (2.2.3 MUST). */
        if (in[i] != 0x20) {
            *err = BRISK__QPACK_ENCODER_STREAM_ERROR;
            return BRISK_E_PROTO;
        }
        *used = i + 1;
    }
    return BRISK_OK;
}

int brisk__qpack_dec_stream(const uint8_t *in, size_t len, size_t *used, uint64_t *err)
{
    size_t p = 0, k;
    uint64_t v;
    int rc;
    if ((!in && len) || !used || !err) {
        return BRISK_E_ARG;
    }
    *used = 0;
    *err = 0;
    while (p < len) {
        /* 4.4.1 Section Acknowledgment (1...): we never sent a section with RIC > 0 (MUST be
         * an error). 4.4.3 Insert Count Increment (00...): 0, or more than the 0 inserts we
         * made, MUST be an error - so is any value. Neither needs its integer parsed. */
        if ((in[p] & 0xc0) != 0x40) {
            *err = BRISK__QPACK_DECODER_STREAM_ERROR;
            return BRISK_E_PROTO;
        }
        /* 4.4.2 Stream Cancellation (01 + 6-bit stream id): nothing of ours to release */
        rc = brisk__qpack_int_decode(in + p, len - p, 6, &v, &k);
        if (rc == BRISK_E_WANT) {
            break; /* a partial instruction: the caller keeps it */
        }
        if (rc != BRISK_OK) {
            *err = BRISK__QPACK_DECODER_STREAM_ERROR;
            return BRISK_E_PROTO;
        }
        p += k;
        *used = p;
    }
    return BRISK_OK;
}

#    undef QP_STATIC_N
#    undef QP_MAX

#endif /* BRISK_ENABLE_H3 */
