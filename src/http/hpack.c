/* hpack.c - HTTP/2 header compression, HPACK (RFC 7541): the static table, a decoder with a
 * dynamic table in caller memory, and a deliberately dumb encoder.
 *
 * DECODER. Full RFC 7541: indexed fields, the three literal forms, dynamic table size updates,
 * eviction. The dynamic table is a ring of exactly `limit` caller-supplied octets (our advertised
 * SETTINGS_HEADER_TABLE_SIZE). Each entry is stored as [u16 BE name_len][u16 BE value_len][name]
 * [value], wrapping byte by byte, so it takes n + v + 4 octets against the n + v + 32 that RFC
 * 7541 4.1 accounts: with size <= max <= limit the ring cannot overflow. Every emitted field is
 * copied out of the ring (or the static table, or the block) into the caller's scratch as
 * name || value, so the callback always sees contiguous octets, even for an entry that straddles
 * the ring end. Any decoding error makes the decoder dead for good: RFC 9113 4.3 makes it a
 * connection error, and the table may no longer match the peer's.
 *
 * ENCODER. Never inserts into the peer's table and never Huffman-encodes (RFC 7541 7.1: nothing
 * an attacker could use as a compression oracle, and the least code). A field is an indexed
 * static entry on an exact name+value match, else a literal without indexing (6.2.2) that names
 * the lowest static index with that name; sensitive fields are always never-indexed (6.2.3).
 *
 * Not constant time: header fields are not secrets in this client. Every loop is bounded by the
 * input length, the entry count or a constant; there is no recursion.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_H2

#    include <string.h>

/* RFC 7541 Appendix A, index 1..61: "name\0value\0" per entry. One blob instead of 61 pointer
 * pairs, which would cost 8-16 octets each on 64-bit. Checked byte for byte against the RFC by
 * tools/kat.py (check_hpack_source_constants). */
/* clang-format off */
static const char hpack_static[] =
    ":authority\0" "\0"                    /* 1 */
    ":method\0" "GET\0"                    /* 2 */
    ":method\0" "POST\0"                   /* 3 */
    ":path\0" "/\0"                        /* 4 */
    ":path\0" "/index.html\0"              /* 5 */
    ":scheme\0" "http\0"                   /* 6 */
    ":scheme\0" "https\0"                  /* 7 */
    ":status\0" "200\0"                    /* 8 */
    ":status\0" "204\0"                    /* 9 */
    ":status\0" "206\0"                    /* 10 */
    ":status\0" "304\0"                    /* 11 */
    ":status\0" "400\0"                    /* 12 */
    ":status\0" "404\0"                    /* 13 */
    ":status\0" "500\0"                    /* 14 */
    "accept-charset\0" "\0"                /* 15 */
    "accept-encoding\0" "gzip, deflate\0"  /* 16 */
    "accept-language\0" "\0"               /* 17 */
    "accept-ranges\0" "\0"                 /* 18 */
    "accept\0" "\0"                        /* 19 */
    "access-control-allow-origin\0" "\0"   /* 20 */
    "age\0" "\0"                           /* 21 */
    "allow\0" "\0"                         /* 22 */
    "authorization\0" "\0"                 /* 23 */
    "cache-control\0" "\0"                 /* 24 */
    "content-disposition\0" "\0"           /* 25 */
    "content-encoding\0" "\0"              /* 26 */
    "content-language\0" "\0"              /* 27 */
    "content-length\0" "\0"                /* 28 */
    "content-location\0" "\0"              /* 29 */
    "content-range\0" "\0"                 /* 30 */
    "content-type\0" "\0"                  /* 31 */
    "cookie\0" "\0"                        /* 32 */
    "date\0" "\0"                          /* 33 */
    "etag\0" "\0"                          /* 34 */
    "expect\0" "\0"                        /* 35 */
    "expires\0" "\0"                       /* 36 */
    "from\0" "\0"                          /* 37 */
    "host\0" "\0"                          /* 38 */
    "if-match\0" "\0"                      /* 39 */
    "if-modified-since\0" "\0"             /* 40 */
    "if-none-match\0" "\0"                 /* 41 */
    "if-range\0" "\0"                      /* 42 */
    "if-unmodified-since\0" "\0"           /* 43 */
    "last-modified\0" "\0"                 /* 44 */
    "link\0" "\0"                          /* 45 */
    "location\0" "\0"                      /* 46 */
    "max-forwards\0" "\0"                  /* 47 */
    "proxy-authenticate\0" "\0"            /* 48 */
    "proxy-authorization\0" "\0"           /* 49 */
    "range\0" "\0"                         /* 50 */
    "referer\0" "\0"                       /* 51 */
    "refresh\0" "\0"                       /* 52 */
    "retry-after\0" "\0"                   /* 53 */
    "server\0" "\0"                        /* 54 */
    "set-cookie\0" "\0"                    /* 55 */
    "strict-transport-security\0" "\0"     /* 56 */
    "transfer-encoding\0" "\0"             /* 57 */
    "user-agent\0" "\0"                    /* 58 */
    "vary\0" "\0"                          /* 59 */
    "via\0" "\0"                           /* 60 */
    "www-authenticate\0" "\0";             /* 61 */
/* clang-format on */
#    define BRISK__HPACK_STATIC_N 61u

/* Static entry idx (1..61): name and value inside the blob. */
static void st_get(uint32_t idx, const uint8_t **n, size_t *nl, const uint8_t **v, size_t *vl)
{
    const char *p = hpack_static;
    uint32_t i;
    for (i = 1; i < idx; i++) {
        p += strlen(p) + 1;
        p += strlen(p) + 1;
    }
    *n = (const uint8_t *)p;
    *nl = strlen(p);
    p += *nl + 1;
    *v = (const uint8_t *)p;
    *vl = strlen(p);
}

/* ---------------------------------------------------------------------------------- decoder */

/* Byte-wise ring access: no word loads (MIPS/ARMv5 alignment, either endianness). */
static void ring_put(brisk__hpack_dec *d, uint32_t *pos, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        d->mem[*pos] = src[i];
        if (++*pos == d->limit) {
            *pos = 0;
        }
    }
}

static void ring_get(const brisk__hpack_dec *d, uint32_t *pos, uint8_t *dst, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        dst[i] = d->mem[*pos];
        if (++*pos == d->limit) {
            *pos = 0;
        }
    }
}

/* Entry header at *pos: lengths out, *pos moved past the header. */
static void ring_hdr(const brisk__hpack_dec *d, uint32_t *pos, uint32_t *nl, uint32_t *vl)
{
    uint8_t h[4];
    ring_get(d, pos, h, 4);
    *nl = brisk__load_be16(h);
    *vl = brisk__load_be16(h + 2);
}

static void evict_oldest(brisk__hpack_dec *d)
{
    uint32_t pos = d->head, nl, vl, bytes;
    ring_hdr(d, &pos, &nl, &vl);
    bytes = 4 + nl + vl; /* <= used <= limit, so one subtraction wraps it */
    d->head += bytes;
    if (d->head >= d->limit) {
        d->head -= d->limit;
    }
    d->used -= bytes;
    d->size -= nl + vl + 32;
    if (--d->count == 0) {
        d->head = 0;
    }
}

/* RFC 7541 4.3 / 4.4: evict from the oldest end until size <= room (or the table is empty). */
static void evict_to(brisk__hpack_dec *d, uint32_t room)
{
    while (d->count && d->size > room) {
        evict_oldest(d);
    }
}

/* RFC 7541 4.4. name/value live in the caller's scratch, NOT in the ring: the name may come from
 * the very entry this insert evicts ("the referenced name ... is evicted"), and it was copied out
 * before any eviction, so that case is safe by construction. */
static void insert(brisk__hpack_dec *d, const uint8_t *name, size_t nl, const uint8_t *value,
                   size_t vl)
{
    uint8_t h[4];
    uint32_t pos, esz;
    /* 4.1: size = n + v + 32. 4.4: "an attempt to add an entry larger than the maximum size
     * causes the table to be emptied of all existing entries and results in an empty table" -
     * not an error. nl + vl <= scratch_cap cannot wrap; the +32 is kept out of the compare. */
    if (nl + vl > d->max || d->max - (nl + vl) < 32) {
        evict_to(d, 0);
        return;
    }
    esz = (uint32_t)(nl + vl + 32);
    evict_to(d, d->max - esz);
    /* used + n + v + 4 <= size + esz - 28 <= max <= limit: the entry fits. esz >= 32 also
     * means limit > 0 here, and n, v < 65536 because max <= limit <= 65535. */
    pos = d->head + d->used;
    if (pos >= d->limit) {
        pos -= d->limit;
    }
    brisk__store_be16(h, (uint32_t)nl);
    brisk__store_be16(h + 2, (uint32_t)vl);
    ring_put(d, &pos, h, 4);
    ring_put(d, &pos, name, nl);
    ring_put(d, &pos, value, vl);
    d->used += (uint32_t)(nl + vl + 4);
    d->size += esz;
    d->count++;
}

/* Entry idx (RFC 7541 2.3.3: 1..61 static, 62.. dynamic newest first) copied into dst: the name,
 * plus the value right after it when with_value. BRISK_E_PROTO when idx is 0 or past the end
 * ("MUST be treated as a decoding error") or when it does not fit in cap (a local limit). */
static int get_entry(const brisk__hpack_dec *d, uint32_t idx, uint8_t *dst, size_t cap,
                     int with_value, size_t *nl, size_t *vl)
{
    if (idx == 0) {
        return BRISK_E_PROTO; /* RFC 7541 6.1: "The index value of 0 is not used." */
    }
    if (idx <= BRISK__HPACK_STATIC_N) {
        const uint8_t *n, *v;
        st_get(idx, &n, nl, &v, vl);
        if (*nl > cap || (with_value && *vl > cap - *nl)) {
            return BRISK_E_PROTO;
        }
        memcpy(dst, n, *nl);
        if (with_value) {
            memcpy(dst + *nl, v, *vl);
        }
        return BRISK_OK;
    }
    idx -= BRISK__HPACK_STATIC_N + 1; /* 0 = newest */
    if (idx >= d->count) {
        return BRISK_E_PROTO; /* 2.3.3: "Indices strictly greater than the sum ..." */
    }
    {
        /* Walk from the oldest entry: at most count <= limit / 32 = 2047 steps.
         * ponytail: linear walk; add an offset index only if profiling shows it. */
        uint32_t pos = d->head, k, n32, v32, skip = d->count - 1 - idx;
        for (k = 0; k < skip; k++) {
            ring_hdr(d, &pos, &n32, &v32);
            pos += n32 + v32;
            if (pos >= d->limit) {
                pos -= d->limit;
            }
        }
        ring_hdr(d, &pos, &n32, &v32);
        if (n32 > cap || (with_value && v32 > cap - n32)) {
            return BRISK_E_PROTO;
        }
        ring_get(d, &pos, dst, n32);
        *nl = n32;
        *vl = v32;
        if (with_value) {
            ring_get(d, &pos, dst + n32, v32);
        }
    }
    return BRISK_OK;
}

/* RFC 7541 5.2 string literal at blk[*p]: H bit + 7-bit-prefix length + octets, decoded into
 * dst (at most cap). *p moves past it. */
static int get_string(const uint8_t *blk, size_t len, size_t *p, uint8_t *dst, size_t cap,
                      size_t *out)
{
    uint32_t sl;
    size_t used, start = *p;
    if (brisk__hpack_int_decode(blk + start, len - start, 7, &sl, &used) != BRISK_OK) {
        return BRISK_E_PROTO;
    }
    *p += used;
    if (sl > len - *p) {
        return BRISK_E_PROTO; /* the string runs past the block */
    }
    if (blk[start] & 0x80) {
        if (brisk__huff_decode(blk + *p, sl, dst, cap, out) != BRISK_OK) {
            return BRISK_E_PROTO;
        }
    } else {
        if (sl > cap) {
            return BRISK_E_PROTO;
        }
        memcpy(dst, blk + *p, sl);
        *out = sl;
    }
    *p += sl;
    return BRISK_OK;
}

int brisk__hpack_dec_init(brisk__hpack_dec *d, uint8_t *mem, size_t limit)
{
    if (!d || limit > 65535 || (!mem && limit)) {
        return BRISK_E_ARG;
    }
    memset(d, 0, sizeof *d);
    d->mem = mem;
    d->limit = (uint32_t)limit;
    /* RFC 9113 4.3.1: the peer's encoder starts at 4096. If we advertise less, its first field
     * block after acknowledging our SETTINGS must open with a size update (need_update); until
     * then we hold it to our limit, which the ring can take. Above 4096 it starts at 4096 and
     * must signal any growth with a size update (RFC 7541 4.2). */
    d->max = d->limit < 4096 ? d->limit : 4096;
    d->need_update = d->limit < 4096;
    return BRISK_OK;
}

int brisk__hpack_decode(brisk__hpack_dec *d, const uint8_t *blk, size_t len, uint8_t *scratch,
                        size_t scratch_cap, size_t max_list, brisk__hpack_field_fn fn, void *ctx)
{
    size_t p = 0, list = 0, used, nl, vl;
    uint32_t idx;
    int seen = 0, rc;

    if (!d || (!blk && len) || !scratch || !fn) {
        return BRISK_E_ARG;
    }
    if (d->dead) {
        return BRISK_E_PROTO; /* RFC 9113 4.3: the connection is already in error */
    }
    while (p < len) {
        uint8_t b = blk[p];
        unsigned flags = 0;
        int ins = 0;
        if ((b & 0xe0) == 0x20) {
            /* RFC 7541 6.3 Dynamic Table Size Update. 4.2: it "MUST occur at the beginning of the
             * first header block following the change"; we accept it only before the first field
             * representation of a block and fail closed after one (as nghttp2 does). */
            if (seen || brisk__hpack_int_decode(blk + p, len - p, 5, &idx, &used) != BRISK_OK) {
                goto fail;
            }
            /* 6.3: "The new maximum size MUST be lower than or equal to the limit ... A value
             * that exceeds this limit MUST be treated as a decoding error." */
            if (idx > d->limit) {
                goto fail;
            }
            p += used;
            d->max = idx;
            evict_to(d, d->max); /* 4.3 */
            d->need_update = 0;
            continue;
        }
        /* RFC 9113 4.3.1: "An endpoint MUST treat a field block that follows an acknowledgment of
         * the reduction to the maximum dynamic table size as a connection error ... if it does
         * not start with a conformant Dynamic Table Size Update instruction." */
        if (d->need_update) {
            goto fail;
        }
        seen = 1;
        if (b & 0x80) {
            /* 6.1 Indexed Header Field */
            if (brisk__hpack_int_decode(blk + p, len - p, 7, &idx, &used) != BRISK_OK) {
                goto fail;
            }
            p += used;
            if (get_entry(d, idx, scratch, scratch_cap, 1, &nl, &vl) != BRISK_OK) {
                goto fail;
            }
        } else {
            /* 6.2.1 '01' incremental (6-bit), 6.2.2 '0000' without, 6.2.3 '0001' never (4-bit) */
            unsigned n = 4;
            if (b & 0x40) {
                n = 6;
                ins = 1;
            } else if (b & 0x10) {
                flags = BRISK__HPACK_NEVER_INDEXED; /* line 2 must honour 7.1.3 on re-encode */
            }
            if (brisk__hpack_int_decode(blk + p, len - p, n, &idx, &used) != BRISK_OK) {
                goto fail;
            }
            p += used;
            if (idx) { /* indexed name; out of range is a decoding error (2.3.3) */
                if (get_entry(d, idx, scratch, scratch_cap, 0, &nl, &vl) != BRISK_OK) {
                    goto fail;
                }
            } else if (get_string(blk, len, &p, scratch, scratch_cap, &nl) != BRISK_OK) {
                goto fail;
            }
            if (get_string(blk, len, &p, scratch + nl, scratch_cap - nl, &vl) != BRISK_OK) {
                goto fail;
            }
        }
        /* RFC 9113 6.5.2 SETTINGS_MAX_HEADER_LIST_SIZE: uncompressed n + v + 32 per field. Also
         * the bound on amplification (RFC 7541 7.3): a 1-octet reference to a 4 KB entry costs
         * at most max_list of output per block. Exceeding it is OUR limit, not an RFC rule, but
         * it cannot be a stream-level skip: RFC 9113 4.3 needs every block decoded to keep the
         * table in sync, so stopping here is a connection error (fail closed). Same for a field
         * larger than scratch_cap above. */
        if (nl + vl > max_list || max_list - (nl + vl) < 32 || list > max_list - (nl + vl) - 32) {
            goto fail;
        }
        list += nl + vl + 32;
        rc = fn(ctx, scratch, nl, scratch + nl, vl, flags);
        if (rc != 0) {
            d->dead = 1; /* the rest of the block was not decoded: the table is out of sync */
            return rc;
        }
        if (ins) {
            insert(d, scratch, nl, scratch + nl, vl); /* 6.2.1: emitted, then added */
        }
    }
    if (d->need_update) {
        goto fail; /* RFC 9113 4.3.1: an empty block does not start with the update either */
    }
    return BRISK_OK;
fail:
    d->dead = 1;
    return BRISK_E_PROTO;
}

/* ---------------------------------------------------------------------------------- encoder */

void brisk__hpack_enc_init(brisk__hpack_enc *e)
{
    e->cur = 4096; /* RFC 9113 4.3.1: the peer's decoder starts at 4096 */
    e->pending = 0;
}

void brisk__hpack_enc_peer_max(brisk__hpack_enc *e, uint32_t v)
{
    /* RFC 7541 4.2 / RFC 9113 4.3.1: a reduction below what the peer's decoder believes we use
     * must be acknowledged by a size update at the start of our next block. We never index, so
     * we simply drop to 0 once - 0 is within any limit - and never have to signal again. */
    if (v < e->cur) {
        e->pending = 1;
        e->cur = 0;
    }
}

/* RFC 7541 5.1, minimal. -1 when out has no room. */
static int put_int(uint8_t *out, size_t cap, size_t *pos, unsigned flags, unsigned n, size_t v)
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
    for (;;) { /* at most 10 rounds for a 64-bit v */
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

/* RFC 7541 5.2 with H = 0, always. */
static int put_str(uint8_t *out, size_t cap, size_t *pos, const uint8_t *s, size_t n)
{
    if (put_int(out, cap, pos, 0, 7, n) || n > cap - *pos) {
        return -1;
    }
    if (n) {
        memcpy(out + *pos, s, n);
    }
    *pos += n;
    return 0;
}

/* RFC 9113 8.2.1: what a well-formed message may carry. The encoder refuses the rest rather than
 * sending it; h2.c applies the same rule to received fields. */
int brisk__hpack_field_ok(const uint8_t *name, size_t nl, const uint8_t *value, size_t vl)
{
    size_t i;
    if (!name || nl == 0 || (!value && vl)) {
        return 0;
    }
    for (i = 0; i < nl; i++) {
        uint8_t c = name[i];
        /* "A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or
         * 0x7f-0xff"; ':' only as the first octet, i.e. a pseudo-header (8.3) */
        if (c <= 0x20 || (c >= 0x41 && c <= 0x5a) || c >= 0x7f || (c == ':' && i > 0)) {
            return 0;
        }
    }
    for (i = 0; i < vl; i++) {
        uint8_t c = value[i];
        if (c == 0x00 || c == 0x0a || c == 0x0d) { /* "MUST NOT contain a zero value, LF or CR" */
            return 0;
        }
    }
    if (vl) { /* "MUST NOT start or end with an ASCII whitespace character" (SP, HTAB) */
        uint8_t a = value[0], z = value[vl - 1];
        if (a == 0x20 || a == 0x09 || z == 0x20 || z == 0x09) {
            return 0;
        }
    }
    return 1;
}

int brisk__hpack_encode(brisk__hpack_enc *e, const brisk__hpack_field *f, size_t n, uint8_t *out,
                        size_t cap, size_t *out_len)
{
    size_t pos = 0, i;
    if (!out_len) {
        return BRISK_E_ARG;
    }
    *out_len = 0;
    if (!e || (!f && n) || (!out && cap)) {
        return BRISK_E_ARG;
    }
    for (i = 0; i < n; i++) { /* validate everything first: a failed call emits nothing */
        if (!brisk__hpack_field_ok(f[i].name, f[i].name_len, f[i].value, f[i].value_len)) {
            return BRISK_E_ARG;
        }
    }
    if (e->pending && put_int(out, cap, &pos, 0x20, 5, 0)) { /* 6.3: size update to 0 */
        return BRISK_E_ARG;
    }
    for (i = 0; i < n; i++) {
        uint32_t k, exact = 0, name = 0;
        int never = (f[i].flags & BRISK__HPACK_NEVER_INDEXED) != 0;
        for (k = 1; k <= BRISK__HPACK_STATIC_N; k++) {
            const uint8_t *sn, *sv;
            size_t snl, svl;
            st_get(k, &sn, &snl, &sv, &svl);
            if (snl == f[i].name_len && memcmp(sn, f[i].name, snl) == 0) {
                if (!name) {
                    name = k;
                }
                if (!exact && svl == f[i].value_len &&
                    (svl == 0 || memcmp(sv, f[i].value, svl) == 0)) {
                    exact = k;
                }
            }
        }
        if (exact && !never) {
            if (put_int(out, cap, &pos, 0x80, 7, exact)) { /* 6.1 */
                return BRISK_E_ARG;
            }
            continue;
        }
        /* 6.2.3 never indexed ('0001') for sensitive fields, else 6.2.2 without ('0000') */
        if (put_int(out, cap, &pos, never ? 0x10 : 0x00, 4, name) ||
            (!name && put_str(out, cap, &pos, f[i].name, f[i].name_len)) ||
            put_str(out, cap, &pos, f[i].value, f[i].value_len)) {
            return BRISK_E_ARG;
        }
    }
    e->pending = 0;
    *out_len = pos;
    return BRISK_OK;
}

#    undef BRISK__HPACK_STATIC_N

#endif /* BRISK_ENABLE_H2 */
