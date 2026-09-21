/* der.c - strict DER reader. The rules it enforces, with their X.690 clauses, and every
 * function's contract, are documented in the brisk__der block of src/brisk_int.h.
 *
 * Roughly 30 lines of it are the only thing standing between a hostile certificate and the rest
 * of the library, so the shape is deliberately dull: one header decoder, one content-rules
 * table, and thin typed wrappers over both. There is no state beyond the two pointers.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

int brisk__der_fail(brisk__der *c)
{
    c->err = BRISK_E_ARG;
    return BRISK_E_ARG;
}

int brisk__der_end(brisk__der *c)
{
    if (c->err == BRISK_OK && c->p != c->end) {
        return brisk__der_fail(c);
    }
    return c->err;
}

/* One identifier octet plus its length (X.690 8.1). On success c->p points at the contents and
 * *len is their length, already checked to lie inside the value; on failure the cursor is
 * marked failed and left where it was. */
static int der_hdr(brisk__der *c, unsigned *tag, size_t *len)
{
    const uint8_t *p = c->p;
    uint32_t l;
    unsigned b, n, i;

    *tag = 0;
    *len = 0;
    if (c->err != BRISK_OK) {
        return c->err;
    }
    if ((size_t)(c->end - p) < 2u) { /* identifier + at least one length octet */
        return brisk__der_fail(c);
    }
    *tag = *p++;
    if ((*tag & 0x1fu) == 0x1fu) { /* 8.1.2.4 high-tag-number form: no X.509 field uses it */
        return brisk__der_fail(c);
    }
    b = *p++;
    if (b < 0x80u) {
        l = b;
    } else {
        n = b & 0x7fu;
        /* n == 0 is the indefinite form (8.1.3.6), which 10.1 forbids in DER; n == 0x7f is
         * reserved (8.1.3.5 c); anything above 4 describes more bytes than a 32-bit size_t can
         * address, so refusing it here keeps the bounds check below free of overflow. */
        if (n == 0 || n > 4u) {
            return brisk__der_fail(c);
        }
        if ((size_t)(c->end - p) < n) {
            return brisk__der_fail(c);
        }
        if (p[0] == 0) { /* 10.1: the minimum number of octets */
            return brisk__der_fail(c);
        }
        l = 0;
        for (i = 0; i < n; i++) {
            l = (l << 8) | p[i];
        }
        p += n;
        if (l < 0x80u) { /* 10.1: the short form was available and is therefore required */
            return brisk__der_fail(c);
        }
    }
    if ((size_t)l > (size_t)(c->end - p)) {
        return brisk__der_fail(c);
    }
    c->p = p;
    *len = (size_t)l;
    return BRISK_OK;
}

/* The DER content rules of the universal primitive types X.509 uses. 1 = legal. Types not
 * listed - the string and time types, and everything context-specific, whose real type implicit
 * tagging has erased - carry no rule at this layer: their contents are checked by whoever
 * interprets them. */
static int der_leaf_ok(unsigned tag, const uint8_t *v, size_t len)
{
    size_t i;
    int starts; /* the next octet starts a subidentifier (OID only) */

    switch (tag) {
    /* 8.2.1 gives BOOLEAN exactly one contents octet and 8.2.2 makes FALSE all-zero; 11.1
     * then pins TRUE to all-ones, so BER's "any non-zero is true" does not survive into DER. */
    case BRISK__DER_BOOLEAN:
        return len == 1 && (v[0] == 0x00 || v[0] == 0xff);
    /* 8.4: an ENUMERATED is encoded as the INTEGER it stands for, so both rules below apply
     * to it unchanged - RFC 5280 5.3.1 CRLReason is where X.509 uses one. */
    case BRISK__DER_INTEGER:
    case BRISK__DER_ENUMERATED:
        if (len == 0) { /* 8.3.1: one or more contents octets */
            return 0;
        }
        /* 8.3.2: never nine leading zero bits, never nine leading ones */
        return !(len >= 2 &&
                 ((v[0] == 0x00 && (v[1] & 0x80u) == 0) || (v[0] == 0xff && (v[1] & 0x80u) != 0)));
    case BRISK__DER_BIT_STRING:
        /* 8.6.2.1 always puts the unused-bit count there; 8.6.2.2 bounds it to 0..7. */
        if (len == 0 || v[0] > 7) {
            return 0;
        }
        if (len == 1) { /* 8.6.2.3: no bits means no unused bits */
            return v[0] == 0;
        }
        return (v[len - 1] & ((1u << v[0]) - 1u)) == 0; /* 11.2.1: the unused bits are zero */
    case BRISK__DER_NULL:
        return len == 0; /* 8.8.2 */
    /* The mirror of the constructed-form check in brisk__der_walk: these universal types can
     * never be primitive, and a primitive value never reaches that branch, so they have to be
     * refused here. 0x10 and 0x11 are SEQUENCE and SET without the constructed bit. */
    case 0x00: /* 8.1.2.2 table 1: tag 0 is reserved - it is BER's end-of-contents marker */
    case 0x10: /* 8.9.1: "The encoding of a sequence value shall be constructed." */
    case 0x11: /* 8.10.1: and so shall a set's */
        return 0;
    case BRISK__DER_OID:
        if (len == 0) {
            return 0;
        }
        starts = 1;
        for (i = 0; i < len; i++) {
            if (starts && v[i] == 0x80) { /* 8.19.2: a subidentifier has no leading zero bits */
                return 0;
            }
            starts = (v[i] & 0x80u) == 0;
        }
        return starts; /* and the last one has to be terminated */
    default:
        return 1;
    }
}

int brisk__der_enter(brisk__der *c, unsigned tag, brisk__der *body)
{
    unsigned got;
    size_t n;

    body->p = body->end = NULL;
    body->depth = 0;
    body->err = BRISK_E_ARG; /* fails closed if the caller never checks our status */
    if (c->depth >= BRISK__DER_MAX_DEPTH) {
        return brisk__der_fail(c);
    }
    if (der_hdr(c, &got, &n) != BRISK_OK) {
        return c->err;
    }
    if (got != tag || (got & (unsigned)BRISK__DER_CONSTRUCTED) == 0) {
        return brisk__der_fail(c);
    }
    body->p = c->p;
    body->end = c->p + n;
    body->depth = c->depth + 1;
    body->err = BRISK_OK;
    c->p += n; /* the parent skips the whole child, read or not */
    return BRISK_OK;
}

int brisk__der_close(brisk__der *c, brisk__der *body)
{
    if (brisk__der_end(body) != BRISK_OK && c->err == BRISK_OK) {
        c->err = body->err;
    }
    return c->err;
}

int brisk__der_value(brisk__der *c, unsigned tag, const uint8_t **v, size_t *len)
{
    const uint8_t *body;
    unsigned got;
    size_t n;

    *v = NULL;
    *len = 0;
    if (der_hdr(c, &got, &n) != BRISK_OK) {
        return c->err;
    }
    body = c->p;
    if (got != tag || !der_leaf_ok(got, body, n)) {
        return brisk__der_fail(c);
    }
    c->p = body + n;
    *v = body;
    *len = n;
    return BRISK_OK;
}

int brisk__der_tlv(brisk__der *c, const uint8_t **tlv, size_t *len)
{
    const uint8_t *start = c->p;
    unsigned tag;
    size_t n;

    *tlv = NULL;
    *len = 0;
    if (der_hdr(c, &tag, &n) != BRISK_OK) {
        return c->err;
    }
    c->p += n;
    *tlv = start;
    *len = (size_t)(c->p - start);
    return BRISK_OK;
}

int brisk__der_skip(brisk__der *c)
{
    const uint8_t *tlv;
    size_t n;
    return brisk__der_tlv(c, &tlv, &n);
}

int brisk__der_bool(brisk__der *c, int *out)
{
    const uint8_t *v;
    size_t n;

    *out = 0;
    if (brisk__der_value(c, BRISK__DER_BOOLEAN, &v, &n) != BRISK_OK) {
        return c->err;
    }
    *out = v[0] != 0;
    return BRISK_OK;
}

int brisk__der_null(brisk__der *c)
{
    const uint8_t *v;
    size_t n;
    return brisk__der_value(c, BRISK__DER_NULL, &v, &n);
}

int brisk__der_oid(brisk__der *c, const uint8_t **v, size_t *len)
{
    return brisk__der_value(c, BRISK__DER_OID, v, len);
}

int brisk__der_int(brisk__der *c, const uint8_t **v, size_t *len)
{
    return brisk__der_value(c, BRISK__DER_INTEGER, v, len);
}

int brisk__der_unsigned(brisk__der *c, const uint8_t **v, size_t *len)
{
    if (brisk__der_int(c, v, len) != BRISK_OK) {
        return c->err;
    }
    if ((*v)[0] & 0x80u) { /* negative: no field this reader feeds accepts one */
        *v = NULL;
        *len = 0;
        return brisk__der_fail(c);
    }
    /* Drop the 0x00 that 8.3.3's two's-complement encoding forces onto a positive value whose
     * top bit is set. What is left is minimal already, because der_leaf_ok applied 8.3.2. */
    if (*len > 1 && (*v)[0] == 0x00) {
        (*v)++;
        (*len)--;
    }
    return BRISK_OK;
}

int brisk__der_uint(brisk__der *c, uint32_t *out)
{
    const uint8_t *v;
    size_t n, i;

    *out = 0;
    if (brisk__der_unsigned(c, &v, &n) != BRISK_OK) {
        return c->err;
    }
    if (n > 4u) {
        return brisk__der_fail(c);
    }
    for (i = 0; i < n; i++) {
        *out = (*out << 8) | v[i];
    }
    return BRISK_OK;
}

int brisk__der_bitstring(brisk__der *c, const uint8_t **v, size_t *len, unsigned *unused)
{
    const uint8_t *raw;
    size_t n;

    *v = NULL;
    *len = 0;
    *unused = 0;
    if (brisk__der_value(c, BRISK__DER_BIT_STRING, &raw, &n) != BRISK_OK) {
        return c->err;
    }
    *unused = raw[0]; /* der_leaf_ok has already bounded it to 0..7 and n to >= 1 */
    *v = raw + 1;
    *len = n - 1;
    return BRISK_OK;
}

int brisk__der_walk(const uint8_t *der, size_t len)
{
    /* The end of every constructed value we are inside. Depth is bounded here rather than by
     * the C stack: the recursive version of this loop is one hostile certificate away from a
     * stack overflow on a 4 KB IoT thread. */
    const uint8_t *stack[BRISK__DER_MAX_DEPTH];
    size_t depth = 0;
    brisk__der c;

    brisk__der_init(&c, der, len);
    for (;;) {
        const uint8_t *body;
        unsigned tag;
        size_t n;

        if (der_hdr(&c, &tag, &n) != BRISK_OK) {
            return c.err;
        }
        body = c.p;
        if (tag & (unsigned)BRISK__DER_CONSTRUCTED) {
            /* SEQUENCE and SET are the only universal types that may be constructed. For the
             * string types that is 10.2; the rest (BOOLEAN, INTEGER, ENUMERATED, NULL, OID) are
             * primitive-only in BER already, by 8.2.1, 8.3.1, 8.4, 8.8.1 and 8.19.1. Either way
             * a constructed one is the classic BER length-hiding trick. */
            if ((tag & 0xc0u) == 0 && tag != (unsigned)BRISK__DER_SEQUENCE &&
                tag != (unsigned)BRISK__DER_SET) {
                return brisk__der_fail(&c);
            }
            if (depth == BRISK__DER_MAX_DEPTH) {
                return brisk__der_fail(&c);
            }
            stack[depth++] = c.end;
            c.end = body + n; /* c.p is already at the first child */
        } else {
            if (!der_leaf_ok(tag, body, n)) {
                return brisk__der_fail(&c);
            }
            c.p = body + n;
        }
        while (c.p == c.end) {
            if (depth == 0) {
                return BRISK_OK;
            }
            c.end = stack[--depth];
        }
        if (depth == 0) { /* a second top-level value: one blob holds one value */
            return brisk__der_fail(&c);
        }
    }
}
