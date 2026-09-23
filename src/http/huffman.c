/* huffman.c - the HPACK prefixed integer (RFC 7541 5.1) and the HPACK Huffman decoder
 * (RFC 7541 5.2 + Appendix B). Both are shared with QPACK in M7: RFC 9204 4.1.1 cites 7541 5.1
 * for its integers and 4.1.2 uses the same Huffman code.
 *
 * The Huffman code is canonical (tools/kat.py asserts it against the RFC text): within each code
 * length the codes are consecutive, so a decoder needs only how many codes each length has and
 * the symbols in code order - 31 + 256 octets of rodata instead of a ~12 KB state machine. It
 * walks one bit at a time, which is slower than a table walk; header blocks on an IoT client are
 * small, and the size matters more. Not constant time: header fields are not secrets here.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#if BRISK_ENABLE_H2

int brisk__hpack_int_decode(const uint8_t *p, size_t len, unsigned n, uint32_t *v, size_t *used)
{
    uint32_t mask, val, chunk;
    unsigned shift;
    size_t i;

    if (!p || !v || !used || n < 1 || n > 8) {
        return BRISK_E_ARG;
    }
    if (len == 0) {
        return BRISK_E_PROTO;
    }
    mask = (1u << n) - 1u; /* the flag bits above the prefix are the caller's business */
    val = p[0] & mask;
    if (val < mask) {
        *v = val;
        *used = 1;
        return BRISK_OK;
    }
    /* RFC 7541 5.1: "Integer encodings that exceed implementation limits -- in value or octet
     * length -- MUST be treated as decoding errors." Our limit is 2^32-1, which never needs more
     * than 5 continuation octets; a 6th is refused even when its value would fit (zero-valued
     * redundant octets are legal only within those 5). */
    for (i = 1, shift = 0; i <= 5; i++, shift += 7) {
        if (i >= len) {
            return BRISK_E_PROTO; /* truncated: input ends while the continuation bit is set */
        }
        chunk = p[i] & 0x7fu;
        /* overflow checks BEFORE the shift and the add, so nothing wraps */
        if (shift == 28 && chunk > 0xfu) {
            return BRISK_E_PROTO;
        }
        chunk <<= shift;
        if (chunk > 0xffffffffu - val) {
            return BRISK_E_PROTO;
        }
        val += chunk;
        if (!(p[i] & 0x80)) {
            *v = val;
            *used = i + 1;
            return BRISK_OK;
        }
    }
    return BRISK_E_PROTO; /* a 6th continuation octet */
}

/* RFC 7541 Appendix B, canonical form: huff_count[L] = number of codes of L bits (EOS is one of
 * the four 30-bit codes and the very last code), huff_sym = the 256 octet symbols in code order.
 * Checked byte for byte against the RFC by tools/kat.py (check_hpack_source_constants). */
static const uint8_t huff_count[31] = {0, 0, 0, 0, 0, 10, 26, 32, 6,  0, 5,  3,  2,  6, 2, 3,
                                       0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4};
static const uint8_t huff_sym[256] = {
    0x30, 0x31, 0x32, 0x61, 0x63, 0x65, 0x69, 0x6f, 0x73, 0x74, 0x20, 0x25, 0x2d, 0x2e, 0x2f, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3d, 0x41, 0x5f, 0x62, 0x64, 0x66, 0x67, 0x68, 0x6c, 0x6d,
    0x6e, 0x70, 0x72, 0x75, 0x3a, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
    0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x59, 0x6a, 0x6b, 0x71, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x26, 0x2a, 0x2c, 0x3b, 0x58, 0x5a, 0x21, 0x22, 0x28, 0x29, 0x3f, 0x27,
    0x2b, 0x7c, 0x23, 0x3e, 0x00, 0x24, 0x40, 0x5b, 0x5d, 0x7e, 0x5e, 0x7d, 0x3c, 0x60, 0x7b, 0x5c,
    0xc3, 0xd0, 0x80, 0x82, 0x83, 0xa2, 0xb8, 0xc2, 0xe0, 0xe2, 0x99, 0xa1, 0xa7, 0xac, 0xb0, 0xb1,
    0xb3, 0xd1, 0xd8, 0xd9, 0xe3, 0xe5, 0xe6, 0x81, 0x84, 0x85, 0x86, 0x88, 0x92, 0x9a, 0x9c, 0xa0,
    0xa3, 0xa4, 0xa9, 0xaa, 0xad, 0xb2, 0xb5, 0xb9, 0xba, 0xbb, 0xbd, 0xbe, 0xc4, 0xc6, 0xe4, 0xe8,
    0xe9, 0x01, 0x87, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8f, 0x93, 0x95, 0x96, 0x97, 0x98, 0x9b, 0x9d,
    0x9e, 0xa5, 0xa6, 0xa8, 0xae, 0xaf, 0xb4, 0xb6, 0xb7, 0xbc, 0xbf, 0xc5, 0xe7, 0xef, 0x09, 0x8e,
    0x90, 0x91, 0x94, 0x9f, 0xab, 0xce, 0xd7, 0xe1, 0xec, 0xed, 0xc7, 0xcf, 0xea, 0xeb, 0xc0, 0xc1,
    0xc8, 0xc9, 0xca, 0xcd, 0xd2, 0xd5, 0xda, 0xdb, 0xee, 0xf0, 0xf2, 0xf3, 0xff, 0xcb, 0xcc, 0xd3,
    0xd4, 0xd6, 0xdd, 0xde, 0xdf, 0xf1, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x7f, 0xdc, 0xf9, 0x0a, 0x0d, 0x16,
};

int brisk__huff_decode(const uint8_t *in, size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
    /* Canonical decode: after L bits, the codes of length L are first .. first + count - 1, and
     * their symbols start at huff_sym[index]. `code` and `first` stay below 2^30. */
    uint32_t code = 0, first = 0, index = 0, ones = 1;
    unsigned bits = 0; /* bits of the current, unfinished code */
    size_t i, n = 0;
    int b;

    if ((!in && len) || (!out && cap) || !out_len) {
        return BRISK_E_ARG;
    }
    *out_len = 0;
    for (i = 0; i < len; i++) {
        for (b = 7; b >= 0; b--) {
            uint32_t bit = (uint32_t)(in[i] >> b) & 1u;
            code |= bit;
            ones &= bit;
            bits++;
            if (code - first < huff_count[bits]) { /* unsigned: also false when code < first */
                index += code - first;
                if (index == 256) {
                    /* RFC 7541 5.2: "A Huffman-encoded string literal containing the EOS symbol
                     * MUST be treated as a decoding error." */
                    return BRISK_E_PROTO;
                }
                if (n == cap) {
                    return BRISK_E_PROTO; /* local limit: the caller's buffer */
                }
                out[n++] = huff_sym[index];
                code = first = index = 0;
                bits = 0;
                ones = 1;
                continue;
            }
            index += huff_count[bits];
            first = (first + huff_count[bits]) << 1;
            code <<= 1;
            /* bits reaches 30 only on the four 30-bit codes, which the test above always takes
             * (the code is complete), so `bits` never indexes past huff_count[30]. */
        }
    }
    /* RFC 7541 5.2: "A padding strictly longer than 7 bits MUST be treated as a decoding error.
     * A padding not corresponding to the most significant bits of the code for the EOS symbol
     * MUST be treated as a decoding error." EOS is 30 one bits, so both reduce to: fewer than 8
     * leftover bits, all of them ones. */
    if (bits > 7 || !ones) {
        return BRISK_E_PROTO;
    }
    *out_len = n;
    return BRISK_OK;
}

#endif /* BRISK_ENABLE_H2 */
