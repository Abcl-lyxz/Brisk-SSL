/* fuzz_pem.c - libFuzzer / AFL++ entry point for the streaming PEM reader (src/x509/bundle.c).
 *
 *   python tools/dev.py fuzz pem --seconds 60
 *
 * brisk__x509_pem_feed has no error return - a malformed block is skipped - so the oracle is
 * memory safety, termination and chunking independence. The input's first byte seeds the chunk
 * sizes (1..64); the rest is the bundle text. It is decoded twice: in one call sequence over the
 * whole buffer, and again handed over in those random chunks, the way a file read in pieces
 * arrives. Both must yield the same certificates, byte for byte, in the same order - a reader
 * whose state machine loses a byte at a chunk edge (inside BEGIN, in the middle of a base64
 * quantum, at the END line) only shows up here. Every call must also leave *in / *len inside
 * what it was given, and der_len <= sizeof der.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define OUT_MAX 16384 /* > 8192 * 3 / 4: every certificate an input of -max_len can hold */

static uint8_t whole[OUT_MAX], chunked[OUT_MAX];

/* One call; checks the contract and appends a completed block to out as len(2) | der. */
static int feed(brisk__x509_pem *p, const uint8_t **in, size_t *len, uint8_t *out, size_t *n)
{
    const uint8_t *start = *in;
    size_t before = *len;
    int r = brisk__x509_pem_feed(p, in, len);

    if ((r != 0 && r != 1) || *in < start || *len > before || *in + *len != start + before) {
        abort();
    }
    if (r == 0 && *len != 0) {
        abort(); /* 0 means the input is exhausted */
    }
    if (r == 1) {
        if (p->der_len > sizeof p->der || *n + 2 + p->der_len > OUT_MAX) {
            abort();
        }
        out[(*n)++] = (uint8_t)(p->der_len >> 8);
        out[(*n)++] = (uint8_t)p->der_len;
        memcpy(out + *n, p->der, p->der_len);
        *n += p->der_len;
    }
    return r;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brisk__x509_pem p;
    const uint8_t *in;
    size_t left, nw = 0, nc = 0, off, step;
    uint32_t x;

    if (size == 0) {
        return 0;
    }
    x = data[0] | 0x100u; /* never 0: xorshift32 */
    data++;
    size--;

    brisk__x509_pem_init(&p);
    in = data;
    left = size;
    while (feed(&p, &in, &left, whole, &nw) == 1) {
    }

    brisk__x509_pem_init(&p);
    for (off = 0; off < size; off += step) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        step = 1 + (x & 63);
        if (step > size - off) {
            step = size - off;
        }
        in = data + off;
        left = step;
        while (feed(&p, &in, &left, chunked, &nc) == 1) {
        }
    }
    if (nw != nc || memcmp(whole, chunked, nw) != 0) {
        abort(); /* libFuzzer records it as a crash; __builtin_trap is a GNU extension */
    }
    return 0;
}
