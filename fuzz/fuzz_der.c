/* fuzz_der.c - libFuzzer / AFL++ entry point for the strict DER reader.
 *
 *   python tools/dev.py fuzz          # build with clang + ASan/UBSan and run the seeded corpus
 *
 * brisk__der_walk is total: every input is either BRISK_OK or BRISK_E_ARG, so the oracle here
 * is not a verdict but memory safety and termination. What is being hunted is a read past the
 * buffer on a truncated length, a loop that never advances, and a stack overflow from nesting -
 * which is why the walk carries its own end stack instead of recursing. ASan's redzones do the
 * real work; never build this without -fsanitize=address.
 *
 * The second half is a differential check between the two ways this module is used: whatever
 * the whole-value walk accepts, the cursor API must accept as one TLV of exactly the same
 * length. A parser built on the cursor relies on that, and only a fuzzer will find the input
 * where the two disagree.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brisk__der c;
    const uint8_t *tlv;
    size_t n;
    int rc = brisk__der_walk(data, size);

    if (rc != BRISK_OK && rc != BRISK_E_ARG) {
        abort(); /* libFuzzer records it as a crash; __builtin_trap is a GNU extension */
    }
    if (rc != BRISK_OK) {
        return 0;
    }
    brisk__der_init(&c, data, size);
    if (brisk__der_tlv(&c, &tlv, &n) != BRISK_OK || tlv != data || n != size ||
        brisk__der_end(&c) != BRISK_OK) {
        abort(); /* libFuzzer records it as a crash; __builtin_trap is a GNU extension */
    }
    return 0;
}
