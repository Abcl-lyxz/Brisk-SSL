/* fuzz_name.c - libFuzzer / AFL++ entry point for RFC 9525 service identity.
 *
 *   python tools/dev.py fuzz name    # build with clang + ASan/UBSan and run the seeded corpus
 *
 * One blob drives both halves: the first octet says how much of it is the reference identifier
 * and the rest is the GeneralNames CONTENTS a certificate would have carried. Neither is a
 * verdict oracle - a host name either matches or it does not - so what is hunted here is the
 * pointer arithmetic, and there are two places worth the CPU:
 *   - parse_ipv6's "::" expansion, which computes a memmove destination from two lengths the
 *     input chose (the shift and the zero fill have to abut exactly inside 16 octets), and its
 *     dotted-quad tail, which writes 4 more octets at an offset the input chose as well.
 *   - dns_match's wildcard branch, which advances both sides past a label and subtracts the
 *     lengths, i.e. the one place a size_t can go backwards.
 * ASan's redzones do the real work. The SAN blob is fed RAW, exactly as a peer's certificate
 * would carry it and without brisk__der_walk in front of it, which is stricter than production:
 * cert.c walks every extnValue before this module ever sees one.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#include "brisk_int.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brisk__x509_cert c;
    uint8_t ip[16];
    size_t host_len;
    int rc;

    if (size < 1) {
        return 0;
    }
    host_len = data[0] % size;
    data++;
    size--;

    if (brisk__x509_parse_ip((const char *)data, host_len, ip) > 16) {
        abort(); /* libFuzzer records it as a crash; __builtin_trap is a GNU extension */
    }

    memset(&c, 0, sizeof c);
    c.san = data + host_len;
    c.san_len = size - host_len;
    rc = brisk__x509_match_host(&c, (const char *)data, host_len);
    if (rc != BRISK_OK && rc != BRISK_E_AUTH && rc != BRISK_E_ARG) {
        abort();
    }
    return 0;
}
