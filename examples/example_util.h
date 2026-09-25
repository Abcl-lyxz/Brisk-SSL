/* example_util.h - the bits every example needs and the library deliberately does not do:
 * reading files, and a readable name for an error code.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EXAMPLE_UTIL_H
#define EXAMPLE_UTIL_H

#include <stdio.h>
#include <stdlib.h>

#include "brisk.h"

/* Whole file into a malloc'd buffer; NULL (and a message) on failure. */
static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf = NULL;
    long n;
    if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0 || (buf = malloc((size_t)n + 1)) == NULL ||
        fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "cannot read %s\n", path);
        free(buf);
        buf = NULL;
    } else {
        *len = (size_t)n;
    }
    if (f != NULL) {
        fclose(f);
    }
    return buf;
}

static const char *err_name(int rc)
{
    switch (rc) {
    case BRISK_OK:
        return "ok";
    case BRISK_E_ARG:
        return "E_ARG (bad argument or config)";
    case BRISK_E_RNG:
        return "E_RNG (no kernel randomness)";
    case BRISK_E_AUTH:
        return "E_AUTH (server certificate/signature not acceptable)";
    case BRISK_E_PROTO:
        return "E_PROTO (server broke the protocol)";
    case BRISK_E_PEER_ALERT:
        return "E_PEER_ALERT (server sent a fatal alert)";
    case BRISK_E_IO:
        return "E_IO (network error)";
    case BRISK_E_TIMEOUT:
        return "E_TIMEOUT";
    case BRISK_E_INSECURE:
        return "E_INSECURE (server only offers TLS below the security floor: TLS 1.2 without "
               "extended master secret / renegotiation_info, or TLS <= 1.1)";
    case BRISK_E_RETRY:
        return "E_RETRY (HTTP/2, HTTP/3: not processed, retry on a new connection)";
    default:
        return "unknown error";
    }
}

#endif /* EXAMPLE_UTIL_H */
