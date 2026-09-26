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

#endif /* EXAMPLE_UTIL_H */
