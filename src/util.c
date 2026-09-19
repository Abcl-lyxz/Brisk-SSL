/* util.c - constant-time compare, secure wipe, version/build info.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

int brisk__ct_memeq(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = a, *y = b;
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        acc |= (uint8_t)(x[i] ^ y[i]);
    }
    return (int)(1 & ((uint32_t)(acc - 1) >> 8)); /* acc == 0 -> 1, else 0, without a branch */
}

/* Calling memset through a volatile pointer keeps the compiler from proving the store dead. */
static void *(*const volatile brisk__memset)(void *, int, size_t) = memset;

void brisk__secure_zero(void *p, size_t n)
{
    if (n) {
        brisk__memset(p, 0, n);
    }
}

#if BRISK_PROFILE == BRISK_PROFILE_TINY
#    define BRISK__PROFILE_NAME "TINY"
#elif BRISK_PROFILE == BRISK_PROFILE_DEFAULT
#    define BRISK__PROFILE_NAME "DEFAULT"
#else
#    define BRISK__PROFILE_NAME "FULL"
#endif

/* "@(#)" makes `strings`/`what` find the configuration in a shipped firmware image. */
static const char brisk__build_info[] =
    "@(#)BRISKCFG " BRISK_SSL_VERSION_STRING " profile=" BRISK__PROFILE_NAME;

const char *brisk_version(void)
{
    return BRISK_SSL_VERSION_STRING;
}

const char *brisk_build_info(void)
{
    return brisk__build_info + 13; /* skip "@(#)BRISKCFG " */
}
