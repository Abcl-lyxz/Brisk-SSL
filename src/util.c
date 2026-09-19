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

/* "@(#)" makes `strings`/`what` find the configuration in a shipped firmware image. The consumer
 * links with --gc-sections, which would drop the string unless brisk_build_info() is called, so:
 * `retain` (GCC >= 11, Clang >= 13, binutils >= 2.36) keeps it in .rodata, and on older ELF
 * toolchains a copy goes into .comment, which gc-sections never discards. */
#if defined(__has_attribute)
#    if __has_attribute(retain)
#        define BRISK__RETAIN __attribute__((used, retain))
#    endif
#endif
#ifndef BRISK__RETAIN
#    define BRISK__RETAIN
#    if defined(__ELF__)
__asm__(".pushsection .comment\n\t.asciz \"@(#)BRISKCFG " BRISK_SSL_VERSION_STRING
        " profile=" BRISK__PROFILE_NAME "\"\n\t.popsection");
#    endif
#endif

BRISK__RETAIN static const char brisk__build_info[] =
    "@(#)BRISKCFG " BRISK_SSL_VERSION_STRING " profile=" BRISK__PROFILE_NAME;
#undef BRISK__RETAIN

const char *brisk_version(void)
{
    return BRISK_SSL_VERSION_STRING;
}

const char *brisk_build_info(void)
{
    return brisk__build_info + 13; /* skip "@(#)BRISKCFG " */
}
