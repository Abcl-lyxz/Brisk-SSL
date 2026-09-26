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
    int r;
    for (i = 0; i < n; i++) {
        acc |= (uint8_t)(x[i] ^ y[i]);
    }
    /* acc == 0 -> 1, else 0, without a branch */
    r = (int)(1 & ((uint32_t)(acc - 1) >> 8));
    /* The one legitimate declassification: callers branch on "did the tag match", and that answer
     * is public (it is what the peer learns from the alert). Without it every tag check would show
     * up as a secret-dependent branch under `dev.py ct`. */
    BRISK__CT_PUBLIC(&r, sizeof r);
    return r;
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

/* The default time policy says nothing, so the usual image pays no bytes for it; the two that
 * deviate from it say so, because "why does this gateway accept an expired certificate?" is a
 * question that gets asked of a binary nobody has the build flags for any more. */
#if BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_STRICT
#    define BRISK__TIME_NAME " time=strict"
#elif BRISK_X509_TIME_POLICY == BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
#    define BRISK__TIME_NAME " time=INSECURE_NO_TIME"
#else
#    define BRISK__TIME_NAME ""
#endif

/* Every brisk_config.h knob that is on by default in every profile and was turned off, so a
 * firmware that cannot reach an RSA server says why: " -rsa -x25519". Empty by default. */
#if BRISK_ENABLE_AESGCM
#    define BRISK__OFF_AESGCM ""
#else
#    define BRISK__OFF_AESGCM " -aesgcm"
#endif
#if BRISK_ENABLE_AES256
#    define BRISK__OFF_AES256 ""
#else
#    define BRISK__OFF_AES256 " -aes256"
#endif
#if BRISK_ENABLE_CHACHA
#    define BRISK__OFF_CHACHA ""
#else
#    define BRISK__OFF_CHACHA " -chacha"
#endif
#if BRISK_ENABLE_X25519
#    define BRISK__OFF_X25519 ""
#else
#    define BRISK__OFF_X25519 " -x25519"
#endif
#if BRISK_ENABLE_P256_KX
#    define BRISK__OFF_P256_KX ""
#else
#    define BRISK__OFF_P256_KX " -p256_kx"
#endif
#if BRISK_ENABLE_RSA
#    define BRISK__OFF_RSA ""
#else
#    define BRISK__OFF_RSA " -rsa"
#endif
#if BRISK_ENABLE_TICKETS
#    define BRISK__OFF_TICKETS ""
#else
#    define BRISK__OFF_TICKETS " -tickets"
#endif
#if BRISK_ENABLE_PEM
#    define BRISK__OFF_PEM ""
#else
#    define BRISK__OFF_PEM " -pem"
#endif
#if BRISK_ENABLE_SYSTEM_CA
#    define BRISK__OFF_SYSTEM_CA ""
#else
#    define BRISK__OFF_SYSTEM_CA " -system_ca"
#endif
#if BRISK_ENABLE_CUSTOM_IO
#    define BRISK__OFF_CUSTOM_IO ""
#else
#    define BRISK__OFF_CUSTOM_IO " -custom_io"
#endif
#if BRISK_ENABLE_KEYLOG
#    define BRISK__KEYLOG_NAME " KEYLOG" /* every traffic secret can leave through cfg.keylog */
#else
#    define BRISK__KEYLOG_NAME ""
#endif
#define BRISK__OFF_NAMES                                                                           \
    BRISK__OFF_AESGCM BRISK__OFF_AES256 BRISK__OFF_CHACHA BRISK__OFF_X25519 BRISK__OFF_P256_KX     \
        BRISK__OFF_RSA BRISK__OFF_TICKETS BRISK__OFF_PEM BRISK__OFF_SYSTEM_CA BRISK__OFF_CUSTOM_IO

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
        " profile=" BRISK__PROFILE_NAME BRISK__TIME_NAME BRISK__OFF_NAMES BRISK__KEYLOG_NAME
        "\"\n\t.popsection");
#    endif
#endif

BRISK__RETAIN static const char brisk__build_info[] =
    "@(#)BRISKCFG " BRISK_SSL_VERSION_STRING
    " profile=" BRISK__PROFILE_NAME BRISK__TIME_NAME BRISK__OFF_NAMES BRISK__KEYLOG_NAME;
#undef BRISK__RETAIN
#undef BRISK__TIME_NAME
#undef BRISK__OFF_NAMES
#undef BRISK__KEYLOG_NAME
#undef BRISK__OFF_AESGCM
#undef BRISK__OFF_AES256
#undef BRISK__OFF_CHACHA
#undef BRISK__OFF_X25519
#undef BRISK__OFF_P256_KX
#undef BRISK__OFF_RSA
#undef BRISK__OFF_TICKETS
#undef BRISK__OFF_PEM
#undef BRISK__OFF_SYSTEM_CA
#undef BRISK__OFF_CUSTOM_IO

/* brisk_strerror: the name always, the sentence with BRISK_ENABLE_ERROR_STRINGS. Indexed by
 * -err (BRISK_E_ARG = -1 .. BRISK_E_INSECURE = -10). */
#if BRISK_ENABLE_ERROR_STRINGS
#    define BRISK__ERR(name, text) name " (" text ")"
#else
#    define BRISK__ERR(name, text) name
#endif
static const char *const brisk__err_str[] = {
    "ok",
    BRISK__ERR("E_ARG", "bad argument or config"),
    BRISK__ERR("E_RNG", "no kernel randomness"),
    BRISK__ERR("E_AUTH", "server certificate/signature not acceptable"),
    BRISK__ERR("E_PROTO", "server broke the protocol"),
    BRISK__ERR("E_PEER_ALERT", "server sent a fatal alert"),
    BRISK__ERR("E_IO", "network error"),
    BRISK__ERR("E_TIMEOUT", "no progress within the timeout"),
    BRISK__ERR("E_WANT", "sans-I/O: feed more bytes first"),
    BRISK__ERR("E_RETRY", "HTTP/2, HTTP/3: not processed, retry on a new connection"),
    BRISK__ERR("E_INSECURE", "server only offers TLS below the security floor: TLS 1.2 without "
                             "extended master secret / renegotiation_info, or TLS <= 1.1")};
#undef BRISK__ERR

const char *brisk_strerror(int err)
{
    if (err > 0 || err < -(int)(sizeof brisk__err_str / sizeof brisk__err_str[0] - 1)) {
        return "unknown error";
    }
    return brisk__err_str[-err];
}

const char *brisk_version(void)
{
    return BRISK_SSL_VERSION_STRING;
}

const char *brisk_build_info(void)
{
    return brisk__build_info + 13; /* skip "@(#)BRISKCFG " */
}
