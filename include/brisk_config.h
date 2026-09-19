/* brisk_config.h - the ONLY Brisk-SSL configuration file.
 *
 * Most users set nothing. Pick a profile and/or override single features on the compiler
 * command line (or put them in your own header and pass -DBRISK_USER_CONFIG='"my_brisk.h"'):
 *
 *   -DBRISK_PROFILE=BRISK_PROFILE_TINY      TLS 1.3 only, smallest binary
 *   -DBRISK_PROFILE=BRISK_PROFILE_DEFAULT   + TLS 1.2, HTTP/2, mTLS                 (default)
 *   -DBRISK_PROFILE=BRISK_PROFILE_FULL      + QUIC, HTTP/3
 *   -DBRISK_ENABLE_<FEATURE>=0|1            force one feature on/off
 *
 * Feature knobs are tri-state: undefined = decided by the profile and by what other features need;
 * 0/1 = your explicit choice, never overridden. Anything the library needs is switched on
 * automatically; an impossible combination fails with an #error that says how to fix it.
 * docs/CONFIG.md lists what every knob costs in KB per CPU architecture.
 *
 * Public struct sizes never depend on this file, so a library and an application built with
 * different settings still agree on the ABI.
 */
#ifndef BRISK_CONFIG_H
#define BRISK_CONFIG_H

#define BRISK_PROFILE_TINY    1
#define BRISK_PROFILE_DEFAULT 2
#define BRISK_PROFILE_FULL    3

#ifdef BRISK_USER_CONFIG
#    include BRISK_USER_CONFIG
#endif

#ifndef BRISK_PROFILE
#    define BRISK_PROFILE BRISK_PROFILE_DEFAULT
#endif
#if BRISK_PROFILE < BRISK_PROFILE_TINY || BRISK_PROFILE > BRISK_PROFILE_FULL
#    error "BRISK_PROFILE must be BRISK_PROFILE_TINY, BRISK_PROFILE_DEFAULT or BRISK_PROFILE_FULL"
#endif

/* Feature knobs are added here as each milestone lands (see docs/ROADMAP.md). Pattern:
 *
 *   #ifndef BRISK_ENABLE_X
 *   #  define BRISK_ENABLE_X (BRISK_PROFILE >= BRISK_PROFILE_DEFAULT)
 *   #endif
 *   #if BRISK_ENABLE_X            -- then force what X depends on, #error on explicit 0
 *
 * Resolve top-down: application protocols -> transports -> crypto primitives.
 * SHA-256/384/512, HMAC and HKDF are always built: every TLS configuration needs them.
 */

#endif /* BRISK_CONFIG_H */
