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

/* TLS 1.2 client (RFC 5246 mechanics, RFC 9846 downgrade and E rules; src/tls/tls12.c). The
 * ClientHello then offers TLS 1.3 AND 1.2 (supported_versions [0x0304, 0x0303]) with the six
 * ECDHE + AEAD suites (ECDSA/RSA x AES-128/256-GCM, ChaCha20-Poly1305), extended_main_secret
 * REQUIRED (RFC 7627), renegotiation refused (RFC 5746), no CBC / static RSA / SHA-1 signature /
 * compression / resumption. Off in TINY: that ClientHello stays TLS 1.3 only, byte for byte, and
 * a TLS 1.2 ServerHello is protocol_version. A device that must be 1.3-only in a bigger profile
 * builds with -DBRISK_ENABLE_TLS12=0 - there is no runtime version knob. Needs nothing forced:
 * SHA-2, HMAC, AES-GCM, ChaCha20-Poly1305, X25519, P-256, RSA and X.509 are always linked. */
#ifndef BRISK_ENABLE_TLS12
#    define BRISK_ENABLE_TLS12 (BRISK_PROFILE >= BRISK_PROFILE_DEFAULT)
#endif

/* HTTP/2 (RFC 9113). An optional module the application calls explicitly over a TLS connection
 * whose ALPN it chose - never switched on by the core: HPACK (RFC 7541, src/http/hpack.c +
 * huffman.c) and frames, streams, flow control and the brisk_h2_* API (src/http/h2.c). Off in
 * TINY. Needs nothing else. With it off all three files compile to empty translation units. */
#ifndef BRISK_ENABLE_H2
#    define BRISK_ENABLE_H2 (BRISK_PROFILE >= BRISK_PROFILE_DEFAULT)
#endif

/* The SETTINGS_HEADER_TABLE_SIZE this client advertises, in octets: the largest HPACK dynamic
 * table the peer may make us keep, and exactly the ring memory the caller hands the decoder. A
 * RAM knob. RFC 9113 4.3.1 makes 4096 the initial value, and a smaller one forces every peer to
 * open its first header block with a table size update - RFC 9113 4.3.1 calls reducing it "not
 * widely interoperable", so lower it only after testing against your servers. The 65535 cap lets
 * the ring store entry lengths as 16 bits. No public struct size depends on it. */
#ifndef BRISK_H2_HEADER_TABLE_SIZE
#    define BRISK_H2_HEADER_TABLE_SIZE 4096
#endif
#if BRISK_H2_HEADER_TABLE_SIZE < 0 || BRISK_H2_HEADER_TABLE_SIZE > 65535
#    error "BRISK_H2_HEADER_TABLE_SIZE must be 0..65535"
#endif

/* HTTP/2 streams open at once (RFC 9113 5.1.2): each costs BRISK_H2_STREAM_WINDOW + 4096 octets
 * of brisk_h2_size(). The server's SETTINGS_MAX_CONCURRENT_STREAMS may lower it further. */
#ifndef BRISK_H2_MAX_STREAMS
#    define BRISK_H2_MAX_STREAMS 4
#endif
#if BRISK_H2_MAX_STREAMS < 1 || BRISK_H2_MAX_STREAMS > 64
#    error "BRISK_H2_MAX_STREAMS must be 1..64"
#endif

/* Per-stream HTTP/2 receive window in octets (our SETTINGS_INITIAL_WINDOW_SIZE, RFC 9113 6.9.2):
 * the server may have this much response data in flight per stream, and it is exactly the
 * buffer each stream owns, so nothing is ever dropped. Throughput per stream is about
 * window / RTT (8192 at 50 ms = 1.3 Mbit/s); doubling it doubles both. A RAM knob. */
#ifndef BRISK_H2_STREAM_WINDOW
#    define BRISK_H2_STREAM_WINDOW 8192
#endif
#if BRISK_H2_STREAM_WINDOW < 1024 || BRISK_H2_STREAM_WINDOW > 1048576
#    error "BRISK_H2_STREAM_WINDOW must be 1024..1048576"
#endif

/* Client certificates (mTLS): ECDSA P-256 signing with a hedged RFC 6979 nonce, and the
 * brisk_sign_fn hook for a key held in a secure element. Off in TINY - a gateway that only
 * authenticates the server links neither. It is a knob rather than always-on because
 * src/crypto/p256.c is linked into every build for ECDHE, which is mandatory-to-implement, so
 * without this the smallest image would pay for signing it never performs. */
#ifndef BRISK_ENABLE_MTLS
#    define BRISK_ENABLE_MTLS (BRISK_PROFILE >= BRISK_PROFILE_DEFAULT)
#endif

/* ECDSA P-384 signature VERIFICATION (src/crypto/p384.c). Verify only - no P-384 keygen, ECDH or
 * signing exists in this library and none is planned. Off in TINY, on from DEFAULT up.
 *
 * A knob rather than always-on because RFC 9846 9.1 makes only ecdsa_secp256r1_sha256 (plus
 * rsa_pkcs1_sha256 and rsa_pss_rsae_sha256) mandatory to implement, and the IANA registry in
 * RFC 9846 11 lists ecdsa_secp384r1_sha384 as "Recommended" only - unlike p256.c and rsa.c,
 * which every conformant client must carry. What makes it worth switching ON is X.509, not the
 * handshake: Let's Encrypt's Generation Y intermediates are P-384, so a chain from them cannot
 * be verified without it.
 *
 * Nothing needs forcing: src/crypto/bn.c is already linked unconditionally for RSA, and p384.c
 * rides on it unchanged. With the knob off, p384.c compiles to an empty translation unit and
 * links to nothing. */
#ifndef BRISK_ENABLE_P384
#    define BRISK_ENABLE_P384 (BRISK_PROFILE >= BRISK_PROFILE_DEFAULT)
#endif

/* GHASH without multiply instructions (src/crypto/gcm.c). The default GHASH is constant time
 * only if the CPU's integer multiply is: ARM7/ARM9 (armv5) and some MIPS32 cores (4K family)
 * finish early on small operands, which would leak the GCM hash key H through timing. 1 = use
 * shifts and masked XORs only (about 4x slower GHASH, a few hundred bytes smaller); 0 = the
 * multiply-based one. Undefined = on for armv4/armv5 and 32-bit MIPS, off elsewhere. Force it
 * to 1 for any other core whose MUL latency depends on the operands. AES-GCM stays offered on
 * every target either way; ChaCha20-Poly1305 is preferred where AES is slow in software. */
#ifndef BRISK_GHASH_MULFREE
#    if (defined(__arm__) &&                                                                       \
         ((defined(__ARM_ARCH) && __ARM_ARCH < 6) || defined(__ARM_ARCH_5TE__) ||                  \
          defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_5T__) || defined(__ARM_ARCH_4T__))) ||  \
        (defined(__mips__) && !defined(__mips64))
#        define BRISK_GHASH_MULFREE 1
#    else
#        define BRISK_GHASH_MULFREE 0
#    endif
#endif

/* Largest RSA modulus accepted when verifying a certificate signature, in bits. The project's
 * first VALUE knob - every other one is a tri-state boolean - and it is a STACK lever, not a
 * flash one: it sizes BRISK__BN_MAX_LIMBS, hence both the i31 scratch inside src/crypto/rsa.c and
 * the CIOS accumulator inside brisk__bn_mont_mul (640 bytes of frame at 4096) - so with
 * BRISK_ENABLE_P384 on it is a stack lever for src/crypto/p384.c too, whose deepest chain is
 * 2648 bytes at 4096. Measured at -Os along the deepest call chain, a PSS verify needs 3392 bytes
 * of stack at 4096 and 2064 at 2048; PKCS#1 v1.5 needs 3088 and 1760. The full table is in the
 * src/crypto/rsa.c header.
 *
 * 4096 by default because real trust anchors are 4096-bit (ISRG Root X1). Drop it to 2048 only
 * for a private PKI whose largest certificate you control. There is no knob to switch RSA off:
 * RFC 9846 9.1 makes rsa_pkcs1_sha256 (certificates) and rsa_pss_rsae_sha256 (CertificateVerify
 * and certificates) mandatory to implement, exactly as it does P-256 ECDHE.
 *
 * No public struct size depends on this, so the ABI rule at the top of this file still holds. */
#ifndef BRISK_RSA_MAX_BITS
#    define BRISK_RSA_MAX_BITS 4096
#endif
#if BRISK_RSA_MAX_BITS < 2048 || BRISK_RSA_MAX_BITS > 4096 || (BRISK_RSA_MAX_BITS % 8) != 0
#    error "BRISK_RSA_MAX_BITS must be 2048..4096 and a multiple of 8"
#endif

/* X.509 validity window: when is a certificate too old to trust on a device whose clock may
 * never have been set? A gateway boots with a 1970 RTC, has no battery, and may sit for a week
 * before NTP answers, so "compare notBefore/notAfter against the system clock" is not a policy
 * on this class of hardware, it is a coin flip.
 *
 * BRISK_X509_TIME_FLOOR is the lower bound the firmware carries: an image cannot be running
 * EARLIER than the moment it was built. A clock below the floor is therefore not a clock, it is
 * an unset counter, and BRISK_X509_TIME_POLICY decides what to do about that:
 *
 *   ..._STRICT            refuse the certificate. A device that cannot tell the time cannot
 *                         check an expiry, and this says so instead of guessing. Pick it when
 *                         NTP or a battery-backed RTC is guaranteed before the first connection.
 *   ..._FLOOR (default)   fall back to the floor: require notAfter >= floor, i.e. the
 *                         certificate had not already expired when this firmware was built.
 *                         notBefore is NOT checked in that state - the real time is somewhere
 *                         above the floor, so a certificate issued after the build is
 *                         legitimate and unprovable. Weaker than a real clock, strictly
 *                         stronger than no check: the long-dead leaf an attacker replays is
 *                         still refused.
 *   ..._INSECURE_NO_TIME  never look at the dates; expired certificates pass. For a device with
 *                         no clock at all and a private PKI it pins instead. Named INSECURE so
 *                         it cannot be chosen by accident, and brisk_build_info() reports it.
 *
 * With a usable clock the first two do the same ordinary thing: notBefore <= now <= notAfter.
 *
 * WHAT RFC 5280 SAYS, since this is a deviation and deserves to be named as one: 6.1.3 (a)(2)
 * requires "the certificate validity period includes the current time", and 6.1.1 (b) makes
 * "the current date/time" an INPUT to path validation. On hardware where that input does not
 * exist, the choice is between refusing every connection (STRICT, which is the conformant
 * reading) and substituting a weaker predicate that is still monotone in the attacker's
 * disfavour (FLOOR). INSECURE_NO_TIME drops the requirement outright.
 *
 * WHAT FLOOR DOES NOT BUY, none of which is an argument against it and all of which decides
 * whether STRICT is the better pick for a given device:
 *   - The bound AGES. It is the build date, not today: three years after an image ships, "was
 *     already expired when this was built" lets through a certificate that died almost three
 *     years ago. A device that is never re-flashed converges on INSECURE_NO_TIME.
 *   - A certificate compromised NEAR the build date stays acceptable forever to a device whose
 *     clock is never set - there is no revocation here, so expiry is the only freshness signal
 *     and this is the half of it that is given up.
 *   - "Clock below the floor" is not only an unset RTC: an attacker who controls unauthenticated
 *     NTP, or the reset line of the RTC, can PUT a fully checked client into that state. FLOOR
 *     bounds what that buys them; STRICT denies it. Where the time source is authenticated,
 *     STRICT is the right knob.
 *
 * A device that persists a last-known-good time cannot raise the floor today: the floor is a
 * compile-time constant, and passing the stored timestamp as `now` instead would be worse than
 * useless - it lifts the clock above the floor, so notBefore is enforced again, against a stale
 * value, and every certificate issued since then is refused. A runtime floor belongs to the M3
 * client config, where the device's storage is already in the picture.
 *
 * Set the floor to YOUR build time - `-DBRISK_X509_TIME_FLOOR=$(date -u +%s)` - and it tracks
 * every release; the default below is only as good as the day it was last edited. It is
 * deliberately NOT derived from __DATE__: that breaks reproducible builds, and a floor nobody
 * can reproduce is a floor nobody can audit. */
#define BRISK_X509_TIME_POLICY_STRICT           1
#define BRISK_X509_TIME_POLICY_FLOOR            2
#define BRISK_X509_TIME_POLICY_INSECURE_NO_TIME 3

#ifndef BRISK_X509_TIME_POLICY
#    define BRISK_X509_TIME_POLICY BRISK_X509_TIME_POLICY_FLOOR
#endif
#if BRISK_X509_TIME_POLICY < BRISK_X509_TIME_POLICY_STRICT ||                                      \
    BRISK_X509_TIME_POLICY > BRISK_X509_TIME_POLICY_INSECURE_NO_TIME
#    error "BRISK_X509_TIME_POLICY must be BRISK_X509_TIME_POLICY_{STRICT,FLOOR,INSECURE_NO_TIME}"
#endif

/* Seconds since 1970-01-01T00:00:00Z. 1788220800 is 2026-09-01T00:00:00Z, the month this
 * default was last moved - it is a placeholder for your own build time, not a maintained date. */
#ifndef BRISK_X509_TIME_FLOOR
#    define BRISK_X509_TIME_FLOOR 1788220800
#endif
/* Bounded at both ends on purpose. A floor in MILLISECONDS is the typo this catches, and it is
 * not a harmless one: every real clock would sit below it, so STRICT would refuse every
 * certificate and FLOOR would demand a notAfter in the year 57969 - a silent total outage on a
 * shipped gateway. A value past INT64_MAX is the opposite failure, and worse: the constant turns
 * unsigned, the (int64_t) cast wraps it negative, and the floor quietly stops existing. The
 * upper bound fires on both, at build time, where it costs nothing. */
#if BRISK_X509_TIME_FLOOR <= 0 || BRISK_X509_TIME_FLOOR > 4102444800 /* 2100-01-01T00:00:00Z */
#    error "BRISK_X509_TIME_FLOOR must be a Unix timestamp in SECONDS, e.g. $(date -u +%s)"
#endif

/* Largest handshake message the TLS 1.3 engine buffers, in bytes of body. In practice that is
 * the server's Certificate message, which is reassembled whole because the certificates are
 * parsed in place. 12 KB holds a leaf plus two intermediates even at RSA-4096; a longer chain
 * fails the handshake closed (illegal_parameter - a local limit, not an RFC one). A RAM knob:
 * the engine's scratch buffer is this plus about 3 KB (brisk__tls13_hs_scratch_size). No public
 * struct size depends on it. */
#ifndef BRISK_TLS_MAX_HS_MSG
#    define BRISK_TLS_MAX_HS_MSG 12288
#endif
#if BRISK_TLS_MAX_HS_MSG < 4096 || BRISK_TLS_MAX_HS_MSG > 65536
#    error "BRISK_TLS_MAX_HS_MSG must be 4096..65536"
#endif

/* Largest mTLS device chain (cfg client_chain: concatenated DER, leaf first) the TLS 1.3 engine
 * sends, in bytes. The client Certificate is built whole in the engine's output queue, so this
 * is RAM: the scratch buffer grows by exactly this much, and only with BRISK_ENABLE_MTLS. RFC
 * 9846 4.4.2 allows 2^24-1; 4 KB holds a P-256 leaf plus an RSA-4096 issuing CA, or a leaf plus
 * two RSA-2048 CAs. A longer chain is BRISK_E_ARG at setup (a local limit, never truncated). */
#ifndef BRISK_TLS_MAX_CLIENT_CHAIN
#    define BRISK_TLS_MAX_CLIENT_CHAIN 4096
#endif
#if BRISK_TLS_MAX_CLIENT_CHAIN < 1024 || BRISK_TLS_MAX_CLIENT_CHAIN > 65536
#    error "BRISK_TLS_MAX_CLIENT_CHAIN must be 1024..65536"
#endif

#endif /* BRISK_CONFIG_H */
