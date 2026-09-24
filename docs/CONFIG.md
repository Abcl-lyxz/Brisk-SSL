# Configuring Brisk-SSL

Everything is in one file, `include/brisk_config.h`. Most users change nothing.

## Profiles
| Profile | Contents | Select with |
|---|---|---|
| TINY | TLS 1.3 client, X25519/P-256, AES-GCM + ChaCha20, ECDSA/RSA verify | `-DBRISK_PROFILE=BRISK_PROFILE_TINY` |
| DEFAULT | TINY + TLS 1.2, AES-256, HTTP/2, mTLS | (default) |
| FULL | DEFAULT + QUIC + HTTP/3 | `-DBRISK_PROFILE=BRISK_PROFILE_FULL` |

With CMake: `-DBRISK_PROFILE=TINY|DEFAULT|FULL`.

## Knobs
Knobs are tri-state: leave undefined (profile decides), or pass `-DBRISK_ENABLE_<X>=0|1`.
Dependencies switch on automatically; impossible combinations stop the build with an `#error`
that says how to fix it. Knobs are added as their milestone lands.

| Knob | Default | Needs | Size cost (bytes, -Os) |
|---|---|---|---|
| (always built) SHA-256/384/512, HMAC, HKDF | on | - | see table below |
| `BRISK_ENABLE_MTLS` — client certificates: ECDSA P-256 signing (hedged RFC 6979) and the `brisk_sign_fn` hook | DEFAULT and FULL | SHA-2, HMAC, P-256 (all already built) | 818 (armv7hf) … 1776 (mips); 1309 on x86_64 |
| `BRISK_ENABLE_TLS12` - TLS 1.2 client in the same ClientHello as TLS 1.3 (RFC 5246 mechanics, RFC 9846 downgrade/E rules): ECDHE-ECDSA/RSA x AES-128/256-GCM + ChaCha20-Poly1305, extended main secret required, no renegotiation / resumption / CBC / static RSA / SHA-1. Off = the TLS 1.3-only offer, byte for byte (preset `dev-tls13`). | DEFAULT and FULL | nothing new (SHA-2, HMAC, GCM, ChaCha, X25519, P-256, RSA, X.509 are always built) | 5292 (armv7hf) ... 9928 (mipsel); 7715 on x86_64 - tls12.c 2754..5008, record 1.2 framing 1504..2692, PRF 320..724, handshake 664..1472. RAM: `brisk_conn_size()` +~350 B. TINY is not byte-identical: shared refactors cost 136..220 B there |
| `BRISK_GHASH_MULFREE` — GHASH with shifts and masked XORs only (SP 800-38D Algorithm 1), for CPUs whose integer multiply finishes early on small operands and would leak the GCM key H through timing. About 4x slower GHASH; AES-GCM stays offered. | on for armv4/armv5 and 32-bit MIPS, off elsewhere (auto) | - | saves 1116 (armv5), 1068 (mips/mipsel); force it to 1 on any other core with a variable-latency MUL |
| `BRISK_ENABLE_P384` — ECDSA **P-384 signature verification** (`ecdsa_secp384r1_sha384`). Verify only: no P-384 keygen, ECDH or signing exists. | DEFAULT and FULL | `src/crypto/bn.c` (already built for RSA) | 2671 (armv7hf) … 5092 (mips/mipsel); 3775 on x86_64 |
| `BRISK_ENABLE_H2` - HTTP/2, today HPACK (RFC 7541: `src/http/hpack.c` + `src/http/huffman.c`, the Huffman decoder and prefixed integer shared with QPACK in M7). An optional module called explicitly; never switched on by ALPN. | DEFAULT and FULL | - | 3366 (armv7hf) ... 5788 (mipsel/mips64); 4441 on x86_64. hpack / huffman: x86_64 3698/743, i686 3471/775, aarch64 4003/719, armv7hf 2787/579, armv5 4207/819, mips 4920/840, mipsel 4948/840, mips64 4928/860, riscv64 3349/665, ppc 4335/791. RAM per connection (`brisk_h2_size()`, caller-owned): the `BRISK_H2_HEADER_TABLE_SIZE` ring (4 KB), two `BRISK_H2_MAX_HEADER_LIST` buffers (field block + scratch), 5 KB tx/rx, and per stream `BRISK_H2_STREAM_WINDOW` + `BRISK_H2_MAX_HEADER_LIST` |

`BRISK_ENABLE_P384` is a knob, unlike P-256 and RSA, because RFC 9846 9.1 makes only
`ecdsa_secp256r1_sha256` mandatory to implement and the registry in RFC 9846 11 lists
`ecdsa_secp384r1_sha384` as "Recommended" only. Switch it on for the public Web PKI anyway:
Let's Encrypt's Generation Y intermediates are P-384, so a chain from them cannot be verified
without it. With it off, `src/crypto/p384.c` compiles to an empty object and costs nothing.

RSA verification has **no knob**: RFC 9846 9.1 makes `rsa_pkcs1_sha256` (certificates) and
`rsa_pss_rsae_sha256` (CertificateVerify and certificates) mandatory to implement, so
`src/crypto/bn.c` and `src/crypto/rsa.c` are in every profile including TINY - exactly as
`src/crypto/p256.c` is, for ECDHE. Together they cost 2613 (armv7hf) to 4956 (mips64) bytes of
flash, and that is simply owed: there is no honest knob to hide a mandatory-to-implement
algorithm behind.

### Value knobs
| Knob | Default | Range | What it changes |
|---|---|---|---|
| `BRISK_RSA_MAX_BITS` | 4096 | 2048 to 4096, multiple of 8 | The largest RSA modulus a certificate signature may use. A **stack** lever, not a flash one: it sizes `BRISK__BN_MAX_LIMBS`, which is the CIOS accumulator inside `brisk__bn_mont_mul` (640 B of frame at 4096) as well as the i31 scratch in `src/crypto/rsa.c`. That accumulator sits under every one of the ~12,000 Montgomery multiplications a P-384 verify runs, so with `BRISK_ENABLE_P384` on this knob moves `src/crypto/p384.c`'s stack too - 2648 B at 4096 along its deepest chain. Measured with `-fstack-usage` at -Os along the deepest call chain, a PSS verify needs 3392 B of stack at 4096 and 2064 B at 2048; PKCS#1 v1.5 needs 3088 B and 1760 B. Flash and the public ABI are unaffected. Drop it to 2048 only for a private PKI whose largest certificate you control - public trust anchors are 4096-bit (ISRG Root X1). |
| `BRISK_TLS_MAX_HS_MSG` | 12288 | 4096 to 65536 | The largest TLS 1.3 handshake message body the engine buffers - in practice the server's Certificate, which is reassembled whole because the certificates are parsed in place. A **RAM** lever: the engine's scratch buffer (`brisk__tls13_hs_scratch_size()`) is this plus ~4 KB (a CertificateVerify at `BRISK_RSA_MAX_BITS`, `BRISK__X509_MAX_CHAIN` parsed-certificate structs, a 2 KB output queue, plus `BRISK_TLS_MAX_CLIENT_CHAIN` with mTLS). A bigger Certificate fails the handshake closed with `illegal_parameter` (a local limit; the RFC names none). 12 KB holds a leaf and two intermediates even at RSA-4096; check real chains during interop (M3 line 5) before lowering it. Flash and the public ABI are unaffected. |
| `BRISK_TLS_MAX_CLIENT_CHAIN` | 4096 | 1024 to 65536 | The largest mTLS device chain (`client_chain`, concatenated DER) the TLS 1.3 client sends, in bytes. The client Certificate is built whole in the engine's output queue, so this is **RAM**: the scratch buffer grows by exactly this much, and only in builds with `BRISK_ENABLE_MTLS`. 4 KB holds a P-256 device leaf plus an RSA-4096 issuing CA, or a leaf plus two RSA-2048 CAs. A longer chain is `BRISK_E_ARG` at setup (a local limit; RFC 9846 4.4.2 allows 2^24-1), never truncated. Flash and the public ABI are unaffected. |
| `BRISK_H2_HEADER_TABLE_SIZE` | 4096 | 0 to 65535 | The SETTINGS_HEADER_TABLE_SIZE this client advertises for HTTP/2: the largest HPACK dynamic table a server may make us keep, and exactly the ring the caller hands `brisk__hpack_dec_init` - a **RAM** lever (4 KB per HTTP/2 connection at the default, plus the per-field scratch). RFC 9113 4.3.1 makes 4096 the initial value; below it every server must open its first header block with a table size update, which RFC 9113 4.3.1 calls "not widely interoperable" - test against your servers (M4 line 3 interop) before lowering it. The 65535 cap lets the ring store entry lengths in 16 bits. Only with `BRISK_ENABLE_H2`. Flash and the public ABI are unaffected. |
| `BRISK_H2_MAX_HEADER_LIST` | 8192 | 4096 to 65535 | The SETTINGS_MAX_HEADER_LIST_SIZE this client advertises for HTTP/2: the largest response header section (name + value + 32 per field) it accepts; a bigger one ends the connection with COMPRESSION_ERROR. A **RAM** lever: the field-block buffer, the scratch and each stream's ring are this size, so `brisk_h2_size()` moves by (2 + `BRISK_H2_MAX_STREAMS`) x the change - +24 KB going from 4096 to 8192 at 4 streams. 4096 fits typical IoT backends, but github.com and www.cloudflare.com send ~5.3 KB of response headers (2026-09-24) and fail at 4096. Flash and the public ABI are unaffected. |

### Time: what an expired certificate means on a device with no clock
| Knob | Default | Values | What it changes |
|---|---|---|---|
| `BRISK_X509_TIME_POLICY` | `..._FLOOR` | `BRISK_X509_TIME_POLICY_STRICT`, `..._FLOOR`, `..._INSECURE_NO_TIME` | What happens when the clock reads below `BRISK_X509_TIME_FLOOR`, i.e. when it has clearly never been set. |
| `BRISK_X509_TIME_FLOOR` | `1767225600` (2026-01-01Z) | any positive Unix timestamp | The lower bound the firmware carries. Pass your own build time: `-DBRISK_X509_TIME_FLOOR=$(date -u +%s)`. |

A gateway boots with a 1970 RTC, has no battery, and may sit for a week before NTP answers, so
"compare `notAfter` against the system clock" is not a policy on this hardware. The floor is the
one thing the firmware knows for free: it cannot be running *earlier* than it was built.

| Clock | STRICT | FLOOR (default) | INSECURE_NO_TIME |
|---|---|---|---|
| at or above the floor | `notBefore <= now <= notAfter` | same | not checked |
| below the floor (unset) | refuse the certificate | `notAfter >= floor` only | not checked |

FLOOR does not check `notBefore` while the clock is unset, and that is not an oversight: the real
time is somewhere above the floor, so a certificate issued after this firmware was built is
legitimate and cannot be told apart from one dated in the future. What FLOOR still buys is the
half that matters against an attacker - a certificate that had already expired when the image was
built is refused, so a compromised leaf from two years ago cannot be replayed at a device that
believes it is 1970.

The **trust anchor is exempt** from the window under every policy. An expired root breaks working
devices with no attacker anywhere near them (DST Root CA X3, 2021); RFC 5280 6.1.1 (d) defines an
anchor as a name and a key rather than a certificate, so nothing is being bent. The intermediate
below it is still checked.

Both knobs are ordinary `-D` defines; the policy also has a CMake cache variable, so the two
non-default policies can be built and tested by name:
`cmake --preset dev -DBRISK_X509_TIME_POLICY=STRICT` (or `INSECURE_NO_TIME`). The `x509` suite
carries the verdict for all three and reads the column the build selected.

`INSECURE_NO_TIME` compiles the check out entirely - and says so in `brisk_build_info()`
(`profile=TINY time=INSECURE_NO_TIME`), so `strings firmware.bin | grep BRISKCFG` answers "why
does this gateway accept an expired certificate?" on an image nobody has the build flags for any
more. `STRICT` reports itself the same way; the default stays silent and costs nothing.

## Measured size (M1a, `python tools/dev.py size --arch all`)
Flash = code + read-only data + data of the library objects actually linked (libc excluded).

| module | x86_64 | i686 | aarch64 | armv7hf | armv5 | mips | mipsel | mips64 | riscv64 | ppc |
|---|---|---|---|---|---|---|---|---|---|---|
| hkdf (HMAC+HKDF+Expand-Label) | 1098 | 1212 | 1271 | 729 | 1095 | 1736 | 1740 | 1684 | 1041 | 1243 |
| sha2 (SHA-256/384/512) | 3272 | 4520 | 3344 | 3306 | 4348 | 5712 | 5716 | 4720 | 3376 | 4460 |
| util | 136 | 183 | 169 | 127 | 201 | 212 | 212 | 216 | 141 | 305 |
| **total flash** | 4506 | 5915 | 4784 | 4162 | 5644 | 7660 | 7668 | 6620 | 4558 | 6008 |

RAM: no static RAM beyond a few bytes; contexts are caller-owned
(`brisk_sha256_ctx` 104 B, `brisk_sha512_ctx` 200 B, `brisk_hmac_ctx` 408 B on 64-bit).

## What did my firmware get compiled with?
`brisk_build_info()` returns e.g. `0.1.0-dev profile=DEFAULT`; the same text is embedded as
`@(#)BRISKCFG ...`, so `strings firmware.bin | grep BRISKCFG` works on a shipped image.
