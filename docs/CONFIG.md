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

RSA verification has **no knob**: RFC 9846 9.1 makes `rsa_pkcs1_sha256` (certificates) and
`rsa_pss_rsae_sha256` (CertificateVerify and certificates) mandatory to implement, so
`src/crypto/bn.c` and `src/crypto/rsa.c` are in every profile including TINY - exactly as
`src/crypto/p256.c` is, for ECDHE. Together they cost 2613 (armv7hf) to 4956 (mips64) bytes of
flash, and that is simply owed: there is no honest knob to hide a mandatory-to-implement
algorithm behind.

### Value knobs
| Knob | Default | Range | What it changes |
|---|---|---|---|
| `BRISK_RSA_MAX_BITS` | 4096 | 2048 to 4096, multiple of 8 | The largest RSA modulus a certificate signature may use. A **stack** lever, not a flash one: it sizes the i31 scratch in `src/crypto/rsa.c` and nothing else. Measured with `-fstack-usage` at -Os along the deepest call chain, a PSS verify needs 3392 B of stack at 4096 and 2064 B at 2048; PKCS#1 v1.5 needs 3088 B and 1760 B. Flash and the public ABI are unaffected. Drop it to 2048 only for a private PKI whose largest certificate you control - public trust anchors are 4096-bit (ISRG Root X1). |

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
