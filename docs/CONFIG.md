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
| `BRISK_ENABLE_P384` — ECDSA **P-384 signature verification** (`ecdsa_secp384r1_sha384`). Verify only: no P-384 keygen, ECDH or signing exists. | DEFAULT and FULL | `src/crypto/bn.c` (already built for RSA) | 2671 (armv7hf) … 5092 (mips/mipsel); 3775 on x86_64 |

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
