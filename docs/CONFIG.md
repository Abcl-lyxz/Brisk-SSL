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
