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

## Measured size (M1a, `python tools/dev.py size --arch all`)
Flash = code + read-only data + data of the library objects actually linked (libc excluded).

| module | x86_64 | i686 | aarch64 | armv7hf | armv5 | mips | mipsel | mips64 | riscv64 | ppc |
|---|---|---|---|---|---|---|---|---|---|---|
| hkdf (HMAC+HKDF+Expand-Label) | 1098 | 1212 | 1271 | 729 | 1095 | 1736 | 1740 | 1684 | 1041 | 1243 |
| sha2 (SHA-256/384/512) | 3295 | 4537 | 3352 | 3318 | 4368 | 5748 | 5752 | 4736 | 3394 | 4484 |
| util | 136 | 183 | 169 | 127 | 201 | 212 | 212 | 216 | 141 | 305 |
| **total flash** | 4529 | 5932 | 4792 | 4174 | 5664 | 7696 | 7704 | 6636 | 4576 | 6032 |

RAM: no static RAM beyond a few bytes; contexts are caller-owned
(`brisk_sha256_ctx` 104 B, `brisk_sha512_ctx` 200 B, `brisk_hmac_ctx` 408 B on 64-bit).

## What did my firmware get compiled with?
`brisk_build_info()` returns e.g. `0.1.0-dev profile=DEFAULT`; the same text is embedded as
`@(#)BRISKCFG ...`, so `strings firmware.bin | grep BRISKCFG` works on a shipped image.
