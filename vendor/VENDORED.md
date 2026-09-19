# Vendored code

Everything under `vendor/` is upstream code copied in byte-for-byte. **Never hand-edit it**
(a `PreToolUse` hook refuses the edit): to change it, re-vendor from a new upstream commit and
update this file.

## fiat-crypto — `vendor/fiat/`

Formally verified field arithmetic for X25519 and P-256. It is the only third-party code we do
not write ourselves, because the carry chains are proved correct in Coq and machine-generated;
hand-written replacements are where real-world curve libraries get their bugs.

| | |
|---|---|
| Upstream | <https://github.com/mit-plv/fiat-crypto> |
| Tag / commit | `v0.1.6` = `9d0682462646bf645cba7409fa45794dee0418aa` |
| Vendored on | 2026-09-20 |
| License | `MIT OR Apache-2.0 OR BSD-1-Clause` (see `COPYRIGHT`); we take it under Apache-2.0 |
| Local changes | none |

### Files

| File | Upstream path | sha256 |
|---|---|---|
| `curve25519_32.c` | `fiat-c/src/curve25519_32.c` | `403a8a4431fc85adc030ee0105b694360621cd20de2ae003accafbce661bade1` |
| `curve25519_64.c` | `fiat-c/src/curve25519_64.c` | `645233c37707ba0580338aa84d8380357078a2c9bb2db80f0c5ff4e979650e3e` |
| `p256_32.c` | `fiat-c/src/p256_32.c` | `e0cb5e365fb1f0ed1d8c1f0c741565313c65d1dcee5baf06658ec30960e781b9` |
| `p256_64.c` | `fiat-c/src/p256_64.c` | `68cc5c4fa08de660a869a412618a30848f11d18051245013fe53fa4e313ec701` |
| `COPYRIGHT` `AUTHORS` `LICENSE-MIT` `LICENSE-APACHE` `LICENSE-BSD-1` | repo root | — |

### How they are built

The `_32` / `_64` split is the field representation, not the ABI: `_64` needs `__int128`
(unsaturated 51-bit limbs for 25519, 64-bit Montgomery for P-256), `_32` does not. Pick by
`UINTPTR_MAX`, the same way `BRISK__AES_CT64` picks the AES variant.

Upstream generates these with `--static --inline`, so **every function is `static`**: the files
are `#include`d into one of our `src/crypto/*.c` translation units, never added to
`add_library(brisk ...)` on their own (compiling one alone produces an empty object and a wall of
`-Wunused-function`). The including file is responsible for silencing `-Wunused-function` for the
operations that curve does not use.

Verified at vendoring time: all four compile clean under
`-std=c99 -Wall -Wextra -Wpedantic` (`-m32` for the `_32` pair, `-Wno-unused-function`).

### Re-vendoring

```sh
SHA=<new commit>
for f in fiat-c/src/curve25519_32.c fiat-c/src/curve25519_64.c \
         fiat-c/src/p256_32.c fiat-c/src/p256_64.c \
         COPYRIGHT AUTHORS LICENSE-MIT LICENSE-APACHE LICENSE-BSD-1; do
    curl -sfL "https://raw.githubusercontent.com/mit-plv/fiat-crypto/$SHA/$f" \
         -o "vendor/fiat/$(basename "$f")"
done
sha256sum vendor/fiat/*.c   # record below
```

Then update the table above, re-run `python tools/dev.py test --arch all`, and explain the size
delta — a new fiat release can change limb counts and therefore flash size.
