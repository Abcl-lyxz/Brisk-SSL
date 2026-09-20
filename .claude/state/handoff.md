# Handoff - 2026-09-20 (session 5)

## Done
- 2e907ba crypto: vendored fiat-crypto v0.1.6 (`9d0682462646bf645cba7409fa45794dee0418aa`) into
  `vendor/fiat/`: `{curve25519,p256}_{32,64}.c` byte-for-byte + COPYRIGHT/AUTHORS/all 3 licenses.
  `vendor/VENDORED.md` has the pinned commit, per-file sha256 and the exact re-vendor command;
  NOTICE updated, `.gitattributes` marks `vendor/**` vendored. No build wiring, no size delta.
- 6dc658c crypto: X25519 (`src/crypto/x25519.c`, RFC 7748) - decodeScalar25519 on a private copy,
  Montgomery ladder with mask/XOR cswap, 254-sq/11-mul Fermat inversion, all-zero reject
  (RFC 7748 6.1/7, RFC 9846 7.4.2 -> `BRISK_E_ARG`, out wiped). 672 KAT rows + 3 iterated
  (RFC 7748 5.2/6.1, RFC 8448, all 518 Wycheproof XdhComp, differential). 11 archs green,
  `dev.py ct` green, baseline saved.

## In progress
- Nothing. Tree clean. **Both commits are local - `git push` has not run yet.**

## Next up
- M1c: `P-256 ECDHE + ECDSA verify` on `vendor/fiat/p256_{32,64}.c` (trimmed fiat on 32-bit:
  square=mul, Fermat inversion). Then `ECDSA P-256 sign, hedged RFC 6979 + sign-callback hook`.
  Use `/implement-module` with the ROADMAP line as the task text - it worked well this session.

## Decisions / gotchas
- fiat `_32` and `_64` export **identical function names and signatures**; only the field-element
  typedef differs (5xu64 vs 10xu32). So the curve layer is written once and the variant is one
  `#include`. Same trick will work for P-256.
- `BRISK__FIAT_64` (brisk_int.h) needs `UINTPTR_MAX > 0xFFFFFFFF` **and** `__SIZEOF_INT128__`, so
  x32/n32 take the 32-bit file. `-DBRISK__FIAT_64=0` forces it anywhere; `dev.py ct` uses that to
  get valgrind over the 32-bit field code (same pattern as `BRISK__AES_CT64`).
- fiat generates with `--static --inline`: the files are `#include`d into one of our TUs, **never**
  added to `add_library`. Needs `-Ivendor` - added to CMake and to `.claude/hooks/post_edit.js`.
  The including TU owns the `-Wunused-function` pragma push/pop around the include.
- `vendor/` is edit-blocked by `pre_guard.js`. To change it: re-vendor per VENDORED.md.
- A **second** `BRISK__CT_PUBLIC` now exists (the x25519 all-zero verdict); reason is written at
  `src/crypto/x25519.c:217`. Still the rule: a new one needs a written reason.
- Wipe limit, stated in the x25519 header: our locals are zeroed, but fiat keeps the same limbs in
  its own frame and is edit-blocked, so a stack scan can still find field residue. Closing it means
  scrubbing the stack window - a separate decision, not silently claimed.
- **Size is the thing to watch.** 32-bit fiat is ~2x the 64-bit one (fully unrolled 10-limb carry
  chains): x25519 flash = 3.9 KB riscv64/aarch64 but 9.2 KB i686, 8.9 KB mips/mipsel. TOTAL on
  mipsel is now 27.6 KB. P-256 will be worse. Raise TINY-profile knobs before M8 if this matters.
- The RFC 7748 1,000,000-iteration vector is in `tests/kat/x25519_iter.inc` but only runs with
  `BRISK_TEST_SLOW=1`; 1,000 runs by default (hours under qemu-armv5 otherwise).
- Still open from earlier sessions: armv5/MIPS32 GHASH timing leak (plan in ARCHITECTURE.md, fix at
  M3); HMAC ctx use after failed init/final; `kat.py` per-source minimum-count guards; hand-check of
  the `-Os` aes_ct disassembly on mips/armv5.
