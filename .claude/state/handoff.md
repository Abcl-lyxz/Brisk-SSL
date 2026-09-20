# Handoff - 2026-09-20 (session 6)

## Done
- fba9ccb crypto: P-256 ECDHE + ECDSA verify (`src/crypto/p256.c`, ROADMAP M1c line ticked).
  RCB-2015 complete addition, 256-step double-and-add-always ladder, Fermat inversion, in-house
  8x32 CIOS Montgomery mod n. 462 ECDH / 299 verify / 74 keygen / 748 scalar rows; 11 archs green,
  `dev.py ct` green on both field variants, baseline saved.

## In progress
- Nothing. Tree clean. **fba9ccb is not pushed yet** (the earlier two commits are).

## Next up
- M1c: `ECDSA P-256 sign, hedged RFC 6979 (mTLS) + sign-callback hook`. `/implement-module` with
  the ROADMAP line as task text. The mod-n core (`brisk__p256_scalar_{valid,reduce,add,mul,inv}`)
  is already there and is what sign needs; `brisk__p256_scalar_inv` exponentiates the *public*
  constant n-2, so it is safe on a secret k despite the `if (bit)`.

## Decisions / gotchas
- **`sc_mont_mul` requires a < n and b < n** (`p256.c:~555`, written there). Sign adds new call
  sites: reduce every operand first. Without it `t[SC_LIMBS]` can reach 2, where one conditional
  subtraction cannot reduce at all - two reviewers proposed a uniform-mask "fix" for
  `sc_cond_sub_n`; it was refuted, it only swaps one wrong answer for another. The precondition is
  the whole protection.
- **Error-code split in verify, decided this session**: r or s outside [1, n-1] -> `BRISK_E_AUTH`
  (FIPS 186-5 6.4.2 step 1 says INVALID, and RFC 9846 4.5.2 wants decrypt_error). A public key
  that is not a point -> `BRISK_E_ARG` (bad_certificate). M3 must map them that way.
- **`tools/kat.py fetch()` now enforces the sha256 column of `tests/kat/SOURCES.md`** and dies on
  mismatch, cache hits included. Before, the table was rewritten from whatever was downloaded, so
  it pinned nothing. If upstream republishes a file, update its SOURCES.md row in the same commit
  as the regenerated vectors, deliberately. "Deliberately not used" lives in the kat.py template,
  not in the .md - hand edits to SOURCES.md are overwritten.
- **Stack figures are per optimisation level** (`p256.c` header has the table). 1504 B keygen/ECDH
  and 1856 B verify at -Os; -O3 reaches 2160 B, -O0 (what the CMake presets use) about 4 KB. Do
  not quote "2 KB" without the level.
- **Size.** p256 is 6230 B (riscv64) to 17195 B (i686); `fiat_p256_mul` alone is over half the
  32-bit figure. The in-house mod-n core is ~2 KB against the ~8-10 KB a re-vendored fiat
  p256_scalar would have cost - that is why it is in-house. TOTAL on i686 is now 41.6 KB. TINY
  profile knobs need raising before M8.
- **Two hardening items deferred on purpose, not forgotten:**
  1. `fe_cmov` (`p256.c`) and `fe_cswap` (`x25519.c`) have no compiler value barrier, while the
     fiat code beside them was generated with one. Fix is one `brisk__ct_value_barrier_u32/u64` in
     `src/util.c` and 4 call sites - do it for both files at once, with its own ct re-run.
  2. Typedefs `fe` / `pt` / `sc_ctx` in p256.c are unprefixed. No collision today (an amalgamation
     was compiled to check), but `p384.c` in M1d would want the same names. Rename at M8.
- `tests/test_p256.c` does **not** pin `P256_P`; `check_p256_source_constants()` in kat.py does,
  at generation time only. The header comment says so now - do not re-add the old claim.
