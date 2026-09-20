# Handoff - 2026-09-21 (session 7)

## Done
- b107f6f crypto: `BRISK__CT_BARRIER` (src/brisk_int.h, by the ctgrind macros) on all four
  hand-written ct masks - fe_cmov + sc_cond_sub_n (p256.c), fe_cswap (x25519.c), poly1305's final
  reduction - plus the `-Os` pin. A macro, not the `brisk__ct_value_barrier_u32/u64` pair planned
  last session: an out-of-line call stops being a barrier once the amalgamation or LTO inlines it,
  and `"+r"` is width-agnostic, so one macro covers both limb sizes. util.c untouched.
- eb3425e crypto: ECDSA P-256 sign (FIPS 186-5 6.4.1 + RFC 6979 3.2, hedged per 3.6 bullet 2),
  `brisk_sign_fn` hook, `BRISK_ENABLE_MTLS` knob. M1c is closed; ROADMAP ticked. 57 sign rows,
  RFC 6979 A.2.5 reproduces the published k/r/s. 11 archs + ct32/ct64 green, baseline re-saved.

## In progress
- Nothing. Tree clean, everything pushed.

## Next up
- M1d: `i31 Montgomery bignum (constant-time), RSA PKCS#1 v1.5 + PSS verify 2048-4096`.
  `/implement-module` with the ROADMAP line as task text. P-384 verify (the next line) rides on
  the same bignum - design for both.

## Decisions / gotchas
- **`-Os` is now load-bearing, not taste.** At -O2 signing needs 3200 B and verify 2144 B, both
  over budget; -O3 sign is 3328 B. The pin in CMakeLists.txt is what keeps the documented figures
  true, and it overrides CMAKE_BUILD_TYPE on purpose (so `dev.py ct` now checks -Os, not -O1, and
  there is no -O0 row left to quote). Do not raise it without re-measuring the p256.c table.
- **Stack budget is 3 KB with BRISK_ENABLE_MTLS, 2 KB without** (was 2 KB flat). The sign path's
  fault-check verify is nested inside the signing frame; no reordering removes that, and dropping
  the countermeasure is not on offer - a glitched signature leaks the device key.
- **`sc_mont_mul`'s precondition (a < n, b < n) still governs every new call site.** The sign path
  honours it only because it goes through `brisk__p256_scalar_{reduce,add,mul,inv}`. M1d's bignum
  is a separate core - do not assume the p256 scalar rules carry over.
- **Recorded coverage gap** (tests/kat/SOURCES.md, not papered over): the k-out-of-range
  (p ~ 2^-32) and r/s == 0 (p ~ 2^-128) retries ship with no KAT - unreachable by any official
  vector and unsearchable at P-256 sizes.
- **`/implement-module` can die mid-run on the session limit.** It did here, in `fix:r1`, after
  the edits but before re-running anything. The tree looked finished and was not verified. Read
  `subagents/workflows/<run>/journal.jsonl` (`type:result`) for the build result and the
  refuted=false findings, then re-run tests yourself before trusting it.
- **Docker Desktop does not start with the machine here**, and launching the .exe is not enough -
  the engine needs the GUI. `test --arch all` and `ct` fail on an npipe error until then; ask
  early, it cost ~10 min of waiting this session.
- Still deferred to M8: the unprefixed `fe` / `pt` / `sc_ctx` typedefs in p256.c (p384.c will want
  the same names), and raising the TINY knobs - i686 TOTAL is 42987 B now.
