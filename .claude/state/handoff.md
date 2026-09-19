# Handoff - 2026-09-19 (session 3)

## Done
- d2bbdd6 crypto: AES-128/256 bitsliced constant-time, encrypt-only. `src/crypto/aes_ct.c` (32-bit)
  and `aes_ct64.c` (64-bit), both are always in CMake and `#if BRISK__AES_CT64` selects one. Same
  `brisk__aes_init/encrypt/ctr32` API. Adapted from BearSSL 7bea48e5, MIT notice in the file
  headers and NOTICE. Vectors: FIPS 197, CAVP (incl. MCT), SP 800-38A CTR, RFC 9001 A.2/A.3 HP,
  counter-wrap differential. All 13 presets green. 19/19 non-equivalent mutations caught.
  Size baseline saved.

## In progress
- Nothing. The GHASH+GCM workflow was started and then stopped during the spec phase, so the
  tree is clean.

## Next up
- M1b: GHASH (ctmul 32-bit / ctmul64 64-bit, BearSSL-style, MIT notice) + AES-GCM AEAD
  (SP 800-38D), 96-bit IV only, 16-byte tag. Mirror the ChaCha20-Poly1305 AEAD API: ct tag
  compare, wipe the output on BRISK_E_AUTH. Build on brisk__aes_ctr32. Vectors: GCM spec
  cases, Wycheproof aes_gcm (skip non-96-bit IV and AES-192), differential, and decrypt the
  RFC 9001 A.2 client Initial packet. Use `/implement-module` (the task text last time was the
  line above).

## Decisions / gotchas
- brisk__aes_key is fixed at 248 B. It has an explicit `unsigned pad` because i386 aligns
  uint64_t to 4, which would otherwise make it 244 B. A static assert in test_aes.c checks this.
- Only one AES variant links per arch (ct64 on x86_64, aarch64, mips64, riscv64). The host x86
  preset runs ct and host x64 runs ct64.
- AES stack per call: ~0.6 KB (ct), ~1.1 KB (ct64).
- brisk__aes_* does not check k->nr. That review finding was refuted: it is an internal API and
  an uninitialised key is the caller's bug.
- Still open: hand-check the -Os disassembly of aes_ct on mips/armv5 for constant time (or
  wait for the M1b CT tooling / ctgrind task).
- Reviewer agents again returned empty findings (2 of 3). The mutation run at
  scratchpad mut_aes.py was the real check, so repeat that for GCM.
- Earlier deferred items still open: HMAC ctx use after failed init/final; kat.py per-source
  minimum-count guards.
- Cost: the implement-module workflow used ~480k subagent tokens for AES.
