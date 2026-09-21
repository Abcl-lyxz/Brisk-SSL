# Handoff - 2026-09-21 (session 8)

## Done
- 1ffaa17 crypto: P-384 ECDSA verify on the i31 bignum. **M1 Crypto is closed.** bn.c untouched,
  exactly as its header promised: p384.c adds constants, a projective point type and one
  Straus-Shamir interleaved ladder (384 doublings + ~384 adds, no table). RCB-2015 Alg. 4 complete
  addition as in p256.c; Fermat inversions through `brisk__bn_modpow_pub` with p-2 and n-2 derived
  at run time. `BRISK_ENABLE_P384`, off in TINY. 630 generated rows (CAVP SigVer P-384/SHA-384+512,
  CAVP PKV, Wycheproof sha384+sha512 p1363, RFC 6979 A.2.6). 11 archs + asan + ct32/ct64 green,
  baseline re-saved (+2671 armv7hf .. +5092 mips, RAM unchanged).

## In progress
- Nothing. Tree clean, committed and pushed.

## Next up
- **M2 X.509, first line: `DER parser (strict, depth-limited) + fuzz target`.** `/implement-module`
  with that ROADMAP line as task text. Nothing from M1 blocks it.

## Decisions / gotchas
- **`/implement-module` died on the session limit for the SECOND run in a row**, again in `fix:r2`,
  again after every edit was written and before anything was re-run. Assume this is the normal
  failure mode, not bad luck. Recovery that worked: map `subagents/workflows/<run>/journal.jsonl`
  by `key` (`type:started` carries the label, `type:result` the verdict), take every
  `refuted:false`, check whether the fix agent already applied it, then run host tests, `--arch
  all`, `ct` and `size` yourself. All four round-2 findings turned out to be already fixed.
- **Do not trust the workflow's own summary object.** Its `build` came back null (the post-phases
  threw on `build.files_changed`), and it reported a "round 3, found 3, confirmed 0" that has no
  entries in the journal at all. The journal is the record; the summary is not.
- **`p384.c:410` `(void)` on `p384_load_reduced` / `brisk__bn_encode` status: refuted by BOTH
  skeptics and left as is on purpose.** The path needs `bn_be_bitlen(src) > m[0]`, but src is
  fixed at 48 bytes and `m[0]` is pinned to 384 by `p384_ctx_init`; the same convention is used at
  four other sites in the file. Do not re-raise it in the next audit.
- **`BRISK_RSA_MAX_BITS` is now a stack lever for p384.c too**, not just rsa.c: `bn_mont_mul`
  sizes its CIOS accumulator at `BRISK__BN_MAX_LIMBS` (640 B at 4096) whatever the operand width,
  and it sits under every one of a verify's ~12,000 multiplications. p384 verify is 2648 B along
  the deepest chain at -Os, inside the 3 KB budget. Recorded in docs/CONFIG.md, deliberately NOT
  fixed in bn.c (a VLA is forbidden by -Wvla, alloca is not on offer).
- **M2 must not call `brisk__p384_ecdsa_verify` with `hash_len` 32.** A P-384 key certified with
  ecdsa-with-SHA256 exists in some private PKIs and this API cannot verify it by design (RFC 9846
  4.3.3 pairs the curve with its own hash). The certificate layer rejects that pairing with
  `unsupported_certificate`; the API returns BRISK_E_ARG for a short digest.
- **Cost of a P-384 verify, measured:** 3.2 ms on the x86_64 host at -Os, 32 ms under qemu-armv5 -
  cheap enough that the p384 suite runs in 42 s there against p256's 148 s. Upgrade paths, in
  order and none taken: `bn_muladd_small` + CT divrem to kill `bn_to_mont`'s 403 doublings, then a
  2-bit joint window (~12%), then a Solinas fast reduction (a locked-decision change).
- Docker Desktop was already running this session; `--arch all` and `ct` worked with no npipe error.
