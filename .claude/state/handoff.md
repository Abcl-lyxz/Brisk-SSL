# Handoff - 2026-09-19 (session 1)

## Done
- M0 infra: CMake presets (host dev/dev32, Docker x86_64/asan + 9 cross archs under qemu),
  Docker image `brisk-dev`, tools/dev.py (test/size/image), tools/kat.py, CI, size baseline.
- M1a hash layer: SHA-256/384/512, HMAC, HKDF, Expand-Label - green on all 13 presets.
  4.2 KB (armv7 Thumb-2) .. 7.7 KB (MIPS32).
- Claude Code setup: hooks, statusline, skills, agents, rules, workflows, `rfc` MCP, CLAUDE.md.

- Adversarial review (3 lenses + refutation) of M1a: 10 confirmed findings fixed in b2b51e4
  (SHA-384/512 stack leak, ct_memeq tests, output canaries, BRISKCFG retain, static lib).
  Refuted-but-worth-revisiting later: HMAC ctx used after failed init/final fails open (make
  update/final check alg when TLS code lands); tools/kat.py per-source minimum-count guards.
- CI green on GitHub Actions (~2.5 min with cache).

## Next up
- M1b: `src/os/linux_rand.c` (getrandom per-arch syscall numbers -> /dev/random poll ->
  /dev/urandom, fail closed), then ChaCha20-Poly1305 (RFC 8439 + Wycheproof) via `/implement-module`.

## Decisions / gotchas
- Python's CA bundle rejects csrc.nist.gov; kat.py reuses `.cache/kat/*` (download with curl if
  needed). Every vector is re-verified with hashlib, so the source host doesn't matter.
- RFC 4231 TC3 has a typo ("Key" without "="); RFC 9001 TOC contains "A.1.  Keys" - both handled.
- ASan cannot link `-static`: the size probe is behind `-DBRISK_SIZE_PROBE=ON` (dev.py sets it).
- Hooks are exec-form `node` scripts; `python` (not `python3`) on the Windows host.
- The user's personal `.claude/settings.local.json` sets `ECC_GATEGUARD=off` (not committed).
