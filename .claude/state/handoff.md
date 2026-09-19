# Handoff - 2026-09-19 (session 2)

## Done
- 89768a7 os: kernel RNG `src/os/linux_rand.c` - getrandom via own per-arch syscall table
  (#error-checked vs SYS_getrandom), pre-4.8-only /dev/random-wait -> /dev/urandom fallback,
  write-once `seeded` latch, UNAME26 refused, fail closed (BRISK_E_RNG). Fault-injection tests via
  -Wl,--wrap=syscall,poll,uname,personality; 14 mutations caught. 3 review rounds.
- a29e4c9 crypto: ChaCha20 / Poly1305 / AEAD (RFC 8439) `src/crypto/chacha20_poly1305.c` +
  tests/test_aead.c; RFC 8439, Wycheproof, differential, RFC 9001 A.5. New BRISK_E_AUTH.
  dev.py FORBIDDEN also covers __muldi3 and 64-bit shift helpers. Size baseline saved.
- All green on 13 presets.

## In progress
- Nothing.

## Next up
- M1b: AES-128/256 constant-time bitsliced (ct on 32-bit, ct64 on 64-bit), encrypt-only
  (BearSSL-style aes_ct/aes_ct64: keep MIT notice in file header + NOTICE). Then GHASH + GCM.
  Use `/implement-module`.

## Decisions / gotchas
- RNG: fallback only when kernel < 4.8 (OpenSSL's cut-off): from 4.8 a readable /dev/random
  does not mean urandom is seeded, so seccomp-blocked getrandom there -> BRISK_E_RNG.
  personality(0xffffffff) returns -1 under qemu-user on 32-bit targets: treated as "unknown".
- The rand test's `fallback_gate()` must run first in the process (latch can't be reset).
- ChaCha20 rounds stay unrolled: rolling saved only 210-430 B and costs speed on MIPS/ARM.
- Poly1305 poly_finish's last h0->h1 carry is unreachable by vectors (~2^-100); keep it.
- Reviewer agents sometimes return empty findings or get blocked by the API cyber safeguard:
  verify with a mutation run instead of trusting "0 findings".
- Earlier deferred items still open: HMAC ctx use after failed init/final; kat.py per-source
  minimum-count guards.
- Session cost ran ~$80; the implement-module workflow is ~380k subagent tokens per module.
