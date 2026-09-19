# Handoff - 2026-09-20 (session 4)

## Done
- 5a439ff crypto: GHASH + AES-GCM. One file `src/crypto/gcm.c`: ctmul64 / ctmul32 GHASH picked
  by `#if BRISK__AES_CT64` (same split as aes_ct), AEAD_AES_128/256_GCM, 96-bit IV and 16-byte
  tag only, ct tag compare, output wiped on BRISK_E_AUTH. BearSSL 7bea48e5, MIT notice in the
  header and NOTICE. Vectors: CAVP GCMVS, Wycheproof (96-bit IV, AES-128/256), GHASH edge H
  values, differential set, RFC 9001 A.2/A.3 Initial packets; all re-checked against a Python
  SP 800-38D reference in tools/kat.py. 27/27 mutations caught. Flash +1.5 KB (armv7hf) ..
  +2.7 KB (MIPS32), RAM unchanged, baseline saved.
- 7007119 build: CT tooling. `BRISK__CT_SECRET` / `BRISK__CT_PUBLIC` in brisk_int.h (valgrind
  client requests, no-ops without -DBRISK_CT_CHECK), new `ct` suite in tests/test_ct.c,
  `python tools/dev.py ct`, skill `/ct-check`.

## In progress
- Nothing. Tree clean, all 13 presets green, `dev.py ct` green.

## Next up
- M1c: vendor fiat-crypto `curve25519_{32,64}` and `p256_{32,64}` into `vendor/fiat/` untouched
  (a hook blocks edits there) + `vendor/VENDORED.md` with the upstream commit and license +
  NOTICE. Then X25519 (RFC 7748, incl. the 1,000-iteration test, reject all-zero output).
  Use `/implement-module` with the ROADMAP line as the task text.

## Decisions / gotchas
- `dev.py ct` is x86_64-only (valgrind cannot run under qemu-user), so it builds twice: native
  and `-DBRISK__AES_CT64=0` to cover the 32-bit AES/GHASH C. brisk_int.h now only defines
  BRISK__AES_CT64 `#ifndef`, which is what makes that override possible.
- Add every new primitive to tests/test_ct.c or it is simply not checked. If a run looks
  suspiciously clean, inject `if (secret16[0] == 0x5A) { t_checks++; }` into test_ct() and
  confirm both variants FAIL (that is how this one was verified).
- Only one BRISK__CT_PUBLIC exists: the brisk__ct_memeq result (a failed tag check is public).
  A second one needs a written reason.
- Still open, now with a documented plan in ARCHITECTURE.md: armv5 / MIPS32 4K early-terminating
  multipliers leak H through GHASH timing. Valgrind cannot see it. When M3 lands, those targets
  get a multiply-free GHASH or no AES-GCM in the default ClientHello.
- Reviewer round found 3, 2 confirmed (static `too_long` name clash with chacha20_poly1305.c for
  the future amalgamation; the ARCHITECTURE wording above). The workflow hit the session limit in
  its fix phase - the fixes, tests, size and commit were finished by hand.
- Earlier deferred items still open: HMAC ctx use after failed init/final; kat.py per-source
  minimum-count guards; hand-check of the -Os aes_ct disassembly on mips/armv5.
- Cost: the implement-module workflow used ~665k subagent tokens for GCM.
