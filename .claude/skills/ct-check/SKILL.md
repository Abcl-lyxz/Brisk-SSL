---
description: Brisk-SSL constant-time check - run the ct suite under valgrind (ctgrind) so any branch, memory index or division that depends on a secret is reported. Use after touching src/crypto/ or any code that handles keys.
argument-hint: ""
---
# Constant-time check

Run `python tools/dev.py ct`. It builds the tests with `-DBRISK_CT_CHECK` in Docker and runs the
`ct` suite under valgrind, twice: `ct64` (native variant) and `ct32` (`-DBRISK__AES_CT64=0`, the
32-bit AES/GHASH code). A finding prints the offending line plus the `BRISK__CT_SECRET` call that
marked the value, and exits non-zero.

- A new primitive is only covered once it is called from `tests/test_ct.c` with its key, secret
  input and context marked `BRISK__CT_SECRET`. Public values (nonce, AAD, ciphertext, tag,
  lengths) stay unmarked - that is what makes a report meaningful.
- Fix a report in the code: replace the branch with a mask, the table lookup with a bitsliced or
  full-scan access, the `/` or `%` with shifts. Never by marking the secret public.
- `BRISK__CT_PUBLIC` is only for a value the protocol reveals anyway. There is one today, the
  `brisk__ct_memeq` result in `src/util.c` (the peer learns a bad tag from the alert). Adding a
  second one needs a line in the commit message saying what makes it public.
- What this does NOT catch: data-dependent instruction timing in hardware - the early-terminating
  multipliers on armv5 / MIPS32 4K noted in `docs/ARCHITECTURE.md`, cache and branch predictor
  effects. Valgrind checks the code's data flow, not the CPU.
- Sanity: it is easy to end up checking nothing. If a run is suspiciously clean after a big change,
  add `if (secret16[0] == 0x5A) { t_checks++; }` to `test_ct()`, confirm both variants FAIL, and
  remove it again.
