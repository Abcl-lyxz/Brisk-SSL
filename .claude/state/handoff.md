# Handoff - 2026-09-22 (session 12)

## Done
- 56effd5 **x509: the validity window and its time policy. M2 line 5 closed.**
  `BRISK_X509_TIME_POLICY` = STRICT / FLOOR (default) / INSECURE_NO_TIME plus
  `BRISK_X509_TIME_FLOOR` (build date, 2026-09-01 by default, never `__DATE__`) in
  `include/brisk_config.h`; `brisk__x509_time_ok` in `src/x509/chain.c`;
  `brisk__x509_chain_verify` gained an `int64_t now`. 20 policy vectors
  (`tests/kat/x509_validity.inc`, all three columns per row) + 7 chain rows. CMake has a
  `BRISK_X509_TIME_POLICY` cache variable, so `cmake --preset dev -DBRISK_X509_TIME_POLICY=STRICT`
  runs the other columns. chain.c +72 (riscv64) .. +244 (mips) B, RAM unchanged. 11 archs +
  asan, TINY, STRICT, INSECURE_NO_TIME, ct all green; baseline re-saved.

## In progress
- Nothing. The tree is clean.

## Next up
- M2 line 6: `CA bundle autodetect + lazy lookup; SPKI sha256 pins (additive)`. The anchor
  callback it plugs into already exists and is documented: `brisk__x509_anchor_fn` in
  `src/brisk_int.h` (lookup by issuer Name, `index` walks same-Name roots, returning any
  negative code means "no more") - that signature was designed for exactly this, so the bundle
  scans its file per lookup instead of parsing every root into RAM. `spki`/`spki_len` in
  `brisk__x509_cert` is already the whole SubjectPublicKeyInfo TLV a sha256 pin hashes.
  File reading belongs in `src/os/`; nothing outside it may touch a syscall.

## Decisions / gotchas
- **Both reviewers earn their keep again - run `rfc-auditor` AND `portability-reviewer` on every
  x509 change.** rfc-auditor caught a real regression: validity was checked one level LATE, so
  an expired same-Name sibling shadowed the live intermediate and a buildable chain failed. The
  rule: in that walk, every path property is a SELECTION predicate on the candidate
  (`name_eq`, `usable_ca`, now the window) - anything checked after the walk commits silently
  removes the backtracking the candidate loop was written to provide. portability-reviewer
  caught `tests/size_probe.c` still calling the 4-argument `chain_verify`, which breaks
  `dev.py size` on every arch - **any signature change has to touch that file too**.
- **A KAT row can drift to the wrong side of a constant and still pass.** One row meant to pin
  the `now == notBefore` boundary sat below the floor, where notBefore is never read: the oracle
  simply relabelled it and nothing failed. `row()` in `x509_validity_vectors()` now takes
  `clock="usable"|"unset"` and dies if `now` is on the other side. Any future vector table built
  around a threshold owes the same assertion.
- The floor is compile-time only. A persisted last-known-good time must NOT be passed as `now`
  instead (it lifts the clock above the floor, so notBefore is enforced against a stale value and
  every fresh certificate is refused) - a runtime floor is an M3 client-config decision.
- Still true from session 11: this Bash tool's heredoc eats backslashes, so patch scripts with
  escapes go through the Write tool; and .c fragments must not be written into the scratchpad.
