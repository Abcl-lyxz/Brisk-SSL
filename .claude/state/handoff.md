# Handoff - 2026-09-22 (session 13)

## Done
- 52799f1 **x509: CA bundle as a lazy trust store + additive SPKI pins. M2 line 6 closed.**
  `src/x509/bundle.c` is a sans-I/O PEM decoder (RFC 7468) - bytes in, one DER out, all state in
  `brisk__x509_pem`, BEGIN matched whole and ANCHORED to a line start (no differential against
  OpenSSL's `PEM_read_bio`). `src/os/linux_ca.c` autodetects among 6 distro paths, requiring a
  non-empty REGULAR file, and `brisk__os_ca_anchor` is a `brisk__x509_anchor_fn` that opens,
  scans, matches a subject Name and closes. `find_anchor`/`anchor_ctx` became one
  `const brisk__x509_trust *` carrying sha256 SPKI pins. 44 new vectors (base64 from RFC 4648
  s10; decoder fed at chunk sizes 1/2/3/7/64/whole).
- 0870d67 **x509: the walk became a depth-first search WITH BACKTRACKING. M2 line 7 closed.**
  `chosen[]` is the path and each level's resume position at once; `pin_mask` is a bitmask so an
  abandoned parent's pin contribution can be undone; `below` unwinds on backtrack.
  `BRISK__X509_MAX_LOOKUPS` (16) is a new budget - see gotchas. chain +152..+280 B, stack
  +40..+64 B, no RAM change. 11 archs + asan, TINY, STRICT, INSECURE_NO_TIME, ct all green;
  baseline re-saved after each commit.

## In progress
- Nothing. The tree is clean and pushed.

## Next up
- M2 line 8, the last one: **x509-limbo suite**. Expect it to hit path building hardest - that
  is what the two commits above just rewrote, so read the SEARCH STRATEGY block in
  `src/brisk_int.h` before starting. `tools/kat.py` has no downloader for it yet; `fetch()` at
  the top of that file is the pattern, and `tests/kat/SOURCES.md` is generated from it.

## Decisions / gotchas
- **Both reviewers found the SAME regression, and neither found it by reading the diff alone** -
  they modelled the cost. Backtracking moved the anchor block from "once per level" to "once per
  DESCENT", and a store lookup is NOT paid for out of `BRISK__X509_MAX_VERIFY` (a candidate
  refused on its Name or CA bits never reaches `++work`). With the CA bundle behind it that is
  an `open()` + a ~200 KB pass per miss, 33 of them per handshake. **Any new loop in chain.c
  needs its own budget question asked separately for I/O and for crypto.**
- **Mutation-test a vector that guards a fail-OPEN invariant.** `pin_mask &= ~(...)` and
  `below--` could both be DELETED with the whole suite green. The rows that now catch them
  (pin 12, chain 48) were each confirmed by removing the line and watching exactly one row fail.
  Same trick proved the three backtracking rows fail against `git show HEAD:src/x509/chain.c`.
- A `.c` file written into the scratchpad gets compiled by the post-edit hook AND reformatted at
  80 columns. Use `.txt` for a code fragment and splice it in, then `clang-format -i`.
- Still true: this Bash tool's heredoc eats backslashes AND runs backticks - patch scripts with
  either go through the Write tool.
- `x509-limbo` aside, the two remaining known gaps are recorded in the ROADMAP M8 lines:
  `fuzz_pem` has no harness, and `src/os/` has a feature-test-macro ordering blocker for the
  amalgamation.
