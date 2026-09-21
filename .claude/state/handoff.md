# Handoff - 2026-09-21 (session 9)

## Done
- 326340b **x509: strict DER reader + fuzz target. M2 line 1 closed.** `src/x509/der.c`: zero-copy
  cursor, sticky error, X.690 clause 8/10/11 enforced; `brisk__der_walk` validates a whole value
  with its own 16-deep end stack, so attacker nesting never reaches the C stack. 884 vectors -
  337 real SPKIs from the cached Wycheproof suites, the 481 adversarial signature blobs of
  `ecdsa_secp256r1_sha256_test.json` (the DER sibling the p1363 API could not use), and one
  generated row per clause. `python tools/dev.py fuzz der` is new (clang+ASan/UBSan, corpus
  unpacked from der.inc, nothing extra committed): 20.1M execs clean. 11 archs + asan, ct32/ct64,
  baseline re-saved.

## In progress
- **`Certificate parse` (M2 line 2) is WRITTEN AND UNCOMMITTED.** New: `src/x509/cert.c`,
  `tests/test_x509.c`, `tests/kat/x509_cert.inc` (102 certs), `tests/kat/x509_time.inc` (41).
  Modified: `src/brisk_int.h` (the `x509/cert.c` block), `CMakeLists.txt`, `tests/test.h`,
  `tests/test_main.c`, `tests/size_probe.c`, `tools/kat.py`.
- Verified: host dev+dev32 10/10, TINY profile clean (9101 checks), Docker x86_64 + asan.
  **NOT verified: the 9 cross archs, `ct`, `size`.** The sweep was killed twice - once by the
  harness for host RAM pressure (9 parallel containers), once by the user.
- To finish: `python tools/dev.py test --arch all` (use `-j 3` if RAM is tight) -> `ct` ->
  `size --arch all --save` (cert is a NEW module: 3252 B armv7hf .. 6308 B mips, RAM unchanged)
  -> tick the ROADMAP box -> commit `x509:`. Nothing else is left to write.

## Next up
- Finish the above, then M2 line 3: `Chain building (unordered/extra certs, stop at first trust
  anchor), signature checks`. cert.c already hands it `tbs`/`sig`/`sig_alg`/`sig_hash`/
  `sig_salt_len`/`key_alg`/`key`, and issuer/subject as raw TLVs for a memcmp chain.

## Decisions / gotchas
- **Both reviewers earn their keep on this module; two rounds found real fail-open bugs.** Run
  `rfc-auditor` AND `portability-reviewer` on cert/chain code before every commit.
- **RSASSA-PSS: never require the DEFAULT fields.** RFC 4055 3.1 makes omitting `trailerField` a
  MUST for signers and accepting all four absent a MUST for validators. The first draft demanded
  all four present, i.e. it rejected every PSS certificate in existence. Same trap one level down:
  RFC 4055 5 says PKCS#1 v1.5 params MUST be accepted absent as well as NULL.
- **`key_usage == 0` means "absent" only if the BIT STRING LENGTH is bounded to 9.** Checking the
  octet count plus X.690 11.2.2 is not enough: a 2-octet string whose only set bit is >= 9
  satisfies both, harvests nothing, and chain code reads the 0 as unrestricted.
- **`brisk__der_walk` does not descend into an extnValue** - an OCTET STRING is a leaf. cert.c
  walks each recognised extnValue separately; without it a SAN entry with a BER length reaches
  the hostname matcher. Remember this when writing the names item.
- **32-bit `/` and `%` are allowed** (c-code.md bans 64-bit only) and `days_from_civil` uses four.
  A reviewer will flag `__aeabi_idivmod` on armv5/armv7hf; it is not a defect, do not "fix" it.
- `check_x509_source_constants()` in tools/kat.py verifies all 22 OIDs in cert.c against their
  dotted forms - add new OIDs to `X509_OIDS` there or the run dies.
