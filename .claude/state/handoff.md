# Handoff - 2026-09-22 (session 14)

## Done
- 26cb78d **x509: x509-limbo folded into the chain KAT set. M2 X.509 IS DONE.**
  96 kept of 9793 after two filters. `tools/kat.py` gained an SRC entry for `limbo.json`,
  `pem_to_der`, `iso_to_epoch`, `x509_limbo_vectors` (~130 lines). NOT cross-checked in
  Python: limbo verdicts are validator answers, not "primitive f(x) = y" rows a Python oracle
  can recompute; the check is structural (PEM parses, chain shape fits) and semantic (the
  walk's answer matches). `tests/test_x509.c` gained `limbo_load` + `t_limbo`; the loader is
  DELIBERATELY permissive - a cert our parser refuses is skipped, not a fixture error, so
  `webpki::forbidden-p192-root` and `rfc5280::unknown-critical-extension-unrelated-root` both
  work through the same door a real caller would use. 11 archs + asan green; no library-side
  change so size delta is zero.

## In progress
- Nothing. Tree is clean and pushed. M2 is closed.

## Next up
- **M3 line 1: TLS 1.3 handshake engine** (messages + epochs, exports secrets, HRR, key
  schedule). Cite **RFC 9846**, NOT 8446 - 8446 is obsoleted. `include/brisk.h` has stubs for
  `brisk_connect/read/write/close` and `brisk_feed/pull` that this feeds into. Key schedule
  reuses `brisk__hkdf_expand_label` from M1a (RFC 8448 vectors already in
  `expand_label.inc`). Start with `/implement-module M3 line 1` - big task, needs the full
  workflow.

## Decisions / gotchas
- **x509-limbo's `validation_time` is almost always below `BRISK_X509_TIME_FLOOR`** (9604 of
  9793 carry a 2023-2024 time; FLOOR is 2026-09-01). `x509_limbo_vectors` bumps sub-floor
  times to FLOOR+60s; four `bettertls::pathbuilding::tc{5,12,38,44}` cases whose SUCCESS side
  depends on a cert expiring between the authored time and the floor are in
  `LIMBO_UNSUPPORTED_IDS`. `rfc5280::validity::*` dropped as an id-prefix for the same reason.
- **Anchor/intermediate parse failures are absorbed by the loader, not fixture bugs.** A limbo
  case may deliberately hand a validator a malformed cert (P-192 root, unknown critical
  extension); the loader skips it and lets the walk continue on the parseable subset. That is
  what a real caller does over the wire.
- **CABF strictness beyond RFC 5280 is a deliberate divergence, not a bug.** Nine specific ids
  in `LIMBO_UNSUPPORTED_IDS` (`webpki::malformed-aia`, `webpki::v1-cert`, `webpki::ee-
  basicconstraints-ca`, `webpki::ca-as-leaf`, `webpki::forbidden-rsa-not-divisible-by-8-*`).
  Brisk sits at the RFC 5280 layer; adding CABF is a policy decision, not this milestone.
