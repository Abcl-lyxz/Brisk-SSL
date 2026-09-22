# Handoff - 2026-09-22 (session 10)

## Done
- 2335876 **x509: certificate parser. M2 line 2 closed.** The work session 9 left uncommitted,
  finished: 11 archs + asan green, ct32/ct64 clean, baseline re-saved (cert is 3388 B armv7hf ..
  6456 B mips, RAM unchanged).
- 8fd9868 **x509: chain building + signature checks. M2 line 3 closed.** New `src/x509/chain.c`
  (838 B armv7hf .. 1636 B mips): `brisk__x509_chain_verify` walks upward, asking the trust
  store BEFORE the peer's list at every level, trying every same-Name candidate; and
  `brisk__x509_signed_by`, which hashes the TBS and strictly decodes the ECDSA-Sig-Value /
  RSAPublicKey. 48 new vectors (36 chains + 12 signature rows). 11 archs + asan, TINY, ct green,
  baseline re-saved.

## In progress
- Nothing. The tree is clean and pushed.

## Next up
- M2 line 4: `RFC 9525 hostname / IP matching`. `cert.c` already hands over `san` (the
  GeneralNames CONTENTS, NULL when absent) and `subject` as a raw TLV; nothing looks inside a
  GeneralName yet, so the DNS/IP alphabet checks, the embedded-NUL and control-character
  rejection, and the single-leftmost-label wildcard rule all belong to the new module.

## Decisions / gotchas
- **Both reviewers still earn their keep - run `rfc-auditor` AND `portability-reviewer` on every
  x509 change.** This round they found: the trust anchor being wrongly held to 6.1.4 (k)'s
  version rule, and an unbounded `n_certs` turning one handshake into 8 x n RSA-4096 verifies
  (now `BRISK__X509_MAX_VERIFY`). Neither shows up in a test that only asks "does the chain
  build".
- **A trust anchor is a Name and a key (RFC 5280 6.1.1 (d)), not certificate i of 6.1.3.** So a
  v1/v2 root in a legacy bundle is accepted; cA, keyCertSign and pathLen are still applied.
- **Stack is now the binding constraint, not flash.** Measured end-to-end at 4096-bit RSA:
  3784 B armv7hf, 3872 mips, 4176 x86_64 (the table is in the chain.c block of brisk_int.h).
  Anything added to this call chain must be re-measured with `-fstack-usage`.
- **Sizing a buffer by config while its length comes from caller data is how a stack overflow
  gets written.** `raw[64]` under BRISK_ENABLE_P384=0 plus an issuer whose key_alg said P-384
  would have written 96 bytes; the guard has to sit where `flen` is chosen.
- **kat.py is one namespace.** A new generator that redefines an existing constant silently
  rewrites OTHER tables - `KU_KEY_CERT_SIGN` (a decoded bitmask) vs the bit numbers x_named_bits
  wants. Diff `tests/kat/*.inc` against HEAD after touching tools/kat.py.
- Do not write .c fragments into the scratchpad: the post-edit hook formats them with default
  clang-format (2-space, reflowed comments) and that style then travels into the repo file.
- **M8 amalgamation hazard, pre-existing:** `src/crypto/aes_ct.c` and `aes_ct64.c` both define
  static `ortho`, `bswap32`, `sbox`, `sub_word`, `skey_expand`, `add_round_key`, `mix_columns`,
  `shift_rows`. Two of those files in one TU will not link.
