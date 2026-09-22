# Handoff - 2026-09-23 (session 15)

## Done
- 3ee1b16 **tls: TLS 1.3 key schedule + Finished MAC + exporter (M3, first slice).**
  New `src/tls/keyschedule.c`: `brisk__tls_ks_init/_derive_handshake/_derive_application/
  _derive_resumption/_exporter/_wipe` + `brisk__tls_finished_mac`. Pure composition over
  `brisk__hkdf_extract` and `brisk__hkdf_expand_label`; no secret ever reaches a branch,
  intermediates wiped on every path. Decls in `src/brisk_int.h` (RFC 9846 sect 7.1/4.5.3/7.5
  cited). `tests/test_tls13_ks.c` drives the whole cascade against the RFC 8448 sect 3 trace
  (SHA-256, TLS_AES_128_GCM_SHA256) with the ten stage outputs LIFTED VERBATIM from
  `expand_label.inc/hkdf_extract.inc`, plus a SHA-384 self-consistency run and a PSK-present
  init. 11 archs + asan green; TOTAL flash +1.2 KB (x86_64) to +2.4 KB (mips), the whole
  delta is the new module, no libgcc/float helpers.

## In progress
- Nothing. Tree is clean and pushed.

## Next up
- **M3 line 1, second half: handshake messages + epochs + HRR.** Key schedule is done and
  waiting; this slice wires ClientHello, ServerHello, EncryptedExtensions, Certificate,
  CertificateVerify, Finished into a sans-I/O state machine, owns the transcript hash, tags
  outbound bytes by epoch (initial / handshake / application), and handles HRR (retry with
  the peer-chosen group). Cite **RFC 9846**, NOT 8446. Handshake engine hands `dhe`, `th_ch_sh`,
  `th_ch_sf`, `th_ch_cf` into the keyschedule helpers this session landed. Big task -
  `/implement-module M3 line 1 second half` with the full workflow.

## Decisions / gotchas
- **Reviewer coverage on 3ee1b16 was thin.** The implement-module workflow's crypto-reviewer
  round 1, crypto-reviewer round 3 and rfc-auditor round 3 all tripped Claude's cyber
  safeguards mid-run (`[cyber]`). Rounds 1-2 still confirmed 4 findings which the fix loop
  addressed; round 3 had one clean reviewer and no independent second opinion. The code is
  pure HKDF composition against an official trace, so risk is low, but a fresh `/audit
  src/tls` or a manual crypto-reviewer pass before the record layer commit is cheap insurance.
- **`brisk__tls_ks` carries `secret[BRISK_HASH_MAX_LEN]` and no length field**, because the
  algorithm is stored alongside and `brisk_hash_len(ks->alg)` is authoritative. The struct
  size is public-config-independent per project rule. Advancing stages `memcpy`s the new
  secret into `ks->secret` and wipes the local; the caller only sees derived outputs.
- **`brisk__tls_finished_mac` wipes `finished_key` before return on every path.** The compare
  against the peer's verify_data must stay in the handshake engine as `brisk__ct_memeq`;
  keyschedule.c never touches peer bytes.
