# Handoff - 2026-09-27 (session 25)

## Done - M9 boxes 2-4 (all 10 archs green, host + amalg + ct)
- 944af08 **tls:** brisk_connect_fd / brisk_connect_io (custom transport).
- 35a2aeb **crypto:** public crypto API (BRISK_ENABLE_CRYPTO_API), src/crypto/api.c + linux_rand.c.
- f32b2de **crypto:** algorithm knobs AESGCM/AES256/CHACHA/X25519/P256_KX/RSA + BRISK_AES_IMPL.
- bc4ac35 **tls:** feature knobs TICKETS/PEM/SYSTEM_CA/CUSTOM_IO; brisk_build_info appends " -rsa ...".
- 5ad670c **tls:** brisk_strerror (ERROR_STRINGS, off in TINY = name only) + cfg.keylog (KEYLOG, off everywhere).
- Size: mips DEFAULT 140.4 of 144 KB (knobs off free up to 8.9 KB x25519 / 5.2 AES+GCM / 3.4 ChaCha).

## In progress
- Nothing. Tree clean.

## Next up - ROADMAP M9 box "Runtime cfg"
- min/max version, suites/groups preference strings, SNI override, SPKI pins (on top of chain
  verification), time_floor, record_size_limit (RFC 8449 - the engine already honours the
  server's). rfc-auditor clean.
- Open design questions to ASK the user first (not decided yet):
  1. suites/groups format: comma short names like ALPN ("chacha,aes128" / "x25519,p256") vs
     IANA names vs uint16 arrays - recommend comma short names.
  2. SNI override: cfg.sni NULL = host, "" = omit, else send it while still verifying `host`?
  3. SPKI pin scope: SHA-256 of SPKI matching any cert of the verified chain vs leaf only.
- New fields go at the END of brisk_cfg (0/NULL = default); note the ABI change for 0.2.

## Decisions / gotchas
- Knobs (user, 2026-09-26): on in every profile, only explicit 0 drops one - MTI ones too,
  documented non-conformant. Off = empty TU + fail-closed static inline stubs in brisk_int.h
  (callers keep one code path; clang warns on an UNUSED static inline in the amalgamation -
  gate a stub whose only caller is optional, like brisk__chacha20 under QUIC).
- The CMake test suite needs every algorithm knob on (byte-exact ClientHello replays); knob-off
  builds are covered by tests/test_knobs.c in the `dev.py amalg` matrix (KNOBS_OFF).
- P256_KX=0 + TLS 1.2: a conforming server will not do ECDHE_ECDSA with a P-256 cert (RFC 8422 5.3).
- GHASH width is BRISK__GHASH64, independent of BRISK_AES_IMPL (dev.py ct passes both =0 for ct32).
- Python edits on Windows: write bytes (read_bytes/write_bytes) or CRLF sneaks in; run
  clang-format -i on files edited outside the Edit tool.
- Don't edit src/ while a Docker arch run is going: the containers compile the live tree.
- All-arch: two groups (4 then 6) with -j 2; a chained background command works.
- EMS stays required (user, 2026-09-25). Bash heredoc eats backslashes: use the Write tool.
