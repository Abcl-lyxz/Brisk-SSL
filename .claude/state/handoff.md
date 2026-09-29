# Handoff - 2026-09-29 (session 26)

## Done - M9 finished, v0.2.0 released (all 11 Docker presets + host + amalg green)
- e1996d8 **tls:** runtime policy in brisk_cfg - suites, groups, sni, pins/n_pins, time_floor,
  min_version (tests/test_conn.c conn_policy, every guard mutation-checked; rfc-auditor +
  portability-reviewer, 2 findings fixed). mips DEFAULT 141.4 KB of 144.
- b97087f **docs:** examples/tcp_tls_embedded.c (ISRG Root X1 as xxd array + brisk_connect_fd;
  live: letsencrypt.org OK, example.com E_AUTH), README "Certificates without files".
- 9836010 **build:** version 0.2.0; tag v0.2.0 pushed; GitHub release with dist/brisk.{c,h}.
- d9a1189 **build:** OpenWrt package pinned to v0.2.0 (commit + PKG_MIRROR_HASH, SDK-verified).

## In progress
- Nothing. Tree clean, every ROADMAP box through M9 ticked.

## Next up
- No milestone left: /next must propose one from ROADMAP `## Backlog` (options + recommendation),
  ask the user, then write it as `## M10 ...` with `- [ ]` tasks.
  Candidates: sign callback over TLS 1.2, TLS 1.3 external PSK, public X.509 API, AES HW accel,
  .so build / OCSP stapling.

## Decisions / gotchas
- Runtime cfg (user, 2026-09-29): comma short names ("chacha,aes128,aes256" / "x25519,p256"),
  sni NULL=host / ""=none / else sent (cert still checked against host), pins = any cert on the
  verified path incl. anchor. Skipped on purpose: max_version (1.3 always offered) and our own
  record_size_limit (receive buffer is fixed full size).
- sni != host => tickets neither offered nor kept (RFC 9846 4.7.1, rfc-auditor finding).
- time_floor lives in brisk__x509_trust; chain.c time_ok(c, now, floor); non-zero is BRISK_E_ARG
  under INSECURE_NO_TIME. Any local brisk__x509_trust must set time_floor (32-bit test caught it).
- TLS 1.2 suites are derived from the TLS 1.3 list (handshake.c SUITES12), same default bytes.
- HOST TOOLCHAIN: since the msys2 update (2026-09-28) ucrt64 gcc is first on PATH and dev32 cannot
  link ("ld returned 5"). Run `PATH=/c/TDM-GCC-64/bin:$PATH python tools/dev.py test`; rm the
  build/dev* dirs if configured with the wrong gcc. User may want to fix PATH order.
- Bash heredoc still eats backslashes ('\0' became a NUL byte): write C via Write/Edit.
- OpenWrt pin flow: tag -> Makefile commit + PKG_MIRROR_HASH:=skip -> SDK `download` then
  `check FIXUP=1` -> paste hash -> fresh download + compile to verify.
- Don't edit src/ while a Docker arch run is going (containers compile the live tree).
