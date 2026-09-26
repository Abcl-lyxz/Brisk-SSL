# Handoff - 2026-09-26 (session 24)

## Done - M9 box 1: key/chain formats
- 34a575f **tls:** new `cfg.client_key_len` field. Accepted key forms:
  - 0 or 32 = raw d (v0.1 compat);
  - SEC1 or PKCS#8, as DER or PEM, auto-detected; prime256v1 only.
  - The key is parsed once into `brisk_conn.key`, which is wiped on close and on setup failure.
  - `client_chain` may also be PEM. It is decoded straight into the hs output in two passes, with no per-conn buffer.
  - The strict constant-time base64 `brisk__x509_pem_block` in src/x509/bundle.c is shared with the streaming reader.
  - New files: src/x509/key.c, tests/test_key.c, fuzz/fuzz_key.c, tests/kat/{key,mtls_key}.inc (openssl via kat.py).
  - Examples now read PEM keys directly. Host tests and all 10 archs are green.
- Size: DEFAULT/FULL grew 3-4 KB flash, TINY 0.1-0.3 KB. **mips DEFAULT is at 138.1 of 144 KB budget**.

## In progress
- Nothing. The tree is clean.

## Next up - ROADMAP M9 box 2: custom transport
- `brisk_connect_fd`: the caller opens the socket/fd, and brisk_close does not close it.
- `brisk_connect_io`: send/recv callbacks, for UART, tunnels and tests.
- net_flush/net_fill go through an io vtable (src/os/linux_net.c, src/tls/conn.c).
- read/write must work for non-socket fds.
- Watch the mips DEFAULT flash headroom (6 KB left). The M9 compile-time knobs box is the way to buy some back.

## Decisions / gotchas
- The client_key_len==0 => raw 32 bytes rule is kept for v0.1 code, so the docs tell callers to refuse an empty key file themselves.
- The PEM chain limit counts decoded DER (BRISK_TLS_MAX_CLIENT_CHAIN). brisk_config.h now errors if that is greater than BRISK_TLS_MAX_HS_MSG.
- The all-arch run gets killed by low memory when it runs in the background. What works: run it in the foreground in two groups (4 archs, then 6) with `-j 2`, and poll the log with a foreground loop.
- EMS stays required (user, 2026-09-25): an old server gets a clear E_INSECURE.
- Live-run findings are in docs/TROUBLESHOOTING.md (badssl/hivemq E_INSECURE, mosquitto private CA).
- OpenWrt-built binaries need libgcc_s (weak __register_frame_info). It is not a Brisk bug.
- The Bash heredoc eats backslashes. Write code with the Write tool or use chr(92).
- Poll CI in the foreground (`gh run view ID --json status,conclusion`, sleep 60).
