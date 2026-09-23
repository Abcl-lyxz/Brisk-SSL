# Handoff - 2026-09-23 (session 17)

## Done - M3 TLS 1.3 client is COMPLETE
- 5d0a8ab **crypto: multiply-free GHASH** (`BRISK_GHASH_MULFREE`, auto on armv4/5 + 32-bit MIPS).
  `brisk__ghash_mulfree` always compiled so every arch runs its KATs; ct suite covers it.
- e83e41f **tls: public client API.** `src/tls/conn.c` (sans-I/O `brisk_conn_init/feed/pull/
  app_read/app_write/close_notify/status/alpn/resumed/conn_wipe`), `src/os/linux_net.c`
  (`brisk_connect/read/write/close`, poll deadlines, per-address time slices, 64-bit time_t).
  New `BRISK_E_IO/E_TIMEOUT/E_WANT`. `brisk_conn_size()` ~42 KB; blocking ~48 KB/connection.
  Tests `conn` (all archs), `sock` (Linux); fuzz `conn`. Via /implement-module wf_892459cc-609.
- 4f71b10 **examples + interop.** `examples/brisk_get.c` (CLI), `aws_iot_https.c`,
  `mqtt_tls.c`. `python tools/dev.py interop` 18/18 (openssl s_server, nginx, Caddy);
  `python tools/dev.py badssl` 19/19 as expected. Dockerfile gained openssl/nginx/caddy.
- All pushed; 11 archs green, ct clean.

## In progress
- Nothing. Tree clean.

## Next up
- **M4 HTTP/2 line 1: HPACK** (RFC 7541): static table + literal encoder, decoder with dynamic
  table, Huffman decode (shared later with QPACK). Vectors: RFC 7541 Appendix C via /kat.
  Run it with /implement-module. h2 is an explicit optional module over a brisk_conn
  (`brisk_h2_open(c)`), never auto-switched; ALPN "h2" is the caller's choice.

## Decisions / gotchas
- badssl.com has NO TLS 1.3 host: its bad-cert rows prove nothing until M5 (TLS 1.2).
  revoked.badssl.com must flip to "expect success" at M5 (no CRL/OCSP by design).
- `brisk_close_notify` before CONNECTED is BRISK_E_ARG (abandon = brisk_conn_wipe).
- API returns int + out-param (`brisk_connect(&cfg, host, port, &c)`), never NULL-means-error.
- Open (ROADMAP line 4 notes): runtime cert-time floor not in brisk_cfg yet (must go through
  the x509 time check, never by raising `now`); sans-I/O stamps tickets with init time.
- Examples not yet run against a real AWS IoT account.
- implement-module review loop is capped at 3 rounds: the last round's findings are fixed but
  never re-reviewed - read the journal and check them by hand (one was missed this session).
- Git-bash mangles `docker -v` paths: use PowerShell for ad-hoc docker runs.
- Internal errors -> BRISK_E_ARG, never BRISK_E_PROTO; closure alert before CONNECTED ->
  BRISK_E_PEER_ALERT.
