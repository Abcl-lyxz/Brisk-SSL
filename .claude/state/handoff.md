# Handoff - 2026-09-24 (session 17, continued)

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
- 0e2cb9b **http: HPACK** (src/http/hpack.c + huffman.c, knob BRISK_ENABLE_H2, off in TINY).
- 52ead49 **http: HTTP/2 client** (src/http/h2.c, blocking brisk_h2_* API - user chose simple
  blocking + 4 streams). 3 rfc-auditor findings fixed (padding double credit, 1xx flood cap 16,
  FRAME_SIZE_ERROR). New BRISK_E_RETRY, knobs BRISK_H2_MAX_STREAMS / BRISK_H2_STREAM_WINDOW.
- **M4 HTTP/2 COMPLETE**: h2 interop 35/35 (nginx, h2o, nghttpd; examples/h2_get.c).
- All pushed; 11 archs green, ct clean.

## In progress
- Nothing. Tree clean.

## Next up
- **M5 TLS 1.2 client** (first ROADMAP item under M5): ECDHE + AEAD only, EMS required,
  renegotiation refused, downgrade sentinel checked (docs/ARCHITECTURE.md Security defaults).
  Run it with /implement-module; afterwards flip badssl expectations (revoked -> success).

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
- h2o runs as `nobody` in the interop container: its files must live outside /src/build
  (pid in /tmp). The Docker image builds h2o from source - needs free RAM.
- Git-bash mangles `docker -v` paths: use PowerShell for ad-hoc docker runs.
- Internal errors -> BRISK_E_ARG, never BRISK_E_PROTO; closure alert before CONNECTED ->
  BRISK_E_PEER_ALERT.
- implement-module agents can die on the session limit mid-review: failed verify agents mean
  UNVERIFIED findings - read the journal and check them by hand (2 were real this time).
- h2 flood counter resets on every blocking call (callers retry on TIMEOUT), so per-object caps
  (1xx per stream) are needed where a peer can repeat forever.
- QPACK (M7) must prefix its static helpers (qp_*): hpack.c names clash when amalgamated.
