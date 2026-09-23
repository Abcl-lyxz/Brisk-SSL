# Handoff - 2026-09-23 (session 16)

## Done
- da17163 **tls: TLS 1.3 client handshake engine, sans-I/O.** `src/tls/handshake.c`: CH/SH/HRR/EE/
  CR/Certificate/CertificateVerify/Finished, transcript, epochs, secrets out, QUIC transport
  params (RFC 9001 8.2). `brisk__x509_ecdsa_raw` exported from chain.c. New `BRISK_E_PROTO`,
  `BRISK_TLS_MAX_HS_MSG`. Fuzz target `tls13_hs`.
- 04cbb86 **tls: record layer, KeyUpdate, alerts, close_notify.** `src/tls/record.c`:
  `brisk__tls_rec_seal/open` + sans-I/O `brisk__tls13_conn` driver. Post-handshake NST
  (`cfg.on_ticket`) and KeyUpdate handled. Own record_size_limit (RFC 8449) enforced inbound.
  Fuzz target `tls13_rec`.
- 5952de0 **tls: PSK tickets, ALPN list, SNI, mTLS ECDSA P-256.** New `src/tls/ticket.c` (blob
  export/import), binder, obfuscated age, ALPN must match offer, SNI never an IP literal, client
  auth flight. New knob `BRISK_TLS_MAX_CLIENT_CHAIN` (4096, mTLS builds only). Fuzz `ticket`.
- All three: 11 archs green, ct ok, fuzz clean, size baseline re-saved (TOTAL flash now
  53-100 KB: x86_64 70583, armv7hf 52972, mipsel 99780).

## In progress
- Nothing. Tree clean and pushed.

## Next up
- **Multiply-free GHASH (user decided, see docs/ARCHITECTURE.md "Crypto choices").** In
  src/crypto/gcm.c add a shift + masked-XOR GHASH, chosen by a new tri-state knob in
  include/brisk_config.h (auto = on for armv5 and 32-bit MIPS). Same SP 800-38D/Wycheproof
  vectors must pass with the knob forced on for every arch; ct check must stay clean. Do this
  before line 4; the user said not to start line 4 yet.
- Then M3 line 4: `src/os/` sockets + public API `brisk_connect/read/write/close`, sans-I/O
  `brisk_feed/pull`. The line-4 arena must keep the handshake reassembly scratch alive for
  post-handshake messages (or skip NSTs that do not fit).

## Decisions / gotchas
- **implement-module build step hit the session limit twice** (record layer, line 3). Resume
  with `Workflow({scriptPath, resumeFromRunId})` works: spec replays from cache, build picks up
  the partial tree. A `review round 1: found 3, confirmed 0` result with `build: null` means
  nothing was reviewed - ignore it.
- **Safety filters refused some reviewer/verify agents** (crypto-reviewer r1 on line 3, two
  verify agents). Empty verify results were checked by hand; all were already fixed. Later in
  the session auto mode's classifier blocked Bash entirely; switching to default permission
  mode unblocked it.
- Internal errors map to `BRISK_E_ARG` (alert 80), never `BRISK_E_PROTO` - protocol errors blame
  the peer, local faults do not.
- A closure alert before CONNECTED is `BRISK_E_PEER_ALERT`, never a clean EOF.
