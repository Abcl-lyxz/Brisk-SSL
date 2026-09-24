# Handoff - 2026-09-24 (session 18)

## Done - M5 TLS 1.2 client is COMPLETE
- 829223b **tls: TLS 1.2 client** (src/tls/tls12.c, PRF in hkdf.c, 1.2 records + CCS gate in
  record.c). One ClientHello offers 1.3 + 1.2; ECDHE + AEAD only, EMS + renegotiation_info
  required, downgrade sentinel checked. Knob BRISK_ENABLE_TLS12 (off in TINY, preset dev-tls13).
  New `brisk_tls_version()`; auth callback got a `version` param. Via /implement-module
  wf_16e3c45c-ece; its reviewers died on the session limit, so review was run by hand:
  rfc-auditor found 1.3 SH/HRR picking an offered 1.2 suite accepted (fixed + 2 kat rows),
  portability: HS_SHARED (helpers static when TLS12=0), test guard for TLS12 && !P384.
- 11 archs green, ct clean, interop 57/57, size baseline saved (+5.3..9.9 KB DEFAULT).

## In progress
- Nothing. Tree clean.

## Needs a user decision
- mTLS over TLS 1.2 with a `sign` callback fails closed (internal_error): the callback signs raw
  tbs bytes, TLS 1.2 signs the whole transcript. Proposal: a digest scheme (e.g. 0xFE03) = a
  public API change. `client_key` works.

## Next up
- **M6 QUIC v1 client**, first ROADMAP item: packets + header protection, CRYPTO frames on the
  TLS 1.3 engine, transport parameters. Run with /implement-module early in a session.

## Decisions / gotchas
- badssl.com hosts send NO extended master secret (openssl s_client: "Extended master secret:
  no"), so with EMS required every badssl row fails with handshake_failure - incl. revoked.
  The table in dev.py expects that; the "flip revoked to success" plan is void.
- Known limit: P-384 ECDSA leaf + SKE scheme 0x0403 is refused (P-384 verify needs >= 48-byte
  digest). We don't offer secp384r1, so RFC 8422 5.1 servers shouldn't pick it. Fails closed.
- TINY grew 136..220 B from shared-code restructuring (not byte-identical any more).
- implement-module: reviewer agents failing = no review happened. Always run rfc-auditor /
  crypto-reviewer / portability-reviewer by hand then (it found a real bug again).
- Earlier: `brisk_close_notify` before CONNECTED is E_ARG; API is int + out-param; runtime
  cert-time floor still not in brisk_cfg; examples not run against real AWS IoT.
