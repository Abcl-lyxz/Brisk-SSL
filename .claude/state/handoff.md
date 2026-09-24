# Handoff - 2026-09-24 (session 19)

## Done - M6 item 1 (QUIC packets, CRYPTO, transport parameters)
- 3f21602 **quic: packets + header protection, CRYPTO on the TLS 1.3 engine, transport
  parameters**. src/quic/packet.c (varint, PN, headers, Initial secrets, seal/open + HP) and
  src/quic/conn.c (TP codec, frames, CRYPTO reassembly per level, key discard,
  CONNECTION_CLOSE). Internal brisk__quic_* only. Knob BRISK_ENABLE_QUIC = FULL only; dev/dev32
  presets now build FULL, dev-tls13 builds DEFAULT (QUIC off, empty TUs).
- Built with /implement-module wf_d050ee15-053; its 3 reviewers died on the session limit AGAIN,
  so they were run by hand. Fixed: leftover CRYPTO at a key change -> PROTOCOL_VIOLATION (engine
  pseudo-alert 255 at both epoch checks); MAX_STREAMS/STREAMS_BLOCKED > 2^60, RETIRE_CID,
  NEW_CID to an empty DCID now close; open restores the protected header on AEAD failure; seal
  refuses pn < next_pn (nonce reuse) and sets the PN-length bits; pn_decode checks nbits; the
  32-bit CRYPTO-length test really hits the guard now. All guards mutation-tested.
- 11 archs green, ct64/ct32/ct32m clean. Size DEFAULT +48..+100 B (armv7hf -20), baseline not
  re-saved. QUIC in FULL costs 7.9-14.8 KB.

## In progress
- Nothing. Tree clean.

## Needs a user decision
- (still open) mTLS over TLS 1.2 with a `sign` callback fails closed; digest-scheme proposal
  postponed to M8.

## Next up
- **M6 item 2**: ACK, loss detection / PTO, NewReno (integer), flow control, streams + the
  public brisk_quic_* API. The ROADMAP line lists the stateful MUSTs rfc-auditor found (stream
  state/limit/flow-control errors, NEW_CONNECTION_ID limit + retire_prior_to, ACK and
  PATH_RESPONSE generation). Start it early in a session with /implement-module.

## Decisions / gotchas
- conn.c pkt_finish hard-codes a 4-byte PN because brisk__quic_send / cc_build lay the payload
  out at hl + 4. Once largest_acked exists, pass brisk__quic_pn_len's value through all three.
- The engine wipes c_ap/s_ap right after on_secret: key update (item 3) must keep the app
  secret in brisk__quic_conn.
- brisk__quic_conn_init does not check that the caller's iscid TP equals its scid (server
  rejects under 7.3) - fold into the public API in item 2.
- Before M7 adds another FULL-only knob, drop BRISK_PROFILE=FULL from the `base` preset so
  host x64 builds the shipped DEFAULT (TLS 1.2 on) again.
- dev.py size keys modules by object basename: tls/conn.c and quic/conn.c share one row.
- implement-module reviewers failing = no review. Run all 3 by hand; this time they found 1
  test bug, 2 RFC MUST issues and 4 crypto hardening items.
