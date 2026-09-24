# Handoff - 2026-09-25 (session 20)

## Done - M6 items 2 and 3
- bc13c98 **quic: ACK, loss recovery, streams + flow control**. New src/quic/recovery.c (ACK
  ranges, RTT, loss/PTO, integer NewReno) and src/quic/stream.c (stream table, flow control,
  STREAM_STATE/LIMIT/FLOW_CONTROL/FINAL_SIZE). conn.c: coalescing builder, variable PN length,
  NEW_CID limits + retire_prior_to, PATH_RESPONSE, idle, pacing, deadline/close. Review fixes:
  last 2 sent records reserved for PTO probes; the anti-deadlock PTO stays armed after the
  Initial space is dropped (a handshake stalled to idle); deadline() = now when a probe or a
  PATH_RESPONSE is owed; the preferred_address CID is seq 1 in cids[1].
- 7a7da6d **quic: Retry, VN, stateless reset, key update**. Review fixes: self-initiated key
  update keeps the old rx keys until a new-phase packet (QC_KU_WAIT); next local update waits
  3*PTO after the confirming ACK (ku_ack_at); reset token only for a CID we have sent on
  (dcid_unsent); VN/Retry only as the first packet of a datagram.
- Both: 11 archs green, ct clean, fuzz quic_pkt clean. DEFAULT size unchanged (QUIC is FULL
  only; still the item-1 +48..+100 B vs baseline, not re-saved). FULL: recovery+stream
  +8.5..18 KB, item 3 +3.6..4.5 KB; sizeof(brisk__quic_conn) 6.8 KB, scratch ~47 KB (x86_64).

## In progress
- Nothing. Tree clean.

## Needs a user decision
- **Public QUIC API shape** (blocks the interop harness): brisk_quic_connect/stream_open/
  read/write/close over UDP in src/os + sans-I/O feed/pull, caller-owned memory via
  brisk_quic_size(). Ask before writing include/brisk.h.
- (still open) mTLS over TLS 1.2 with a `sign` callback fails closed; digest-scheme proposal
  postponed to M8.

## Next up
- **M6 item 4**: quic-interop-runner harness (hq-interop), after the public API decision.
  It needs the public brisk_quic_* API + a UDP driver in src/os/.

## Decisions / gotchas
- Contract: call brisk__quic_send after every recv (a Retry's resent ClientHello is not in
  deadline()). Public API must hide this.
- Deliberate: lost data is re-queued at once; RFC 9002 7.4 MAY not taken; 1-RTT PTO probe
  sends new data or PING; next rx keys derived 3*PTO after promote (6.3 MAY, not ~1 PTO).
- Untested defensive guard: qc_ku_opened refuses to promote when rx_ku.suite == 0.
- Before M7 adds another FULL-only knob, drop BRISK_PROFILE=FULL from the `base` preset.
- dev.py size keys modules by object basename: tls/conn.c and quic/conn.c share one row.
- /implement-module died on the session limit in BOTH runs (reviewers, then fix:r2). Hand-run
  rfc-auditor found 3 real bugs in item 2. kat.py once hit Errno 22 writing hpack.inc (file
  lock) - just rerun it.
