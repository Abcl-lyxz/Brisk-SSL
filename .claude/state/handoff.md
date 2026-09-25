# Handoff - 2026-09-25 (session 21)

## Done - M6 item 4 (M6 complete)
- 3244654 **quic: public brisk_quic_* API + hq-interop harness**. include/brisk.h QUIC section:
  sans-I/O brisk_quic_size/init/feed/pull/deadline/status/wipe (src/quic/api.c), blocking
  brisk_quic_connect/close over one UDP socket (src/os/linux_udp.c), streams by uint64_t id
  (stream_open/write/read/accept). Reuses brisk_cfg; empty alpn -> BRISK_E_ARG (RFC 9001 8.1).
  feed/pull hide the engine's send-after-recv contract. Symbols only with BRISK_ENABLE_QUIC.
- Review fixes: ICMP PMTU/EMSGSIZE not fatal; udp_drain bounded; idle timeout reported;
  stream_open waits for a slot; QUIC CH1 keeps the PSK only if CH1 + worst-case CH2 fit the
  2048 B Initial retention (QC_RET0 must stay == CONN_CH_MAX); brisk_hq parse_url overflow.
- Verified by hand: 11 archs green; tools/interop/run_direct.sh 14/14 (7 cases x quic-go,
  ngtcp2) on a freshly rebuilt brisk-interop:local. DEFAULT flash -2..+244 B vs baseline
  (includes item 1's unsaved +48..+100 B; baseline still not re-saved).

## In progress
- Nothing. Tree clean.

## Needs a user decision
- **M7: raise FULL's BRISK_QUIC_MAX_STREAMS 4 -> 8?** h3 needs initial_max_streams_uni 3
  (control + 2 QPACK); with 4 only one request slot is left. Recommended 8 (scratch roughly
  47 -> ~80 KB on x86_64, estimate, not measured). Changing it means regenerating the
  quic_api CH vectors (tools/kat.py). Asked, not answered yet.
- (still open) mTLS over TLS 1.2 with a `sign` callback fails closed; digest-scheme proposal
  postponed to M8.

## Next up
- **M7 HTTP/3**: QPACK static-only (capacity 0) + Huffman (reuse src/http huffman), control
  stream + SETTINGS, `brisk_h3_*` over brisk_quic_*. Settle the MAX_STREAMS question first.
  Before adding another FULL-only knob, drop BRISK_PROFILE=FULL from the `base` preset.

## Decisions / gotchas
- Interop lives in WSL2's Docker (images + runner at ~/brisk-interop/quic-interop-runner),
  not Docker Desktop's Windows context. Run: `wsl -e bash -c 'cd /mnt/d/.../TLS && docker
  build -f tools/interop/Dockerfile -t brisk-interop:local . && tools/interop/run_direct.sh
  ~/brisk-interop/quic-interop-runner <server image>'`. Rebuild the image after C changes.
- ns-3 simulator (run_local.sh) BLOCKED on WSL2 (no UDP forwarded even quic-go<->quic-go):
  loss/reordering interop still needs a native Linux run.
- Harness image knobs: STREAM_BUF 65536, MAX_STREAMS 16, CRYPTO_BUF 16384 (defaults crawl).
- Client never sends *_BLOCKED frames: deliberate policy (stream.c header), reviewers refuted.
- `dev.py test --arch all` takes >10 min now: run it in the background.
- dev.py size keys modules by object basename: tls/conn.c and quic/conn.c share one row.
