# Handoff - 2026-09-25 (session 22)

## Done - M7 complete
- 714bd29 **build:** BRISK_QUIC_MAX_STREAMS 4 -> 8 (user OK'd; h3 needs 3 server uni streams),
  quic_api.inc regenerated, quic_api SOURCES.md paragraph moved into kat.py. `dev` host preset
  now builds DEFAULT; dev32 + every Docker preset stay FULL.
- eed1e9c **http: HTTP/3 + static-only QPACK, brisk_h3_*** (via /implement-module; round-3
  rfc-auditor + portability reviewers re-run by hand after the session limit killed them).
  Round-3 fixes: `te` in a response/trailer is malformed (h3 4.2 and h2 8.2.2); request serves
  the control stream before the GOAWAY check (5.2). Both mutation-tested (row fails on revert).
- 11 archs green. DEFAULT flash +244..+492 B (h2.c helpers now shared/non-static), baseline
  not re-saved.

## In progress
- Nothing. Tree clean.

## Needs the user
- Run ns-3 interop on their Linux VPS (Docker natively, IPv6 on in daemon.json):
  `tools/interop/run_local.sh` -> send build/interop/result.json.
- h3 interop vs real servers not done: examples/h3_get.c exists, never run against quic-go /
  ngtcp2 / nginx-quic. Good to do on the same VPS.
- (still open) mTLS over TLS 1.2 with a `sign` callback fails closed; digest-scheme proposal
  postponed to M8.

## Next up
- **M8 item 1**: `fuzz/fuzz_pem.c` for brisk__x509_pem_feed (random chunk sizes, assert
  der_len <= sizeof der) + a second corpus extractor in tools/dev.py fuzz_corpus() (the .inc's
  first column is PEM text, not hex). Then amalgamation (tools/amalg.py).

## Decisions / gotchas
- WSL vs Docker: on Windows Docker always runs inside the WSL2 VM; ns-3 fails because WSL2's
  network doesn't forward the sim's UDP, not because of Docker. Native Linux + Docker fixes it.
- Server uni-stream credit (3) is granted ONLY when cfg.alpn offers "h3" (api.c qa_offers_h3);
  hq-interop / other ALPNs keep byte-identical TPs. Concurrent h3 requests = MAX_STREAMS - 4.
- BRISK_ENABLE_H3 forces QUIC + H2 (qpack reuses huffman.c + h2.c field checks).
- test_h3 fake io delivers one event chunk per wait(); op `P` pumps pending events between
  calls (models data a blocking wait left unparsed in the rings).
- python-hyper h2 accepts `te` in responses: listed in kat.py's h2 `known` deviations.
- sizeof(brisk__quic_conn) ~8.4 KB x86_64, quic scratch 82432 B at defaults (CONFIG.md).
- `dev.py test --arch all` > 10 min: run in background. A stale empty .git/index.lock appeared
  once after a background run; check no git process, then remove.
- Interop image: WSL2 Docker, ~/brisk-interop/quic-interop-runner, run_direct.sh; knobs
  STREAM_BUF 65536, MAX_STREAMS 16, CRYPTO_BUF 16384.
