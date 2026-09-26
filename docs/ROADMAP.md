# Brisk-SSL roadmap

Tick a box only when the work is green on **every** arch (`python tools/dev.py test --arch all`).
`/next` works on the first unchecked item; the SessionStart hook shows it.

## M0 Infra
- [x] Repo, Apache-2.0, git remote, .clang-format, .gitattributes
- [x] CMake + presets (host dev/dev32, Docker x86_64/asan + 9 cross archs under qemu)
- [x] Docker image `brisk-dev` (Debian trixie cross gcc, qemu-user, clang tooling)
- [x] tools/dev.py (test, size with per-module map parse + libgcc/float check, image), size baseline
- [x] tools/kat.py (official vectors re-verified in Python)
- [x] Claude Code setup: hooks, statusline, skills, agents, rules, workflows, rfc MCP, CLAUDE.md
- [x] CI (GitHub Actions): all archs + size summary

## M1 Crypto
### M1a Hash layer
- [x] SHA-256 / SHA-384 / SHA-512
- [x] HMAC, HKDF extract/expand, TLS 1.3 HKDF-Expand-Label (RFC 8448 + RFC 9001 A.1 vectors)
### M1b RNG + AEAD
- [x] `src/os/linux_rand.c`: getrandom syscall (per-arch numbers) -> poll /dev/random -> /dev/urandom, fail closed
- [x] ChaCha20 + Poly1305 + AEAD (RFC 8439, Wycheproof)
- [x] AES-128/256 constant-time (bitsliced; ct on 32-bit, ct64 on 64-bit), encrypt-only
- [x] GHASH (ctmul / ctmul64) + GCM (SP 800-38D, Wycheproof); decrypt RFC 9001 A.2 Initial packet
- [x] CT tooling: `CT_SECRET` macros + valgrind ctgrind job; `/ct-check` skill
### M1c Elliptic curves (fiat-crypto)
- [x] Vendor fiat curve25519_{32,64}, p256_{32,64} + vendor/VENDORED.md (commit, license) + NOTICE
- [x] X25519 (RFC 7748 incl. 1,000-iteration test; reject all-zero)
- [x] P-256 ECDHE + ECDSA verify (trimmed fiat on 32-bit: square=mul, Fermat inversion)
- [x] ECDSA P-256 sign, hedged RFC 6979 (mTLS) + sign-callback hook
### M1d Bignum
- [x] i31 Montgomery bignum (constant-time), RSA PKCS#1 v1.5 + PSS verify 2048-4096
- [x] P-384 ECDSA verify on the generic bignum (`BRISK_ENABLE_P384`, off in TINY)

## M2 X.509
- [x] DER parser (strict, depth-limited) + fuzz target
- [x] Certificate parse: basicConstraints, keyUsage, EKU, SAN, validity, unknown-critical reject
- [x] Chain building (unordered/extra certs, stop at first trust anchor), signature checks
- [x] RFC 9525 hostname / IP matching
- [x] Time policy STRICT / FLOOR (default) / INSECURE_NO_TIME; int64 dates
- [x] CA bundle autodetect + lazy lookup; SPKI sha256 pins (additive)
- [x] Path building: depth-first search with backtracking, replacing the greedy "first
      candidate that verifies wins". A CA rollover puts two certificates with one subject Name
      and one key on the wire and the useless legacy cross-certificate goes first, so a greedy
      walk refused chains it held every certificate for; SPKI pins made that reachable far more
      often. Costs one pointer per level (32 B on 32-bit, 64 on 64-bit) and no extra bound:
      every descent already costs a signature verification, which MAX_VERIFY caps.
- [x] x509-limbo suite

## M3 TLS 1.3 client
- [x] Handshake engine (messages + epochs, exports secrets), HRR, key schedule
  - Engine landed (`src/tls/handshake.c`): CH/SH/HRR/EE/CR/Certificate/CertificateVerify/
    Finished, epochs, secrets out, `brisk__tls13_auth_x509`. Post-handshake NewSessionTicket
    (parsed strictly, handed to `cfg.on_ticket` or ignored) and KeyUpdate are handled since line 2.
    CertificateRequest is answered with an empty Certificate (mTLS is
    line 3). ALPN in EE is accepted unchecked until line 3.
- [x] Record layer (TCP), KeyUpdate, alerts, close_notify
  - `src/tls/record.c`: `brisk__tls_rec_seal/open` + the sans-I/O `brisk__tls13_conn` driver.
    GHASH timing on early-terminating multipliers: `BRISK_GHASH_MULFREE` (auto on for armv5 and
    32-bit MIPS) swaps in a shift + masked-XOR GHASH. Post-handshake messages still use the engine's
    reassembly scratch, so the line-4 arena must keep it alive (or skip NSTs that do not fit).
- [x] PSK resumption tickets (export/import blob), ALPN list, SNI, mTLS (ECDSA)
- [x] `src/os/` sockets + public API `brisk_connect/read/write/close`, sans-I/O `brisk_feed/pull`
  - `src/tls/conn.c` (sans-I/O `brisk_conn`: CH1/CH2 builder, in-memory + file trust store, ALPN
    list, ticket in/out with the no-PSK retry) and `src/os/linux_net.c` (clocks, getaddrinfo +
    non-blocking TCP with poll deadlines, `brisk_conn_init`, the blocking API). One malloc per
    blocking connection; `brisk_conn_size()` per arch is in the commit message.
  - Open: a RUNTIME certificate-time floor (a persisted last-known-good time) is not in
    `brisk_cfg` yet. It must be threaded through `brisk__x509_chain_verify` /
    `brisk__x509_time_ok` next to `BRISK_X509_TIME_FLOOR` - never done by raising `now`.
  - Open: sans-I/O connections stamp tickets with the init time (no clock in the core); add a
    public `brisk_conn_set_time` if a long-lived sans-I/O user needs fresher stamps.
- [x] RFC 8448 trace test; Docker interop (nginx, Caddy, openssl s_server); badssl.com
  - RFC 8448 traces: covered by tests/test_tls13_hs.c, test_tls13_rec.c, test_tls13_ks.c.
  - `python tools/dev.py interop` (one container, throwaway PKI under build/interop/pki,
    examples/brisk_get as the client): openssl 3.5 s_server - default, each of the 3 suites,
    HRR (P-256-only server), RSA-2048 leaf, P-384 intermediate, ALPN, mTLS (and its refusal
    without a cert), resumption (2nd run resumed=1), server-requested KeyUpdate, wrong host /
    untrusted CA -> E_AUTH, TLS 1.2-only server -> E_PEER_ALERT; nginx 1.26 and Caddy 2.6
    GET a known body. 18/18 pass (2026-09-23).
  - `python tools/dev.py badssl`: NO badssl.com host speaks TLS 1.3 (checked with
    `openssl s_client -tls1_3`). Since M5 they answer TLS 1.2, but WITHOUT extended master
    secret (`openssl s_client -tls1_2`: "Extended master secret: no", 2026-09-24), which M5
    requires - so every badssl row still fails (handshake_failure) and the bad-certificate rows
    still prove nothing; revoked.badssl.com could not be flipped to success. The rows that do
    mean something: TLS 1.0/1.1, CBC, 3DES, RC4, static RSA and DHE-only hosts are refused.
    Positive controls (www.cloudflare.com, www.google.com, system bundle) pass. 26/26.
- [x] Examples: AWS IoT HTTPS over raw TLS (ALPN x-amzn-http-ca), MQTT-over-TLS sketch
  - `examples/brisk_get.c` (generic CLI, the interop/badssl client), `aws_iot_https.c` (mTLS
    POST /topics on 443), `mqtt_tls.c` (MQTT 3.1.1 CONNECT/PUBLISH, ALPN x-amzn-mqtt-ca on 443).
    Built on Linux with BRISK_BUILD_EXAMPLES; not yet run against a real AWS account.

## M4 HTTP/2
- [x] HPACK (static + literal encoder, decoder with table, Huffman decode shared with QPACK)
  - `src/http/hpack.c` + `src/http/huffman.c` behind `BRISK_ENABLE_H2` (DEFAULT/FULL, empty TUs
    in TINY); `BRISK_H2_HEADER_TABLE_SIZE` (4096) sizes the caller-owned ring. Decoder: full
    RFC 7541, sticky-dead on any error (RFC 9113 4.3), RFC 9113 4.3.1 size-update rule, local
    scratch/max_list limits fail closed. Encoder: static index or literal without/never
    indexing, never Huffman, never indexes (7.1). RFC 9113 8.2.1 receive-side field checks are
    owed by line 2 (in the decode callback). Vectors: RFC 7541 App. C + hpack-test-case
    (8 encoders) + generated invalid rows; fuzz target `hpack`.
- [x] Frames, streams, flow control, SETTINGS, PING, GOAWAY; `brisk_h2_*`
  - `src/http/h2.c`: pure core `brisk__h2_feed` (one frame per call) / `brisk__h2_pull` under a
    thin blocking layer (`brisk_h2_open/request/response/read/stream_close/close`; open lives in
    `src/os/linux_net.c`, everything else links on the mingw host). Caller memory
    `brisk_h2_size()` (~66 KB default); knobs `BRISK_H2_MAX_STREAMS` (4) and
    `BRISK_H2_STREAM_WINDOW` (8192, proposed - needs user sign-off). New `BRISK_E_RETRY` (8.7;
    proposed). `brisk_conn.port` feeds `:authority`. Request builder refuses every ':' name,
    uppercase, connection-specific fields, host, te != trailers (8.2/8.3). Flood guards:
    32 CONTINUATION per block, 1000 frames without progress per call.
  - Vectors: `h2.inc` scenario rows (kat.py, cross-checked against python-hyper h2 when
    installed; 26 documented deviations), replayed at many splits + timeouts; fuzz target `h2`.
  - QPACK (M7) must prefix its static helpers (qp_*) - hpack.c's generic names (insert,
    put_int, ...) clash when amalgamated; h2.c uses h2_*.
  - Before commit: rfc-auditor pass (not yet run).
- [x] Interop: nginx, h2o, nghttpd
  - `python tools/dev.py interop` h2 rows via `examples/h2_get.c`: nginx 1.26, h2o (built from a
    pinned commit - trixie has no package), nghttpd (with response trailers): small GET + headers,
    1.5 MB GET (receive flow control), 300 KB POST echo (send flow control), 4 parallel 1.5 MB
    streams, 404; nginx keepalive_requests 1 -> GOAWAY -> 2nd request E_RETRY; a server without
    ALPN -> brisk_h2_open E_ARG. 35/35 with the TLS rows (2026-09-24).

## M5 TLS 1.2 client
- [x] ECDHE-ECDSA/RSA x AES-GCM / ChaCha20-Poly1305, EMS required, renegotiation_info, PRF
  - `src/tls/tls12.c` (the TLS 1.2 half of the engine), `brisk__tls12_prf` in hkdf.c, RFC 5246
    6.2.3.3 AEAD framing + the CCS gate + the HelloRequest answer in record.c; one ClientHello
    offers TLS 1.3 and 1.2 (supported_versions [0x0304, 0x0303], 6 suites, EMS,
    renegotiation_info, ec_point_formats). Knob `BRISK_ENABLE_TLS12` (off in TINY; preset
    `dev-tls13` builds it off). `brisk_tls_version()` added. mTLS over 1.2 with `client_key`;
    a `sign` callback fails closed (internal_error) - the callback contract is raw tbs bytes
    and TLS 1.2 signs the whole transcript. Decided 2026-09-24: postponed to M8 (a digest scheme
    such as 0xFE03 is a public API change; wait for a real secure-element user).
  - Vectors: NIST ACVP TLS-v1.2-KDF-RFC7627 + kdf-components v1.2 (480 rows); generated
    records (106) and flows (21 full handshakes, 104 single faults, incl. Wycheproof ecpoint /
    x25519 low-order SKE points). Interop 57/57 (2026-09-24): openssl s_server -tls1_2 with every
    suite x {ECDSA, RSA} x {X25519, P-256}, P-384 chain, ALPN, mTLS, CBC-only / no-EMS /
    TLS 1.1 refused, HelloRequest; nginx and Caddy TLS 1.2 GET; h2 over TLS 1.2 on nginx.
  - Known limit: a P-384 ECDSA leaf signing its SKE with 0x0403 (SHA-256) is refused - P-384
    verify wants a >= 48-byte digest. secp384r1 is not in our groups, so per RFC 8422 5.1 a
    server should not pick an ECDSA suite for that cert anyway. Fails closed.
  - Manual review pass (workflow reviewers hit the session limit): rfc-auditor found a 1.3
    SH/HRR picking an offered 1.2 suite was accepted (fixed, 2 kat rows); portability fixes.
- [x] Refuse CBC, RSA key exchange, SHA-1, compression, renegotiation; downgrade sentinel

## M6 QUIC v1 client
- [x] Packets + header protection, CRYPTO frames on the TLS 1.3 engine, transport parameters
- [x] ACK, loss detection / PTO, NewReno (integer), flow control, streams. Also the stateful
      1-RTT frame MUSTs that are only syntax-checked now (rfc-auditor, M6 item 1): STREAM /
      STOP_SENDING / MAX_STREAM_DATA on a stream we never opened or a receive-only one
      (STREAM_STATE_ERROR), server stream ids past our initial_max_streams (STREAM_LIMIT_ERROR),
      data past our flow-control limits (FLOW_CONTROL_ERROR), NEW_CONNECTION_ID count vs our
      active_connection_id_limit and retire_prior_to (RFC 9000 5.1.1, 19.15), ACK +
      PATH_RESPONSE generation (13.2.1, 8.2.2). Keep brisk__quic_conn's own sent TPs for it.
      conn.c pkt_finish hard-codes a 4-byte PN: pass brisk__quic_pn_len's value to the payload
      layout in brisk__quic_send / cc_build once largest_acked is tracked. Keep the application
      traffic secret for key update (the engine wipes it after on_secret). The `dev` host preset
      builds the shipped DEFAULT profile; dev32 and every Docker preset build FULL.
- [x] Retry, version negotiation, stateless-reset detection, receive-side key update
- [x] quic-interop-runner harness (hq-interop) + the public `brisk_quic_*` API (sans-I/O and
      blocking over one UDP socket, streams by id). tools/interop/: all 7 cases pass against
      quic-go and ngtcp2 on a plain Docker bridge (`run_direct.sh`); the ns-3 simulator run
      (`run_local.sh`) is blocked on WSL2 but passes 14/14 on GitHub Actions
      (`.github/workflows/interop.yml`, manual trigger). Our TP defaults: max_idle_timeout 30000,
      max_udp_payload_size 1472 (the UDP driver's buffer), initial_max_data = MAX_STREAMS *
      STREAM_BUF, bidi_local = STREAM_BUF, no peer streams (bidi / uni 0). BRISK_QUIC_MAX_STREAMS
      default 4 -> 8 for M7 (h3 needs 3 uni streams: control + 2 QPACK). DEFAULT size: conn.c grew ~60-260 B (conn_hello takes its buffer; the shared
      front half is static outside QUIC builds).

## M7 HTTP/3
- [x] QPACK static-only (capacity 0) + Huffman; control stream + SETTINGS; `brisk_h3_*`
  - `src/http/qpack.c` (RFC 9204: static table, dynamic capacity 0 / blocked streams 0, the
    Huffman decoder shared with HPACK), `src/http/h3.c` (RFC 9114: framing, control stream +
    SETTINGS + GOAWAY, QPACK encoder/decoder streams read and checked, request state machine),
    public `brisk_h3_*` over a blocking `brisk_quic` mirroring `brisk_h2_*` (same header types).
    `BRISK_ENABLE_H3` (FULL) forces QUIC + H2 on. Server uni streams (3) are granted only when
    cfg.alpn offers "h3"; other ALPNs keep byte-identical transport parameters. stream.c gained
    a local abort (RESET_STREAM / STOP_SENDING with an app code).
  - Vectors: RFC 9204 static table + Appendix B where static-only applies, a Python QPACK
    encoder/decoder, 104 h3 scenario rows, fuzz seeds (fuzz_qpack, fuzz_h3). 3 review rounds.
  - Interop (2026-09-25, `examples/h3_get.c` from Docker): cloudflare-quic.com, www.google.com,
    quic.nginx.org, www.facebook.com, cloudflare.com all complete; `-n 4` parallel requests on
    one connection to cloudflare-quic.com identical.

## M8 Hardening + release
- [x] Fuzzers (libFuzzer/AFL++) for every parser, seed corpora. Last one: `fuzz/fuzz_pem.c`
      for `brisk__x509_pem_feed` - the whole buffer vs pseudo-random chunks (1..64, seeded by
      the first input byte) must yield the same certificates; `der_len <= sizeof der`, every
      call inside its input. Seeds: `x509_bundle.inc`'s PEM column (second extractor in
      `fuzz_corpus()`). 2026-09-25: 619k runs / 120 s clean.
- [x] Amalgamation `dist/brisk.c` + `dist/brisk.h` (tools/amalg.py), tested in CI
      (`python tools/dev.py amalg`: TINY / DEFAULT / FULL + the 32-bit AES/fiat variants,
      gcc and clang, -Werror as one TU; the full suite linked against it). The M2 blockers were
      already gone: `aes_ct.c` / `aes_ct64.c` are whole-file `#if !BRISK__AES_CT64` /
      `#if BRISK__AES_CT64`, and `_GNU_SOURCE` is hoisted to the top of `dist/brisk.c` (a
      superset of linux_ca.c's `_POSIX_C_SOURCE`). One gcc false positive fixed on the way
      (`-Wmaybe-uninitialized`, handshake.c auth_x509, visible only with cross-file inlining).
- [x] Size budgets per profile; docs/CONFIG.md flag -> KB table generated by CI
      (`size/budget.json`: the most flash a profile may take on ANY arch - TINY 104 / DEFAULT
      144 / FULL 216 KB, ~7% over mipsel at 97.1 / 134.0 / 201.3 KB on 2026-09-25;
      `python tools/dev.py size --profiles [--doc]`, CI fails over budget and prints the table)
- [x] Docs: `docs/API.md` generated from brisk.h (`tools/apidoc.py`, CI `--check`),
      `docs/TROUBLESHOOTING.md` per error code (with the 2026-09 live-run findings), examples
      built by every Docker preset (all five, FULL, -Wall -Wextra -Wpedantic)
- [x] OpenWrt package Makefile (`openwrt/brisk-ssl/Makefile`: build-only `libbrisk-ssl` - static
      lib + headers staged via the new CMake `install()` rules - and `brisk-get`; profile from
      menuconfig). Built with the official SDK (openwrt/sdk:x86-64-24.10.2, musl, 2026-09-25,
      `USE_SOURCE_DIR`); the .ipk's brisk_get / h2_get reach google / cloudflare from Alpine.
- [x] v0.1.0 released 2026-09-25: tag `v0.1.0` (7ad5731) after CI green (all archs, amalg,
      size budgets) and interop 14/14; GitHub release with `dist/brisk.{c,h}`. OpenWrt Makefile
      pinned to the commit + PKG_MIRROR_HASH; SDK download verifies and builds from the tag.

## M9 Open API (0.2): any transport, any key format, public crypto, more knobs
Plan (2026-09-25): make Brisk usable for more than HTTPS - raw TCP/UART protocols, certificates
compiled in as arrays, the device's own payload encryption, and wolfSSL-style knobs. Secure by
default still holds: certificate verification can never be switched off.
- [x] Key/chain formats: `cfg.client_key_len` (32 = raw scalar; else SEC1 / PKCS#8 DER or PEM,
      auto-detected, P-256 only, parsed once into the conn and wiped); `client_chain` also PEM.
      Vectors generated by openssl in `tools/kat.py`; new `fuzz/fuzz_key.c`.
      ABI note for the 0.2 release notes: `client_key_len` sits right after `client_key`, so
      `brisk_cfg` changed layout - rebuild against the new header; positional initialisers break,
      zero-init / designated ones do not. `BRISK_TLS_MAX_CLIENT_CHAIN` now bounds the DER bytes
      of the chain, not `client_chain_len` (PEM text is ~1.37x). BER keys are refused on purpose
- [ ] Custom transport: `brisk_connect_fd` (a socket/fd the caller opened; not closed by
      brisk_close) and `brisk_connect_io` (send/recv callbacks for UART, tunnels, tests);
      net_flush/net_fill go through the io vtable; read/write for non-socket fds
- [ ] Public crypto API (`BRISK_ENABLE_CRYPTO_API`): brisk_random, AEAD seal/open (AES-GCM,
      ChaCha20-Poly1305), HKDF, X25519, P-256 keygen/ECDH/sign/verify, P-384 + RSA verify - thin
      wrappers over src/crypto, tested against the existing KATs, ct-checked
- [ ] Compile-time knobs: AESGCM, CHACHA, AES256, X25519, P256_KX, RSA, TICKETS, SYSTEM_CA, PEM,
      CUSTOM_IO, ERROR_STRINGS (+ `brisk_strerror`), KEYLOG (default off everywhere),
      AES_IMPL; deps auto-resolved with #error on conflict; CI knob-matrix job (each knob off)
- [ ] Runtime cfg: min/max version, suites/groups preference strings, sni override, SPKI pins
      (on top of chain verification), time_floor, max_fragment / record_size_limit (RFC 8449);
      rfc-auditor clean
- [ ] Docs + release: `examples/tcp_tls_embedded.c` (CA/cert/key as `xxd -i` arrays, no files),
      README "Certificates without files", CONFIG.md knob -> KB table, apidoc, v0.2.0 tag

## Backlog (pick the next milestone from here when every box above is ticked)
- mTLS `sign` callback over TLS 1.2 (today fails closed with E_ARG, brisk.h sign docs)
- TLS 1.3 external PSK (no certificates at all, private broker/gateway)
- Public X.509 API (parse, verify a chain from memory, read subject / public key)
- AES hardware acceleration (ARMv8 crypto extensions, AES-NI)
- Shared library (.so) build, OCSP stapling
