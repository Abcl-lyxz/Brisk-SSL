# Brisk-SSL architecture

Design agreed on 2026-09-19 after research into TLS/QUIC client requirements for IoT endpoints,
crypto options, cross-arch tooling and API ergonomics. This is the "why"; `include/brisk.h` is
the API reference and `docs/ROADMAP.md` the plan.

## Goals
1. **Easy configuration**: a zero-initialised config is secure; one header (`brisk_config.h`)
   with 3 profiles and a handful of tri-state knobs; a CI-generated table of what every knob
   costs in KB per arch. (Fixes the two wolfSSL pains: scattered docs, unknown size flags.)
2. **Small and frugal**: no malloc in the core, no global state, per-connection arena,
   `-ffunction-sections` + `--gc-sections`, size tracked per module per arch on every change.
3. **Portable**: C99 + Linux only; tested on 10 CPU archs incl. big-endian and 32-bit.
4. **Correct and safe**: official vectors, RFC-cited code, constant-time crypto, fail closed.

## Scope
Client only. TLS 1.3 + TLS 1.2 over TCP, QUIC v1, optional HTTP/2 and HTTP/3 modules.
Brisk is an **SSL library**: the core hands you a TLS byte stream; what you send over it
(MQTT, HTTP/1.1, your own protocol) is up to you. h2/h3 modules are called explicitly - the
library never switches protocols by itself. Out of scope: server role, 0-RTT, renegotiation,
TLS <= 1.1, CBC suites, static RSA, SHA-1 signatures, compression.

## Layers (dependencies point down only)
```
L6 src/os/       Linux only: linux_net.c (blocking brisk_connect/read/write/close over TCP),
                 linux_udp.c (blocking brisk_quic_connect), linux_rand.c (getrandom ->
                 /dev/urandom), linux_ca.c (CA bundle autodetect); clocks
L5 src/tls/conn.c  the public connection, sans-I/O (brisk_conn_init/feed/pull/app_*)
   src/quic/api.c  the public brisk_quic_*, sans-I/O                           (optional)
L4 src/http/     h2 + HPACK, h3 + QPACK (static-only), shared Huffman decoder     (optional)
L3 src/tls/      TLS 1.3 handshake engine, record layer, TLS 1.2, ticket blobs
   src/quic/     packets/header protection, streams, ACK/loss/NewReno          (optional)
L2 src/x509/     DER, chain building, RFC 9525 names, time policy, PEM bundles
L1 src/crypto/   sha2, hkdf (HMAC/HKDF/Expand-Label/PRF), aead (AES-ct+GCM, ChaCha20-Poly1305),
                 ec (X25519, P-256 on fiat-crypto), bn (i31: RSA verify, P-384 verify)
L0 src/util.c    constant-time compare, secure wipe, build info
```

### One TLS 1.3 engine for TCP and QUIC
The handshake engine consumes and produces handshake **messages tagged with an epoch**
(Initial/Handshake/1-RTT) and exports **secrets**, never packet keys (picotls model). The TCP
record layer derives `key`/`iv` and frames records; QUIC derives `quic key/iv/hp` and carries
the same bytes in CRYPTO frames. A QUIC flag enforces RFC 9001: no ChangeCipherSpec, empty
legacy_session_id, ALPN mandatory, transport parameters extension 0x39, no KeyUpdate message.

## Public API shape
```c
brisk_cfg cfg = BRISK_DEFAULTS;              /* zero-init = secure defaults */
cfg.alpn      = "x-amzn-http-ca";            /* comma-separated list: "h2,http/1.1", "mqtt" */
cfg.ca_file   = "/etc/ssl/certs/ca-certificates.crt";   /* NULL (+ no ca_mem) = autodetect */
cfg.client_chain = dev_der; cfg.client_chain_len = n;   /* mTLS, ECDSA P-256 (in memory)   */
cfg.client_key   = dev_d32;                             /* or cfg.sign = secure element    */

brisk_conn *c;
if (brisk_connect(&cfg, "iot.example.com", 443, &c) != BRISK_OK) { ... }
brisk_write(c, req, req_len);
n = brisk_read(c, buf, sizeof buf);          /* >0 data, 0 close_notify, <0 BRISK_E_* */
brisk_close(c);

brisk_h2_open(c, mem, brisk_h2_size(), &h);             /* optional modules (M4, M7) */
brisk_quic_connect(&cfg, host, 443, &q);                 /* cfg.alpn = "h3" */
brisk_h3_open(q, mem3, brisk_h3_size(), &h3);

/* sans-I/O for your own loop, in your own memory (brisk_conn_size() bytes) */
brisk_conn_init(mem, sizeof mem, &cfg, host, &c);
brisk_pull(c, out, cap); brisk_feed(c, in, n, &used); brisk_app_read(c, buf, cap, &got);
```
Status-returning calls (`int` + out-parameter), never a NULL-means-error pointer. There is no
runtime `versions` knob: TLS 1.2 is the compile-time `BRISK_ENABLE_TLS12` (profile DEFAULT).

HTTP/2 (decided 2026-09-23): simple blocking API over an open brisk_conn whose ALPN is "h2" -
`brisk_h2_open(c, mem, len, &h)`, `brisk_h2_request(...) -> stream`, `brisk_h2_response`,
`brisk_h2_read`, `brisk_h2_stream_close`, `brisk_h2_close` (GOAWAY; the caller closes the TLS
connection). Up to 4 concurrent streams (value knob `BRISK_H2_MAX_STREAMS`), caller memory
sized by `brisk_h2_size()`. No push, no priority.

## Memory model
- Core: caller-provided memory sized by `brisk_*_size()`; blocking API does one arena malloc
  per connection.
- Arena = fixed state | rec_in 16,645 B | handshake scratch. The receive record buffer must
  hold a full 2^14+256+5 record: OpenSSL and Go servers ignore RFC 8449 record_size_limit
  (which Brisk sends), so a smaller buffer would only work against servers you control;
  max_fragment_length is not implemented.
- Certificate chain reassembly cap 12 KB (knob `BRISK_TLS_MAX_HS_MSG`). The scratch lives as
  long as the connection (post-handshake NewSessionTicket / KeyUpdate); h2/h3 state is separate
  caller memory.
- MEASURED (M3 line 4): `brisk_conn_size()` = 41,839 B on 32-bit targets (i686 41,763) and
  42,663 B on 64-bit: rec_in 16,645 + handshake scratch 19.8-20.4 KB (12 KB reassembly +
  CertificateVerify + certificate array + 6 KB output queue with mTLS) + ~5.4 KB fixed state
  (engine, record dirs, the 2 KB PEM scratch of the anchor lookup, host, ALPN). The blocking
  API adds 6 KB (tx 4 KB, rx 2 KB) to its one malloc, so ~48 KB per connection. The old
  "~26 KB" estimate ignored that the scratch must outlive the handshake (post-handshake
  NewSessionTicket/KeyUpdate go through the engine). Cheapest future cuts: a TINY profile with
  a smaller BRISK_TLS_MAX_HS_MSG, or sharing the PEM scratch with the output queue.
- RE-MEASURED (M5, TLS 1.2 on): `brisk_conn_size()` grows by about 350 B - 43,024 B on a 64-bit
  host, 42,200 B with -m32 (mingw gcc; Linux figures sit within ~80 B of these) - from the TLS
  1.2 engine state (P-256 d, preliminary / main secret, randoms, our ECDHE share: ~210 B), the
  receive key waiting for the server CCS (~48 B), 16 offered suites instead of 8, and 73 more
  bytes of reassembly so a Certificate plus an RSA-4096 ServerKeyExchange fit together. A
  BRISK_ENABLE_TLS12=0 build keeps the pre-M5 figure to within a few bytes.
- HTTP/2, QUIC and HTTP/3 add their own caller-owned memory: `brisk_h2_size()` (HPACK ring,
  header buffers, per-stream windows), a QUIC connection ~8.4 KB + `brisk__quic_scratch_size()`
  82 KB at the defaults (8 stream slots of 2 x 4 KB), `brisk_h3_size()` ~49 KB. Formulas and
  the knobs that shrink them: docs/CONFIG.md.

## Security defaults
- Verification always on (chain + RFC 9525 hostname, SAN only); there is no switch to turn it
  off. The only date-related opt-out is the compile-time `BRISK_X509_TIME_POLICY_INSECURE_NO_TIME`,
  which `brisk_build_info()` reports. No revocation checking (CRL / OCSP).
- TLS 1.3 suites, in this order on every CPU: ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM
  (constant-time software AES is slower than ChaCha20 everywhere; the server still chooses). Groups: x25519, secp256r1 (P-384 is verify-only - no P-384 ECDHE).
  Decided 2026-09-24 to keep it so: a server that accepts only secp384r1 key shares (seen:
  pantip.com) fails closed with its handshake_failure alert. IoT backends accept X25519/P-256.
- Signatures accepted: ECDSA P-256/P-384 (SHA-256/384), RSA-PSS and PKCS#1 v1.5 (certs) 2048-4096.
- TLS 1.2 (M5): ECDHE + AEAD only, EMS required, renegotiation refused, downgrade sentinel checked.
  A server below that floor (no EMS / renegotiation_info, or TLS <= 1.1) fails with its own
  code, `BRISK_E_INSECURE`, so the field can tell "old server" from "broken server".
- No 0-RTT (telemetry POSTs are not replay-safe).
- Clock policy FLOOR (default): if the wall clock is below `BRISK_X509_TIME_FLOOR` (the build
  date) the clock is "unsynced" - check notAfter against the floor, skip notBefore. STRICT
  refuses instead; INSECURE_NO_TIME skips the window. The floor is compile-time only today: a
  persisted last-known-good time cannot raise it, and must NOT be passed as `now` instead - that
  lifts the clock above the floor and re-enables the notBefore check against a stale value, so
  every freshly issued certificate is refused. A runtime floor (from the device's storage) is not in
  v0.1.0. The trust anchor is
  exempt from the window (RFC 5280 6.1.1 (d); DST Root CA X3, 2021). Dates are int64, never
  `time_t` (Y2038, 9999 notAfter). Knob table in docs/CONFIG.md.
- SPKI pinning is NOT in v0.1.0; a private PKI uses `ca_mem` with only its own root. If pins
  come, they are additive (never replace chain validation) and pin roots, not
  leaves/intermediates (Let's Encrypt rotates intermediates; lifetimes drop to 47 days by 2029).
- RNG: getrandom (own per-arch syscall table, checked against the headers). Only on kernels
  < 4.8 without it (ENOSYS, or EPERM from seccomp): /dev/urandom once /dev/random has been
  readable, waited for once per process (on >= 4.8 readable no longer means seeded, so a filter
  that blocks getrandom there fails). Fail closed otherwise; no userspace DRBG, so fork-safe.

## Crypto choices
- Hash layer (done): loop-rolled SHA-2, HMAC, HKDF, Expand-Label. 4.2 KB (Thumb-2) .. 7.7 KB (MIPS32).
- AES: bitsliced constant-time (32-bit and 64-bit variants), encrypt direction only (TLS/QUIC
  never decrypt with AES). GHASH without tables (BearSSL ctmul64 on 64-bit, ctmul32 on 32-bit:
  32x32->32 multiplies only, so no widening multiply or libgcc helper). AES-GCM takes 96-bit
  IVs and 16-byte tags only; the key context caches H = E(K, 0) (264 B). Known limit: ARM7/ARM9
  (armv5) and some MIPS32 4K cores have early-terminating multipliers, so GHASH timing there
  may depend on H. Listing ChaCha20-Poly1305 first does not remove this - the server picks the
  suite, and AES-128-GCM is mandatory in TLS 1.3. **Done (2026-09-23):** a multiply-free
  GHASH (shift + masked XOR, SP 800-38D Algorithm 1), picked by `BRISK_GHASH_MULFREE` in
  brisk_config.h, auto on for armv5 and 32-bit MIPS; always compiled so every arch runs its KATs
  and the ct suite checks it. AES-GCM stays in the default ClientHello on every target
  (interop), and those targets pay GHASH speed only when the server picks AES.
- X25519 and P-256 field arithmetic from fiat-crypto (formally verified). On 32-bit targets the
  fiat P-256 code is trimmed (square = mul, Fermat inversion) - ~8 KB instead of ~24 KB on MIPS.
- P-384 and RSA are verify-only (public data) on one generic i31 Montgomery bignum.
- Everything verified with NIST CAVP / RFC / Wycheproof vectors re-checked in Python.

## Build, test, size
- Constant time is checked, not just reviewed: `dev.py ct` builds the tests with -DBRISK_CT_CHECK,
  which marks every key and secret input "undefined" for valgrind, and runs the `ct` suite under
  memcheck (both the 64-bit and the 32-bit AES/GHASH variant). Any branch, memory index or
  division that depends on a secret is reported. Hardware timing (the multiplier caveat above,
  caches) is out of its reach.
- CMake presets: host `dev`/`dev32` (TDM-GCC); Docker `x86_64`, `asan`, and i686, aarch64,
  armv7hf, armv5 (ARM926), mips (BE), mipsel, mips64, riscv64, ppc (BE) under qemu-user.
- `tools/dev.py size` links a static probe at -Os and attributes kept sections per module from
  the GNU ld map; fails if 64-bit division or float helpers appear in 32-bit builds.
- Amalgamation (M8): `tools/amalg.py` writes `dist/brisk.c` + `dist/brisk.h` for
  copy-two-files integration; `dev.py amalg` compiles it -Werror per profile (gcc + clang) and
  runs the suite against it. Size budgets per profile: `size/budget.json`, `dev.py size --profiles`.
- Fuzzing: a libFuzzer harness per parser (`fuzz/`, `dev.py fuzz <target>`), seeded from the KATs.

## Key facts from research (2026-09)
- RFC 9846 (July 2026) obsoletes RFC 8446, 5246, 7627, 8422, 5077: cite 9846.
- AWS IoT Core HTTPS = HTTP/1.0/1.1 only (ALPN `x-amzn-http-ca` on 443) -> use the raw TLS
  stream. MQTT on 8883 or 443 with ALPN `x-amzn-mqtt-ca`. Azure IoT Hub MQTT needs TLS 1.2.
- Let's Encrypt "Generation Y" (default since 2026-05-13): ECDSA chains use P-384 intermediates
  and cross-sign to RSA-4096 ISRG Root X1 -> P-384 and RSA-4096 verification are mandatory.
- UDP/QUIC is often blocked on OT/cellular networks; the user picks h2 or h3 explicitly.
