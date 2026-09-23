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
L6 src/os/       Linux: sockets (connect timeout, MSG_NOSIGNAL), getrandom -> /dev/urandom,
                 monotonic + wall clocks, CA bundle autodetect
L5 src/brisk.c   blocking public API: brisk_connect/read/write/close, brisk_h2_*, brisk_h3_*
L4 src/http/     h2 + HPACK, h3 + QPACK (static-only), shared Huffman decoder     (optional)
L3 src/tls/      TLS 1.3 handshake engine, record layer, TLS 1.2
   src/quic/     packets/header protection, streams, ACK/loss/NewReno          (optional)
L2 src/x509/     DER, chain building, RFC 9525 names, time policy, pins
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
cfg.versions  = BRISK_TLS12 | BRISK_TLS13;
cfg.alpn      = "x-amzn-http-ca";            /* free-form list: "h2", "mqtt", ... */
cfg.ca_file   = "/etc/ssl/certs/ca-certificates.crt";   /* NULL = autodetect */
cfg.cert_file = "dev.crt"; cfg.key_file = "dev.key";    /* mTLS, ECDSA P-256 */

brisk_conn *c = brisk_connect(&cfg, "iot.example.com", 443);
brisk_write(c, req, req_len);
n = brisk_read(c, buf, sizeof buf);
brisk_close(c);

brisk_h2 *h = brisk_h2_open(c);                          /* optional modules */
brisk_h3 *q = brisk_h3_connect(&cfg, host, 443);

brisk_feed(c, in, n); brisk_pull(c, out, cap);           /* sans-I/O for your own loop */
```

## Memory model
- Core: caller-provided memory sized by `brisk_*_size()`; blocking API does one arena malloc
  per connection.
- Arena = fixed state | rec_in 16,645 B | rec_out 4 KB | union{handshake scratch, h2/h3 runtime}.
  The receive record buffer must hold a full 2^14+256+5 record: OpenSSL and Go servers ignore
  RFC 8449 record_size_limit, so smaller buffers only work against servers you control
  (opt-in `max_fragment_length`, handshake fails cleanly if not acknowledged).
- Certificate chain reassembly cap 12 KB (knob); scratch reused for HTTP state after Finished.
- Estimates until measured: TLS 1.3 ~26 KB peak, + h2 ~35-40 KB, QUIC + h3 ~45 KB.

## Security defaults
- Verification always on (chain + RFC 9525 hostname, SAN only); `insecure` is explicit and logged.
- TLS 1.3 suites: ChaCha20-Poly1305 first on CPUs without AES instructions, else AES-128-GCM;
  AES-256-GCM available. Groups: x25519, secp256r1 (P-384 is verify-only - no P-384 ECDHE).
- Signatures accepted: ECDSA P-256/P-384 (SHA-256/384), RSA-PSS and PKCS#1 v1.5 (certs) 2048-4096.
- TLS 1.2 (M5): ECDHE + AEAD only, EMS required, renegotiation refused, downgrade sentinel checked.
- No 0-RTT (telemetry POSTs are not replay-safe).
- Clock policy FLOOR (default): if the wall clock is below `BRISK_X509_TIME_FLOOR` (the build
  date) the clock is "unsynced" - check notAfter against the floor, skip notBefore. STRICT
  refuses instead; INSECURE_NO_TIME skips the window. The floor is compile-time only today: a
  persisted last-known-good time cannot raise it, and must NOT be passed as `now` instead - that
  lifts the clock above the floor and re-enables the notBefore check against a stale value, so
  every freshly issued certificate is refused. A runtime floor belongs to the M3 client config,
  where the device's storage is already in the picture. The trust anchor is
  exempt from the window (RFC 5280 6.1.1 (d); DST Root CA X3, 2021). Dates are int64, never
  `time_t` (Y2038, 9999 notAfter). Knob table in docs/CONFIG.md.
- SPKI pins are additive (never replace chain validation); pin roots, not leaves/intermediates
  (Let's Encrypt rotates intermediates; certificate lifetimes drop to 47 days by 2029).
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
  suite, and AES-128-GCM is mandatory in TLS 1.3. **Decided (2026-09-23):** a multiply-free
  GHASH (shift + masked XOR), picked by a tri-state knob in brisk_config.h whose auto value turns
  it on for armv5 and 32-bit MIPS. AES-GCM stays in the default ClientHello on every target
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
- Later: amalgamated `dist/brisk.c` + `dist/brisk.h` for copy-two-files integration.

## Key facts from research (2026-09)
- RFC 9846 (July 2026) obsoletes RFC 8446, 5246, 7627, 8422, 5077: cite 9846.
- AWS IoT Core HTTPS = HTTP/1.0/1.1 only (ALPN `x-amzn-http-ca` on 443) -> use the raw TLS
  stream. MQTT on 8883 or 443 with ALPN `x-amzn-mqtt-ca`. Azure IoT Hub MQTT needs TLS 1.2.
- Let's Encrypt "Generation Y" (default since 2026-05-13): ECDSA chains use P-384 intermediates
  and cross-sign to RSA-4096 ISRG Root X1 -> P-384 and RSA-4096 verification are mandatory.
- UDP/QUIC is often blocked on OT/cellular networks; the user picks h2 or h3 explicitly.
