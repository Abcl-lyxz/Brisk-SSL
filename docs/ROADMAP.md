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
- [ ] RFC 8448 trace test; Docker interop (nginx, Caddy, openssl s_server); badssl.com
- [ ] Examples: AWS IoT HTTPS over raw TLS (ALPN x-amzn-http-ca), MQTT-over-TLS sketch

## M4 HTTP/2
- [ ] HPACK (static + literal encoder, decoder with table, Huffman decode shared with QPACK)
- [ ] Frames, streams, flow control, SETTINGS, PING, GOAWAY; `brisk_h2_*`
- [ ] Interop: nginx, h2o, nghttpd

## M5 TLS 1.2 client
- [ ] ECDHE-ECDSA/RSA x AES-GCM / ChaCha20-Poly1305, EMS required, renegotiation_info, PRF
- [ ] Refuse CBC, RSA key exchange, SHA-1, compression, renegotiation; downgrade sentinel

## M6 QUIC v1 client
- [ ] Packets + header protection, CRYPTO frames on the TLS 1.3 engine, transport parameters
- [ ] ACK, loss detection / PTO, NewReno (integer), flow control, streams
- [ ] Retry, version negotiation, stateless-reset detection, receive-side key update
- [ ] quic-interop-runner harness (hq-interop)

## M7 HTTP/3
- [ ] QPACK static-only (capacity 0) + Huffman; control stream + SETTINGS; `brisk_h3_*`

## M8 Hardening + release
- [ ] Fuzzers (libFuzzer/AFL++) for every parser, seed corpora. Still missing: `fuzz_pem`
      for `brisk__x509_pem_feed` (M2) - feed the input in pseudo-random chunk sizes and
      assert `der_len <= sizeof der`; `tests/test_x509.c` only sweeps six fixed sizes, and
      `fuzz_corpus()` in tools/dev.py needs a second extractor because that .inc file's
      first column is PEM text, not hex.
- [ ] Amalgamation `dist/brisk.c` + `dist/brisk.h` (tools/amalg.py), tested in CI
      (blocker found in M2: `aes_ct.c` and `aes_ct64.c` share eight static names -
      `ortho`, `bswap32`, `sbox`, `sub_word`, `skey_expand`, `add_round_key`,
      `mix_columns`, `shift_rows` - so the two cannot land in one TU as they stand.
      Second blocker, `src/os/`: `linux_ca.c` defines `_POSIX_C_SOURCE` and `linux_rand.c`
      defines `_GNU_SOURCE`, each correctly for its own TU. Concatenated in that order the
      first one's `<errno.h>` freezes glibc's feature set before `_GNU_SOURCE` is seen and
      `syscall()` loses its declaration. Hoist both to the top of the amalgamation, or move
      them into `target_compile_definitions(brisk PRIVATE ...)` and delete the in-file blocks)
- [ ] Size budgets per profile; docs/CONFIG.md flag -> KB table generated by CI
- [ ] Docs: API reference from brisk.h, troubleshooting per error code, examples built in CI
- [ ] OpenWrt package Makefile; v0.1.0 release
