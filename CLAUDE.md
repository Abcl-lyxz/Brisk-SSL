# Brisk-SSL

Zero-dependency **C99 SSL/TLS client library for Linux IoT/IIoT devices** (routers, gateways) on
many CPU archs. TLS 1.3 + 1.2, QUIC v1, optional HTTP/2 and HTTP/3 modules. Goals: dead-simple
config with secure defaults, tiny binary, low RAM/CPU, fast. The user writes Thai; reply in Thai
when they do. Code, comments, commits and docs are English.

## Resume rule
If the user says "ต่อ", "continue", "next" or gives no specific task → run **`/next`** right away
(the SessionStart hook already injected the current milestone and last handoff). Before the
session ends run **`/handoff`**.

## Locked decisions (don't re-litigate; see docs/ARCHITECTURE.md for the why)
- C99, zero deps (libc + Linux syscalls). Linux only; archs: x86_64 i686 aarch64 armv7hf armv5
  mips(BE) mipsel mips64 riscv64 ppc(BE).
- **Client only.** An SSL library, not an HTTP client: the core is a TLS stream
  (`brisk_connect/read/write/close` + sans-I/O `brisk_feed/pull`); users send what they want
  (MQTT, HTTP/1.1, custom). h2/h3 are optional modules called explicitly - no auto protocol
  switching. ALPN is a free-form string list.
- Crypto in-house; only fiat-crypto field arithmetic (X25519, P-256) is vendored. mTLS = ECDSA
  P-256 device keys (+ sign callback). RSA = verify only. P-384 = verify only.
- Order: M1 crypto → M2 X.509 → M3 TLS 1.3 → M4 h2 → M5 TLS 1.2 → M6 QUIC → M7 h3 → M8 release.
- Config: only `include/brisk_config.h` (profiles TINY/DEFAULT/FULL + tri-state knobs, deps
  auto-resolved). Public struct sizes never depend on config.
- Cite RFC 9846 for TLS 1.3 (it obsoletes 8446/5246/7627/8422/5077). Apache-2.0.

## Layout
```
include/brisk.h        public API = the reference docs      include/brisk_config.h  the only config
src/brisk_int.h        internal decls (brisk__ prefix)      src/util.c              ct compare, wipe, build info
src/crypto/            sha2 hkdf aead ec bn rsa             src/x509/               der.c (+ cert, chain, names next)
src/{tls,quic,http}/   later milestones                     src/os/                 linux_rand.c
tests/test_*.c         suites (runner: tests/test_main.c)   tests/kat/*.inc         generated vectors, don't edit
fuzz/fuzz_*.c          libFuzzer entry points               tools/kat.py            fetch + verify vectors
tools/dev.py           test / size / ct / fuzz / image      tools/mcp/rfc_server.py MCP: rfc_get / rfc_search
docker/Dockerfile      cross gcc + qemu image               size/baseline.json      size regression baseline
docs/ROADMAP.md  docs/ARCHITECTURE.md  docs/CONFIG.md
```

## Commands
| What | Command |
|---|---|
| host tests (fast, x64 + x86) | `python tools/dev.py test` |
| every arch under qemu | `python tools/dev.py test --arch all` (or `--arch mips ppc`) |
| constant-time check (valgrind) | `python tools/dev.py ct` |
| fuzz a parser (clang + ASan/UBSan) | `python tools/dev.py fuzz der --seconds 60` |
| size table / save baseline | `python tools/dev.py size --arch all --md` / `... --save` |
| regenerate vectors | `python tools/kat.py` |
| rebuild Docker image | `python tools/dev.py image` |
| one preset directly | `cmake --workflow --preset dev` |

## Claude Code setup in this repo
- Skills: `/next` `/handoff` `/test` `/size` `/kat` `/ct-check` `/new-module`
- Workflows: `/implement-module <task>` (spec → vectors → tests → code → 3 reviewers → fix loop),
  `/audit [path]` (read-only multi-lens security audit)
- Agents: `crypto-reviewer`, `portability-reviewer`, `rfc-auditor`
- Rules (auto-loaded by path): `.claude/rules/{c-code,crypto,protocol,build}.md`
- Hooks: session context on start; clang-format + `gcc -fsyntax-only` after C edits; tests must
  pass before stopping when C changed; edits to `vendor/` and destructive git are blocked.
- MCP `rfc`: exact RFC text - use it instead of memory for any protocol detail.

## Working rules
- Test-first with official vectors (`/kat`); never hand-type vectors.
- Before committing: `python tools/dev.py test --arch all` green, size delta explained.
- Commit messages scoped: `crypto:`, `x509:`, `tls:`, `http:`, `quic:`, `build:`, `docs:`, `claude:`.
- Never force-push; `main` is the only branch for now.
