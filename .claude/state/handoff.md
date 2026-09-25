# Handoff - 2026-09-25 (session 23)

## Done - live testing, M8 complete, v0.1.0 released
- 1249a9a **tls:** first found by live testing. Tickets never arrived from real servers because
  CH1 carried psk_key_exchange_modes only alongside a PSK. It now sends them whenever
  cfg.on_ticket is set. cloudflare/google resume; github/facebook don't resume with OpenSSL either.
- 9badc3e **tls:** new public `BRISK_E_INSECURE` (-10) for TLS 1.2 without EMS/RI and for
  TLS <= 1.1 (the alert is unchanged). CH2 keeps psk modes when the HRR drops the PSK.
  rfc-auditor: clean.
- e54a699 **build:** fuzz_pem, tools/amalg.py plus `dev.py amalg` (every profile, gcc+clang
  -Werror, suite against dist/), size budgets (`size/budget.json`, `dev.py size --profiles`),
  CMake install(), openwrt/brisk-ssl.
- ce03993 / 7ad5731 **docs:** API.md is generated (tools/apidoc.py). Added TROUBLESHOOTING.md.
  README, SECURITY, ARCHITECTURE, CONFIG and CLAUDE.md now match the code. Version is "0.1.0".
- **v0.1.0 tagged at 7ad5731**, and the GitHub release has dist/brisk.{c,h} attached. CI was
  green (all archs, amalg, size budgets) and interop was 14/14 on the same commit.
- e2fdc8f **build:** the OpenWrt Makefile is pinned to the commit and PKG_MIRROR_HASH. The SDK
  (openwrt/sdk:x86-64-24.10.2) downloads, verifies and builds from the tag.

## In progress
- Nothing. The tree is clean and every ROADMAP milestone (M1-M8) is ticked.

## Next up (post-1.0 backlog - ask the user which one; ROADMAP has no open item)
1. The mTLS `sign` callback over TLS 1.2: today it fails closed (E_ARG). It needs a digest-scheme
   or a pre-hashed callback variant (brisk.h:389). This is the only documented functional gap.
2. A runtime X.509 time floor from device storage (ARCHITECTURE "Clock policy").
3. Add ROADMAP "M9 / 0.2" once the user picks. Candidates: shared lib (.so), revocation
   (OCSP stapling), SPKI pins.

## Decisions / gotchas
- EMS stays required (user, 2026-09-25): an old server gets a clear E_INSECURE, not an opt-in knob.
- Live-run findings are in docs/TROUBLESHOOTING.md.
  - E_INSECURE: badssl.com and broker.hivemq.com.
  - Unreachable: mqtt.eclipseprojects.io:8883.
  - Private CA: test.mosquitto.org, so E_AUTH unless you pass ca_file.
- OpenWrt-built binaries need libgcc_s: a weak __register_frame_info from the toolchain's
  crtbegin. It's in default images, so this isn't a Brisk bug.
- The Bash tool heredoc eats backslashes ("\\n" becomes a real newline). Write Python snippets
  with the Write tool, or use chr(92).
- Low memory on this PC reaps background watchers. Poll CI with a foreground loop instead
  (`gh run view ID --json status,conclusion`, sleep 60, 9 min per call).
