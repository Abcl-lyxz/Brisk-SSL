---
description: Resume Brisk-SSL work - pick the next unchecked docs/ROADMAP.md task and implement it test-first. Use when the user says ต่อ / continue / next, or gives no specific task.
argument-hint: "[task or milestone, optional]"
---
# Continue Brisk-SSL

1. Read `.claude/state/handoff.md` and `docs/ROADMAP.md`. The task is `$ARGUMENTS` if given,
   otherwise the first unchecked `- [ ]` item. Say in one line what you are starting (reply in
   Thai when the user writes Thai). Only ask the user when a real design decision is open.
   No unchecked item left: propose the next milestone from `## Backlog` (options +
   recommendation), and once the user picks, add it as `## Mx` with `- [ ]` tasks, then start.
2. Understand before coding: read the RFC sections with the `rfc` MCP tools (`rfc_get`,
   `rfc_search`) - cite RFC 9846 for TLS 1.3, not 8446 - and the existing code it touches.
3. Test-first:
   - official vectors via `/kat <primitive>` (never hand-typed), then `tests/test_<module>.c`
   - implement following `.claude/rules/` (loaded automatically for src/, tests/, ...)
   - `python tools/dev.py test` (host, fast) -> `python tools/dev.py test --arch all` (11 Docker presets)
   - `python tools/dev.py size --arch all` and report the size delta (`--save` only when intended)
4. Non-trivial modules: run the `/implement-module` workflow instead of doing it inline.
   Crypto/protocol changes get the `crypto-reviewer`, `portability-reviewer`, `rfc-auditor`
   agents before commit.
5. Tick the ROADMAP box, commit with a scoped message (`crypto:`, `x509:`, `tls:`, `http:`,
   `quic:`, `build:`, `docs:`), then continue with the next task unless the user said stop.
   Before the session ends run `/handoff`.
