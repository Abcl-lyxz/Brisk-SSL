---
description: Add official known-answer test vectors for a Brisk-SSL primitive or protocol step (NIST CAVP, RFC appendices, Wycheproof) to tools/kat.py, cross-checked in Python and emitted to tests/kat/*.inc.
argument-hint: "<primitive, e.g. chacha20-poly1305 | x25519 | rfc8448-handshake>"
---
# Add known-answer vectors for $ARGUMENTS

1. Sources, official only: NIST CAVP/ACVP, the RFC's test-vector appendix (fetch via `fetch()`
   so URL + sha256 land in `tests/kat/SOURCES.md`), C2SP Wycheproof `testvectors_v1/*.json`
   (include its **invalid** cases), RFC 8448 / RFC 9001 traces for protocol steps.
2. In `tools/kat.py`: add a parser + a Python reference (stdlib `hashlib`/`hmac`, or a short
   readable reference implementation) and **re-verify every vector before emitting**; `die()`
   on any mismatch or when fewer vectors than expected were parsed (no silent zero-vector runs).
3. Very large sets: thin them deliberately and say so in a `ponytail:` comment (see LongMsg).
4. Emit `tests/kat/<name>.inc` with `emit()`; run `python tools/kat.py`.
5. Write the C test that consumes it (`tests/test_<module>.c`, unaligned buffers, split
   updates, invalid vectors must fail) **before** the implementation, then `/test`.
