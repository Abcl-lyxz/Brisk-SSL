---
paths:
  - "src/tls/**"
  - "src/x509/**"
  - "src/quic/**"
  - "src/http/**"
---
# Protocol rules (Brisk-SSL)

- Sans-I/O: engines take bytes/datagrams and a `now` value, produce bytes, expose a deadline.
  No sockets, clocks, malloc or logging side effects inside; `src/os/` does I/O.
- One TLS 1.3 handshake engine serves TCP (record layer) and QUIC (CRYPTO frames): it deals in
  handshake messages tagged by epoch and exports *secrets*, never packet keys.
- Comment every MUST with its section: TLS 1.3 RFC 9846 (traces RFC 8448), X.509 RFC 5280,
  names RFC 9525, HTTP/2 RFC 9113 + HPACK 7541, QUIC RFC 9000/9001/9002, HTTP/3 RFC 9114 +
  QPACK 9204, TLS guidance RFC 9325. Look text up with the `rfc` MCP tools.
- Fail closed: unexpected message, unknown critical extension, bad length, trailing bytes ->
  fatal alert / error. Never "best effort" parsing.
- Parsers bounds-check every length before reading, never recurse on attacker-controlled depth,
  and get a fuzz harness entry (M8).
- Secure defaults: a zero-initialised `brisk_cfg` is the secure configuration; anything
  insecure is an explicit, loudly-logged opt-in. No 0-RTT, no renegotiation, no compression,
  AEAD-only suites, hostname + chain validation always on.
- Client only. ALPN is a free-form string list chosen by the user; no automatic protocol
  switching (h2/h3 are modules the user calls explicitly).
- Get an `rfc-auditor` pass before committing protocol changes.
