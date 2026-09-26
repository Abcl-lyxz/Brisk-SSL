# Troubleshooting by error code

What each `BRISK_E_*` means in the field, the usual causes, and what to try. The contract of every
code is in [`include/brisk.h`](../include/brisk.h) (index: [API.md](API.md)). The examples print
the name (`brisk: connect failed: E_AUTH ...`); in your own code, `brisk_alert(c)` gives the TLS
alert behind `E_PEER_ALERT` (the one the server sent) and, on the sans-I/O API, `brisk_pull`
hands you the one Brisk sends back.

Quick triage: run `openssl s_client -connect HOST:PORT -servername HOST -tlsextdebug` from the
same network. If OpenSSL also fails, the problem is the server or the path, not Brisk.

## `BRISK_E_AUTH` (-3): the server's certificate or signature is not acceptable

The handshake reached the certificate and it did not pass. In order of likelihood:

- **The CA is not trusted.** With `ca_file` and `ca_mem` both NULL, Brisk reads the system bundle
  (`/etc/ssl/certs/ca-certificates.crt` and the other usual paths - see `src/os/linux_ca.c`). A
  stripped firmware image often ships none: install `ca-certificates` or point `ca_file` at a
  bundle. A private broker CA (test.mosquitto.org, most factory MQTT) needs `ca_file` / `ca_mem`
  with THAT CA; `ca_mem` alone trusts only what you give it.
- **The device clock.** A gateway without RTC or NTP boots in 1970 or at its build date.
  `BRISK_X509_TIME_POLICY` decides what happens then (default FLOOR: the firmware's build time
  stands in for "now"); STRICT refuses every certificate until the clock is set. Set the time
  (NTP) before the first connection, or read `docs/CONFIG.md` before choosing another policy.
- **The name does not match.** The `host` you pass is checked against the certificate's SAN
  (RFC 9525); connect with the name, not the IP, unless the certificate lists the IP.
- **An incomplete chain.** The server does not send its intermediate. Browsers fetch it (AIA);
  Brisk does not. Fix the server, or add the intermediate to `ca_mem`.
- **An unsupported key.** Server keys: ECDSA P-256 / P-384, RSA 2048..`BRISK_RSA_MAX_BITS`.
  Ed25519 and RSA-1024 server certificates are refused.
- On an established connection: a record that fails authentication (tampered or corrupted data).

## `BRISK_E_INSECURE` (-10): the server is below the security floor

The server speaks TLS correctly, but only in a way Brisk will never accept, and no setting
lowers that floor:

- **TLS 1.2 without Extended Master Secret** (RFC 7627) or without `renegotiation_info`
  (RFC 5746), both required by RFC 9325. OpenSSL shows it as `Extended master secret: no`.
  Seen in the field (2026-09): badssl.com and the public broker.hivemq.com:8883 - old nginx /
  Java TLS stacks, common on IoT brokers.
- **TLS 1.1, 1.0 or SSL 3.0 only** (RFC 8996).

The fix is on the server: enable TLS 1.3, or update its TLS library (EMS is on by default in
every maintained one). Retrying does not help.

## `BRISK_E_PEER_ALERT` (-5): the server gave up

The server sent a fatal alert; `brisk_alert(c)` returns it (RFC 9846 6.2 numbering):

| alert | usual meaning |
|---|---|
| 40 handshake_failure | no common suite / group / signature scheme: a server that only offers CBC, RC4, 3DES, static RSA, DHE or finite-field groups; or it demands a client certificate you did not configure |
| 70 protocol_version | a TLS 1.0 / 1.1 only server |
| 42..46, 48 (certificate alerts) | the server rejected OUR client certificate (mTLS): wrong CA, expired device cert |
| 112 unrecognized_name | the server has no certificate for that SNI name |
| 120 no_application_protocol | none of `cfg.alpn` is served there |
| 0 close_notify before the handshake finished | the server closed on us (overload, IP filter) |

A close before the handshake completed is never reported as a clean end: nothing was
authenticated yet. With `brisk_h2_*` / `brisk_h3_*`, this code also means the server reset the
stream or sent GOAWAY with an error.

## `BRISK_E_PROTO` (-4): the server broke the protocol

A message out of order, a bad length, an extension the RFC forbids. Brisk has already sent the
matching fatal alert. It is rare against mainstream servers. If one reproduces, capture it
(`tcpdump -w`) and compare with `openssl s_client`; it may be a middlebox (a "TLS inspection"
firewall, a captive portal answering in HTTP) rather than the server itself.

## `BRISK_E_IO` (-6): the network failed

DNS failed, the TCP connect was refused, the socket errored, or the server's TCP FIN arrived
before its close_notify. After you have read data, a bare FIN from an HTTP/1.1 server with
`Connection: close` is common and harmless (`brisk_get` treats it as done); before any data it
is a truncation. QUIC: the idle timeout closed the connection.

Check: DNS and a default route on the device, a firewall between you and port 443/8883, and for
QUIC that UDP 443 leaves your network at all (many corporate networks block it - fall back to
TCP + h2).

## `BRISK_E_TIMEOUT` (-7): nothing happened for `cfg.timeout_ms`

From `brisk_read` it is harmless - call again. From `brisk_connect` the attempt is over. From
`brisk_write` it is final (a half-sent record may be on the wire): close the connection.
A host that does not answer at all (seen: mqtt.eclipseprojects.io:8883) ends here, not in E_IO.

## `BRISK_E_ARG` (-1): the call itself is wrong

A caller mistake or a local limit, never the peer: a NULL or too-short buffer, an invalid host
string (1..255 bytes, A-labels for IDNs), an ALPN entry that is empty or longer than 255, a
`client_key` that does not parse or does not match the chain's leaf, a device chain over
`BRISK_TLS_MAX_CLIENT_CHAIN` (DER bytes) or with a malformed PEM block, a stream
call on a stream that is already closed. Also a `sign` callback that refused (internal_error),
and mTLS with a `sign` callback against a TLS 1.2 server that asks for a certificate: in v0.1.0
the callback works over TLS 1.3 only - use `client_key` there, or enable TLS 1.3 on the server.

A `client_key` is refused (setup returns `BRISK_E_ARG`, your key buffer untouched) when it is
encrypted (`ENCRYPTED PRIVATE KEY`, or `Proc-Type: 4,ENCRYPTED` inside `EC PRIVATE KEY`), on a
curve other than P-256 (prime256v1), not the key of the leaf certificate in `client_chain`, BER
rather than DER, or followed by trailing bytes; also a PEM file with zero or two key blocks, and
a SEC1 key whose private scalar is 31 octets (a sloppy encoder stripped a leading zero). Fix any
of these with `openssl pkey -in key.pem -out key2.pem` (add `-passin` for an encrypted key).

## `BRISK_E_RNG` (-2): no kernel randomness

`getrandom()` is missing or blocked. A seccomp filter must allow `getrandom` (and `poll` /
`/dev/random` on kernels before 3.17); on very early boot, wait for the entropy pool.

## `BRISK_E_RETRY` (-9): HTTP/2 or HTTP/3 request not processed

The server guaranteed it did not act on the request (REFUSED_STREAM, a GOAWAY above it, or a
request made after GOAWAY). Retry it on a NEW connection - safe even for a POST.

## `BRISK_E_WANT` (-8): not an error

Sans-I/O only: feed more bytes first (`brisk_feed`), then call again.

## Session resumption does not resume

`brisk_resumed(c)` stays 0 although you store and hand back tickets (`-T FILE` in brisk_get):

- Set `cfg.on_ticket`: without it Brisk does not ask for tickets at all.
- Offer the ticket to the SAME `host` string, over the same transport (TCP tickets over QUIC are
  refused, and the reverse).
- Many large sites spread connections over machines with different ticket keys, or do not
  resume at all: in the 2026-09 run cloudflare.com and google.com resumed every time,
  example.com 5 of 6, github.com and facebook.com never (OpenSSL neither). Not a failure: the
  handshake is just a full one.
