# Brisk-SSL

A small, zero-dependency **C99 SSL/TLS client library for Linux IoT and IIoT devices** -
routers, gateways and industrial boxes on x86, ARM, MIPS, RISC-V and PowerPC.

- **TLS 1.3 and TLS 1.2** client, **QUIC v1**, optional **HTTP/2** and **HTTP/3** modules
- **Easy**: `BRISK_DEFAULTS` is already the secure configuration; one config header, three profiles
- **Small**: 52-97 KB of flash for TLS 1.3 (TINY), 71-134 KB with TLS 1.2 + HTTP/2 (DEFAULT);
  no malloc in the core, every context caller-owned, size budgets enforced in CI
- **Portable**: tested on 10 CPU architectures under qemu, incl. big-endian MIPS / PowerPC and
  ARMv5; glibc and musl (OpenWrt)
- **Honest crypto**: official NIST / RFC / Wycheproof vectors, constant-time code checked
  under valgrind, formally verified field arithmetic (fiat-crypto) for X25519 and P-256

> Status: **v0.1.0**, the first release. The API may still change before 1.0. Security
> reports: [SECURITY.md](SECURITY.md).

## Quick start: a TLS stream
```c
#include "brisk.h"

brisk_cfg cfg = BRISK_DEFAULTS;   /* system CA bundle, hostname check, TLS 1.3 then 1.2 */
cfg.alpn = "mqtt";                /* optional, any list: "h2,http/1.1", "x-amzn-mqtt-ca" */

brisk_conn *c;
int rc = brisk_connect(&cfg, "broker.example.com", 8883, &c);
if (rc == BRISK_OK) {
    brisk_write(c, packet, packet_len);         /* you decide what to send */
    int n = brisk_read(c, buf, sizeof buf);     /* > 0 data, 0 close_notify, < 0 BRISK_E_* */
    brisk_close(c);
}
```
Brisk is an SSL library, not an HTTP client: run MQTT, HTTP/1.1 or your own protocol over the
stream. Error codes and what to do about them: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

Also available:
- **mTLS**: an ECDSA P-256 device key (`cfg.client_chain` + `cfg.client_key`) or a secure
  element through the `cfg.sign` callback. With a TLS 1.2 server, only `client_key` works: the
  `sign` callback is TLS 1.3 only in v0.1.0
- **Session resumption**: `cfg.on_ticket` hands you tickets, and `cfg.ticket` offers one next time
- **Sans-I/O**: the same connection in your own event loop and memory, with `brisk_conn_init`,
  `brisk_feed`, `brisk_pull`, `brisk_app_read` and `brisk_app_write`

## HTTP/2 and HTTP/3 (optional modules, called explicitly)
```c
cfg.alpn = "h2";                                         /* HTTP/2 over the TLS stream */
brisk_connect(&cfg, host, 443, &c);
brisk_h2_open(c, mem, brisk_h2_size(), &h);
brisk_h2_request(h, "GET", "/v1/status", NULL, 0, NULL, 0, &s);
brisk_h2_response(s, &status, NULL, NULL);
while ((n = brisk_h2_read(s, buf, sizeof buf)) > 0) { ... }

cfg.alpn = "h3";                                         /* HTTP/3 over QUIC (FULL profile) */
brisk_quic_connect(&cfg, host, 443, &q);
brisk_h3_open(q, mem, brisk_h3_size(), &h3);             /* then the same request/response calls */
```
Complete programs: [`examples/`](examples) (`brisk_get`, `h2_get`, `h3_get`, `mqtt_tls`,
`aws_iot_https`). Every public call is listed in [docs/API.md](docs/API.md), and
[`include/brisk.h`](include/brisk.h) has the full contracts.

## Tested against real servers (2026-09-25)
| What | Result |
|---|---|
| TLS 1.3 / 1.2 + HTTP/1.1: google, cloudflare, github, wikipedia, amazon, apple, facebook, microsoft, example.com, sanook, kasikornbank | all connect |
| HTTP/2: google, cloudflare, github, wikipedia, nghttp2.org (also 4 parallel requests, POST) | all complete |
| HTTP/3: cloudflare-quic.com, google, facebook, quic.nginx.org, cloudflare (also 4 parallel) | all complete |
| QUIC interop runner (ns-3) vs quic-go and ngtcp2 | 14/14 |
| badssl.com: expired, wrong host, self-signed, untrusted root, RC4, 3DES, DH-1024, TLS 1.0/1.1 | all refused |
| Resumption: cloudflare, google | resumed |
| MQTT over TLS: broker.emqx.io | published |

## Integrate
| Way | How |
|---|---|
| CMake | `add_subdirectory(Brisk-SSL)` + `target_link_libraries(app PRIVATE brisk)`, or `cmake --install` (libbrisk.a + 2 headers) |
| Two files | `python tools/amalg.py` writes `dist/brisk.c` + `dist/brisk.h`: `cc -std=c99 -Os -c brisk.c` |
| OpenWrt | [`openwrt/brisk-ssl/Makefile`](openwrt/brisk-ssl/Makefile): `libbrisk-ssl` (build-only) and `brisk-get` |
| By hand | add `src/**/*.c` and `include/` to your build: plain C99, no dependencies |

Choose a profile with `-DBRISK_PROFILE=TINY|DEFAULT|FULL`:
- **TINY**: TLS 1.3 only
- **DEFAULT**: adds TLS 1.2, mTLS, P-384 and HTTP/2
- **FULL**: adds QUIC and HTTP/3

Knobs and the measured size per profile and architecture are in [docs/CONFIG.md](docs/CONFIG.md).

## What it refuses, always
No SSL 3.0, TLS 1.0 or TLS 1.1. No CBC, RC4, 3DES, static-RSA or DHE suites. No TLS 1.2 without
extended master secret, no renegotiation, no compression and no 0-RTT. Certificate chain and
host name verification cannot be switched off.

A server below that floor gets `BRISK_E_INSECURE`.

## Develop
```sh
cmake --workflow --preset dev                 # host build + tests
python tools/dev.py test --arch all           # every arch under qemu (Docker)
python tools/dev.py ct                        # constant-time check under valgrind
python tools/dev.py fuzz der --seconds 60     # libFuzzer on any parser (der, pem, conn, h3, ...)
python tools/dev.py amalg                     # dist/brisk.c: every profile, gcc + clang, + tests
python tools/dev.py size --profiles           # flash per profile vs size/budget.json
python tools/dev.py interop                   # vs openssl s_server, nginx, Caddy, h2o, nghttpd
python tools/dev.py badssl                    # vs badssl.com (Docker + internet)
```
Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). History and plan: [docs/ROADMAP.md](docs/ROADMAP.md).

## License
Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
