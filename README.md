# Brisk-SSL

A small, zero-dependency **C99 SSL/TLS client library for Linux IoT and IIoT devices** -
routers, gateways and industrial boxes on x86, ARM, MIPS, RISC-V and PowerPC.

- **TLS 1.3 and TLS 1.2** client, **QUIC v1**, optional **HTTP/2** and **HTTP/3** modules
- **Easy**: a zero-initialised config is already secure; one config header with three profiles
- **Small**: no malloc in the core, dead-code elimination friendly, size tracked per module per arch
- **Portable**: tested on 10 CPU architectures (incl. big-endian MIPS/PowerPC and ARMv5) under qemu
- **Honest crypto**: official NIST / RFC / Wycheproof vectors, constant-time code, formally
  verified field arithmetic (fiat-crypto) for X25519 and P-256

> Status: **early development** (milestone M1, crypto). The hash layer is done; TLS is not usable
> yet. See [docs/ROADMAP.md](docs/ROADMAP.md).

## What it will look like
```c
#include "brisk.h"

brisk_cfg cfg = BRISK_DEFAULTS;              /* secure defaults */
cfg.alpn    = "x-amzn-http-ca";              /* any ALPN: "h2", "mqtt", ... */
cfg.ca_file = "/etc/ssl/certs/ca-certificates.crt";

brisk_conn *c;
if (brisk_connect(&cfg, "iot.example.com", 443, &c) == BRISK_OK) {
    brisk_write(c, request, request_len);    /* you decide what to send */
    n = brisk_read(c, buf, sizeof buf);      /* >0 data, 0 close_notify, <0 BRISK_E_* */
    brisk_close(c);
}
```
Brisk is an SSL library, not an HTTP client: run MQTT, HTTP/1.1 or your own protocol over the TLS
stream, or use the optional `brisk_h2_*` / `brisk_h3_*` modules explicitly.

## Available today
```c
uint8_t digest[BRISK_SHA256_LEN], mac[BRISK_SHA256_LEN];
brisk_sha256(data, len, digest);
brisk_hmac(BRISK_HASH_SHA256, key, key_len, msg, msg_len, mac);   /* e.g. cloud SAS tokens */
```

| Module | Flash, armv7 Thumb-2 | Flash, MIPS32 |
|---|---|---|
| SHA-256/384/512 + HMAC + HKDF | 4.2 KB | 7.7 KB |

Full table: [docs/CONFIG.md](docs/CONFIG.md).

## Build
```sh
cmake --workflow --preset dev                 # host build + tests (gcc)
python tools/dev.py test --arch all           # every arch under qemu (needs Docker)
python tools/dev.py size --arch all --md      # per-module size table
```
Or add `src/` and `include/` to your own build: plain C99, no dependencies. Configuration:
[docs/CONFIG.md](docs/CONFIG.md). Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License
Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Security issues: [SECURITY.md](SECURITY.md).
