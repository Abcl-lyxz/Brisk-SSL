# QUIC interop harness (M6 item 4)

`brisk_hq` is an hq-interop client for [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner):
the public blocking API (`brisk_quic_connect`, `brisk_quic_stream_*`, `brisk_quic_close`) plus
four internal seams from `src/brisk_int.h` that no shipped build can reach: the offered suite
list (chacha20), an NSS key log (`SSLKEYLOGFILE`), an initiated key update (keyupdate) and one
I/O round while no stream slot is free. Certificate verification stays on: the runner mounts its
per-run CA at `/certs/ca.pem` in the client container too (checked in its `docker-compose.yml`),
and the leaf names `server4` - no insecure switch was needed.

| file | what |
|---|---|
| `Dockerfile` (+ `.dockerignore`) | multi-stage on `martenseemann/quic-network-simulator-endpoint`: static FULL lib + `brisk_hq` |
| `run_endpoint.sh` | the endpoint contract: `/setup.sh`, client role only, `wait-for-it sim:57832`, unsupported cases exit 127 |
| `brisk_hq.c` | the client: `$REQUESTS` URLs, `GET /path\r\n` + FIN per bidi stream, body to `/downloads/<basename>` |
| `run_local.sh` | the real runner (ns-3 simulator): clones it, registers `brisk`, `run.py -c brisk -s quic-go,ngtcp2 -t ...` |
| `run_direct.sh` | fallback without the simulator: server image + `brisk_hq` on a plain Docker bridge |

Build knobs of the harness image (brisk_config.h knobs only): `BRISK_QUIC_STREAM_BUF=65536`,
`BRISK_QUIC_MAX_STREAMS=16`, `BRISK_QUIC_CRYPTO_BUF=16384` - the default 4 x 4 KB windows would
crawl through the transfer case's megabytes at the simulator's 30 ms RTT.

## Results

**ns-3 simulator on GitHub Actions (2026-09-25, `.github/workflows/interop.yml`, ubuntu-24.04,
Docker upgraded to current): 14 / 14** - all 7 cases x quic-go and ngtcp2 under
`simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25`. Run it with `gh workflow run
interop.yml` (inputs `servers`, `tests`); the job fails unless every case succeeded, and the
logs + pcaps are the `interop` artifact. Gotcha found there: the runner passes
`TESTCASE=transfer` to the client in its multiplexing test, so brisk_hq keeps every stream slot
in flight for all transfer-family cases (one request per RTT missed the 60 s limit).

**ns-3 simulator on WSL2 (Windows 11, Docker 29.7.2, tshark 4.2.2): BLOCKED by the environment.** The runner, the simulator and
all three containers start; `handshake` against quic-go fails with a timeout, and so does
**quic-go client vs quic-go server** - the simulator's pcaps show no UDP at all while the
client's own capture shows its 1200-byte Initials leaving `eth0` (checksums OK, DF set). The
ns-3 bridge does not forward UDP under this WSL2 kernel (5.15.167.4-microsoft-standard-WSL2).
Rerun `run_local.sh` on a native Linux Docker host to get the lossy-link results.

**Direct (`run_direct.sh`, no simulator: no loss, no delay):** 14 / 14, every downloaded file
byte-identical to the served one.

| case | quic-go (martenseemann/quic-go-interop) | ngtcp2 (ghcr.io/ngtcp2/ngtcp2-interop) |
|---|---|---|
| handshake | pass | pass |
| transfer (2 + 3 + 5 MB) | pass | pass |
| multiplexing (200 files) | pass | pass |
| retry | pass | pass |
| chacha20 | pass | pass |
| keyupdate (1 MB, client-initiated update) | pass | pass |
| resumption (ticket from connection 1, `brisk_quic_resumed` on 2) | pass | pass |

Notes: the direct mode passes each server the runner's server-side test name (`multiplexing`
and `keyupdate` run the server's `transfer`); ngtcp2's endpoint script needs `QLOGDIR` set and
writable. Not covered here: loss, reordering, the simulator's bandwidth limit, amplification
limits - the ns-3 run is still owed.
