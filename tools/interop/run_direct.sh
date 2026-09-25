#!/bin/bash
# Fallback when the ns-3 simulator cannot forward traffic (seen on WSL2): brisk_hq against a
# server image on a plain Docker bridge - no loss, no delay, same endpoint contract otherwise
# (server TESTCASE, /certs from the runner's certs.sh, /www, /downloads; client verifies).
# Usage: tools/interop/run_direct.sh <runner checkout> [server image] [tests]
set -u
RUNNER=${1:?path to a quic-interop-runner checkout (for certs.sh)}
IMAGE=${2:-martenseemann/quic-go-interop:latest}
TESTS=${3:-handshake transfer multiplexing retry chacha20 keyupdate resumption}
W=$(mktemp -d)
mkdir -p "$W/www" "$W/certs"
(cd "$RUNNER" && ./certs.sh "$W/certs" 1 >/dev/null 2>&1)
docker network create bqnet >/dev/null 2>&1
for t in $TESTS; do
    rm -rf "$W/dl" && mkdir -p "$W/dl" "$W/logs/$t/server/qlog"
    rm -f "$W"/www/*
    case $t in
    transfer) sizes="2097152 3145728 5242880" ;;
    multiplexing) sizes=$(for i in $(seq 1 200); do echo 32; done) ;;
    keyupdate) sizes="1048576" ;;
    resumption) sizes="1024 2048 4096" ;;
    *) sizes="1024" ;;
    esac
    reqs=""
    i=0
    for s in $sizes; do
        i=$((i + 1))
        head -c "$s" /dev/urandom >"$W/www/f$i"
        reqs="$reqs https://server4:443/f$i"
    done
    st=$t # the runner's server-side test name (testcases_quic.py testname(SERVER))
    case $t in multiplexing | keyupdate) st=transfer ;; esac
    docker rm -f server4 >/dev/null 2>&1
    docker run -d --name server4 --network bqnet --cap-add NET_ADMIN -v "$W/certs:/certs:ro" \
        -v "$W/www:/www:ro" -v "$W/logs/$t/server:/logs" -e QLOGDIR=/logs/qlog -e SSLKEYLOGFILE=/logs/keys.log -e ROLE=server -e TESTCASE="$st" "$IMAGE" >/dev/null
    sleep 3
    docker run --rm --network bqnet --entrypoint brisk_hq -v "$W/certs:/certs:ro" \
        -v "$W/dl:/downloads" -v "$W/logs/$t:/logs" -e TESTCASE="$t" -e REQUESTS="${reqs# }" \
        -e SSLKEYLOGFILE=/logs/keys.log brisk-interop:local >"$W/logs/$t/client.txt" 2>&1
    rc=$?
    ok=$rc
    if [ $rc -eq 0 ]; then
        for f in "$W"/www/*; do
            cmp -s "$f" "$W/dl/$(basename "$f")" || ok=2
        done
    fi
    echo "$t: exit $rc, files $([ $ok -eq 0 ] && echo identical || echo MISMATCH)"
    [ $rc -ne 0 ] && tail -3 "$W/logs/$t/client.txt"
done
docker rm -f server4 >/dev/null 2>&1
echo "logs: $W/logs"
