#!/bin/bash
# Run brisk_hq against quic-go and ngtcp2 through quic-interop-runner (ns-3 simulator).
# Needs Linux with Docker (IPv6 enabled, NET_ADMIN), python3, tshark >= 4 on PATH. On Windows:
# run it inside WSL2 with Docker Desktop's WSL integration. Usage from the repo root:
#   tools/interop/run_local.sh [servers] [tests]
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SERVERS=${1:-quic-go,ngtcp2}
TESTS=${2:-handshake,transfer,multiplexing,retry,chacha20,keyupdate,resumption}
WORK=${WORK:-$ROOT/build/interop}

docker build -f "$ROOT/tools/interop/Dockerfile" -t brisk-interop:local "$ROOT"
mkdir -p "$WORK"
if [ ! -d "$WORK/quic-interop-runner" ]; then
    git clone --depth 1 https://github.com/quic-interop/quic-interop-runner "$WORK/quic-interop-runner"
fi
cd "$WORK/quic-interop-runner"
python3 -m venv .venv 2>/dev/null || true
. .venv/bin/activate
pip install -q -r requirements.txt
# add (or refresh) our entry: image built above, client role only
python3 - <<'PY'
import json
p = "implementations_quic.json"
d = json.load(open(p))
d["brisk"] = {"image": "brisk-interop:local", "url": "https://github.com/", "role": "client"}
json.dump(d, open(p, "w"), indent=2)
PY
python3 run.py -c brisk -s "$SERVERS" -t "$TESTS" -d -l "$WORK/logs" -j "$WORK/result.json" || true
echo "results: $WORK/result.json, logs: $WORK/logs"
