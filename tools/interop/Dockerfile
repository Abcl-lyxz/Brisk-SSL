# brisk-interop: the Brisk-SSL hq-interop client for quic-interop-runner (M6 item 4).
# Build from the repository root:  docker build -f tools/interop/Dockerfile -t brisk-interop:local .
#
# The harness build raises the QUIC RAM knobs (brisk_config.h knobs only, nothing else): the
# default 4 x 4 KB stream windows would crawl through the transfer case's MBs at the simulator's
# 30 ms RTT. Recorded in tools/interop/README.md.
FROM martenseemann/quic-network-simulator-endpoint:latest AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*
COPY CMakeLists.txt /src/
COPY include /src/include
COPY src /src/src
COPY vendor /src/vendor
COPY tools/interop/brisk_hq.c /src/tools/interop/
ARG KNOBS="-DBRISK_QUIC_STREAM_BUF=65536 -DBRISK_QUIC_MAX_STREAMS=16 -DBRISK_QUIC_CRYPTO_BUF=16384"
RUN cmake -S /src -B /b -G Ninja -DCMAKE_BUILD_TYPE=Release -DBRISK_PROFILE=FULL \
        -DBRISK_BUILD_TESTS=OFF -DBRISK_BUILD_EXAMPLES=OFF -DCMAKE_C_FLAGS="$KNOBS" \
    && cmake --build /b \
    && gcc -std=c99 -O2 -Wall -Wextra $KNOBS -DBRISK_PROFILE=BRISK_PROFILE_FULL \
        -I/src/include -I/src/src /src/tools/interop/brisk_hq.c /b/libbrisk.a -o /brisk_hq

FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=build /brisk_hq /usr/local/bin/brisk_hq
COPY tools/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
