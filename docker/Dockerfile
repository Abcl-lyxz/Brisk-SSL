# brisk-dev: every cross toolchain + qemu-user + analysis tools in one image.
# Debian trixie is pinned on purpose: its successor drops the MIPS cross compilers.
# Tests run through qemu via CMAKE_CROSSCOMPILING_EMULATOR, so no binfmt/privileged mode is needed.

# h2o (HTTP/2 interop server) is not packaged in trixie: build a pinned commit, copy the binary.
FROM debian:trixie-slim AS h2o
ARG DEBIAN_FRONTEND=noninteractive
ARG H2O_COMMIT=cac7e6568ad98a848f099ecd0a18b881f632479a
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates libssl-dev zlib1g-dev \
    && git init -q /h2o && cd /h2o \
    && git fetch -q --depth 1 https://github.com/h2o/h2o.git $H2O_COMMIT && git checkout -q FETCH_HEAD \
    && cmake -S . -B b -G Ninja -DCMAKE_BUILD_TYPE=Release -DWITH_MRUBY=OFF \
    && ninja -C b h2o

FROM debian:trixie-slim
ARG DEBIAN_FRONTEND=noninteractive
# libc6-dev-*-cross are only "Recommends" of the gcc cross packages -> list them explicitly.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build python3 git ca-certificates curl file \
        clang lld llvm libclang-rt-dev clang-format clang-tidy cppcheck valgrind \
        qemu-user \
        openssl nginx-light caddy nghttp2-server \
        gcc-i686-linux-gnu        libc6-dev-i386-cross \
        gcc-aarch64-linux-gnu     libc6-dev-arm64-cross \
        gcc-arm-linux-gnueabihf   libc6-dev-armhf-cross \
        gcc-arm-linux-gnueabi     libc6-dev-armel-cross \
        gcc-mips-linux-gnu        libc6-dev-mips-cross \
        gcc-mipsel-linux-gnu      libc6-dev-mipsel-cross \
        gcc-mips64-linux-gnuabi64 libc6-dev-mips64-cross \
        gcc-riscv64-linux-gnu     libc6-dev-riscv64-cross \
        gcc-powerpc-linux-gnu     libc6-dev-powerpc-cross \
    && rm -rf /var/lib/apt/lists/*

COPY --from=h2o /h2o/b/h2o /usr/local/bin/h2o

WORKDIR /src
