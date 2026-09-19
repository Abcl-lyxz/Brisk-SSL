# brisk-dev: every cross toolchain + qemu-user + analysis tools in one image.
# Debian trixie is pinned on purpose: its successor drops the MIPS cross compilers.
# Tests run through qemu via CMAKE_CROSSCOMPILING_EMULATOR, so no binfmt/privileged mode is needed.
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
# libc6-dev-*-cross are only "Recommends" of the gcc cross packages -> list them explicitly.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build python3 git ca-certificates curl file \
        clang lld llvm libclang-rt-dev clang-format clang-tidy cppcheck valgrind \
        qemu-user \
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

WORKDIR /src
