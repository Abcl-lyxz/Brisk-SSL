# armv5: arm-linux-gnueabi, tests run under qemu-arm (sysroot from Debian's libc6-dev-*-cross)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
set(CMAKE_CROSSCOMPILING_EMULATOR qemu-arm -cpu arm926 -L /usr/arm-linux-gnueabi)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_C_FLAGS_INIT "-march=armv5te -marm") # old routers (Kirkwood etc.); qemu arm926 traps anything newer
