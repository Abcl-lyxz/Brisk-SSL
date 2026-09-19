/* linux_rand.c - the kernel CSPRNG, the library's only source of randomness (Linux only).
 *
 * getrandom(2) (Linux >= 3.17) with flags 0 blocks until the kernel pool is initialised and never
 * blocks afterwards. If it is missing (ENOSYS) or a seccomp filter rejects it (EPERM) on a kernel
 * older than 4.8, use the libsodium/OpenSSL recipe: wait once until /dev/random is readable, which
 * on those kernels means /dev/urandom has been seeded, then read /dev/urandom. From 4.8 on that
 * no longer holds and getrandom always exists, so a filter that blocks it gets BRISK_E_RNG, as
 * does every other failure. There is no userspace DRBG, so fork() can never duplicate output.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE /* syscall(); must precede every #include */
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/personality.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "brisk_int.h"

/* getrandom's syscall number, so it works when the toolchain's kernel headers predate 3.17
 * (common in router SDKs) but the device kernel is newer. Cross-checked below against
 * <sys/syscall.h> whenever that knows the number. Unknown arch without it: fallback path only. */
#if defined(__x86_64__) && defined(__ILP32__)
#    define NR_GETRANDOM (0x40000000 + 318) /* x32 */
#elif defined(__x86_64__)
#    define NR_GETRANDOM 318
#elif defined(__i386__)
#    define NR_GETRANDOM 355
#elif defined(__aarch64__) || defined(__riscv) || defined(__loongarch__)
#    define NR_GETRANDOM 278 /* asm-generic table */
#elif defined(__arm__) && defined(__ARM_EABI__)
#    define NR_GETRANDOM 384
#elif defined(__mips__) && defined(_MIPS_SIM) && defined(_ABIO32) && _MIPS_SIM == _ABIO32
#    define NR_GETRANDOM 4353 /* 4000 + 353 */
#elif defined(__mips__) && defined(_MIPS_SIM) && defined(_ABIN32) && _MIPS_SIM == _ABIN32
#    define NR_GETRANDOM 6317 /* 6000 + 317 */
#elif defined(__mips__) && defined(_MIPS_SIM) && defined(_ABI64) && _MIPS_SIM == _ABI64
#    define NR_GETRANDOM 5313 /* 5000 + 313 */
#elif defined(__powerpc__) || defined(__powerpc64__)
#    define NR_GETRANDOM 359
#elif defined(SYS_getrandom)
#    define NR_GETRANDOM SYS_getrandom
#endif
#if defined(NR_GETRANDOM) && defined(SYS_getrandom)
#    if NR_GETRANDOM != SYS_getrandom
#        error "getrandom syscall number disagrees with <sys/syscall.h>: fix the table"
#    endif
#endif

/* len bytes from getrandom (fd < 0) or from fd, retrying EINTR and short reads. Chunks of at most
 * 256 bytes: a getrandom request that size is never cut short by a signal once seeded. */
static int fill(int fd, uint8_t *out, size_t len)
{
    size_t off = 0;
    while (off < len) {
        size_t n = len - off < 256 ? len - off : 256;
        long r;
        if (fd >= 0) {
            r = (long)read(fd, out + off, n);
        } else {
#ifdef NR_GETRANDOM
            r = syscall(NR_GETRANDOM, out + off, n, 0);
#else
            r = -1;
            errno = ENOSYS;
#endif
        }
        if (r > 0 && (size_t)r <= n) {
            off += (size_t)r;
        } else if (r < 0 && errno == EINTR) {
            continue;
        } else if (r < 0 && fd < 0 && (errno == ENOSYS || errno == EPERM)) {
            return BRISK__RAND_FALLBACK;
        } else {
            return BRISK_E_RNG; /* EOF, error, or a count we did not ask for */
        }
    }
    return BRISK_OK;
}

/* A regular file where a device should be (rootfs images built without mknod) holds no entropy. */
static int open_chr(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode))) {
        close(fd);
        fd = -1;
    }
    return fd;
}

int brisk__os_getrandom(uint8_t *out, size_t len)
{
    return fill(-1, out, len);
}

/* On the kernels that get here, /dev/random's readability is a live entropy estimate that reads
 * drain again, while "seeded" never turns false: wait once per process, or handshakes would stall
 * for minutes on a quiet router. The library's only mutable static - a write-once flag for a
 * kernel fact (fork() keeps it true; a race between threads costs one extra poll).
 * ponytail: opens /dev/urandom per call (no cached fd); only pre-4.8 kernels without getrandom
 * get here, and TLS asks for a few hundred bytes per handshake. */
static int seeded;

int brisk__os_urandom(uint8_t *out, size_t len)
{
    int r, fd;
    if (!seeded) {
        struct pollfd p;
        fd = open_chr("/dev/random");
        if (fd < 0) {
            return BRISK_E_RNG;
        }
        p.fd = fd;
        p.events = POLLIN;
        p.revents = 0;
        do {
            r = poll(&p, 1, -1);
        } while (r < 0 && (errno == EINTR || errno == EAGAIN));
        close(fd);
        if (r != 1 || !(p.revents & POLLIN)) {
            return BRISK_E_RNG;
        }
        seeded = 1;
    }
    fd = open_chr("/dev/urandom");
    if (fd < 0) {
        return BRISK_E_RNG;
    }
    r = fill(fd, out, len);
    close(fd);
    return r;
}

/* 1 on kernels older than 4.8, the only ones where a readable /dev/random implies a seeded
 * /dev/urandom: until then interrupt entropy goes to the urandom pool first (3.10/3.16 random.c);
 * 4.8's ChaCha CRNG broke that (OpenSSL's rand_unix.c uses the same cut-off). */
static int kernel_before_4_8(void)
{
    struct utsname u;
    unsigned v[2] = {0, 0}, i = 0;
    const char *s;
    /* UNAME26 (setarch --uname-2.6) makes a 4.9 kernel report "2.6.69": trust no release then.
     * The query never fails on a real kernel; qemu-user on 32-bit targets returns -1. */
    int pers = personality(0xffffffff);
    if ((pers != -1 && (pers & 0x0020000)) || uname(&u) != 0) {
        return 0;
    }
    for (s = u.release; i < 2 && v[i] < 1000; s++) { /* "3.10.14-openwrt" -> 3, 10 */
        if (*s >= '0' && *s <= '9') {
            v[i] = v[i] * 10 + (unsigned)(*s - '0');
        } else if (*s == '.') {
            i++;
        } else {
            break;
        }
    }
    return v[0] != 0 && (v[0] < 4 || (v[0] == 4 && v[1] < 8));
}

int brisk__os_random(uint8_t *out, size_t len)
{
    int r = brisk__os_getrandom(out, len);
    if (r == BRISK__RAND_FALLBACK) {
        r = kernel_before_4_8() ? brisk__os_urandom(out, len) : BRISK_E_RNG;
    }
    return r;
}

#undef NR_GETRANDOM
