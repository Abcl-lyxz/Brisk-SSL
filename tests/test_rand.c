/* test_rand.c - kernel randomness (src/os/linux_rand.c, Linux builds only).
 *
 * A CSPRNG has no known answers, so this checks the plumbing on every arch: each source returns
 * BRISK_OK (getrandom must not fall back, which proves the per-arch syscall number under qemu),
 * every byte of the buffer is written and none outside it, odd lengths across the 256-byte
 * chunking, unaligned buffers, and the output is neither constant nor grossly biased. Fault
 * injection plays old and new kernels, seccomp, signals, poll errors and broken emulators to prove
 * every failure either takes the (pre-4.8 only, waited-once) /dev/urandom path or fails closed.
 */
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <string.h>
#include <sys/utsname.h>

#include "brisk_int.h"
#include "test.h"

#define CANARY  0xA5
#define GUARD   16
#define MAX_LEN 4099

typedef int (*source_fn)(uint8_t *out, size_t len);

/* Byte i counts as written once it differs from the canary in one of 8 calls; a false failure
 * has probability 2^-64 per byte. Guard bytes around the buffer must never change. */
static void fill_checks(source_fn f, long src)
{
    static const size_t lens[] = {1,  2,  3,   15,  16,  17,   31,     32,
                                  33, 64, 255, 256, 257, 1000, MAX_LEN};
    static uint8_t buf[GUARD + 3 + MAX_LEN + GUARD], seen[MAX_LEN];
    size_t li, off, i;
    int k;
    for (li = 0; li < sizeof lens / sizeof lens[0]; li++) {
        for (off = 0; off < 4; off++) {
            size_t len = lens[li];
            uint8_t *p = buf + GUARD + off;
            int ok = 1;
            memset(seen, 0, len);
            for (k = 0; k < 8; k++) {
                memset(buf, CANARY, sizeof buf);
                ok &= f(p, len) == BRISK_OK;
                for (i = 0; i < len; i++) {
                    seen[i] |= p[i] != CANARY;
                }
                for (i = 0; i < GUARD + off; i++) {
                    ok &= buf[i] == CANARY;
                }
                for (i = GUARD + off + len; i < sizeof buf; i++) {
                    ok &= buf[i] == CANARY;
                }
            }
            for (i = 0; i < len; i++) {
                ok &= seen[i];
            }
            CHECKI(ok, src * 100000 + (long)len * 10 + (long)off);
        }
    }
}

static void distinct_and_unbiased(source_fn f, long src)
{
    static uint8_t big[4096];
    uint8_t a[32], b[32];
    long ones = 0;
    size_t i;
    int j;
    CHECKI(f(a, sizeof a) == BRISK_OK && f(b, sizeof b) == BRISK_OK, src);
    CHECKI(memcmp(a, b, sizeof a) != 0, src); /* equal by chance: 2^-256 */
    CHECKI(f(big, sizeof big) == BRISK_OK, src);
    for (i = 0; i < sizeof big; i++) {
        for (j = 0; j < 8; j++) {
            ones += big[i] >> j & 1;
        }
    }
    /* 32768 fair bits: mean 16384, sigma 90.5. +-800 is 8.8 sigma, so this never fails by chance
     * but catches ASCII, a stuck bit or a mostly-zero buffer. */
    CHECKI(ones > 16384 - 800 && ones < 16384 + 800, src);
}

/* CMakeLists.txt links the tests with -Wl,--wrap=syscall,--wrap=poll,--wrap=uname,--wrap=personality,
 * so the library's getrandom call (its only syscall() use), its /dev/random wait and its
 * kernel-version check land here: pass through, or fail the way the real world does. */
enum { PASS, FAIL, HALF, INTR, ZERO, OVER };
enum { P_PASS, P_FAIL, P_ERR, P_INTR_ONCE };
static int mode, fail_errno, poll_mode;
static long calls, polls;
static const char *fake_release; /* NULL = the real uname() */
static int fake_uname26;

int __real_personality(unsigned long persona);
int __wrap_personality(unsigned long persona);

int __wrap_personality(unsigned long persona)
{
    int r = __real_personality(persona);
    return fake_uname26 ? (r == -1 ? 0 : r) | 0x0020000 : r;
}

int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int __real_uname(struct utsname *u);
int __wrap_uname(struct utsname *u);

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    polls++;
    switch (poll_mode) {
    case P_FAIL:
        errno = ENOMEM;
        return -1;
    case P_ERR: /* "ready", but with an error instead of data */
        fds[0].revents = POLLERR;
        return 1;
    case P_INTR_ONCE:
        poll_mode = P_PASS;
        errno = EINTR;
        return -1;
    }
    return __real_poll(fds, nfds, timeout);
}

int __wrap_uname(struct utsname *u)
{
    int r = __real_uname(u);
    if (r == 0 && fake_release) {
        strcpy(u->release, fake_release);
    }
    return r;
}

long __real_syscall(long nr, ...);
long __wrap_syscall(long nr, ...);

long __wrap_syscall(long nr, ...)
{
    va_list ap;
    void *buf;
    size_t n;
    int flags;
    va_start(ap, nr);
    buf = va_arg(ap, void *);
    n = va_arg(ap, size_t);
    flags = va_arg(ap, int);
    va_end(ap);
    calls++;
    switch (mode) {
    case FAIL: /* old kernel (ENOSYS), seccomp (EPERM), or a real error */
        errno = fail_errno;
        return -1;
    case HALF: /* short reads */
        n = (n + 1) / 2;
        break;
    case INTR: /* a signal on every other call */
        if (calls & 1) {
            errno = EINTR;
            return -1;
        }
        break;
    case ZERO: /* broken emulator: nothing read, no error */
        return 0;
    case OVER: /* broken emulator: more than asked for */
        return (long)n + 1;
    }
    return __real_syscall(nr, buf, n, flags);
}

/* Must run before anything else reads /dev/urandom: the seeded latch is write-once. */
static void fallback_gate(void)
{
    uint8_t b[16];
    polls = 0;
    mode = FAIL;
    fail_errno = ENOSYS;
    fake_release = "5.4.0-openwrt"; /* getrandom filtered on a new kernel: never fall back */
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG && polls == 0);
    fake_release = "4.8.0";
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG && polls == 0);
    fake_release = "3.10.14+"; /* old router kernel: wait for /dev/random, then read urandom */
    poll_mode = P_FAIL;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG && polls == 1); /* failure propagates */
    poll_mode = P_ERR;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG && polls == 2); /* and does not latch */
    poll_mode = P_INTR_ONCE;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_OK && polls == 4); /* EINTR retried */
    CHECK(brisk__os_random(b, sizeof b) == BRISK_OK && polls == 4); /* latched: no 2nd wait */
    fake_release = "4.7.10";
    CHECK(brisk__os_random(b, sizeof b) == BRISK_OK);
    fake_release = "2.6.36.4brcmarm";
    CHECK(brisk__os_random(b, sizeof b) == BRISK_OK);
    fail_errno = EPERM;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_OK); /* seccomp on an old kernel */
    fake_release = "4.19.0";
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG);
    fake_release = "2.6.69"; /* what a 4.9 kernel says under UNAME26 */
    fake_uname26 = 1;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG);
    fake_uname26 = 0;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_OK); /* same string, no personality: allowed */
    mode = PASS;
    fake_release = NULL;
}

static void fault_injection(void)
{
    static const int fallback[] = {ENOSYS, EPERM}, fatal[] = {EFAULT, EINVAL, EIO, EAGAIN};
    uint8_t b[16];
    size_t i;
    calls = 0;
    CHECK(brisk__os_getrandom(b, sizeof b) == BRISK_OK && calls == 1); /* the wrap is live */
    mode = FAIL;
    fake_release = "3.10.14";
    for (i = 0; i < sizeof fallback / sizeof fallback[0]; i++) {
        fail_errno = fallback[i];
        CHECKI(brisk__os_getrandom(b, sizeof b) == BRISK__RAND_FALLBACK, i);
        fill_checks(brisk__os_random, 10 + (long)i); /* served entirely by /dev/urandom */
    }
    for (i = 0; i < sizeof fatal / sizeof fatal[0]; i++) {
        fail_errno = fatal[i];
        CHECKI(brisk__os_random(b, sizeof b) == BRISK_E_RNG, i);
    }
    fake_release = NULL;
    mode = HALF;
    fill_checks(brisk__os_getrandom, 20);
    mode = INTR;
    fill_checks(brisk__os_getrandom, 21);
    mode = ZERO;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG);
    mode = OVER;
    CHECK(brisk__os_random(b, sizeof b) == BRISK_E_RNG);
    mode = PASS;
}

void test_rand(void)
{
    static const source_fn src[] = {brisk__os_random, brisk__os_getrandom, brisk__os_urandom};
    long s;
    fallback_gate(); /* first: the latch cannot be reset */
    CHECK(brisk__os_random(NULL, 0) == BRISK_OK);
    CHECK(brisk__os_getrandom(NULL, 0) == BRISK_OK);
    for (s = 0; s < (long)(sizeof src / sizeof src[0]); s++) {
        fill_checks(src[s], s);
        distinct_and_unbiased(src[s], s);
    }
    fault_injection();
}
