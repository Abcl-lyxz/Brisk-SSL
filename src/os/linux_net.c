/* linux_net.c - clocks, TCP and the blocking API over the sans-I/O connection (Linux only).
 *
 * Everything here is a thin loop over src/tls/conn.c: brisk_connect = one malloc + TCP connect
 * + (pull, send, recv, feed) until connected; brisk_read / brisk_write the same loop for
 * application data. The socket stays non-blocking and every wait is a poll() with the time left
 * until a monotonic deadline, so no call can hang past cfg.timeout_ms (DNS excepted:
 * getaddrinfo has no timeout).
 *
 * Error policy (RFC 9846 6.1, 6.2): a protocol failure sends its one fatal alert (best effort)
 * and returns; a TCP FIN before close_notify is BRISK_E_IO, never a clean EOF; a read timeout is
 * harmless, a send failure or timeout is final (a record may be half on the wire).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE  /* SOCK_NONBLOCK / SOCK_CLOEXEC, getaddrinfo; must precede every #include \
                          */
#endif
/* 64-bit time_t on 32-bit glibc >= 2.34 (Y2038; _TIME_BITS needs _FILE_OFFSET_BITS 64).
 * Older glibc and musl (64-bit since 1.2) ignore them; time_t never reaches the API. */
#ifndef _FILE_OFFSET_BITS
#    define _FILE_OFFSET_BITS 64
#endif
#ifndef _TIME_BITS
#    define _TIME_BITS 64
#endif
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "brisk_int.h"

#define NET_TIMEOUT_DEFAULT 10000u
#define NET_CLOSE_WAIT      1000u /* brisk_close: at most this long for close_notify to leave */
#define NET_P256_TRIES      8

static int64_t net_clock(clockid_t id)
{
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0) {
        return 0;
    }
    /* widening alone does not fix Y2038 - _TIME_BITS above does; tv_nsec is `long`, maybe
     * 64-bit: narrow it before dividing so no 64-bit division helper is pulled in */
    return (int64_t)ts.tv_sec * 1000 + (int64_t)((uint32_t)ts.tv_nsec / 1000000u);
}

int64_t brisk__os_wall_ms(void)
{
    return net_clock(CLOCK_REALTIME);
}

int64_t brisk__os_mono_ms(void)
{
    return net_clock(CLOCK_MONOTONIC);
}

/* Wait until fd is ready for `ev` or the deadline passes; EINTR recomputes the time left. */
static int net_wait(int fd, short ev, int64_t deadline)
{
    struct pollfd pfd;
    int64_t left;
    int r;
    for (;;) {
        left = deadline - brisk__os_mono_ms();
        if (left <= 0) {
            return BRISK_E_TIMEOUT;
        }
        pfd.fd = fd;
        pfd.events = ev;
        pfd.revents = 0;
        r = poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (r > 0) {
            return BRISK_OK; /* ready, or POLLERR/POLLHUP: the next call reports which */
        }
        if (r < 0 && errno != EINTR) {
            return BRISK_E_IO;
        }
    }
}

int brisk__os_send_all(int fd, const uint8_t *p, size_t n, int64_t deadline)
{
    ssize_t r;
    int rc;
    while (n != 0) {
        r = send(fd, p, n, MSG_NOSIGNAL); /* EPIPE instead of SIGPIPE killing the process */
        if (r > 0) {
            p += r;
            n -= (size_t)r;
        } else if (r < 0 && errno == EINTR) {
            continue;
        } else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            rc = net_wait(fd, POLLOUT, deadline);
            if (rc != BRISK_OK) {
                return rc;
            }
        } else {
            return BRISK_E_IO;
        }
    }
    return BRISK_OK;
}

int brisk__os_recv(int fd, uint8_t *p, size_t cap, int64_t deadline, size_t *n)
{
    ssize_t r;
    int rc;
    *n = 0;
    for (;;) {
        r = recv(fd, p, cap, 0);
        if (r >= 0) {
            *n = (size_t)r; /* 0 = the peer closed its side */
            return BRISK_OK;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return BRISK_E_IO;
        }
        rc = net_wait(fd, POLLIN, deadline);
        if (rc != BRISK_OK) {
            return rc;
        }
    }
}

#define NET_SLICE_MIN 2000u /* ms: a connect attempt's floor when the budget is split */

int brisk__os_dial(const struct addrinfo *res, int64_t deadline, int *fd)
{
    const struct addrinfo *ai;
    uint32_t addrs = 0, slice;
    int64_t left, until;
    int s, rc = BRISK_E_IO, err;
    socklen_t el;

    *fd = -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        addrs++;
    }
    for (ai = res; ai != NULL && *fd < 0; ai = ai->ai_next, addrs--) {
        s = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
        if (s < 0) {
            continue;
        }
        if (connect(s, ai->ai_addr, ai->ai_addrlen) != 0) {
            /* EINTR: the connect goes on asynchronously, same as EINPROGRESS */
            if (errno != EINPROGRESS && errno != EINTR) {
                close(s);
                continue;
            }
            /* a share of what is left (at least NET_SLICE_MIN), so one blackholed address
             * (say a dead IPv6 route) cannot eat the budget of the ones after it */
            left = deadline - brisk__os_mono_ms();
            slice = left <= 0 ? 0 : left > (int64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)left;
            slice = slice / addrs < NET_SLICE_MIN ? NET_SLICE_MIN : slice / addrs;
            until = brisk__os_mono_ms() + slice;
            rc = net_wait(s, POLLOUT, until < deadline ? until : deadline);
            err = 0;
            el = sizeof err;
            if (rc == BRISK_OK &&
                (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0)) {
                rc = BRISK_E_IO;
            }
            if (rc != BRISK_OK) {
                close(s);
                continue; /* on a timeout too: the deadline check in net_wait ends the loop */
            }
        }
        *fd = s;
        rc = BRISK_OK;
    }
    return *fd >= 0 ? BRISK_OK : rc;
}

/* getaddrinfo, then brisk__os_dial within the deadline. No AI_ADDRCONFIG: it hides
 * "localhost" in a container whose only interface is lo. */
static int net_open(const char *host, uint16_t port, uint32_t timeout_ms, int *fd,
                    int64_t *deadline)
{
    struct addrinfo hints, *res = NULL;
    char serv[6];
    int rc;
    size_t i = sizeof serv - 1;

    *fd = -1;
    serv[i] = '\0';
    do {
        serv[--i] = (char)('0' + port % 10);
        port = (uint16_t)(port / 10);
    } while (port != 0);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    if (getaddrinfo(host, serv + i, &hints, &res) != 0) {
        return BRISK_E_IO;
    }
    *deadline = brisk__os_mono_ms() + timeout_ms;
    rc = brisk__os_dial(res, *deadline, fd);
    freeaddrinfo(res);
    return rc;
}

int brisk__os_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms, int *fd)
{
    int64_t deadline;
    if (host == NULL || fd == NULL) {
        return BRISK_E_ARG;
    }
    return net_open(host, port, timeout_ms ? timeout_ms : NET_TIMEOUT_DEFAULT, fd, &deadline);
}

/* ------------------------------------------------------------------ the connection ---------- */

/* The 160 per-connection random bytes (layout in brisk_int.h); the P-256 slice is redrawn until
 * it is a valid scalar (1 <= d < n fails with probability ~2^-32, so the bound only stops a
 * broken source). */
static int net_rand(uint8_t rnd[BRISK__CONN_RAND])
{
    int i;
    if (brisk__os_random(rnd, BRISK__CONN_RAND) != BRISK_OK) {
        return BRISK_E_RNG;
    }
    for (i = 0; i < NET_P256_TRIES; i++) {
        if (brisk__p256_scalar_valid(rnd + 96)) {
            return BRISK_OK;
        }
        if (brisk__os_random(rnd + 96, 32) != BRISK_OK) {
            break;
        }
    }
    brisk__secure_zero(rnd, BRISK__CONN_RAND);
    return BRISK_E_RNG;
}

int brisk_conn_init(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                    brisk_conn **out)
{
    uint8_t rnd[BRISK__CONN_RAND];
    int rc;
    if (out != NULL) {
        *out = NULL;
    }
    rc = net_rand(rnd);
    if (rc == BRISK_OK) {
        rc = brisk__conn_setup(mem, mem_len, cfg, host, brisk__os_wall_ms(), rnd,
                               brisk__os_ca_anchor, out);
    }
    brisk__secure_zero(rnd, sizeof rnd);
    return rc;
}

/* A send failed: a record may be half on the wire, so nothing more can follow it. The sticky
 * error is BRISK_E_IO even for a send timeout - a stored BRISK_E_TIMEOUT would read as
 * "retry" from brisk_read (brisk.h) and spin forever on a dead connection. */
static int net_dead(brisk_conn *c, int rc)
{
    c->io_err = rc == BRISK_E_TIMEOUT ? BRISK_E_IO : rc;
    return rc;
}

/* Send everything the connection owes (handshake flight, alert, KeyUpdate, close_notify). */
static int net_flush(brisk_conn *c, int64_t deadline)
{
    size_t n;
    int rc;
    while ((n = brisk_pull(c, c->tx, BRISK__CONN_TX)) != 0) {
        rc = brisk__os_send_all(c->fd, c->tx, n, deadline);
        if (rc != BRISK_OK) {
            return net_dead(c, rc);
        }
    }
    return BRISK_OK;
}

/* Feed what is staged, receiving first when nothing is. A protocol error sends its alert. */
static int net_fill(brisk_conn *c, int64_t deadline)
{
    size_t n, used;
    int rc;
    if (c->rx_len == 0) {
        rc = brisk__os_recv(c->fd, c->rx, BRISK__CONN_RX, deadline, &n);
        if (rc == BRISK_OK && n == 0) {
            rc = BRISK_E_IO; /* FIN without close_notify: truncation, never EOF (6.1) */
        }
        if (rc != BRISK_OK) {
            if (rc != BRISK_E_TIMEOUT) {
                c->io_err = rc;
            }
            return rc;
        }
        c->rx_off = 0;
        c->rx_len = n;
    }
    if (!c->fixed_now) {
        brisk__conn_set_time(c, brisk__os_wall_ms()); /* 4.3.11.1: ticket age from receipt */
    }
    rc = brisk_feed(c, c->rx + c->rx_off, c->rx_len, &used);
    c->rx_off += used;
    c->rx_len -= used;
    if (rc != BRISK_OK && c->io_err == 0) {
        net_flush(c, brisk__os_mono_ms() + c->timeout_ms); /* the one fatal alert (6.2) */
    }
    return rc;
}

static void net_free(brisk_conn *c)
{
    uint8_t *heap = c->heap;
    size_t len = c->heap_len;
    if (c->fd >= 0) {
        close(c->fd);
    }
    brisk_conn_wipe(c);
    brisk__secure_zero(heap, len);
    free(heap);
}

/* One malloc: [conn arena | tx | rx]; the handshake runs until connected with our last flight
 * sent (RFC 9846 4.4.4: the client Finished completes it; tickets are not waited for). */
static int net_connect(const brisk_cfg *cfg, const char *host, int fd, const uint8_t *rnd,
                       int64_t now_ms, uint16_t port, brisk_conn **out)
{
    size_t size = brisk_conn_size(), total = size + BRISK__CONN_TX + BRISK__CONN_RX;
    uint8_t *heap, own[BRISK__CONN_RAND];
    int64_t deadline = 0;
    brisk_conn *c = NULL;
    int rc;

    heap = (uint8_t *)calloc(1, total);
    if (heap == NULL) {
        if (fd >= 0) {
            close(fd);
        }
        return BRISK_E_IO;
    }
    rc = rnd != NULL ? BRISK_OK : net_rand(own);
    if (rc == BRISK_OK) {
        rc = brisk__conn_setup(heap, size, cfg, host, now_ms >= 0 ? now_ms : brisk__os_wall_ms(),
                               rnd != NULL ? rnd : own, brisk__os_ca_anchor, &c);
    }
    brisk__secure_zero(own, sizeof own);
    if (rc != BRISK_OK) {
        if (fd >= 0) {
            close(fd);
        }
        free(heap); /* setup wiped it */
        return rc;
    }
    c->heap = heap;
    c->heap_len = total;
    c->tx = heap + size;
    c->rx = c->tx + BRISK__CONN_TX;
    c->fixed_now = (uint8_t)(now_ms >= 0);
    c->timeout_ms = cfg->timeout_ms != 0 ? cfg->timeout_ms : NET_TIMEOUT_DEFAULT;
    c->fd = fd;
    if (fd < 0) {
        rc = net_open(host, port, c->timeout_ms, &c->fd, &deadline);
    } else {
        deadline = brisk__os_mono_ms() + c->timeout_ms;
    }
    while (rc == BRISK_OK) {
        rc = net_flush(c, deadline);
        if (rc == BRISK_OK) {
            rc = brisk_status(c);
            if (rc == BRISK_OK) {
                *out = c;
                return BRISK_OK;
            }
            rc = rc == BRISK_E_WANT ? net_fill(c, deadline) : rc;
        }
    }
    net_free(c);
    return rc;
}

int brisk_connect(const brisk_cfg *cfg, const char *host, uint16_t port, brisk_conn **out)
{
    if (out != NULL) {
        *out = NULL;
    }
    if (cfg == NULL || host == NULL || out == NULL) {
        return BRISK_E_ARG;
    }
    return net_connect(cfg, host, -1, NULL, -1, port, out);
}

int brisk__connect_fd(const brisk_cfg *cfg, const char *host, int fd, const uint8_t *rnd,
                      int64_t now_ms, brisk_conn **out)
{
    if (out != NULL) {
        *out = NULL;
    }
    if (cfg == NULL || host == NULL || out == NULL || fd < 0) {
        if (fd >= 0) {
            close(fd);
        }
        return BRISK_E_ARG;
    }
    return net_connect(cfg, host, fd, rnd, now_ms, 0, out);
}

int brisk_read(brisk_conn *c, void *buf, size_t cap)
{
    size_t n;
    int rc;
    if (c == NULL || buf == NULL || cap == 0 || c->heap == NULL) {
        return BRISK_E_ARG;
    }
    if (c->io_err != 0) {
        return c->io_err;
    }
    cap = cap > INT_MAX ? INT_MAX : cap;
    for (;;) {
        rc = brisk_app_read(c, buf, cap, &n);
        if (rc == BRISK_OK) {
            return (int)n; /* data, or 0 after close_notify */
        }
        if (rc != BRISK_E_WANT) {
            return rc;
        }
        /* a KeyUpdate answer (4.7.3) is owed before we sit in recv */
        if (net_flush(c, brisk__os_mono_ms() + c->timeout_ms) != BRISK_OK) {
            return c->io_err; /* a stuck send is final: BRISK_E_IO, never a retryable timeout */
        }
        rc = net_fill(c, brisk__os_mono_ms() + c->timeout_ms);
        if (rc != BRISK_OK) {
            return rc;
        }
    }
}

int brisk_write(brisk_conn *c, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t used, n;
    int rc;
    if (c == NULL || (buf == NULL && len != 0) || c->heap == NULL) {
        return BRISK_E_ARG;
    }
    if (c->io_err != 0) {
        return c->io_err;
    }
    while (len != 0) {
        rc = brisk_app_write(c, p, len, &used, c->tx, BRISK__CONN_TX, &n);
        if (n != 0) {
            int s = brisk__os_send_all(c->fd, c->tx, n, brisk__os_mono_ms() + c->timeout_ms);
            if (s != BRISK_OK) {
                return net_dead(c, s);
            }
        }
        if (rc != BRISK_OK) {
            net_flush(c, brisk__os_mono_ms() + c->timeout_ms); /* the fatal alert, if any */
            return rc;
        }
        if (used == 0 && n == 0) {
            return BRISK_E_ARG; /* cannot happen with a 4 KB tx; never spin */
        }
        p += used;
        len -= used;
    }
    return BRISK_OK;
}

void brisk_close(brisk_conn *c)
{
    if (c == NULL) {
        return;
    }
    if (c->heap == NULL) {
        brisk_conn_wipe(c); /* not ours to free: a sans-I/O connection */
        return;
    }
    if (c->io_err == 0 && brisk_close_notify(c) == BRISK_OK) {
        /* 6.1: close_notify before closing the write side, unless an error alert was sent */
        net_flush(c, brisk__os_mono_ms() +
                         (c->timeout_ms < NET_CLOSE_WAIT ? c->timeout_ms : NET_CLOSE_WAIT));
    }
    net_free(c);
}

#undef NET_TIMEOUT_DEFAULT
#undef NET_CLOSE_WAIT
#undef NET_P256_TRIES
#undef NET_SLICE_MIN
