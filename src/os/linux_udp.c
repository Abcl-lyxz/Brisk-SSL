/* linux_udp.c - the blocking QUIC driver over the sans-I/O brisk_quic (Linux only).
 *
 * One malloc [brisk_quic arena | tx 1200 | rx BRISK__QUIC_RX_MAX], one connected non-blocking UDP
 * socket, and one loop: pull everything owed and send it, poll() until the connection's deadline
 * or a datagram, feed what arrived. Every blocking call is that loop (the stream calls in
 * src/quic/api.c run it through q->io), so ACKs, flow control, PTO and key updates keep going
 * for every stream while one call waits.
 *
 * RFC 9000 14: Don't Fragment where the kernel allows it; a datagram longer than our receive
 * buffer (= the max_udp_payload_size we advertise) is dropped, never fed truncated (MSG_TRUNC).
 * ICMP errors are ignored: unauthenticated (RFC 9000 21), so whatever a connected socket reports
 * for one (ECONNREFUSED, EMSGSIZE, EHOSTUNREACH ...) only loses that datagram. PMTUDISC_PROBE
 * keeps DF but ignores the kernel's PMTU cache: a forged "Fragmentation Needed" below 1200 must
 * not stop our 1200-byte datagrams (14.2.1 MUST ignore).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* SOCK_NONBLOCK / SOCK_CLOEXEC, getaddrinfo; before every #include */
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _TIME_BITS
#define _TIME_BITS 64
#endif
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "brisk_int.h"

#if BRISK_ENABLE_QUIC

#define UDP_TIMEOUT_DEFAULT 10000u

int brisk__os_udp_connect(const char *host, uint16_t port, int *fd)
{
    struct addrinfo hints, *res = NULL;
    char serv[6];
    size_t i = sizeof serv - 1;
    int s, v;

    *fd = -1;
    if (host == NULL) {
        return BRISK_E_ARG;
    }
    serv[i] = '\0';
    do {
        serv[--i] = (char)('0' + port % 10);
        port = (uint16_t)(port / 10);
    } while (port != 0);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;
    if (getaddrinfo(host, serv + i, &hints, &res) != 0 || res == NULL) {
        return BRISK_E_IO;
    }
    /* ponytail: the first address only - add a per-address fallback on handshake timeout if
     * dual-stack devices need it */
    s = socket(res->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s >= 0) {
        /* RFC 9000 14 (MUST): no fragmentation; DF "if possible" - an odd kernel's refusal is
         * not an error */
#if defined(IP_MTU_DISCOVER) && (defined(IP_PMTUDISC_PROBE) || defined(IP_PMTUDISC_DO))
        if (res->ai_family == AF_INET) {
#    ifdef IP_PMTUDISC_PROBE
            v = IP_PMTUDISC_PROBE; /* DF, PMTU cache ignored (Linux 2.6.22+) */
#    else
            v = IP_PMTUDISC_DO;
#    endif
            (void)setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof v);
        }
#endif
#if defined(IPV6_MTU_DISCOVER) && (defined(IPV6_PMTUDISC_PROBE) || defined(IPV6_PMTUDISC_DO))
        if (res->ai_family == AF_INET6) {
#    ifdef IPV6_PMTUDISC_PROBE
            v = IPV6_PMTUDISC_PROBE;
#    else
            v = IPV6_PMTUDISC_DO;
#    endif
            (void)setsockopt(s, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &v, sizeof v);
        }
#endif
        (void)v;
        /* connected: the kernel drops datagrams from any other address (we never migrate) */
        if (connect(s, res->ai_addr, res->ai_addrlen) != 0) {
            close(s);
            s = -1;
        }
    }
    freeaddrinfo(res);
    if (s < 0) {
        return BRISK_E_IO;
    }
    *fd = s;
    return BRISK_OK;
}

int brisk__os_udp_fatal(int err)
{
    /* only a broken local socket; everything else (EAGAIN, ENOBUFS, and every errno an ICMP
     * message can leave on a connected socket) is a lost datagram: loss recovery or the idle
     * timeout decides (RFC 9000 14.2.1, 21) */
    return err == EBADF || err == ENOTSOCK || err == EFAULT || err == EINVAL ||
           err == EDESTADDRREQ || err == ENOTCONN;
}

/* Send everything owed. A lost datagram is QUIC's business; a dead socket is BRISK_E_IO. */
static int udp_flush(brisk_quic *q)
{
    size_t n;
    ssize_t r;
    while ((n = brisk_quic_pull(q, q->c.tx, BRISK_QUIC_DGRAM_MAX, brisk__os_mono_ms())) != 0) {
        do {
            r = send(q->c.fd, q->c.tx, n, MSG_NOSIGNAL);
        } while (r < 0 && errno == EINTR);
        if (r < 0 && brisk__os_udp_fatal(errno)) {
            q->c.io_err = BRISK_E_IO;
            return BRISK_E_IO;
        }
    }
    return BRISK_OK;
}

/* Feed the datagrams waiting on the socket, at most UDP_DRAIN_MAX per call: a flood (spoofed
 * garbage from the server's address) must not starve our sends and timers. */
#define UDP_DRAIN_MAX 16
static void udp_drain(brisk_quic *q)
{
    ssize_t r;
    unsigned i;
    for (i = 0; i < UDP_DRAIN_MAX; i++) {
        /* MSG_TRUNC: the real length, so an oversize datagram is seen - and dropped */
        r = recv(q->c.fd, q->c.rx, BRISK__QUIC_RX_MAX, MSG_TRUNC | MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            continue; /* EINTR, or an ICMP error (unauthenticated, ignored); a dead socket: send */
        }
        if ((size_t)r <= BRISK__QUIC_RX_MAX) {
            brisk_quic_feed(q, q->c.rx, (size_t)r, brisk__os_mono_ms());
        }
        if (q->q.err != 0) {
            return;
        }
    }
}

/* One round: flush, then wait for a datagram until the connection's deadline or the stall
 * limit, feed. BRISK_OK (call again), the sticky error, or BRISK_E_TIMEOUT at the stall limit. */
static int udp_round(brisk_quic *q)
{
    struct pollfd pfd;
    int64_t now, until, left;
    if (q->c.io_err != 0) {
        return q->c.io_err;
    }
    if (udp_flush(q) != BRISK_OK) {
        return BRISK_E_IO;
    }
    if (q->q.err != 0) {
        return q->q.err;
    }
    now = brisk__os_mono_ms();
    if (now >= q->stall) {
        return BRISK_E_TIMEOUT;
    }
    until = brisk_quic_deadline(q);
    until = until < q->stall ? until : q->stall;
    left = until - now;
    left = left < 0 ? 0 : left > INT_MAX ? INT_MAX : left;
    pfd.fd = q->c.fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, (int)left) > 0) {
        udp_drain(q);
    }
    /* a due timer (loss, PTO, idle, ACK) runs in the next pull */
    return q->q.err != 0 ? q->q.err : BRISK_OK;
}

static void udp_free(brisk_quic *q)
{
    uint8_t *heap = q->c.heap;
    size_t len = q->c.heap_len;
    if (q->c.fd >= 0) {
        close(q->c.fd);
    }
    brisk__secure_zero(heap, len);
    free(heap);
}

static int udp_io(brisk_quic *q, int op)
{
    if (op == BRISK__QIO_START) {
        q->stall = brisk__os_mono_ms() + q->c.timeout_ms;
        return BRISK_OK;
    }
    if (op == BRISK__QIO_WAIT) {
        return udp_round(q);
    }
    if (op == BRISK__QIO_FLUSH) {
        return q->c.io_err != 0 ? q->c.io_err : udp_flush(q);
    }
    if (q->c.io_err == 0) {
        udp_flush(q); /* the CONNECTION_CLOSE, once (RFC 9000 10.2) */
    }
    udp_free(q);
    return BRISK_OK;
}

static int udp_rand(uint8_t rnd[BRISK__QUIC_RAND])
{
    if (brisk__conn_rand(rnd) != BRISK_OK ||
        brisk__os_random(rnd + BRISK__CONN_RAND, BRISK__QUIC_RAND - BRISK__CONN_RAND) != BRISK_OK) {
        brisk__secure_zero(rnd, BRISK__QUIC_RAND);
        return BRISK_E_RNG;
    }
    return BRISK_OK;
}

int brisk_quic_init(void *mem, size_t mem_len, const brisk_cfg *cfg, const char *host,
                    brisk_quic **out)
{
    uint8_t rnd[BRISK__QUIC_RAND];
    int rc;
    if (out != NULL) {
        *out = NULL;
    }
    /* RFC 9001 8.1: an empty ALPN fails before any randomness is drawn */
    if (cfg == NULL || cfg->alpn == NULL || cfg->alpn[0] == '\0') {
        return BRISK_E_ARG;
    }
    rc = udp_rand(rnd);
    if (rc == BRISK_OK) {
        rc = brisk__quic_setup(mem, mem_len, cfg, host, brisk__os_wall_ms(), rnd,
                               brisk__os_ca_anchor, NULL, 0, out);
    }
    brisk__secure_zero(rnd, sizeof rnd);
    return rc;
}

int brisk__quic_connect_ex(const brisk_cfg *cfg, const char *host, uint16_t port, int fd,
                           const uint8_t *rnd, int64_t wall_ms, const uint16_t *suites,
                           size_t n_suites, brisk__quic_keylog_fn keylog, void *keylog_ctx,
                           brisk_quic **out)
{
    size_t size = brisk_quic_size(), total = size + BRISK_QUIC_DGRAM_MAX + BRISK__QUIC_RX_MAX;
    uint8_t *heap, own[BRISK__QUIC_RAND];
    brisk_quic *q = NULL;
    int rc;

    if (out != NULL) {
        *out = NULL;
    }
    if (cfg == NULL || host == NULL || out == NULL || cfg->alpn == NULL || cfg->alpn[0] == '\0') {
        if (fd >= 0) {
            close(fd);
        }
        return BRISK_E_ARG;
    }
    heap = (uint8_t *)calloc(1, total);
    if (heap == NULL) {
        if (fd >= 0) {
            close(fd);
        }
        return BRISK_E_IO;
    }
    rc = rnd != NULL ? BRISK_OK : udp_rand(own);
    if (rc == BRISK_OK) {
        rc = brisk__quic_setup(heap, size, cfg, host, wall_ms >= 0 ? wall_ms : brisk__os_wall_ms(),
                               rnd != NULL ? rnd : own, brisk__os_ca_anchor, suites, n_suites, &q);
    }
    brisk__secure_zero(own, sizeof own);
    if (rc == BRISK_OK && fd < 0) {
        rc = brisk__os_udp_connect(host, port, &fd);
        if (rc != BRISK_OK) {
            brisk_quic_wipe(q);
        }
    }
    if (rc != BRISK_OK) {
        if (fd >= 0) {
            close(fd);
        }
        free(heap); /* setup wiped it */
        return rc;
    }
    q->q.keylog = keylog;
    q->q.keylog_ctx = keylog_ctx;
    q->q.keylog_random = q->c.rnd; /* the client random: rnd[0..32) */
    q->c.heap = heap;
    q->c.heap_len = total;
    q->c.tx = heap + size;
    q->c.rx = q->c.tx + BRISK_QUIC_DGRAM_MAX;
    q->c.fd = fd;
    q->c.port = port;
    q->c.timeout_ms = cfg->timeout_ms != 0 ? cfg->timeout_ms : UDP_TIMEOUT_DEFAULT;
    q->io = udp_io;
    udp_io(q, BRISK__QIO_START); /* cfg.timeout_ms covers the whole handshake */
    for (;;) {
        rc = udp_round(q);
        if (rc != BRISK_OK) {
            break;
        }
        if (brisk__quic_established(&q->q)) {
            rc = udp_flush(q); /* our Finished (RFC 9001 4.1.2: then 1-RTT is usable) */
            if (rc == BRISK_OK) {
                *out = q;
                return BRISK_OK;
            }
            break;
        }
    }
    if (q->q.err == 0) {
        brisk__quic_close(&q->q, 0); /* best effort: tell the server we gave up */
    }
    udp_io(q, BRISK__QIO_FREE);
    return rc;
}

int brisk_quic_connect(const brisk_cfg *cfg, const char *host, uint16_t port, brisk_quic **out)
{
    return brisk__quic_connect_ex(cfg, host, port, -1, NULL, -1, NULL, 0, NULL, NULL, out);
}

int brisk__quic_connect_fd(const brisk_cfg *cfg, const char *host, int fd, const uint8_t *rnd,
                           int64_t wall_ms, brisk_quic **out)
{
    if (fd < 0) {
        if (out != NULL) {
            *out = NULL;
        }
        return BRISK_E_ARG;
    }
    return brisk__quic_connect_ex(cfg, host, 0, fd, rnd, wall_ms, NULL, 0, NULL, NULL, out);
}

int brisk_quic_poll(brisk_quic *q, uint32_t ms)
{
    int rc;
    if (q == NULL) {
        return BRISK_E_ARG;
    }
    if (q->io != udp_io) {
        return q->q.err != 0 ? q->q.err : BRISK_E_WANT; /* sans-I/O: the caller's loop */
    }
    q->stall = brisk__os_mono_ms() + ms;
    while ((rc = udp_round(q)) == BRISK_OK) {
    }
    return rc == BRISK_E_TIMEOUT ? BRISK_OK : rc; /* ms passed: nothing wrong */
}

#undef UDP_DRAIN_MAX
#undef UDP_TIMEOUT_DEFAULT

#endif /* BRISK_ENABLE_QUIC */
