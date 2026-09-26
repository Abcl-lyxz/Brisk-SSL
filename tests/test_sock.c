/* test_sock.c - the blocking API (src/os/linux_net.c) over loopback TCP, Linux only.
 *
 * A fork()ed child plays the server from test_conn.c's P-256 fixture flow (tools/kat.py): it
 * reads the ClientHello, replays the server records, reads the client flight, then - per mode -
 * echoes one application record under s_ap and sends close_notify, goes silent, or drops the
 * TCP connection. The parent drives brisk__connect_via (brisk_connect / _fd / _io with the
 * fixture's randomness and clock) and the public brisk_read / brisk_write / brisk_close; the
 * same flow also runs over a raw-mode pty (a non-socket fd, as a UART). No threads: the
 * qemu-user archs run it too, so every time bound is generous. */
#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "brisk_int.h"
#include "test.h"

enum { S_ECHO, S_SILENT, S_FIN, S_SLOW_ECHO, S_KEYUPDATE };

static uint8_t stream[1 << 14], buf[1 << 15];
static size_t stream_len;
static t_conn_fixture FX;

static int listen_lo(uint16_t *port)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 1) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &al) != 0) {
        exit(2);
    }
    *port = ntohs(a.sin_port);
    return s;
}

static int read_full(int fd, uint8_t *p, size_t n)
{
    ssize_t r;
    while (n != 0) {
        r = read(fd, p, n);
        if (r <= 0) {
            return 0;
        }
        p += r;
        n -= (size_t)r;
    }
    return 1;
}

static int write_full(int fd, const uint8_t *p, size_t n)
{
    ssize_t r;
    while (n != 0) {
        r = write(fd, p, n);
        if (r <= 0) {
            return 0;
        }
        p += r;
        n -= (size_t)r;
    }
    return 1;
}

static int dir_hex(brisk__tls_dir *d, const char *hex)
{
    uint8_t s[32];
    t_unhex(hex, s, sizeof s);
    memset(d, 0, sizeof *d);
    return brisk__tls_dir_init(d, BRISK__EPOCH_APP, 0x1301, s, 32);
}

/* The child: 0 = it saw exactly what it expected. */
static int serve(int fd, int mode)
{
    static const uint8_t CN[2] = {1, 0};
    brisk__tls_dir cr, sw;
    uint8_t type, alert;
    size_t n, len;

    if (fd >= 0 && mode == S_SILENT) { /* accept, never answer: wait for the client to quit */
        while (read(fd, buf, sizeof buf) > 0) {
        }
        return 0;
    }
    if (fd < 0 || !read_full(fd, buf, FX.ch_len)) {
        return 1;
    }
    if (!write_full(fd, stream, stream_len) || !read_full(fd, buf, FX.flight_len)) {
        return 2;
    }
    if (mode == S_FIN) {
        close(fd); /* FIN (or RST) without close_notify */
        return 0;
    }
    if (mode == S_KEYUPDATE) { /* KeyUpdate(update_requested), then never read: parent kills us */
        static const uint8_t KU[5] = {24, 0, 0, 1, 1};
        if (dir_hex(&sw, FX.s_ap) != BRISK_OK ||
            brisk__tls_rec_seal(&sw, BRISK__CT_HANDSHAKE, 0x0303, KU, 5, 0, buf, sizeof buf, &n) !=
                BRISK_OK ||
            !write_full(fd, buf, n)) {
            return 6;
        }
        for (;;) {
            pause();
        }
    }
    /* one application record from the client, echoed back under s_ap, then close_notify */
    if (!read_full(fd, buf, 5) || !read_full(fd, buf + 5, brisk__load_be16(buf + 3))) {
        return 3;
    }
    if (dir_hex(&cr, FX.c_ap) != BRISK_OK || dir_hex(&sw, FX.s_ap) != BRISK_OK ||
        brisk__tls_rec_open(&cr, buf, 5 + brisk__load_be16(buf + 3), &type, &len, &alert) !=
            BRISK_OK ||
        type != BRISK__CT_APP) {
        return 4;
    }
    memmove(stream, buf + 5, len);
    if (mode == S_SLOW_ECHO) {
        usleep(300 * 1000); /* the client is then sure to sit in poll() */
    }
    if (brisk__tls_rec_seal(&sw, BRISK__CT_APP, 0x0303, stream, len, 0, buf, sizeof buf, &n) !=
            BRISK_OK ||
        brisk__tls_rec_seal(&sw, BRISK__CT_ALERT, 0x0303, CN, 2, 0, buf + n, sizeof buf - n,
                            &len) != BRISK_OK ||
        !write_full(fd, buf, n + len)) {
        return 5;
    }
    /* the client's close_notify (6.1), or its FIN */
    while (read(fd, buf, sizeof buf) > 0) {
    }
    close(fd);
    return 0;
}

static int server(int ls, int mode)
{
    return serve(accept(ls, NULL, NULL), mode);
}

/* Fork a server in `mode` on 127.0.0.1; returns its pid, the port in *port. */
static pid_t spawn(int mode, uint16_t *port)
{
    int ls = listen_lo(port), rc, small = 4096;
    pid_t pid;
    if (mode == S_KEYUPDATE) { /* a fixed, small window: no autotuning may drain the fill */
        setsockopt(ls, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    }
    pid = fork();
    if (pid == 0) {
        rc = server(ls, mode);
        _exit(rc);
    }
    close(ls);
    return pid;
}

static int reaped_ok(pid_t pid)
{
    int st = 0;
    return waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* brisk_io callbacks over the fd in *ctx, as a caller would write them */
static int io_ready(int fd, short ev, uint32_t ms)
{
    struct pollfd p;
    p.fd = fd;
    p.events = ev;
    p.revents = 0;
    return poll(&p, 1, ms > 60000 ? 60000 : (int)ms) > 0;
}

static int io_send(void *ctx, const uint8_t *b, size_t n, uint32_t ms)
{
    ssize_t r;
    if (!io_ready(*(int *)ctx, POLLOUT, ms)) {
        return BRISK_E_TIMEOUT;
    }
    r = send(*(int *)ctx, b, n, MSG_NOSIGNAL);
    return r < 0 ? BRISK_E_IO : (int)r;
}

static int io_recv(void *ctx, uint8_t *b, size_t cap, uint32_t ms)
{
    ssize_t r;
    if (!io_ready(*(int *)ctx, POLLIN, ms)) {
        return BRISK_E_TIMEOUT;
    }
    r = recv(*(int *)ctx, b, cap, 0);
    return r < 0 ? BRISK_E_IO : (int)r;
}

enum { D_OWN, D_FD, D_IO }; /* brisk_connect's socket, brisk_connect_fd, brisk_connect_io */
static int dial_fd = -1;    /* the caller's fd for D_FD / D_IO: close it after brisk_close */

static int dial_via(int fd, int how, brisk_conn **c)
{
    static const brisk_io IO = {io_send, io_recv, &dial_fd};
    brisk_cfg cfg = BRISK_DEFAULTS;
    cfg.ca_mem = FX.root;
    cfg.ca_mem_len = FX.root_len;
    cfg.timeout_ms = 20000; /* qemu-emulated handshakes are slow */
    dial_fd = fd;
    return brisk__connect_via(&cfg, FX.host, fd, how == D_OWN, how == D_IO ? &IO : NULL,
                              t_conn_rnd(), FX.now_ms, c);
}

static int dial(uint16_t port, int how, brisk_conn **c)
{
    int fd = -1;
    if (brisk__os_tcp_connect("127.0.0.1", port, 5000, &fd) != BRISK_OK) {
        return BRISK_E_IO;
    }
    if (how == D_FD) { /* a blocking fd: brisk_close must hand it back blocking */
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    }
    return dial_via(fd, how, c);
}

/* The fd is still open and blocking again (brisk_connect_fd's flags restored); close it. */
static int fd_given_back(void)
{
    int fl = fcntl(dial_fd, F_GETFL);
    close(dial_fd);
    return fl >= 0 && (fl & O_NONBLOCK) == 0;
}

static void sock_echo(void)
{
    static const char MSG[] = "hello over loopback";
    brisk_conn *c = NULL;
    uint16_t port;
    pid_t pid;
    int i, n;

    /* 0 = brisk_connect's own socket, 1 = the same waiting in poll(), 2 = _fd, 3 = _io */
    for (i = 0; i < 4; i++) {
        pid = spawn(i == 1 ? S_SLOW_ECHO : S_ECHO, &port);
        CHECKI(dial(port, i < 2 ? D_OWN : i == 2 ? D_FD : D_IO, &c) == BRISK_OK && c != NULL, i);
        CHECKI(brisk_write(c, MSG, sizeof MSG) == BRISK_OK, i);
        if (i == 1) {
            t_poll_eintr_once(); /* the read waits in poll(): EINTR must be retried */
        }
        n = brisk_read(c, buf, sizeof buf);
        CHECKI(n == (int)sizeof MSG && memcmp(buf, MSG, sizeof MSG) == 0, i);
        CHECKI(!t_poll_injected(), i); /* the injection was consumed, by our poll */
        CHECKI(brisk_read(c, buf, sizeof buf) == 0, i); /* close_notify = clean end */
        CHECKI(brisk_read(c, buf, sizeof buf) == 0, i);
        CHECKI(brisk_write(c, MSG, 3) == BRISK_OK, i); /* 6.1: our side is still open */
        brisk_close(c);
        if (i == 2) { /* the fd is ours: the child only ends on our FIN */
            CHECK(fd_given_back());
        } else if (i == 3) {
            close(dial_fd);
        }
        CHECKI(reaped_ok(pid), i);
        t_rand_reset();
    }
}

/* brisk_connect_fd on a non-socket fd: the same echo over a raw-mode pty, as over a UART. */
static void sock_pty(void)
{
    static const char MSG[] = "hello over a tty";
    struct termios tio;
    brisk_conn *c = NULL;
    int m = posix_openpt(O_RDWR | O_NOCTTY), s = -1;
    pid_t pid;

    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0 || ptsname(m) == NULL ||
        (s = open(ptsname(m), O_RDWR | O_NOCTTY)) < 0 || tcgetattr(s, &tio) != 0) {
        CHECK(0);
        return;
    }
    cfmakeraw(&tio); /* 8-bit clean, no echo: set before the child can see a byte */
    CHECK(tcsetattr(s, TCSANOW, &tio) == 0);
    pid = fork();
    if (pid == 0) {
        close(m);
        _exit(serve(s, S_ECHO));
    }
    close(s);
    CHECK(dial_via(m, D_FD, &c) == BRISK_OK && c != NULL);
    if (c != NULL) {
        CHECK(!c->fd_sock);
        CHECK(brisk_write(c, MSG, sizeof MSG) == BRISK_OK);
        CHECK(brisk_read(c, buf, sizeof buf) == (int)sizeof MSG &&
              memcmp(buf, MSG, sizeof MSG) == 0);
        CHECK(brisk_read(c, buf, sizeof buf) == 0);
        brisk_close(c);
    }
    CHECK(fd_given_back()); /* also closes the master: the child's last read ends */
    CHECK(reaped_ok(pid));
    t_rand_reset();
}

/* brisk_io answers are untrusted: anything out of range is BRISK_E_IO, never a spin or overflow */
static int io_rc; /* what the fake recv answers: 1 = cap + 1, else the value itself */
static uint32_t io_max, io_min = UINT32_MAX; /* the timeout_ms range the callbacks saw */

static int io_sink(void *ctx, const uint8_t *b, size_t n, uint32_t ms)
{
    (void)b;
    io_min = ms < io_min ? ms : io_min;
    io_max = ms > io_max ? ms : io_max;
    return ctx != NULL ? (int)n + 1 : (int)n; /* ctx set: claim one byte too many */
}

static int io_fake(void *ctx, uint8_t *b, size_t cap, uint32_t ms)
{
    (void)ctx;
    (void)b;
    io_min = ms < io_min ? ms : io_min;
    io_max = ms > io_max ? ms : io_max;
    return io_rc == 1 ? (int)cap + 1 : io_rc;
}

static void sock_io_errors(void)
{
    static const int RC[] = {BRISK_E_TIMEOUT, 0, 1, BRISK_E_WANT, -100};
    static const int WANT[] = {BRISK_E_TIMEOUT, BRISK_E_IO, BRISK_E_IO, BRISK_E_IO, BRISK_E_IO};
    brisk_cfg cfg = BRISK_DEFAULTS;
    brisk_io io = {io_sink, io_fake, NULL};
    brisk_conn *c = (brisk_conn *)buf;
    int fd, fl;
    size_t i;

    cfg.timeout_ms = 300;
    for (i = 0; i < sizeof RC / sizeof RC[0]; i++) {
        io_rc = RC[i];
        CHECKI(brisk_connect_io(&cfg, "example.com", &io, &c) == WANT[i] && c == NULL, (int)i);
    }
    CHECK(io_min >= 1 && io_max <= 300);
    io.ctx = &io; /* send claims more than it was given */
    CHECK(brisk_connect_io(&cfg, "example.com", &io, &c) == BRISK_E_IO && c == NULL);
    /* bad arguments */
    CHECK(brisk_connect_io(&cfg, "example.com", NULL, &c) == BRISK_E_ARG && c == NULL);
    io.recv = NULL;
    CHECK(brisk_connect_io(&cfg, "example.com", &io, &c) == BRISK_E_ARG && c == NULL);
    CHECK(brisk_connect_fd(&cfg, "example.com", -1, &c) == BRISK_E_ARG && c == NULL);
    fd = open("/dev/null", O_RDWR);
    close(fd);
    CHECK(brisk_connect_fd(&cfg, "example.com", fd, &c) == BRISK_E_ARG && c == NULL);
    { /* a datagram socket would cut records: refused, fd untouched */
        int sp[2];
        CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0);
        fl = fcntl(sp[0], F_GETFL);
        CHECK(brisk_connect_fd(&cfg, "example.com", sp[0], &c) == BRISK_E_ARG && c == NULL);
        CHECK(fcntl(sp[0], F_GETFL) == fl);
        close(sp[0]);
        close(sp[1]);
    }
    /* a failed brisk_connect_fd hands the fd back open, flags unchanged: /dev/null reads EOF */
    fd = open("/dev/null", O_RDWR);
    fl = fcntl(fd, F_GETFL);
    CHECK(brisk_connect_fd(&cfg, "example.com", fd, &c) == BRISK_E_IO && c == NULL);
    CHECK(fl >= 0 && fcntl(fd, F_GETFL) == fl);
    close(fd);
}

static void sock_errors(void)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    brisk_conn *c = (brisk_conn *)buf;
    int64_t t0;
    uint16_t port;
    pid_t pid;
    int ls;

    /* a port nobody listens on: bind, learn it, close */
    ls = listen_lo(&port);
    close(ls);
    CHECK(brisk_connect(&cfg, "127.0.0.1", port, &c) == BRISK_E_IO && c == NULL);
    /* bad arguments never touch the network */
    CHECK(brisk_connect(NULL, "127.0.0.1", port, &c) == BRISK_E_ARG);
    CHECK(brisk_connect(&cfg, "bad host", port, &c) == BRISK_E_ARG && c == NULL);
    /* accepted, never answered: BRISK_E_TIMEOUT from brisk_connect, near its 200 ms */
    pid = spawn(S_SILENT, &port);
    cfg.timeout_ms = 200;
    t0 = brisk__os_mono_ms();
    CHECK(brisk_connect(&cfg, "127.0.0.1", port, &c) == BRISK_E_TIMEOUT && c == NULL);
    CHECK(brisk__os_mono_ms() - t0 < 10000);
    CHECK(reaped_ok(pid));
#if BRISK_ENABLE_P384 /* dial() replays the fixture, which needs the P-384 offer */
    {
        int rc, i, n;
        /* FIN after the handshake without close_notify: truncation, BRISK_E_IO - never EOF 0 */
        pid = spawn(S_FIN, &port);
        CHECK(dial(port, D_OWN, &c) == BRISK_OK);
        CHECK(brisk_read(c, buf, sizeof buf) == BRISK_E_IO);
        CHECK(brisk_read(c, buf, sizeof buf) == BRISK_E_IO); /* sticky */
        brisk_close(c);
        CHECK(reaped_ok(pid));
        /* writing into a closed connection: BRISK_E_IO, and no SIGPIPE (MSG_NOSIGNAL) */
        pid = spawn(S_FIN, &port);
        CHECK(dial(port, D_OWN, &c) == BRISK_OK);
        CHECK(reaped_ok(pid));
        for (i = 0, rc = BRISK_OK; i < 50 && rc == BRISK_OK; i++) {
            rc = brisk_write(c, buf, 1000);
            usleep(10 * 1000);
        }
        CHECK(rc == BRISK_E_IO);
        brisk_close(c);
        /* the owed KeyUpdate answer cannot be sent (peer not reading, buffers full): brisk_read
         * fails final with BRISK_E_IO, never a sticky "retry" BRISK_E_TIMEOUT */
        pid = spawn(S_KEYUPDATE, &port);
        CHECK(dial(port, D_OWN, &c) == BRISK_OK);
        rc = 4096;
        setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &rc, sizeof rc);
        /* fill until EAGAIN holds across pauses: ACKs free space after the first one */
        for (i = 0, n = 0; i < 100000 && n < 3; i++) {
            if (send(c->fd, buf, sizeof buf, MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {
                n = 0;
            } else {
                n++;
                usleep(100 * 1000);
            }
        }
        c->timeout_ms = 200;
        rc = brisk_read(c, buf, sizeof buf);
        CHECKI(rc == BRISK_E_IO, -rc);
        CHECK(brisk_read(c, buf, sizeof buf) == BRISK_E_IO); /* sticky, returned at once */
        CHECK(brisk_write(c, buf, 1) == BRISK_E_IO);
        brisk_close(c);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
#endif
    brisk_close(NULL);
    CHECK(brisk_read(NULL, buf, 1) == BRISK_E_ARG && brisk_write(NULL, buf, 1) == BRISK_E_ARG);
}

/* A dead first address must not eat the whole budget: the first listener's accept queue is
 * full (backlog 0 plus one pending connection), so Linux drops our SYN and that connect hangs
 * like a blackholed IPv6 route; the second, working listener must still be reached in time. */
static void sock_dial(void)
{
    struct sockaddr_in sa[2];
    struct addrinfo ai[2];
    struct pollfd pfd;
    socklen_t al = sizeof sa[0];
    uint16_t port;
    int full, good, filler, fd = -1, i;
    int64_t t0;

    memset(sa, 0, sizeof sa);
    memset(ai, 0, sizeof ai);
    full = socket(AF_INET, SOCK_STREAM, 0);
    sa[0].sin_family = AF_INET;
    sa[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(full >= 0 && bind(full, (struct sockaddr *)&sa[0], sizeof sa[0]) == 0 &&
          listen(full, 0) == 0 && getsockname(full, (struct sockaddr *)&sa[0], &al) == 0);
    filler = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(filler >= 0);
    (void)connect(filler, (struct sockaddr *)&sa[0], sizeof sa[0]);
    pfd.fd = filler;
    pfd.events = POLLOUT;
    CHECK(poll(&pfd, 1, 5000) == 1); /* established: the accept queue is now full */
    good = listen_lo(&port);
    sa[1] = sa[0];
    sa[1].sin_port = htons(port);
    for (i = 0; i < 2; i++) {
        ai[i].ai_family = AF_INET;
        ai[i].ai_socktype = SOCK_STREAM;
        ai[i].ai_addr = (struct sockaddr *)&sa[i];
        ai[i].ai_addrlen = sizeof sa[i];
    }
    ai[0].ai_next = &ai[1];
    t0 = brisk__os_mono_ms();
    CHECK(brisk__os_dial(ai, t0 + 4000, &fd) == BRISK_OK && fd >= 0);
    al = sizeof sa[0];
    CHECK(fd >= 0 && getpeername(fd, (struct sockaddr *)&sa[0], &al) == 0 &&
          sa[0].sin_port == htons(port));
    CHECK(brisk__os_mono_ms() - t0 < 4000);
    if (fd >= 0) {
        close(fd);
    }
    /* an expired deadline: BRISK_E_TIMEOUT for an address that does not answer at once */
    ai[0].ai_next = NULL;
    CHECK(brisk__os_dial(ai, brisk__os_mono_ms(), &fd) == BRISK_E_TIMEOUT && fd == -1);
    close(filler);
    close(good);
    close(full);
}

void test_sock(void)
{
    t_rand_reset(); /* whatever test_rand left injected must not leak into this suite */
    CHECK(!t_poll_injected());
    stream_len = t_conn_server(stream, &FX);
#if BRISK_ENABLE_P384
    sock_echo();
    sock_pty();
#endif
    sock_errors();
    sock_io_errors();
    sock_dial();
    t_rand_reset();
}
