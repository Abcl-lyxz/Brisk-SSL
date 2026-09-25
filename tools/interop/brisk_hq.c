/* brisk_hq.c - hq-interop client for quic-interop-runner (M6 item 4). NOT a product: a harness.
 *
 * Per the runner's endpoint contract: $TESTCASE names the case, $REQUESTS is a space-separated
 * list of https://host:port/path URLs, each fetched with ALPN "hq-interop" as `GET /path\r\n`
 * on a new bidi stream with FIN, the body written to /downloads/<basename>. Exit 0 = success,
 * 1 = failure, 127 = unsupported case. $SSLKEYLOGFILE gets NSS key log lines (seam).
 *
 * The public blocking API does the work; the seams from src/brisk_int.h are only: the suite
 * list (chacha20), the key log and an initiated key update (keyupdate). Verification stays on: the
 * runner mounts its CA at /certs/ca.pem.
 *
 * Build: see tools/interop/Dockerfile.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk_int.h"

#if !BRISK_ENABLE_QUIC
#    error "brisk_hq needs a FULL build (BRISK_ENABLE_QUIC)"
#endif

#define MAX_REQ 4096

typedef struct {
    char host[256], path[1024];
    uint16_t port;
} req_t;

static req_t R[MAX_REQ];
static size_t n_req;
static uint8_t ticket[BRISK_TICKET_MAX];
static size_t ticket_len;
static const char *testcase;

static void keylog(void *ctx, const uint8_t *cr, unsigned epoch, int is_send, const uint8_t *s,
                   size_t len)
{
    FILE *f = (FILE *)ctx;
    const char *label =
        epoch == BRISK__EPOCH_HANDSHAKE
            ? (is_send ? "CLIENT_HANDSHAKE_TRAFFIC_SECRET" : "SERVER_HANDSHAKE_TRAFFIC_SECRET")
            : (is_send ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0");
    size_t i;
    fprintf(f, "%s ", label);
    for (i = 0; i < 32; i++) {
        fprintf(f, "%02x", cr[i]);
    }
    fputc(' ', f);
    for (i = 0; i < len; i++) {
        fprintf(f, "%02x", s[i]);
    }
    fputc('\n', f);
    fflush(f);
}

static void on_ticket(void *ctx, const uint8_t *blob, size_t len)
{
    (void)ctx;
    if (len <= sizeof ticket) {
        memcpy(ticket, blob, len);
        ticket_len = len;
    }
}

/* https://host[:port]/path; IPv6 literals in brackets */
static int parse_url(const char *u, req_t *r)
{
    const char *h, *e, *p;
    size_t hl;
    if (strncmp(u, "https://", 8) != 0) {
        return 0;
    }
    h = u + 8;
    p = strchr(h, '/');
    if (p == NULL) {
        p = h + strlen(h);
    }
    if (*h == '[') {
        e = strchr(h, ']');
        if (e == NULL || e > p) {
            return 0;
        }
        hl = (size_t)(e - h - 1);
        if (hl == 0 || hl >= sizeof r->host) {
            return 0;
        }
        memcpy(r->host, h + 1, hl);
        e++;
    } else {
        for (e = h; e < p && *e != ':'; e++) {
        }
        hl = (size_t)(e - h);
        if (hl == 0 || hl >= sizeof r->host) {
            return 0;
        }
        memcpy(r->host, h, hl);
    }
    r->host[hl] = '\0';
    r->port = (uint16_t)(*e == ':' ? atoi(e + 1) : 443);
    snprintf(r->path, sizeof r->path, "%s", *p ? p : "/");
    return 1;
}

typedef struct {
    int64_t id;
    FILE *f;
    size_t got;
} active_t;

/* Fetch R[first..last) over q, at most `window` streams in flight. 0 on success. */
static int fetch(brisk_quic *q, size_t first, size_t last, size_t window, int keyupdate)
{
    static uint8_t buf[65536];
    char line[1100], out[1200];
    active_t a[64];
    size_t na = 0, next = first, i, ku_done = !keyupdate;
    uint64_t err;
    int64_t id;
    int r;
    if (window > 64) {
        window = 64;
    }
    while (next < last || na != 0) {
        while (next < last && na < window) {
            id = brisk_quic_stream_open(q, 1); /* blocks while every slot is busy */
            if (id < 0) {
                fprintf(stderr, "open: %d\n", (int)id);
                return 1;
            }
            snprintf(line, sizeof line, "GET %s\r\n", R[next].path);
            if (brisk_quic_stream_write(q, (uint64_t)id, line, strlen(line), 1) !=
                (int)strlen(line)) {
                fprintf(stderr, "write failed\n");
                return 1;
            }
            snprintf(out, sizeof out, "/downloads/%s", strrchr(R[next].path, '/') + 1);
            a[na].id = id;
            a[na].got = 0;
            a[na].f = fopen(out, "wb");
            if (a[na].f == NULL) {
                perror(out);
                return 1;
            }
            na++;
            next++;
        }
        /* the oldest stream to its FIN; the others buffer meanwhile */
        while ((r = brisk_quic_stream_read(q, (uint64_t)a[0].id, buf, sizeof buf, &err)) > 0) {
            fwrite(buf, 1, (size_t)r, a[0].f);
            a[0].got += (size_t)r;
            if (!ku_done && a[0].got >= 1024) {
                /* RFC 9001 6.1: allowed once confirmed and the current phase is ACKed */
                r = brisk__quic_key_update(&q->q);
                ku_done = r == BRISK_OK;
                if (r != BRISK_OK && r != BRISK_E_WANT) {
                    return 1;
                }
            }
        }
        fclose(a[0].f);
        if (r != 0) {
            fprintf(stderr, "read: %d (quic error 0x%llx)\n", r,
                    (unsigned long long)brisk_quic_error(q));
            return 1;
        }
        for (i = 1; i < na; i++) {
            a[i - 1] = a[i];
        }
        na--;
    }
    if (!ku_done) {
        fprintf(stderr, "keyupdate: never allowed\n");
        return 1;
    }
    return 0;
}

static int run(const uint16_t *suites, size_t n_suites, size_t first, size_t last, size_t window,
               int keyupdate, int want_resumed, FILE *kl)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    brisk_quic *q;
    int rc;
    cfg.alpn = "hq-interop";
    cfg.ca_file = "/certs/ca.pem";
    cfg.timeout_ms = 20000;
    cfg.on_ticket = on_ticket;
    if (want_resumed) {
        cfg.ticket = ticket;
        cfg.ticket_len = ticket_len;
    }
    rc = brisk__quic_connect_ex(&cfg, R[first].host, R[first].port, -1, NULL, -1, suites, n_suites,
                                kl != NULL ? keylog : NULL, kl, &q);
    if (rc != BRISK_OK) {
        fprintf(stderr, "connect %s:%u: %d\n", R[first].host, R[first].port, rc);
        return 1;
    }
    if (want_resumed && !brisk_quic_resumed(q)) {
        fprintf(stderr, "resumption: the server did a full handshake\n");
        brisk_quic_close(q, 0);
        return 1;
    }
    rc = fetch(q, first, last, window, keyupdate);
    /* resumption: the NewSessionTicket may trail the data */
    if (rc == 0 && !want_resumed && ticket_len == 0 && strcmp(testcase, "resumption") == 0) {
        brisk_quic_poll(q, 1000);
    }
    brisk_quic_close(q, 0);
    return rc;
}

int main(void)
{
    static const uint16_t CHACHA[] = {0x1303};
    const char *reqs = getenv("REQUESTS"), *klp = getenv("SSLKEYLOGFILE");
    char *list, *tok;
    FILE *kl = NULL;
    int rc;
    testcase = getenv("TESTCASE");
    if (testcase == NULL || reqs == NULL) {
        return 127;
    }
    list = strdup(reqs);
    for (tok = strtok(list, " "); tok != NULL && n_req < MAX_REQ; tok = strtok(NULL, " ")) {
        if (!parse_url(tok, &R[n_req++])) {
            fprintf(stderr, "bad url %s\n", tok);
            return 1;
        }
    }
    if (n_req == 0) {
        return 1;
    }
    if (klp != NULL && *klp != '\0') {
        kl = fopen(klp, "a");
    }
    if (strcmp(testcase, "handshake") == 0 || strcmp(testcase, "transfer") == 0 ||
        strcmp(testcase, "retry") == 0) {
        rc = run(NULL, 0, 0, n_req, 1, 0, 0, kl);
    } else if (strcmp(testcase, "multiplexing") == 0) {
        rc = run(NULL, 0, 0, n_req, BRISK_QUIC_MAX_STREAMS, 0, 0, kl);
    } else if (strcmp(testcase, "chacha20") == 0) {
        rc = run(CHACHA, 1, 0, n_req, 1, 0, 0, kl);
    } else if (strcmp(testcase, "keyupdate") == 0) {
        rc = run(NULL, 0, 0, n_req, 1, 1, 0, kl);
    } else if (strcmp(testcase, "resumption") == 0) {
        rc = run(NULL, 0, 0, 1, 1, 0, 0, kl);
        if (rc == 0 && ticket_len == 0) {
            fprintf(stderr, "resumption: no ticket received\n");
            rc = 1;
        }
        if (rc == 0 && n_req > 1) {
            rc = run(NULL, 0, 1, n_req, 1, 0, 1, kl);
        }
    } else {
        rc = 127;
    }
    if (kl != NULL) {
        fclose(kl);
    }
    free(list);
    return rc;
}
