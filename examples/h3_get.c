/* h3_get.c - HTTP/3 requests over one QUIC connection with brisk_h3_*.
 *
 *   h3_get [options] host [port] path        port defaults to 443
 *     -c FILE     trust only this PEM bundle (default: the system bundle)
 *     -n N        N requests of path in parallel on one connection (1..4, default 1)
 *     -q          print "status S bytes B fnv H" per response instead of the body
 *
 * Response headers go to stderr as "< name: value". Exit status 0 when every response arrived
 * complete (any HTTP status), 1 on usage errors, 2 on a failure ("brisk: ..." on stderr). Needs
 * a FULL build (BRISK_ENABLE_H3).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk.h"
#include "example_util.h"

#if BRISK_ENABLE_H3

static void on_header(void *ctx, const char *name, size_t name_len, const char *value,
                      size_t value_len)
{
    (void)ctx;
    fprintf(stderr, "< %.*s: %.*s\n", (int)name_len, name, (int)value_len, value);
}

/* Read the response of s; print it (or its size and FNV-1a 32 with quiet). */
static int fetch(brisk_h3_stream *s, int quiet)
{
    unsigned char buf[4096];
    unsigned long fnv = 2166136261UL, total = 0;
    int status, n, i;
    int rc = brisk_h3_response(s, &status, on_header, NULL);
    if (rc != BRISK_OK) {
        return rc;
    }
    while ((n = brisk_h3_read(s, buf, sizeof buf)) > 0) {
        for (i = 0; i < n; i++) {
            fnv = ((fnv ^ buf[i]) * 16777619UL) & 0xffffffffUL;
        }
        total += (unsigned long)n;
        if (!quiet) {
            fwrite(buf, 1, (size_t)n, stdout);
        }
    }
    if (quiet) {
        printf("status %d bytes %lu fnv %08lx\n", status, total, fnv);
    } else {
        fprintf(stderr, "< :status: %d\n", status);
    }
    return n;
}

int main(int argc, char **argv)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    const char *host, *path;
    brisk_h3_stream *s[4];
    int i, k, rc, n = 1, quiet = 0, opened = 0;
    uint16_t port = 443;
    brisk_quic *q;
    brisk_h3 *h = NULL;
    void *mem;

    (void)read_file; /* example_util.h: not needed here */
    cfg.alpn = "h3";
    for (i = 1; i < argc && argv[i][0] == '-'; i += 2) {
        const char *v = i + 1 < argc ? argv[i + 1] : "";
        switch (argv[i][1]) {
        case 'c':
            cfg.ca_file = v;
            break;
        case 'n':
            n = atoi(v);
            break;
        case 'q':
            quiet = 1;
            i--; /* no value */
            break;
        default:
            i = argc;
            break;
        }
    }
    if (argc - i < 2 || n < 1 || n > 4) {
        fprintf(stderr, "usage: h3_get [-c ca.pem] [-n 1..4] [-q] host [port] path\n");
        return 1;
    }
    host = argv[i];
    if (argc - i > 2) {
        port = (uint16_t)atoi(argv[i + 1]);
    }
    path = argv[argc - 1];

    rc = brisk_quic_connect(&cfg, host, port, &q);
    if (rc != BRISK_OK) {
        fprintf(stderr, "brisk: connect failed: %s\n", err_name(rc));
        return 2;
    }
    mem = malloc(brisk_h3_size());
    rc = mem == NULL ? BRISK_E_ARG : brisk_h3_open(q, mem, brisk_h3_size(), &h);
    if (rc != BRISK_OK) {
        fprintf(stderr, "brisk: h3_open: %s\n", err_name(rc));
    }
    for (; rc == BRISK_OK && opened < n; opened++) {
        rc = brisk_h3_request(h, "GET", path, NULL, 0, NULL, 0, &s[opened]);
        if (rc != BRISK_OK) {
            fprintf(stderr, "brisk: request %d: %s\n", opened + 1, err_name(rc));
            opened--; /* the failed request holds no stream */
        }
    }
    for (k = 0; k < opened; k++) {
        int r = rc == BRISK_OK ? fetch(s[k], quiet) : BRISK_OK;
        if (r != BRISK_OK) {
            fprintf(stderr, "brisk: response %d: %s (QUIC error 0x%llx)\n", k + 1, err_name(r),
                    (unsigned long long)brisk_quic_error(q));
            rc = r;
        }
        brisk_h3_stream_close(s[k]);
    }
    brisk_h3_close(h);
    brisk_quic_close(q, 0x100); /* H3_NO_ERROR (RFC 9114 8.1) */
    free(mem);
    return rc == BRISK_OK ? 0 : 2;
}

#else

int main(void)
{
    (void)read_file;
    (void)err_name;
    fprintf(stderr,
            "h3_get: this build has no HTTP/3 (BRISK_ENABLE_H3 is 0; use the FULL profile)\n");
    return 1;
}

#endif
