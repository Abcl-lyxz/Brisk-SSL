/* brisk_get.c - connect, send one request, print the reply. The smallest complete client, and
 * the tool the interop and badssl runs drive.
 *
 *   brisk_get [options] host [port]          port defaults to 443
 *     -a ALPN     comma-separated ALPN list, e.g. "h2,http/1.1"
 *     -c FILE     trust only this PEM bundle (default: the system bundle)
 *     -C FILE     mTLS: client chain, PEM or concatenated DER, leaf first
 *     -K FILE     mTLS: P-256 private key, PEM, SEC1 / PKCS#8 DER or the raw 32-byte d
 *     -T FILE     resumption: offer the ticket in FILE if present, save the newest one there
 *     -r TEXT     request to send; "\n" in TEXT becomes CRLF, "" = handshake only.
 *                 Default: GET / HTTP/1.1 with Host and Connection: close
 *
 * Prints the reply to stdout and "brisk: tls=0x0304 alpn=... resumed=..." (0x0303 for TLS 1.2)
 * to stderr. Exit status 0 on a clean close_notify or peer close after data, 1 on usage errors,
 * 2 when the connection failed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk.h"
#include "example_util.h"

struct ticket_sink {
    const char *path;
};

static void save_ticket(void *ctx, const uint8_t *blob, size_t len)
{
    const struct ticket_sink *s = ctx;
    FILE *f = fopen(s->path, "wb"); /* key material: a real device would use a 0600 file */
    if (f != NULL) {
        fwrite(blob, 1, len, f);
        fclose(f);
    }
}

/* "\n" -> CRLF, in place into a new buffer */
static char *crlf(const char *s, size_t *len)
{
    char *out = malloc(2 * strlen(s) + 1);
    size_t n = 0;
    if (out == NULL) {
        return NULL;
    }
    for (; *s != '\0'; s++) {
        if (*s == '\n') {
            out[n++] = '\r';
        }
        out[n++] = *s;
    }
    *len = n;
    return out;
}

int main(int argc, char **argv)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    struct ticket_sink sink = {NULL};
    const char *req_text = NULL, *host, *alpn_name;
    uint8_t *chain = NULL, *key = NULL, *ticket = NULL;
    size_t key_len = 0, req_len, alpn_len;
    char *req, buf[4096];
    brisk_conn *c;
    int i, rc, n, got = 0;
    uint16_t port = 443;

    for (i = 1; i + 1 < argc && argv[i][0] == '-'; i += 2) {
        const char *v = argv[i + 1];
        switch (argv[i][1]) {
        case 'a':
            cfg.alpn = v;
            break;
        case 'c':
            cfg.ca_file = v;
            break;
        case 'C':
            chain = read_file(v, &cfg.client_chain_len);
            cfg.client_chain = chain;
            break;
        case 'K':
            key = read_file(v, &key_len);
            cfg.client_key = key;
            cfg.client_key_len = key_len; /* raw d, SEC1 / PKCS#8 DER or PEM */
            break;
        case 'T':
            sink.path = v;
            cfg.on_ticket = save_ticket;
            cfg.ticket_ctx = &sink;
            ticket = read_file(v, &cfg.ticket_len); /* missing file = full handshake */
            cfg.ticket = ticket;
            break;
        case 'r':
            req_text = v;
            break;
        default:
            i = argc;
            break;
        }
    }
    if (i >= argc || (key != NULL && key_len == 0)) { /* 0 would mean raw d */
        fprintf(stderr,
                "usage: brisk_get [-a alpn] [-c ca.pem] [-C chain.pem|der -K key.pem|der|d] "
                "[-T ticket] [-r request] host [port]\n");
        return 1;
    }
    host = argv[i];
    if (i + 1 < argc) {
        port = (uint16_t)atoi(argv[i + 1]);
    }
    if (req_text == NULL) {
        snprintf(buf, sizeof buf, "GET / HTTP/1.1\nHost: %s\nConnection: close\n\n", host);
        req_text = buf;
    }
    req = crlf(req_text, &req_len);

    rc = brisk_connect(&cfg, host, port, &c);
    if (rc != BRISK_OK) {
        free(ticket);
        fprintf(stderr, "brisk: connect failed: %s\n", err_name(rc));
        return 2;
    }
    if (brisk_alpn(c, &alpn_name, &alpn_len) != BRISK_OK) {
        alpn_len = 0;
    }
    fprintf(stderr, "brisk: tls=0x%04x alpn=%.*s resumed=%d\n", (unsigned)brisk_tls_version(c),
            (int)alpn_len, alpn_len ? alpn_name : "", brisk_resumed(c));

    rc = req_len > 0 ? brisk_write(c, req, req_len) : BRISK_OK;
    while (rc == BRISK_OK && req_len > 0 && (n = brisk_read(c, buf, sizeof buf)) != 0) {
        if (n < 0) {
            /* HTTP servers often just drop TCP after the reply: fine once data arrived */
            rc = (n == BRISK_E_IO && got) ? BRISK_OK : n;
            break;
        }
        fwrite(buf, 1, (size_t)n, stdout);
        got = 1;
    }
    brisk_close(c);
    free(ticket); /* single use (RFC 9846 C.4): -T FILE now holds a newer one, if any came */
    free(req);
    free(chain);
    if (key != NULL) {
        memset(key, 0, key_len); /* our buffer: the library wipes only its parsed copy */
        free(key);
    }
    if (rc != BRISK_OK) {
        fprintf(stderr, "brisk: %s\n", err_name(rc));
        return 2;
    }
    return 0;
}
