/* aws_iot_https.c - publish one message to AWS IoT Core over HTTPS with an X.509 device
 * certificate: plain HTTP/1.1 over the raw TLS stream, no HTTP library.
 *
 *   aws_iot_https ENDPOINT chain.pem key.pem TOPIC MESSAGE
 *     ENDPOINT   xxxxxxxx-ats.iot.<region>.amazonaws.com
 *     chain.pem  the device certificate from AWS (xxxx-certificate.pem.crt)
 *     key.pem    its P-256 key, PEM or DER
 *
 * The console's one-click "auto-generate certificate" gives an RSA key, which brisk cannot
 * use (mTLS is ECDSA P-256 only). Make a P-256 key and register it through a CSR instead:
 *   openssl ecparam -genkey -name prime256v1 -out key.pem
 *   openssl req -new -key key.pem -subj /CN=dev -out dev.csr
 * then "Create with CSR" (CreateCertificateFromCsr) and download xxxx-certificate.pem.crt.
 *
 * AWS IoT speaks HTTPS on 8443 with plain TLS, or on 443 when the client offers ALPN
 * "x-amzn-http-ca" - the one a firewalled device usually needs, so that is what this does.
 * The server side is HTTP/1.0/1.1 only, which is why this is raw TLS and not brisk_h2.
 * Trust: the system bundle must hold Amazon Root CA 1 (or 3); set cfg.ca_file otherwise.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk.h"
#include "example_util.h"

int main(int argc, char **argv)
{
    brisk_cfg cfg = BRISK_DEFAULTS;
    uint8_t *chain, *key;
    size_t key_len = 0;
    char req[2048], reply[1024];
    brisk_conn *c;
    int rc, n, len;

    if (argc != 6) {
        fprintf(stderr, "usage: aws_iot_https ENDPOINT chain.pem key.pem TOPIC MESSAGE\n");
        return 1;
    }
    chain = read_file(argv[2], &cfg.client_chain_len);
    key = read_file(argv[3], &key_len);
    if (chain == NULL || key == NULL || key_len == 0) { /* 0 would mean raw d */
        fprintf(stderr, "need a chain and a key (PEM, DER or the raw 32-byte d)\n");
        return 1;
    }
    cfg.client_chain = chain;
    cfg.client_key = key;
    cfg.client_key_len = key_len;
    cfg.alpn = "x-amzn-http-ca";

    /* RFC 9112: Content-Length framing; the topic is used as given (URL-encode it yourself) */
    len = snprintf(req, sizeof req,
                   "POST /topics/%s?qos=1 HTTP/1.1\r\nHost: %s\r\n"
                   "Content-Type: application/json\r\nContent-Length: %zu\r\n"
                   "Connection: close\r\n\r\n%s",
                   argv[4], argv[1], strlen(argv[5]), argv[5]);
    if (len < 0 || (size_t)len >= sizeof req) {
        fprintf(stderr, "message too long for this example\n");
        return 1;
    }

    rc = brisk_connect(&cfg, argv[1], 443, &c);
    if (rc == BRISK_OK) {
        rc = brisk_write(c, req, (size_t)len);
        /* "HTTP/1.1 200 OK ... {"message":"OK","traceId":...}" on success */
        while (rc == BRISK_OK && (n = brisk_read(c, reply, sizeof reply)) > 0) {
            fwrite(reply, 1, (size_t)n, stdout);
        }
        brisk_close(c);
    }
    memset(key, 0, key_len);
    free(key);
    free(chain);
    if (rc != BRISK_OK) {
        fprintf(stderr, "failed: %s\n", err_name(rc));
        return 2;
    }
    return 0;
}
