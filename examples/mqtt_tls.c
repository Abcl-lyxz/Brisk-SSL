/* mqtt_tls.c - an MQTT 3.1.1 sketch over the TLS stream: CONNECT, wait for CONNACK, PUBLISH
 * one QoS 0 message, DISCONNECT. No MQTT library: the point is that the TLS connection is just a
 * byte pipe, and a 60-line client is enough for telemetry.
 *
 *   mqtt_tls HOST PORT CLIENT_ID TOPIC MESSAGE [chain.der key.d]
 *
 * PORT 8883 is MQTT over TLS as usual. PORT 443 offers ALPN "x-amzn-mqtt-ca", which is how AWS
 * IoT Core accepts MQTT on 443; other brokers ignore it. chain.der / key.d add a device
 * certificate (see aws_iot_https.c for the openssl conversions). A real client also needs
 * PINGREQ every keep-alive interval, QoS 1 retries and SUBSCRIBE - not shown.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brisk.h"
#include "example_util.h"

/* fixed header + remaining length (MQTT 3.1.1 2.2.3, variable-length int) */
static size_t mqtt_hdr(uint8_t *p, uint8_t type, size_t rem)
{
    size_t n = 0;
    p[n++] = type;
    do {
        p[n] = (uint8_t)(rem & 0x7f);
        rem >>= 7;
        p[n++] |= rem ? 0x80 : 0;
    } while (rem);
    return n;
}

static size_t mqtt_str(uint8_t *p, const char *s)
{
    size_t len = strlen(s);
    p[0] = (uint8_t)(len >> 8);
    p[1] = (uint8_t)len;
    memcpy(p + 2, s, len);
    return len + 2;
}

int main(int argc, char **argv)
{
    static const uint8_t disconnect[2] = {0xe0, 0x00};
    brisk_cfg cfg = BRISK_DEFAULTS;
    uint8_t *chain = NULL, *key = NULL, pkt[1024], body[1024], ack[4];
    size_t key_len = 0, bl, pl, got = 0;
    brisk_conn *c;
    int rc, n;
    uint16_t port;

    if ((argc != 6 && argc != 8) || strlen(argv[3]) + strlen(argv[4]) + strlen(argv[5]) > 900) {
        fprintf(stderr, "usage: mqtt_tls HOST PORT CLIENT_ID TOPIC MESSAGE [chain.der key.d]\n");
        return 1;
    }
    port = (uint16_t)atoi(argv[2]);
    if (port == 443) {
        cfg.alpn = "x-amzn-mqtt-ca";
    }
    if (argc == 8) {
        chain = read_file(argv[6], &cfg.client_chain_len);
        key = read_file(argv[7], &key_len);
        if (chain == NULL || key == NULL || key_len != 32) {
            return 1;
        }
        cfg.client_chain = chain;
        cfg.client_key = key;
    }

    rc = brisk_connect(&cfg, argv[1], port, &c);
    if (rc == BRISK_OK) {
        /* CONNECT (3.1): "MQTT", level 4, flags clean session, keep-alive 60 s, client id */
        static const uint8_t vh[10] = {0, 4, 'M', 'Q', 'T', 'T', 4, 0x02, 0, 60};
        memcpy(body, vh, sizeof vh);
        bl = sizeof vh + mqtt_str(body + sizeof vh, argv[3]);
        pl = mqtt_hdr(pkt, 0x10, bl);
        memcpy(pkt + pl, body, bl);
        rc = brisk_write(c, pkt, pl + bl);
        /* CONNACK (3.2): 20 02 00 00 = accepted */
        while (rc == BRISK_OK && got < sizeof ack) {
            n = brisk_read(c, ack + got, sizeof ack - got);
            rc = n > 0 ? BRISK_OK : (n == 0 ? BRISK_E_IO : n);
            got += n > 0 ? (size_t)n : 0;
        }
        if (rc == BRISK_OK && (ack[0] != 0x20 || ack[3] != 0)) {
            fprintf(stderr, "broker refused CONNECT, return code %u\n", ack[3]);
            rc = BRISK_E_ARG;
        }
        if (rc == BRISK_OK) { /* PUBLISH QoS 0 (3.3): topic, then the payload as is */
            bl = mqtt_str(body, argv[4]);
            memcpy(body + bl, argv[5], strlen(argv[5]));
            bl += strlen(argv[5]);
            pl = mqtt_hdr(pkt, 0x30, bl);
            memcpy(pkt + pl, body, bl);
            rc = brisk_write(c, pkt, pl + bl);
        }
        if (rc == BRISK_OK) {
            rc = brisk_write(c, disconnect, sizeof disconnect);
        }
        brisk_close(c);
    }
    if (key != NULL) {
        memset(key, 0, key_len);
        free(key);
    }
    free(chain);
    if (rc != BRISK_OK) {
        fprintf(stderr, "failed: %s\n", err_name(rc));
        return 2;
    }
    puts("published");
    return 0;
}
