/* test.h - the whole test "framework": a check macro and a hex decoder. */
#ifndef BRISK_TEST_H
#define BRISK_TEST_H

#include <stddef.h>
#include <stdint.h>

extern long t_checks, t_fails;

void t_check(int ok, const char *file, int line, const char *what, long idx);
#define CHECK(c)       t_check(!!(c), __FILE__, __LINE__, #c, -1)
#define CHECKI(c, idx) t_check(!!(c), __FILE__, __LINE__, #c, (long)(idx)) /* with vector index */

/* Decode a hex string into out (cap bytes). Aborts the run on odd length / bad digit / overflow. */
size_t t_unhex(const char *hex, uint8_t *out, size_t cap);

/* suites */
void test_hash(void);
void test_aead(void);
void test_aes(void);
void test_x25519(void);
void test_p256(void);
void test_p384(void); /* the suite is a no-op stub when BRISK_ENABLE_P384 is 0 */
void test_rsa(void);
void test_der(void);
void test_x509(void);
void test_ct(void);          /* constant-time smoke run; the real check is `dev.py ct` */
void test_tls13_ks(void);    /* TLS 1.3 key schedule (RFC 9846 sect 7.1) + Finished + exporter */
void test_tls13_hs(void);    /* TLS 1.3 handshake engine (RFC 9846 sect 4) */
void test_tls13_rec(void);   /* TLS 1.3 record layer + connection driver (RFC 9846 sect 5) */
void tls13_rec_ct_run(void); /* its constant-time run, called from test_ct */
void tls13_hs_ct_run(void);  /* its constant-time run, called from test_ct */
void test_rand(void);        /* Linux only */
void test_conn(void);        /* the public connection API, sans-I/O (src/tls/conn.c) */
void test_tls12_prf(void);   /* TLS 1.2 PRF / EMS / key block (RFC 5246 5, RFC 7627) - ACVP */
void test_tls12_rec(void);   /* TLS 1.2 AEAD records (RFC 5246 6.2.3.3, RFC 5288, RFC 7905) */
void test_tls12_hs(void);    /* TLS 1.2 handshakes through the public connection (M5) */
void tls12_ct_run(void);     /* its constant-time run, called from test_ct */
void test_sock(void);        /* Linux only: the blocking API over loopback TCP */
void test_hpack(void);       /* HPACK (RFC 7541); a no-op stub when BRISK_ENABLE_H2 is 0 */
void test_h2(void);          /* HTTP/2 frames + brisk_h2_* (RFC 9113); same stub rule */
void test_quic(void);        /* QUIC v1 (RFC 9000/9001); a stub when BRISK_ENABLE_QUIC is 0 */
void quic_ct_run(void);      /* its constant-time run, called from test_ct */

/* test_conn.c -> test_sock.c: the P-256 fixture flow as a server byte stream */
typedef struct {
    const uint8_t *root; /* the anchor, DER */
    size_t root_len;
    const char *host, *c_ap, *s_ap; /* host, application traffic secrets (hex) */
    long long now_ms;
    size_t ch_len, flight_len; /* the client's ClientHello record, CCS + Finished record */
} t_conn_fixture;
size_t t_conn_server(uint8_t *out, t_conn_fixture *f); /* SH + flight records into out */
const uint8_t *t_conn_rnd(void);                       /* the 160 bytes that replay it */
/* test_rand.c's poll/syscall fault injection, for test_sock.c */
void t_rand_reset(void);      /* back to pass-through */
void t_poll_eintr_once(void); /* the next poll() fails with EINTR */
int t_poll_injected(void);    /* 1 while an injection is still pending */

#endif
