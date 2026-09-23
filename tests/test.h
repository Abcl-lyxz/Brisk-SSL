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
void test_ct(void);         /* constant-time smoke run; the real check is `dev.py ct` */
void test_tls13_ks(void);   /* TLS 1.3 key schedule (RFC 9846 sect 7.1) + Finished + exporter */
void test_tls13_hs(void);   /* TLS 1.3 handshake engine (RFC 9846 sect 4) */
void test_tls13_rec(void);  /* TLS 1.3 record layer + connection driver (RFC 9846 sect 5) */
void tls13_rec_ct_run(void); /* its constant-time run, called from test_ct */
void tls13_hs_ct_run(void); /* its constant-time run, called from test_ct */
void test_rand(void);       /* Linux only */

#endif
