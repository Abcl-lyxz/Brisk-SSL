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
void test_rsa(void);
void test_ct(void);   /* constant-time smoke run; the real check is `dev.py ct` */
void test_rand(void); /* Linux only */

#endif
