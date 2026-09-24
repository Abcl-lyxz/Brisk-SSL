/* test_main.c - runs every suite, or only those named on the command line: brisk_tests [suite...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

long t_checks, t_fails;

void t_check(int ok, const char *file, int line, const char *what, long idx)
{
    t_checks++;
    if (ok) {
        return;
    }
    if (++t_fails <= 25) { /* first failures are enough; don't flood qemu logs */
        if (idx >= 0) {
            fprintf(stderr, "FAIL %s:%d: %s [vector %ld]\n", file, line, what, idx);
        } else {
            fprintf(stderr, "FAIL %s:%d: %s\n", file, line, what);
        }
    }
}

static int nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

size_t t_unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex), i;
    if (n % 2 || n / 2 > cap) {
        fprintf(stderr, "t_unhex: bad length %lu (cap %lu)\n", (unsigned long)n,
                (unsigned long)cap);
        exit(2);
    }
    for (i = 0; i < n / 2; i++) {
        int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "t_unhex: bad digit\n");
            exit(2);
        }
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return n / 2;
}

static const struct {
    const char *name;
    void (*run)(void);
} SUITES[] = {
    {"hash", test_hash},
    {"aead", test_aead},
    {"aes", test_aes},
    {"x25519", test_x25519},
    {"p256", test_p256},
    {"p384", test_p384},
    {"rsa", test_rsa},
    {"der", test_der},
    {"x509", test_x509},
    {"ct", test_ct},
    {"tls13_ks", test_tls13_ks},
    {"tls13_hs", test_tls13_hs},
    {"tls13_rec", test_tls13_rec},
    {"conn", test_conn},
    {"tls12_prf", test_tls12_prf},
    {"tls12_rec", test_tls12_rec},
    {"tls12_hs", test_tls12_hs},
    {"hpack", test_hpack},
    {"h2", test_h2},
    {"quic", test_quic},
#ifdef __linux__
    {"rand", test_rand},
    {"sock", test_sock},
#endif
};

int main(int argc, char **argv)
{
    size_t i;
    int j;
    for (i = 0; i < sizeof SUITES / sizeof SUITES[0]; i++) {
        int want = argc < 2;
        for (j = 1; j < argc; j++) {
            want |= strcmp(argv[j], SUITES[i].name) == 0;
        }
        if (want) {
            long before = t_fails;
            SUITES[i].run();
            printf("%-8s %s\n", SUITES[i].name, t_fails == before ? "ok" : "FAILED");
        }
    }
    printf("%ld checks, %ld failures\n", t_checks, t_fails);
    if (t_checks == 0) { /* misspelt suite name in add_test() must not "pass" */
        fprintf(stderr, "no checks ran: unknown suite name?\n");
        return 2;
    }
    return t_fails ? 1 : 0;
}
