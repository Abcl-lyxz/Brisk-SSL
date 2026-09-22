/* linux_ca.c - the distribution's CA bundle as a trust store, read lazily (Linux only).
 *
 * brisk__x509_chain_verify asks for an anchor BY ISSUER NAME, one candidate at a time. That
 * signature is what makes this file possible: a lookup opens the bundle, streams it through the
 * PEM decoder in src/x509/bundle.c, hands back the first certificate whose subject is the Name
 * that was asked for, and closes it again. Nothing is parsed that is not looked at, and the
 * only RAM held between calls is the one certificate in brisk__x509_bundle.pem.
 *
 * The alternative - parse 140 roots into an array at startup - costs ~350 KB on a device that
 * budgets 26 KB for a whole connection, to save a linear scan of a file the page cache is
 * already holding. Not close.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* O_CLOEXEC is POSIX.1-2008. A VERSION test and not #ifndef: a router SDK that already
 * puts -D_POSIX_C_SOURCE=199506L in CFLAGS would make a bare #ifndef skip, and the build
 * would then fail on exactly the mipsel/armv5 targets this library exists for. Nothing is
 * included yet, so redefining it here is safe. Must precede every #include. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200809L
#    undef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "brisk_int.h"

/* Where the distributions put it, most common first. The list is the union of what the major
 * families ship, because an IoT image is as likely to be OpenWrt or Alpine as Debian:
 *   /etc/ssl/certs/ca-certificates.crt   Debian, Ubuntu, OpenWrt, Alpine, Arch
 *   /etc/pki/tls/certs/ca-bundle.crt     Fedora, RHEL, CentOS, Amazon Linux
 *   /etc/ssl/ca-bundle.pem               openSUSE, SLES
 *   /etc/ssl/cert.pem                    Alpine, buildroot, anything BSD-flavoured
 *   /etc/pki/tls/cacert.pem              older RHEL
 *   /etc/ssl/certs/ca-bundle.crt         a symlink some images ship instead of the first
 *
 * NOT consulted: $SSL_CERT_FILE and $SSL_CERT_DIR. OpenSSL honours them; a library that reads
 * its trust root out of the environment lets anything that can set a variable in a service's
 * unit file redirect verification, and on an appliance that is a bigger surface than it is a
 * convenience. A caller who wants another file sets brisk__x509_bundle.path and no search runs.
 *
 * NOT supported either: a hashed directory (/etc/ssl/certs/*.0). It needs getdents and a
 * second Name-to-hash implementation to find a file, and every system that ships one also
 * ships the concatenated bundle above. */
static const char *const CA_PATHS[] = {"/etc/ssl/certs/ca-certificates.crt",
                                       "/etc/pki/tls/certs/ca-bundle.crt",
                                       "/etc/ssl/ca-bundle.pem",
                                       "/etc/ssl/cert.pem",
                                       "/etc/pki/tls/cacert.pem",
                                       "/etc/ssl/certs/ca-bundle.crt"};

/* O_CLOEXEC so a bundle fd cannot leak into a child this library never knew about; a gateway
 * that fork/execs a helper between connections is the normal case, not the exotic one. */
static int open_ro(const char *path)
{
    int fd;
    do {
        fd = open(path, O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    return fd;
}

/* A path only counts as "the bundle" if it is a non-empty REGULAR file. Two reasons, both
 * things that happen on real images rather than hypotheticals:
 *   - a stripped OpenWrt or Alpine image often leaves an EMPTY /etc/ssl/certs/ca-certificates.crt
 *     behind when the package is removed. Taking it because it opens means the populated
 *     /etc/ssl/cert.pem further down the list is never tried and every handshake fails.
 *   - a FIFO or a character device at one of these paths opens fine and then makes read() block
 *     forever, inside a library whose engines are documented never to block. */
static int usable_bundle(const char *path)
{
    struct stat st;
    int fd = open_ro(path), ok;

    if (fd < 0) {
        return 0;
    }
    ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
    close(fd);
    return ok;
}

const char *brisk__os_ca_path(void)
{
    size_t i;
    for (i = 0; i < sizeof CA_PATHS / sizeof CA_PATHS[0]; i++) {
        if (usable_bundle(CA_PATHS[i])) {
            return CA_PATHS[i];
        }
    }
    return NULL;
}

int brisk__os_ca_anchor(void *ctx, const uint8_t *dn, size_t dn_len, size_t index,
                        brisk__x509_cert *out)
{
    brisk__x509_bundle *b = ctx;
    /* A STACK buffer, and that is what sizes it: this frame sits under brisk__x509_parse on a
     * device whose threads get 8 KB, so 256 B is the budget, not the throughput optimum. It
     * costs ~800 read() calls over a 200 KB bundle - about a millisecond of syscall overhead
     * per lookup against a page-cached file, once or twice per handshake. Raise it only
     * together with a fresh stack measurement. */
    uint8_t buf[256];
    size_t hit = 0;
    int fd, rc = BRISK_E_ARG;

    if (b == NULL || dn == NULL || dn_len == 0 || out == NULL) {
        return BRISK_E_ARG;
    }
    if (b->path == NULL) {
        b->path = brisk__os_ca_path(); /* once per bundle, not once per lookup */
        if (b->path == NULL) {
            return BRISK_E_ARG;
        }
    }
    fd = open_ro(b->path);
    if (fd < 0) {
        return BRISK_E_ARG;
    }
    brisk__x509_pem_init(&b->pem);
    for (;;) {
        const uint8_t *p = buf;
        size_t left;
        ssize_t got = read(fd, buf, sizeof buf);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; /* a bundle that stopped being readable is a bundle with no more roots in it */
        }
        if (got == 0) {
            break;
        }
        left = (size_t)got;
        while (brisk__x509_pem_feed(&b->pem, &p, &left) == 1) {
            /* A block that is not a certificate this client can use is skipped, not fatal: a
             * bundle carries roots for algorithms a TINY build was never compiled with, and one
             * of them must not hide the root three entries down. */
            if (brisk__x509_parse(out, b->pem.der, b->pem.der_len) != BRISK_OK) {
                continue;
            }
            if (out->subject_len != dn_len || memcmp(out->subject, dn, dn_len) != 0) {
                continue;
            }
            if (hit++ == index) {
                rc = BRISK_OK;
                goto done;
            }
        }
    }
done:
    close(fd);
    if (rc != BRISK_OK) {
        /* `out` was written by every parse that got this far, and those point into pem.der,
         * which the next lookup overwrites. Leave nothing a caller could be tempted to read. */
        memset(out, 0, sizeof *out);
    }
    return rc;
}
