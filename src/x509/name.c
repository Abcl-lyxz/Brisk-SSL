/* name.c - does this certificate speak for this name? RFC 9525 service identity. What is
 * matched, what is refused and what this client deliberately does not implement is documented
 * in the x509/name.c block of src/brisk_int.h.
 *
 * Two entry points, and the split matters: brisk__x509_parse_ip classifies a reference
 * identifier ONCE (RFC 9525 7.4 is about exactly the bug where two components disagree on
 * whether a string is an address or a name), and brisk__x509_match_host then compares it
 * against one kind of GeneralName and never the other.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

/* ------------------------------------------------------------------ DNS-IDs ---------------- */

/* RFC 9525 6.3 compares A-labels "as case-insensitive ASCII", so this is ASCII and not
 * tolower(): no locale, no ctype.h, and the Turkish dotless i cannot reach it. */
static uint8_t lower(uint8_t c)
{
    return (uint8_t)(c >= 'A' && c <= 'Z' ? c + 32 : c);
}

/* The octets this client is willing to see in a domain name. LDH (RFC 1035 2.3.1) plus the
 * label separator, plus '_', which is not preferred name syntax but which private and IoT PKI
 * issues and which RFC 9525 never turns into a matching rule; plus '*' where a wildcard is
 * allowed. Everything else - a space, a control character, an embedded NUL, any byte of a UTF-8
 * U-label - is out, which is what makes the two sides of the comparison mean one thing each. */
static int dns_char_ok(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '_' || c == '.' || c == '*';
}

/* A domain name this client will compare. Shared by both sides on purpose: a presented
 * identifier that fails is "invalid and MUST be ignored" (RFC 9525 6.3) and a reference
 * identifier that fails is BRISK_E_ARG, but the shape is the same one.
 *
 * `allow_wild` carries 6.3's two wildcard requirements together: there is only one wildcard
 * character (1), and it is the complete content of the left-most label (2). Both fall out of
 * demanding that a '*' sit at offset 0 with a '.' after it - a second '*' anywhere is at a
 * non-zero offset, and a '*' inside a label is too. */
static int name_ok(const uint8_t *p, size_t n, int allow_wild)
{
    size_t i, label = 0;

    if (n == 0 || n > BRISK__X509_MAX_NAME) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (p[i] == '.') {
            if (label == 0) {
                return 0; /* an empty label, which covers a leading dot too */
            }
            label = 0;
            continue;
        }
        if (!dns_char_ok(p[i])) {
            return 0;
        }
        if (p[i] == '*' && !(allow_wild && i == 0 && n > 1 && p[1] == '.')) {
            return 0;
        }
        if (++label > BRISK__X509_MAX_LABEL) {
            return 0;
        }
    }
    return label != 0; /* a trailing root dot is a name this client does not compare */
}

/* Does this name end in an all-digit label? RFC 1123 2.1: "the highest-level component label
 * will be alphabetic", so no real host name does - but a whole family of IPv4 spellings the
 * resolver accepts and brisk__x509_parse_ip refuses does: 010.0.0.1 (octal to some resolvers,
 * decimal to others), 0x7f.0.0.1, 127.1, 2130706433, 1.2.3.4.5. Letting those through as DNS-IDs
 * is exactly the split classification RFC 9525 7.4 is a whole section about: the socket connects
 * to an address while the matcher demands a dNSName spelling the same digits, which any CA in a
 * device's own trust store can issue. Refuse the reference identifier instead and make the
 * caller write the address it means. */
static int numeric_tld(const uint8_t *p, size_t n)
{
    size_t i = n;

    while (i > 0 && p[i - 1] != '.') {
        if (p[i - 1] < '0' || p[i - 1] > '9') {
            return 0;
        }
        i--;
    }
    return i < n; /* name_ok has already refused an empty last label */
}

/* One presented dNSName against the reference identifier. 1 on a match, 0 otherwise - including
 * every presented identifier 6.3 says to ignore, because an ignored one is simply not a match
 * and the search moves on to the next entry. */
static int dns_match(const uint8_t *p, size_t pn, const uint8_t *ref, size_t rn)
{
    size_t i;

    if (!name_ok(p, pn, 1)) {
        return 0;
    }
    if (p[0] == '*') {
        /* "A wildcard in a presented identifier can only match one label in a reference
         * identifier" (6.3): consume exactly the reference's left-most label, which has to be
         * there and has to be non-empty - so *.a.example matches x.a.example and neither
         * a.example nor x.y.a.example. */
        for (i = 0; i < rn && ref[i] != '.'; i++) {
        }
        if (i == 0 || i == rn) {
            return 0;
        }
        ref += i + 1;
        rn -= i + 1;
        p += 2;
        pn -= 2;
    }
    if (pn != rn) {
        return 0;
    }
    for (i = 0; i < rn; i++) {
        if (lower(p[i]) != lower(ref[i])) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ IP-IDs ----------------- */

/* Exactly four decimal groups of 1..3 digits, each 0..255 and none with a leading zero. The
 * leading-zero rule is not decoration: RFC 9525 7.4 is a whole section on an IPv4 literal being
 * classified differently by two components, and 010.0.0.1 is octal to some resolvers and
 * decimal to others. Fail closed and let the caller pass the canonical form. */
static size_t parse_ipv4(const char *s, size_t len, uint8_t *out)
{
    size_t i = 0, g;

    for (g = 0; g < 4; g++) {
        unsigned v = 0, d = 0;

        if (g > 0 && (i == len || s[i++] != '.')) {
            return 0;
        }
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            if (++d > 3) {
                return 0;
            }
            v = v * 10 + (unsigned)(s[i++] - '0');
        }
        if (d == 0 || v > 255 || (d > 1 && s[i - d] == '0')) {
            return 0;
        }
        out[g] = (uint8_t)v;
    }
    return i == len ? 4 : 0;
}

/* 1..4 hexadecimal digits at s[i]; returns how many were read and leaves *v holding them. */
static size_t hex_group(const char *s, size_t len, size_t i, unsigned *v)
{
    size_t d = 0;

    *v = 0;
    while (i + d < len && d < 4) {
        uint8_t c = (uint8_t)s[i + d];
        unsigned digit;

        if (c >= '0' && c <= '9') {
            digit = (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (unsigned)(c - 'a') + 10;
        } else if (c >= 'A' && c <= 'F') {
            digit = (unsigned)(c - 'A') + 10;
        } else {
            break;
        }
        *v = (*v << 4) | digit;
        d++;
    }
    return d;
}

/* RFC 4291 2.2 forms 1, 2 and 3: eight groups, one optional "::" run, an optional dotted-quad
 * tail. No scope identifier (fe80::1%eth0) and no brackets: neither can appear in an iPAddress,
 * so accepting them here would only widen what counts as an IP-ID. `out` is written as the
 * parse goes and is meaningless unless 16 comes back. */
static size_t parse_ipv6(const char *s, size_t len, uint8_t *out)
{
    size_t i = 0, n = 0, gap = (size_t)-1;
    int first = 1;

    for (;;) {
        unsigned v;
        size_t d, j;

        if (!first) {
            if (i == len) {
                break;
            }
            if (s[i] != ':') {
                return 0;
            }
            i++;
            if (i < len && s[i] == ':') { /* a "::" run, and there may be only one */
                if (gap != (size_t)-1) {
                    return 0;
                }
                gap = n;
                i++;
                if (i == len) {
                    break;
                }
            }
        } else if (i < len && s[i] == ':') { /* a leading colon is legal only as "::" */
            if (i + 1 == len || s[i + 1] != ':') {
                return 0;
            }
            gap = 0;
            i += 2;
            first = 0;
            if (i == len) {
                break;
            }
        }
        first = 0;

        /* A dotted-quad tail (RFC 4291 2.2 form 3) takes the last four octets, so it has to end
         * the address: anything left after it fails the i != len check below. */
        for (j = i; j < len && s[j] != ':'; j++) {
        }
        if (memchr(s + i, '.', j - i) != NULL) {
            if (n + 4 > 16 || parse_ipv4(s + i, j - i, out + n) != 4) {
                return 0;
            }
            n += 4;
            i = j;
            break;
        }
        d = hex_group(s, len, i, &v);
        if (d == 0 || n + 2 > 16) {
            return 0;
        }
        out[n++] = (uint8_t)(v >> 8);
        out[n++] = (uint8_t)v;
        i += d;
    }
    if (i != len) {
        return 0;
    }
    if (gap == (size_t)-1) {
        return n == 16 ? 16 : 0;
    }
    if (n >= 16) {
        return 0; /* "::" has to stand for at least one group of zeros */
    }
    memmove(out + 16 - (n - gap), out + gap, n - gap);
    memset(out + gap, 0, 16 - n);
    return 16;
}

size_t brisk__x509_parse_ip(const char *s, size_t len, uint8_t *out)
{
    if (s == NULL || out == NULL || len == 0) {
        return 0;
    }
    /* A colon is the one octet an IPv4 literal and a host name can never hold, so it decides
     * which parser runs and there is no "try both" path to disagree with itself. */
    if (memchr(s, ':', len) != NULL) {
        return parse_ipv6(s, len, out);
    }
    return parse_ipv4(s, len, out);
}

/* ------------------------------------------------------------------ the search ------------- */

int brisk__x509_match_host(const brisk__x509_cert *c, const char *host, size_t host_len)
{
    const uint8_t *ref = (const uint8_t *)host;
    uint8_t ip[16];
    size_t ip_len;
    brisk__der san;

    if (c == NULL || host == NULL) {
        return BRISK_E_ARG;
    }
    /* One trailing root dot is stripped from the REFERENCE identifier - "example.com." and
     * "example.com" name the same host and a user or a config file writes either - and never
     * from a presented one, where name_ok refuses it: a certificate that carries the root dot
     * is not something a CA issues, and treating it as equal would be a second comparison rule
     * for no deployment. */
    if (host_len > 0 && ref[host_len - 1] == '.') {
        host_len--;
    }
    ip_len = brisk__x509_parse_ip(host, host_len, ip);
    if (ip_len == 0 && (!name_ok(ref, host_len, 0) || numeric_tld(ref, host_len))) {
        return BRISK_E_ARG;
    }
    /* RFC 9525 1.3: "Do not include or check strings that look like domain names in the
     * subject's Common Name." No SAN, no identity - the subject is never consulted, whatever it
     * holds. */
    if (c->san == NULL) {
        return BRISK_E_AUTH;
    }

    brisk__der_init(&san, c->san, c->san_len);
    while (brisk__der_peek(&san) != -1) {
        const uint8_t *v;
        size_t n;
        unsigned tag = (unsigned)brisk__der_peek(&san);

        if (ip_len > 0 && tag == (BRISK__DER_CONTEXT | 7)) {
            if (brisk__der_value(&san, tag, &v, &n) != BRISK_OK) {
                break;
            }
            /* 6.4: "an octet-for-octet comparison". The length carries the family, so a
             * 4-octet entry can never answer an IPv6 reference, and the 8- and 32-octet
             * address/mask pairs of a nameConstraints GeneralSubtree match nothing at all. */
            if (n == ip_len && memcmp(v, ip, n) == 0) {
                return BRISK_OK;
            }
        } else if (ip_len == 0 && tag == (BRISK__DER_CONTEXT | 2)) {
            if (brisk__der_value(&san, tag, &v, &n) != BRISK_OK) {
                break;
            }
            if (dns_match(v, n, ref, host_len)) {
                return BRISK_OK;
            }
        } else if (brisk__der_skip(&san) != BRISK_OK) {
            break;
        }
    }
    return BRISK_E_AUTH;
}
