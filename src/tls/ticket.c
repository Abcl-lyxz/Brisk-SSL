/* ticket.c - the TLS 1.3 resumption ticket blob (RFC 9846 4.7.1, 4.3.11.1), sans-I/O.
 *
 * The one parser of bytes the CALLER stored (flash, a file): treat them as hostile. The format
 * and every refusal are documented on the tls/ticket.c block of src/brisk_int.h. Byte-addressed
 * big-endian, no struct overlay, so a blob written on x86 imports on ppc.
 *
 * The blob carries the resumption PSK: every stack copy is wiped, and the parser branches only
 * on public lengths, the version, the suite, the SNI and the times - never on the PSK.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "brisk_int.h"

#define TK_HDR     20      /* ver 1 + suite 2 + issued 8 + lifetime 4 + age_add 4 + psk_len 1 */
#define TK_MAX_AGE 604800u /* seconds; RFC 9846 4.7.1: never more than 7 days */

/* HashLen of a TLS 1.3 suite this build runs, 0 for anything else (RFC 9846 B.4). */
static size_t tk_hl(uint16_t suite)
{
    return suite == 0x1302 ? 48u : (suite == 0x1301 || suite == 0x1303) ? 32u : 0u;
}

/* One trailing root dot is not part of the name (RFC 6066 3, ch_write drops it too). */
static size_t tk_sni_len(const char *sni, size_t n)
{
    return n != 0 && sni[n - 1] == '.' ? n - 1 : n;
}

int brisk__tls13_ticket_export(const brisk__tls13_ticket *t, int64_t now_ms, const char *sni,
                               size_t sni_len, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t hl, need;
    uint64_t issued = (uint64_t)now_ms;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (out == NULL) {
        return BRISK_E_ARG;
    }
    if (t == NULL || out_len == NULL || (sni_len != 0 && sni == NULL)) {
        goto fail;
    }
    sni_len = tk_sni_len(sni, sni_len);
    hl = tk_hl(t->suite);
    /* 4.7.1: lifetime 0 means "discard immediately" */
    if (hl == 0 || t->psk_len != hl || t->lifetime == 0 || t->ticket == NULL ||
        t->ticket_len == 0 || t->ticket_len > 0xffff || sni_len > 255) {
        goto fail;
    }
    need = TK_HDR + hl + 1 + sni_len + 2 + t->ticket_len;
    if (need > cap || need > BRISK_TICKET_MAX) {
        goto fail; /* not resumable; never an error for the connection */
    }
    out[0] = 1;
    brisk__store_be16(out + 1, t->suite);
    brisk__store_be32(out + 3, (uint32_t)(issued >> 32));
    brisk__store_be32(out + 7, (uint32_t)issued);
    brisk__store_be32(out + 11, t->lifetime);
    brisk__store_be32(out + 15, t->age_add);
    out[19] = (uint8_t)hl;
    memcpy(out + TK_HDR, t->psk, hl);
    out[TK_HDR + hl] = (uint8_t)sni_len;
    if (sni_len != 0) {
        memcpy(out + TK_HDR + hl + 1, sni, sni_len);
    }
    brisk__store_be16(out + TK_HDR + hl + 1 + sni_len, (uint32_t)t->ticket_len);
    memcpy(out + TK_HDR + hl + 3 + sni_len, t->ticket, t->ticket_len);
    *out_len = need;
    return BRISK_OK;
fail:
    brisk__secure_zero(out, cap);
    return BRISK_E_ARG;
}

int brisk__tls13_ticket_import(const uint8_t *b, size_t len, const char *sni, size_t sni_len,
                               int64_t now_ms, brisk__tls13_psk *out)
{
    size_t hl, i, n, k;
    uint64_t issued, age;
    uint32_t lifetime;
    uint16_t suite;

    if (out == NULL) {
        return BRISK_E_ARG;
    }
    brisk__secure_zero(out, sizeof *out);
    if (b == NULL || (sni_len != 0 && sni == NULL) || len < TK_HDR || len > BRISK_TICKET_MAX ||
        b[0] != 1) {
        return BRISK_E_ARG;
    }
    suite = (uint16_t)brisk__load_be16(b + 1);
    hl = tk_hl(suite);
    if (hl == 0 || b[19] != hl || len - TK_HDR < hl + 1) {
        return BRISK_E_ARG;
    }
    i = TK_HDR + hl;
    n = b[i++];
    if (len - i < n + 2) {
        return BRISK_E_ARG;
    }
    /* 4.7.1 / 4.3.11: only for the server name the ticket was issued under (ASCII case-folded) */
    sni_len = tk_sni_len(sni, sni_len);
    if (n != sni_len) {
        return BRISK_E_ARG;
    }
    for (k = 0; k < n; k++) {
        uint8_t x = b[i + k], y = (uint8_t)sni[k];
        x = (uint8_t)(x >= 'A' && x <= 'Z' ? x + 32 : x);
        y = (uint8_t)(y >= 'A' && y <= 'Z' ? y + 32 : y);
        if (x != y) {
            return BRISK_E_ARG;
        }
    }
    i += n;
    n = brisk__load_be16(b + i);
    i += 2;
    if (n == 0 || n != len - i) {
        return BRISK_E_ARG; /* ticket<1..2^16-1>, and no trailing bytes */
    }
    issued = ((uint64_t)brisk__load_be32(b + 3) << 32) | brisk__load_be32(b + 7);
    lifetime = brisk__load_be32(b + 11);
    if (lifetime > TK_MAX_AGE) {
        lifetime = TK_MAX_AGE; /* 4.7.1: never beyond 7 days, whatever the server said */
    }
    /* Signed compare in 64 bits; the difference is formed unsigned once now >= issued, so no
     * overflow. lifetime * 1000 <= 6.048e8 fits 32 bits: no 64-bit multiply or divide. */
    if (lifetime == 0 || now_ms < (int64_t)issued) {
        return BRISK_E_ARG;
    }
    age = (uint64_t)now_ms - issued;
    if (age >= (uint64_t)(lifetime * 1000u)) {
        return BRISK_E_ARG;
    }
    out->identity = b + i;
    out->identity_len = n;
    memcpy(out->psk, b + TK_HDR, hl);
    out->psk_len = (uint8_t)hl;
    out->suite = suite;
    /* 4.3.11.1: obfuscated_ticket_age = (age in ms + ticket_age_add) mod 2^32 */
    out->obf_age = (uint32_t)age + brisk__load_be32(b + 15);
    return BRISK_OK;
}

#undef TK_HDR
#undef TK_MAX_AGE
