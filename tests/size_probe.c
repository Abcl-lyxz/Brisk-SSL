/* size_probe.c - references every public/internal entry point so the linker keeps them;
 * tools/dev.py reads the resulting map file to report per-module flash/RAM. Never run in tests. */
#include "brisk_int.h"

int main(int argc, char **argv)
{
    uint8_t out[64];
    brisk_hash_alg alg = (brisk_hash_alg)(argc % 3 + 1);
    (void)argv;
    brisk_sha256(argv, 8, out);
    brisk_sha384(argv, 8, out);
    brisk_sha512(argv, 8, out);
    brisk_hmac(alg, out, 32, out, 32, out);
    brisk__hkdf_extract(alg, out, 32, out, 32, out);
    brisk__hkdf_expand_label(alg, out, 32, "derived", out, 32, out, 32);
    brisk__chacha20(out, 1, out + 32, out, out, 5);
    brisk__chacha20_poly1305_seal(out, out + 32, out, 5, out, 16, out, out + 48);
    brisk__chacha20_poly1305_open(out, out + 32, out, 5, out, 16, out, out + 48);
    {
        brisk__aes_key k;
        brisk__aes_init(&k, out, (size_t)argc * 16);
        brisk__aes_encrypt(&k, out, out);
        brisk__aes_ctr32(&k, out + 16, out, 33, out);
    }
#ifdef __linux__
    brisk__os_random(out, 32);
#endif
    return out[0] + (brisk_build_info()[0] == brisk_version()[0]) +
           brisk__ct_memeq(out, out + 1, 8);
}
