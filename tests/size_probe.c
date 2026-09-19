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
#ifdef __linux__
    brisk__os_random(out, 32);
#endif
    return out[0] + (brisk_build_info()[0] == brisk_version()[0]) +
           brisk__ct_memeq(out, out + 1, 8);
}
