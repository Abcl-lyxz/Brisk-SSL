#!/usr/bin/env python3
"""Fetch official known-answer vectors and emit tests/kat/*.inc (stdlib only).

Every vector is re-computed with Python's hashlib/hmac (or a pure-Python RFC 8439 / FIPS 197 reference) before it is written, so a parsing slip fails
here instead of silently weakening the C tests. Downloads are cached in .cache/kat/.

    python tools/kat.py            # regenerate tests/kat/*.inc + tests/kat/SOURCES.md
"""
import base64
import calendar
import datetime
import hashlib
import hmac
import io
import ipaddress
import json
import random
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "kat"
CACHE = ROOT / ".cache" / "kat"

WP = "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/"
SRC = {
    "cavp_sha": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/shs/shabytetestvectors.zip",
    "rfc4231": "https://www.rfc-editor.org/rfc/rfc4231.txt",
    "rfc5869": "https://www.rfc-editor.org/rfc/rfc5869.txt",
    "rfc8448": "https://www.rfc-editor.org/rfc/rfc8448.txt",
    "rfc9846": "https://www.rfc-editor.org/rfc/rfc9846.txt",
    "rfc9001": "https://www.rfc-editor.org/rfc/rfc9001.txt",
    "rfc8439": "https://www.rfc-editor.org/rfc/rfc8439.txt",
    "rfc7748": "https://www.rfc-editor.org/rfc/rfc7748.txt",
    "wp_x25519": f"{WP}x25519_test.json",
    **{f"cavp_aes_{k}": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
       f"documents/aes/{f}" for k, f in (("kat", "KAT_AES.zip"), ("mmt", "aesmmt.zip"), ("mct", "aesmct.zip"))},
    "cavp_gcm": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/mac/gcmtestvectors.zip",
    "wp_chacha20_poly1305": f"{WP}chacha20_poly1305_test.json",
    "wp_aes_gcm": f"{WP}aes_gcm_test.json",
    **{f"wp_hmac_sha{b}": f"{WP}hmac_sha{b}_test.json" for b in (256, 384, 512)},
    **{f"wp_hkdf_sha{b}": f"{WP}hkdf_sha{b}_test.json" for b in (256, 384, 512)},
    "rfc5903": "https://www.rfc-editor.org/rfc/rfc5903.txt",
    "rfc6979": "https://www.rfc-editor.org/rfc/rfc6979.txt",
    "cavp_ecdh": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/components/ecccdhtestvectors.zip",
    "cavp_ecdsa": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/dss/186-3ecdsatestvectors.zip",
    "wp_p256_ecdh": f"{WP}ecdh_secp256r1_ecpoint_test.json",
    "wp_p256_ecdsa": f"{WP}ecdsa_secp256r1_sha256_p1363_test.json",
    "wp_p256_ecdsa_der": f"{WP}ecdsa_secp256r1_sha256_test.json",
    "tls13_wp_p384_ecdsa_der": f"{WP}ecdsa_secp384r1_sha384_test.json",  # not wp_p384_*: der_wycheproof and x509_real_spkis scan that prefix
    "wp_p384_ecdsa_sha384": f"{WP}ecdsa_secp384r1_sha384_p1363_test.json",
    "wp_p384_ecdsa_sha512": f"{WP}ecdsa_secp384r1_sha512_p1363_test.json",
    "rfc8017": "https://www.rfc-editor.org/rfc/rfc8017.txt",
    "cavp_rsa2": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/dss/186-2rsatestvectors.zip",
    "cavp_rsa3": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/dss/186-3rsatestvectors.zip",
    **{f"wp_rsa_pkcs1_{b}_{s}": f"{WP}rsa_signature_{b}_{s}_test.json"
       for b in (2048, 3072, 4096) for s in ("sha256", "sha384", "sha512")},
    **{f"wp_rsa_pss_{v}": f"{WP}rsa_pss_{v}_test.json" for v in (
        "2048_sha256_mgf1_0", "2048_sha256_mgf1_32", "2048_sha384_mgf1_48",
        "3072_sha256_mgf1_32", "4096_sha256_mgf1_32", "4096_sha384_mgf1_48",
        "4096_sha512_mgf1_32", "4096_sha512_mgf1_64", "misc")},
    "x509_limbo": "https://raw.githubusercontent.com/C2SP/x509-limbo/main/limbo.json",
}
HASH = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}
fetched = {}  # name -> (url, sha256 of bytes)


def pinned_sha256():
    """name -> sha256, parsed out of the committed tests/kat/SOURCES.md table.

    The table used to be write-only: every run recomputed it from whatever had just been
    downloaded, so the column that looks like a pin actually pinned nothing. A poisoned download
    - or a poisoned .cache/kat file, which fetch() reuses without asking - would rewrite both the
    generated vectors and the hash that "verifies" them, and the review would show only a large
    diff in a generated file. Now it is read back and enforced. First run on a new source: the
    name is simply absent and is recorded, which is the only time a hash may change without a
    deliberate edit."""
    table = OUT / "SOURCES.md"
    if not table.exists():
        return {}
    pins = {}
    for line in table.read_text().splitlines():
        m = re.match(r"\|\s*([A-Za-z0-9_]+)\s*\|\s*\S+\s*\|\s*`([0-9a-f]{64})`\s*\|", line)
        if m:
            pins[m.group(1)] = m.group(2)
    return pins


PINS = None


def fetch(name):
    global PINS
    if PINS is None:
        PINS = pinned_sha256()
    url = SRC[name]
    path = CACHE / url.rsplit("/", 1)[1]
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "brisk-kat/1"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                path.write_bytes(r.read())
        except urllib.error.URLError as e:
            # csrc.nist.gov chains to a root some Python CA bundles no longer carry. curl brings
            # its own store and still verifies the chain, so this is a transport swap, not a
            # downgrade: never add ssl._create_unverified_context() here.
            if not isinstance(e.reason, ssl.SSLCertVerificationError):
                raise
            # Download to a temp sibling and rename, so an interrupted transfer cannot leave a
            # truncated file that the `path.exists()` above then reuses forever. The urllib path
            # above is already atomic in this sense: it only writes after a complete read.
            tmp = path.with_suffix(path.suffix + ".part")
            try:
                # -q ignores ~/.curlrc, so a stray `insecure` line there cannot silently turn this
                # into the unverified fetch the comment above forbids - which is exactly the
                # machine, behind a TLS-inspecting proxy, where this fallback gets used.
                # --proto '=https' refuses a plaintext redirect.
                subprocess.run(["curl", "-q", "-sSf", "--proto", "=https", "-A", "brisk-kat/1",
                                "-o", str(tmp), url], check=True)
                tmp.replace(path)
            except FileNotFoundError:
                die(f"{name}: python could not verify the TLS chain and curl is not installed - "
                    f"install curl or download {url} to {path} by hand")
            finally:
                tmp.unlink(missing_ok=True)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if name in PINS and PINS[name] != digest:
        die(f"{name}: sha256 mismatch against tests/kat/SOURCES.md\n"
            f"  expected {PINS[name]}\n"
            f"  got      {digest}  ({path})\n"
            f"  The upstream file changed, or the cached copy is not what it claims to be. Delete\n"
            f"  {path} and rerun to re-download; if upstream really did republish, update the\n"
            f"  SOURCES.md row in the same commit as the regenerated vectors, deliberately.")
    fetched[name] = (url, digest)
    return data


def die(msg):
    sys.exit(f"kat.py: {msg}")


# ---------------------------------------------------------------- reference primitives (Python)
def py_hkdf_extract(bits, salt, ikm):
    return hmac.new(salt, ikm, HASH[bits]).digest()


def py_hkdf_expand(bits, prk, info, n):
    hl = HASH[bits]().digest_size
    if n > 255 * hl:
        return None
    t, out, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), HASH[bits]).digest()
        out += t
        i += 1
    return out[:n]


def py_expand_label(bits, secret, label, ctx, n):
    full = b"tls13 " + label
    info = n.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return py_hkdf_expand(bits, secret, info, n)


# ChaCha20 / Poly1305 / AEAD_CHACHA20_POLY1305 (RFC 8439), written straight from the RFC text.
def py_chacha20_block(key, counter, nonce):
    m32 = 0xFFFFFFFF
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    st += [counter] + [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    x = st[:]

    def qr(a, b, c, d):
        for (p, q, r, n) in ((a, b, d, 16), (c, d, b, 12), (a, b, d, 8), (c, d, b, 7)):
            x[p] = (x[p] + x[q]) & m32
            x[r] ^= x[p]
            x[r] = ((x[r] << n) | (x[r] >> (32 - n))) & m32

    for _ in range(10):
        qr(0, 4, 8, 12), qr(1, 5, 9, 13), qr(2, 6, 10, 14), qr(3, 7, 11, 15)
        qr(0, 5, 10, 15), qr(1, 6, 11, 12), qr(2, 7, 8, 13), qr(3, 4, 9, 14)
    return b"".join(((x[i] + st[i]) & m32).to_bytes(4, "little") for i in range(16))


def py_chacha20(key, counter, nonce, data):
    out = bytearray()
    for j in range(0, len(data), 64):
        ks = py_chacha20_block(key, counter + j // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[j:j + 64], ks))
    return bytes(out)


def py_poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s, p, acc = int.from_bytes(key[16:], "little"), (1 << 130) - 5, 0
    for j in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[j:j + 16] + b"\x01", "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def py_aead_seal(key, nonce, aad, pt):
    otk = py_chacha20_block(key, 0, nonce)[:32]
    ct = py_chacha20(key, 1, nonce, pt)
    pad = lambda b: b"\0" * (-len(b) % 16)
    mac = aad + pad(aad) + ct + pad(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return ct, py_poly1305(otk, mac)


# X25519 (RFC 7748 5), written straight from the RFC's pseudocode: decodeScalar25519, the
# Montgomery ladder with a conditional swap, x_2 * z_2^(p-2). Python ints, so no constant-time
# claim - this is a generator, not the library.
X25519_P = (1 << 255) - 19


def py_x25519(k, u):
    a = bytearray(k)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64  # decodeScalar25519
    kk = int.from_bytes(a, "little")
    p = X25519_P
    x1 = (int.from_bytes(u, "little") & ((1 << 255) - 1)) % p  # mask bit 255, reduce (RFC 7748 5)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (kk >> t) & 1
        if swap ^ kt:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        aa = (x2 + z2) % p
        aa2 = aa * aa % p
        bb = (x2 - z2) % p
        bb2 = bb * bb % p
        e = (aa2 - bb2) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * aa % p, c * bb % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * ((da - cb) ** 2 % p) % p
        x2 = aa2 * bb2 % p
        z2 = e * ((aa2 + 121665 * e) % p) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


X25519_BASE = bytes([9]) + bytes(31)


# AES forward cipher (FIPS 197 5.1/5.2), table-based: fine for a generator, never for the library.
def _gmul2(a):
    return ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else a << 1


def _aes_sbox():
    """FIPS 197 5.1.1: inverse in GF(2^8) mod x^8+x^4+x^3+x+1, then the affine map (computed, not typed)."""
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a, b = _gmul2(a), b >> 1
        return r
    inv = [0] + [next(b for b in range(1, 256) if mul(a, b) == 1) for a in range(1, 256)]
    rot = lambda b, n: ((b << n) | (b >> (8 - n))) & 0xFF
    return [b ^ rot(b, 1) ^ rot(b, 2) ^ rot(b, 3) ^ rot(b, 4) ^ 0x63 for b in inv]


AES_SBOX = _aes_sbox()


def py_aes_expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w, rcon = [list(key[4 * i : 4 * i + 4]) for i in range(nk)], 1
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = [AES_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _gmul2(rcon)
        elif nk > 6 and i % nk == 4:
            t = [AES_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r : 4 * r + 4], []) for r in range(nr + 1)]


def py_aes_encrypt(key, blk, rk=None):
    rk = rk or py_aes_expand(key)
    s = [a ^ b for a, b in zip(blk, rk[0])]
    for r in range(1, len(rk)):
        s = [AES_SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows, column-major state
        if r != len(rk) - 1:  # no MixColumns in the final round
            t = []
            for c in range(4):
                a = s[4 * c : 4 * c + 4]
                x = a[0] ^ a[1] ^ a[2] ^ a[3]
                t += [a[j] ^ x ^ _gmul2(a[j] ^ a[(j + 1) % 4]) for j in range(4)]
            s = t
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


def py_aes_ctr32(key, cb, data):
    """SP 800-38D 6.2 inc32 / 6.5 GCTR: only the low 32 bits count, mod 2^32; a short tail uses the
    leading keystream bytes."""
    rk, low, out = py_aes_expand(key), int.from_bytes(cb[12:], "big"), bytearray()
    for j in range(0, len(data), 16):
        ks = py_aes_encrypt(key, cb[:12] + ((low + j // 16) & 0xFFFFFFFF).to_bytes(4, "big"), rk)
        out += bytes(a ^ b for a, b in zip(data[j : j + 16], ks))
    return bytes(out)


# ---------------------------------------------------------------- RFC text helpers
def rfc_lines(raw):
    """RFC plain text minus page headers/footers/form feeds (they split hex dumps)."""
    out = []
    for ln in raw.decode("utf-8", "replace").split("\n"):
        if "\f" in ln or "[Page " in ln or re.match(r"^RFC \d{4} ", ln):
            continue
        out.append(ln.rstrip())
    return out


def hexbytes(s):
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s))


# ---------------------------------------------------------------- NIST CAVP SHA-2
def cavp_sha():
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_sha")))
    names = {Path(n).name: n for n in z.namelist()}
    kats, monte = [], []
    for bits in (256, 384, 512):
        for kind in ("ShortMsg", "LongMsg"):
            txt = z.read(names[f"SHA{bits}{kind}.rsp"]).decode()
            rows = re.findall(r"Len = (\d+)\s+Msg = ([0-9a-f]+)\s+MD = ([0-9a-f]+)", txt)
            for i, (ln, msg, md) in enumerate(rows):
                m = bytes.fromhex(msg)[: int(ln) // 8]
                if HASH[bits](m).hexdigest() != md:
                    die(f"CAVP SHA{bits}{kind} mismatch len={ln}")
                # ponytail: LongMsg thinned to every 8th (all verified above) to keep the repo small;
                # multi-block paths are also covered by Monte, 10^6 x 'a' and the 0..300 B differential set.
                if kind == "ShortMsg" or i % 8 == 0 or i == len(rows) - 1:
                    kats.append((bits, m.hex(), md))
        txt = z.read(names[f"SHA{bits}Monte.rsp"]).decode()
        seed = bytes.fromhex(re.search(r"Seed = ([0-9a-f]+)", txt).group(1))
        mds = re.findall(r"MD = ([0-9a-f]+)", txt)
        s = seed  # SHAVS 6.4 Monte Carlo: MD_i = H(MD_{i-3} || MD_{i-2} || MD_{i-1}), 1000 per checkpoint
        for j, want in enumerate(mds):
            a = b = c = s
            for _ in range(1000):
                a, b, c = b, c, HASH[bits](a + b + c).digest()
            s = c
            if s.hex() != want:
                die(f"CAVP SHA{bits}Monte mismatch at checkpoint {j}")
        monte.append((bits, seed.hex(), mds))
    return kats, monte


# ---------------------------------------------------------------- HMAC: RFC 4231 + Wycheproof
def rfc4231():
    lines, cases, cur, field = rfc_lines(fetch("rfc4231")), [], None, None
    for ln in lines:
        if re.match(r"^4\.\d+\.\s+Test Case \d+", ln):
            cur = {}
            cases.append(cur)
            field = None
            continue
        if cur is None:
            continue
        # "=" is optional: RFC 4231 Test Case 3 prints "Key            aaaa..." (typo in the RFC)
        m = re.match(r"^\s+(Key|Data|HMAC-SHA-(?:224|256|384|512))\s+(?:=\s+)?([0-9a-f]+)", ln)
        if m:
            field = m.group(1)
            cur[field] = m.group(2)
            continue
        m = re.match(r"^\s{10,}([0-9a-f]{2,})(\s|$)", ln)
        if m and field:
            cur[field] += m.group(1)
        else:
            field = None
    out = []
    for i, c in enumerate(cases, 1):
        key, data = bytes.fromhex(c["Key"]), bytes.fromhex(c["Data"])
        for bits in (256, 384, 512):
            tag = c[f"HMAC-SHA-{bits}"]
            if hmac.new(key, data, HASH[bits]).hexdigest()[: len(tag)] != tag:
                die(f"RFC 4231 TC{i} HMAC-SHA-{bits} mismatch")
            out.append((bits, key.hex(), data.hex(), tag, 1))
    if len(cases) != 7:
        die(f"RFC 4231: expected 7 test cases, parsed {len(cases)}")
    return out


def wycheproof_hmac():
    out = []
    for bits in (256, 384, 512):
        doc = json.loads(fetch(f"wp_hmac_sha{bits}"))
        for g in doc["testGroups"]:
            nbytes = g["tagSize"] // 8
            for t in g["tests"]:
                key, msg = bytes.fromhex(t["key"]), bytes.fromhex(t["msg"])
                valid = t["result"] == "valid"
                ok = hmac.new(key, msg, HASH[bits]).hexdigest()[: 2 * nbytes] == t["tag"]
                if ok != valid:
                    die(f"Wycheproof HMAC-SHA{bits} tcId {t['tcId']} inconsistent")
                out.append((bits, t["key"], t["msg"], t["tag"], int(valid)))
    return out


# ---------------------------------------------------------------- HKDF: RFC 5869 + Wycheproof
def rfc5869():
    text = "\n".join(rfc_lines(fetch("rfc5869")))
    out = []
    for block in re.split(r"\nA\.\d+\.\s+Test Case \d+", text)[1:]:
        if "Hash = SHA-256" not in block:
            continue  # A.4-A.7 are SHA-1

        def field(name):
            m = re.search(rf"^\s+{name}\s+=\s+(.*?)(?=^\s+\w+\s+=|\Z)", block, re.S | re.M)
            v = m.group(1)
            return b"" if v.strip().startswith("(0 octets)") else hexbytes(re.sub(r"\(\d+ octets\)", "", v).replace("0x", ""))

        ikm, salt, info = field("IKM"), field("salt"), field("info")
        n = int(re.search(r"^\s+L\s+=\s+(\d+)", block, re.M).group(1))
        prk, okm = field("PRK"), field("OKM")
        if py_hkdf_extract(256, salt, ikm) != prk or py_hkdf_expand(256, prk, info, n) != okm:
            die("RFC 5869 vector mismatch")
        out.append((256, ikm.hex(), salt.hex(), info.hex(), n, okm.hex(), 1, prk.hex()))
    if len(out) != 3:
        die(f"RFC 5869: expected 3 SHA-256 cases, parsed {len(out)}")
    return out


def wycheproof_hkdf():
    out = []
    for bits in (256, 384, 512):
        doc = json.loads(fetch(f"wp_hkdf_sha{bits}"))
        for g in doc["testGroups"]:
            for t in g["tests"]:
                ikm, salt, info = (bytes.fromhex(t[k]) for k in ("ikm", "salt", "info"))
                valid = t["result"] == "valid"
                got = py_hkdf_expand(bits, py_hkdf_extract(bits, salt, ikm), info, t["size"])
                if (got is not None and got.hex() == t["okm"]) != valid:
                    die(f"Wycheproof HKDF-SHA{bits} tcId {t['tcId']} inconsistent")
                out.append((bits, t["ikm"], t["salt"], t["info"], t["size"], t["okm"], int(valid), ""))
    return out


# ---------------------------------------------------------------- TLS 1.3 key schedule: RFC 8448 + RFC 9001
def rfc8448_blocks():
    """The RFC 8448 traces as ordered {_side, _h, _f} blocks ("{client}  <header>:" + hex fields)."""
    blocks, cur, field, sec = [], None, None, 0
    for ln in rfc_lines(fetch("rfc8448")):
        m = re.match(r"^(\d+)\.  \S", ln)  # a section heading (column 0; the TOC is indented)
        if m:
            sec = int(m.group(1))
        m = re.match(r"^\s*\{(client|server)\}\s+(.*)$", ln)
        if m:
            cur = {"_side": m.group(1), "_h": m.group(2), "_f": {}, "_sec": sec}
            blocks.append(cur)
            field = None
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+([A-Za-z][A-Za-z ]*?) \(\d+ octets\):\s*([0-9a-f ]*)$", ln)
        if m:
            field = m.group(1)
            cur["_f"][field] = m.group(2)
            continue
        m = re.match(r"^\s+salt:\s+0 \(all zero octets\)", ln)
        if m:
            cur["_f"]["salt"] = ""
            field = None
            continue
        if not ln.strip():
            continue  # a page break leaves blank lines inside a long hex dump (the Certificate)
        m = re.match(r"^\s+((?:[0-9a-f]{2} ?)+)$", ln)
        if m and field:
            cur["_f"][field] += " " + m.group(1)
        else:
            field = None
    return blocks


def rfc8448():
    """Every 'extract secret' and 'derive ...' block of the RFC 8448 traces (all SHA-256)."""
    extracts, labels, seen = [], [], set()
    for b in rfc8448_blocks():
        f = {k: hexbytes(v) for k, v in b["_f"].items()}
        if b["_h"].startswith("extract secret") and {"IKM", "secret"} <= f.keys():
            salt = f.get("salt", b"")
            if py_hkdf_extract(256, salt, f["IKM"]) != f["secret"]:
                die(f"RFC 8448 extract mismatch: {b['_h']}")
            key = ("x", salt, f["IKM"])
            if key not in seen:
                seen.add(key)
                extracts.append((256, salt.hex(), f["IKM"].hex(), f["secret"].hex()))
        if "PRK" not in f:
            continue
        for name in list(f):
            if not name.endswith("info"):
                continue
            exp = name[: -len("info")] + "expanded"
            if exp not in f:
                continue
            info, want = f[name], f[exp]
            n, ll = int.from_bytes(info[:2], "big"), info[2]
            full, cl = info[3 : 3 + ll], info[3 + ll]
            ctx = info[4 + ll : 4 + ll + cl]
            if not full.startswith(b"tls13 ") or n != len(want) or 4 + ll + cl != len(info):
                die(f"RFC 8448 bad HkdfLabel in {b['_h']}")
            label = full[6:]
            if py_expand_label(256, f["PRK"], label, ctx, n) != want:
                die(f"RFC 8448 expand-label mismatch: {b['_h']} / {name}")
            key = ("e", f["PRK"], info)
            if key not in seen:
                seen.add(key)
                labels.append((256, f["PRK"].hex(), label.decode(), ctx.hex(), want.hex()))
    if len(extracts) < 3 or len(labels) < 20:
        die(f"RFC 8448: parsed too few vectors ({len(extracts)} extract, {len(labels)} expand-label)")
    return extracts, labels


def rfc9001():
    """RFC 9001 A.1 Initial secrets (client and server)."""
    text = "\n".join(rfc_lines(fetch("rfc9001")))
    a1 = text[text.index("\nA.1.  Keys\n") : text.index("\nA.2.  Client Initial\n")] + "\n\n"  # not the TOC
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 5.2 initial_salt
    cid = bytes.fromhex("8394c8f03e515708")  # RFC 9001 A: client's DCID
    m = re.search(r"initial_secret = HKDF-Extract\(initial_salt, cid\)\s+=\s+([0-9a-f\s]+?)\n\n", a1)
    vals = {"initial_secret": hexbytes(m.group(1))}
    if py_hkdf_extract(256, salt, cid) != vals["initial_secret"]:
        die("RFC 9001 initial_secret mismatch")
    extracts = [(256, salt.hex(), cid.hex(), vals["initial_secret"].hex())]
    labels = []
    pat = r"(\w+)\s*=\s*HKDF-Expand-Label\((\w+),\s*\"([^\"]*)\",\s*\"\",\s*(\d+)\)\s*=\s*([0-9a-f\s]+?)\n\n"
    for name, arg, label, n, hx in re.findall(pat, a1):
        want = hexbytes(hx)
        sec = vals[arg]
        if py_expand_label(256, sec, label.encode(), b"", int(n)) != want:
            die(f"RFC 9001 {name} mismatch")
        vals[name] = want
        labels.append((256, sec.hex(), label, "", want.hex()))
    if len(labels) != 8:
        die(f"RFC 9001 A.1: expected 8 expand-label vectors, parsed {len(labels)}")
    return extracts, labels


# ---------------------------------------------------------------- ChaCha20-Poly1305: RFC 8439 + Wycheproof + RFC 9001 A.5
def rfc8439_fields(lines):
    """Ordered (label, bytes) pairs of one RFC 8439 section: a label line followed by hex dumps in
    any of the RFC's three styles ("000  4c 61 ...  ascii", "FF FF ...", "22:4f:51:...")."""
    out = []
    for ln in lines:
        m = re.match(r"^\s*\d{3}  ((?:[0-9a-f]{2} ){0,15}[0-9a-f]{2})(?:\s|$)", ln)
        m = m or re.match(r"^\s+((?:[0-9A-Fa-f]{2} )+[0-9A-Fa-f]{2})$", ln)
        m = m or re.match(r"^\s+([0-9a-f]{2}(?::[0-9a-f]{2})+:?)$", ln)
        if m and out:
            out[-1][1].extend(hexbytes(m.group(1)))
        elif ln.strip():
            out.append((ln.strip().rstrip(":").strip(), bytearray()))
    return {k: bytes(v) for k, v in out}  # a repeated label keeps its last dump


def rfc8439():
    lines = rfc_lines(fetch("rfc8439"))
    start = {}
    for i, ln in enumerate(lines):
        m = re.match(r"^(\d(?:\.\d){0,2}|A\.\d)\.\s+\S", ln)
        if m:
            start[m.group(1)] = i  # the last hit wins: skips the table of contents

    def sect(a, b):
        return lines[start[a] : start[b]]

    def vectors(a, b):  # "Test Vector #n" blocks of an appendix section -> [(fields, raw text)]
        vs = []
        for ln in sect(a, b):
            if re.match(r"^\s*Test Vector #\d+", ln):
                vs.append([])
            if vs:
                vs[-1].append(ln)
        return [(rfc8439_fields(v), "\n".join(v)) for v in vs]

    def inline(sec, name):  # "Key = 00:01:...:1f." or "Nonce = (00:...:00)." spread over lines
        return hexbytes(re.search(name + r"\s*=\s*\(?([0-9a-f][0-9a-f:\s]*[0-9a-f])", sec).group(1))

    chacha, poly, aead = [], [], []
    # 2.3.2 block function, 2.4.2 encryption
    s, f = "\n".join(sect("2.3.2", "2.4")), rfc8439_fields(sect("2.3.2", "2.4"))
    chacha.append((inline(s, "Key"), int(re.search(r"Block Count = (\d+)", s).group(1)),
                   inline(s, "Nonce"), bytes(64), f["Serialized Block"]))
    s, f = "\n".join(sect("2.4.2", "2.5")), rfc8439_fields(sect("2.4.2", "2.5"))
    chacha.append((inline(s, "Key"), int(re.search(r"Initial Counter = (\d+)", s).group(1)),
                   inline(s, "Nonce"), f["Plaintext Sunscreen"], f["Ciphertext Sunscreen"]))
    # 2.5.2 Poly1305 (key and tag are inline; one key byte is split across two lines)
    s = "\n".join(sect("2.5.2", "2.6"))
    key = hexbytes(re.search(r"Key Material:(.*?)\n\s*o ", s, re.S).group(1))
    tag = hexbytes(re.search(r"Tag:\s*([0-9a-f:]+)", s).group(1))
    poly.append((key, rfc8439_fields(sect("2.5.2", "2.6"))["Message to be Authenticated"], tag))
    # 2.6.2 one-time key generation = first 32 bytes of the counter-0 block
    f = rfc8439_fields(sect("2.6.2", "2.7"))
    chacha.append((f["Key"], 0, f["Nonce"], bytes(32), f["Output bytes"]))
    # 2.8.2 AEAD; nonce = 32-bit fixed-common part || IV
    f = rfc8439_fields(sect("2.8.2", "3"))
    nonce = f["32-bit fixed-common part"] + f["IV"]
    aead.append((f["Key"], nonce, f["AAD"], f["Plaintext"], f["Ciphertext"], f["Tag"], 1))
    if py_chacha20_block(f["Key"], 0, nonce)[:32] != f["Poly1305 Key"]:
        die("RFC 8439 2.8.2 Poly1305 key mismatch")
    # A.1 block function, A.2 encryption
    for v, raw in vectors("A.1", "A.2"):
        ctr = int(re.search(r"Block Counter = (\d+)", raw).group(1))
        chacha.append((v["Key"], ctr, v["Nonce"], bytes(64), v["Keystream"]))
    for v, raw in vectors("A.2", "A.3"):
        ctr = int(re.search(r"Initial Block Counter = (\d+)", raw).group(1))
        chacha.append((v["Key"], ctr, v["Nonce"], v["Plaintext"], v["Ciphertext"]))
    # A.3 Poly1305: #1-#4 give a one-time key, #5-#11 give R / S / data / tag
    for v, _ in vectors("A.3", "A.4"):
        if "One-time Poly1305 Key" in v:
            poly.append((v["One-time Poly1305 Key"], v["Text to MAC"], v["Tag"]))
        else:
            poly.append((v["R"] + v["S"], v["data"], v["tag"]))
    # A.4 key generation (counter 0)
    for v, _ in vectors("A.4", "A.5"):
        chacha.append((v["The ChaCha20 Key"], 0, v["The nonce"], bytes(32), v["Poly1305 one-time key"]))
    # A.5 AEAD decryption
    f = rfc8439_fields(lines[start["A.5"] :])
    if f["Calculated Tag"] != f["Received Tag"]:
        die("RFC 8439 A.5 tag lines differ")
    aead.append((f["The ChaCha20 Key"], f["The nonce"], f["The AAD"], f["Plaintext"], f["Ciphertext"],
                 f["Received Tag"], 1))
    for i, (k, c, n, pt, ct) in enumerate(chacha):
        if len(k) != 32 or len(n) != 12 or not pt or py_chacha20(k, c, n, pt) != ct:
            die(f"RFC 8439 ChaCha20 vector {i} mismatch")
    for i, (k, m, t) in enumerate(poly):
        if len(k) != 32 or py_poly1305(k, m) != t:
            die(f"RFC 8439 Poly1305 vector {i} mismatch")
    for i, (k, n, a, pt, ct, t, _) in enumerate(aead):
        if not pt or py_aead_seal(k, n, a, pt) != (ct, t):
            die(f"RFC 8439 AEAD vector {i} mismatch")
    if (len(chacha), len(poly), len(aead)) != (2 + 1 + 5 + 3 + 3, 1 + 11, 2):
        die(f"RFC 8439: parsed {len(chacha)} chacha, {len(poly)} poly1305, {len(aead)} aead vectors")
    return chacha, poly, aead


def wycheproof_chacha20_poly1305():
    doc = json.loads(fetch("wp_chacha20_poly1305"))
    out, skipped = [], 0
    for g in doc["testGroups"]:
        for t in g["tests"]:
            if g["ivSize"] != 96:  # the API takes a fixed 12-byte nonce, so these cannot be expressed
                if t["result"] != "invalid" or "InvalidNonceSize" not in t["flags"]:
                    die(f"Wycheproof ChaCha20-Poly1305 tcId {t['tcId']}: non-96-bit iv that is not InvalidNonceSize")
                skipped += 1
                continue
            if g["keySize"] != 256 or g["tagSize"] != 128:
                die(f"Wycheproof ChaCha20-Poly1305 tcId {t['tcId']}: unexpected sizes")
            k, n, a, m, ct, tag = (bytes.fromhex(t[x]) for x in ("key", "iv", "aad", "msg", "ct", "tag"))
            valid = t["result"] == "valid"
            if (py_aead_seal(k, n, a, m) == (ct, tag)) != valid:
                die(f"Wycheproof ChaCha20-Poly1305 tcId {t['tcId']} inconsistent")
            out.append((k, n, a, m, ct, tag, int(valid)))
    if len(out) != 316 or skipped != 9 or sum(1 for r in out if not r[6]) != 60:
        die(f"Wycheproof ChaCha20-Poly1305: {len(out)} emitted, {skipped} skipped")
    return out


def rfc9001_chacha():
    """RFC 9001 A.5: ChaCha20-Poly1305 short header packet (key schedule, AEAD, header protection)."""
    text = "\n".join(rfc_lines(fetch("rfc9001")))
    a5 = text[text.rindex("\nA.5.  ChaCha20-Poly1305 Short Header Packet") : text.index("\nAppendix B.")]
    v = {}
    for n, h in re.findall(r"^\s+(secret|key|iv|hp)\b[^\n]*\n\s+=\s+([0-9a-f]+(?:\n\s+[0-9a-f]+)*)", a5, re.M):
        v[n] = hexbytes(h)
    for n, h in re.findall(r"^\s+(nonce|unprotected header|payload plaintext|payload ciphertext|sample|mask|header|packet)"
                           r"\s+=\s+([0-9a-f]+)$", a5, re.M):
        v[n] = bytes.fromhex(h)
    pn = int(re.search(r"^\s+pn\s+=\s+(\d+)", a5, re.M).group(1))
    for lab, n in (("key", 32), ("iv", 12), ("hp", 32)):
        if py_expand_label(256, v["secret"], b"quic " + lab.encode(), b"", n) != v[lab]:
            die(f"RFC 9001 A.5 {lab} mismatch")
    nonce = bytes(a ^ b for a, b in zip(v["iv"], pn.to_bytes(12, "big")))  # RFC 9001 5.3
    hdr = v["unprotected header"]
    ct, tag = py_aead_seal(v["key"], nonce, hdr, v["payload plaintext"])
    pn_len = (hdr[0] & 3) + 1
    sample = (ct + tag)[4 - pn_len : 20 - pn_len]  # RFC 9001 5.4.2: sample starts at pn_offset + 4
    mask = py_chacha20(v["hp"], int.from_bytes(sample[:4], "little"), sample[4:], bytes(5))  # 5.4.4
    prot = bytes([hdr[0] ^ (mask[0] & 0x1F)]) + hdr[1 : len(hdr) - pn_len] + \
        bytes(a ^ b for a, b in zip(hdr[len(hdr) - pn_len :], mask[1:]))
    if (nonce != v["nonce"] or ct + tag != v["payload ciphertext"] or sample != v["sample"]
            or mask != v["mask"] or prot != v["header"] or prot + ct + tag != v["packet"]):
        die("RFC 9001 A.5 packet protection mismatch")
    return [(v["secret"], pn, hdr, v["payload plaintext"], ct + tag, sample, mask, v["packet"])]


def differential_chacha():
    rnd = random.Random(20260920)
    rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
    edges = (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 300)
    aead = [(rb(32), rb(12), rb(a), rb(p)) for a in edges for p in edges]
    while len(aead) < 200:
        aead.append((rb(32), rb(12), rb(rnd.randrange(0, 81)), rb(rnd.randrange(0, 301))))
    aead = [(k, n, a, p, *py_aead_seal(k, n, a, p), 1) for k, n, a, p in aead]
    chacha = []
    for i in range(60):
        n = rnd.randrange(1, 301)
        ctr = rnd.getrandbits(32) if i % 3 else 0xFFFFFFFF
        if ctr + (n + 63) // 64 > 1 << 32:  # caller contract: no counter wrap inside one call
            n = min(n, 64)
        k, nn, m = rb(32), rb(12), rb(n)
        chacha.append((k, ctr, nn, m, py_chacha20(k, ctr, nn, m)))
    poly = []
    for n in list(range(0, 50)) + [rnd.randrange(50, 400) for _ in range(30)]:
        k, m = rb(32), rb(n)
        poly.append((k, m, py_poly1305(k, m)))
    return chacha, poly, aead


# ---------------------------------------------------------------- differential (hashlib) vectors
def differential():
    rnd = random.Random(20260919)
    rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
    hashes, macs, kdfs = [], [], []
    for n in range(0, 301):
        m = rb(n)
        for bits in (256, 384, 512):
            hashes.append((bits, m.hex(), HASH[bits](m).hexdigest()))
    for i in range(120):
        bits = (256, 384, 512)[i % 3]
        key, msg = rb(rnd.randrange(0, 260)), rb(rnd.randrange(0, 300))
        macs.append((bits, key.hex(), msg.hex(), hmac.new(key, msg, HASH[bits]).hexdigest(), 1))
        ikm, salt, info = rb(rnd.randrange(0, 80)), rb(rnd.randrange(0, 80)), rb(rnd.randrange(0, 80))
        size = rnd.randrange(1, 300)
        okm = py_hkdf_expand(bits, py_hkdf_extract(bits, salt, ikm), info, size)
        kdfs.append((bits, ikm.hex(), salt.hex(), info.hex(), size, okm.hex(), 1, ""))
    fips = []
    for msg in (b"abc", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
                b"klmnopqrlmnopqrsmnopqrstnopqrstu"):
        for bits in (256, 384, 512):
            fips.append((bits, msg.hex(), HASH[bits](msg).hexdigest()))
    million = [(bits, HASH[bits](b"a" * 1000000).hexdigest()) for bits in (256, 384, 512)]
    return hashes + fips, macs, kdfs, million


# ---------------------------------------------------------------- AES: FIPS 197, CAVP, SP 800-38A, RFC 9001
def rsp_encrypt(z, fname):
    """[ENCRYPT] rows of one CAVP AESAVS .rsp file as (count, key, pt, ct) byte strings."""
    names = {Path(n).name: n for n in z.namelist()}
    txt = z.read(names[fname]).decode()
    enc = txt[txt.index("[ENCRYPT]") : txt.index("[DECRYPT]")]
    rows = re.findall(r"COUNT = (\d+)\s+KEY = ([0-9a-f]+)\s+PLAINTEXT = ([0-9a-f]+)\s+CIPHERTEXT = ([0-9a-f]+)", enc)
    if not rows:
        die(f"CAVP {fname}: no ENCRYPT rows")
    return [(int(c), bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(x)) for c, k, p, x in rows]


def py_aes_ecb(key, pt):
    rk = py_aes_expand(key)
    return b"".join(py_aes_encrypt(key, pt[j : j + 16], rk) for j in range(0, len(pt), 16))


def aes_vectors():
    # FIPS 197 Appendix C.1 / C.3 (the PDF is not machine-friendly; checked against the reference,
    # which is itself checked against every CAVP row below).
    fips = [(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff"),
             bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")),
            (bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff"),
             bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"))]
    ecb = list(fips)
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_aes_kat")))
    for bits in (128, 256):  # AES-192 deliberately absent (no TLS 1.3 / TLS 1.2 AEAD / QUIC suite uses it)
        for kind in ("GFSbox", "KeySbox", "VarKey", "VarTxt"):
            ecb += [(k, p, c) for _, k, p, c in rsp_encrypt(z, f"ECB{kind}{bits}.rsp")]
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_aes_mmt")))
    for bits in (128, 256):
        ecb += [(k, p, c) for _, k, p, c in rsp_encrypt(z, f"ECBMMT{bits}.rsp")]
    for i, (k, p, c) in enumerate(ecb):
        if len(k) not in (16, 32) or len(p) % 16 or len(p) != len(c) or py_aes_ecb(k, p) != c:
            die(f"AES ECB vector {i} mismatch")
    if len(ecb) != 2 + 7 + 21 + 128 + 128 + 5 + 16 + 256 + 128 + 20:
        die(f"CAVP AES ECB: {len(ecb)} rows")
    # AESAVS 6.4 Monte Carlo (ECB): 1000 chained encryptions per row, then the key update
    mct = []
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_aes_mct")))
    for bits in (128, 256):
        rows = rsp_encrypt(z, f"ECBMCT{bits}.rsp")
        key, pt = rows[0][1], rows[0][2]
        for cnt, k, p, c in rows:
            if (k, p) != (key, pt):
                die(f"CAVP ECBMCT{bits} COUNT {cnt}: key/pt chain mismatch")
            rk, prev, ct = py_aes_expand(key), None, pt
            for _ in range(1000):
                prev, ct = ct, py_aes_encrypt(key, ct, rk)
            if ct != c:
                die(f"CAVP ECBMCT{bits} COUNT {cnt} mismatch")
            key = bytes(a ^ b for a, b in zip(key, ct if bits == 128 else prev + ct))
            pt = ct
            mct.append((cnt, k, p, c))
        if len(rows) != 100:
            die(f"CAVP ECBMCT{bits}: {len(rows)} rows")
    # SP 800-38A F.5.1 / F.5.5 CTR-AES128/256.Encrypt (from the PDF; checked against the reference)
    msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    cb = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ctr = [(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), cb, msg,
            bytes.fromhex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                          "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee")),
           (bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), cb, msg,
            bytes.fromhex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                          "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"))]
    for i, (k, c0, m, c) in enumerate(ctr):
        if py_aes_ctr32(k, c0, m) != c:
            die(f"SP 800-38A F.5 vector {i} mismatch")
    # RFC 9001 A.2 / A.3: header protection mask = AES-ECB(hp, sample)[0..4] with the A.1 hp keys
    text = "\n".join(rfc_lines(fetch("rfc9001")))
    a1 = text[text.index("\nA.1.  Keys\n") : text.index("\nA.2.  Client Initial\n")]
    hps = [bytes.fromhex(h) for h in
           re.findall(r"hp\s+= HKDF-Expand-Label\(\w+, \"quic hp\", \"\", 16\)\s+=\s+([0-9a-f]{32})", a1)]
    a23 = text[text.index("\nA.2.  Client Initial\n") : text.index("\nA.4.  Retry\n")]
    samples = [bytes.fromhex(h) for h in re.findall(r"sample = ([0-9a-f]{32})", a23)]
    masks = [bytes.fromhex(h) for h in
             re.findall(r"mask\s+=(?: AES-ECB\(hp, sample\)\[0\.\.4\]\s+=)?\s+([0-9a-f]{10})\n", a23)]
    if not (len(hps) == len(samples) == len(masks) == 2):
        die(f"RFC 9001 A.2/A.3: parsed {len(hps)} hp, {len(samples)} samples, {len(masks)} masks")
    hp = list(zip(hps, samples, masks))
    for i, (k, s_, m) in enumerate(hp):
        if py_aes_encrypt(k, s_)[:5] != m:
            die(f"RFC 9001 A.{i + 2} AES header protection mismatch")
    # seeded differential CTR set: random keys, counters near the 32-bit wrap, lengths 0..300
    rnd = random.Random(20260921)
    rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
    for i in range(120):
        k = rb(16 if i % 2 else 32)
        low = (0xFFFFFFFF - rnd.randrange(0, 8)) if i % 3 == 0 else rnd.getrandbits(32)
        c0 = rb(12) + low.to_bytes(4, "big")
        m = rb(i if i < 40 else rnd.randrange(0, 301))
        ctr.append((k, c0, m, py_aes_ctr32(k, c0, m)))
    for low in (0xFFFFFFFE, 0xFFFFFFFF):  # wraps to 00000000; byte 11 = ff must not take a carry
        k, c0 = rb(16), rb(11) + b"\xff" + low.to_bytes(4, "big")
        m = rb(16 * 5 + 7)
        ctr.append((k, c0, m, py_aes_ctr32(k, c0, m)))
    return ecb, mct, ctr, hp


# ---------------------------------------------------------------- AES-GCM: CAVP, Wycheproof, RFC 9001 A.2/A.3
def py_gf_mul(x, y):
    """SP 800-38D 6.3 Algorithm 1, bit by bit: blocks as big-endian ints, x^0 is the leftmost bit."""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def py_ghash(y, h, data):
    """y continued over data (SP 800-38D 6.4); a short last block is zero-padded on the right."""
    yi, hi = int.from_bytes(y, "big"), int.from_bytes(h, "big")
    for j in range(0, len(data), 16):
        blk = data[j : j + 16]
        yi = py_gf_mul(yi ^ int.from_bytes(blk + bytes(16 - len(blk)), "big"), hi)
    return yi.to_bytes(16, "big")


def py_gcm_seal(key, iv, aad, pt):
    """SP 800-38D 7.1 with a 96-bit IV: J0 = IV || 0^31 || 1, payload from inc32(J0)."""
    h = py_aes_encrypt(key, bytes(16))
    ct = py_aes_ctr32(key, iv + b"\0\0\0\2", pt)
    pad = lambda b: b + bytes(-len(b) % 16)
    s = py_ghash(bytes(16), h, pad(aad) + pad(ct) + (8 * len(aad)).to_bytes(8, "big") + (8 * len(ct)).to_bytes(8, "big"))
    return ct, bytes(a ^ b for a, b in zip(py_aes_encrypt(key, iv + b"\0\0\0\1"), s))


def cavp_gcm():
    """gcm{EncryptExtIV,Decrypt}{128,256}.rsp, IVlen 96 / Taglen 128 only; FAIL rows are invalid tags."""
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_gcm")))
    names = {Path(n).name: n for n in z.namelist()}
    out, seen = [], 0
    for fname in ("gcmEncryptExtIV128.rsp", "gcmEncryptExtIV256.rsp", "gcmDecrypt128.rsp", "gcmDecrypt256.rsp"):
        txt = z.read(names[fname]).decode().replace("\r", "")
        for sec in re.split(r"\n(?=\[Keylen)", txt)[1:]:
            p = dict(re.findall(r"\[(\w+) = (\d+)\]", sec))
            if p["IVlen"] != "96" or p["Taglen"] != "128":
                continue
            for blk in re.split(r"\n(?=Count = )", sec)[1:]:
                f = dict(re.findall(r"^(\w+) = ?([0-9a-f]*)$", blk, re.M))
                k, iv, a, c, t = (bytes.fromhex(f[x]) for x in ("Key", "IV", "AAD", "CT", "Tag"))
                valid = "FAIL" not in blk
                pt = bytes.fromhex(f["PT"]) if valid else b""
                if len(a) * 8 != int(p["AADlen"]) or len(c) * 8 != int(p["PTlen"]):
                    die(f"CAVP {fname} Count {f['Count']}: length header mismatch")
                if valid and py_gcm_seal(k, iv, a, pt) != (c, t):
                    die(f"CAVP {fname} Count {f['Count']} mismatch")
                if not valid and py_gcm_seal(k, iv, a, py_aes_ctr32(k, iv + b"\0\0\0\2", c))[1] == t:
                    die(f"CAVP {fname} Count {f['Count']}: FAIL row has a correct tag")
                seen += 1
                # ponytail: every row is verified above; only counts 0-2 of each section plus every
                # FAIL row are emitted, to keep the .inc small
                if int(f["Count"]) < 3 or not valid:
                    out.append((k, iv, a, pt if valid else b"", c, t, int(valid)))
    if seen != 4 * 25 * 15 or sum(1 for r in out if not r[6]) < 200:
        die(f"CAVP GCM: {seen} rows seen, {len(out)} emitted")
    return out


def wycheproof_aes_gcm():
    doc = json.loads(fetch("wp_aes_gcm"))
    out, skipped = [], 0
    for g in doc["testGroups"]:
        for t in g["tests"]:
            if g["ivSize"] != 96 or g["keySize"] not in (128, 256) or g["tagSize"] != 128:
                skipped += 1  # only 96-bit IVs, AES-128/256 and 16-byte tags exist in the API
                continue
            k, n, a, m, ct, tag = (bytes.fromhex(t[x]) for x in ("key", "iv", "aad", "msg", "ct", "tag"))
            valid = t["result"] == "valid"
            if (py_gcm_seal(k, n, a, m) == (ct, tag)) != valid:
                die(f"Wycheproof AES-GCM tcId {t['tcId']} inconsistent")
            out.append((k, n, a, m, ct, tag, int(valid)))
    if len(out) != 133 or skipped != 183 or sum(1 for r in out if not r[6]) != 54:
        die(f"Wycheproof AES-GCM: {len(out)} emitted, {skipped} skipped")
    return out


def rfc9001_gcm():
    """RFC 9001 A.2 client / A.3 server Initial (AES-128-GCM): full protected packets."""
    text = "\n".join(rfc_lines(fetch("rfc9001")))
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 5.2 (checked in rfc9001())
    init = py_hkdf_extract(256, salt, bytes.fromhex("8394c8f03e515708"))
    blocks = (("\nA.2.  Client Initial\n", "\nA.3.  Server Initial\n", b"client in", r"1162-byte payload:",
               r"The unprotected header", r"protected packet is:"),
              ("\nA.3.  Server Initial\n", "\nA.4.  Retry\n", b"server in", r"no PADDING frames:",
               r"The header from the server", r"protected packet is then:"))
    out = []
    for start, end, label, p0, p1, k0 in blocks:
        sec = text[text.rindex(start) : text.rindex(end)]
        pt = hexbytes(sec[sec.index(p0) + len(p0) : sec.index(p1)])
        if label == b"client in":
            pt += bytes(1162 - len(pt))  # PADDING frames (RFC 9000 19.1) up to the stated payload size
        hdr = bytes.fromhex(re.search(r"\n\s+(c[0-9a-f]{30,})\n", sec[sec.index(p1) :]).group(1))
        pkt = hexbytes(sec[sec.index(k0) + len(k0) :])
        secret = py_expand_label(256, init, label, b"", 32)
        key, iv, hp = (py_expand_label(256, secret, b"quic " + x, b"", n) for x, n in ((b"key", 16), (b"iv", 12), (b"hp", 16)))
        pn_len = (hdr[0] & 3) + 1
        pn = int.from_bytes(hdr[-pn_len:], "big")
        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))  # RFC 9001 5.3
        ct, tag = py_gcm_seal(key, nonce, hdr, pt)
        mask = py_aes_encrypt(hp, (ct + tag)[4 - pn_len : 20 - pn_len])  # 5.4.2 / 5.4.3
        prot = bytes([hdr[0] ^ (mask[0] & 0x0F)]) + hdr[1:-pn_len] + bytes(a ^ b for a, b in zip(hdr[-pn_len:], mask[1:]))
        if prot + ct + tag != pkt:
            die(f"RFC 9001 {start.strip()} AES-GCM packet mismatch")
        out.append((secret, pn, hdr, pt, pkt))
    if [len(r[3]) for r in out][0] != 1162 or len(out) != 2:
        die("RFC 9001 A.2/A.3: bad parse")
    return out


def differential_gcm():
    rnd = random.Random(20260922)
    rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
    rows = []
    for L in list(range(0, 81)) + [255, 256, 257, 1024, 4097]:
        for a, p in ((L, L), (0, L), (L, 0), (rnd.randrange(0, 40), L)) if L <= 80 else ((L, 17), (13, L)):
            k, iv = rb(16 if len(rows) % 2 else 32), rb(12)
            aad, pt = rb(a), rb(p)
            rows.append((k, iv, aad, pt, *py_gcm_seal(k, iv, aad, pt), 1))
    # length-block swap check: (aad='', pt=X) and (aad=X, pt='') under one key/iv
    k, iv, x = rb(16), rb(12), rb(16)
    for aad, pt in ((b"", x), (x, b""), (b"", x + b"\x01"), (x + b"\x01", b"")):
        rows.append((k, iv, aad, pt, *py_gcm_seal(k, iv, aad, pt), 1))
    if len({r[5] for r in rows[-4:]}) != 4:
        die("differential GCM: swapped length blocks collide")
    # GHASH on its own (y, h, data -> y'), incl. H = 0, H = 1 (0x80 00..), all-ones H / X / y
    ones, one = b"\xff" * 16, b"\x80" + bytes(15)
    gh = [(bytes(16), bytes(16), ones * 2), (bytes(16), one, rb(40)), (ones, ones, ones * 3), (rb(16), ones, rb(33)),
          (ones, rb(16), ones + b"\xff"), (bytes(16), one, b""), (rb(16), rb(16), b"")]
    for n in list(range(0, 50)) + [64, 100, 255]:
        gh.append((rb(16), rb(16), rb(n)))
    if py_ghash(bytes(16), one, one) != one or py_ghash(one, bytes(16), b"") != one:
        die("GHASH reference: identity element broken")
    return rows, [(y, h, d, py_ghash(y, h, d)) for y, h, d in gh]


# ---------------------------------------------------------------- X25519: RFC 7748 + RFC 8448 + Wycheproof
# Row = (scalar, u, out, ok, deep). ok = 0 when the result is the all-zero value, which RFC 7748
# 6.1 / RFC 9846 7.4.2 make an abort; deep = 1 asks test_x25519.c for the slow variants (offsets
# 1..3, canaries): the RFC rows, every all-zero row and every non-canonical u. Running all 518
# Wycheproof cases four times over would blow the 900 s qemu-armv5 budget.
def x25519_row(k, u, deep=0):
    out = py_x25519(k, u)
    return (k.hex(), u.hex(), out.hex(), int(out != bytes(32)), deep)


def rfc7748():
    """RFC 7748 5.2 (two KATs + the iterated test) and 6.1 (Alice/Bob worked example)."""
    text = "\n".join(rfc_lines(fetch("rfc7748")))
    s52 = text[text.index("\n5.2.  Test Vectors") : text.index("\n6.  Diffie-Hellman")]
    hexblk = r"((?:\s+[0-9a-f]+\n)+)"
    rows = []
    pat = (r"Input scalar:\n" + hexblk + r".*?Input u-coordinate:\n" + hexblk +
           r".*?Output u-coordinate:\n" + hexblk)
    for k, u, o in re.findall(pat, s52, re.S):
        k, u, o = hexbytes(k), hexbytes(u), hexbytes(o)
        if len(k) != 32:
            continue  # the X448 pair in the same section
        if py_x25519(k, u) != o:
            die("RFC 7748 5.2 KAT mismatch")
        rows.append(x25519_row(k, u, 1))
    if len(rows) != 2:
        die(f"RFC 7748 5.2: parsed {len(rows)} of 2 X25519 KATs")

    # 6.1: X25519(a,9) = K_A, X25519(b,9) = K_B, X25519(a,K_B) = X25519(b,K_A) = K.
    s61 = text[text.index("\n6.1.  Curve25519") : text.index("\n6.2.  Curve448")]
    v = dict(re.findall(r"((?:Alice's|Bob's) (?:private|public) key|Their shared secret)"
                        r"[^\n]*:\n\s+([0-9a-f]{64})\n", s61))
    if len(v) != 5:
        die(f"RFC 7748 6.1: parsed {len(v)} of 5 fields")
    a, ka = hexbytes(v["Alice's private key"]), hexbytes(v["Alice's public key"])
    b, kb = hexbytes(v["Bob's private key"]), hexbytes(v["Bob's public key"])
    kk = hexbytes(v["Their shared secret"])
    if (py_x25519(a, X25519_BASE), py_x25519(b, X25519_BASE)) != (ka, kb):
        die("RFC 7748 6.1 public key mismatch")
    if py_x25519(a, kb) != kk or py_x25519(b, ka) != kk:
        die("RFC 7748 6.1 shared secret mismatch")
    rows += [x25519_row(a, X25519_BASE, 1), x25519_row(b, X25519_BASE, 1),
             x25519_row(a, kb, 1), x25519_row(b, ka, 1)]

    # Iterated test. The 1,000,000-iteration value is taken from the RFC text and NOT recomputed
    # here (hours in pure Python); test_x25519.c only runs it under BRISK_TEST_SLOW=1.
    it = dict((n.replace(",", ""), hexbytes(h)) for n, h in
              re.findall(r"After (one|1,000|1,000,000) iterations?:\n\s+([0-9a-f]{64})\n", s52))
    if len(it) != 3:
        die(f"RFC 7748 5.2: parsed {len(it)} of 3 iterated values")
    k = u = X25519_BASE
    iters, want = [], {1: it["one"], 1000: it["1000"], 1000000: it["1000000"]}
    for i in range(1, 1001):
        k, u = py_x25519(k, u), k
        if i in want:
            if k != want[i]:
                die(f"RFC 7748 5.2 iterated mismatch at {i}")
            iters.append((i, k.hex()))
    iters.append((1000000, want[1000000].hex()))
    return rows, iters


def rfc8448_x25519():
    """RFC 8448: each ephemeral x25519 key pair, and the handshake IKM = X25519(priv, peer pub)."""
    rows, last = [], {}
    for b in rfc8448_blocks():
        f = {k: hexbytes(v) for k, v in b["_f"].items()}
        if "x25519 key pair" in b["_h"] and {"private key", "public key"} <= f.keys():
            priv, pub = f["private key"], f["public key"]
            if py_x25519(priv, X25519_BASE) != pub:
                die(f"RFC 8448 {b['_side']} x25519 public key mismatch")
            last[b["_side"]] = (priv, pub)
            rows.append(x25519_row(priv, X25519_BASE, 1))
        if b["_h"].startswith('extract secret "handshake"') and "IKM" in f and len(last) == 2:
            # Section 5 completes on P-256 after the HelloRetryRequest, so its IKM is not an
            # X25519 output: the equality test below simply skips it.
            cp, sp = last["client"], last["server"]
            if py_x25519(cp[0], sp[1]) == f["IKM"] == py_x25519(sp[0], cp[1]):
                rows.append(x25519_row(cp[0], sp[1], 1))
    # 4 sections (3, 4, 6, 7) x (client pub, server pub, shared) + section 5's unused client pair
    if len(rows) != 13:
        die(f"RFC 8448 x25519: parsed {len(rows)} rows, expected 13")
    return rows


def wycheproof_x25519():
    doc = json.loads(fetch("wp_x25519"))
    out = []
    for g in doc["testGroups"]:
        if g["curve"] != "curve25519" or g["type"] != "XdhComp":
            die(f"Wycheproof X25519: unexpected group {g['curve']}/{g['type']}")
        for t in g["tests"]:
            priv, pub, shared = (bytes.fromhex(t[x]) for x in ("private", "public", "shared"))
            if len(pub) != 32 or py_x25519(priv, pub) != shared:
                die(f"Wycheproof X25519 tcId {t['tcId']} inconsistent")
            # "acceptable" here still pins the output bytes; only an all-zero shared secret is an
            # error for us, so the expectation comes from the value, never from the flags.
            noncanon = (int.from_bytes(pub, "little") & ((1 << 255) - 1)) >= X25519_P
            out.append(x25519_row(priv, pub, int(shared == bytes(32) or noncanon)))
    zero, deep = sum(1 for r in out if not r[3]), sum(r[4] for r in out)
    if len(out) != 518 or zero != 31 or deep != 36:
        die(f"Wycheproof X25519: {len(out)} vectors, {zero} all-zero, {deep} deep")
    return out


def differential_x25519():
    """Small-order / edge u values plus a seeded random set, both directions of each pair."""
    rows = []
    # The classic small-order and boundary u-coordinates: every one must give the all-zero result.
    small = [0, 1, 325606250916557431795983626356110631294008115727848805560023387167927233504,
             39382357235489614581723060781553021112529911719440698176882885853963445705823,
             X25519_P - 1, X25519_P, X25519_P + 1]
    k0 = bytes(range(1, 33))
    for n in small:
        u = (n % (1 << 256)).to_bytes(32, "little")
        r = x25519_row(k0, u, 1)
        if r[3]:
            die(f"X25519 small-order u {n:#x} did not produce the all-zero value")
        rows.append(r)
    rnd = random.Random(20260923)
    rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))
    for _ in range(32):
        a, b = rb(32), rb(32)
        ka, kb = py_x25519(a, X25519_BASE), py_x25519(b, X25519_BASE)
        if py_x25519(a, kb) != py_x25519(b, ka):
            die("differential X25519: ECDH disagreement")
        rows += [x25519_row(a, X25519_BASE), x25519_row(b, X25519_BASE),
                 x25519_row(a, kb), x25519_row(b, ka)]
    return rows


# ---------------------------------------------------------------- P-256: reference + parameters
# The domain parameters are parsed out of RFC 5903 3.1 (= SP 800-186 3.2.1.3 = SEC 2 2.4.2) and
# never typed here, so the generated vectors and tests/kat/p256_params.inc cannot disagree with
# the spec through a transcription slip. Everything below runs on those parsed values.
P256 = {}
P384 = {}  # RFC 5903 3.2, same labels, same parser


def rfc5903_params(sec, bits, curve):
    """RFC 5903 3.1 / 3.2: p, curve b, group order n, and the generator G, into `curve`."""
    text = "\n".join(rfc_lines(fetch("rfc5903")))
    nxt = f"\n{sec[0]}.{int(sec[2]) + 1}."
    s = text[text.index(f"\n{sec}  {bits}-Bit") : text.index(nxt)]
    want = {"p": "Group Prime/Irreducible Polynomial", "b": "Group Curve b", "n": "Group Order"}
    for key, label in want.items():
        m = re.search(re.escape(label) + r":\n((?:\s+[0-9A-F ]+\n)+)", s)
        if not m:
            die(f"RFC 5903 {sec} {label} not found")
        curve[key] = int.from_bytes(hexbytes(m.group(1)), "big")
    for key in ("gx", "gy"):
        m = re.search(r"\n" + key + r":\n((?:\s+[0-9A-F ]+\n)+)", s)
        if not m:
            die(f"RFC 5903 {sec} generator {key} not found")
        curve[key] = int.from_bytes(hexbytes(m.group(1)), "big")

    # Self-consistency of what we parsed, against the closed forms the same section states.
    closed = {256: 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
              384: 2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1}[bits]
    if curve["p"] != closed:
        die(f"RFC 5903 {sec} p is not the closed form for {bits} bits")
    for v in curve.values():
        if not 0 < v < 2 ** bits:
            die(f"RFC 5903 {sec} parameter out of range")
    if not py_ec_on_curve(curve, curve["gx"], curve["gy"]):
        die(f"RFC 5903 {sec} G is not on the curve")
    if py_ec_mul(curve, curve["n"], (curve["gx"], curve["gy"])) is not None:
        die(f"RFC 5903 {sec} n*G is not the point at infinity")
    w = bits // 4
    return [(k, f"{curve[k]:0{w}x}") for k in ("p", "b", "n", "gx", "gy")]


def check_source_constants(path, prefix, width, curve):
    """The five curve constants compiled into a module, byte-for-byte against the RFC.

    This is how "never hand-type vectors" is honoured for the parameters themselves: they are the
    one thing in the module that cannot come from a generated .inc (src/ does not include tests/),
    so the transcription is checked here instead of trusted. tests/test_p256.c and
    tests/test_p384.c pin G and n through behaviour as well; this catches a slip even in b, which
    no single vector names."""
    src = (ROOT / path).read_text(encoding="utf-8", errors="replace")
    for suffix, key in (("_P", "p"), ("_B", "b"), ("_N", "n"), ("_GX", "gx"), ("_GY", "gy")):
        name = prefix + suffix
        m = re.search(r"static const uint8_t " + name + r"\[%d\] = \{(.*?)\};" % width, src, re.S)
        if not m:
            die(f"{path}: {name}[{width}] not found")
        got = bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
        if got != curve[key].to_bytes(width, "big"):
            die(f"{path}: {name} does not match RFC 5903 ({got.hex()})")


def check_p256_source_constants():
    check_source_constants("src/crypto/p256.c", "P256", 32, P256)


def check_p384_source_constants():
    check_source_constants("src/crypto/p384.c", "P384", 48, P384)


def py_ec_on_curve(curve, x, y):
    p = curve["p"]
    return 0 <= x < p and 0 <= y < p and (y * y - (x * x * x - 3 * x + curve["b"])) % p == 0


def py_ec_add(curve, A, B):
    """Affine addition on y^2 = x^3 - 3x + b. None is the point at infinity."""
    if A is None or B is None:
        return B if A is None else A
    p = curve["p"]
    (x1, y1), (x2, y2) = A, B
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if A == B:
        lam = 3 * (x1 * x1 - 1) * pow(2 * y1, -1, p) % p  # a = -3
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def py_ec_mul(curve, k, A):
    R, k = None, k % (curve["n"] * 2)
    while k:
        if k & 1:
            R = py_ec_add(curve, R, A)
        A, k = py_ec_add(curve, A, A), k >> 1
    return R


def py_p256_on_curve(x, y):
    return py_ec_on_curve(P256, x, y)


def py_p256_add(A, B):
    return py_ec_add(P256, A, B)


def py_p256_mul(k, A):
    return py_ec_mul(P256, k, A)


def p256_enc(A):
    """RFC 9846 4.3.8.2 KeyShareEntry.key_exchange: 0x04 || X || Y, 32 bytes each, big-endian."""
    return b"\x04" + A[0].to_bytes(32, "big") + A[1].to_bytes(32, "big")


P256_G = None  # set in main() once the parameters are parsed


def py_p256_keygen(d):
    """(pub65, ok): ok = 0 when d is outside [1, n-1] and the module must return BRISK_E_ARG."""
    if not 1 <= d < P256["n"]:
        return b"", 0
    return p256_enc(py_p256_mul(d, P256_G)), 1


def py_p256_ecdh(d, peer):
    """32-byte Z, or None when RFC 9846 4.3.8.2 validation rejects the peer point (or d)."""
    if not 1 <= d < P256["n"] or len(peer) != 65 or peer[0] != 4:
        return None
    x, y = int.from_bytes(peer[1:33], "big"), int.from_bytes(peer[33:], "big")
    if not py_p256_on_curve(x, y):
        return None
    R = py_p256_mul(d, (x, y))
    if R is None:
        return None
    return R[0].to_bytes(32, "big")  # leading zeros kept (RFC 9846 7.4.2)


# Expected status codes, matching the C enum used by tests/test_p256.c.
P256_OK, P256_AUTH, P256_ARG = 0, 1, 2


def py_p256_verify(pub, h, sig):
    """FIPS 186-5 6.4.2. Returns P256_OK / P256_AUTH / P256_ARG."""
    n = P256["n"]
    # The order below mirrors brisk__p256_ecdsa_verify exactly, because the expect code a row
    # carries depends on which check fires first: hash_len, then r/s, then the public point.
    if len(pub) != 65 or len(sig) != 64 or len(h) < 32:
        return P256_ARG
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < n and 1 <= s < n):
        # FIPS 186-5 6.4.2 step 1 says INVALID, not an error: a signature the peer could have
        # written, so BRISK_E_AUTH -> decrypt_error, not BRISK_E_ARG -> illegal_parameter.
        return P256_AUTH
    x, y = int.from_bytes(pub[1:33], "big"), int.from_bytes(pub[33:], "big")
    if pub[0] != 4 or not py_p256_on_curve(x, y):
        return P256_ARG  # malformed key material -> bad_certificate, a different condition
    e = int.from_bytes(h[:32], "big") % n  # leftmost min(bitlen n, bitlen H) bits = first 32 bytes
    w = pow(s, -1, n)
    R = py_p256_add(py_p256_mul(e * w % n, P256_G), py_p256_mul(r * w % n, (x, y)))
    if R is None:
        return P256_AUTH
    return P256_OK if R[0] % n == r else P256_AUTH


# ---------------------------------------------------------------- P-256 rows
# ECDH row  = (priv, peer65, z, ok, deep); keygen row = (priv, pub65, ok)
# verify row = (pub65, hash, sig64, expect, deep)
def ecdh_row(d, peer, deep=0):
    z = py_p256_ecdh(d, peer)
    return (f"{d:064x}", peer.hex(), (z or b"").hex(), int(z is not None), deep)


def verify_row(pub, h, sig, deep=0):
    return (pub.hex(), h.hex(), sig.hex(), py_p256_verify(pub, h, sig), deep)


def rfc5903_ecdh():
    """RFC 5903 8.1: one full P-256 exchange, both directions, plus the two public keys."""
    text = "\n".join(rfc_lines(fetch("rfc5903")))
    s = text[text.index("\n8.1.  256-Bit") : text.index("\n8.2.")]
    v = {}
    for key in ("i", "gix", "giy", "r", "grx", "gry", "girx", "giry"):
        m = re.search(r"\n" + key + r":\n((?:\s+[0-9A-F ]+\n)+)", s)
        if not m:
            die(f"RFC 5903 8.1: {key} not found")
        v[key] = int.from_bytes(hexbytes(m.group(1)), "big")
    qi, qr = (v["gix"], v["giy"]), (v["grx"], v["gry"])
    if py_p256_mul(v["i"], P256_G) != qi or py_p256_mul(v["r"], P256_G) != qr:
        die("RFC 5903 8.1: public key mismatch")
    shared = (v["girx"], v["giry"])
    if py_p256_mul(v["i"], qr) != shared or py_p256_mul(v["r"], qi) != shared:
        die("RFC 5903 8.1: shared value mismatch")
    # "The Diffie-Hellman shared secret value is girx."
    keys = [(f"{v['i']:064x}", p256_enc(qi).hex(), 1), (f"{v['r']:064x}", p256_enc(qr).hex(), 1)]
    ecdh = [ecdh_row(v["i"], p256_enc(qr), 1), ecdh_row(v["r"], p256_enc(qi), 1)]
    if any(row[2] != f"{v['girx']:064x}" for row in ecdh):
        die("RFC 5903 8.1: Z is not girx")
    return keys, ecdh


def rsp_sections(text):
    """Split a CAVP .rsp into {'[P-256]': body, '[P-256,SHA-256]': body, ...}.

    Only a curve header starts a new section. Prose headers like
    '[B.4.2 Key Pair Generation by Testing Candidates]' contain spaces and belong to the section
    they sit in - treating them as separators silently empties the one before them."""
    out, cur = {}, None
    for ln in text.replace("\r", "").split("\n"):
        s = ln.strip()
        if re.fullmatch(r"\[[A-Z]-\d+[^\[\]\s]*\]", s):
            cur = s
            out.setdefault(cur, [])
        elif cur is not None:
            out[cur].append(ln)
    return {k: "\n".join(v) for k, v in out.items()}


def cavp_p256():
    """CAVP KAS ECC CDH (keygen + ECDH), and 186-3 ECDSAVS KeyPair / PKV / SigVer (CAVS 11.0).

    186-3 and 186-4 are different zips with different section contents; the count guards below
    are pinned to the 186-3 one named in SRC["cavp_ecdsa"]."""
    keys, ecdh, verify = [], [], []

    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_ecdh")))
    body = rsp_sections(z.read("KAS_ECC_CDH_PrimitiveTest.txt").decode("latin-1"))["[P-256]"]
    pat = (r"COUNT = \d+\nQCAVSx = ([0-9a-f]+)\nQCAVSy = ([0-9a-f]+)\ndIUT = ([0-9a-f]+)\n"
           r"QIUTx = ([0-9a-f]+)\nQIUTy = ([0-9a-f]+)\nZIUT = ([0-9a-f]+)")
    hits = re.findall(pat, body)
    if len(hits) != 25:
        die(f"CAVP CDH P-256: parsed {len(hits)} of 25 COUNTs")
    for qx, qy, d, ix, iy, zz in hits:
        if len(zz) != 64:  # the .rsp writes Z zero-padded to the field width; so do we
            die("CAVP CDH: ZIUT is not 32 bytes")
        d, peer = int(d, 16), p256_enc((int(qx, 16), int(qy, 16)))
        pub, ok = py_p256_keygen(d)
        if not ok or pub != p256_enc((int(ix, 16), int(iy, 16))):
            die("CAVP CDH: QIUT mismatch")
        row = ecdh_row(d, peer, 1)
        if row[2] != f"{int(zz, 16):064x}":
            die("CAVP CDH: ZIUT mismatch")
        keys.append((f"{d:064x}", pub.hex(), 1))
        ecdh.append(row)
    # None of the 25 P-256 ZIUT values happens to start with a zero byte, so the RFC 9846 7.4.2
    # "leading zeros MUST NOT be truncated" rule is pinned by a searched row in
    # differential_p256() instead. Checked here so the claim cannot rot silently.
    if any(int(zz, 16) < 1 << 248 for *_, zz in hits):
        die("CAVP CDH: a ZIUT now has a leading zero byte - fold that row into the padding test")

    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_ecdsa")))
    body = rsp_sections(z.read("KeyPair.rsp").decode("latin-1"))["[P-256]"]
    hits = re.findall(r"d = ([0-9a-f]+)\nQx = ([0-9a-f]+)\nQy = ([0-9a-f]+)", body)
    if len(hits) != 10:
        die(f"CAVP KeyPair P-256: parsed {len(hits)} of 10 pairs")
    for d, qx, qy in hits:
        pub, ok = py_p256_keygen(int(d, 16))
        if not ok or pub != p256_enc((int(qx, 16), int(qy, 16))):
            die("CAVP KeyPair: Q mismatch")
        keys.append((f"{int(d, 16):064x}", pub.hex(), 1))

    # PKV: public-key validation, driven through ECDH with one fixed valid private key.
    # Composition of the 12 P-256 rows: 4 valid, 4 "point not on curve", 4 "Q_x or Q_y out of
    # range". All 4 out-of-range rows carry a 33-byte coordinate, which the 65-byte wire encoding
    # of RFC 9846 4.3.8.2 cannot express at all - truncating them would turn them into different
    # points, so they are skipped, and the in-range half of that check (p <= coord < 2^256) is
    # pinned by the x == p / y == p / coord == 2^256-1 rows built in differential_p256().
    body = rsp_sections(z.read("PKV.rsp").decode("latin-1"))["[P-256]"]
    hits = re.findall(r"Qx = ([0-9a-f]+)\nQy = ([0-9a-f]+)\nResult = ([PF])", body)
    if len(hits) != 12:
        die(f"CAVP PKV P-256: parsed {len(hits)} of 12 cases")
    d_fixed, used, oversize = int(hits[0][0], 16) % (P256["n"] - 1) + 1, 0, 0
    for qx, qy, res in hits:
        x, y = int(qx, 16), int(qy, 16)
        if x >= 2 ** 256 or y >= 2 ** 256:
            oversize += 1
            continue
        peer = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        row = ecdh_row(d_fixed, peer, 1)
        if row[3] != int(res == "P"):
            die(f"CAVP PKV: verdict mismatch for {qx}")
        used += 1
        ecdh.append(row)
    if (used, oversize) != (8, 4):
        die(f"CAVP PKV: {used} usable / {oversize} oversize rows, expected 8 / 4")

    # All three sections whose digest is at least 32 bytes. SHA-384 and SHA-512 are what exercise
    # the leftmost-bits rule of FIPS 186-5 6.4.2 with official negative vectors - without them the
    # only long-hash rows are the 4 positive ones from RFC 6979 A.2.5. The [P-256,SHA-1] and
    # [P-256,SHA-224] sections are skipped: hash_len < 32 is BRISK_E_ARG by design, and neither
    # digest is compiled (RFC 9846 4.3.3 forbids SHA-224 and leaves SHA-1 legacy-only).
    sections = rsp_sections(z.read("SigVer.rsp").decode("latin-1"))
    pat = (r"Msg = ([0-9a-f]+)\nQx = ([0-9a-f]+)\nQy = ([0-9a-f]+)\nR = ([0-9a-f]+)\n"
           r"S = ([0-9a-f]+)\nResult = ([PF])")
    total = 0
    for bits, hfn in ((256, hashlib.sha256), (384, hashlib.sha384), (512, hashlib.sha512)):
        hits = re.findall(pat, sections[f"[P-256,SHA-{bits}]"])
        if len(hits) != 15:
            die(f"CAVP SigVer P-256/SHA-{bits}: parsed {len(hits)} of 15 cases")
        for msg, qx, qy, r, s, res in hits:
            pub = b"\x04" + int(qx, 16).to_bytes(32, "big") + int(qy, 16).to_bytes(32, "big")
            sig = int(r, 16).to_bytes(32, "big") + int(s, 16).to_bytes(32, "big")
            row = verify_row(pub, hfn(bytes.fromhex(msg)).digest(), sig, 1)
            # A CAVP "F" row is a wrong signature, not a malformed one: every R/S here is in range.
            if (row[3] == P256_OK) != (res == "P"):
                die(f"CAVP SigVer SHA-{bits}: verdict mismatch")
            verify.append(row)
            total += 1
    if total != 45:
        die(f"CAVP SigVer P-256: emitted {total} of 45 rows")
    return keys, ecdh, verify


def wycheproof_p256_ecdh():
    """ecdh_secp256r1_ecpoint: the raw 0x04||X||Y bytes RFC 9846 4.3.8.2 puts on the wire."""
    doc = json.loads(fetch("wp_p256_ecdh"))
    rows, invalid, acceptable, wrong_len = [], 0, 0, 0
    for g in doc["testGroups"]:
        if g.get("encoding") != "ecpoint" or g["type"] != "EcdhEcpointTest":
            die(f"Wycheproof P-256 ECDH: unexpected group {g.get('encoding')}/{g['type']}")
        for t in g["tests"]:
            peer = bytes.fromhex(t["public"])
            d = int(t["private"], 16)
            # brisk__p256_ecdh takes a fixed uint8_t[65], so a 0- or 33-byte encoding cannot be
            # handed to it at all: the length check lives in the TLS layer that reads
            # KeyShareEntry.key_exchange. The rule these rows are really about - a compressed
            # point is rejected, never decompressed - is still pinned, by the 0x02/0x03/0x06/0x07
            # rows built in differential_p256() and by the all-256-first-bytes sweep in
            # tests/test_p256.c.
            if len(peer) != 65:
                wrong_len += 1
                continue
            # The expectation is computed from the value and the encoding, never from the flag:
            # Wycheproof's "acceptable" compressed key is a REJECT for us, because TLS 1.3
            # removed point-format negotiation and allows only the uncompressed form.
            row = ecdh_row(d, peer, int(t["result"] != "valid"))
            if t["result"] == "valid" and row[2] != t["shared"]:
                die(f"Wycheproof P-256 ECDH tcId {t['tcId']}: shared mismatch")
            if t["result"] != "valid" and row[3]:
                die(f"Wycheproof P-256 ECDH tcId {t['tcId']}: we accept a non-valid case")
            invalid += t["result"] == "invalid"
            acceptable += t["result"] == "acceptable"
            rows.append(row)
    # 355 rows: 330 valid, 24 invalid, 1 acceptable. 9 are not 65 bytes long (8 invalid + the one
    # acceptable compressed key), leaving 346 = 330 valid + 16 invalid.
    if (len(rows), invalid, acceptable, wrong_len) != (346, 16, 0, 9):
        die(f"Wycheproof P-256 ECDH: {len(rows)} rows, {invalid} invalid, {acceptable} "
            f"acceptable, {wrong_len} not 65 bytes (expected 346/16/0/9 of 355)")
    return rows


def wycheproof_p256_ecdsa():
    """ecdsa_secp256r1_sha256_p1363: raw 64-byte r||s, the shape this module takes."""
    doc = json.loads(fetch("wp_p256_ecdsa"))
    rows, valid, wrong_len = [], 0, 0
    for g in doc["testGroups"]:
        if g["type"] != "EcdsaP1363Verify" or g["sha"] != "SHA-256":
            die(f"Wycheproof P-256 ECDSA: unexpected group {g['type']}/{g['sha']}")
        pub = bytes.fromhex(g["publicKey"]["uncompressed"])
        if len(pub) != 65:
            die("Wycheproof P-256 ECDSA: public key is not 65 bytes")
        for t in g["tests"]:
            sig = bytes.fromhex(t["sig"])
            # brisk__p256_ecdsa_verify takes a fixed uint8_t[64], so a 2- or 82-byte P1363
            # signature cannot be handed to it: the width is fixed by the caller that unwraps the
            # DER ECDSA-Sig-Value. All 21 such rows are "invalid", and what they are really about
            # - r or s outside [1, n-1] - is pinned at the right width by the r/s edge rows built
            # in differential_p256().
            if len(sig) != 64:
                wrong_len += 1
                continue
            h = hashlib.sha256(bytes.fromhex(t["msg"])).digest()
            row = verify_row(pub, h, sig, int(t["result"] != "valid"))
            if (row[3] == P256_OK) != (t["result"] == "valid"):
                die(f"Wycheproof P-256 ECDSA tcId {t['tcId']}: verdict mismatch")
            valid += t["result"] == "valid"
            rows.append(row)
    # 262 rows: 173 valid, 89 invalid. 21 invalid ones are not 64 bytes, leaving 241.
    if (len(rows), valid, wrong_len) != (241, 173, 21):
        die(f"Wycheproof P-256 ECDSA: {len(rows)} rows, {valid} valid, {wrong_len} not 64 bytes "
            f"(expected 241/173/21 of 262)")
    return rows


def rfc6979_verify():
    """RFC 6979 A.2.5 (P-256). Used here only as verify vectors; the SHA-384/512 rows are the
    official exercise of the FIPS 186-5 leftmost-bits rule. Signing is the next roadmap line."""
    text = "\n".join(rfc_lines(fetch("rfc6979")))
    # rindex: the first hit is the table of contents.
    s = text[text.rindex("A.2.5.  ECDSA, 256 Bits") : text.rindex("A.2.6.")]
    kv = dict(re.findall(r"\n\s+(x|Ux|Uy) = ([0-9A-F]{64})\n", s))
    if {"x", "Ux", "Uy"} - kv.keys():
        die(f"RFC 6979 A.2.5: key fields {sorted(kv)}")
    pub = p256_enc((int(kv["Ux"], 16), int(kv["Uy"], 16)))
    if py_p256_keygen(int(kv["x"], 16))[0] != pub:
        die("RFC 6979 A.2.5: U is not x*G")
    # SHA-1 and SHA-224 rows are skipped: neither hash is compiled into this library, and both
    # digests are shorter than the 32 bytes brisk__p256_ecdsa_verify requires. That leaves
    # SHA-256 (no truncation) and SHA-384/512, which are the leftmost-bits rule in action.
    algs = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}
    pat = (r"With SHA-(\d+), message = \"(sample|test)\":\n\s+k = [0-9A-F]{64}\n"
           r"\s+r = ([0-9A-F]{64})\n\s+s = ([0-9A-F]{64})\n")
    hits = re.findall(pat, s)
    if len(hits) != 10:
        die(f"RFC 6979 A.2.5: parsed {len(hits)} of 10 (hash, message) pairs")
    rows = []
    for bits, msg, r, s_ in hits:
        if bits not in algs:
            continue
        h = algs[bits](msg.encode()).digest()
        row = verify_row(pub, h, bytes.fromhex(r) + bytes.fromhex(s_), 1)
        if row[3] != P256_OK:
            die(f"RFC 6979 A.2.5 SHA-{bits}/{msg}: signature does not verify")
        rows.append(row)
    if len(rows) != 6:
        die(f"RFC 6979 A.2.5: {len(rows)} usable rows, expected 6")
    return rows


# ---------------------------------------------------------------- P-256 ECDSA signing
# sign row = (priv, hash, extra, sig64, ok). ok = 0 means BRISK_E_ARG with `sig` untouched: d
# outside [1, n-1], or a hash_len the module does not accept. `extra` is the RFC 6979 3.6 hedging
# input k'; empty means plain RFC 6979, which is what keeps the A.2.5 rows usable as a self-test
# of the hedged code path.
def py_ecdsa_sign_with_k(d, e, k):
    """FIPS 186-5 6.4.1 steps 4-7 with k given. None when r == 0 or s == 0, i.e. retry."""
    n = P256["n"]
    R = py_p256_mul(k, P256_G)
    if R is None:
        return None
    r = R[0] % n
    if r == 0:
        return None
    s = pow(k, -1, n) * (e + r * d) % n
    if s == 0:
        return None
    return r, s


def py_rfc6979_ks(bits, x, z, extra):
    """RFC 6979 3.2 a-h, hedged per 3.6, as a stream of candidate k. Second implementation.

    int2octets(x) (2.3.3) is the 32-byte big-endian key unchanged, since rlen = qlen = 256 for
    P-256; z is bits2octets(h1) (2.3.4) computed by the caller. qlen = 256 and every accepted
    hash is at least 256 bits, so step h's bits2int (2.3.2) is 'the leftmost 32 bytes' with no
    shifting. k' goes AFTER bits2octets(h1), in both step d and step f (3.6, bullet 2) - the one
    placement question the hedged mode has, and the reason extra = b"" must still reproduce
    A.2.5 exactly."""
    alg = HASH[bits]
    hlen = alg().digest_size
    xb = x.to_bytes(32, "big")
    v, k, first = b"\x01" * hlen, b"\x00" * hlen, True
    for tag in (b"\x00", b"\x01"):  # steps d-g
        k = hmac.new(k, v + tag + xb + z + extra, alg).digest()
        v = hmac.new(k, v, alg).digest()
    while True:
        if not first:  # h.3: the previous candidate was rejected - reseed, never reduce
            k = hmac.new(k, v + b"\x00", alg).digest()
            v = hmac.new(k, v, alg).digest()
        first = False
        v = hmac.new(k, v, alg).digest()  # h.2, one pass: tlen = hlen >= qlen
        yield int.from_bytes(v[:32], "big")


def py_p256_sign(d, h, bits, extra=b""):
    """(r, s) for the deterministic (or hedged) nonce. Mirrors the C retry loop exactly."""
    n = P256["n"]
    z = int.from_bytes(h[:32], "big") % n  # bits2octets(h1) (2.3.4) == e of FIPS 186-5 6.4.1
    for i, k in enumerate(py_rfc6979_ks(bits, d, z.to_bytes(32, "big"), extra)):
        if i >= 64:
            die("P-256 sign: no usable k in 64 tries")
        if not 1 <= k < n:  # h.3: compared against q, never reduced mod q (that would bias k)
            continue
        rs = py_ecdsa_sign_with_k(d, z, k)
        if rs is not None:
            return rs
    return None


def sign_row(d, h, bits, extra=b"", ok=1):
    if not ok:
        return (f"{d:064x}", h.hex(), extra.hex(), "", 0)
    r, s = py_p256_sign(d, h, bits, extra)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    if py_p256_verify(py_p256_keygen(d)[0], h, sig) != P256_OK:
        die("P-256 sign: a generated signature does not verify")
    return (f"{d:064x}", h.hex(), extra.hex(), sig.hex(), 1)


def rfc6979_sign():
    """RFC 6979 A.2.5 with extra = NULL: the only official pin on the deterministic-k derivation.

    Both the k values and the resulting (r, s) are checked, so a wrong DRBG that happened to land
    on a valid signature would still fail here. The SHA-384/512 rows are also what exercise
    bits2int on a digest longer than qlen."""
    text = "\n".join(rfc_lines(fetch("rfc6979")))
    s = text[text.rindex("A.2.5.  ECDSA, 256 Bits") : text.rindex("A.2.6.")]
    kv = dict(re.findall(r"\n\s+(x|Ux|Uy) = ([0-9A-F]{64})\n", s))
    if {"x", "Ux", "Uy"} - kv.keys():
        die(f"RFC 6979 A.2.5: key fields {sorted(kv)}")
    x = int(kv["x"], 16)
    if py_p256_keygen(x)[0] != p256_enc((int(kv["Ux"], 16), int(kv["Uy"], 16))):
        die("RFC 6979 A.2.5: U is not x*G")
    pat = (r"With SHA-(\d+), message = \"(sample|test)\":\n\s+k = ([0-9A-F]{64})\n"
           r"\s+r = ([0-9A-F]{64})\n\s+s = ([0-9A-F]{64})\n")
    hits = re.findall(pat, s)
    if len(hits) != 10:
        die(f"RFC 6979 A.2.5: parsed {len(hits)} of 10 (hash, message) pairs")
    rows = []
    for bits, msg, k, r, s_ in hits:
        if int(bits) not in HASH:  # SHA-1 / SHA-224: neither is compiled, see SOURCES.md
            continue
        h = HASH[int(bits)](msg.encode()).digest()
        z = (int.from_bytes(h[:32], "big") % P256["n"]).to_bytes(32, "big")
        if next(py_rfc6979_ks(int(bits), x, z, b"")) != int(k, 16):
            die(f"RFC 6979 A.2.5 SHA-{bits}/{msg}: derived k does not match the RFC")
        row = sign_row(x, h, int(bits))
        if row[3] != (r + s_).lower():
            die(f"RFC 6979 A.2.5 SHA-{bits}/{msg}: r||s does not match the RFC")
        rows.append(row)
    if len(rows) != 6:
        die(f"RFC 6979 A.2.5: {len(rows)} usable rows, expected 6")
    return rows


def cavp_siggen():
    """186-3 ECDSAVS SigGen.txt (Msg, d, Qx, Qy, k, R, S) - the official floor under the
    generated sign rows, without any new API surface:
      1. brisk__p256_keygen(d) must reproduce the published (Qx, Qy)  -> p256_keygen.inc;
      2. brisk__p256_ecdsa_verify must accept the published (R, S)    -> p256_verify.inc;
      3. py_ecdsa_sign_with_k, the core every generated row below is built on, is validated
         against NIST here in Python before it is used - so the generated vectors rest on an
         official foundation rather than on the generator agreeing with itself.
    The k-driven recomputation is deliberately not re-run in C: it would need a public
    sign-with-given-k entry point that no caller wants."""
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_ecdsa")))
    sections = rsp_sections(z.read("SigGen.txt").decode("latin-1"))
    pat = (r"Msg = ([0-9a-f]+)\nd = ([0-9a-f]+)\nQx = ([0-9a-f]+)\nQy = ([0-9a-f]+)\n"
           r"k = ([0-9a-f]+)\nR = ([0-9a-f]+)\nS = ([0-9a-f]+)")
    keys, verify = [], []
    for bits in (256, 384, 512):
        hits = re.findall(pat, sections[f"[P-256,SHA-{bits}]"])
        if len(hits) != 15:
            die(f"CAVP SigGen P-256/SHA-{bits}: parsed {len(hits)} of 15 rows")
        for msg, d, qx, qy, k, r, s_ in hits:
            d = int(d, 16)
            pub, ok = py_p256_keygen(d)
            if not ok or pub != p256_enc((int(qx, 16), int(qy, 16))):
                die("CAVP SigGen: Q is not d*G")
            h = HASH[bits](bytes.fromhex(msg)).digest()
            e = int.from_bytes(h[:32], "big") % P256["n"]
            if py_ecdsa_sign_with_k(d, e, int(k, 16)) != (int(r, 16), int(s_, 16)):
                die(f"CAVP SigGen SHA-{bits}: (R, S) mismatch - the signing core is wrong")
            sig = int(r, 16).to_bytes(32, "big") + int(s_, 16).to_bytes(32, "big")
            # deep = 0: these 45 rows are a keygen/verify pin, not another offset-and-mutation
            # study. Every one of them is valid, so deep would add ~1400 verifications - four
            # times the whole existing valid-row mutation pass - for coverage the CAVP SigVer and
            # RFC 6979 A.2.5 rows already provide, and the p256 suite has a 900 s armv5 budget.
            row = verify_row(pub, h, sig, 0)
            if row[3] != P256_OK:
                die("CAVP SigGen: a published signature does not verify")
            keys.append((f"{d:064x}", pub.hex(), 1))
            verify.append(row)
    if len(verify) != 45:
        die(f"CAVP SigGen P-256: emitted {len(verify)} of 45 rows")
    return keys, verify


def differential_p256_sign():
    """Generated deterministic and hedged rows, plus the invalid-input half.

    Wycheproof publishes no ECDSA *signing* suite (signing has no attacker-controlled input) and
    RFC 6979 3.6 says a variant "ceases to be verifiable against the test vectors published in
    this document", so the hedged rows can only be generated - by the independent Python
    implementation above. Row count is kept small on purpose: every ok row costs the C suite four
    scalar multiplications (sign, then keygen + the two inside the self-verify), and the
    qemu-armv5 budget is 900 s for the whole p256 suite."""
    n = P256["n"]
    rnd = random.Random(20260922)
    rows = []

    # Deterministic, extra = empty. d = 1 and d = n-1 are the scalar-ladder extremes.
    for d in [1, n - 1, rnd.randrange(1, n), rnd.randrange(1, n), rnd.randrange(1, n)]:
        for bits in (256, 384, 512):
            rows.append(sign_row(d, HASH[bits](b"brisk-ssl mTLS").digest(), bits))

    # Hedged (RFC 6979 3.6): a fixed k' keeps the row deterministic, which is the only way this
    # can be a known-answer vector at all.
    for j in range(3):
        d = rnd.randrange(1, n)
        extra = bytes((j * 17 + i) & 0xFF for i in range(32))
        for bits in (256, 384, 512):
            rows.append(sign_row(d, HASH[bits](b"hedged").digest(), bits, extra))
    # Any k' length is legal; the bytes are simply appended.
    d = rnd.randrange(1, n)
    for ln in (0, 1, 16, 33, 64):
        rows.append(sign_row(d, hashlib.sha256(b"k-prime length").digest(), 256, bytes(range(ln))))

    # Digest edge cases: these drive the conditional subtraction inside bits2octets. A tail past
    # the leftmost 32 bytes is ignored by the truncation rule but still selects the DRBG hash.
    for lead in (bytes(32), b"\xff" * 32, n.to_bytes(32, "big"), (n - 1).to_bytes(32, "big")):
        for ln, bits in ((32, 256), (48, 384), (64, 512)):
            rows.append(sign_row(d, lead + bytes(ln - 32), bits))

    # Invalid d (FIPS 186-5 A.2.2 range) -> BRISK_E_ARG, sig untouched.
    h0 = hashlib.sha256(b"invalid").digest()
    for bad in (0, n, n + 1, 2 ** 256 - 1):
        rows.append(sign_row(bad, h0, 256, ok=0))
    # Invalid hash_len: 32, 48 and 64 are the only accepted widths, because hash_len also selects
    # the RFC 6979 HMAC hash (3.2 b) and must be the same H that produced the digest.
    for ln in (31, 33, 47, 49, 63, 65):
        rows.append(sign_row(d, bytes((i * 7 + 1) & 0xFF for i in range(ln)), 256, ok=0))
    return rows


def differential_p256():
    """Seeded agreement, small-k scalar multiplication and hand-built bad encodings."""
    p, n = P256["p"], P256["n"]
    keys, ecdh, verify = [], [], []
    rnd = random.Random(20260920)

    # (c) k*G for the incomplete-addition edge cases, then ~32 seeded agreeing key pairs.
    for k in [1, 2, 3, n - 2, n - 1] + [rnd.randrange(1, n) for _ in range(27)]:
        pub, ok = py_p256_keygen(k)
        keys.append((f"{k:064x}", pub.hex(), ok))
    if keys[0][1] != p256_enc(P256_G).hex():
        die("differential P-256: 1*G is not G")
    for _ in range(32):
        a, b = rnd.randrange(1, n), rnd.randrange(1, n)
        qa, qb = py_p256_keygen(a)[0], py_p256_keygen(b)[0]
        if py_p256_ecdh(a, qb) != py_p256_ecdh(b, qa):
            die("differential P-256: ECDH disagreement")
        ecdh += [ecdh_row(a, qb), ecdh_row(b, qa)]

    # RFC 9846 7.4.2: Z is the x-coordinate as a fixed-width octet string, "leading zeros found in
    # this octet string MUST NOT be truncated". No CAVP P-256 row has one, so search for the
    # smallest k with a leading zero byte in x(k*G) and pin it here.
    acc, found = P256_G, 0
    for k in range(2, 4000):
        acc = py_p256_add(acc, P256_G)
        if acc[0] < 1 << 248:
            row = ecdh_row(k, p256_enc(P256_G), 1)
            if not row[2].startswith("00") or len(row[2]) != 64:
                die("differential P-256: leading-zero Z row is malformed")
            ecdh.append(row)
            keys.append((f"{k:064x}", p256_enc(acc).hex(), 1))
            found = 1
            break
    if not found:
        die("differential P-256: no k with a leading zero byte in x(k*G)")

    # (d) negative point encodings. Every one must be rejected before any scalar multiplication.
    d0, gx, gy = rnd.randrange(1, n), P256["gx"], P256["gy"]
    bad = [b"\x04" + p.to_bytes(32, "big") + gy.to_bytes(32, "big"),      # x == p
           b"\x04" + gx.to_bytes(32, "big") + p.to_bytes(32, "big"),      # y == p
           b"\x04" + bytes(64),                                           # infinity as 0x04||0^64
           b"\x04" + (2 ** 256 - 1).to_bytes(32, "big") + gy.to_bytes(32, "big"),
           b"\x04" + gx.to_bytes(32, "big") + (gy ^ 1).to_bytes(32, "big")]  # off the curve
    for pre in (0x00, 0x02, 0x03, 0x05, 0x06, 0x07):  # compressed/hybrid are rejected, not decoded
        bad.append(bytes([pre]) + gx.to_bytes(32, "big") + gy.to_bytes(32, "big"))
    for peer in bad:
        row = ecdh_row(d0, peer, 1)
        if row[3]:
            die(f"differential P-256: bad encoding {peer[:1].hex()} was accepted")
        ecdh.append(row)
    # A point on the twist: y^2 = x^3 - 3x + b has no solution, so pick x with a non-residue.
    for x in range(2, 200):
        rhs = (x * x * x - 3 * x + P256["b"]) % p
        if pow(rhs, (p - 1) // 2, p) != 1:
            ecdh.append(ecdh_row(d0, b"\x04" + x.to_bytes(32, "big") + bytes(32), 1))
            break
    else:
        die("differential P-256: no twist x found")

    # Out-of-range private keys (FIPS 186-5 A.2.2 rejection): pub untouched, BRISK_E_ARG.
    for d in (0, n, n + 1, 2 ** 256 - 1):
        pub, ok = py_p256_keygen(d)
        if ok:
            die("differential P-256: out-of-range d accepted")
        keys.append((f"{d:064x}", "", 0))
        ecdh.append(ecdh_row(d, p256_enc(P256_G), 1))

    # Verify: out-of-range r/s must be BRISK_E_AUTH. FIPS 186-5 6.4.2 step 1 calls this INVALID,
    # not an error - a peer can put r = 0 on the wire as easily as a wrong signature - so it has to
    # land on the same code as any other failed signature, or the TLS layer emits the wrong alert
    # and the pair of codes becomes an oracle. BRISK_E_ARG here would be a bug, not a nuance.
    pubv = py_p256_keygen(rnd.randrange(1, n))[0]
    h0 = hashlib.sha256(b"brisk").digest()
    for r, s in ((0, 1), (1, 0), (n, 1), (1, n), (2 ** 256 - 1, 1), (1, 2 ** 256 - 1), (0, 0)):
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        row = verify_row(pubv, h0, sig, 1)
        if row[3] != P256_AUTH:
            die("differential P-256: out-of-range r/s not reported as a failed signature")
        verify.append(row)
    return keys, ecdh, verify


def p256_scalar_vectors():
    """Differential rows for the in-house mod-n core, against Python's own arithmetic.

    op: 0 = reduce(a), 1 = add(a,b), 2 = mul(a,b), 3 = inv(a). Operands are full 32-byte values,
    so the >= n cases exercise the reduction the C entry points do on their inputs."""
    n = P256["n"]
    R = 1 << 256
    edge = [0, 1, 2, n - 2, n - 1, n, n + 1, R - 1, R % n, (R % n) - 1]
    rnd = random.Random(20260921)
    rows = []

    def row(op, a, b, r):
        if not 0 <= r < n:
            die("P-256 scalar: reference result out of range")
        return (op, f"{a:064x}", f"{b:064x}", f"{r:064x}")

    for a in edge:
        rows.append(row(0, a, 0, a % n))
        rows.append(row(3, a, 0, 0 if a % n == 0 else pow(a % n, -1, n)))
        for b in edge:
            rows.append(row(1, a, b, (a + b) % n))
            rows.append(row(2, a, b, a * b % n))
    for _ in range(200):
        a, b = rnd.randrange(0, R), rnd.randrange(0, R)
        rows.append(row(1, a, b, (a + b) % n))
        rows.append(row(2, a, b, a * b % n))
    for _ in range(64):
        a = rnd.randrange(1, R)
        rows.append(row(3, a, 0, 0 if a % n == 0 else pow(a % n, -1, n)))
        rows.append(row(0, a, 0, a % n))
    if len(rows) != 20 + 200 + 400 + 128:
        die(f"P-256 scalar: {len(rows)} rows")
    return rows


# ---------------------------------------------------------------- P-384 ECDSA verify (M1d)
# Verify only: no keygen, no ECDH, no sign, ever (docs/ARCHITECTURE.md line 76 locks "no P-384
# ECDHE"). The module exists because Let's Encrypt Generation Y issues from P-384 intermediates,
# so M2 chain building must be able to check that signature.
P384_OK, P384_AUTH, P384_ARG = 0, 1, 2


def p384_enc(A):
    """RFC 9846 4.3.8.2: 0x04 || X || Y, 48 octets each, left-padded with zeros."""
    return b"\x04" + A[0].to_bytes(48, "big") + A[1].to_bytes(48, "big")


def py_p384_verify(pub, h, sig):
    """FIPS 186-5 6.4.2. Returns P384_OK / P384_AUTH / P384_ARG.

    The check order mirrors brisk__p384_ecdsa_verify exactly, because the expect code a row
    carries depends on which check fires first: hash_len, then r/s, then the public point."""
    n = P384["n"]
    if len(pub) != 97 or len(sig) != 96 or len(h) < 48:
        return P384_ARG
    r, s = int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big")
    if not (1 <= r < n and 1 <= s < n):
        # FIPS 186-5 6.4.2 step 1 says INVALID, not an error: a signature the peer could have
        # written, so BRISK_E_AUTH -> decrypt_error, not BRISK_E_ARG -> illegal_parameter.
        return P384_AUTH
    x, y = int.from_bytes(pub[1:49], "big"), int.from_bytes(pub[49:], "big")
    if pub[0] != 4 or not py_ec_on_curve(P384, x, y):
        return P384_ARG  # malformed key material -> bad_certificate, a different condition
    e = int.from_bytes(h[:48], "big") % n  # leftmost min(bitlen n, bitlen H) bits = first 48 bytes
    w = pow(s, -1, n)
    R = py_ec_add(P384, py_ec_mul(P384, e * w % n, P384_G), py_ec_mul(P384, r * w % n, (x, y)))
    if R is None:
        return P384_AUTH
    return P384_OK if R[0] % n == r else P384_AUTH


P384_G = None  # set in main() once the parameters are parsed


# verify row = (pub97, hash, sig96, expect, deep)
def verify_row_384(pub, h, sig, deep=0):
    return (pub.hex(), h.hex(), sig.hex(), py_p384_verify(pub, h, sig), deep)


def cavp_p384_sigver():
    """186-3 ECDSAVS SigVer.rsp [P-384,SHA-384] and [P-384,SHA-512]: 15 rows each, 3 P / 12 F.

    [P-384,SHA-1/224/256] are skipped for the same behavioural reason the P-256 loop skips its
    short-hash sections: hash_len < 48 is BRISK_E_ARG by design (R8), not a truncated verify."""
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_ecdsa")))
    sections = rsp_sections(z.read("SigVer.rsp").decode("latin-1"))
    pat = (r"Msg = ([0-9a-f]+)\nQx = ([0-9a-f]+)\nQy = ([0-9a-f]+)\nR = ([0-9a-f]+)\n"
           r"S = ([0-9a-f]+)\nResult = ([PF])")
    rows, npass = [], 0
    for bits, hfn in ((384, hashlib.sha384), (512, hashlib.sha512)):
        hits = re.findall(pat, sections[f"[P-384,SHA-{bits}]"])
        if len(hits) != 15:
            die(f"CAVP SigVer P-384/SHA-{bits}: parsed {len(hits)} of 15 cases")
        for msg, qx, qy, r, s, res in hits:
            if len(qx) != 96 or len(qy) != 96 or len(r) != 96 or len(s) != 96:
                die(f"CAVP SigVer P-384/SHA-{bits}: a field is not 48 bytes")
            pub = b"\x04" + bytes.fromhex(qx) + bytes.fromhex(qy)
            sig = bytes.fromhex(r) + bytes.fromhex(s)
            row = verify_row_384(pub, hfn(bytes.fromhex(msg)).digest(), sig, 1)
            # A CAVP "F" row is a wrong signature, not malformed key material: every Q here is on
            # the curve and every R/S is in range, so the verdict must be OK or AUTH, never ARG.
            if row[3] == P384_ARG:
                die(f"CAVP SigVer P-384/SHA-{bits}: unexpected BRISK_E_ARG row")
            if (row[3] == P384_OK) != (res == "P"):
                die(f"CAVP SigVer P-384/SHA-{bits}: verdict mismatch")
            npass += res == "P"
            rows.append(row)
    if (len(rows), npass) != (30, 6):
        die(f"CAVP SigVer P-384: {len(rows)} rows, {npass} P, expected 30 / 6")
    return rows


def cavp_p384_pkv():
    """186-3 ECDSAVS PKV.rsp [P-384]: 12 rows, 4 valid / 8 invalid.

    Driven through verify with a fixed in-range (r, s) that cannot possibly verify, so a valid
    point lands on BRISK_E_AUTH and an off-curve one on BRISK_E_ARG - which is exactly the split
    R7 requires. 4 of the 12 carry a 385-bit coordinate that the 97-byte wire encoding of
    RFC 9846 4.3.8.2 cannot express at all; truncating them would turn them into different
    points, so they are skipped and the in-range half of the check is pinned by the generated
    x == p / y == p / coord == 2^384-1 rows in differential_p384()."""
    z = zipfile.ZipFile(io.BytesIO(fetch("cavp_ecdsa")))
    body = rsp_sections(z.read("PKV.rsp").decode("latin-1"))["[P-384]"]
    hits = re.findall(r"Qx = ([0-9a-f]+)\nQy = ([0-9a-f]+)\nResult = ([PF])", body)
    if len(hits) != 12:
        die(f"CAVP PKV P-384: parsed {len(hits)} of 12 cases")
    h0 = hashlib.sha384(b"brisk p384 pkv").digest()
    sig = (7).to_bytes(48, "big") + (11).to_bytes(48, "big")  # in range, cannot verify
    rows, used, oversize = [], 0, 0
    for qx, qy, res in hits:
        x, y = int(qx, 16), int(qy, 16)
        if x >= 2 ** 384 or y >= 2 ** 384:
            oversize += 1
            continue
        row = verify_row_384(p384_enc((x, y)), h0, sig, 1)
        want = P384_AUTH if res == "P" else P384_ARG
        if row[3] != want:
            die(f"CAVP PKV P-384: verdict mismatch for {qx}")
        used += 1
        rows.append(row)
    if (used, oversize) != (8, 4):
        die(f"CAVP PKV P-384: {used} usable / {oversize} oversize rows, expected 8 / 4")
    return rows


def wycheproof_p384_ecdsa(src, hfn, shaname):
    """ecdsa_secp384r1_sha{384,512}_p1363: raw 96-byte r||s, the shape this module takes."""
    doc = json.loads(fetch(src))
    rows, valid, wrong_len, flags = [], 0, 0, {}
    for g in doc["testGroups"]:
        if g["type"] != "EcdsaP1363Verify" or g["sha"] != shaname:
            die(f"Wycheproof {src}: unexpected group {g['type']}/{g['sha']}")
        pub = bytes.fromhex(g["publicKey"]["uncompressed"])
        for t in g["tests"]:
            sig = bytes.fromhex(t["sig"])
            # brisk__p384_ecdsa_verify takes a fixed uint8_t[96] and uint8_t[97], so a
            # wrong-width P1363 signature or point cannot be handed to it at all: the width is
            # settled by the caller that unwraps the DER ECDSA-Sig-Value. What those rows are
            # really about - r or s outside [1, n-1] - is pinned at the right width by the
            # generated edge rows in differential_p384().
            if len(sig) != 96 or len(pub) != 97:
                wrong_len += 1
                continue
            h = hfn(bytes.fromhex(t["msg"])).digest()
            row = verify_row_384(pub, h, sig, int(t["result"] != "valid"))
            if (row[3] == P384_OK) != (t["result"] == "valid"):
                die(f"Wycheproof {src} tcId {t['tcId']}: verdict mismatch")
            for fl in t.get("flags", []):
                flags[fl] = flags.get(fl, 0) + 1
            valid += t["result"] == "valid"
            rows.append(row)
    return rows, valid, wrong_len, flags


def rfc6979_verify_384():
    """RFC 6979 A.2.6 (P-384). The SHA-384 and SHA-512 rows for "sample" and "test" are the four
    official RFC-appendix verify vectors; SHA-1/224/256 are below the 48-byte minimum.

    PARSER NOTE: unlike A.2.5, every A.2.6 hex value wraps across two indented lines, so the
    fixed-width [0-9A-F]{64} regexes of the P-256 parser match nothing here - silently, which is
    why each count below is guarded."""
    text = "\n".join(rfc_lines(fetch("rfc6979")))
    s = text[text.rindex("A.2.6.  ECDSA, 384 Bits") : text.rindex("A.2.7.")]
    kv = {}
    for key in ("x", "Ux", "Uy"):
        m = re.search(r"\n\s+" + key + r" = ((?:[0-9A-F]+\s*)+)", s)
        if not m:
            die(f"RFC 6979 A.2.6: {key} not found")
        kv[key] = "".join(m.group(1).split())
        if len(kv[key]) != 96:
            die(f"RFC 6979 A.2.6: {key} is {len(kv[key])} hex chars, expected 96")
    pub = p384_enc((int(kv["Ux"], 16), int(kv["Uy"], 16)))
    if p384_enc(py_ec_mul(P384, int(kv["x"], 16), P384_G)) != pub:
        die("RFC 6979 A.2.6: U is not x*G")
    algs = {"384": hashlib.sha384, "512": hashlib.sha512}
    pat = (r'With SHA-(\d+), message = "(sample|test)":\n'
           r"\s+k = (?:[0-9A-F]+\s*)+r = ((?:[0-9A-F]+\s*)+)s = ((?:[0-9A-F]+\s*)+)")
    hits = re.findall(pat, s)
    if len(hits) != 10:
        die(f"RFC 6979 A.2.6: parsed {len(hits)} of 10 (hash, message) pairs")
    rows = []
    for bits, msg, r, s_ in hits:
        if bits not in algs:
            continue
        r, s_ = "".join(r.split()), "".join(s_.split())
        if len(r) != 96 or len(s_) != 96:
            die(f"RFC 6979 A.2.6 SHA-{bits}/{msg}: r or s is not 48 bytes")
        h = algs[bits](msg.encode()).digest()
        row = verify_row_384(pub, h, bytes.fromhex(r) + bytes.fromhex(s_), 1)
        if row[3] != P384_OK:
            die(f"RFC 6979 A.2.6 SHA-{bits}/{msg}: signature does not verify")
        rows.append(row)
    if len(rows) != 4:
        die(f"RFC 6979 A.2.6: {len(rows)} usable rows, expected 4")
    return rows


def differential_p384():
    """Seeded edge cases: the r/s range boundary, bad point encodings, and the hash_len rule.

    These are what cover the Wycheproof classes the 96/97-byte width filter drops, and what pins
    n behaviourally (no vector names n directly)."""
    p, n = P384["p"], P384["n"]
    gx, gy = P384["gx"], P384["gy"]
    rnd = random.Random(20260921)
    rows = []
    d = rnd.randrange(1, n)
    pub = p384_enc(py_ec_mul(P384, d, P384_G))
    h0 = hashlib.sha384(b"brisk").digest()

    # A real signature, so the negative rows below sit next to something that does verify and the
    # "different key" row cannot pass by accident.
    k = rnd.randrange(1, n)
    R = py_ec_mul(P384, k, P384_G)
    r = R[0] % n
    e = int.from_bytes(h0[:48], "big") % n
    s = pow(k, -1, n) * (e + r * d) % n
    if not (1 <= r < n and 1 <= s < n):
        die("differential P-384: degenerate signature, change the seed")
    good = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    if py_p384_verify(pub, h0, good) != P384_OK:
        die("differential P-384: the generated signature does not verify")
    rows.append(verify_row_384(pub, h0, good, 1))
    # The same signature under a different key: AUTH, never OK and never ARG.
    other = p384_enc(py_ec_mul(P384, rnd.randrange(1, n), P384_G))
    rows.append(verify_row_384(other, h0, good, 1))

    # FIPS 186-5 6.4.2 step 1: r or s outside [1, n-1] is INVALID -> BRISK_E_AUTH, never
    # BRISK_E_ARG. Returning ARG would emit illegal_parameter and hand the peer an oracle
    # separating "malformed r/s" from "wrong signature". These rows also pin n.
    for rr, ss in ((0, s), (r, 0), (n, s), (r, n), (n + 1, s), (r, n + 1),
                   (2 ** 384 - 1, s), (r, 2 ** 384 - 1), (0, 0), (n - 1, n - 1)):
        row = verify_row_384(pub, h0, rr.to_bytes(48, "big") + ss.to_bytes(48, "big"), 1)
        if row[3] != P384_AUTH:
            die("differential P-384: an out-of-range r/s is not a failed signature")
        rows.append(row)

    # Bad point encodings. Every one is BRISK_E_ARG, decided before any scalar multiplication.
    bad = [b"\x04" + p.to_bytes(48, "big") + gy.to_bytes(48, "big"),     # x == p
           b"\x04" + gx.to_bytes(48, "big") + p.to_bytes(48, "big"),     # y == p
           b"\x04" + bytes(96),                                          # infinity has no encoding
           b"\x04" + b"\xff" * 96,                                       # both coords 2^384-1
           b"\x04" + (2 ** 384 - 1).to_bytes(48, "big") + gy.to_bytes(48, "big"),
           b"\x04" + gx.to_bytes(48, "big") + (gy ^ 1).to_bytes(48, "big")]  # off the curve
    for pre in (0x00, 0x02, 0x03, 0x05, 0x06, 0x07):  # compressed/hybrid rejected, not decoded
        bad.append(bytes([pre]) + gx.to_bytes(48, "big") + gy.to_bytes(48, "big"))
    # A point on the twist: y^2 = x^3 - 3x + b has no solution for this x.
    for xt in range(2, 400):
        if pow((xt ** 3 - 3 * xt + P384["b"]) % p, (p - 1) // 2, p) != 1:
            bad.append(b"\x04" + xt.to_bytes(48, "big") + bytes(48))
            break
    else:
        die("differential P-384: no twist x found")
    for enc in bad:
        row = verify_row_384(enc, h0, good, 1)
        if row[3] != P384_ARG:
            die(f"differential P-384: bad encoding {enc[:1].hex()} was accepted")
        rows.append(row)

    # hash_len < 48 is a caller bug -> BRISK_E_ARG, not a truncated verify (R8). The C test also
    # checks hash_len 32, the SHA-256-against-a-P-384-key case R8 names.
    for hlen in (0, 47):
        row = verify_row_384(pub, h0[:hlen], good, 1)
        if row[3] != P384_ARG:
            die("differential P-384: a short hash is not BRISK_E_ARG")
        rows.append(row)

    # x_R with a leading zero byte: the 48-byte fixed-width comparison against r must not depend
    # on where the value starts. Searched, because no official vector happens to have one.
    for kk in range(1, 6000):
        Rk = py_ec_mul(P384, kk, P384_G)
        if Rk[0] % n < 1 << 376:
            dk = rnd.randrange(1, n)
            pk = p384_enc(py_ec_mul(P384, dk, P384_G))
            rk = Rk[0] % n
            ek = int.from_bytes(h0[:48], "big") % n
            sk = pow(kk, -1, n) * (ek + rk * dk) % n
            row = verify_row_384(pk, h0, rk.to_bytes(48, "big") + sk.to_bytes(48, "big"), 1)
            if row[3] != P384_OK or not row[2].startswith("00"):
                die("differential P-384: leading-zero x_R row is malformed")
            rows.append(row)
            break
    else:
        die("differential P-384: no k with a leading zero byte in x(k*G) mod n")
    return rows


# ---------------------------------------------------------------- RSA: bignum + RSASSA verify
# Verdicts, mirroring the C entry points: 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG.
RSA_OK, RSA_AUTH, RSA_ARG = 0, 1, 2
RSA_MIN_BITS, RSA_MAX_BITS = 2048, 4096
DIGESTINFO = {}  # 256/384/512 -> the DER prefix, parsed out of RFC 8017 9.2 note 1


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def rfc8017_digestinfo():
    """The three DER DigestInfo prefixes of RFC 8017 9.2 note 1, parsed out of the RFC text.

    PKCS#1 v2.2 has no test-vector appendix (unlike RFC 8439 / 7748 / 6979), so this is the one
    thing the RFC itself can pin here - the same trick check_p256_source_constants() uses for the
    P-256 parameters, and the only way to get this table without hand-typing a vector."""
    text = "\n".join(rfc_lines(fetch("rfc8017")))
    out = {}
    for bits in (256, 384, 512):
        m = re.search(r"SHA-%d:\s+\(0x\)((?:[0-9a-f]{2}[\s]*)+)\|\|" % bits, text)
        if not m:
            die("RFC 8017 9.2: DigestInfo prefix for SHA-%d not found" % bits)
        pre = hexbytes(m.group(1))
        # 30 <len> 30 0d 06 09 <oid> 05 00 04 <hlen>: DER SEQUENCE, AlgorithmIdentifier with the
        # explicit NULL parameters note 1 requires, then the OCTET STRING header for H.
        if len(pre) != 19 or pre[0] != 0x30 or pre[-4:] != bytes([0x05, 0x00, 0x04, bits // 8]):
            die("RFC 8017 9.2: SHA-%d prefix parsed as %s" % (bits, pre.hex()))
        out[bits] = pre
    if len({v[:15] for v in out.values()}) != 3:
        die("RFC 8017 9.2: two DigestInfo prefixes collide")
    return out


def check_rsa_source_constants():
    """The three DigestInfo prefixes in src/crypto/rsa.c must equal RFC 8017 9.2 note 1.

    Pinned here rather than in a .inc, because the library does not export the table and a
    hand-typed constant is exactly what this project refuses to ship. Same precedent as
    check_p256_source_constants()."""
    src = (ROOT / "src" / "crypto" / "rsa.c").read_text()
    for bits, want in sorted(DIGESTINFO.items()):
        m = re.search(r"RSA_DI_SHA%d\[RSA_DI_LEN\] = \{([^}]*)\}" % bits, src)
        if not m:
            die("src/crypto/rsa.c: RSA_DI_SHA%d not found" % bits)
        got = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
        if got != want:
            die("src/crypto/rsa.c: RSA_DI_SHA%d is %s, RFC 8017 9.2 says %s"
                % (bits, got.hex(), want.hex()))


def py_rsa_key_verdict(n, e, max_bits=RSA_MAX_BITS):
    """RFC 8017 3.1 (n odd, 3 <= e < n) plus the project's 2048..BRISK_RSA_MAX_BITS policy.

    The e < 2^256 cap mirrors rsa_vp1's `e_len > 32`: e < n alone lets an attacker-chosen exponent
    in a chain certificate cost ~6100 Montgomery multiplications per verification. 2^256 is the
    ceiling NIST SP 800-89 5.3.3, FIPS 186-5 B.3 and CA/B Forum BR 6.1.6 all agree on, so it
    refuses no compliant certificate."""
    bits = n.bit_length()
    if bits < RSA_MIN_BITS or bits > max_bits or n % 2 == 0:
        return RSA_ARG
    if e < 3 or e >= n or e % 2 == 0 or e.bit_length() > 256:
        return RSA_ARG
    return RSA_OK


def py_rsa_vp1(n, e, sig):
    """RFC 8017 5.2.2. None means 'signature representative out of range' or the wrong width."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:  # 8.2.2 step 1 / 8.1.2 step 1
        return None
    s = int.from_bytes(sig, "big")
    if s >= n:  # 5.2.2 step 1
        return None
    return pow(s, e, n), k


def py_pkcs1_verify(n, e, bits, h, sig, max_bits=RSA_MAX_BITS):
    """RFC 8017 8.2.2 with the EMSA-PKCS1-v1_5 encoding of 9.2, strict DER (note 2 NOT adopted)."""
    if py_rsa_key_verdict(n, e, max_bits) != RSA_OK or bits not in DIGESTINFO:
        return RSA_ARG
    if len(h) != bits // 8:
        return RSA_ARG
    r = py_rsa_vp1(n, e, sig)
    if r is None:
        return RSA_AUTH
    m, k = r
    t = DIGESTINFO[bits] + h
    if k < len(t) + 11:  # 9.2 step 3: emLen < tLen + 11
        return RSA_AUTH
    want = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return RSA_OK if m.to_bytes(k, "big") == want else RSA_AUTH


def py_mgf1(bits, seed, mask_len):
    """RFC 8017 B.2.1."""
    out = b""
    c = 0
    while len(out) < mask_len:
        out += HASH[bits](seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:mask_len]


def py_pss_verify(n, e, bits, slen, mh, sig, max_bits=RSA_MAX_BITS):
    """RFC 8017 8.1.2 + EMSA-PSS-VERIFY 9.1.2. One hash for both the digest and MGF1."""
    if py_rsa_key_verdict(n, e, max_bits) != RSA_OK or bits not in HASH:
        return RSA_ARG
    hlen = bits // 8
    if len(mh) != hlen:
        return RSA_ARG
    r = py_rsa_vp1(n, e, sig)
    if r is None:
        return RSA_AUTH
    m, _ = r
    embits = n.bit_length() - 1  # 8.1.2 step 2c: emLen = ceil((modBits - 1) / 8)
    emlen = (embits + 7) // 8
    if m >= 1 << (8 * emlen):  # I2OSP would fail -> "invalid signature"
        return RSA_AUTH
    em = m.to_bytes(emlen, "big")
    if emlen < hlen + slen + 2:  # 9.1.2 step 3
        return RSA_AUTH
    if em[-1] != 0xBC:  # step 4
        return RSA_AUTH
    masked, hh = em[: emlen - hlen - 1], em[emlen - hlen - 1: -1]  # step 5
    top = 8 * emlen - embits  # step 6: the leftmost 8*emLen - emBits bits must be zero
    if top and masked[0] >> (8 - top):
        return RSA_AUTH
    db = bytes(a ^ b for a, b in zip(masked, py_mgf1(bits, hh, len(masked))))  # steps 7-8
    db = bytes([db[0] & (0xFF >> top)]) + db[1:]  # step 9
    if any(db[: emlen - hlen - slen - 2]) or db[emlen - hlen - slen - 2] != 0x01:  # step 10-11
        return RSA_AUTH
    salt = db[len(db) - slen:] if slen else b""  # step 11
    hp = HASH[bits](b"\x00" * 8 + mh + salt).digest()  # steps 12-13
    return RSA_OK if hp == hh else RSA_AUTH  # step 14


# rsa row = (key index, hash bits, salt_len (-1 = PKCS#1 v1.5), digest, sig, expect, deep).
# Keys are pooled: a Wycheproof group or a CAVP [mod = N] section shares one 4096-bit modulus
# across hundreds of rows, and inlining it in every row would be a megabyte of duplicate hex.
RSA_KEYS = []
_rsa_key_idx = {}


def rsa_key(n_hex, e_hex):
    key = (n_hex, e_hex)
    if key not in _rsa_key_idx:
        _rsa_key_idx[key] = len(RSA_KEYS)
        RSA_KEYS.append(key)
    return _rsa_key_idx[key]


def pkcs1_row(n_hex, e_hex, bits, h, sig, deep=0):
    n, e = int(n_hex, 16), int(e_hex, 16)
    return (rsa_key(n_hex, e_hex), bits, -1, h.hex(), sig.hex(),
            py_pkcs1_verify(n, e, bits, h, sig), deep)


def pss_row(n_hex, e_hex, bits, slen, h, sig, deep=0):
    n, e = int(n_hex, 16), int(e_hex, 16)
    return (rsa_key(n_hex, e_hex), bits, slen, h.hex(), sig.hex(),
            py_pss_verify(n, e, bits, slen, h, sig), deep)


def rsp_mod_sections(text):
    """Split a CAVP RSA .rsp into {2048: body, ...} on the [mod = N] headers."""
    out, cur = {}, None
    for ln in text.replace("\r", "").split("\n"):
        m = re.fullmatch(r"\[mod = (\d+)\]", ln.strip())
        if m:
            cur = int(m.group(1))
            out.setdefault(cur, [])
        elif cur is not None:
            out[cur].append(ln)
    return {k: "\n".join(v) for k, v in out.items()}


# Every CAVS SigVer block, PKCS#1 v1.5 and PSS alike: the v1.5 files carry a vestigial
# "SaltVal = 00" line from the shared template, so it is optional here rather than a second regex.
CAVP_RSA_ROW = (r"SHAAlg = SHA(\d+)\ne = ([0-9a-fA-F]+)\nd = [0-9a-fA-F]+\n"
                r"Msg = ([0-9a-f]*)\nS = ([0-9a-f]+)\n(?:SaltVal = ([0-9a-f]*)\n)?"
                r"Result = ([PF])")


def cavp_pss_saltlens(text):
    """(mod, sha) -> sLen, from the '# Salt len' / '# Combinations selected' header comment.

    186-2 pins one salt length (10) for the whole file; 186-3 varies it per (mod, hash) and
    writes 'SaltVal = 00' when sLen is 0, so the SaltVal line cannot give the length."""
    head = "\n".join(ln for ln in text.replace("\r", "").split("\n") if ln.startswith("#"))
    m = re.search(r"Salt len:\s*(\d+)\s*$", head, re.M)
    if m:
        return {}, int(m.group(1))
    out = {}
    # Non-greedy up to the next "Mod Size": the per-hash groups are ';'-separated and the
    # sections are ';;'-separated, so a greedy scan swallows the whole header into mod 1024.
    for mod, body in re.findall(r"Mod Size (\d+) with (.*?)(?=Mod Size \d+ with|$)", head, re.S):
        for sha, sl in re.findall(r"SHA-(\d+)\(Salt len:\s*(\d+)\)", body):
            out[(int(mod), int(sha))] = int(sl)
    if not out:
        die("CAVP PSS: no salt lengths in the file header")
    return out, None


def split_key_blocks(section):
    """[(n hex, body)] for a CAVP [mod = N] section: one entry per "n = " line.

    A section holds several independent key blocks. Taking the first n for the whole section
    silently checks most rows against the wrong modulus."""
    parts = re.split(r"\nn = ([0-9a-f]+)\n", "\n" + section.strip("\n") + "\n")
    return [(parts[i], parts[i + 1]) for i in range(1, len(parts) - 1, 2)]


def cavp_rsa(src, fname, pss):
    """CAVP SigVer rows for mod >= 2048 with SHA-256/384/512 - the only sizes and digests this
    library compiles. The 186-2 archive is the ONLY official source with 4096-bit rows."""
    text = zipfile.ZipFile(io.BytesIO(fetch(src))).read(fname).decode("latin-1")
    saltmap, saltfix = cavp_pss_saltlens(text) if pss else ({}, None)
    rows, npass, nfail = [], 0, 0
    for mod, section in sorted(rsp_mod_sections(text).items()):
        for n_hex, body in split_key_blocks(section):
            if int(n_hex, 16).bit_length() != mod:
                die("%s [mod = %d]: n is %d bits" % (fname, mod, int(n_hex, 16).bit_length()))
            hits = re.findall(CAVP_RSA_ROW, body)
            if not hits:
                die("%s [mod = %d]: no rows parsed" % (fname, mod))
            for sha, e_hex, msg, sig, salt, res in hits:
                bits = int(sha)
                # SHA-1 / SHA-224 have no brisk_hash_alg value; 1024/1536 are below the floor.
                if bits not in HASH or mod < RSA_MIN_BITS or mod > RSA_MAX_BITS:
                    continue
                slen = -1
                if pss:
                    slen = saltfix if saltfix is not None else saltmap.get((mod, bits), -1)
                    if slen < 0:
                        die("%s: no salt length for mod %d SHA-%d" % (fname, mod, bits))
                    if salt and len(salt) // 2 not in (slen, 1):
                        die("%s: SaltVal is %d bytes, header says %d"
                            % (fname, len(salt) // 2, slen))
                # A few 186-3 SigVer15 rows print Msg or S with an odd number of hex digits:
                # CAVS dropped the leading zero nibble. One of them is a P row whose S is
                # 511 digits - exactly the I2OSP leading-zero case of RFC 8017 4.1 - so the
                # reading is "pad on the left", and that keeps S at the k octets 8.2.2 step 1
                # requires. The P/F cross-check below is what proves the reading right.
                msg = msg if len(msg) % 2 == 0 else "0" + msg
                sig = sig if len(sig) % 2 == 0 else "0" + sig
                h = HASH[bits](bytes.fromhex(msg)).digest()
                e_hex = e_hex if len(e_hex) % 2 == 0 else "0" + e_hex
                sig = bytes.fromhex(sig)
                row = (pss_row(n_hex, e_hex, bits, slen, h, sig, 1) if pss
                       else pkcs1_row(n_hex, e_hex, bits, h, sig, 1))
                # A CAVP F row is a wrong signature or a corrupted EM, never bad key material.
                if (row[5] == RSA_OK) != (res == "P"):
                    die("%s mod %d SHA-%d: verdict mismatch (CAVP says %s)"
                        % (fname, mod, bits, res))
                npass += res == "P"
                nfail += res == "F"
                rows.append(row)
    return rows, npass, nfail


def wycheproof_rsa(name, pss, deep_max_bits):
    """One Wycheproof rsassa_{pkcs1,pss}_verify suite, every in-scope row.

    The expectation is recomputed from the value, never taken from the flag: the single
    'acceptable' MissingNull row is INVALID here, because RFC 8017 9.2 note 2's BER leniency is
    not adopted (the decision is recorded in tests/kat/SOURCES.md)."""
    doc = json.loads(fetch(name))
    rows, counts, flags, skipped = [], {"valid": 0, "invalid": 0, "acceptable": 0}, {}, 0
    for g in doc["testGroups"]:
        want = "RsassaPssVerify" if pss else "RsassaPkcs1Verify"
        if g["type"] != want:
            die("%s: unexpected group type %s" % (name, g["type"]))
        m = re.fullmatch(r"SHA-(\d+)", g["sha"])
        bits = int(m.group(1)) if m else 0
        # A separate MGF hash is refused by design (one `alg` covers both, RFC 9846 4.3.3), and
        # SHA-1 / SHA-224 / SHA-512-t have no brisk_hash_alg value.
        if bits not in HASH or (pss and (g.get("mgf") != "MGF1" or g.get("mgfSha") != g["sha"])):
            skipped += len(g["tests"])
            continue
        n_hex = g["publicKey"]["modulus"]
        e_hex = g["publicKey"]["publicExponent"]
        n_hex = n_hex if len(n_hex) % 2 == 0 else "0" + n_hex
        e_hex = e_hex if len(e_hex) % 2 == 0 else "0" + e_hex
        slen = int(g["sLen"]) if pss else -1
        for t in g["tests"]:
            h = HASH[bits](bytes.fromhex(t["msg"])).digest()
            sig = bytes.fromhex(t["sig"])
            # deep costs four verifications; at 4096 bits that is the qemu-armv5 budget, so the
            # offset pass runs only up to deep_max_bits. See tests/test_rsa.c.
            deep = int(t["result"] != "valid" and int(g["keySize"]) <= deep_max_bits)
            row = (pss_row(n_hex, e_hex, bits, slen, h, sig, deep) if pss
                   else pkcs1_row(n_hex, e_hex, bits, h, sig, deep))
            if (row[5] == RSA_OK) != (t["result"] == "valid"):
                if not (t["result"] == "acceptable" and row[5] == RSA_AUTH):
                    die("%s tcId %d: we say %d, upstream says %s"
                        % (name, t["tcId"], row[5], t["result"]))
            counts[t["result"]] += 1
            for f in t.get("flags", []):
                flags[f] = flags.get(f, 0) + 1
            rows.append(row)
    return rows, counts, flags, skipped


def cavp_private_key(fname, mod):
    """(n_hex, e_hex, d, k) from a 186-2 SigVer section, which publishes n, p and q.

    That is what lets the EM-corruption rows below be *built* rather than hand-typed: no key
    generation, no primality testing and no randomness enters this file."""
    text = zipfile.ZipFile(io.BytesIO(fetch("cavp_rsa2"))).read(fname).decode("latin-1")
    n_hex, body = split_key_blocks(rsp_mod_sections(text)[mod])[0]
    n = int(n_hex, 16)
    p = int(re.search(r"\np = ([0-9a-f]+)", body).group(1), 16)
    q = int(re.search(r"\nq = ([0-9a-f]+)", body).group(1), 16)
    if p * q != n or n.bit_length() != mod:
        die("%s [mod = %d]: p*q != n" % (fname, mod))
    e_hex = re.search(r"\ne = ([0-9a-fA-F]+)\n", body).group(1)
    e_hex = e_hex if len(e_hex) % 2 == 0 else "0" + e_hex
    e = int(e_hex, 16)
    d = pow(e, -1, (p - 1) * (q - 1) // _gcd(p - 1, q - 1))
    return n_hex, e_hex, n, e, d, mod // 8


def rsa_em_corruption():
    """One row per EMSA-PKCS1-v1_5 rule, built by signing a corrupted EM with a published key.

    No public suite isolates the rules one at a time: Wycheproof's 117 InvalidAsnInPadding and 75
    ModifiedPadding rows are a net, not a map, so a regression there says 'something in the
    padding' rather than which rule. These say which rule."""
    rows = []
    for mod in (2048, 4096):
        n_hex, e_hex, n, e, d, k = cavp_private_key("SigVer15_186-3.rsp", mod)

        def sign_em(em):
            return pow(int.from_bytes(em[:k], "big"), d, n).to_bytes(k, "big")

        for bits in (256, 384, 512):
            h = HASH[bits](b"brisk EM corruption " + str(mod).encode()).digest()
            t = DIGESTINFO[bits] + h
            ps = k - len(t) - 3
            good = bytes(b"\x00\x01" + b"\xff" * ps + b"\x00" + t)
            row = pkcs1_row(n_hex, e_hex, bits, h, sign_em(good), 1)
            if row[5] != RSA_OK:
                die("EM corruption: the uncorrupted control row does not verify")
            rows.append(row)
            bad = []
            for pos, val in ((0, 0x01),            # first octet != 0x00
                             (1, 0x02),            # encryption padding type
                             (1, 0x00),            # block type absent
                             (2, 0xFE),            # one PS octet != 0xff
                             (2 + ps // 2, 0x00),  # a 0x00 in the middle of PS
                             (2 + ps, 0xFF),       # the 0x00 separator missing
                             (2 + ps + 1, 0x31),   # DigestInfo SEQUENCE tag changed
                             (k - 1, 0x00)):       # last octet of H changed
                c = bytearray(good)
                c[pos] = val
                bad.append(bytes(c))
            # PS cut to 7 octets - the short-PS forgery the small-e Bleichenbacher class lives on.
            bad.append(b"\x00\x01" + b"\xff" * 7 + b"\x00" + t + b"\x00" * (ps - 7))
            # DigestInfo with the NULL parameters absent: Wycheproof's single "acceptable" row,
            # at every hash. RFC 8017 9.2 note 1 requires them; note 2's leniency is not adopted.
            p0 = DIGESTINFO[bits]
            nonull = (bytes([p0[0], p0[1] - 2, p0[2], p0[3] - 2]) + p0[4:13] + p0[15:])
            bad.append(b"\x00\x01" + b"\xff" * (k - len(nonull) - len(h) - 3) + b"\x00" +
                       nonull + h)
            # a valid DigestInfo followed by trailing garbage (one PS octet eaten)
            bad.append(b"\x00\x01" + b"\xff" * (ps - 1) + b"\x00" + t + b"\x2a")
            # DigestInfo for a different hash
            other = 384 if bits != 384 else 512
            t2 = DIGESTINFO[other] + HASH[other](b"x").digest()
            bad.append(b"\x00\x01" + b"\xff" * (k - len(t2) - 3) + b"\x00" + t2)
            # the hash moved one octet left, pad extended right (NIST failure reason 4)
            bad.append(b"\x00\x01" + b"\xff" * (ps - 1) + b"\x00" + t + b"\xff")
            # the trailing 00 of the pad removed, DigestInfo shifted (NIST failure reason 5)
            bad.append(b"\x00\x01" + b"\xff" * (ps + 1) + t)
            for em in bad:
                row = pkcs1_row(n_hex, e_hex, bits, h, sign_em(em), 1)
                if row[5] != RSA_AUTH:
                    die("EM corruption: %s was not rejected" % em[:6].hex())
                rows.append(row)
    return rows


def rsa_odd_modbits_key(want_bits):
    """A public key whose modulus has want_bits bits with want_bits % 8 == 1, plus its d.

    Needed because emLen = ceil((modBits - 1)/8) is k - 1 only when modBits - 1 is a multiple of
    8, i.e. when modBits % 8 == 1 - and every published RSA vector in existence uses a modulus of
    1024, 2048, 3072 or 4096 bits, so NO official source reaches that branch of RFC 8017 8.1.2
    step 2c. The modulus here is a small published prime times two published CAVP primes, which
    keeps this file free of primality testing and of randomness; RFC 8017 3.1 asks for a product
    of odd primes, not for exactly two of them, and nothing on the verify path counts factors.

    ponytail: brute force over the published prime pool, a few thousand big multiplies at
    generation time. A real key generator would be fifteen more lines and one more thing to get
    wrong; upgrade only if a future vector needs a modulus this cannot reach."""
    pool = set()
    for fname in ("SigVer15_186-3.rsp", "SigVerPSS_186-3.rsp"):
        text = zipfile.ZipFile(io.BytesIO(fetch("cavp_rsa2"))).read(fname).decode("latin-1")
        for v in re.findall(r"\n[pq] = ([0-9a-f]+)\n", text.replace("\r", "")):
            pool.add(int(v, 16))
    pool = sorted(pool)
    e = 65537
    for f in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73):
        for i, a in enumerate(pool):
            for b in pool[i + 1:]:
                n = f * a * b
                if n.bit_length() != want_bits:
                    continue
                lam = (a - 1) * (b - 1) // _gcd(a - 1, b - 1)
                lam = lam * (f - 1) // _gcd(lam, f - 1)
                if _gcd(e, lam) != 1:
                    continue
                w = (want_bits + 7) // 8
                return n.to_bytes(w, "big").hex(), "010001", n, pow(e, -1, lam), w
    die("no %d-bit modulus can be assembled from the published CAVP primes" % want_bits)


def pss_build(n, d, k, mod_bits, bits, slen, salt=None, db_pad=None, sep=0x01, trailer=0xBC,
              hp=None, topbit=0):
    """(mHash, signature) for an EM built exactly as RFC 8017 9.1.1 would - or deliberately not.

    Every knob is one step of EMSA-PSS-VERIFY (9.1.2), so a row that regresses names the rule it
    broke instead of just saying "PSS rejected it"."""
    hlen = bits // 8
    embits = mod_bits - 1
    emlen = (embits + 7) // 8
    top = 8 * emlen - embits
    mh = HASH[bits](b"brisk PSS " + str(mod_bits).encode()).digest()
    salt = bytes(range(slen)) if salt is None else salt
    hh = hp if hp is not None else HASH[bits](bytes(8) + mh + salt).digest()
    pad = db_pad if db_pad is not None else bytes(emlen - hlen - len(salt) - 2)
    db = pad + bytes([sep]) + salt
    masked = bytearray(x ^ y for x, y in zip(db, py_mgf1(bits, hh, len(db))))
    masked[0] = (masked[0] & (0xFF >> top)) | topbit
    em = bytes(masked) + hh + bytes([trailer])
    if len(em) != emlen:
        die("PSS build: EM is %d octets, emLen is %d" % (len(em), emlen))
    return mh, pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def rsa_pss_em_corruption():
    """The RFC 8017 9.1.2 structural rules, one row each, built with a published private key.

    Both emLen shapes of 8.1.2 step 2c are here and both matter:
      modBits 2048 / 4096 -> emLen == k,     8*emLen - emBits == 1, so the leftmost-bit masking
                                             of steps 6 and 9 is live;
      modBits 2049 / 3073 -> emLen == k - 1, no masking at all. No published vector anywhere uses
                                             a modulus of that shape (see rsa_odd_modbits_key),
                                             so without these rows that branch ships untested."""
    rnd = random.Random(20260921)
    keys, rows = [], []
    for mod in (2048, 4096):
        n_hex, e_hex, n, _e, d, k = cavp_private_key("SigVerPSS_186-3.rsp", mod)
        keys.append((n_hex, e_hex, n, d, k, mod))
    for mod in (2049, 3073):
        n_hex, e_hex, n, d, k = rsa_odd_modbits_key(mod)
        keys.append((n_hex, e_hex, n, d, k, mod))
    for n_hex, e_hex, n, d, k, mod in keys:
        emlen = (mod - 1 + 7) // 8
        for bits in (256, 384, 512):
            hlen = bits // 8
            for slen in (0, 10, hlen):
                mh, sig = pss_build(n, d, k, mod, bits, slen)
                row = pss_row(n_hex, e_hex, bits, slen, mh, sig, 1)
                if row[5] != RSA_OK:
                    die("PSS corruption: an uncorrupted control row does not verify")
                rows.append(row)
            slen = hlen
            mh, sig = pss_build(n, d, k, mod, bits, slen)

            def bld(**kw):
                return pss_build(n, d, k, mod, bits, slen, **kw)[1]

            bad = [(slen, bld(trailer=0xBD)),                 # trailer octet != 0xbc
                   (slen, bld(db_pad=bytes(emlen - hlen - slen - 3) + b"\x01")),  # DB lead != 0
                   (slen, bld(sep=0x00)),                     # the 0x01 separator absent
                   (slen, bld(sep=0x02)),                     # wrong separator octet
                   (slen + 1, sig),                           # salt read one octet too long
                   (slen - 1, sig),                           # salt read one octet too short
                   (slen, bld(hp=bytes(hlen))),               # H is not Hash(0^8 || mHash || salt)
                   (slen, bld(salt=bytes(slen),               # salt replaced, H left alone
                              hp=HASH[bits](bytes(8) + mh + bytes(range(slen))).digest()))]
            if 8 * emlen - (mod - 1):
                # Step 6: a set bit among the leftmost 8*emLen - emBits. Only meaningful when
                # there ARE such bits, i.e. emLen == k; on the emLen == k - 1 keys the count is
                # zero, and forcing bit 7 there is just another DB corruption - which the row
                # above already covers, and which is a coin flip to begin with because the bit
                # may already be set.
                bad.append((slen, bld(topbit=0x80)))
            for sl, s2 in bad:
                row = pss_row(n_hex, e_hex, bits, sl, mh, s2, 1)
                if row[5] != RSA_AUTH:
                    die("PSS corruption: a structural row was not rejected")
                rows.append(row)
            # emLen < hLen + sLen + 2 is "inconsistent" (BRISK_E_AUTH), never BRISK_E_ARG.
            for sl in (emlen, emlen - hlen - 1, 4096):
                rows.append(pss_row(n_hex, e_hex, bits, sl, mh, sig, 1))
        # In range but EM is noise: the generic 9.1.2 rejection at this width.
        mh = hashlib.sha256(b"noise").digest()
        rows.append(pss_row(n_hex, e_hex, 256, 32, mh, rnd.randrange(0, n).to_bytes(k, "big"), 1))
    if sum(r[5] == RSA_OK for r in rows) != len(keys) * 3 * 3:
        die("PSS corruption: wrong number of positive control rows")
    return rows


# ---------------------------------------------------------------- i31 bignum differential rows
# bn row = (op, m, a, b, r, k). Operands are big-endian octet strings at the modulus's byte
# width; `b` doubles as the exponent octet string for modpow. NO official vector source exists
# for a bare big-integer library (recorded in tests/kat/SOURCES.md as an accepted gap) - this is
# a seeded differential set against Python's arbitrary-precision int, sitting on the i31 limb
# boundaries where an off-by-one in the announced-length header hides and nothing else looks.
BN_ENCODE, BN_ADD, BN_SUB, BN_MONTMUL, BN_MODPOW = 0, 1, 2, 3, 4
BN_MODULI = []  # pooled: one 512-octet modulus is shared by every row at that width


def bn_vectors():
    rnd = random.Random(20260921)
    rows = []
    # 31*k - 1, 31*k and 31*k + 1 are where the limb count implied by the header word changes,
    # and 31*k + 1 is also where the top limb holds exactly one bit. 2048 and 4096 are the RSA
    # widths. Six moduli rather than fifteen: every extra one costs ~230 KB of generated table
    # for coverage the six already have, and the 4000 RSA rows are the end-to-end net anyway.
    for i, bits in enumerate([2046, 2047, 2048, 3068, 4092, 4096]):
        # An odd modulus of exactly `bits` bits; the first one's top limb holds a single bit.
        m = (1 << (bits - 1)) | 1 if i == 0 else \
            (1 << (bits - 1)) | (rnd.getrandbits(bits - 2) << 1) | 1
        w = (bits + 7) // 8
        limbs = (bits + 30) // 31
        R = 1 << (31 * limbs)
        # add/sub are limb-level, so their result is only reduced mod 2^(31*limbs) and can need
        # more octets than the modulus does: 2048 bits is 67 limbs = 2077 bits = 260 octets.
        # Everything else is a residue mod m and fits the modulus's own width.
        wfull = (31 * limbs + 7) // 8
        mi = len(BN_MODULI)
        BN_MODULI.append(m.to_bytes(w, "big").hex())

        def row(op, a, b, r, k=0, rw=w):
            return (op, mi, a.to_bytes(w, "big").hex() if isinstance(a, int) else a,
                    b.to_bytes(w, "big").hex() if isinstance(b, int) else b,
                    r.to_bytes(rw, "big").hex() if isinstance(r, int) else r, k)

        vals = [0, 1, m - 1, R % m, rnd.randrange(2, m - 1)]
        for a in vals:
            rows.append(row(BN_ENCODE, a, 0, a))
            for b in vals:
                rows.append(row(BN_MONTMUL, a, b, a * b * pow(R, -1, m) % m))
                # k is the carry / borrow, and the borrow is also what brisk__bn_lt must return,
                # so these rows pin lt too and it needs no op of its own.
                rows.append(row(BN_ADD, a, b, (a + b) % R, (a + b) >> (31 * limbs), wfull))
                rows.append(row(BN_SUB, a, b, (a - b) % R, int(a < b), wfull))
        for ex in (b"\x01", b"\x02", b"\x03", b"\x00\x01\x00\x01", b"\x01\x00\x01", b"\x11",
                   b"\xff\xff\xff", b"\x00\x00\x01\x00\x01", (m - 2).to_bytes(w, "big")[:5]):
            a = vals[-1]
            rows.append(row(BN_MODPOW, a, ex.hex(), pow(a, int.from_bytes(ex, "big"), m)))
    return rows

# ---------------------------------------------------------------------- DER (M2 X.509)
# There is no CAVP or Wycheproof suite for "a DER parser". What stands in for one:
#   1. every DER blob the already-pinned Wycheproof suites carry as *data* - the
#      SubjectPublicKeyInfo / RSAPublicKey of every RSA, P-256 and P-384 group - which a strict
#      reader MUST accept, and
#   2. ecdsa_secp256r1_sha256_test.json, the DER sibling of the p1363 suite this project uses
#      for ECDSA itself. Its 481 distinct signature blobs are the only large adversarial DER
#      corpus that exists: 92 rows flagged InvalidEncoding, 7 BerEncodedSignature, plus
#      integer-overflow and modified-integer families, all written by people trying to break
#      ASN.1 parsers. The p1363 API could not use them; a DER reader is exactly what they are for.
#   3. generated rows, one per X.690 clause the reader enforces, because a corpus of real
#      signatures does not contain a BIT STRING with 8 unused bits or a 17-deep nesting.
# The expectation is never read off a Wycheproof flag - those describe a *signature*, and a
# blob can be a perfectly good DER encoding of the wrong thing. It comes from py_der_walk()
# below, a second implementation of X.690 clause 10/11 written against the text; the flags are
# then used as an assertion on the aggregate (every "valid" row parses, every BER row does not).
DER_MAX_DEPTH = 16  # must match BRISK__DER_MAX_DEPTH in src/brisk_int.h


def py_der_hdr(b, i, end):
    """(tag, content start, content end) or None. Identifier + length, X.690 8.1 and 10.1."""
    if end - i < 2:
        return None
    tag = b[i]
    if tag & 0x1f == 0x1f:  # 8.1.2.4 high-tag-number form
        return None
    i += 1
    n = b[i]
    i += 1
    if n < 0x80:
        ln = n
    else:
        k = n & 0x7f
        # k == 0 is the indefinite form (8.1.3.6), banned by 10.1; k == 0x7f is reserved;
        # b[i] == 0 is a non-minimal length (10.1)
        if k == 0 or k > 4 or end - i < k or b[i] == 0:
            return None
        ln = int.from_bytes(b[i:i + k], "big")
        i += k
        if ln < 0x80:  # 10.1: the short form was available
            return None
    if ln > end - i:
        return None
    return tag, i, i + ln


def py_der_leaf_ok(tag, v):
    """DER content rules of the universal primitive types, X.690 8.x + 11.x."""
    if tag == 0x01:  # BOOLEAN, 11.1
        return len(v) == 1 and v[0] in (0x00, 0xff)
    if tag in (0x02, 0x0a):  # INTEGER 8.3.1 / 8.3.2, and ENUMERATED by 8.4
        return len(v) >= 1 and not (len(v) >= 2 and (
            (v[0] == 0x00 and not v[1] & 0x80) or (v[0] == 0xff and v[1] & 0x80)))
    if tag == 0x03:  # BIT STRING, 8.6.2.2 / 8.6.2.3 / 11.2.1
        if not v or v[0] > 7:
            return False
        if len(v) == 1:
            return v[0] == 0
        return v[-1] & ((1 << v[0]) - 1) == 0
    if tag == 0x05:  # NULL, 8.8.2
        return len(v) == 0
    if tag in (0x00, 0x10, 0x11):
        # Universal types that can never be primitive, the mirror of the constructed-form check
        # in py_der_walk: tag 0 is reserved for BER's end-of-contents (8.1.2.2 table 1), and
        # 8.9.1 / 8.10.1 say a SEQUENCE and a SET are always constructed.
        return False
    if tag == 0x06:  # OBJECT IDENTIFIER, 8.19.2
        if not v:
            return False
        starts = True
        for x in v:
            if starts and x == 0x80:
                return False
            starts = not x & 0x80
        return starts
    return True


def py_der_walk(b):
    """True if b is exactly one strictly DER-encoded value, nested at most DER_MAX_DEPTH deep."""
    stack, i, end = [], 0, len(b)
    while True:
        h = py_der_hdr(b, i, end)
        if h is None:
            return False
        tag, s, e = h
        if tag & 0x20:
            if tag & 0xc0 == 0 and tag not in (0x30, 0x31):  # 10.2
                return False
            if len(stack) == DER_MAX_DEPTH:
                return False
            stack.append(end)
            i, end = s, e
        else:
            if not py_der_leaf_ok(tag, b[s:e]):
                return False
            i = e
        while i == end:
            if not stack:
                return True
            end = stack.pop()
        if not stack:
            return False  # a second top-level value: one blob holds one


def der_tlv(tag, content, lenbytes=0, ln=None):
    """Encode one TLV. lenbytes forces the long form to that width (for the non-minimal rows),
    ln overrides the length field without changing the content (for the truncated rows)."""
    n = len(content) if ln is None else ln
    if lenbytes:
        head = bytes([tag, 0x80 | lenbytes]) + n.to_bytes(lenbytes, "big")
    elif n < 0x80:
        head = bytes([tag, n])
    else:
        e = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(e)]) + e
    return head + content


def der_nest(depth, inner=b"\x05\x00"):
    for _ in range(depth):
        inner = der_tlv(0x30, inner)
    return inner


def der_generated():
    """(bytes, expect_ok, note) for every rule in the brisk__der header block."""
    long128 = bytes(range(128))  # exactly 0x80 bytes: the first length needing the long form
    rows = [
        # --- accepted: the shapes a certificate is actually made of
        (b"\x05\x00", 1, "NULL"),
        (b"\x02\x01\x00", 1, "INTEGER 0"),
        (b"\x02\x01\x7f", 1, "INTEGER 127"),
        (b"\x02\x02\x00\x80", 1, "INTEGER 128 with the 8.3.2 sign octet"),
        (b"\x02\x01\x80", 1, "INTEGER -128"),
        (b"\x02\x02\xff\x7f", 1, "INTEGER -129"),
        (b"\x01\x01\x00", 1, "BOOLEAN FALSE"),
        (b"\x01\x01\xff", 1, "BOOLEAN TRUE"),
        (b"\x03\x01\x00", 1, "BIT STRING, no bits"),
        (b"\x03\x03\x04\xf0\xf0", 1, "BIT STRING, 4 unused bits, all zero"),
        (b"\x03\x02\x07\x80", 1, "BIT STRING, one bit set"),
        (b"\x06\x03\x2a\x86\x48", 1, "OID 1.2.840"),
        (b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", 1, "OID sha256WithRSAEncryption"),
        (b"\x0a\x01\x01", 1, "ENUMERATED 1, a CRLReason as RFC 5280 5.3.1 encodes it"),
        (b"\x30\x00", 1, "empty SEQUENCE"),
        (b"\x31\x00", 1, "empty SET"),
        (b"\x30\x06\x02\x01\x01\x02\x01\x02", 1, "SEQUENCE of two INTEGERs"),
        (b"\xa0\x03\x02\x01\x02", 1, "[0] EXPLICIT INTEGER, the X.509 version field"),
        (b"\x82\x0b" + b"example.com", 1, "[2] IMPLICIT IA5String, a dNSName"),
        (der_tlv(0x04, long128), 1, "OCTET STRING of 128 bytes: the shortest legal long form"),
        (der_tlv(0x04, bytes(300)), 1, "OCTET STRING of 300 bytes, two length octets"),
        (der_nest(DER_MAX_DEPTH), 1, f"{DER_MAX_DEPTH} nested SEQUENCEs: exactly the depth cap"),
        # --- rejected: length and identifier encoding (X.690 8.1, 10.1)
        (b"", 0, "empty input"),
        (b"\x05", 0, "identifier octet with no length"),
        (b"\x04\x03\x01\x02", 0, "length runs past the end"),
        (b"\x04\x80\x01\x02", 0, "indefinite length (8.1.3.6), forbidden by 10.1"),
        (b"\x04\xff\x01", 0, "reserved length octet 0xff (8.1.3.5)"),
        (der_tlv(0x04, long128, lenbytes=2), 0, "non-minimal long form: 0x0080 in two octets"),
        (der_tlv(0x04, b"\x01" * 0x7f, lenbytes=1), 0, "long form for 127: short form required"),
        (b"\x1f\x01\x01\x00", 0, "high-tag-number form (8.1.2.4)"),
        (b"\x3f\x03\x02\x01\x01", 0, "high-tag-number form, constructed"),
        (b"\x10\x03\x02\x01\x01", 0, "primitive SEQUENCE (8.9.1)"),
        (b"\x11\x03\x02\x01\x01", 0, "primitive SET (8.10.1)"),
        (b"\x00\x00", 0, "BER end-of-contents marker, tag 0 is reserved (8.1.2.2)"),
        (b"\x30\x04\x02\x01\x01\x00\x00", 0, "end-of-contents inside a definite-length SEQUENCE"),
        (b"\x24\x03\x04\x01\x00", 0, "constructed OCTET STRING (10.2)"),
        (b"\x23\x03\x03\x01\x00", 0, "constructed BIT STRING (10.2)"),
        (b"\x2c\x02\x0c\x00", 0, "constructed UTF8String (10.2)"),
        (b"\x37\x02\x17\x00", 0, "constructed UTCTime (10.2)"),
        (b"\x22\x03\x02\x01\x01", 0, "constructed INTEGER (8.3.1 makes it primitive-only)"),
        (der_tlv(0x04, long128, lenbytes=5), 0, "five length octets: more than a size_t holds"),
        (b"\x0a\x00", 0, "ENUMERATED with no contents octet (8.3.1 via 8.4)"),
        (b"\x0a\x02\x00\x01", 0, "ENUMERATED with a redundant leading zero (8.3.2 via 8.4)"),
        (b"\x30\x01\x05", 0, "truncated header inside a SEQUENCE"),
        (b"\x30\x03\x02\x01\x01\x00", 0, "trailing byte after the top-level value"),
        (b"\x05\x00\x05\x00", 0, "two top-level values"),
        (b"\x30\x02\x02\x01\x01", 0, "SEQUENCE that truncates the INTEGER inside it"),
        # --- rejected: contents (X.690 8.3, 8.6, 8.8, 8.19, 11.1, 11.2.1)
        (b"\x02\x00", 0, "INTEGER with no octets (8.3.1)"),
        (b"\x02\x02\x00\x00", 0, "INTEGER 0 with a redundant leading zero (8.3.2)"),
        (b"\x02\x02\x00\x01", 0, "INTEGER 1 with a redundant leading zero (8.3.2)"),
        (b"\x02\x02\xff\xff", 0, "INTEGER -1 with redundant leading ones (8.3.2)"),
        (b"\x02\x02\xff\x80", 0, "INTEGER -128 with redundant leading ones (8.3.2)"),
        (b"\x01\x00", 0, "BOOLEAN with no octets"),
        (b"\x01\x01\x01", 0, "BOOLEAN TRUE encoded as 01 (11.1 requires ff)"),
        (b"\x01\x02\x00\xff", 0, "BOOLEAN of two octets"),
        (b"\x03\x00", 0, "BIT STRING without the unused-bit count"),
        (b"\x03\x01\x01", 0, "BIT STRING, no bits but 1 unused (8.6.2.3)"),
        (b"\x03\x02\x08\x00", 0, "BIT STRING with 8 unused bits (8.6.2.2)"),
        (b"\x03\x02\x01\xff", 0, "BIT STRING with a set unused bit (11.2.1)"),
        (b"\x03\x03\x04\xf0\xf1", 0, "BIT STRING with set unused bits (11.2.1)"),
        (b"\x05\x01\x00", 0, "NULL with contents (8.8.2)"),
        (b"\x06\x00", 0, "OID with no octets"),
        (b"\x06\x02\x2a\x80", 0, "OID whose last subidentifier never terminates (8.19.2)"),
        (b"\x06\x03\x2a\x80\x01", 0, "OID with a padded subidentifier (8.19.2)"),
        (b"\x06\x01\x80", 0, "OID that is one continuation octet"),
        (der_nest(DER_MAX_DEPTH + 1), 0, f"{DER_MAX_DEPTH + 1} nested SEQUENCEs: past the depth cap"),
    ]
    out = []
    for b, want, note in rows:
        got = 1 if py_der_walk(b) else 0
        if got != want:
            die(f"der_generated: {note!r} expected {want}, py_der_walk said {got}")
        out.append((b.hex(), 1 - want, note))
    return out


def der_wycheproof():
    """Every DER blob the cached Wycheproof suites carry, with py_der_walk's verdict."""
    rows, seen, stats = [], set(), {"keys": 0, "sigs accepted": 0, "sigs rejected": 0}
    keys = []
    for name in list(SRC):
        if not name.startswith(("wp_rsa_", "wp_p256_", "wp_p384_")):
            continue
        for g in json.loads(fetch(name))["testGroups"]:
            for field in ("publicKeyDer", "publicKeyAsn"):
                if isinstance(g.get(field), str) and g[field] not in seen:
                    seen.add(g[field])
                    keys.append((name, field, g[field]))
    for name, field, hx in keys:
        if not py_der_walk(bytes.fromhex(hx)):
            die(f"{name} {field} is not strict DER: {hx[:64]}...")
        stats["keys"] += 1
        rows.append((hx, 0, f"{name} {field}"))

    data = json.loads(fetch("wp_p256_ecdsa_der"))
    sigs, flags_of, result_of = [], {}, {}
    for g in data["testGroups"]:
        for t in g["tests"]:
            if t["sig"] in seen:
                continue
            seen.add(t["sig"])
            sigs.append(t["sig"])
            flags_of[t["sig"]] = t.get("flags", [])
            result_of[t["sig"]] = t["result"]
    for hx in sigs:
        ok = py_der_walk(bytes.fromhex(hx))
        # A Wycheproof "valid" row is a signature that verifies, so its encoding is DER by
        # construction: if our reader would reject one, the reader is wrong.
        if result_of[hx] == "valid" and not ok:
            die(f"wp_p256_ecdsa_der: a valid signature was rejected: {hx}")
        # BerEncodedSignature is the flag for "BER but not DER" - exactly what clause 10 bans.
        if "BerEncodedSignature" in flags_of[hx] and ok:
            die(f"wp_p256_ecdsa_der: a BER-encoded signature was accepted: {hx}")
        stats["sigs accepted" if ok else "sigs rejected"] += 1
        flag = flags_of[hx][0] if flags_of[hx] else "-"
        rows.append((hx, 0 if ok else 1, f"wp ecdsa_secp256r1_sha256 {flag}"))
    print(f"  DER corpus: {stats}")
    return rows


DER_OP = {"uint": 0, "int": 1, "unsigned": 2, "bool": 3, "oid": 4, "bits": 5, "null": 6}


def der_values():
    """(op, hex, reject, want hex, aux) for the typed readers. want/aux are ignored when the
    row is a rejection."""
    rows = []

    def add(op, b, want=b"", aux=0, reject=0):
        rows.append((DER_OP[op], b.hex(), reject, want.hex(), aux))

    for value in (0, 1, 127, 128, 255, 256, 65535, 65536, 16777215, 16777216, 2 ** 31,
                  2 ** 32 - 1):
        n = max(1, (value.bit_length() + 8) // 8)  # DER keeps one sign bit
        enc = der_tlv(0x02, value.to_bytes(n, "big"))
        mag = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        add("uint", enc, aux=value)
        add("unsigned", enc, want=mag)
        add("int", enc, want=value.to_bytes(n, "big"))
    add("uint", der_tlv(0x02, (2 ** 32).to_bytes(5, "big")), reject=1)  # five magnitude octets
    add("uint", b"\x02\x01\x81", reject=1)  # negative
    add("unsigned", b"\x02\x01\x81", reject=1)
    add("unsigned", b"\x02\x02\xff\x00", reject=1)
    add("int", b"\x02\x01\x81", want=b"\x81")  # a negative serial number stays opaque
    add("int", b"\x02\x02\xff\x00", want=b"\xff\x00")
    add("int", b"\x03\x01\x00", reject=1)  # wrong tag
    add("uint", b"\x05\x00", reject=1)

    add("bool", b"\x01\x01\x00", aux=0)
    add("bool", b"\x01\x01\xff", aux=1)
    add("bool", b"\x01\x01\x01", reject=1)
    add("bool", b"\x02\x01\x00", reject=1)

    add("null", b"\x05\x00")
    add("null", b"\x05\x01\x00", reject=1)
    add("null", b"\x30\x00", reject=1)

    for oid in ("2a8648ce3d030107",  # prime256v1
                "2a8648ce3d0201",  # id-ecPublicKey
                "2a864886f70d010101",  # rsaEncryption
                "551d0f",  # id-ce-keyUsage
                "2b06010505070301"):  # id-kp-serverAuth
        add("oid", der_tlv(0x06, bytes.fromhex(oid)), want=bytes.fromhex(oid))
    add("oid", b"\x06\x02\x2a\x80", reject=1)
    add("oid", b"\x06\x00", reject=1)
    add("oid", b"\x04\x03\x2a\x86\x48", reject=1)

    add("bits", b"\x03\x01\x00", want=b"", aux=0)
    add("bits", b"\x03\x02\x07\x80", want=b"\x80", aux=7)
    add("bits", b"\x03\x03\x04\xf0\xf0", want=b"\xf0\xf0", aux=4)
    add("bits", b"\x03\x02\x01\x06", want=b"\x06", aux=1)  # keyUsage digitalSignature+keyCertSign
    add("bits", b"\x03\x02\x08\x00", reject=1)
    add("bits", b"\x03\x02\x01\xff", reject=1)
    add("bits", b"\x03\x00", reject=1)
    add("bits", b"\x04\x02\x00\xff", reject=1)
    return rows


# ------------------------------------------------------------------ X.509 certificates (M2)
# No official "parse this certificate" suite exists at this layer either. x509-limbo is the real
# one and it is its own ROADMAP item; what stands here until then is:
#   1. certificates BUILT by the encoder below, one per rule src/x509/cert.c enforces, with the
#      expected decode of every field computed in Python. A constructed certificate is the only
#      way to get a keyUsage with a trailing zero bit or a pathLenConstraint without cA - no CA
#      issues those, which is exactly why a parser has to be told about them explicitly.
#   2. the same shell wrapped around REAL SubjectPublicKeyInfo blobs taken from the Wycheproof
#      suites, so read_spki() meets key material produced by other people's tools rather than
#      only by this file.
# The signatures on all of them are nonsense bytes, deliberately: this item parses, it does not
# verify, and a vector set that needed valid signatures could not cover a tenth of these cases.
X509_MAX_CERTS = 30  # real SPKIs to wrap; the whole table would be 300 KB for nothing new


def py_oid(dotted):
    """DER contents octets of an OBJECT IDENTIFIER, X.690 8.19."""
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        chunk = [n & 0x7f]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7f))
            n >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


X509_OIDS = {
    "OID_RSA": "1.2.840.113549.1.1.1", "OID_RSA_PSS": "1.2.840.113549.1.1.10",
    "OID_MGF1": "1.2.840.113549.1.1.8", "OID_RSA_SHA256": "1.2.840.113549.1.1.11",
    "OID_RSA_SHA384": "1.2.840.113549.1.1.12", "OID_RSA_SHA512": "1.2.840.113549.1.1.13",
    "OID_EC_KEY": "1.2.840.10045.2.1", "OID_P256": "1.2.840.10045.3.1.7",
    "OID_ECDSA_SHA256": "1.2.840.10045.4.3.2", "OID_ECDSA_SHA384": "1.2.840.10045.4.3.3",
    "OID_ECDSA_SHA512": "1.2.840.10045.4.3.4", "OID_P384": "1.3.132.0.34",
    "OID_SHA256": "2.16.840.1.101.3.4.2.1", "OID_SHA384": "2.16.840.1.101.3.4.2.2",
    "OID_SHA512": "2.16.840.1.101.3.4.2.3", "OID_KEY_USAGE": "2.5.29.15",
    "OID_SAN": "2.5.29.17", "OID_BASIC_CONSTR": "2.5.29.19", "OID_EKU": "2.5.29.37",
    "OID_EKU_ANY": "2.5.29.37.0", "OID_KP_SERVER": "1.3.6.1.5.5.7.3.1",
    "OID_KP_CLIENT": "1.3.6.1.5.5.7.3.2",
}


def check_x509_source_constants():
    """Every OID table entry in src/x509/cert.c must equal the encoding of its dotted form.

    Same guard as check_p256_source_constants(): the bytes in the source are not allowed to be
    something a human typed and nobody re-derived."""
    src = (ROOT / "src" / "x509" / "cert.c").read_text()
    for name, dotted in sorted(X509_OIDS.items()):
        m = re.search(r"OID_" + name[4:] + r"\s*=\s*\{\s*(\d+)\s*,\s*\{([^}]*)\}", src)
        if not m:
            die(f"cert.c: no table entry for {name}")
        got = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(2)))
        want = py_oid(dotted)
        if int(m.group(1)) != len(want) or got != want:
            die(f"cert.c {name} ({dotted}): source has {got.hex()}/{m.group(1)}, "
                f"the OID encodes to {want.hex()}/{len(want)}")
    print(f"  cert.c: {len(X509_OIDS)} OIDs match their dotted forms")


X509_TIME_FLOOR = None  # BRISK_X509_TIME_FLOOR, read from the header by check_x509_time_config()


def check_x509_time_config():
    """The validity floor and the default policy come from include/brisk_config.h.

    Every validity row below is computed against them, so a header whose floor moved and whose
    vectors nobody regenerated fails the suite instead of testing a window that no longer
    exists. Same standard as check_x509_source_constants()."""
    global X509_TIME_FLOOR
    src = (ROOT / "include" / "brisk_config.h").read_text()
    m = re.search(r"#\s*define\s+BRISK_X509_TIME_FLOOR\b\s+(\d+)", src)
    if not m:
        die("brisk_config.h: no BRISK_X509_TIME_FLOOR default")
    X509_TIME_FLOOR = int(m.group(1))
    m = re.search(r"#\s*define\s+BRISK_X509_TIME_POLICY\s+BRISK_X509_TIME_POLICY_(\w+)", src)
    if not m or m.group(1) != "FLOOR":
        die("brisk_config.h: the default BRISK_X509_TIME_POLICY is no longer FLOOR")
    if not 0 < X509_TIME_FLOOR < 2 ** 31:
        die("brisk_config.h: BRISK_X509_TIME_FLOOR %d is not a plausible date" % X509_TIME_FLOOR)
    if CHAIN_NOW <= X509_TIME_FLOOR:
        die("the chain rows' clock (%d) is below the floor; they would all take the unset-clock "
            "branch and stop testing the walk" % CHAIN_NOW)
    print("  brisk_config.h: time floor %d (%s), default policy FLOOR"
          % (X509_TIME_FLOOR, asn1_time_str(X509_TIME_FLOOR)))


def asn1_time_str(secs):
    """The RFC 5280 4.1.2.5 encoding of an instant: UTCTime through 2049, GeneralizedTime from
    2050 on, which is exactly the split 4.1.2.5.1 / 4.1.2.5.2 mandate."""
    t = (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
         + datetime.timedelta(seconds=secs))
    return t.strftime("%y%m%d%H%M%SZ" if t.year < 2050 else "%Y%m%d%H%M%SZ")


def py_time_verdict(policy, nbf, naf, now, floor):
    """0 = BRISK_OK, 1 = BRISK_E_AUTH, straight from the BRISK_X509_TIME_POLICY block of
    include/brisk_config.h: a clock below the floor is an unset counter, and the policy says
    what an unset counter buys."""
    if policy == "insecure":
        return 0
    if now < floor:
        return 1 if policy == "strict" else (0 if naf >= floor else 1)
    return 0 if nbf <= now <= naf else 1



# ---------------------------------------------------------------- a certificate encoder
def x_seq(*p):
    return der_tlv(0x30, b"".join(p))


def x_oid(dotted):
    return der_tlv(0x06, py_oid(dotted))


def x_int(v):
    if isinstance(v, bytes):
        return der_tlv(0x02, v)
    n = max(1, (v.bit_length() + 8) // 8)
    return der_tlv(0x02, v.to_bytes(n, "big"))


def x_ctx(num, content, constructed=True):
    return der_tlv(0x80 | (0x20 if constructed else 0) | num, content)


def x_bits(payload, unused=0):
    return der_tlv(0x03, bytes([unused]) + payload)


def x_named_bits(bits):
    """A NamedBitList BIT STRING with the trailing zero bits removed, per X.690 11.2.2."""
    if not bits:
        return x_bits(b"", 0)
    top = max(bits)
    octets = bytearray(top // 8 + 1)
    for b in bits:
        octets[b // 8] |= 0x80 >> (b % 8)
    return x_bits(bytes(octets), 7 - top % 8)


def x_name(cn):
    """RDNSequence with one commonName; b"" gives the empty name RFC 5280 4.2.1.6 allows."""
    if cn is None:
        return x_seq()
    return x_seq(der_tlv(0x31, x_seq(x_oid("2.5.4.3"), der_tlv(0x0c, cn.encode()))))


def x_ext(dotted, critical, value):
    parts = [x_oid(dotted)]
    if critical:
        parts.append(der_tlv(0x01, b"\xff"))
    parts.append(der_tlv(0x04, value))
    return x_seq(*parts)


def x_alg_rsa_pkcs1(h=256):
    return x_seq(x_oid(f"1.2.840.113549.1.1.{ {256: 11, 384: 12, 512: 13}[h] }"), b"\x05\x00")


def x_alg_ecdsa(h=256):
    return x_seq(x_oid(f"1.2.840.10045.4.3.{ {256: 2, 384: 3, 512: 4}[h] }"))


SHA_OID = {256: "2.16.840.1.101.3.4.2.1", 384: "2.16.840.1.101.3.4.2.2",
           512: "2.16.840.1.101.3.4.2.3"}


def x_alg_pss(h=256, salt=None, trailer=None, mgf_h=None, omit_hash=False, omit_mgf=False):
    """RSASSA-PSS-params, RFC 4055 3.1, in the DER form a conforming CA actually emits: every
    field has a DEFAULT, so trailerField is always omitted (3.1 makes that a MUST for signers)
    and saltLength is omitted when it is the default 20. Pass trailer= or omit_* to build the
    shapes a validator must accept or refuse."""
    salt = {256: 32, 384: 48, 512: 64}[h] if salt is None else salt
    parts = []
    if not omit_hash:
        parts.append(x_ctx(0, x_seq(x_oid(SHA_OID[h]))))
    if not omit_mgf:
        parts.append(x_ctx(1, x_seq(x_oid("1.2.840.113549.1.1.8"),
                                    x_seq(x_oid(SHA_OID[mgf_h or h])))))
    if salt != 20:
        parts.append(x_ctx(2, x_int(salt)))
    if trailer is not None:
        parts.append(x_ctx(3, x_int(trailer)))
    return x_seq(x_oid("1.2.840.113549.1.1.10"), x_seq(*parts))


def x_spki_rsa(n_hex=None, e_hex="010001"):
    n = bytes.fromhex(n_hex or RSA_KEYS[0][0])
    key = x_seq(x_int(int.from_bytes(n, "big")), x_int(int.from_bytes(bytes.fromhex(e_hex), "big")))
    return x_seq(x_seq(x_oid("1.2.840.113549.1.1.1"), b"\x05\x00"), x_bits(key))


def x_spki_ec(curve="1.2.840.10045.3.1.7", point=None):
    if point is None:
        point = bytes.fromhex("04") + bytes(96 if curve.endswith("0.34") else 64)
    return x_seq(x_seq(x_oid("1.2.840.10045.2.1"), x_oid(curve)), x_bits(point))


def x_time(text):
    return der_tlv(0x17 if len(text) <= 13 else 0x18, text.encode())


def make_cert(version=3, serial=1, alg=None, outer_alg=None, issuer="Brisk Test CA",
              subject="device.example.com", nbf="200101000000Z", naf="300101000000Z",
              spki=None, exts=None, sig=None, sig_unused=0, uids=b"", extra_tbs=b"",
              sign=None):
    alg = x_alg_rsa_pkcs1() if alg is None else alg
    spki = x_spki_rsa() if spki is None else spki
    parts = []
    if version != 1:
        parts.append(x_ctx(0, x_int(version - 1)))
    parts += [x_int(serial), alg, x_name(issuer), x_seq(x_time(nbf), x_time(naf)), x_name(subject),
              spki]
    tbs = x_seq(*parts, uids, extra_tbs, x_ctx(3, x_seq(*exts)) if exts is not None else b"")
    if sign is not None:  # a chain row: the signature is over these exact bytes (4.1.1.3)
        sig = sign(tbs)
    return x_seq(tbs, outer_alg if outer_alg is not None else alg,
                 x_bits(sig if sig is not None else bytes(64), sig_unused))


# ---------------------------------------------------------------- expected decode
def cert_row(der, note, reject=0, flags=0, version=3, key_alg=1, sig_alg=1, sig_hash=1, salt=0,
             key_usage=0, eku=0, is_ca=0, path_len=-1, serial=b"\x01", san=b"",
             nbf="200101000000Z", naf="300101000000Z"):
    nb = na = 0
    if not reject:
        nb, na = py_asn1_time(nbf), py_asn1_time(naf)
    return (der.hex(), reject, note, flags, version, key_alg, sig_alg, sig_hash, salt, key_usage, eku,
            is_ca, path_len, serial.hex(), san.hex(), nb, na)


def py_asn1_time(text):
    """Seconds since the epoch for a UTCTime / GeneralizedTime string, via calendar.timegm."""
    if len(text) == 13:
        yy = int(text[:2])
        y, rest = (2000 + yy if yy < 50 else 1900 + yy), text[2:12]
    else:
        y, rest = int(text[:4]), text[4:14]
    mo, d, h, mi, s = (int(rest[i:i + 2]) for i in range(0, 10, 2))
    return calendar.timegm((y, mo, d, h, mi, s, 0, 1, 0))


def iso_to_epoch(text):
    """Seconds since epoch for an RFC 3339 UTC string. x509-limbo writes validation_time in
    two spellings, `...Z` and `...+00:00` (with optional fractional seconds), and the offset
    is always zero. A non-zero offset would be a schema change, so this refuses it rather than
    silently pick a timezone."""
    m = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?"
        r"(Z|([+-])(\d{2}):(\d{2}))$", text)
    if not m:
        raise ValueError(f"cannot parse ISO timestamp {text!r}")
    y, mo, d, h, mi, s = (int(g) for g in m.group(1, 2, 3, 4, 5, 6))
    if m.group(7) != "Z":
        if int(m.group(9)) or int(m.group(10)):
            raise ValueError(f"non-UTC offset in {text!r}")
    return calendar.timegm((y, mo, d, h, mi, s, 0, 1, 0))


def pem_to_der(text):
    """Decode ONE PEM CERTIFICATE block back to DER. limbo hands us the whole PEM text; we do
    not need brisk__x509_pem_feed's multi-block streaming here. Only the CERTIFICATE label is
    accepted, so a private key or CRL slipping in is a fixture bug, not a silent misread."""
    lines, inside = [], False
    for line in text.splitlines():
        s = line.strip()
        if s == "-----BEGIN CERTIFICATE-----":
            inside = True
        elif s == "-----END CERTIFICATE-----":
            inside = False
            break
        elif inside and s:
            lines.append(s)
    if not lines:
        raise ValueError("no CERTIFICATE block")
    return base64.b64decode("".join(lines), validate=True)


def x509_time_vectors():
    """(tag, text, reject, seconds) for brisk__x509_time."""
    rows = []
    good = ["500101000000Z", "700101000000Z", "991231235959Z", "000101000000Z",
            "490101000000Z", "240229120000Z", "380119031407Z", "010203040506Z"]
    for t in good:
        rows.append((0x17, t, 0, py_asn1_time(t)))
        rows.append((0x18, "20" + t if int(t[:2]) < 50 else "19" + t, 0,
                     py_asn1_time(("20" if int(t[:2]) < 50 else "19") + t)))
    for t in ["19500101000000Z", "20000229000000Z", "21000301000000Z", "99991231235959Z",
              "20240101000000Z"]:
        rows.append((0x18, t, 0, py_asn1_time(t)))
    bad_utc = [
        ("2001010000Z", "no seconds - RFC 5280 4.1.2.5.1 requires them"),
        ("200101000000", "no Z terminator"),
        ("200101000000+0100", "a time differential, not Zulu"),
        ("200101000000z", "lowercase z"),
        ("201301000000Z", "month 13"),
        ("200001000000Z", "month 0"),
        ("200132000000Z", "day 32"),
        ("200100000000Z", "day 0"),
        ("230229000000Z", "29 February in a common year"),
        ("200101240000Z", "hour 24"),
        ("200101006000Z", "minute 60"),
        ("200101000060Z", "second 60 - a leap second, refused on purpose"),
        ("2001010000x0Z", "a non-digit in the seconds"),
        ("", "empty"),
    ]
    for t, why in bad_utc:
        rows.append((0x17, t, 1, 0))
    for t, why in [("2020010100000Z", "one digit short"), ("202001010000001Z", "one digit long"),
                   ("20200101000000.5Z", "a fractional part - 4.1.2.5.2 forbids it"),
                   ("19490101000000Z", "before 1950: a local floor, not an RFC 5280 rule"), ("100000101000000Z", "16 octets: longer than any GeneralizedTime this profile takes")]:
        rows.append((0x18, t, 1, 0))
    rows.append((0x13, "200101000000Z", 1, 0))  # PrintableString, not a Time
    return rows


KU_DIGITAL_SIGNATURE, KU_KEY_ENCIPHERMENT, KU_KEY_CERT_SIGN, KU_CRL_SIGN = 0x01, 0x04, 0x20, 0x40
EKU_SERVER, EKU_CLIENT, EKU_ANY, EKU_OTHER = 0x01, 0x02, 0x04, 0x08
SAN_DNS = der_tlv(0x82, b"device.example.com")
SAN_TWO = SAN_DNS + der_tlv(0x87, bytes([192, 0, 2, 1]))



def x509_validity_vectors():
    """(cert, now, [want_strict, want_floor, want_insecure], note) for brisk__x509_time_ok.

    One row per branch of the policy, plus the boundaries on both sides of every comparison -
    an off-by-one in `now <= notAfter` is the whole bug class this module can have. The three
    verdicts travel together because the policy is a compile-time knob: whichever one a build
    chose, the C reads its own column, and a row that is wrong for the other two is still
    visible here.

    YEARS > 2038 are deliberate. notBefore/notAfter and `now` are int64 everywhere, so a 32-bit
    build that truncated one of them somewhere would answer these rows backwards."""
    f = X509_TIME_FLOOR
    yr = 365 * 86400
    rows = []

    def row(nbf, naf, now, note, clock="usable"):
        """`clock` is which branch of the policy this row is FOR. It is checked rather than
        inferred: a row written to pin a notBefore boundary is worth nothing if its clock sits
        below the floor, because the unset-clock branch never looks at notBefore and the oracle
        would quietly relabel the row instead of failing."""
        if (now >= f) != (clock == "usable"):
            die("validity row '%s': clock=%s, but now is on the other side of the floor" % (
                note, clock))
        nbf_s, naf_s = asn1_time_str(nbf), asn1_time_str(naf)
        if py_asn1_time(nbf_s) != nbf or py_asn1_time(naf_s) != naf:
            die("validity row '%s': the encoding does not round-trip" % note)
        if nbf > naf:
            die("validity row '%s': cert.c refuses notBefore > notAfter at parse time" % note)
        want = [py_time_verdict(p, nbf, naf, now, f) for p in ("strict", "floor", "insecure")]
        rows.append((make_cert(nbf=nbf_s, naf=naf_s).hex(), now, want, note))

    # A clock at or above the floor: the ordinary window check, and its four boundaries.
    row(f - 10 * yr, f + 10 * yr, f + yr, "a usable clock inside the window")
    row(f - 10 * yr, f - yr, f + yr, "a usable clock, the certificate expired")
    row(f + 2 * yr, f + 3 * yr, f + yr, "a usable clock, the certificate is not valid yet")
    row(f, f + 10 * yr, f, "the clock is exactly the floor")
    row(f + yr, f + 2 * yr, f + yr, "now == notBefore is inside")
    row(f - yr, f + yr, f + yr, "now == notAfter is inside")
    row(f + 1, f + yr, f, "one second before notBefore")
    row(f - yr, f - 1, f, "one second after notAfter")

    # Below the floor the clock is not a clock. STRICT stops; FLOOR judges notAfter alone.
    row(f - yr, f + yr, f - 1, "one second below the floor, notAfter is above it", clock="unset")
    row(f - 10 * yr, f - 5 * yr, f - 1, "below the floor, the certificate died before the build",
        clock="unset")
    row(f - yr, f, f - 1, "below the floor, notAfter == the floor exactly", clock="unset")
    row(f - yr, f - 1, f - 1, "below the floor, notAfter one second under it", clock="unset")
    row(f - yr, f + yr, 0, "an RTC that has never been set", clock="unset")
    row(f + 5 * yr, f + 6 * yr, 0, "an unset RTC cannot judge a notBefore in the future", clock="unset")
    row(f - yr, f + yr, -1, "a clock that reads before the epoch", clock="unset")

    # int64 dates: both sides of the 32-bit second, and the end of GeneralizedTime.
    row(py_asn1_time("200101000000Z"), py_asn1_time("390101000000Z"), 2 ** 31,
        "just past the 32-bit second, still inside the window")
    row(py_asn1_time("200101000000Z"), 2 ** 31 - 1, 2 ** 31,
        "expired one second before the 32-bit wrap")
    row(py_asn1_time("200101000000Z"), py_asn1_time("99991231235959Z"), 2 ** 33,
        "the last instant GeneralizedTime can encode is still ahead")
    row(py_asn1_time("200101000000Z"), py_asn1_time("300101000000Z"), 2 ** 33,
        "a clock in the year 2242")
    row(py_asn1_time("500101000000Z"), f + yr, f,
        "a notBefore before the epoch is a negative int64")

    print("  x509 validity: %d rows, floor %d" % (len(rows), X509_TIME_FLOOR))
    return rows


def x509_real_spkis():
    """SubjectPublicKeyInfo blobs from the cached Wycheproof suites, one per distinct key, kept
    only where the algorithm is one this client supports."""
    out, seen = [], set()
    for name in list(SRC):
        if not name.startswith(("wp_rsa_", "wp_p256_", "wp_p384_")):
            continue
        for g in json.loads(fetch(name))["testGroups"]:
            hx = g.get("publicKeyDer")
            if not isinstance(hx, str) or hx in seen:
                continue
            seen.add(hx)
            blob = bytes.fromhex(hx)
            for oid, alg, p384 in ((py_oid("1.2.840.113549.1.1.1"), 1, 0),
                                   (py_oid("1.2.840.10045.3.1.7"), 2, 0),
                                   (py_oid("1.3.132.0.34"), 3, 1)):
                if oid in blob:
                    out.append((blob, alg, p384, name))
                    break
    out.sort(key=lambda r: (r[1], len(r[0]), r[0]))
    return out[:X509_MAX_CERTS] if len(out) <= X509_MAX_CERTS else \
        out[::max(1, len(out) // X509_MAX_CERTS)][:X509_MAX_CERTS]


def x509_cert_vectors():
    rows = []
    ku_leaf = x_ext("2.5.29.15", True, x_named_bits([0, 2]))
    ku_ca = x_ext("2.5.29.15", True, x_named_bits([5, 6]))
    bc_ca = x_ext("2.5.29.19", True, x_seq(der_tlv(0x01, b"\xff")))
    bc_ca0 = x_ext("2.5.29.19", True, x_seq(der_tlv(0x01, b"\xff"), x_int(0)))
    san = x_ext("2.5.29.17", False, x_seq(SAN_DNS))
    eku = x_ext("2.5.29.37", False, x_seq(x_oid("1.3.6.1.5.5.7.3.1"),
                                          x_oid("1.3.6.1.5.5.7.3.2")))

    # ---------------------------------------------------------------- accepted
    rows.append(cert_row(make_cert(exts=[san]), "v3 RSA leaf with a dNSName", san=SAN_DNS))
    rows.append(cert_row(make_cert(version=1, exts=None), "v1 RSA, no extensions", version=1))
    rows.append(cert_row(make_cert(version=2, exts=None), "v2 RSA, no extensions", version=2))
    rows.append(cert_row(make_cert(spki=x_spki_ec(), alg=x_alg_ecdsa(256), exts=[san]),
                         "P-256 leaf, ecdsa-with-SHA256", key_alg=2, sig_alg=3, sig_hash=1,
                         san=SAN_DNS))
    rows.append(cert_row(make_cert(spki=x_spki_ec("1.3.132.0.34"), alg=x_alg_ecdsa(384),
                                   exts=[san]),
                         "P-384 leaf, ecdsa-with-SHA384", key_alg=3, sig_alg=3, sig_hash=2,
                         san=SAN_DNS, flags=1))
    rows.append(cert_row(make_cert(alg=x_alg_pss(256), exts=[san]),
                         "RSASSA-PSS sha256, salt 32", sig_alg=2, sig_hash=1, salt=32,
                         san=SAN_DNS))
    rows.append(cert_row(make_cert(alg=x_alg_pss(512, salt=0), exts=[san]),
                         "RSASSA-PSS sha512, salt 0", sig_alg=2, sig_hash=3, salt=0, san=SAN_DNS))
    rows.append(cert_row(make_cert(alg=x_alg_rsa_pkcs1(384), exts=[san]),
                         "sha384WithRSAEncryption", sig_hash=2, san=SAN_DNS))
    rows.append(cert_row(make_cert(alg=x_seq(x_oid("1.2.840.113549.1.1.11")), exts=[san]),
                         "sha256WithRSAEncryption with absent parameters: RFC 4055 5 makes "
                         "accepting them a MUST", san=SAN_DNS))
    rows.append(cert_row(make_cert(alg=x_alg_pss(256, salt=20), exts=[san]),
                         "RSASSA-PSS with saltLength omitted, i.e. the DEFAULT 20",
                         sig_alg=2, sig_hash=1, salt=20, san=SAN_DNS))
    rows.append(cert_row(make_cert(alg=x_alg_pss(256, trailer=1), exts=[san]),
                         "RSASSA-PSS with trailerField present at 1: RFC 4055 3.1 tells "
                         "validators to recognise it", sig_alg=2, sig_hash=1, salt=32,
                         san=SAN_DNS))
    rows.append(cert_row(make_cert(exts=[bc_ca, ku_ca], subject="Brisk Test CA"),
                         "CA: basicConstraints cA, keyCertSign + cRLSign",
                         key_usage=KU_KEY_CERT_SIGN | KU_CRL_SIGN, is_ca=1))
    rows.append(cert_row(make_cert(exts=[bc_ca0, ku_ca], subject="Brisk Test CA"),
                         "CA with pathLenConstraint 0",
                         key_usage=KU_KEY_CERT_SIGN | KU_CRL_SIGN, is_ca=1, path_len=0))
    rows.append(cert_row(make_cert(exts=[ku_leaf, san]), "leaf keyUsage dS + kE",
                         key_usage=KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT, san=SAN_DNS))
    rows.append(cert_row(make_cert(exts=[eku, san]), "EKU serverAuth + clientAuth",
                         eku=EKU_SERVER | EKU_CLIENT, san=SAN_DNS))
    rows.append(cert_row(make_cert(exts=[x_ext("2.5.29.37", False, x_seq(x_oid("2.5.29.37.0"))),
                                         san]),
                         "EKU anyExtendedKeyUsage", eku=EKU_ANY, san=SAN_DNS))
    rows.append(cert_row(make_cert(exts=[x_ext("2.5.29.37", True,
                                               x_seq(x_oid("1.3.6.1.5.5.7.3.9"))), san]),
                         "EKU with a purpose this client does not name", eku=EKU_OTHER,
                         san=SAN_DNS))
    rows.append(cert_row(make_cert(subject=None, exts=[x_ext("2.5.29.17", True, x_seq(SAN_DNS))]),
                         "empty subject with a critical SAN (4.2.1.6)", san=SAN_DNS))
    rows.append(cert_row(make_cert(exts=[x_ext("2.5.29.17", False, x_seq(SAN_TWO))]),
                         "SAN with a dNSName and an iPAddress", san=SAN_TWO))
    rows.append(cert_row(make_cert(exts=[san, x_ext("1.3.6.1.4.1.11129.2.4.2", False,
                                                    b"\x04\x02\x00\x01")]),
                         "unknown NON-critical extension is ignored (4.2)", san=SAN_DNS))
    rows.append(cert_row(make_cert(serial=b"\x7f" + b"\xff" * 19, exts=[san]),
                         "a 20-octet serial number (4.1.2.2)", serial=b"\x7f" + b"\xff" * 19,
                         san=SAN_DNS))
    rows.append(cert_row(make_cert(serial=b"\x81", exts=[san]),
                         "a negative serial: non-conforming, kept opaque (4.1.2.2 note)",
                         serial=b"\x81", san=SAN_DNS))
    rows.append(cert_row(make_cert(nbf="20200101000000Z", naf="20991231235959Z", exts=[san]),
                         "GeneralizedTime validity", san=SAN_DNS, nbf="20200101000000Z",
                         naf="20991231235959Z"))
    rows.append(cert_row(make_cert(uids=x_ctx(1, bytes([0]) + b"\xaa", constructed=False) +
                                   x_ctx(2, bytes([0]) + b"\xbb", constructed=False), exts=[san]),
                         "issuerUniqueID and subjectUniqueID, ignored (4.1.2.8)", san=SAN_DNS))
    rows.append(cert_row(make_cert(exts=[x_ext("2.5.29.15", True, x_named_bits([8]))]),
                         "keyUsage decipherOnly alone: bit 8, two octets",
                         key_usage=0x100))

    # ---------------------------------------------------------------- rejected
    def bad(der, note):
        rows.append(cert_row(der, note, reject=1))

    bad(make_cert(exts=[x_ext("2.5.29.30", True, x_seq()), san]),
        "a CRITICAL extension this client does not implement (4.2, nameConstraints)")
    bad(make_cert(exts=[ku_leaf, ku_leaf, san]), "keyUsage twice (4.2)")
    bad(make_cert(exts=[san, san]), "subjectAltName twice (4.2)")
    bad(make_cert(exts=[x_ext("2.5.29.15", True, x_bits(b"", 0)), san]),
        "keyUsage with no bits set (4.2.1.3)")
    bad(make_cert(exts=[x_ext("2.5.29.15", True, x_bits(b"\x80", 0)), san]),
        "keyUsage with trailing zero bits (X.690 11.2.2)")
    bad(make_cert(exts=[x_ext("2.5.29.15", True, x_bits(b"\x00\x40", 6)), san]),
        "keyUsage whose only set bit is 9, above the nine 4.2.1.3 defines")
    bad(make_cert(subject=None, exts=[x_ext("2.5.29.17", False, x_seq(SAN_DNS))]),
        "empty subject with a NON-critical subjectAltName (4.1.2.6)")
    bad(make_cert(subject=None, exts=[bc_ca, ku_ca, x_ext("2.5.29.17", True, x_seq(SAN_DNS))]),
        "a cA certificate with an empty subject (4.1.2.6)")
    bad(make_cert(exts=[x_ext("2.5.29.17", False,
                              x_seq(der_tlv(0x82, b"device.example.com", lenbytes=1)))]),
        "a dNSName with a non-minimal length inside extnValue (X.690 10.1)")
    bad(make_cert(exts=[x_ext("2.5.29.15", True, x_named_bits([5])), san]),
        "keyCertSign without basicConstraints cA (4.2.1.9)")
    bad(make_cert(exts=[x_ext("2.5.29.19", True, x_seq(x_int(0))), san]),
        "pathLenConstraint without cA (4.2.1.9)")
    bad(make_cert(exts=[x_ext("2.5.29.19", True, x_seq(der_tlv(0x01, b"\x00"))), san]),
        "cA encoded as FALSE instead of omitted (X.690 11.5)")
    bad(make_cert(exts=[x_seq(x_oid("2.5.29.17"), der_tlv(0x01, b"\x00"),
                              der_tlv(0x04, x_seq(SAN_DNS)))],),
        "critical encoded as FALSE instead of omitted (X.690 11.5)")
    bad(make_cert(exts=[bc_ca0, x_ext("2.5.29.15", True, x_named_bits([6])), ],),
        "pathLenConstraint with keyUsage that lacks keyCertSign (4.2.1.9)")
    bad(x_seq(x_seq(x_ctx(0, x_int(0)), x_int(1), x_alg_rsa_pkcs1(), x_name("CA"),
                    x_seq(x_time("200101000000Z"), x_time("300101000000Z")), x_name("leaf"),
                    x_spki_rsa()), x_alg_rsa_pkcs1(), x_bits(bytes(64))),
        "version explicitly encoded as v1 (X.690 11.5)")
    bad(make_cert(version=4, exts=[san]), "version 4 does not exist (4.1.2.1)")
    bad(make_cert(version=1, exts=[san]), "extensions in a v1 certificate (4.1.2.9)")
    bad(make_cert(version=1, uids=x_ctx(1, bytes([0]) + b"\xaa", constructed=False)),
        "issuerUniqueID in a v1 certificate (4.1.2.8)")
    bad(make_cert(subject=None, exts=[ku_leaf]),
        "empty subject with no subjectAltName (4.2.1.6)")
    bad(make_cert(subject=None), "empty subject and no extensions at all (4.2.1.6)")
    bad(make_cert(exts=[x_ext("2.5.29.17", True, x_seq())]),
        "empty subjectAltName sequence (4.2.1.6)")
    bad(make_cert(exts=[x_ext("2.5.29.37", False, x_seq()), san]),
        "empty extendedKeyUsage sequence (4.2.1.12)")
    bad(make_cert(issuer=None, exts=[san]), "empty issuer name (4.1.2.4)")
    bad(make_cert(exts=[]), "extensions [3] present but the SEQUENCE is empty")
    bad(make_cert(alg=x_alg_rsa_pkcs1(256), outer_alg=x_alg_rsa_pkcs1(384), exts=[san]),
        "signatureAlgorithm differs from the TBS signature field (4.1.1.2)")
    bad(make_cert(alg=x_alg_pss(256), outer_alg=x_alg_pss(256, salt=31), exts=[san]),
        "signatureAlgorithm differs only in the PSS saltLength (4.1.1.2)")
    bad(make_cert(alg=x_seq(x_oid("1.2.840.113549.1.1.5"), b"\x05\x00"), exts=[san]),
        "sha1WithRSAEncryption (RFC 9325 5.1)")
    bad(make_cert(alg=x_seq(x_oid("1.2.840.10045.4.3.2"), b"\x05\x00"), spki=x_spki_ec(),
                  exts=[san]),
        "ecdsa-with-SHA256 with NULL parameters (RFC 5758 3.2 says absent)")
    bad(make_cert(alg=x_alg_pss(256, mgf_h=384), exts=[san]),
        "RSASSA-PSS whose MGF1 hash differs from the message hash")
    bad(make_cert(alg=x_alg_pss(256, trailer=2), exts=[san]),
        "RSASSA-PSS with trailerField 2 (RFC 4055 3.1: the value MUST be 1)")
    bad(make_cert(alg=x_alg_pss(256, omit_hash=True), exts=[san]),
        "RSASSA-PSS with hashAlgorithm omitted, i.e. the SHA-1 default (RFC 9325 4.5)")
    bad(make_cert(alg=x_alg_pss(256, omit_mgf=True), exts=[san]),
        "RSASSA-PSS with maskGenAlgorithm omitted, i.e. MGF1-SHA1 (RFC 9846 4.3.3)")
    bad(make_cert(alg=x_seq(x_oid("1.2.840.113549.1.1.10"),
                            x_seq(x_ctx(0, x_seq(x_oid("1.3.14.3.2.26"))),
                                  x_ctx(1, x_seq(x_oid("1.2.840.113549.1.1.8"),
                                                 x_seq(x_oid("1.3.14.3.2.26")))),
                                  x_ctx(2, x_int(20)), x_ctx(3, x_int(1)))), exts=[san]),
        "RSASSA-PSS with SHA-1 (RFC 9325 5.1)")
    bad(make_cert(spki=x_seq(x_seq(x_oid("1.2.840.10040.4.1")), x_bits(b"\x02\x01\x01")),
                  exts=[san]), "a DSA public key")
    bad(make_cert(spki=x_spki_ec("1.3.132.0.10"), alg=x_alg_ecdsa(256), exts=[san]),
        "secp256k1: a curve this library does not carry")
    bad(make_cert(spki=x_spki_ec(point=b"\x04" + bytes(63)), alg=x_alg_ecdsa(256), exts=[san]),
        "a P-256 point one octet short")
    bad(make_cert(spki=x_spki_ec(point=b"\x02" + bytes(32)), alg=x_alg_ecdsa(256), exts=[san]),
        "a compressed P-256 point (RFC 5480 2.2)")
    bad(make_cert(spki=x_seq(x_seq(x_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
                             x_bits(x_seq(x_int(3), x_int(65536)), 1)), exts=[san]),
        "subjectPublicKey BIT STRING with unused bits")
    bad(make_cert(spki=x_seq(x_seq(x_oid("1.2.840.113549.1.1.1")),
                             x_bits(x_seq(x_int(3), x_int(65537)))), exts=[san]),
        "rsaEncryption with the NULL parameters absent (RFC 4055 1.2)")
    bad(make_cert(nbf="300101000000Z", naf="200101000000Z", exts=[san]),
        "notBefore after notAfter")
    bad(make_cert(nbf="201301000000Z", exts=[san]), "notBefore in month 13")
    bad(make_cert(nbf="2001010000Z", exts=[san]), "a UTCTime without seconds (4.1.2.5.1)")
    bad(make_cert(exts=[san], sig=bytes(64), sig_unused=1),
        "signatureValue BIT STRING with unused bits")
    bad(make_cert(exts=[san], sig=b""), "an empty signatureValue")
    bad(make_cert(exts=[san]) + b"\x00", "a trailing byte after the certificate")
    bad(make_cert(exts=[x_seq(x_oid("2.5.29.17"), der_tlv(0x04, x_seq(SAN_DNS) + b"\x05\x00"))]),
        "extnValue with a second value after the SAN")
    bad(make_cert(exts=[x_ext("2.5.29.19", True, x_seq(der_tlv(0x01, b"\x01"))), san]),
        "cA encoded as the BER true 0x01 (X.690 11.1)")

    # ---------------------------------------------------------------- real key material
    real = x509_real_spkis()
    for blob, alg, p384, src in real:
        rows.append(cert_row(make_cert(spki=blob, exts=[san],
                                       alg=x_alg_ecdsa(256) if alg != 1 else x_alg_rsa_pkcs1()),
                             f"real SPKI from {src}", key_alg=alg,
                             sig_alg=3 if alg != 1 else 1, sig_hash=1, san=SAN_DNS,
                             flags=p384))
    print(f"  x509: {sum(1 for r in rows if not r[1])} accepted, "
          f"{sum(1 for r in rows if r[1])} rejected, {len(real)} around real keys")
    return rows


# ---------------------------------------------------------------- C emitters
# ------------------------------------------------------------------- X.509 chains (M2)
# The certificates above carry nonsense signatures because a parser does not look at them. A
# chain does, so every certificate below is REALLY signed: small PKIs are built here, each
# signature is produced with the pure-Python signer and then re-verified with the pure-Python
# verifier (py_p256_verify, py_p384_verify, py_pkcs1_verify, py_pss_verify) before it is
# emitted, so a broken signer cannot quietly turn into a C test that passes.
#
# There is no official suite to take these from - x509-limbo is the nearest thing and it is its
# own ROADMAP item. What is here is one row per rule src/x509/chain.c enforces, which is the
# same standard the cert rows are held to.
CHAIN_MAX_CERTS = 9  # leaf + 8, which is one past BRISK__X509_MAX_CHAIN on purpose
CHAIN_CERT_CAP = 2048  # per-cert buffer in g_row; must match tests/test_x509.c CHAIN_CERT_CAP
LIMBO_NOTE_MAX = 128   # a limbo id can be long; cap it so the emitted C string stays legible
# The clock every chain row is judged at unless it says otherwise: inside the 2001..2030
# window the certificates below are built with, and above BRISK_X509_TIME_FLOOR so the walk
# takes the ordinary branch. check_x509_time_config() enforces the second half.
CHAIN_NOW = None  # set in main(), once py_asn1_time exists
# flags bit 1: the row needs BRISK_ENABLE_P384. Bit 2: it needs the validity window to be
# ENFORCED, so a BRISK_X509_TIME_POLICY_INSECURE_NO_TIME build skips it.
# Bit 4: the row runs with a clock BELOW the floor, which only a policy with a fallback can
# accept - STRICT refuses everything there by design.
CHAIN_F_P384, CHAIN_F_TIME, CHAIN_F_UNSET = 1, 2, 4
CHAIN_MAX_ANCHORS = 2
RSA_CHAIN_KEY = None  # (n_hex, e_hex, n, d, k), built once in main()


def py_ec_sign(curve, d, digest, k):
    """(r, s) with the nonce given. FIPS 186-5 6.4.1, leftmost-bits rule of 6.4.

    A nonce of our own choosing is fine here and RFC 6979 would only be noise: these signatures
    are test fixtures over public data, not a demonstration that the signer is safe. What does
    matter is that each one verifies, which the caller checks."""
    n = curve["n"]
    flen = (n.bit_length() + 7) // 8
    z = int.from_bytes(digest[:flen], "big") % n
    R = py_ec_mul(curve, k, (curve["gx"], curve["gy"]))
    if R is None:
        return None
    r = R[0] % n
    s = pow(k, -1, n) * (z + r * d) % n
    return None if r == 0 or s == 0 else (r, s)


def ec_issuer(curve, d, hbits):
    """A signing identity: its SubjectPublicKeyInfo, its AlgorithmIdentifier, and sign(tbs)."""
    n = curve["n"]
    pub = py_ec_mul(curve, d, (curve["gx"], curve["gy"]))
    flen = (n.bit_length() + 7) // 8
    point = b"\x04" + pub[0].to_bytes(flen, "big") + pub[1].to_bytes(flen, "big")
    curve_oid = "1.2.840.10045.3.1.7" if flen == 32 else "1.3.132.0.34"

    state = {}

    def sign(tbs):
        h = HASH[hbits](tbs).digest()
        for i in range(1, 64):
            k = int.from_bytes(hashlib.sha512(b"brisk chain k" + bytes([i]) + tbs).digest(),
                               "big") % n
            if not 1 <= k < n:
                continue
            rs = py_ec_sign(curve, d, h, k)
            if rs is None:
                continue
            sig = rs[0].to_bytes(flen, "big") + rs[1].to_bytes(flen, "big")
            if flen == 32:
                ok = py_p256_verify(point, h, sig) == P256_OK
            else:
                ok = py_p384_verify(point, h, sig) == P384_OK
            if not ok:
                die("chain: an EC signature this file produced does not verify")
            state["rs"] = rs
            return x_seq(x_int(rs[0]), x_int(rs[1]))
        die("chain: no usable EC nonce in 64 tries")

    return {"spki": x_spki_ec(curve_oid, point), "alg": x_alg_ecdsa(hbits), "sign": sign,
            "state": state}


def py_pkcs1_sign(n, d, k, hbits, tbs):
    """RFC 8017 9.2 EMSA-PKCS1-v1_5, then RSASP1 of 8.2.1."""
    di = DIGESTINFO[hbits] + HASH[hbits](tbs).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(di) - 3) + b"\x00" + di
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def py_pss_sign(n, d, k, mod_bits, hbits, slen, tbs):
    """RFC 8017 9.1.1 EMSA-PSS-ENCODE then 8.1.1, with a fixed salt (see py_ec_sign on nonces)."""
    hlen = hbits // 8
    embits = mod_bits - 1
    emlen = (embits + 7) // 8
    mh = HASH[hbits](tbs).digest()
    salt = HASH[hbits](b"brisk chain salt" + mh).digest()[:slen]
    hh = HASH[hbits](bytes(8) + mh + salt).digest()
    db = bytes(emlen - hlen - slen - 2) + b"\x01" + salt
    masked = bytearray(x ^ y for x, y in zip(db, py_mgf1(hbits, hh, len(db))))
    masked[0] &= 0xFF >> (8 * emlen - embits)
    em = bytes(masked) + hh + b"\xbc"
    return mh, pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def rsa_issuer(hbits, pss_salt=None):
    """An RSA signing identity, PKCS#1 v1.5 or - when pss_salt is given - RSASSA-PSS."""
    n_hex, e_hex, n, d, k = RSA_CHAIN_KEY
    mod_bits = n.bit_length()
    e = int(e_hex, 16)

    def sign(tbs):
        if pss_salt is None:
            sig = py_pkcs1_sign(n, d, k, hbits, tbs)
            if py_pkcs1_verify(n, e, hbits, HASH[hbits](tbs).digest(), sig) != RSA_OK:
                die("chain: a PKCS#1 signature this file produced does not verify")
        else:
            mh, sig = py_pss_sign(n, d, k, mod_bits, hbits, pss_salt, tbs)
            if py_pss_verify(n, e, hbits, pss_salt, mh, sig) != RSA_OK:
                die("chain: a PSS signature this file produced does not verify")
        return sig

    alg = x_alg_pss(hbits, salt=pss_salt) if pss_salt is not None else x_alg_rsa_pkcs1(hbits)
    return {"spki": x_spki_rsa(n_hex, e_hex), "alg": alg, "sign": sign}


def x_bc(ca=True, path_len=None):
    """basicConstraints, critical as RFC 5280 4.2.1.9 requires of a CA certificate."""
    inner = (der_tlv(0x01, b"\xff") if ca else b"") + (b"" if path_len is None else x_int(path_len))
    return x_ext("2.5.29.19", True, x_seq(inner))


# BIT NUMBERS of RFC 5280 4.2.1.3, which is what x_named_bits wants - not the KU_* masks above,
# which are the decoded value a cert row carries.
KU_BIT_DIGITAL_SIGNATURE = 0
KU_BIT_KEY_CERT_SIGN = 5


def x_ku(*bits):
    return x_ext("2.5.29.15", True, x_named_bits(list(bits)))


def cert_kw(issuer_name, subject, signer, key, version=3, exts=None, serial=1):
    """Everything about a certificate except its signature, so the same TBS can be emitted
    twice: once really signed, once with a signature a row built to be wrong."""
    return dict(version=version, serial=serial, alg=signer["alg"], issuer=issuer_name,
                subject=subject, spki=key["spki"], exts=exts)


def chain_cert(issuer_name, subject, signer, key, version=3, exts=None, serial=1, **kw):
    """One certificate: `signer` signs it, `key` contributes the subjectPublicKeyInfo. `kw`
    reaches make_cert, which is how a row gives one certificate its own validity window."""
    return make_cert(sign=signer["sign"],
                     **cert_kw(issuer_name, subject, signer, key, version, exts, serial), **kw)


def chain_row(certs, anchors, want, note, flags=0, now=None):
    if len(certs) > CHAIN_MAX_CERTS or len(anchors) > CHAIN_MAX_ANCHORS:
        die(f"chain row '{note}' does not fit the fixed arrays")
    return ([c.hex() for c in certs], [a.hex() for a in anchors], want, flags,
            CHAIN_NOW if now is None else now, note)


def uint_der(v):
    """The contents octets of a DER INTEGER holding the non-negative v (X.690 8.3.2)."""
    n = max(1, (v.bit_length() + 8) // 8)
    return v.to_bytes(n, "big")


def x509_sig_vectors():
    """brisk__x509_signed_by on its own: the two DER parsers it owns, and the pairings it must
    refuse. want: 0 = BRISK_OK, 1 = BRISK_E_AUTH, 2 = BRISK_E_ARG.

    These are the only structures in a certificate the peer controls that brisk__der_walk never
    validates - an ECDSA-Sig-Value and an RSAPublicKey both live inside a BIT STRING, which the
    walk treats as a leaf - so every one of their rejections gets a row. A chain vector cannot
    reach them: it only ever reports that no path was built."""
    rows = []
    root = ec_issuer(P256, 0x5EED0001, 256)
    inter = ec_issuer(P256, 0x5EED0002, 256)
    leaf = ec_issuer(P256, 0x5EED0004, 256)
    ee_ext = [x_bc(False), x_ku(KU_BIT_DIGITAL_SIGNATURE)]
    ca_ext = [x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)]

    kw = cert_kw("Brisk Inter", "device.example.com", inter, leaf, exts=ee_ext)
    good = make_cert(sign=inter["sign"], **kw)
    r, s = inter["state"]["rs"]
    inter_c = chain_cert("Brisk Root", "Brisk Inter", root, inter, exts=ca_ext)
    root_c = chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext)

    def sig_row(sig, want, note):
        rows.append((make_cert(sig=sig, **kw).hex(), inter_c.hex(), want, 0, note))

    rows.append((good.hex(), inter_c.hex(), 0, 0, "the signature the issuer really made"))
    rows.append((good.hex(), root_c.hex(), 1, 0, "the right shape under the wrong key"))
    sig_row(x_seq(x_int(r), x_int(s)) + b"\x00", 2, "a trailing octet after the SEQUENCE")
    sig_row(x_seq(x_int(r)), 2, "an ECDSA-Sig-Value with no s")
    sig_row(der_tlv(0x04, x_int(r) + x_int(s)), 2, "an OCTET STRING instead of a SEQUENCE")
    sig_row(x_seq(der_tlv(0x02, b"\x00" + uint_der(r)), x_int(s)), 2,
            "a non-minimal INTEGER for r (X.690 8.3.2)")
    sig_row(x_seq(der_tlv(0x02, b"\xff" + uint_der(r)[1:]), x_int(s)), 2, "a negative r")
    sig_row(x_seq(der_tlv(0x02, b"\x01" + uint_der(r)), x_int(s)), 2,
            "an r wider than the field")
    sig_row(x_seq(x_int(0), x_int(s)), 1, "r = 0, which FIPS 186-5 6.4.2 calls INVALID")
    sig_row(x_seq(x_int(r), x_int(0)), 1, "s = 0")

    # An RSAPublicKey that is not one. cert.c hands the BIT STRING over without looking inside
    # (read_spki only bounds an EC point), so this reaches rsa_key and nothing earlier.
    rsa_ca = rsa_issuer(256)
    broken = dict(rsa_ca)
    broken["spki"] = x_seq(x_seq(x_oid("1.2.840.113549.1.1.1"), b"\x05\x00"), x_bits(x_seq()))
    rows.append((chain_cert("Brisk RSA", "device.example.com", rsa_ca, leaf, exts=ee_ext).hex(),
                 chain_cert("Brisk RSA", "Brisk RSA", rsa_ca, broken, exts=ca_ext).hex(), 2, 0,
                 "an RSAPublicKey with no modulus"))

    # A P-384 key with a SHA-256 signature: producible per FIPS 186-5, not a pairing RFC 5480 4
    # names, and not one the M1 verifiers take. The signature bytes are never reached.
    p384 = ec_issuer(P384, 0x5EED0006, 384)
    rows.append((make_cert(alg=x_alg_ecdsa(256), issuer="Brisk 384", subject="device.example.com",
                           spki=leaf["spki"], exts=ee_ext).hex(),
                 chain_cert("Brisk 384", "Brisk 384", p384, p384, exts=ca_ext).hex(), 2, 1,
                 "a P-384 key under a SHA-256 signature"))
    print(f"  x509 signatures: {len(rows)} rows")
    return rows


def x509_chain_vectors():
    """One row per rule src/x509/chain.c enforces. want: 0 = BRISK_OK, 1 = BRISK_E_AUTH."""
    rows = []
    root = ec_issuer(P256, 0x5EED0001, 256)
    inter = ec_issuer(P256, 0x5EED0002, 256)
    inter2 = ec_issuer(P256, 0x5EED0003, 256)  # a second CA that shares inter's Name
    leaf = ec_issuer(P256, 0x5EED0004, 256)
    other = ec_issuer(P256, 0x5EED0005, 256)  # never part of any path

    ca_ext = [x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)]
    ee_ext = [x_bc(False), x_ku(KU_BIT_DIGITAL_SIGNATURE)]

    root_c = chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext)
    inter_c = chain_cert("Brisk Root", "Brisk Inter", root, inter, exts=ca_ext)
    leaf_c = chain_cert("Brisk Inter", "device.example.com", inter, leaf, exts=ee_ext)
    alien = chain_cert("Somewhere Else", "unrelated.example", other, other, exts=ca_ext)

    rows.append(chain_row([leaf_c, inter_c], [root_c], 0, "leaf -> intermediate -> root"))
    rows.append(chain_row([leaf_c, alien, inter_c], [root_c], 0,
                          "the intermediate is not the first extra"))
    rows.append(chain_row([leaf_c, inter_c, alien], [root_c, alien], 0,
                          "an unrelated certificate is also trusted"))
    rows.append(chain_row([chain_cert("Brisk Root", "device.example.com", root, leaf,
                                      exts=ee_ext)], [root_c], 0,
                          "the root issued the leaf itself"))
    rows.append(chain_row([leaf_c], [root_c], 1, "the intermediate was not sent"))
    rows.append(chain_row([leaf_c, inter_c], [], 1, "an empty trust store"))
    rows.append(chain_row([leaf_c, inter_c], [alien], 1, "the trust store holds the wrong root"))
    rows.append(chain_row([root_c], [], 1, "a self-signed certificate is not its own anchor"))

    # A tampered signature has to survive the parse to reach the verifier, so flip a bit of the
    # signatureValue - the one field cert.c copies out without looking at it.
    bad_leaf, bad_inter = bytearray(leaf_c), bytearray(inter_c)
    bad_leaf[-1] ^= 0x01
    bad_inter[-1] ^= 0x01
    rows.append(chain_row([bytes(bad_leaf), inter_c], [root_c], 1,
                          "the leaf signature was altered"))
    rows.append(chain_row([leaf_c, bytes(bad_inter)], [root_c], 1,
                          "the intermediate signature was altered"))

    # RFC 5280 6.1.4 (k), (n): what makes a certificate usable as a parent.
    # No keyUsage on this one: cert.c already refuses keyCertSign without cA (4.2.1.9), so
    # asserting both here would test the parser a second time instead of testing 6.1.4 (k).
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=[x_bc(False)])],
                          [root_c], 1, "6.1.4 (k) the intermediate is not a CA"))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter)],
                          [root_c], 1, "6.1.4 (k) the intermediate has no basicConstraints"))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              version=1)],
                          [root_c], 1, "6.1.4 (k) a v1 intermediate is refused"))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=[x_bc(True), x_ku(KU_BIT_DIGITAL_SIGNATURE)])],
                          [root_c], 1, "6.1.4 (n) the intermediate cannot sign certificates"))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=[x_bc(True)])],
                          [root_c], 0, "6.1.4 (n) no keyUsage leaves signing unconstrained"))
    rows.append(chain_row([leaf_c, inter_c],
                          [chain_cert("Brisk Root", "Brisk Root", root, root,
                                      exts=[x_bc(True), x_ku(KU_BIT_DIGITAL_SIGNATURE)])],
                          1, "6.1.4 (n) the same rule applies to the anchor"))

    # 6.1.4 (l), (m): pathLenConstraint counts the non-self-issued certificates BELOW.
    root0 = chain_cert("Brisk Root", "Brisk Root", root, root,
                       exts=[x_bc(True, 0), x_ku(KU_BIT_KEY_CERT_SIGN)])
    root1 = chain_cert("Brisk Root", "Brisk Root", root, root,
                       exts=[x_bc(True, 1), x_ku(KU_BIT_KEY_CERT_SIGN)])
    rows.append(chain_row([leaf_c, inter_c], [root0], 1,
                          "6.1.4 (m) pathLen 0 with an intermediate below"))
    rows.append(chain_row([leaf_c, inter_c], [root1], 0,
                          "6.1.4 (m) pathLen 1 allows exactly that one"))
    rows.append(chain_row([chain_cert("Brisk Root", "device.example.com", root, leaf,
                                      exts=ee_ext)], [root0], 0,
                          "6.1.4 (m) pathLen 0 still issues end entities"))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=[x_bc(True, 0), x_ku(KU_BIT_KEY_CERT_SIGN)])],
                          [root_c], 0, "6.1.4 (m) pathLen 0 on the issuing intermediate"))
    # A self-issued certificate sits in the path but does not consume the budget, so this fits
    # under a pathLen of 1 although three certificates lie between the leaf and the root.
    rows.append(chain_row([leaf_c, chain_cert("Brisk Inter", "Brisk Inter", inter, inter,
                                              exts=ca_ext, serial=9), inter_c],
                          [root1], 0,
                          "6.1.4 (l) a self-issued certificate does not consume the budget"))

    # Two CAs with the same subject Name: only one of them signed the leaf (a key rollover).
    leaf2 = chain_cert("Brisk Inter", "device.example.com", inter2, leaf, exts=ee_ext, serial=2)
    inter2_c = chain_cert("Brisk Root", "Brisk Inter", root, inter2, serial=2, exts=ca_ext)
    rows.append(chain_row([leaf2, inter_c, inter2_c], [root_c], 0,
                          "the wrong same-Name intermediate comes first"))
    rows.append(chain_row([leaf2, inter2_c, inter_c], [root_c], 0,
                          "the right same-Name intermediate comes first"))
    rows.append(chain_row([leaf2, inter_c], [root_c], 1,
                          "only the wrong same-Name intermediate was sent"))

    # A trust anchor is a Name and a key (6.1.1 (d)), not certificate i of 6.1.3, so the
    # version rule of (k) does not reach it - but the other three do, deliberately.
    rows.append(chain_row([leaf_c, inter_c],
                          [chain_cert("Brisk Root", "Brisk Root", root, root, version=1)], 0,
                          "6.1.1 (d) a v1 anchor is still an anchor"))
    rows.append(chain_row([leaf_c, inter_c],
                          [chain_cert("Brisk Root", "Brisk Root", root, root, exts=[x_bc(False)])],
                          1, "a v3 anchor that says cA FALSE means it"))

    # pathLenConstraint two levels up, which is the row that tells `path_len < below` apart
    # from `path_len <= below`: interB may have one certificate under it, and it has two.
    inter_b = ec_issuer(P256, 0x5EED0007, 256)
    b_c = chain_cert("Brisk Root", "Brisk B", root, inter_b,
                     exts=[x_bc(True, 0), x_ku(KU_BIT_KEY_CERT_SIGN)])
    a_c = chain_cert("Brisk B", "Brisk Inter", inter_b, inter, exts=ca_ext)
    rows.append(chain_row([leaf_c, a_c, b_c], [root_c], 1,
                          "6.1.4 (m) pathLen 0 two levels above the end entity"))
    rows.append(chain_row([leaf_c, a_c, chain_cert("Brisk Root", "Brisk B", root, inter_b,
                                                   exts=[x_bc(True, 1),
                                                         x_ku(KU_BIT_KEY_CERT_SIGN)])],
                          [root_c], 0, "6.1.4 (m) pathLen 1 two levels above the end entity"))

    # The depth bound itself: BRISK__X509_MAX_CHAIN is 8, so an end entity with 7 intermediates
    # under an anchor is the longest path that may build, and one more must not.
    def ladder(n):
        """leaf <- I1 <- ... <- In <- root, as a row's certificate list (leaf first)."""
        cas = [ec_issuer(P256, 0x5EED0100 + j, 256) for j in range(n)]
        certs = [chain_cert("CA 0", "device.example.com", cas[0], leaf, exts=ee_ext)]
        for j in range(n):
            up = cas[j + 1] if j + 1 < n else root
            up_name = "CA %d" % (j + 1) if j + 1 < n else "Brisk Root"
            certs.append(chain_cert(up_name, "CA %d" % j, up, cas[j], exts=ca_ext, serial=j + 1))
        return certs

    rows.append(chain_row(ladder(7), [root_c], 0, "the longest path that fits the depth bound"))
    rows.append(chain_row(ladder(8), [root_c], 1, "one certificate past the depth bound"))

    # Loop bait: a certificate that issues itself and is not an anchor. A walk that did not
    # bound itself would follow it forever.
    rows.append(chain_row([chain_cert("Loop", "device.example.com", other, leaf, exts=ee_ext),
                           chain_cert("Loop", "Loop", other, other, exts=ca_ext)],
                          [], 1, "a self-issued cycle terminates"))

    # The other signature families, in the same shape.
    for note, ca, sub in (("RSA PKCS#1 v1.5 throughout", rsa_issuer(256), rsa_issuer(256)),
                          ("RSASSA-PSS throughout", rsa_issuer(256, 32), rsa_issuer(256, 32)),
                          ("an RSA root over an EC intermediate", rsa_issuer(384), inter)):
        rows.append(chain_row(
            [chain_cert("Brisk Inter", "device.example.com", sub, leaf, exts=ee_ext),
             chain_cert("Brisk Root", "Brisk Inter", ca, sub, exts=ca_ext)],
            [chain_cert("Brisk Root", "Brisk Root", ca, ca, exts=ca_ext)], 0, note))

    # P-384, which only a build with BRISK_ENABLE_P384 can follow.
    p384 = ec_issuer(P384, 0x5EED0006, 384)
    rows.append(chain_row(
        [chain_cert("Brisk Inter 384", "device.example.com", inter, leaf, exts=ee_ext),
         chain_cert("Brisk Root 384", "Brisk Inter 384", p384, inter, exts=ca_ext)],
        [chain_cert("Brisk Root 384", "Brisk Root 384", p384, p384, exts=ca_ext)], 0,
        "a P-384 root", flags=1))

    # An EC key cannot verify an RSA signature, whatever the Names say.
    rows.append(chain_row([chain_cert("Brisk Root", "device.example.com", rsa_issuer(256), leaf,
                                      exts=ee_ext)], [root_c], 1,
                          "an RSA signature under an EC anchor key"))

    # 6.1.3 (a)(2): which certificates of the path the window is checked on, which is the half
    # brisk__x509_time_ok cannot answer on its own. The policy itself is x509_validity.inc's job,
    # so every row here runs with a clock above the floor, where all policies bar
    # INSECURE_NO_TIME agree - and that one skips them (CHAIN_F_TIME).
    dead = dict(nbf="200101000000Z", naf="210101000000Z")   # expired long before CHAIN_NOW
    unborn = dict(nbf="400101000000Z", naf="450101000000Z")  # 2040: not valid yet
    rows.append(chain_row([chain_cert("Brisk Inter", "device.example.com", inter, leaf,
                                      exts=ee_ext, **dead), inter_c], [root_c], 1,
                          "6.1.3 (a)(2) an expired end entity", flags=CHAIN_F_TIME))
    rows.append(chain_row([chain_cert("Brisk Inter", "device.example.com", inter, leaf,
                                      exts=ee_ext, **unborn), inter_c], [root_c], 1,
                          "6.1.3 (a)(2) an end entity that is not valid yet", flags=CHAIN_F_TIME))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=ca_ext, **dead)], [root_c], 1,
                          "6.1.3 (a)(2) an expired intermediate", flags=CHAIN_F_TIME))
    # The row that tells "validity filters the candidates" apart from "validity is checked once
    # the walk has committed": both intermediates carry the same Name AND the same key, so both
    # verify the leaf, and the expired one is first. A walk that commits to it has thrown the
    # live one away and fails a chain it was given a complete path for.
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=ca_ext, serial=7, **dead), inter_c],
                          [root_c], 0,
                          "an expired same-Name sibling does not hide the live intermediate"))

    # The state a gateway actually boots into: the RTC reads 0, which is below the floor. Under
    # FLOOR the walk still builds (every certificate here outlives the floor); under STRICT it
    # cannot, which is what CHAIN_F_UNSET skips.
    rows.append(chain_row([leaf_c, inter_c], [root_c], 0,
                          "a clock that was never set still reaches the anchor under FLOOR",
                          flags=CHAIN_F_UNSET, now=0))

    # The anchor is exempt, on purpose and unlike every other rule the walk applies to it: an
    # expired root breaks working devices with no attacker in sight (DST Root CA X3, 2021), and
    # the intermediate below it still has to be current.
    rows.append(chain_row([leaf_c, inter_c],
                          [chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext,
                                      **dead)], 0,
                          "6.1.1 (d) an expired anchor still anchors"))
    rows.append(chain_row([leaf_c, chain_cert("Brisk Root", "Brisk Inter", root, inter,
                                              exts=ca_ext, **dead)],
                          [chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext,
                                      **dead)], 1,
                          "an exempt anchor does not excuse the intermediate under it",
                          flags=CHAIN_F_TIME))

    # BACKTRACKING. Every row above has at most one usable candidate per level, so they pass
    # with a greedy walk too; these are the ones that need the search to come back. The shape is
    # not exotic - it is a CA rollover seen from the client, where two certificates share a
    # subject Name and a key and differ only in who signed them, and the useless one is first on
    # the wire because it is the legacy cross-certificate the server kept for old clients.
    # 0x5EED0008 and not 0007: inter_b above already holds 0007, and one key wearing two
    # identities is how a vector ends up passing for a reason nobody intended.
    root2 = ec_issuer(P256, 0x5EED0008, 256)
    root2_c = chain_cert("Brisk Root 2", "Brisk Root 2", root2, root2, exts=ca_ext)
    # Same subject and same KEY as inter_c, so it verifies the leaf just as well - and then
    # leads nowhere, because nothing anchors or continues "Brisk Nowhere".
    inter_dead = chain_cert("Brisk Nowhere", "Brisk Inter", other, inter, exts=ca_ext, serial=21)
    rows.append(chain_row([leaf_c, inter_dead, inter_c], [root_c], 0,
                          "the first same-Name intermediate dead-ends and the search returns "
                          "for the second"))
    rows.append(chain_row([leaf_c, inter_c, inter_dead], [root_c], 0,
                          "the same pair in the other order, where greedy already worked"))
    inter_dead2 = chain_cert("Brisk Nowhere 2", "Brisk Inter", other, inter, exts=ca_ext,
                             serial=22)
    rows.append(chain_row([leaf_c, inter_dead, inter_dead2], [root_c], 1,
                          "two dead ends and no third candidate is still a refusal"))
    # Two independent backtracks, at two different depths, so the resume index, `below` and the
    # path itself all have to unwind correctly rather than merely not crash. The root level has
    # the same trap as the intermediate level: two certificates with subject "Brisk Root"
    # carrying the root's key, only the second of which reaches the anchor that IS in the store.
    cross_dead = chain_cert("Brisk Nowhere", "Brisk Root", other, root, exts=ca_ext, serial=23)
    cross_live = chain_cert("Brisk Root 2", "Brisk Root", root2, root, exts=ca_ext, serial=24)
    rows.append(chain_row([leaf_c, inter_dead, inter_c, cross_dead, cross_live], [root2_c], 0,
                          "two backtracks at two depths: a dead intermediate AND a dead "
                          "cross-certificate above the live one"))
    rows.append(chain_row([leaf_c, inter_dead, inter_c, cross_dead], [root2_c], 1,
                          "the same list without the live cross-certificate"))
    # `below` has to be RESTORED on the way back, not just incremented on the way down, and
    # nothing above reads it: every row so far uses a CA with no pathLenConstraint, so
    # usable_ca's `path_len >= below` branch is never taken on a row that backtracks. Here the
    # abandoned branch (inter_dead, non-self-issued) would leave below one too high, and the
    # live path then needs every bit of "Brisk B"'s pathLen 1 - so a leaked count refuses a
    # chain the device holds every certificate for. b_c above is the pathLen 0 version of the
    # same identity, which is why this one is built rather than reused.
    b_pl1 = chain_cert("Brisk Root", "Brisk B", root, inter_b,
                       exts=[x_bc(True, 1), x_ku(KU_BIT_KEY_CERT_SIGN)])
    rows.append(chain_row([leaf_c, inter_dead, a_c, b_pl1], [root_c], 0,
                          "6.1.4 (l) below is restored after a backtrack, so pathLen 1 still "
                          "fits"))
    rows.append(chain_row([leaf_c, inter_dead, a_c, b_c], [root_c], 1,
                          "the same shape at pathLen 0, which does not fit either way"))

    print(f"  x509 chains: {sum(1 for r in rows if not r[2])} accepted, "
          f"{sum(1 for r in rows if r[2])} rejected")
    return rows


# ----------------------------------------------------- CA bundles and SPKI pins (M2)
# Three tables, because three separate things can break.
#   x509_bundle.inc  the PEM decoder on its own (brisk__x509_pem_feed), driven by the base64
#                    vectors of RFC 4648 section 10 wrapped in BEGIN/END lines - so the alphabet
#                    and the padding are tested against the RFC rather than against a
#                    certificate that would also pass with a subtly wrong decoder.
#   x509_store.inc   a whole chain verified against a bundle FILE, which is the only thing that
#                    exercises the lazy lookup in src/os/linux_ca.c end to end: open, scan,
#                    match a subject Name, walk `index`, close.
#   x509_pin.inc     brisk__x509_trust.pins: additive, path-members-only, and a selection
#                    predicate rather than a verdict passed after the walk has committed.
BUNDLE_MAX_BLOBS = 7
STORE_MAX_CERTS = 3
PIN_MAX = 3
X509_ANCHOR_MAX = None  # BRISK__X509_ANCHOR_MAX, read from src/brisk_int.h


def check_x509_anchor_max():
    """BRISK__X509_ANCHOR_MAX decides which PEM block is too big to decode, and the oversize row
    below is built to sit exactly one byte past it. Read it rather than repeat it."""
    global X509_ANCHOR_MAX
    src = (ROOT / "src" / "brisk_int.h").read_text()
    m = re.search(r"#\s*define\s+BRISK__X509_ANCHOR_MAX\s+(\d+)", src)
    if not m:
        die("brisk_int.h: no BRISK__X509_ANCHOR_MAX")
    X509_ANCHOR_MAX = int(m.group(1))
    if not 512 <= X509_ANCHOR_MAX <= 1 << 16:
        die(f"brisk_int.h: BRISK__X509_ANCHOR_MAX {X509_ANCHOR_MAX} is not a plausible cap")
    print(f"  brisk_int.h: anchor buffer {X509_ANCHOR_MAX} B")


def pem_block(der, label="CERTIFICATE", cols=64, eol="\n", body=None):
    """One PEM block (RFC 7468 4). `body` overrides the base64, which is how a corrupt or
    oversized block is written."""
    b64 = base64.b64encode(der).decode() if body is None else body
    lines = [b64[i:i + cols] for i in range(0, len(b64), cols)] or [""]
    return f"-----BEGIN {label}-----{eol}" + eol.join(lines) + eol + f"-----END {label}-----{eol}"


def x509_bundle_vectors():
    """(pem text, [decoded blob hex, ...], note) for brisk__x509_pem_feed."""
    rows = []

    def row(pem, blobs, note):
        if len(blobs) > BUNDLE_MAX_BLOBS:
            die(f"bundle row '{note}' does not fit the fixed array")
        rows.append((pem, [b.hex() for b in blobs], note))

    # RFC 4648 section 10, the base64 test vectors, each one made into a block. They are the
    # reason this table exists: they pin the alphabet and every padding length, and "" pins the
    # empty body, which the decoder must hand over as a zero-length block rather than swallow.
    rfc4648 = [(b"", ""), (b"f", "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v"),
               (b"foob", "Zm9vYg=="), (b"fooba", "Zm9vYmE="), (b"foobar", "Zm9vYmFy")]
    for plain, b64 in rfc4648:
        row(pem_block(None, body=b64), [plain],
            "RFC 4648 10: %r is %s" % (plain.decode(), b64 or "an empty body"))
    row("".join(pem_block(None, body=b) for _, b in rfc4648), [p for p, _ in rfc4648],
        "RFC 4648 10: all seven back to back, so one block's padding cannot leak into the next")

    # Real certificates, in the shapes a bundle file actually arrives in.
    root = ec_issuer(P256, 0x5EED0001, 256)
    inter = ec_issuer(P256, 0x5EED0002, 256)
    ca_ext = [x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)]
    root_c = chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext)
    inter_c = chain_cert("Brisk Root", "Brisk Inter", root, inter, exts=ca_ext)
    rsa_c = chain_cert("Brisk RSA", "Brisk RSA", rsa_issuer(256), rsa_issuer(256), exts=ca_ext)

    row(pem_block(root_c), [root_c], "one certificate, the ordinary 64-column wrapping")
    row(pem_block(root_c, cols=76), [root_c], "76-column wrapping, which some exports use")
    row(pem_block(root_c, cols=4), [root_c], "a pathologically short line length")
    row(pem_block(root_c, eol="\r\n"), [root_c], "CRLF line endings (RFC 7468 3)")
    row(pem_block(root_c)[:-1], [root_c], "no newline after the END line")
    row(pem_block(rsa_c), [rsa_c], "an RSA root, the 1.2 KB shape a real bundle is full of")
    row(pem_block(root_c) + pem_block(inter_c), [root_c, inter_c], "two certificates, no filler")
    row("Brisk Root\n==========\n" + pem_block(root_c)
        + "\nBrisk Inter\n===========\n" + pem_block(inter_c), [root_c, inter_c],
        "the subject headers Debian's ca-certificates.crt writes above each certificate")

    # Labels that are not CERTIFICATE. The BEGIN line is matched whole, so none of them opens a
    # block - and the certificate that FOLLOWS is what proves the scan resynchronised rather
    # than merely failed (the lesson of the RFC 9525 multi-entry rows).
    for label in ("RSA PRIVATE KEY", "TRUSTED CERTIFICATE", "X509 CRL", "CERTIFICATE REQUEST"):
        row(pem_block(root_c, label=label) + pem_block(inter_c), [inter_c],
            f"{label} is not a certificate, and the next block still decodes")

    # Damage, always followed by a good certificate for the same reason.
    row(pem_block(None, body="AAAA!AAA") + pem_block(inter_c), [inter_c],
        "a byte outside the base64 alphabet drops its block")
    row(pem_block(root_c).replace("-----END CERTIFICATE-----\n", "") + pem_block(inter_c),
        [root_c, inter_c], "a block with no END line is ended by the next BEGIN, and a body "
                           "that is complete still decodes - the same rule that recovers the "
                           "block after a file truncated mid-write")
    big = base64.b64encode(bytes(X509_ANCHOR_MAX + 1)).decode()
    row(pem_block(None, body=big) + pem_block(inter_c), [inter_c],
        f"a block past BRISK__X509_ANCHOR_MAX ({X509_ANCHOR_MAX} B) is dropped, not truncated")
    # One base64 group short: still a whole number of groups, so it decodes cleanly to a DER
    # that is three bytes shy of a certificate - a silent truncation if nobody parses it.
    short = base64.b64encode(root_c[:-3]).decode()
    row(pem_block(None, body=short) + pem_block(inter_c), [root_c[:-3], inter_c],
        "base64 cut short decodes to a short blob, which is the parser's problem and not the "
        "decoder's")

    # Whitespace inside a body. Not RFC 7468, and accepted anyway: a bundle pasted into a config
    # file arrives indented, and the certificate is verified afterwards regardless.
    b64 = base64.b64encode(root_c).decode()
    row("-----BEGIN CERTIFICATE-----\n"
        + "".join(f"  {b64[i:i + 32]} \n" for i in range(0, len(b64), 32))
        + "-----END CERTIFICATE-----\n", [root_c], "an indented body, spaces and all")
    row("", [], "an empty file yields nothing and must not hang")
    row("no PEM here at all\n" * 8, [], "a file with no block in it")

    print(f"  x509 bundles: {len(rows)} PEM rows")
    return rows


def x509_store_vectors():
    """(pem text, [chain cert hex, ...], want, flags, now, note): a chain against a bundle FILE."""
    rows = []
    root = ec_issuer(P256, 0x5EED0001, 256)
    root2 = ec_issuer(P256, 0x5EED0007, 256)  # a second key under the SAME root Name
    inter = ec_issuer(P256, 0x5EED0002, 256)
    leaf = ec_issuer(P256, 0x5EED0004, 256)
    other = ec_issuer(P256, 0x5EED0005, 256)
    ca_ext = [x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)]
    ee_ext = [x_bc(False), x_ku(KU_BIT_DIGITAL_SIGNATURE)]

    root_c = chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext)
    root2_c = chain_cert("Brisk Root", "Brisk Root", root2, root2, exts=ca_ext, serial=2)
    other_c = chain_cert("Brisk Other", "Brisk Other", other, other, exts=ca_ext)
    inter_c = chain_cert("Brisk Root", "Brisk Inter", root, inter, exts=ca_ext)
    leaf_c = chain_cert("Brisk Inter", "device.example.com", inter, leaf, exts=ee_ext)
    chain = [leaf_c, inter_c]

    def row(pem, certs, want, note):
        if len(certs) > STORE_MAX_CERTS:
            die(f"store row '{note}' does not fit the fixed array")
        rows.append((pem, [c.hex() for c in certs], want, CHAIN_NOW, note))

    row(pem_block(root_c), chain, 0, "the root is in the bundle")
    row(pem_block(other_c) + pem_block(root_c), chain, 0,
        "the root is the SECOND entry, so the scan does not stop at the first subject it sees")
    row("Brisk Other\n" + pem_block(other_c) + "Brisk Root\n" + pem_block(root_c)
        + pem_block(other_c, label="RSA PRIVATE KEY"), chain, 0,
        "headers and a private key between the entries change nothing")
    # Two roots share one subject Name and only the second signed this path: the lookup has to
    # keep walking `index` for the same Name instead of reporting the first hit and stopping.
    row(pem_block(root2_c) + pem_block(root_c), chain, 0,
        "a same-Name root that did not sign this path is walked past, not taken as the answer")
    row(pem_block(other_c), chain, 1, "a bundle without the root")
    row(pem_block(None, body="AAAA!AAA"), chain, 1, "a bundle whose only entry is corrupt")
    row("", chain, 1, "an empty bundle file")
    # The BEGIN line must sit at the start of a line: an indented block is invisible to
    # OpenSSL's PEM_read_bio too, and a root only THIS library can see is a root nobody audited.
    row("  " + pem_block(root_c), chain, 1, "an indented BEGIN line is not a trust anchor")
    row("junk -----BEGIN CERTIFICATE-----\n" + pem_block(root_c)[28:], chain, 1,
        "a BEGIN line that starts mid-line is not a trust anchor either")
    # RFC 5280 6.1.1 (d) exempts the anchor from the validity window, and the bundle is where
    # that decision actually bites: a distro bundle really does carry dead roots (DST Root CA
    # X3, 2021). Locked in ARCHITECTURE.md; this is the end-to-end proof through a real file.
    row(pem_block(chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext,
                             nbf="200101000000Z", naf="210101000000Z")), chain, 0,
        "6.1.1 (d) an expired root in the bundle still anchors")
    print(f"  x509 stores: {sum(1 for r in rows if not r[2])} accepted, "
          f"{sum(1 for r in rows if r[2])} rejected")
    return rows


def x509_pin_vectors():
    """(certs, anchors, pins, want, flags, now, note) for brisk__x509_trust.pins."""
    rows = []
    root = ec_issuer(P256, 0x5EED0001, 256)
    root2 = ec_issuer(P256, 0x5EED0007, 256)
    inter = ec_issuer(P256, 0x5EED0002, 256)
    leaf = ec_issuer(P256, 0x5EED0004, 256)
    other = ec_issuer(P256, 0x5EED0005, 256)
    ca_ext = [x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)]
    ee_ext = [x_bc(False), x_ku(KU_BIT_DIGITAL_SIGNATURE)]

    root_c = chain_cert("Brisk Root", "Brisk Root", root, root, exts=ca_ext)
    root2_c = chain_cert("Brisk Root 2", "Brisk Root 2", root2, root2, exts=ca_ext)
    inter_c = chain_cert("Brisk Root", "Brisk Inter", root, inter, exts=ca_ext)
    leaf_c = chain_cert("Brisk Inter", "device.example.com", inter, leaf, exts=ee_ext)
    other_c = chain_cert("Brisk Other", "Brisk Other", other, other, exts=ca_ext)
    # The DST Root CA X3 shape: the old root is still an anchor, and the peer also ships a
    # cross-certificate that carries the OLD key under a NEW root's signature.
    cross_c = chain_cert("Brisk Root 2", "Brisk Root", root2, root, exts=ca_ext, serial=3)

    def pin(issuer):
        return hashlib.sha256(issuer["spki"]).hexdigest()

    def row(certs, anchors, pins, want, note):
        if len(pins) > PIN_MAX:
            die(f"pin row '{note}' does not fit the fixed array")
        rows.append(([c.hex() for c in certs], [a.hex() for a in anchors], pins, want,
                     CHAIN_NOW, note))

    chain = [leaf_c, inter_c]
    row(chain, [root_c], [], 0, "no pins at all: the ordinary chain verdict is unchanged")
    row(chain, [root_c], [pin(root)], 0, "the anchor's key is pinned")
    row(chain, [root_c], [pin(inter)], 0, "an intermediate ON the path is pinned")
    row(chain, [root_c], [pin(leaf)], 0, "the end entity is pinned")
    row(chain, [root_c], [pin(other), pin(root)], 0,
        "one pin of two matches, which is what a rollover pin set looks like")
    row(chain, [root_c], [pin(other)], 1, "a pin no certificate on the path satisfies")
    # The whole reason pins are checked on path MEMBERS: otherwise a peer satisfies a pin by
    # attaching the pinned certificate to a chain it has nothing to do with.
    row([leaf_c, inter_c, other_c], [root_c], [pin(other)], 1,
        "a pinned certificate the peer merely ATTACHED is not on the path")
    # Additive, structurally: with no trust store there is no path, so no pin can rescue it.
    # The test drives this row with find_anchor == NULL as well, where the anchor list is unused.
    row(chain, [], [pin(leaf)], 1, "pins never stand in for a trust store")
    # A pin that fails at the first anchor must not end the walk: the longer path through the
    # cross-certificate reaches an anchor that IS pinned, and that is the chain to build.
    row([leaf_c, inter_c, cross_c], [root_c, root2_c], [pin(root2)], 0,
        "the pin picks the cross-signed path over the shorter one that does not satisfy it")
    row([leaf_c, inter_c, cross_c], [root_c, root2_c], [pin(other)], 1,
        "the same two paths, neither of them pinned")
    # The KNOWN LIMIT, written down as a vector so it cannot be forgotten and so the day
    # src/x509/chain.c grows a depth-first search this row FAILS and whoever did the work is
    # told to flip it to 0. Two intermediates share a Name and a key, so both verify the leaf;
    # the first chains to the unpinned root and the second to the pinned one. A walk that
    # commits to the first candidate that verifies can never reach the pinned path. This is the
    # real rollover shape - the legacy cross-certificate goes first on the wire - which is
    # exactly why it is worth a row rather than a comment.
    inter_old = chain_cert("Brisk Root", "Brisk Inter", root, inter, exts=ca_ext, serial=11)
    inter_new = chain_cert("Brisk Root 2", "Brisk Inter", root2, inter, exts=ca_ext, serial=12)
    row([leaf_c, inter_old, inter_new], [root_c, root2_c], [pin(root2)], 0,
        "backtracking: the first same-Name intermediate dead-ends at an unpinned root and the "
        "search comes back for the second, which reaches the pinned one")
    # The same three certificates with no pins: here the FIRST candidate does reach an anchor,
    # so the greedy walk is right and this row proves the pair above fails for the pin reason
    # and not because the fixtures do not chain.
    row([leaf_c, inter_old, inter_new], [root_c, root2_c], [], 0,
        "the same three certificates without pins, where the greedy first choice does anchor")
    # The OTHER half of backtracking and pins, and the one that fails OPEN if it breaks: a pin
    # satisfied on a branch the search then ABANDONS must not count for the path it settles on.
    # inter_dead leads only to nowhere_c, whose key is the pinned one; the search commits it,
    # dead-ends one level further, unwinds both levels and comes back for inter_c - which
    # reaches the anchor with nothing pinned on it. Drop the pin_mask clear in chain.c and this
    # row starts returning BRISK_OK while every other row in the suite still passes.
    inter_dead = chain_cert("Brisk Nowhere", "Brisk Inter", other, inter, exts=ca_ext, serial=21)
    nowhere_c = chain_cert("Brisk Dead End", "Brisk Nowhere", other, other, exts=ca_ext)
    row([leaf_c, inter_dead, nowhere_c, inter_c], [root_c], [pin(other)], 1,
        "a pin satisfied only on a branch the search abandons is not satisfied")
    print(f"  x509 pins: {sum(1 for r in rows if not r[3])} accepted, "
          f"{sum(1 for r in rows if r[3])} rejected")  # r[3] is `want`
    return rows


# --------------------------------------------------------------------------------- x509-limbo
# x509-limbo (github.com/C2SP/x509-limbo) is the closest thing to an official test corpus for
# an X.509 path validator. It is FOLDED IN here rather than treated as a KAT set, because it is
# not a KAT set: the tests are not "primitive f(x) = y" rows a Python oracle can recompute,
# they are "validator v({trust, intermediates, leaf, clock}) = SUCCESS | FAILURE" verdicts on
# constructed PKIs. The oracle is the human who wrote each case; the cross-check we can do is
# structural (every fixture must be well-formed DER, every kept row must fit our maxima) and
# semantic (the walk's answer must match the verdict).
#
# Not every limbo case is a fair question to ask brisk__x509_chain_verify. See the src/brisk_int.h
# block above the function for what it enforces and, more importantly, what it does NOT: hostname
# and IP matching, EKU policy at the end entity, name constraints, certificate policies and
# revocation. A limbo case whose verdict rests on one of those answers a question we do not ask
# - "SUCCESS if you enforce name constraints" and "FAILURE if you enforce policies" and so on -
# so a validator that skips it agrees with limbo by accident, and one that adds it disagrees for
# the wrong reason. UNSUPPORTED_FEATURES filters those out by the `features` array x509-limbo
# already tags them with. See tests/kat/SOURCES.md for the running skip tally.
#
# UNSUPPORTED_FEATURES intersects tc["features"]; if the intersection is non-empty the case is
# dropped. `pedantic-*` cases are dropped too: they encode CABF-lint-flavoured verdicts that a
# generic RFC 5280 validator is not obliged to reach.
LIMBO_UNSUPPORTED_FEATURES = frozenset({
    "name-constraints", "name-constraint-dn",
    "has-cert-policies", "has-policy-constraints",
    "has-crl", "has-crl-dp",
    "has-mldsa",  # RFC 9881 post-quantum signatures; not compiled here
    "aki-checks-key-identifier",
    "max-chain-depth",
    "denial-of-service",
    "pedantic-serial-number", "pedantic-public-key",
    "pedantic-public-suffix-wildcard",
    "pedantic-rfc5280",
    "pedantic-webpki", "pedantic-webpki-eku", "pedantic-webpki-subscriber-key",
    "rfc5280-incompatible-with-webpki",
})

# Namespaces whose whole point is a check brisk__x509_chain_verify does not run: name
# constraints (RFC 5280 4.2.1.10), name-based service identity (RFC 9525, brisk__x509_match_host
# owns that), EKU/KU/policy at the end entity, revocation, SKI/AKI byte-comparison, and
# rfc9881 post-quantum signatures. `online::` reaches real Web PKI cert chains that expire on
# their own schedule; a KAT set that changes underneath is worse than none. `bettertls::
# nameconstraints` is 9491 name-constraint-focused cases with no `features` tag to reach.
LIMBO_UNSUPPORTED_ID_PREFIXES = (
    "bettertls::nameconstraints::",
    "crl::",
    "rfc9881::",
    "online::",
    "rfc5280::nc::", "webpki::nc::",
    "rfc5280::san::", "webpki::san::",
    "rfc5280::cn::",  "webpki::cn::",
    "rfc5280::aki::", "webpki::aki::",
    "rfc5280::ski::",
    "rfc5280::eku::", "webpki::eku::",
    "rfc5280::pc",  # policy constraints - one test, "rfc5280::pc"
    "rfc5280::serial::",
    # Validity-boundary cases whose verdict rests on the exact `now` passed. tools/kat.py bumps
    # a below-floor validation_time up to FLOOR + 60s so the row survives to the C tests, so a
    # case that checks whether now == naf accepts or rejects would answer for the clamped time
    # instead of the case's authored one.
    "rfc5280::validity::",
)

# Individual cases whose verdict a stricter WEB PKI (CABF-flavoured) validator would reach and
# an RFC-5280-only validator like brisk__x509_chain_verify would not - kept explicit rather than
# hidden behind a `webpki::` blanket skip, because the rest of that namespace (`forbidden-p192*`,
# `forbidden-dsa*`, `forbidden-weak-rsa*`, `explicit-curve`, `cryptographydotio-chain*`) DOES
# reach the walk correctly. Each entry names the RFC/CABF distinction that puts it here.
LIMBO_UNSUPPORTED_IDS = frozenset({
    "webpki::malformed-aia",                              # AIA syntax; CABF, not RFC 5280
    "webpki::forbidden-rsa-not-divisible-by-8-in-leaf",   # CABF 6.1.5
    "webpki::forbidden-rsa-not-divisible-by-8-in-root",   # CABF 6.1.5
    "webpki::v1-cert",                                    # CABF requires v3 EE; RFC tolerates
    "webpki::ee-basicconstraints-ca",                     # CABF 7.1.2.7.8; RFC does not forbid
    "webpki::ca-as-leaf",                                 # CABF forbids CA cert as EE
    "rfc5280::root-non-critical-basic-constraints",       # RFC MUST-critical; we tolerate
    "rfc5280::root-inconsistent-ca-extensions",           # anchor-side pedantic
    "rfc5280::ca-as-leaf-wrong-san",                      # peer_name mismatch, not chain
    # bettertls pathbuilding cases that rely on the original validation_time. kat.py bumps
    # sub-floor times up to the floor; these are the cases whose certificates expired between
    # the authored time and the floor, so a chain that limbo says builds does not build here.
    "bettertls::pathbuilding::tc5",
    "bettertls::pathbuilding::tc12",
    "bettertls::pathbuilding::tc38",
    "bettertls::pathbuilding::tc44",
})


def x509_limbo_vectors():
    """One row per x509-limbo test case that reaches brisk__x509_chain_verify. Returns rows in
    chain_row shape, so t_limbo in test_x509.c can drive them through the same walk t_chain
    already exercises."""
    data = json.loads(fetch("x509_limbo").decode("utf-8"))
    cases = data.get("testcases") or []
    if not cases:
        die("x509-limbo: limbo.json has no testcases")

    rows = []
    skipped = {}

    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1

    for tc in cases:
        tid = tc.get("id") or "<no-id>"
        if tc.get("validation_kind") != "SERVER":
            skip("validation_kind:non-SERVER"); continue
        pref = next((p for p in LIMBO_UNSUPPORTED_ID_PREFIXES if tid.startswith(p)), None)
        if pref:
            skip("id:" + pref); continue
        if tid in LIMBO_UNSUPPORTED_IDS:
            skip("id:cabf-only"); continue
        blockers = set(tc.get("features") or []) & LIMBO_UNSUPPORTED_FEATURES
        if blockers:
            skip("feature:" + sorted(blockers)[0]); continue
        # The chain_verify signature does not take these callback-shaped policy hooks - they
        # are a job for the caller wrapping it. A case whose verdict depends on the validator
        # enforcing them is not answerable at this layer.
        if tc.get("key_usage") or tc.get("extended_key_usage") or tc.get("signature_algorithms"):
            skip("caller-policy"); continue
        if tc.get("max_chain_depth") is not None:
            skip("max-chain-depth-runtime"); continue

        leaf_pem = tc.get("peer_certificate")
        anchors_pem = tc.get("trusted_certs") or []
        inters_pem = tc.get("untrusted_intermediates") or []
        if not leaf_pem:
            skip("no-peer-certificate"); continue
        if not anchors_pem:
            skip("no-anchors"); continue
        n_certs = 1 + len(inters_pem)
        if n_certs > CHAIN_MAX_CERTS:
            skip("too-many-certs"); continue
        if len(anchors_pem) > CHAIN_MAX_ANCHORS:
            skip("too-many-anchors"); continue

        try:
            leaf = pem_to_der(leaf_pem)
            inters = [pem_to_der(p) for p in inters_pem]
            anchors = [pem_to_der(p) for p in anchors_pem]
        except (ValueError, base64.binascii.Error):
            skip("pem-decode"); continue

        # The FLOOR time policy clamps `now` up to BRISK_X509_TIME_FLOOR; a case with
        # validation_time below the floor gets a different `now` than the case's author
        # intended, and so a different verdict. STRICT does not clamp, but building a table
        # that fires only on STRICT would defeat the point of the FLOOR default carrying it.
        # Drop the row instead - limbo has hundreds; the below-floor slice is not load-bearing.
        vt_text = tc.get("validation_time")
        if vt_text:
            try:
                vt = iso_to_epoch(vt_text)
            except ValueError:
                skip("validation_time-parse"); continue
            # Below the floor the FLOOR policy would clamp `now` up and answer a different
            # question than the case's author intended. Bump `now` to just above the floor and
            # accept the divergence: only cases whose SUCCESS side depends on a cert that
            # expires between vt and FLOOR will disagree, and those show up as t_limbo
            # failures that filter into LIMBO_UNSUPPORTED_IDS below.
            now = max(vt, X509_TIME_FLOOR + 60)
        else:
            now = CHAIN_NOW

        # A cert wider than the g_row buffer would abort t_unhex on load - the row is dropped
        # here so that limit stays a fixture-side check, not a runtime crash.
        oversize = next((d for d in [leaf] + inters + anchors if len(d) > CHAIN_CERT_CAP), None)
        if oversize is not None:
            skip("cert-too-big"); continue

        want = 0 if tc.get("expected_result") == "SUCCESS" else 1
        note = ("limbo:" + tid)[:LIMBO_NOTE_MAX]
        rows.append(chain_row([leaf] + inters, anchors, want, note, flags=2, now=now))

    total = len(cases)
    kept, dropped = len(rows), sum(skipped.values())
    if kept + dropped != total:
        die(f"x509-limbo: kept {kept} + dropped {dropped} != total {total}")
    print(f"  x509-limbo: {kept} rows kept of {total}, {dropped} dropped")
    for reason, count in sorted(skipped.items(), key=lambda x: (-x[1], x[0])):
        print(f"    - {reason}: {count}")
    return rows, skipped


# ------------------------------------------------- X.509 service identity (RFC 9525 names, M2)
# No official suite exists here either: RFC 9525 carries rules and a few illustrative examples,
# never a vector file, and x509-limbo (its own ROADMAP item) is the nearest thing. So this is
# one row per rule src/x509/name.c enforces, with the RFC's own examples folded in where it has
# them, and the SAN written out as the GeneralNames CONTENTS - exactly the bytes cert.c hands
# over in brisk__x509_cert.san. want: 0 = BRISK_OK, 1 = BRISK_E_AUTH (no presented identifier
# matched), 2 = BRISK_E_ARG (the caller's reference identifier is not usable as one).


def gn_dns(s):
    """dNSName [2] IMPLICIT IA5String (RFC 5280 4.2.1.6)."""
    return x_ctx(2, s if isinstance(s, bytes) else s.encode(), constructed=False)


def gn_ip(text):
    """iPAddress [7] IMPLICIT OCTET STRING: 4 octets for IPv4, 16 for IPv6 (RFC 5280 4.2.1.6).
    Python's ipaddress is the oracle for the octets, so a typo here is a crash and not a row
    that quietly tests the wrong address."""
    return x_ctx(7, ipaddress.ip_address(text).packed, constructed=False)


def x509_name_vectors():
    rows = []

    def row(san, host, want, note):
        rows.append((b"".join(san).hex(), host, want, note))

    def dns(*names):
        return [gn_dns(n) for n in names]

    # --- 6.3, exact matching ------------------------------------------------------------------
    row(dns("www.bigcompany.example"), "www.bigcompany.example", 0, "the identifier itself")
    row(dns("www.bigcompany.example"), "WWW.BigCompany.Example", 0,
        "6.3 case-insensitive ASCII, the RFC's own example")
    row(dns("WWW.BigCompany.Example"), "www.bigcompany.example", 0, "and the other way round")
    row(dns("www.bigcompany.example"), "web.bigcompany.example", 1, "6.1.2's rejected example")
    row(dns("www.bigcompany.example"), "bigcompany.example", 1, "a parent is not a match")
    row(dns("bigcompany.example"), "www.bigcompany.example", 1, "nor is a child")
    row(dns("www.bigcompany.example.evil.example"), "www.bigcompany.example", 1,
        "the reference identifier as a PREFIX of a longer presented one")
    row(dns("evil.example.www.bigcompany.example"), "www.bigcompany.example", 1,
        "and as a suffix of one")
    row(dns("a.example", "b.example", "c.example"), "b.example", 0,
        "7.5: any one of several presented identifiers may match")
    row(dns("a.example", "b.example"), "c.example", 1, "...and none of them has to")
    row(dns("my_device.lan"), "my_device.lan", 0,
        "an underscore: not preferred name syntax, but private PKI issues it and nothing in "
        "6.3 turns a label alphabet into a matching rule")
    row(dns("localhost"), "localhost", 0, "a single-label name, which a private PKI does issue")

    # --- 6.3, the wildcard rule ---------------------------------------------------------------
    row(dns("*.bigcompany.example"), "www.bigcompany.example", 0, "the left-most label")
    row(dns("*.bigcompany.example"), "WWW.BigCompany.Example", 0, "a wildcard still folds case")
    row(dns("*.BigCompany.Example"), "www.bigcompany.example", 0, "...from either side")
    row(dns("*.bigcompany.example"), "bigcompany.example", 1,
        "6.3: a wildcard matches ONE label, never zero")
    row(dns("*.bigcompany.example"), "a.b.bigcompany.example", 1, "...and never two")
    row(dns("*.*.bigcompany.example"), "a.b.bigcompany.example", 1,
        "6.3 (1): 'There is only one wildcard character'")
    row(dns("w*.bigcompany.example"), "www.bigcompany.example", 1,
        "6.3 (2): the complete content of the label, not a prefix of it")
    row(dns("*w.bigcompany.example"), "ww.bigcompany.example", 1, "...nor a suffix of it")
    row(dns("www.*.example"), "www.bigcompany.example", 1, "6.3 (2): left-most, not any label")
    row(dns("*"), "example", 1, "a bare wildcard with no label after it")
    row(dns("*."), "example", 1, "...and one with an empty label after it")
    row(dns("*.example"), "www.bigcompany.example", 1, "a wildcard does not waive the suffix")
    row(dns("*.bigcompany.example"), ".bigcompany.example", 2,
        "an empty left-most label in the REFERENCE identifier")
    row(dns("*.bigcompany.example"), "*.bigcompany.example", 2,
        "6.3: 'This specification covers only wildcard characters in presented identifiers'")

    # --- 6.3, presented identifiers that 'MUST be ignored' ------------------------------------
    row([gn_dns(b"")], "bigcompany.example", 1, "an empty dNSName")
    row([gn_dns(b"www.bigcompany.example\x00.evil.example")], "www.bigcompany.example", 1,
        "an embedded NUL: the classic way to make two parsers read two different names")
    row([gn_dns(b"www.bigcompany.example\x00")], "www.bigcompany.example", 1,
        "...including one that only truncates")
    row([gn_dns(b"www.bigcompany.example\n")], "www.bigcompany.example", 1,
        "a trailing control character")
    row([gn_dns(b"www.bigcompany.example ")], "www.bigcompany.example", 1, "a trailing space")
    row([gn_dns(b"www.bigcompany.example.")], "www.bigcompany.example", 1,
        "a trailing root dot, which no CA issues and which would need its own comparison rule")
    row([gn_dns(b".bigcompany.example")], "bigcompany.example", 1, "a leading dot")
    row([gn_dns(b"www..bigcompany.example")], "www.bigcompany.example", 1, "an empty label")
    row([gn_dns("hôtel.example".encode())], "xn--htel-fsa.example", 1,
        "6.3: a U-label is never matched - the comparison is over A-labels only")
    row(dns("xn--htel-fsa.example"), "xn--htel-fsa.example", 0, "...and an A-label is ASCII")
    row(dns("xn--htel-fsa.example"), "hôtel.example", 2,
        "6.3: the caller owes the A-label; this library does not implement IDNA")
    row(dns("a" * 64 + ".example"), "a" * 64 + ".example", 2,
        "a label over 63 octets (RFC 1035 2.3.4)")
    long_name = ".".join(["abcdefgh"] * 29)  # 260 octets
    row(dns(long_name), long_name, 2, "a name over 255 octets (RFC 1035 2.3.4)")
    row([], "www.bigcompany.example", 1, "an empty GeneralNames")
    # 6.3 says an invalid presented identifier "MUST be ignored", which is a statement about
    # what happens NEXT: every row above has the bad entry alone, so it cannot tell "ignored it
    # and kept looking" from "aborted the whole search". These can.
    row([gn_dns(b"*.*.bigcompany.example"), gn_dns("www.bigcompany.example")],
        "www.bigcompany.example", 0,
        "6.3: an invalid presented identifier is IGNORED - the search continues past it")
    row([gn_dns(b"www.bigcompany.example\x00.evil.example"), gn_dns("www.bigcompany.example")],
        "www.bigcompany.example", 0, "...the same for an embedded NUL")
    row([gn_dns("a" * 64 + ".example"), gn_dns("www.bigcompany.example")],
        "www.bigcompany.example", 0, "...and for an over-long label")

    # --- 7.4, spellings of an IPv4 address that are not IP-IDs and must not become DNS-IDs ----
    for text in ("010.0.0.1", "0x7f.0.0.1", "127.1", "2130706433", "1.2.3.4.5", "192.0.2.107.5"):
        row(dns(text), text, 2,
            "7.4: a resolver reads this as an address, so it is not a reference identifier "
            "this library will treat as a name either")
    row(dns("3com.example"), "3com.example", 0, "a leading digit is a label, not an address")
    row(dns("v6.example.1a"), "v6.example.1a", 0, "...and so is a last label that only starts "
                                                  "with one")

    # --- 1.3 and 6.2: only a dNSName carries a DNS-ID -----------------------------------------
    row([x_ctx(1, b"admin@bigcompany.example", constructed=False),
         gn_dns("www.bigcompany.example")], "www.bigcompany.example", 0,
        "an rfc822Name [1] ahead of the match: skipped, not compared")
    row([x_ctx(1, b"www.bigcompany.example", constructed=False)], "www.bigcompany.example", 1,
        "1.3: 'Only check DNS domain names via the subjectAltName extension designed for that "
        "purpose: dNSName'")
    row([x_ctx(6, b"https://www.bigcompany.example/", constructed=False)],
        "www.bigcompany.example", 1, "a URI-ID is not a DNS-ID, and URI-IDs are not implemented")
    row([x_ctx(0, x_seq(x_oid("1.3.6.1.5.5.7.8.7"),
                        x_ctx(0, der_tlv(0x16, b"_imaps.isp.example"))))], "isp.example", 1,
        "an otherName SRV-ID: a constructed entry, skipped whole")
    row([x_ctx(4, x_name("www.bigcompany.example"))], "www.bigcompany.example", 1,
        "a directoryName holding the same string")
    row([x_ctx(4, x_name("www.bigcompany.example")), gn_dns("www.bigcompany.example")],
        "www.bigcompany.example", 0, "...and the walk still reaches the dNSName after it")

    # --- 6.4, IP-IDs --------------------------------------------------------------------------
    row([gn_ip("192.0.2.107")], "192.0.2.107", 0, "6.1.2's IPv4 example")
    row([gn_ip("192.0.2.107")], "192.0.2.108", 1, "6.4 is octet-for-octet")
    row([gn_ip("2001:db8::abcd")], "2001:db8::abcd", 0, "6.1.2's IPv6 example")
    row([gn_ip("2001:db8::abcd")], "2001:DB8:0:0:0:0:0:ABCD", 0,
        "a different text form of the same 16 octets")
    row([gn_ip("192.0.2.107"), gn_dns("www.bigcompany.example")], "www.bigcompany.example", 0,
        "an iPAddress ahead of the dNSName that matches")
    row([gn_dns("192.0.2.107")], "192.0.2.107", 1,
        "7.4: an IP literal is classified ONCE, and a dNSName never answers an IP-ID")
    row([gn_ip("192.0.2.107")], "www.bigcompany.example", 1, "nor an iPAddress a DNS-ID")
    row(dns("*.0.2.107"), "192.0.2.107", 1, "a wildcard never applies to an IP-ID")
    row([x_ctx(7, ipaddress.ip_address("192.0.2.107").packed + b"\xff\xff\xff\xff",
               constructed=False)], "192.0.2.107", 1,
        "an 8-octet iPAddress: a name-constraints CIDR, never a SAN entry (RFC 5280 4.2.1.10)")
    row([x_ctx(7, b"", constructed=False)], "192.0.2.107", 1, "an empty iPAddress")
    row([gn_ip("::ffff:192.0.2.107")], "192.0.2.107", 1,
        "an IPv4-mapped entry is 16 octets and never equals a 4-octet IP-ID")
    row([gn_ip("::ffff:192.0.2.107")], "::ffff:192.0.2.107", 0,
        "...but it does equal the literal that produced it")
    row([gn_ip("192.0.2.107")], "192.0.2.107.", 0,
        "one trailing root dot comes off the reference identifier BEFORE it is classified, so "
        "this is still an IP-ID")
    row([gn_dns("192.0.2.107")], "192.0.2.107.", 1, "...and still never a DNS-ID")

    print(f"  x509 names: {sum(1 for r in rows if r[2] == 0)} matches, "
          f"{sum(1 for r in rows if r[2] != 0)} refusals")
    return rows


def x509_ip_vectors():
    """brisk__x509_parse_ip on its own. Python's ipaddress is the oracle for every ACCEPTED
    row - the octets below are its output, not typed by hand. The rejects are a local profile
    and are deliberately NOT cross-checked against it: ipaddress takes scope identifiers
    (fe80::1%eth0) and this parser must not, because no certificate can carry a zone."""
    rows = []
    ok = ["0.0.0.0", "255.255.255.255", "192.0.2.107", "1.2.3.4", "127.0.0.1",
          "::", "::1", "2001:db8::abcd", "2001:0db8:0000:0000:0000:0000:0000:abcd",
          "2001:DB8::ABCD", "fe80::1", "1:2:3:4:5:6:7:8", "1::8", "1:2:3:4:5:6:7::",
          "::2:3:4:5:6:7:8", "::ffff:192.0.2.107", "64:ff9b::192.0.2.107",
          "1:2:3:4:5:6:1.2.3.4"]
    for text in ok:
        rows.append((text, ipaddress.ip_address(text).packed.hex(), "accepted"))

    bad = [
        ("", "the empty string"),
        ("1.2.3", "three groups"),
        ("1.2.3.4.5", "five"),
        ("1.2.3.4.", "a trailing dot"),
        (".1.2.3.4", "a leading dot"),
        ("1..2.3", "an empty group"),
        ("1.2.3.256", "a group over 255"),
        ("1.2.3.4444", "a group of four digits"),
        ("01.2.3.4", "a leading zero, which some resolvers read as octal (7.4)"),
        ("1.2.3.04", "...in any group"),
        ("1.2.3.+4", "a sign"),
        (" 1.2.3.4", "a leading space"),
        ("1.2.3.4 ", "a trailing space"),
        ("0x7f.0.0.1", "hexadecimal"),
        ("1.2.3.4:443", "a port"),
        (":", "a lone colon"),
        (":::", "three colons"),
        (":1:2:3:4:5:6:7:8", "one leading colon"),
        ("1:2:3:4:5:6:7:8:", "one trailing colon"),
        ("1:2:3:4:5:6:7:8:9", "nine groups"),
        ("1:2:3:4:5:6:7", "seven groups and no ::"),
        ("1::2::3", "two :: runs"),
        ("1:2:3:4:5:6:7:8::", ":: standing for no group at all"),
        ("12345::", "a group of five hex digits"),
        ("1::g", "a non-hex digit"),
        ("fe80::1%eth0", "a scope identifier"),
        ("[2001:db8::1]", "the URI bracket form (RFC 3986 3.2.2)"),
        ("::ffff:1.2.3", "a short IPv4 tail"),
        ("::ffff:192.0.2.107:1", "an IPv4 tail that is not last"),
        ("1:2:3:4:5:6:7:1.2.3.4", "an IPv4 tail one group too far"),
        ("www.example", "a host name"),
    ]
    for text, note in bad:
        rows.append((text, "", note))
    print(f"  x509 ip literals: {len(ok)} accepted, {len(bad)} rejected")
    return rows


# ---------------------------------------------------------------- TLS 1.3 handshake engine (M3)
# Everything tests/test_tls13_hs.c replays: the RFC 8448 traces as message flows with every secret
# re-derived here, a synthetic ECDSA/RSA-PSS server for the production auth path (the RFC 8448
# server key is RSA-1024 and chains to nothing), a mutation table whose alerts each cite the RFC
# 9846 section that fixes them, and Wycheproof signatures and key shares routed through the
# CertificateVerify and key_share code.
ALERT = {"unexpected_message": 10, "handshake_failure": 40, "bad_certificate": 42,
         "unsupported_certificate": 43, "illegal_parameter": 47, "unknown_ca": 48,
         "decode_error": 50, "decrypt_error": 51, "protocol_version": 70, "internal_error": 80,
         "missing_extension": 109, "unsupported_extension": 110}
TLS13_F_TIME = 1  # the verdict depends on BRISK_X509_TIME_POLICY (INSECURE_NO_TIME connects)
# The offer brisk__tls13_ch_write makes by default in a build with BRISK_ENABLE_P384 (the C test
# passes these lists explicitly, so the byte comparison holds in every profile).
TLS13_SUITES = [0x1303, 0x1301, 0x1302]
TLS13_GROUPS = [0x001d, 0x0017]
TLS13_SIGS = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]
RFC9846 = {}


def t_u16(v):
    return v.to_bytes(2, "big")


def t_v8(b):
    return bytes([len(b)]) + b


def t_v16(b):
    return len(b).to_bytes(2, "big") + b


def t_v24(b):
    return len(b).to_bytes(3, "big") + b


def t_msg(typ, body):
    """A handshake message: msg_type(1) || uint24 length || body (RFC 9846 4)."""
    return bytes([typ]) + t_v24(body)


def t_body(msg, typ):
    if not msg or msg[0] != typ or int.from_bytes(msg[1:4], "big") != len(msg) - 4:
        die(f"tls13: not a well-formed handshake message of type {typ}")
    return msg[4:]


def t_exts_parse(b):
    out, i = [], 0
    while i + 4 <= len(b):
        t, n = int.from_bytes(b[i:i + 2], "big"), int.from_bytes(b[i + 2:i + 4], "big")
        out.append([t, b[i + 4:i + 4 + n]])
        i += 4 + n
    if i != len(b):
        die("tls13: malformed extension block in a trace message")
    return out


def t_exts_build(exts):
    return t_v16(b"".join(t_u16(t) + t_v16(d) for t, d in exts))


def t_ext(exts, t):
    return next((d for tt, d in exts if tt == t), None)


def t_hello_parse(msg):
    """ServerHello / HelloRetryRequest (RFC 9846 4.2.3) as a dict that t_hello_build inverts."""
    b = t_body(msg, 2)
    sl = b[34]
    i = 35 + sl
    el = int.from_bytes(b[i + 3:i + 5], "big")
    if i + 5 + el != len(b):
        die("tls13: trailing bytes after a ServerHello")
    return {"ver": b[:2], "random": b[2:34], "sid": b[35:i], "suite": b[i:i + 2], "comp": b[i + 2],
            "exts": t_exts_parse(b[i + 5:])}


def t_hello_build(h, **kw):
    h = dict(h, **kw)
    ext = b"" if h["exts"] is None else t_exts_build(h["exts"])  # None: no extensions field
    return t_msg(2, h["ver"] + h["random"] + t_v8(h["sid"]) + h["suite"] + bytes([h["comp"]])
                 + ext)


def t_ch_parse(msg):
    b = t_body(msg, 1)
    sl = b[34]
    i = 35 + sl
    cl = int.from_bytes(b[i:i + 2], "big")
    suites = b[i + 2:i + 2 + cl]
    i += 2 + cl
    i += 1 + b[i]
    el = int.from_bytes(b[i:i + 2], "big")
    if i + 2 + el != len(b):
        die("tls13: trailing bytes after a ClientHello")
    return {"sid": b[35:35 + sl], "suites": suites, "exts": t_exts_parse(b[i + 2:])}


def t_alpn(names):
    """RFC 7301 3.1 ProtocolName entries without the outer uint16: the brisk__tls13_ch_params form."""
    return b"".join(t_v8(n) for n in names)


def t_ch(random, sid, suites, groups, sigs, share_group, share_pub, sni=b"", cookie=b"", alpn=b"",
         modes=False, psk=None):
    """The ClientHello brisk__tls13_ch_write produces, field for field and in the same extension
    order (RFC 9846 4.2.2), so the C builder is byte-compared against this, not only
    round-tripped through its own parser. psk = (identity, obfuscated_ticket_age, HashLen): the
    pre_shared_key extension goes LAST (4.3.11) with a binder of HashLen zero bytes, which
    t_binder_fill (and the C engine) replace."""
    exts = []
    if sni:
        exts.append((0, t_v16(b"\x00" + t_v16(sni))))  # RFC 6066 3: host_name(0)
    exts.append((10, t_v16(b"".join(t_u16(g) for g in groups))))
    exts.append((13, t_v16(b"".join(t_u16(s) for s in sigs))))
    if alpn:
        exts.append((16, t_v16(alpn)))  # RFC 7301 3.1
    exts.append((43, t_v8(t_u16(0x0304))))
    if cookie:
        exts.append((44, t_v16(cookie)))
    if modes:
        exts.append((45, t_v8(b"\x01")))  # RFC 9846 4.3.9: [psk_dhe_ke] only
    exts.append((51, t_v16(t_u16(share_group) + t_v16(share_pub))))
    if psk:
        ident, age, hl = psk
        exts.append((41, t_v16(t_v16(ident) + age.to_bytes(4, "big")) + t_v16(t_v8(bytes(hl)))))
    return t_msg(1, t_u16(0x0303) + random + t_v8(sid)
                 + t_v16(b"".join(t_u16(s) for s in suites)) + b"\x01\x00" + t_exts_build(exts))


def t_th(bits, msgs):
    """Transcript-Hash(M1 || ... || Mn), RFC 9846 4.1."""
    return HASH[bits](b"".join(msgs)).digest()


def t_message_hash(bits, ch1):
    """The synthetic message_hash(254) that replaces ClientHello1 after an HRR (RFC 9846 4.1)."""
    return t_msg(254, HASH[bits](ch1).digest())


def t_cv_content(th):
    return b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + th  # RFC 9846 4.5.2


def t_binder(bits, psk, th):
    """RFC 9846 4.3.11.2 + 7.1: a PskBinderEntry is a Finished MAC (4.5.3) under
    binder_key = Derive-Secret(HKDF-Extract(0, PSK), "res binder", "")."""
    hl, H = bits // 8, HASH[bits]
    early = py_hkdf_extract(bits, bytes(hl), psk)
    bk = py_expand_label(bits, early, b"res binder", H(b"").digest(), hl)
    return hmac.new(py_expand_label(bits, bk, b"finished", b"", hl), th, H).digest()


def t_binder_fill(bits, psk, prefix, ch):
    """ch (one binder of HashLen, last) with its binder computed over Transcript-Hash(prefix ||
    Truncate(ch)), Truncate dropping the binders list (2 + 1 + HashLen bytes)."""
    hl = bits // 8
    th = HASH[bits](b"".join(prefix) + ch[:-(3 + hl)]).digest()
    return ch[:-hl] + t_binder(bits, psk, th)


def t_flow(bits, dhe, pre, sh, ee, cr, cert, cv, psk=None, client=None):
    """The RFC 9846 7.1 key schedule, both Finished MACs (4.5.3) and the client flight of one
    handshake, from nothing but its messages. `pre` is [CH], or [message_hash, HRR, CH2].
    psk: the resumption PSK the ServerHello selected (no Certificate/CertificateVerify then).
    client(msgs): the client's Certificate [+ CertificateVerify] answering `cr`, given the
    transcript up to the server Finished; None answers with an empty Certificate."""
    hl, H = bits // 8, HASH[bits]
    zeros, empty = bytes(hl), H(b"").digest()
    early = py_hkdf_extract(bits, zeros, psk or zeros)
    hs = py_hkdf_extract(bits, py_expand_label(bits, early, b"derived", empty, hl), dhe)
    t_sh = pre + [sh]
    th_sh = t_th(bits, t_sh)
    c_hs = py_expand_label(bits, hs, b"c hs traffic", th_sh, hl)
    s_hs = py_expand_label(bits, hs, b"s hs traffic", th_sh, hl)
    ms = py_hkdf_extract(bits, py_expand_label(bits, hs, b"derived", empty, hl), zeros)
    t_cert = t_sh + [ee] + ([cr] if cr else []) + ([cert] if cert else [])
    tbs = t_cv_content(t_th(bits, t_cert)) if cert else b""
    t_cv = t_cert + ([cv] if cv else [])
    sf = hmac.new(py_expand_label(bits, s_hs, b"finished", b"", hl), t_th(bits, t_cv), H).digest()
    t_sf = t_cv + [t_msg(20, sf)]
    th_sf = t_th(bits, t_sf)
    # A CertificateRequest is answered with the device chain + CertificateVerify, or with an
    # empty Certificate when no suitable key is configured (RFC 9846 4.5.1); the client Finished
    # covers whatever was sent.
    flight = (client(t_sf) if client else [t_msg(11, b"\x00" + t_v24(b""))]) if cr else []
    cf = hmac.new(py_expand_label(bits, c_hs, b"finished", b"", hl), t_th(bits, t_sf + flight),
                  H).digest()
    t_cf = t_sf + flight + [t_msg(20, cf)]
    return {"c_hs": c_hs, "s_hs": s_hs, "tbs": tbs, "sf": t_msg(20, sf),
            "cf": b"".join(flight) + t_msg(20, cf), "th_sh": th_sh, "th_sf": th_sf,
            "th_cf": t_th(bits, t_cf),
            "c_ap": py_expand_label(bits, ms, b"c ap traffic", th_sf, hl),
            "s_ap": py_expand_label(bits, ms, b"s ap traffic", th_sf, hl),
            "exp": py_expand_label(bits, ms, b"exp master", th_sf, hl),
            "res": py_expand_label(bits, ms, b"res master", t_th(bits, t_cf), hl)}


def t_dhe(group, priv, share):
    if group == 0x001d:
        z = py_x25519(priv, share)
        return None if z == bytes(32) else z
    return py_p256_ecdh(int.from_bytes(priv, "big"), share)


def t_suite_bits(sh):
    return 384 if t_hello_parse(sh)["suite"] == b"\x13\x02" else 256


def t_row(note, fl, *, ch1, priv1, g1, sh, ee, cert, cv, root=b"", host="", now=0, flags=0,
          alert=0, hrr=b"", ch2=b"", priv2=b"", g2=0, cr=b"", cookie=b"", psk=b"", psk_suite=0,
          resumed=0, alpn="", cchain=b"", ckey=b"", srand=b""):
    return (note, root.hex(), host, now, flags, alert, g1, priv1.hex(), ch1.hex(), hrr.hex(), g2,
            priv2.hex(), ch2.hex(), cookie.hex(), sh.hex(), ee.hex(), cr.hex(), cert.hex(), cv.hex(),
            fl["sf"].hex(), fl["cf"].hex(), fl["s_hs"].hex(),
            fl["c_hs"].hex(), fl["s_ap"].hex(), fl["c_ap"].hex(), fl["exp"].hex(), fl["res"].hex(),
            fl["tbs"].hex(), psk.hex(), psk_suite, resumed, alpn, cchain.hex(), ckey.hex(),
            srand.hex())


def rfc9846_constants():
    """RFC 9846 4.2.3 (the HRR random and both DOWNGRD sentinels) and 4.5.2 (the worked
    CertificateVerify content), parsed out of the RFC text, never typed."""
    text = "\n".join(rfc_lines(fetch("rfc9846")))
    s423 = text[text.index("\n4.2.3.  Server Hello\n"):text.index("\n4.2.4.  Hello Retry Request\n")]
    i = s423.index('SHA-256 of "HelloRetryRequest":')
    hrr = hexbytes(s423[i + 31:s423.index("Upon receiving", i)])
    if hrr != hashlib.sha256(b"HelloRetryRequest").digest():
        die("RFC 9846 4.2.3: the HRR random is not SHA-256(\"HelloRetryRequest\")")
    down = [hexbytes(m) for m in re.findall(r"bytes:\s*\n((?:\s*[0-9A-F]{2})+)\s*\n", s423)]
    if down != [b"DOWNGRD\x01", b"DOWNGRD\x00"]:
        die(f"RFC 9846 4.2.3: DOWNGRD sentinels parsed as {down}")
    s452 = text[text.index("\n4.5.2.  Certificate Verify\n"):text.index("\n4.5.3.  Finished\n")]
    i = s452.index("CertificateVerify would be:")
    cv = hexbytes(s452[i + 27:s452.index("On the sender side", i)])
    if cv != t_cv_content(b"\x01" * 32):
        die("RFC 9846 4.5.2: the worked CertificateVerify content does not match the rule")
    RFC9846.update(hrr=hrr, down1=down[0], down0=down[1])
    # The client-context variant of the same worked example (4.5.2's formula): generated.
    cv_client = cv.replace(b"server CertificateVerify", b"client CertificateVerify")
    if cv_client == cv:
        die("RFC 9846 4.5.2: the server context string was not found")
    return [(hrr.hex(), down[0].hex(), down[1].hex(), (b"\x01" * 32).hex(), cv.hex(),
             cv_client.hex())]


def tls13_traces():
    """RFC 8448 sections 3, 5, 6 and 7 as flows, every secret and both Finished MACs re-derived
    from the messages alone and compared against what the trace printed."""
    secs = {}
    for b in rfc8448_blocks():
        secs.setdefault(b["_sec"], []).append(b)
    ks_src = (ROOT / "tests" / "test_tls13_ks.c").read_text()
    rows, parts = [], []
    for sec, note in ((3, "RFC 8448 sect 3: simple 1-RTT"),
                      (5, "RFC 8448 sect 5: HelloRetryRequest, x25519 -> secp256r1"),
                      (6, "RFC 8448 sect 6: CertificateRequest answered with an empty Certificate"),
                      (7, "RFC 8448 sect 7: compatibility mode, 32-byte session id")):
        msgs, keys, want = {"client": [], "server": []}, [], {}
        for b in secs[sec]:
            f = {k: hexbytes(v) for k, v in b["_f"].items()}
            m = re.match(r"construct an? (\w+) handshake message", b["_h"])
            if m:
                msgs[b["_side"]].append((m.group(1), f[m.group(1)]))
            m = re.match(r"create an ephemeral (x25519|P-256) key pair", b["_h"])
            if m and b["_side"] == "client":
                keys.append((0x001d if m.group(1) == "x25519" else 0x0017, f["private key"]))
            m = re.match(r'derive secret "tls13 (c hs traffic|s hs traffic|c ap traffic|'
                         r's ap traffic|exp master|res master)"', b["_h"])
            if m and "expanded" in f:
                want.setdefault(m.group(1), (f["expanded"], f["hash"]))
        one = lambda side, name: next((v for n, v in msgs[side] if n == name), b"")
        chs = [v for n, v in msgs["client"] if n == "ClientHello"]
        shs = [v for n, v in msgs["server"] if n == "ServerHello"]
        hrr, sh = (shs[0] if len(shs) == 2 else b""), shs[-1]
        ee, cr, cert, cv, sf = (one("server", n) for n in (
            "EncryptedExtensions", "CertificateRequest", "Certificate", "CertificateVerify",
            "Finished"))
        if len(chs) != (2 if hrr else 1) or len(keys) != len(chs) or not (ee and cert and cv and sf):
            die(f"RFC 8448 sect {sec}: unexpected message set")
        cookie = b""
        if hrr:
            h = t_hello_parse(hrr)
            if h["random"] != RFC9846["hrr"]:
                die("RFC 8448 sect 5: the HRR random is not the RFC 9846 4.2.3 constant")
            c = t_ext(h["exts"], 44)
            if c is None or t_ext(t_ch_parse(chs[1])["exts"], 44) != c:
                die("RFC 8448 sect 5: CH2 does not echo the HRR cookie")
            cookie = c[2:]
        bits = t_suite_bits(sh)
        ks = t_ext(t_hello_parse(sh)["exts"], 51)
        g = int.from_bytes(ks[:2], "big")
        if keys[-1][0] != g:
            die(f"RFC 8448 sect {sec}: the server share is not in the client's last group")
        pre = [t_message_hash(bits, chs[0]), hrr, chs[1]] if hrr else [chs[0]]
        fl = t_flow(bits, t_dhe(g, keys[-1][1], ks[4:]), pre, sh, ee, cr, cert, cv)
        if fl["sf"] != sf:
            die(f"RFC 8448 sect {sec}: server Finished mismatch")
        for name, k in (("c hs traffic", "c_hs"), ("s hs traffic", "s_hs"),
                        ("c ap traffic", "c_ap"), ("s ap traffic", "s_ap"), ("exp master", "exp")):
            if want[name][0] != fl[k]:
                die(f"RFC 8448 sect {sec}: {name} mismatch")
        if want["c hs traffic"][1] != fl["th_sh"] or want["c ap traffic"][1] != fl["th_sf"]:
            die(f"RFC 8448 sect {sec}: transcript hash mismatch")
        if sec == 6:
            # The trace's client answers with an RSA certificate this library cannot produce,
            # so from the client flight on the values are ours, computed by the same cascade.
            if not cr or one("client", "Finished") == fl["cf"][-36:]:
                die("RFC 8448 sect 6: expected a CertificateRequest and a diverging flight")
        elif fl["cf"] != one("client", "Finished") or want["res master"] != (fl["res"], fl["th_cf"]):
            die(f"RFC 8448 sect {sec}: client Finished / res master mismatch")
        if sec == 3:
            for name, v in (("TH_CH_SH", fl["th_sh"]), ("TH_CH_SF", fl["th_sf"]),
                            ("TH_CH_CF", fl["th_cf"])):
                m = re.search(name + r' = "([0-9a-f]{64})"', ks_src)
                if not m or m.group(1) != v.hex():
                    die(f"RFC 8448 sect 3: {name} disagrees with tests/test_tls13_ks.c")
        kw = dict(ch1=chs[0], priv1=keys[0][1], g1=keys[0][0], sh=sh, ee=ee, cr=cr, cert=cert,
                  cv=cv)
        if hrr:
            kw.update(hrr=hrr, ch2=chs[1], priv2=keys[1][1], g2=keys[1][0], cookie=cookie)
        rows.append(t_row(note, fl, **kw))
        parts.append(dict(kw, sf=sf, nst=one("server", "NewSessionTicket")))
    print(f"  tls13 traces: {len(rows)} RFC 8448 flows re-derived")
    return rows, parts


def tls13_fixture():
    """A P-256 root, a leaf for device.example.com, and whole server flights signed with them:
    the only end-to-end run of brisk__tls13_auth_x509, because the RFC 8448 server key is
    RSA-1024 and chains to nothing. The ECDSA nonces are the chain fixtures' (see py_ec_sign)."""
    root = ec_issuer(P256, 0x7153E001, 256)
    leaf = ec_issuer(P256, 0x7153E002, 256)
    rogue = ec_issuer(P256, 0x7153E003, 256)
    rsa_leaf = rsa_issuer(256, pss_salt=32)
    ca_ext = [x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)]

    def leaf_cert(host="device.example.com", ku=KU_BIT_DIGITAL_SIGNATURE,
                  eku="1.3.6.1.5.5.7.3.1", key=leaf, **kw):
        exts = [x_bc(False), x_ku(ku), x_ext("2.5.29.17", False, x_seq(gn_dns(host))),
                x_ext("2.5.29.37", False, x_seq(x_oid(eku)))]
        return chain_cert("Brisk TLS Root", "device.example.com", root, key, exts=exts, **kw)

    root_c = chain_cert("Brisk TLS Root", "Brisk TLS Root", root, root, exts=ca_ext)
    rogue_c = chain_cert("Brisk TLS Root", "Brisk TLS Root", rogue, rogue, exts=ca_ext)
    seed = lambda tag: hashlib.sha256(b"brisk tls13 fixture " + tag).digest()
    c_priv, s_priv, sid = seed(b"client x25519"), seed(b"server x25519"), seed(b"session id")
    c_pub, s_pub = py_x25519(c_priv, X25519_BASE), py_x25519(s_priv, X25519_BASE)
    ch = t_ch(seed(b"client random"), sid, TLS13_SUITES, TLS13_GROUPS, TLS13_SIGS, 0x001d, c_pub,
              b"device.example.com")
    rows = []

    def flight(note, alert, cert_der=None, anchor=root_c, scheme=0x0403, signer=leaf,
               wrong_th=False, mangle=None, suite=0x1301, flags=0):
        cert_der = cert_der or leaf_cert()
        sh = t_msg(2, t_u16(0x0303) + seed(b"server random") + t_v8(sid) + t_u16(suite) + b"\x00"
                   + t_exts_build([(43, t_u16(0x0304)), (51, t_u16(0x001d) + t_v16(s_pub))]))
        ee = t_msg(8, t_exts_build([(0, b"")]))  # an empty server_name: RFC 6066 3
        cert = t_msg(11, b"\x00" + t_v24(t_v24(cert_der) + t_v16(b"")))
        bits = 384 if suite == 0x1302 else 256
        th = t_th(bits, [ch, sh, ee, cert])
        sig = signer["sign"](t_cv_content(bytes(bits // 8) if wrong_th else th))
        if mangle:
            sig = mangle(sig)
        cv = t_msg(15, t_u16(scheme) + t_v16(sig))
        fl = t_flow(bits, py_x25519(c_priv, s_pub), [ch], sh, ee, b"", cert, cv)
        rows.append(t_row(note, fl, ch1=ch, priv1=c_priv, g1=0x001d, sh=sh, ee=ee, cert=cert,
                          cv=cv, root=anchor, host="device.example.com", now=CHAIN_NOW,
                          flags=flags, alert=ALERT[alert] if alert else 0))

    flight("fixture: P-256 leaf, ecdsa_secp256r1_sha256, TLS_AES_128_GCM_SHA256", None)
    flight("fixture: TLS_AES_256_GCM_SHA384 (SHA-384 transcript)", None, suite=0x1302)
    flight("fixture: TLS_CHACHA20_POLY1305_SHA256", None, suite=0x1303)
    flight("fixture: RSA-2049 leaf, rsa_pss_rsae_sha256 (sLen = hLen)", None,
           cert_der=leaf_cert(key=rsa_leaf), scheme=0x0804, signer=rsa_leaf)
    flight("RFC 9525 6.3: the leaf names another host -> bad_certificate", "bad_certificate",
           cert_der=leaf_cert(host="other.example.com"))
    flight("RFC 9846 4.5.1.2: keyUsage without digitalSignature -> unsupported_certificate",
           "unsupported_certificate", cert_der=leaf_cert(ku=4))
    flight("RFC 5280 4.2.1.12: EKU clientAuth only -> unsupported_certificate",
           "unsupported_certificate", cert_der=leaf_cert(eku="1.3.6.1.5.5.7.3.2"))
    flight("RFC 5280 6.1.3: expired leaf -> bad_certificate", "bad_certificate",
           cert_der=leaf_cert(naf="270101000000Z"), flags=TLS13_F_TIME)
    flight("RFC 5280 6.1: the anchor shares the root's Name but not its key -> bad_certificate",
           "bad_certificate", anchor=rogue_c)
    flight("RFC 9846 4.5.2: CertificateVerify signed over the wrong transcript -> decrypt_error",
           "decrypt_error", wrong_th=True)
    flight("RFC 9846 4.5.2: one flipped signature bit -> decrypt_error", "decrypt_error",
           mangle=lambda s: s[:-1] + bytes([s[-1] ^ 1]))
    flight("RFC 9846 4.5.2: BER length in the ECDSA-Sig-Value -> decode_error", "decode_error",
           mangle=lambda s: b"\x30\x81" + s[1:])
    flight("RFC 9846 4.3.3: ecdsa_secp384r1_sha384 with a P-256 key -> illegal_parameter",
           "illegal_parameter", scheme=0x0503)
    flight("RFC 9846 4.3.3: rsa_pss_rsae_sha256 with a P-256 key -> illegal_parameter",
           "illegal_parameter", scheme=0x0804)
    flight("RFC 9846 4.3.3: rsa_pkcs1_sha256 is never valid in CertificateVerify",
           "illegal_parameter", scheme=0x0401)
    print(f"  tls13 fixture: {len(rows)} synthetic flows")
    chw = [(seed(b"client random").hex(), sid.hex(), "".join(f"{v:04x}" for v in TLS13_SUITES),
            "".join(f"{v:04x}" for v in TLS13_GROUPS), "".join(f"{v:04x}" for v in TLS13_SIGS),
            "device.example.com", 0x001d, c_pub.hex(), "", ch.hex(), "", 0, "", 0, 0)]
    p256 = py_p256_keygen(int.from_bytes(seed(b"client p256"), "big"))[0]
    cookie = seed(b"cookie") * 3
    chw.append(("00" * 32, "", "1301", "001d0017", "04030804", "", 0x0017, p256.hex(), cookie.hex(),
                t_ch(bytes(32), b"", [0x1301], [0x001d, 0x0017], [0x0403, 0x0804], 0x0017, p256,
                     b"", cookie).hex(), "", 0, "", 0, 0))
    return rows, chw


def t_mutations(parts):
    """Single-fault variants of the RFC 8448 messages. Each row names the message it replaces
    (by position in that flow's server flight) and the alert, with the section that fixes it.
    A row whose alert is not an RFC MUST says 'local' and why."""
    rows = []
    names = {}
    for fi, p in enumerate(parts):
        names[fi] = [n for n in ("hrr", "sh", "ee", "cr", "cert", "cv", "sf") if p.get(n)]

    def row(fi, name, msg, alert, note):
        rows.append((fi, names[fi].index(name), msg.hex(), ALERT[alert], note))

    s3, s5, s6, s7 = parts
    sh = t_hello_parse(s3["sh"])
    ks = t_ext(sh["exts"], 51)
    sv = [43, t_u16(0x0304)]
    no_sv = [e for e in sh["exts"] if e[0] != 43]
    row(0, "sh", t_hello_build(sh, ver=t_u16(0x0304)), "protocol_version",
        "RFC 9846 4.2.3: legacy_version must be 0x0303")
    row(0, "sh", t_hello_build(sh, sid=b"\x5a" * 32), "illegal_parameter",
        "RFC 9846 4.2.3: legacy_session_id_echo differs from what was sent")
    row(0, "sh", t_hello_build(sh, suite=t_u16(0x1304)), "illegal_parameter",
        "RFC 9846 4.2.3: cipher suite not offered")
    row(0, "sh", t_hello_build(sh, comp=1), "illegal_parameter",
        "RFC 9846 4.2.3: legacy_compression_method != 0")
    row(0, "sh", t_hello_build(sh, exts=no_sv + [[43, t_u16(0x0303)]]), "illegal_parameter",
        "RFC 9846 4.3.1: selected_version below TLS 1.3")
    row(0, "sh", t_hello_build(sh, exts=no_sv + [[43, b"\x03"]]), "decode_error",
        "RFC 9846 4.3: supported_versions truncated")
    row(0, "sh", t_hello_build(sh, exts=no_sv + [[43, b"\x03\x04\x00"]]), "decode_error",
        "RFC 9846 4.3: trailing byte inside supported_versions")
    for tail, tag in ((RFC9846["down1"], "01"), (RFC9846["down0"], "00")):
        row(0, "sh", t_hello_build(sh, exts=no_sv, random=sh["random"][:24] + tail),
            "illegal_parameter", f"RFC 9846 4.2.3: no supported_versions and DOWNGRD{tag}")
    row(0, "sh", t_hello_build(sh, exts=no_sv), "protocol_version",
        "RFC 9846 4.3.1: a TLS 1.2 ServerHello (local: TLS 1.2 is M5)")
    row(0, "sh", t_hello_build(sh, exts=None, random=sh["random"][:24] + RFC9846["down1"]),
        "illegal_parameter", "RFC 9846 4.2.3: extension-less ServerHello (RFC 5246 7.4.1.3) "
        "with DOWNGRD01")
    row(0, "sh", t_hello_build(sh, exts=None), "protocol_version",
        "RFC 9846 4.3.1: extension-less TLS 1.2 ServerHello (local: TLS 1.2 is M5)")
    row(0, "sh", t_msg(2, t_body(t_hello_build(sh, exts=None), 2) + bytes(1)), "decode_error",
        "RFC 9846 4: one stray byte where the extensions length belongs")
    row(0, "sh", t_hello_build(sh, exts=sh["exts"] + [[51, ks]]), "illegal_parameter",
        "RFC 9846 4.3: duplicate key_share (local alert; the RFC names none)")
    row(0, "sh", t_hello_build(sh, exts=sh["exts"] + [[41, t_u16(0)]]), "unsupported_extension",
        "RFC 9846 4.3: unsolicited pre_shared_key")
    row(0, "sh", t_hello_build(sh, exts=sh["exts"] + [[0, b""]]), "illegal_parameter",
        "RFC 9846 4.3: server_name offered but not allowed in a ServerHello")
    no_ks = [e for e in sh["exts"] if e[0] != 51]
    p256_pub = t_ext(t_hello_parse(s5["sh"])["exts"], 51)[4:]
    row(0, "sh", t_hello_build(sh, exts=no_ks + [[51, t_u16(0x0017) + t_v16(p256_pub)]]),
        "illegal_parameter", "RFC 9846 4.3.8: share in a group the client sent no share for")
    for n in (31, 33):
        kx = (ks[4:] + b"\x00")[:n]
        row(0, "sh", t_hello_build(sh, exts=no_ks + [[51, t_u16(0x001d) + t_v16(kx)]]),
            "illegal_parameter", f"RFC 9846 4.3.8.2: x25519 key_exchange of {n} bytes (local)")
    row(0, "sh", t_hello_build(sh, exts=no_ks + [[51, ks + b"\x00"]]), "decode_error",
        "RFC 9846 4.3: trailing byte inside key_share")
    row(0, "sh", t_hello_build(sh, exts=no_ks), "missing_extension",
        "RFC 9846 9.2: no key_share and no PSK (local alert)")
    body = t_body(s3["sh"], 2)
    row(0, "sh", t_msg(2, body[:-1]), "decode_error", "RFC 9846 4: ServerHello one byte short")
    row(0, "sh", t_msg(2, body + b"\x00"), "decode_error", "RFC 9846 4: ServerHello trailing byte")
    ee = t_exts_parse(t_body(s3["ee"], 8)[2:])
    row(0, "ee", t_msg(8, t_exts_build(ee + [[51, ks]])), "illegal_parameter",
        "RFC 9846 4.4.1: key_share in EncryptedExtensions")
    row(0, "ee", t_msg(8, t_exts_build(ee + [[42, b""]])), "unsupported_extension",
        "RFC 9846 4.3: early_data was never offered")
    row(0, "ee", t_msg(8, t_exts_build(ee + [[43, t_u16(0x0304)]])), "illegal_parameter",
        "RFC 9846 4.4.1: supported_versions in EncryptedExtensions")
    row(0, "ee", t_msg(8, t_exts_build([e for e in ee if e[0] != 0] + [[0, b"\x00"]])),
        "decode_error", "RFC 6066 3: a non-empty server_name answer")
    row(0, "ee", t_msg(8, t_exts_build(ee) + b"\x00"), "decode_error",
        "RFC 9846 4: trailing byte after the extension block")
    row(0, "ee", t_msg(8, t_exts_build(ee + [[10, t_ext(ee, 10)]])), "illegal_parameter",
        "RFC 9846 4.3: duplicate supported_groups (local alert)")
    cb = t_body(s3["cert"], 11)
    entries = cb[4:]
    row(0, "cert", t_msg(11, b"\x01\x00" + cb[1:]), "illegal_parameter",
        "RFC 9846 4.5.1: non-empty certificate_request_context")
    row(0, "cert", t_msg(11, b"\x00" + t_v24(b"")), "decode_error",
        "RFC 9846 4.5.1.3: empty certificate_list")
    der_len = int.from_bytes(entries[:3], "big")
    one_ext = entries[:3 + der_len] + t_v16(t_u16(5) + t_v16(b"\x01\x00\x00\x00\x00"))
    row(0, "cert", t_msg(11, b"\x00" + t_v24(one_ext)), "unsupported_extension",
        "RFC 9846 4.5.1: CertificateEntry extension that was never requested")
    row(0, "cert", t_msg(11, b"\x00" + t_v24(t_v24(b"") + t_v16(b""))), "decode_error",
        "RFC 9846 4.5.1: cert_data<1..2^24-1> is empty")
    row(0, "cert", t_msg(11, b"\x00" + t_v24(t_v24(b"\x30\x03\x02\x01\x01") + t_v16(b""))),
        "bad_certificate", "RFC 9846 4.5.1.3: a certificate that does not parse (local alert)")
    cvb = t_body(s3["cv"], 15)
    for scheme, why in ((0x0401, "rsa_pkcs1_sha256 is certificates-only (4.3.3)"),
                        (0x0203, "ecdsa_sha1 (4.3.3: SHA-1 MUST NOT be used)"),
                        (0x0807, "ed25519 was never offered (4.5.2)")):
        row(0, "cv", t_msg(15, t_u16(scheme) + cvb[2:]), "illegal_parameter",
            f"RFC 9846 {why}")
    row(0, "cv", t_msg(15, cvb[:-1]), "decode_error", "RFC 9846 4.5.2: signature length mismatch")
    fb = t_body(s3["sf"], 20)
    row(0, "sf", t_msg(20, fb[:-1] + bytes([fb[-1] ^ 1])), "decrypt_error",
        "RFC 9846 4.5.3: one flipped bit in verify_data")
    row(0, "sf", t_msg(20, fb[:-1]), "decode_error", "RFC 9846 4.5.3: verify_data of HashLen-1")
    row(0, "sf", t_msg(20, fb + b"\x00"), "decode_error", "RFC 9846 4.5.3: verify_data of HashLen+1")
    for at, msg, why in (("sh", s3["ee"], "EncryptedExtensions before ServerHello"),
                         ("cert", s3["cv"], "CertificateVerify before Certificate"),
                         ("cv", s3["sf"], "Finished before CertificateVerify"),
                         ("ee", s3["ch1"], "a ClientHello from the server"),
                         ("ee", s3["sh"], "a second ServerHello"),
                         ("sh", s3["nst"], "NewSessionTicket during the handshake"),
                         ("ee", t_msg(0x63, b""), "an unknown message type")):
        row(0, at, msg, "unexpected_message", f"RFC 9846 4 / A.1: {why}")
    # sect 7: the 32-byte session id echo (compatibility mode, Appendix E.4)
    h7 = t_hello_parse(s7["sh"])
    row(3, "sh", t_hello_build(h7, sid=h7["sid"][:-1] + bytes([h7["sid"][-1] ^ 1])),
        "illegal_parameter", "RFC 9846 4.2.3: one flipped byte in a 32-byte session id echo")
    # sect 5: HelloRetryRequest
    hr = t_hello_parse(s5["hrr"])
    base = [e for e in hr["exts"] if e[0] not in (51, 44)]
    row(1, "hrr", t_hello_build(hr, exts=base), "illegal_parameter",
        "RFC 9846 4.2.4: an HRR that would not change the ClientHello")
    row(1, "sh", s5["hrr"], "unexpected_message", "RFC 9846 4.2.4: a second HelloRetryRequest")
    kept = [e for e in hr["exts"] if e[0] != 51]
    row(1, "hrr", t_hello_build(hr, exts=kept + [[51, t_u16(0x001d)]]), "illegal_parameter",
        "RFC 9846 4.3.8: selected_group already had a share in ClientHello1")
    row(1, "hrr", t_hello_build(hr, exts=kept + [[51, t_u16(0x001e)]]), "illegal_parameter",
        "RFC 9846 4.3.8: selected_group not in supported_groups")
    no_cookie = [e for e in hr["exts"] if e[0] != 44]
    row(1, "hrr", t_hello_build(hr, exts=no_cookie + [[44, t_v16(b"\x42" * 257)]]),
        "illegal_parameter", "RFC 9846 4.3.2: cookie over BRISK__TLS13_COOKIE_MAX (local limit)")
    row(1, "hrr", t_hello_build(hr, exts=no_cookie + [[44, t_v16(b"")]]), "decode_error",
        "RFC 9846 4.3.2: cookie<1..2^16-1> is empty")
    row(1, "hrr", t_hello_build(hr, exts=hr["exts"] + [[42, b""]]), "unsupported_extension",
        "RFC 9846 4.2.4: an HRR extension other than cookie that was never offered")
    row(1, "hrr", t_hello_build(hr, suite=t_u16(0x1304)), "illegal_parameter",
        "RFC 9846 4.2.4: HRR cipher suite not offered")
    row(1, "hrr", t_hello_build(hr, ver=t_u16(0x0304)), "protocol_version",
        "RFC 9846 4.2.4: HRR legacy_version must be 0x0303")
    row(1, "hrr", t_hello_build(hr, exts=[e for e in hr["exts"] if e[0] != 43]), "protocol_version",
        "RFC 9846 4.2.4: HRR without supported_versions (local: read as TLS 1.2)")
    h5 = t_hello_parse(s5["sh"])
    no_ks5 = [e for e in h5["exts"] if e[0] != 51]
    row(1, "sh", t_hello_build(h5, exts=no_ks5 + [[51, t_u16(0x001d) + t_v16(ks[4:])]]),
        "illegal_parameter", "RFC 9846 4.3.8: ServerHello group differs from the HRR's")
    row(1, "sh", t_hello_build(h5, suite=t_u16(0x1303)), "illegal_parameter",
        "RFC 9846 4.2.4: ServerHello suite differs from the HRR's")
    # sect 6: CertificateRequest
    crb = t_body(s6["cr"], 13)
    crx = t_exts_parse(crb[3:])
    row(2, "cr", t_msg(13, b"\x01\x00" + crb[1:]), "illegal_parameter",
        "RFC 9846 4.4.2: non-empty certificate_request_context")
    row(2, "cr", t_msg(13, b"\x00" + t_exts_build([e for e in crx if e[0] != 13])),
        "missing_extension", "RFC 9846 4.4.2: no signature_algorithms")
    row(2, "cr", t_msg(13, b"\x00" + t_exts_build(crx + [[51, ks]])), "illegal_parameter",
        "RFC 9846 4.3: key_share in a CertificateRequest")
    row(2, "cr", t_msg(13, b"\x00" + t_exts_build(crx + [[13, t_ext(crx, 13)]])),
        "illegal_parameter", "RFC 9846 4.3: duplicate signature_algorithms (local alert)")
    row(2, "cr", t_msg(13, b"\x00" + t_exts_build([e for e in crx if e[0] != 13]
                                                   + [[13, t_v16(b"\x04\x03\x08")]])),
        "decode_error", "RFC 9846 4.3.3: odd-length signature_algorithms")
    # Wycheproof x25519 small-order points spliced into the sect 3 ServerHello (RFC 9846 7.4.2:
    # an all-zero shared secret MUST abort), and invalid P-256 points into sect 5 (4.3.8.2).
    priv = parts[0]["priv1"]
    seen = set()
    for g in json.loads(fetch("wp_x25519"))["testGroups"]:
        for t in g["tests"]:
            u = bytes.fromhex(t["public"])
            if u in seen or py_x25519(priv, u) != bytes(32):
                continue
            seen.add(u)
            row(0, "sh", t_hello_build(sh, exts=no_ks + [[51, t_u16(0x001d) + t_v16(u)]]),
                "illegal_parameter", f"RFC 9846 7.4.2: Wycheproof x25519 tcId {t['tcId']}")
    n_x = len(seen)
    d5 = int.from_bytes(parts[1]["priv2"], "big")
    seen = set()
    for g in json.loads(fetch("wp_p256_ecdh"))["testGroups"]:
        for t in g["tests"]:
            pt = bytes.fromhex(t["public"])
            if pt in seen or t["result"] == "valid" or py_p256_ecdh(d5, pt) is not None:
                continue
            seen.add(pt)
            row(1, "sh", t_hello_build(h5, exts=no_ks5 + [[51, t_u16(0x0017) + t_v16(pt)]]),
                "illegal_parameter", f"RFC 9846 4.3.8.2: Wycheproof ecpoint tcId {t['tcId']}")
    if n_x < 10 or len(seen) < 10:
        die(f"tls13 mutations: only {n_x} x25519 and {len(seen)} P-256 invalid shares")
    print(f"  tls13 mutations: {len(rows)} rows ({n_x} x25519, {len(seen)} P-256 shares)")
    return rows


def t_ecdsa_der(sig, flen):
    """r || s out of a strict DER ECDSA-Sig-Value (RFC 5480 A.1), or None."""
    if not py_der_walk(sig):
        return None
    h = py_der_hdr(sig, 0, len(sig))
    if h is None or h[0] != 0x30 or h[2] != len(sig):
        return None
    i, out = h[1], b""
    for _ in range(2):
        v = py_der_hdr(sig, i, h[2])
        if v is None or v[0] != 0x02:
            return None
        c = sig[v[1]:v[2]]
        if c[0] & 0x80:
            return None
        c = c.lstrip(b"\x00") or b"\x00"
        if len(c) > flen:
            return None
        out += c.rjust(flen, b"\x00")
        i = v[2]
    return out if i == h[2] else None


def tls13_cv_vectors():
    """Wycheproof signatures through brisk__tls13_cv_verify: ECDSA as the DER ECDSA-Sig-Value a
    CertificateVerify carries (4.3.3), RSA-PSS as rsa_pss_rsae_* with sLen fixed to hLen. The
    verdict is recomputed here from the value, and must agree with upstream's 'valid'."""
    keys, rows = [], []
    for src, scheme, flen, alg, verify, ok in (
            ("wp_p256_ecdsa_der", 0x0403, 32, 2, py_p256_verify, P256_OK),
            ("tls13_wp_p384_ecdsa_der", 0x0503, 48, 3, py_p384_verify, P384_OK)):
        for g in json.loads(fetch(src))["testGroups"]:
            pub = bytes.fromhex(g["publicKey"]["uncompressed"])
            keys.append((alg, pub.hex()))
            for t in g["tests"]:
                msg, sig = bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"])
                raw = t_ecdsa_der(sig, flen)
                good = raw is not None and verify(pub, HASH[flen * 8](msg).digest(), raw) == ok
                if good != (t["result"] == "valid"):
                    die(f"{src} tcId {t['tcId']}: we say {good}, upstream says {t['result']}")
                rows.append((len(keys) - 1, scheme, msg.hex(), sig.hex(), int(good)))
    for src, scheme, bits in (("wp_rsa_pss_2048_sha256_mgf1_32", 0x0804, 256),
                              ("wp_rsa_pss_3072_sha256_mgf1_32", 0x0804, 256),
                              ("wp_rsa_pss_2048_sha384_mgf1_48", 0x0805, 384),
                              ("wp_rsa_pss_4096_sha512_mgf1_64", 0x0806, 512),
                              ("wp_rsa_pss_2048_sha256_mgf1_0", 0x0804, 256)):
        for g in json.loads(fetch(src))["testGroups"]:
            if g["sha"] != f"SHA-{bits}" or g.get("mgfSha") != g["sha"]:
                continue
            n = int(g["publicKey"]["modulus"], 16)
            e = int(g["publicKey"]["publicExponent"], 16)
            keys.append((1, x_seq(x_int(n), x_int(e)).hex()))
            for t in g["tests"]:
                msg, sig = bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"])
                good = py_pss_verify(n, e, bits, bits // 8, HASH[bits](msg).digest(), sig) == RSA_OK
                if int(g["sLen"]) == bits // 8:
                    if good != (t["result"] == "valid"):
                        die(f"{src} tcId {t['tcId']}: we say {good}, upstream says {t['result']}")
                # Other sLen files: the verdict is ours alone. A row upstream signed with sLen = hLen
                # (tcId 69 of mgf1_0 is one) verifies here, which is what a TLS peer must see.
                rows.append((len(keys) - 1, scheme, msg.hex(), sig.hex(), int(good)))
    print(f"  tls13 CertificateVerify: {len(rows)} Wycheproof rows over {len(keys)} keys, "
          f"{sum(r[4] for r in rows)} valid")
    return keys, rows


# ------------------------------------------ TLS 1.3 resumption, ALPN, mTLS (M3 line 3, RFC 9846 4.3.11)
TLS13_ALPN = [b"mqtt", b"x-amzn-mqtt-ca"]
TICKET_MAX = 2048  # must match BRISK_TICKET_MAX in include/brisk.h


def t_ticket_blob(suite, issued_ms, lifetime, age_add, psk, sni, ticket):
    """Ticket blob v1 (src/tls/ticket.c): ver | suite | issued_ms(int64) | lifetime | age_add |
    psk_len psk | sni_len sni | ticket_len ticket, big-endian, byte-addressed."""
    return (b"\x01" + t_u16(suite) + (issued_ms & (2**64 - 1)).to_bytes(8, "big")
            + lifetime.to_bytes(4, "big") + age_add.to_bytes(4, "big") + t_v8(psk) + t_v8(sni)
            + t_v16(ticket))


def tls13_psk(parts):
    """RFC 8448 sect 4 (resumed handshake) and the flows M3 line 3 adds on top of sect 3/6.

    Official, checked here byte for byte: sect 3's NewSessionTicket turned into the sect 4 PSK
    (RFC 9846 4.7.1), the sect 4 binder over 'ClientHello prefix' (4.3.11.2), the early secret,
    and the whole sect 4 cascade (handshake/application secrets, server Finished) re-derived from
    the official messages with that PSK. The sect 4 ClientHello carries early_data, which this
    client never sends, so every flow the C engine replays is GENERATED with the same cascade:
    the sect 4 PSK, keys and server messages under a ClientHello from brisk__tls13_ch_write's
    layout (no early_data), a PSK + HRR, a declined PSK, and sect 6's CertificateRequest answered
    by a P-256 device key."""
    s3, s5, s6, s7 = parts
    secs = {}
    for b in rfc8448_blocks():
        secs.setdefault(b["_sec"], []).append(b)

    def blk(sec, side, head):
        for b in secs[sec]:
            if b["_side"] == side and b["_h"].startswith(head) and b["_f"]:
                return {k: hexbytes(v) for k, v in b["_f"].items()}
        die(f"RFC 8448 sect {sec}: no {side} block '{head}'")

    # sect 3: the NewSessionTicket and the PSK it yields (RFC 9846 4.7.1)
    ks3 = t_ext(t_hello_parse(s3["sh"])["exts"], 51)
    fl3 = t_flow(256, t_dhe(0x001d, s3["priv1"], ks3[4:]), [s3["ch1"]], s3["sh"], s3["ee"], b"",
                 s3["cert"], s3["cv"])
    nst = t_body(s3["nst"], 4)
    lifetime, age_add = int.from_bytes(nst[:4], "big"), int.from_bytes(nst[4:8], "big")
    nonce = nst[9:9 + nst[8]]
    i = 9 + nst[8]
    ticket = nst[i + 2:i + 2 + int.from_bytes(nst[i:i + 2], "big")]
    psk = py_expand_label(256, fl3["res"], b"resumption", nonce, 32)
    if blk(3, "server", "generate resumption secret")["expanded"] != psk:
        die("RFC 8448 sect 3: resumption PSK mismatch")
    early4 = blk(4, "client", 'extract secret "early"')
    if early4["IKM"] != psk or py_hkdf_extract(256, bytes(32), psk) != early4["secret"]:
        die("RFC 8448 sect 4: the early secret is not HKDF-Extract(0, sect 3's PSK)")
    # sect 4: the binder (4.3.11.2) over Truncate(CH)
    b4 = blk(4, "client", "calculate PSK binder")
    ch4 = blk(4, "client", "send handshake record")["payload"]
    prefix = b4["ClientHello prefix"]
    if ch4[:len(prefix)] != prefix or len(ch4) != len(prefix) + 3 + 32:
        die("RFC 8448 sect 4: the ClientHello prefix is not Truncate(ClientHello)")
    if HASH[256](prefix).digest() != b4["binder hash"]:
        die("RFC 8448 sect 4: binder hash mismatch")
    binder = t_binder(256, psk, b4["binder hash"])
    if binder != b4["finished"] or ch4[-32:] != binder or t_binder_fill(256, psk, [], ch4) != ch4:
        die("RFC 8448 sect 4: PSK binder mismatch")
    c4 = t_ch_parse(ch4)
    if t_ext(c4["exts"], 42) is None:
        die("RFC 8448 sect 4: expected early_data in the ClientHello (the negative row)")
    pe = t_ext(c4["exts"], 41)
    il = int.from_bytes(pe[2:4], "big")
    if pe[4:4 + il] != ticket:
        die("RFC 8448 sect 4: the PSK identity is not sect 3's ticket")
    obf = int.from_bytes(pe[4 + il:8 + il], "big")
    # sect 4: the cascade with the PSK, from the official messages
    sh4 = blk(4, "server", "construct a ServerHello")["ServerHello"]
    ee4 = blk(4, "server", "construct an EncryptedExtensions")["EncryptedExtensions"]
    ck = blk(4, "client", "create an ephemeral x25519")
    s_pub4 = t_ext(t_hello_parse(sh4)["exts"], 51)[4:]
    dhe4 = py_x25519(ck["private key"], s_pub4)
    fl4 = t_flow(256, dhe4, [ch4], sh4, ee4, b"", b"", b"", psk=psk)
    if fl4["sf"] != blk(4, "server", "construct a Finished")["Finished"]:
        die("RFC 8448 sect 4: server Finished mismatch")
    for name, k in (("c hs traffic", "c_hs"), ("s hs traffic", "s_hs"), ("c ap traffic", "c_ap"),
                    ("s ap traffic", "s_ap"), ("exp master", "exp")):
        if blk(4, "server", f'derive secret "tls13 {name}"')["expanded"] != fl4[k]:
            die(f"RFC 8448 sect 4: {name} mismatch")

    # Generated flows on the sect 4 keys, ClientHello in brisk__tls13_ch_write's layout.
    seed = lambda tag: hashlib.sha256(b"brisk tls13 psk " + tag).digest()
    rnd = t_body(ch4, 1)[2:34]
    c_priv, c_pub = ck["private key"], ck["public key"]
    alpn = t_alpn(TLS13_ALPN)
    ee_alpn = t_msg(8, t_exts_build([(0, b""), (16, t_v16(t_v8(b"mqtt")))]))
    ee_plain = t_msg(8, t_exts_build([(0, b"")]))

    def ch_of(group, pub, prefix, age, with_psk=True):
        ch = t_ch(rnd, b"", TLS13_SUITES, TLS13_GROUPS, TLS13_SIGS, group, pub, b"server",
                  alpn=alpn, modes=True, psk=(ticket, age, 32) if with_psk else None)
        return t_binder_fill(256, psk, prefix, ch) if with_psk else ch

    def sh_of(suite, group, pub, sel=True):
        exts = ([(41, t_u16(0))] if sel else []) + [(51, t_u16(group) + t_v16(pub)),
                                                    (43, t_u16(0x0304))]
        return t_msg(2, t_u16(0x0303) + seed(b"server random") + t_v8(b"") + t_u16(suite)
                     + b"\x00" + t_exts_build(exts))

    rows, chw = [], []
    ch1 = ch_of(0x001d, c_pub, [], obf)
    chw.append((rnd.hex(), "", "".join(f"{v:04x}" for v in TLS13_SUITES),
                "".join(f"{v:04x}" for v in TLS13_GROUPS), "".join(f"{v:04x}" for v in TLS13_SIGS),
                "server", 0x001d, c_pub.hex(), "",
                t_ch(rnd, b"", TLS13_SUITES, TLS13_GROUPS, TLS13_SIGS, 0x001d, c_pub, b"server",
                     alpn=alpn, modes=True, psk=(ticket, obf, 32)).hex(),
                alpn.hex(), 1, ticket.hex(), obf, 32))
    chw.append((rnd.hex(), "", "1301", "001d", "0403", "", 0x001d, c_pub.hex(), "",
                t_ch(rnd, b"", [0x1301], [0x001d], [0x0403], 0x001d, c_pub, alpn=alpn).hex(),
                alpn.hex(), 0, "", 0, 0))
    common = dict(psk=psk, psk_suite=0x1301, alpn="")
    # 1. resumed: the official sect 4 ServerHello (pre_shared_key 0 + x25519, psk_dhe_ke)
    fl = t_flow(256, dhe4, [ch1], sh4, ee_alpn, b"", b"", b"", psk=psk)
    rows.append(t_row("RFC 8448 sect 4 minus 0-RTT: resumed, psk_dhe_ke, ALPN mqtt", fl, ch1=ch1,
                      priv1=c_priv, g1=0x001d, sh=sh4, ee=ee_alpn, cert=b"", cv=b"",
                      **dict(common, resumed=1, alpn="mqtt")))
    fresh = py_expand_label(256, fl["res"], b"resumption", nonce, 32)
    # 2. declined: a full handshake (sect 3's certificate) under the same ClientHello
    sh = sh_of(0x1301, 0x001d, s_pub4, sel=False)
    fl = t_flow(256, dhe4, [ch1], sh, ee_plain, b"", s3["cert"], s3["cv"])
    rows.append(t_row("PSK offered, declined: full handshake, no ALPN answer", fl, ch1=ch1,
                      priv1=c_priv, g1=0x001d, sh=sh, ee=ee_plain, cert=s3["cert"], cv=s3["cv"],
                      **common))
    # 3 + 4. PSK + HelloRetryRequest (4.3.11.2 + 4.2.2): same hash, then SHA-384
    c_d = int.from_bytes(seed(b"client p256"), "big")
    s_d = int.from_bytes(seed(b"server p256"), "big")
    c_p256, s_p256 = py_p256_keygen(c_d)[0], py_p256_keygen(s_d)[0]
    dhe_p = py_p256_ecdh(c_d, s_p256)

    def hrr_of(suite):
        return t_msg(2, t_u16(0x0303) + RFC9846["hrr"] + t_v8(b"") + t_u16(suite) + b"\x00"
                     + t_exts_build([(43, t_u16(0x0304)), (51, t_u16(0x0017))]))

    hrr = hrr_of(0x1301)
    mh = t_message_hash(256, ch1)
    ch2 = ch_of(0x0017, c_p256, [mh, hrr], (obf + 1500) & 0xffffffff)
    sh = sh_of(0x1301, 0x0017, s_p256)
    fl = t_flow(256, dhe_p, [mh, hrr, ch2], sh, ee_alpn, b"", b"", b"", psk=psk)
    rows.append(t_row("PSK + HRR (same hash): CH2 binder over message_hash(CH1) || HRR || "
                      "Truncate(CH2)", fl, ch1=ch1, priv1=c_priv, g1=0x001d, hrr=hrr, ch2=ch2,
                      priv2=c_d.to_bytes(32, "big"), g2=0x0017, sh=sh, ee=ee_alpn, cert=b"", cv=b"",
                      **dict(common, resumed=1, alpn="mqtt")))
    hrr384 = hrr_of(0x1302)
    ch2n = ch_of(0x0017, c_p256, [], 0, with_psk=False)
    sh = sh_of(0x1302, 0x0017, s_p256, sel=False)
    fl = t_flow(384, dhe_p, [t_message_hash(384, ch1), hrr384, ch2n], sh, ee_plain, b"",
                s3["cert"], s3["cv"])
    rows.append(t_row("PSK + HRR to SHA-384: the PSK is dropped from CH2, full handshake", fl,
                      ch1=ch1, priv1=c_priv, g1=0x001d, hrr=hrr384, ch2=ch2n,
                      priv2=c_d.to_bytes(32, "big"), g2=0x0017, sh=sh, ee=ee_plain,
                      cert=s3["cert"], cv=s3["cv"], **common))

    # 5 + 6. mTLS: sect 6's CertificateRequest answered with a P-256 device chain
    ca = ec_issuer(P256, 0x7153E020, 256)
    dev_d = 0x7153E021
    dev = ec_issuer(P256, dev_d, 256)
    ca_c = chain_cert("Brisk Device CA", "Brisk Device CA", ca, ca,
                      exts=[x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)])

    def dev_leaf(key=dev, ku=KU_BIT_DIGITAL_SIGNATURE):
        return chain_cert("Brisk Device CA", "device-0001", ca, key,
                          exts=[x_bc(False), x_ku(ku),
                                x_ext("2.5.29.37", False, x_seq(x_oid("1.3.6.1.5.5.7.3.2")))])

    leaf_c = dev_leaf()
    chain = [leaf_c, ca_c]
    srand = hashlib.sha256(b"brisk tls13 sign_rand").digest()
    dev_pub = py_p256_keygen(dev_d)[0]

    # The IIoT shape the old 2 KB output queue refused: a P-256 leaf issued by an RSA CA, sent
    # with that CA and its RSA root, each carrying CRL/AIA URLs. It must stay above the old
    # 1908-byte cap and within BRISK_TLS_MAX_CLIENT_CHAIN's default (4096).
    rsa_k = rsa_issuer(256)
    urls = "http://pki.device.example/brisk-rsa-issuing-ca"

    def pki_exts(is_ca, ku):
        return [x_bc(is_ca), x_ku(ku),
                x_ext("2.5.29.31", False, x_seq(x_seq(x_ctx(0, x_ctx(0, der_tlv(
                    0x86, (urls + ".crl").encode())))))),
                x_ext("1.3.6.1.5.5.7.1.1", False, x_seq(
                    x_seq(x_oid("1.3.6.1.5.5.7.48.2"), der_tlv(0x86, (urls + ".crt").encode())),
                    x_seq(x_oid("1.3.6.1.5.5.7.48.1"),
                          der_tlv(0x86, b"http://ocsp.device.example")))),
                x_ext("2.5.29.32", False, x_seq(x_seq(x_oid("2.23.140.1.2.1"))))]

    rsa_chain = [chain_cert("Brisk RSA Issuing CA", "device-0001", rsa_k, dev,
                            exts=pki_exts(False, KU_BIT_DIGITAL_SIGNATURE)),
                 chain_cert("Brisk RSA Root CA", "Brisk RSA Issuing CA", rsa_k, rsa_k,
                            exts=pki_exts(True, KU_BIT_KEY_CERT_SIGN)),
                 chain_cert("Brisk RSA Root CA", "Brisk RSA Root CA", rsa_k, rsa_k,
                            exts=[x_bc(True), x_ku(KU_BIT_KEY_CERT_SIGN)])]
    rsa_len = len(b"".join(rsa_chain))
    if not 1908 < rsa_len <= 4096:
        die(f"mTLS: the RSA-issued device chain is {rsa_len} bytes, want 1909..4096")

    def client(msgs, chain=chain):
        cert = t_msg(11, b"\x00" + t_v24(b"".join(t_v24(c) + t_v16(b"") for c in chain)))
        tbs = (b" " * 64 + b"TLS 1.3, client CertificateVerify\x00"
               + t_th(256, msgs + [cert]))  # RFC 9846 4.5.2, client context
        h = hashlib.sha256(tbs).digest()
        r, s_ = py_p256_sign(dev_d, h, 256, srand)
        raw = r.to_bytes(32, "big") + s_.to_bytes(32, "big")
        if py_p256_verify(dev_pub, h, raw) != P256_OK:
            die("mTLS: the client CertificateVerify does not verify")
        return [cert, t_msg(15, t_u16(0x0403) + t_v16(x_seq(x_int(r), x_int(s_))))]

    ks6 = t_ext(t_hello_parse(s6["sh"])["exts"], 51)
    dhe6 = t_dhe(s6["g1"], s6["priv1"], ks6[4:])
    mt = dict(cchain=b"".join(chain), ckey=dev_d.to_bytes(32, "big"), srand=srand)
    fl = t_flow(256, dhe6, [s6["ch1"]], s6["sh"], s6["ee"], s6["cr"], s6["cert"], s6["cv"],
                client=client)
    rows.append(t_row("RFC 8448 sect 6 shape: CertificateRequest answered by a P-256 device key",
                      fl, ch1=s6["ch1"], priv1=s6["priv1"], g1=s6["g1"], sh=s6["sh"], ee=s6["ee"],
                      cr=s6["cr"], cert=s6["cert"], cv=s6["cv"], **mt))
    mt_rsa = dict(mt, cchain=b"".join(rsa_chain))
    fl = t_flow(256, dhe6, [s6["ch1"]], s6["sh"], s6["ee"], s6["cr"], s6["cert"], s6["cv"],
                client=lambda msgs: client(msgs, rsa_chain))
    rows.append(t_row(f"RFC 9846 4.4.2: a {rsa_len}-byte device chain (P-256 leaf, RSA issuing "
                      "CA + root) in the client flight", fl, ch1=s6["ch1"], priv1=s6["priv1"],
                      g1=s6["g1"], sh=s6["sh"], ee=s6["ee"], cr=s6["cr"], cert=s6["cert"],
                      cv=s6["cv"], **mt_rsa))
    cr_rsa = t_msg(13, b"\x00" + t_exts_build([(13, t_v16(t_u16(0x0804) + t_u16(0x0401)))]))
    fl = t_flow(256, dhe6, [s6["ch1"]], s6["sh"], s6["ee"], cr_rsa, s6["cert"], s6["cv"])
    rows.append(t_row("RFC 9846 4.5.1: CR without ecdsa_secp256r1_sha256 -> empty Certificate", fl,
                      ch1=s6["ch1"], priv1=s6["priv1"], g1=s6["g1"], sh=s6["sh"], ee=s6["ee"],
                      cr=cr_rsa, cert=s6["cert"], cv=s6["cv"], **mt))

    # hs_init's device-chain checks (RFC 9846 4.5.1.2): (note, chain, key, ok)
    p384 = ec_issuer(P384, 0x7153E022, 384)
    mtls = [("device chain leaf + CA, matching key", b"".join(chain), dev_d, 1),
            ("leaf alone", leaf_c, dev_d, 1),
            ("leaf + RSA issuing CA + RSA root, over 1908 bytes", b"".join(rsa_chain), dev_d, 1),
            ("key does not match the leaf", b"".join(chain), dev_d + 1, 0),
            ("RSA leaf (RSA is verify only)", dev_leaf(key=rsa_issuer(256)), dev_d, 0),
            ("P-384 leaf (verify only)", dev_leaf(key=p384), dev_d, 0),
            ("keyUsage without digitalSignature", dev_leaf(ku=4), dev_d, 0),
            ("garbage DER", b"\x30\x03\x02\x01\x01", dev_d, 0),
            ("a stray byte after the leaf", leaf_c + b"\x00", dev_d, 0)]
    mtls = [(n, c.hex(), d.to_bytes(32, "big").hex(), ok) for n, c, d, ok in mtls]

    # SH / EE / flight negatives on the resumed and HRR flows (alert, section)
    muts = []  # (flow offset in rows, message name, bytes, alert, note)
    hs4 = t_hello_parse(sh4)
    rest = [e for e in hs4["exts"] if e[0] != 41]
    for sel, alert, why in ((t_u16(1), "illegal_parameter",
                             "4.3.11: selected_identity not offered"),
                            (b"\x00", "decode_error", "4.3.11: selected_identity truncated"),
                            (b"\x00\x00\x00", "decode_error", "4.3.11: trailing byte")):
        muts.append((0, "sh", t_hello_build(hs4, exts=[[41, sel]] + rest), alert,
                     f"RFC 9846 {why}"))
    muts.append((0, "sh", t_hello_build(hs4, suite=t_u16(0x1302)), "illegal_parameter",
                 "RFC 9846 4.3.11: PSK selected under a suite of another hash"))
    muts.append((0, "sh", t_hello_build(hs4, exts=[e for e in hs4["exts"] if e[0] != 51]),
                 "illegal_parameter", "RFC 9846 4.3.11: PSK selected without key_share "
                 "(psk_dhe_ke only)"))
    for name, m, why in (("sf", s6["cr"], "CertificateRequest"),
                         ("sf", s3["cert"], "Certificate")):
        muts.append((0, name, m, "unexpected_message",
                     f"RFC 9846 4.4.2 / A.1: a {why} in a PSK handshake"))
    fb = t_body(bytes.fromhex(rows[0][19]), 20)
    muts.append((0, "sf", t_msg(20, fb[:-1] + bytes([fb[-1] ^ 1])), "decrypt_error",
                 "RFC 9846 4.5.3: flipped server Finished in a PSK handshake"))
    muts.append((0, "ee", t_msg(8, t_exts_build([(0, b""), (16, t_v16(t_v8(b"h2")))])),
                 "illegal_parameter", "RFC 7301 3.1: ALPN answer not in the offer (TCP, local)"))
    hh = t_hello_parse(hrr)
    muts.append((2, "hrr", t_hello_build(hh, exts=hh["exts"] + [[41, t_u16(0)]]),
                 "illegal_parameter", "RFC 9846 4.3 Table 1: pre_shared_key in a "
                 "HelloRetryRequest"))

    blob_issued = 1758600000000
    blob = t_ticket_blob(0x1301, blob_issued, lifetime, age_add, psk, b"server", ticket)
    one = (s3["nst"].hex(), psk.hex(), prefix.hex(), b4["binder hash"].hex(), binder.hex(),
           ch4.hex(), early4["secret"].hex(), blob.hex(), blob_issued, blob_issued + 5000,
           (5000 + age_add) & 0xffffffff, ticket.hex(), fresh.hex(), lifetime, age_add)
    print(f"  tls13 psk: sect 4 binder/early/cascade verified, {len(rows)} flows, {len(muts)} "
          f"mutations, {len(mtls)} device chains")
    return rows, chw, muts, mtls, [one]


def tls13_ecdsa_der():
    """brisk__x509_ecdsa_der, the CertificateVerify encoder: every 'valid' Wycheproof
    ecdsa_secp256r1_sha256_test.json signature must come back byte for byte from its r || s
    (the minimal DER of X.690 8.3.2 is unique), plus generated edge cases."""
    n = P256["n"]
    seen, rows = set(), []
    for g in json.loads(fetch("wp_p256_ecdsa_der"))["testGroups"]:
        for t in g["tests"]:
            sig = bytes.fromhex(t["sig"])
            if t["result"] != "valid" or sig in seen:
                continue
            raw = t_ecdsa_der(sig, 32)
            if raw is None:
                die(f"wycheproof tcId {t['tcId']}: a valid signature does not parse")
            r, s_ = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
            if x_seq(x_int(r), x_int(s_)) != sig:
                die(f"wycheproof tcId {t['tcId']}: a valid signature is not minimal DER")
            seen.add(sig)
            rows.append((raw.hex(), sig.hex(), f"wycheproof tcId {t['tcId']}"))
    for r, s_, note in ((1, 1, "r = s = 1"), (1 << 255, n - 1, "r top bit set, s = n - 1"),
                        (n - 1, n - 2, "both 33-byte INTEGERs: the 72-byte maximum"),
                        (0x7f, 0x80, "one-byte r, s needing a 0x00 pad"),
                        (1 << 200, 0xff << 100, "leading zero octets stripped")):
        der = x_seq(x_int(r), x_int(s_))
        rows.append(((r.to_bytes(32, "big") + s_.to_bytes(32, "big")).hex(), der.hex(), note))
    if max(len(r[1]) for r in rows) != 144:
        die("ecdsa der: no 72-byte row")
    print(f"  tls13 ecdsa DER encoder: {len(rows)} rows")
    return rows


# ---------------------------------------------------------------- TLS 1.3 record layer (RFC 9846 5)
# Everything tests/test_tls13_rec.c replays. The RFC 8448 records are re-sealed here from their
# payload under the trace's own keys and must match the printed "complete record" byte for byte.
# No official record trace exists for ChaCha20-Poly1305 or AES-256-GCM/SHA-384, for KeyUpdate
# ("traffic upd"), for padding or for the size limits, so those rows are generated with the same
# Python AEADs that reproduce RFC 8439, SP 800-38D, Wycheproof and the RFC 8448 records.
REC_CT = {"change_cipher_spec": 20, "alert": 21, "handshake": 22, "application_data": 23}
REC_SUITE = {0x1301: (256, 16), 0x1302: (384, 32), 0x1303: (256, 32)}  # hash bits, key length
REC_MAX_INNER = (1 << 14) + 1  # RFC 9846 5.4
REC_MAX_CIPHER = (1 << 14) + 256  # RFC 9846 5.2
REC_A_BAD_MAC, REC_A_OVERFLOW, REC_A_UNEXPECTED = 20, 22, 10


def rec_keys(suite, secret):
    """RFC 9846 7.3: key and iv from a traffic secret."""
    bits, kl = REC_SUITE[suite]
    return py_expand_label(bits, secret, b"key", b"", kl), py_expand_label(bits, secret, b"iv", b"", 12)


def rec_nonce(iv, seq):
    return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))  # RFC 9846 5.3


def rec_seal_raw(suite, key, iv, seq, inner):
    """TLSCiphertext around an arbitrary TLSInnerPlaintext (RFC 9846 5.2): outer type 23, 0x0303,
    AAD = the header as sent."""
    hdr = bytes([23, 3, 3]) + (len(inner) + 16).to_bytes(2, "big")
    seal = py_aead_seal if suite == 0x1303 else py_gcm_seal
    ct, tag = seal(key, rec_nonce(iv, seq), hdr, inner)
    return hdr + ct + tag


def rec_seal(suite, key, iv, seq, typ, payload, pad=0):
    return rec_seal_raw(suite, key, iv, seq, payload + bytes([typ]) + bytes(pad))


def rec_row(name, suite, secret, seq, typ, payload, record, *, ver=0x0303, pad=0, alert=0, sec=0,
            side=0, idx=0):
    key, iv = rec_keys(suite, secret) if suite else (b"", b"")
    return (name, sec, side, idx, suite, secret.hex(), key.hex(), iv.hex(), seq, typ, ver, pad,
            payload.hex(), record.hex(), alert)


def rec_rfc8448():
    """Every record of RFC 8448 sections 3-7, keyed by who wrote it and under which traffic keys.
    A '{side} derive write traffic keys for X' block switches that side's write keys (seq 0) even
    when it prints no fields ('same as ...'): the key then comes from the peer's matching 'derive
    read traffic keys' block. Section 6's client flight uses an RSA client key this library cannot
    produce, but the record math does not care, so its records are kept too."""
    secs, rows, keysets = {}, [], {}
    for b in rfc8448_blocks():
        secs.setdefault(b["_sec"], []).append(b)
    other = {"client": "server", "server": "client"}
    for sec in (3, 4, 5, 6, 7):
        keys, phase, seq, idx = {}, {"client": None, "server": None}, {}, {"client": 0, "server": 0}
        for b in secs[sec]:
            f = {k: hexbytes(v) for k, v in b["_f"].items()}
            side = b["_side"]
            m = re.match(r"derive (write|read) traffic keys for "
                         r"(early application data|handshake data|application data)", b["_h"])
            if m:
                writer = side if m.group(1) == "write" else other[side]
                if "PRK" in f:
                    k, iv = rec_keys(0x1301, f["PRK"])
                    if (k, iv) != (f["key expanded"], f["iv expanded"]):
                        die(f"RFC 8448 sect {sec}: {b['_h']} key/iv mismatch")
                    if keys.get((writer, m.group(2)), (f["PRK"],))[0] != f["PRK"]:
                        die(f"RFC 8448 sect {sec}: two secrets for {writer} {m.group(2)}")
                    keys[(writer, m.group(2))] = (f["PRK"], k, iv)
                if m.group(1) == "write":
                    phase[side], seq[side] = m.group(2), 0
                continue
            m = re.match(r"send (handshake|application_data|alert|change_cipher_spec) record", b["_h"])
            if not m:
                continue
            typ, payload, rec = REC_CT[m.group(1)], f["payload"], f["complete record"]
            name = f"8448s{sec} {side} {idx[side]}"
            sd = 1 if side == "server" else 0
            if rec[0] != 23:  # unprotected (ClientHello, ServerHello, HRR, compat CCS)
                if rec[0] != typ or int.from_bytes(rec[3:5], "big") != len(payload) or rec[5:] != payload:
                    die(f"RFC 8448 {name}: bad plaintext record")
                rows.append(rec_row(name, 0, b"", 0, typ, payload, rec, sec=sec, side=sd, idx=idx[side],
                                    ver=int.from_bytes(rec[1:3], "big")))
            else:
                secret, k, iv = keys[(side, phase[side])]
                if rec_seal(0x1301, k, iv, seq[side], typ, payload) != rec:
                    die(f"RFC 8448 {name}: re-sealed record differs from the trace")
                rows.append(rec_row(name, 0x1301, secret, seq[side], typ, payload, rec, sec=sec,
                                    side=sd, idx=idx[side]))
                seq[side] += 1
            idx[side] += 1
        keysets[sec] = keys
    if len(rows) < 40 or sum(1 for r in rows if r[4]) < 25:
        die(f"RFC 8448 records: parsed too few ({len(rows)})")
    return rows, keysets


def rec_hs(typ, body):
    return bytes([typ]) + len(body).to_bytes(3, "big") + body


def rec_nst(lifetime, age_add, nonce, ticket, exts):
    """NewSessionTicket (RFC 9846 4.7.1) from its fields; exts = [(type, data)]."""
    e = b"".join(t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d for t, d in exts)
    return rec_hs(4, lifetime.to_bytes(4, "big") + age_add.to_bytes(4, "big") + t_v8(nonce)
                  + len(ticket).to_bytes(2, "big") + ticket + len(e).to_bytes(2, "big") + e)


# RFC 9846 4.2 Table 1: extension types defined for some message but not for NewSessionTicket
# (early_data, 42, is the one NST extension). Unknown types (not in Table 1) are ignored.
NST_RECOGNISED_NOT_ALLOWED = {0, 1, 5, 10, 13, 14, 15, 16, 18, 19, 20, 21, 27, 28, 34, 39, 41,
                              43, 44, 45, 47, 48, 49, 50, 51, 52}


def rec_nst_parse(msg):
    """An independent strict reader of a NewSessionTicket (RFC 9846 4.7.1): the fields
    (lifetime, age_add, nonce, ticket, max_early_data) or the alert number."""
    if len(msg) < 4 or msg[0] != 4 or int.from_bytes(msg[1:4], "big") != len(msg) - 4:
        die("NST row: bad handshake header")
    b = msg[4:]
    if len(b) < 9 or len(b) < 9 + b[8] + 2:
        return 50
    life, age, nonce = int.from_bytes(b[0:4], "big"), int.from_bytes(b[4:8], "big"), b[9:9 + b[8]]
    i = 9 + b[8]
    tl = int.from_bytes(b[i:i + 2], "big")
    if tl == 0 or len(b) < i + 2 + tl + 2:  # ticket<1..2^16-1>
        return 50
    ticket, i = b[i + 2:i + 2 + tl], i + 2 + tl
    if len(b) != i + 2 + int.from_bytes(b[i:i + 2], "big"):
        return 50
    e, i, seen, med = b[i + 2:], 0, set(), 0
    while i < len(e):
        if len(e) - i < 4 or int.from_bytes(e[i + 2:i + 4], "big") > len(e) - i - 4:
            return 50
        t, dl = int.from_bytes(e[i:i + 2], "big"), int.from_bytes(e[i + 2:i + 4], "big")
        if t in seen:
            return 47  # RFC 9846 4.3: at most one extension of each type
        seen.add(t)
        if t in NST_RECOGNISED_NOT_ALLOWED:
            return 47  # RFC 9846 4.3: recognised, but Table 1 allows only early_data in NST
        if t == 42:  # early_data carries max_early_data_size (4.7.1)
            if dl != 4:
                return 50
            med = int.from_bytes(e[i + 4:i + 8], "big")
        i += 4 + dl
    return (life, age, nonce, ticket, med)


def tls13_records():
    """Rows for tests/test_tls13_rec.c: record seal/open, nonces, KeyUpdate chains, post-handshake
    messages, and the seeds for fuzz/fuzz_tls13_rec.c."""
    rows, keysets = rec_rfc8448()
    n8448 = len(rows)
    rnd = random.Random(20260923)

    def seed(tag, n):
        return (hashlib.sha384 if n > 32 else hashlib.sha256)(b"brisk tls13 record " + tag).digest()[:n]

    # (a) the two suites no trace covers, plus AES-128-GCM through the same generator; seq values
    # that catch a 32-bit truncation or a little-endian store of the 64-bit counter.
    for suite in (0x1301, 0x1302, 0x1303):
        sec = seed(b"suite %04x" % suite, REC_SUITE[suite][0] // 8)
        k, iv = rec_keys(suite, sec)
        for j, s in enumerate((0, 1, 0xFF, 0x100, 1 << 32, 1 << 63, (1 << 64) - 2)):
            typ = (23, 22, 21)[j % 3]
            n = 2 if typ == 21 else (1, 1, 2, 15, 16, 17, 100)[j]
            pl = bytes(rnd.randrange(1, 256) for _ in range(n))
            rows.append(rec_row(f"gen {suite:04x} seq {s}", suite, sec, s, typ, pl,
                                rec_seal(suite, k, iv, s, typ, pl)))
        # zero-length application data is legal (5.4) and delivers nothing
        rows.append(rec_row(f"gen {suite:04x} empty app", suite, sec, 7, 23, b"",
                            rec_seal(suite, k, iv, 7, 23, b"")))
        # (c) padding, the largest content, the largest inner plaintext: all accepted
        for name, pl, pad in (("pad 1", b"\x17" * 20, 1), ("pad 255", b"\x2a" * 20, 255),
                              ("pad to limit", bytes(range(1, 101)), REC_MAX_INNER - 1 - 100),
                              ("max content", bytes((i & 0xFF) | 1 for i in range(1 << 14)), 0),
                              ("empty app pad to limit", b"", REC_MAX_INNER - 1)):
            rows.append(rec_row(f"gen {suite:04x} {name}", suite, sec, 3, 23, pl,
                                rec_seal(suite, k, iv, 3, 23, pl, pad), pad=pad))
        # (c) inner plaintexts under a VALID tag that RFC 9846 5.4 still rejects
        for name, inner, alert in (("inner too long", bytes(1 << 14) + b"\x17\x00", REC_A_OVERFLOW),
                                   ("inner all zero", bytes(5), REC_A_UNEXPECTED),
                                   ("inner empty", b"", REC_A_UNEXPECTED),
                                   ("empty handshake", b"\x16", REC_A_UNEXPECTED),
                                   ("empty alert", b"\x15\x00\x00", REC_A_UNEXPECTED),
                                   ("inner ccs", b"\x01\x14", REC_A_UNEXPECTED),
                                   ("inner type 24", b"\x01\x18", REC_A_UNEXPECTED),
                                   ("inner type 99", b"\x01\x63\x00", REC_A_UNEXPECTED)):
            rows.append(rec_row(f"gen {suite:04x} {name}", suite, sec, 5, 0, b"",
                                rec_seal_raw(suite, k, iv, 5, inner), alert=alert))
        # protected length below one tag (5.2): no AEAD call can succeed
        for n in range(16):
            rows.append(rec_row(f"gen {suite:04x} short {n}", suite, sec, 0, 0, b"",
                                bytes([23, 3, 3, 0, n]) + bytes(rnd.randrange(256) for _ in range(n)),
                                alert=REC_A_BAD_MAC))
    s = keysets[3]
    s_ap, _, siv = s[("server", "application data")]
    s_hs = s[("server", "handshake data")][0]
    c_ap = s[("client", "application data")][0]
    rows.append(rec_row("gen overflow cipher", 0x1301, s_ap, 0, 0, b"",
                        bytes([23, 3, 3]) + (REC_MAX_CIPHER + 1).to_bytes(2, "big")
                        + bytes(REC_MAX_CIPHER + 1), alert=REC_A_OVERFLOW))
    # unprotected (5.1): the 2^14 limit, zero-length handshake / alert, unknown types
    for name, rec, typ, alert in (
            ("plain max", bytes([22, 3, 3, 0x40, 0]) + bytes(1 << 14), 22, 0),
            ("plain overflow", bytes([22, 3, 3, 0x40, 1]) + bytes((1 << 14) + 1), 0, REC_A_OVERFLOW),
            ("plain empty handshake", bytes([22, 3, 3, 0, 0]), 0, REC_A_UNEXPECTED),
            ("plain empty alert", bytes([21, 3, 3, 0, 0]), 0, REC_A_UNEXPECTED),
            ("plain type 24", bytes([24, 3, 3, 0, 1, 1]), 0, REC_A_UNEXPECTED),
            ("plain type 0", bytes([0, 3, 3, 0, 1, 1]), 0, REC_A_UNEXPECTED),
            ("plain type 255", bytes([255, 3, 3, 0, 1, 1]), 0, REC_A_UNEXPECTED)):
        rows.append(rec_row("gen " + name, 0, b"", 0, typ, b"" if alert else rec[5:], rec, alert=alert))
    # (d) mutations of RFC 8448 sect 3's server application data record (s_ap, seq 1): one bit in
    # the AAD (type, both version bytes), the ciphertext or the tag; a replay; a skipped seq; the
    # wrong epoch's key. Every one is bad_record_mac and nothing else.
    app = bytes.fromhex(next(r for r in rows if r[0] == "8448s3 server 3")[13])
    for name, at in (("aad type", 0), ("aad version hi", 1), ("aad version lo", 2), ("ct first", 5),
                     ("ct last", len(app) - 17), ("tag first", len(app) - 16), ("tag last", len(app) - 1)):
        mut = bytearray(app)
        mut[at] ^= 1
        rows.append(rec_row(f"mut {name}", 0x1301, s_ap, 1, 0, b"", bytes(mut), alert=REC_A_BAD_MAC))
    rows.append(rec_row("mut replay seq 2", 0x1301, s_ap, 2, 0, b"", app, alert=REC_A_BAD_MAC))
    rows.append(rec_row("mut skip seq 0", 0x1301, s_ap, 0, 0, b"", app, alert=REC_A_BAD_MAC))
    rows.append(rec_row("mut s_hs key", 0x1301, s_hs, 1, 0, b"", app, alert=REC_A_BAD_MAC))

    # (b) KeyUpdate: application_traffic_secret_N+1 = Expand-Label(N, "traffic upd", "", HashLen)
    # (RFC 9846 7.2), four generations from each sect 3 app secret, a SHA-384 and a ChaCha one.
    # Each generation carries one sealed record so the rotated key is exercised, not just compared.
    pl50 = bytes(range(50))
    for label, suite, sec in (("s_ap", 0x1301, s_ap), ("c_ap", 0x1301, c_ap),
                              ("384", 0x1302, seed(b"upd 384", 48)), ("chacha", 0x1303, seed(b"upd cc", 32))):
        bits = REC_SUITE[suite][0]
        for g in range(4):
            k, iv = rec_keys(suite, sec)
            rows.append(rec_row(f"upd {label} g{g}", suite, sec, 0, 23, pl50,
                                rec_seal(suite, k, iv, 0, 23, pl50)))
            sec = py_expand_label(bits, sec, b"traffic upd", b"", bits // 8)
    # What the client must send, byte for byte: KeyUpdate(update_not_requested) under the OLD c_ap
    # (4.7.3) then application data under c_ap_1 from seq 0; and around the 2^24 rekey point.
    ku0 = rec_hs(24, b"\x00")
    c_ap1 = py_expand_label(256, c_ap, b"traffic upd", b"", 32)
    for name, secret, sq, typ, pl in (("drv c ku0 g0 seq 0", c_ap, 0, 22, ku0),
                                      ("drv c app g1 seq 0", c_ap1, 0, 23, pl50),
                                      ("drv c app g0 seq rekey-1", c_ap, (1 << 24) - 1, 23, pl50),
                                      ("drv c ku0 g0 seq rekey", c_ap, 1 << 24, 22, ku0)):
        k, iv = rec_keys(0x1301, secret)
        rows.append(rec_row(name, 0x1301, secret, sq, typ, pl, rec_seal(0x1301, k, iv, sq, typ, pl)))
    names = [r[0] for r in rows]
    if len(set(names)) != len(names):
        die("record rows: duplicate name")

    # nonce builder: RFC 9001 A.5 (packet number 654360564 XOR iv = the printed nonce, a multi-byte
    # XOR) plus generated sequence numbers against the sect 3 s_ap iv.
    text = "\n".join(rfc_lines(fetch("rfc9001")))
    a5 = text[text.rindex("\nA.5.  ChaCha20-Poly1305 Short Header Packet"):text.index("\nAppendix B.")]
    q_secret = hexbytes(re.search(r"^\s+secret\b[^\n]*\n\s+=\s+([0-9a-f]+(?:\n\s+[0-9a-f]+)*)",
                                  a5, re.M).group(1))
    q_iv = py_expand_label(256, q_secret, b"quic iv", b"", 12)
    pn = int(re.search(r"^\s+pn\s+=\s+(\d+)", a5, re.M).group(1))
    q_nonce = bytes.fromhex(re.search(r"^\s+nonce\s+=\s+([0-9a-f]+)$", a5, re.M).group(1))
    if rec_nonce(q_iv, pn) != q_nonce:
        die("RFC 9001 A.5 nonce mismatch")
    nonces = [(q_iv.hex(), pn, q_nonce.hex())]
    for sq in (0, 1, 0xFF, 0x100, 1 << 32, 1 << 63, (1 << 64) - 1, 0x0102030405060708):
        nonces.append((siv.hex(), sq, rec_nonce(siv, sq).hex()))

    # post-handshake messages (RFC 9846 4.7): the sect 3 NewSessionTicket and its single-fault
    # variants, KeyUpdate bodies, and messages that are never legal after the handshake.
    nst = bytes.fromhex(next(r for r in rows if r[0] == "8448s3 server 2")[12])
    f = rec_nst_parse(nst)
    if not isinstance(f, tuple) or f[0] != 30 or f[4] != 0x400:
        die("RFC 8448 sect 3 NewSessionTicket: unexpected fields")
    life, age, nn, tk, _ = f
    ed = (42, (0x400).to_bytes(4, "big"))
    b = nst[4:]
    if b[-10:-8] != b"\x00\x08":
        die("RFC 8448 sect 3 NewSessionTicket: expected one 8-byte extension block")
    msgs = [("nst 8448s3", nst, 0),
            ("nst no ext", rec_nst(life, age, nn, tk, []), 0),
            ("nst empty nonce", rec_nst(life, age, b"", tk, [ed]), 0),
            ("nst unknown ext ignored", rec_nst(life, age, nn, tk, [(0xfafa, b"\x01\x02"), ed]), 0),
            ("nst lifetime 604801", rec_nst(604801, age, nn, tk, [ed]), 0),
            # RFC 9001 4.6.1: the only early_data value a QUIC client may accept
            ("nst early_data quic", rec_nst(life, age, nn, tk, [(42, b"\xff" * 4)]), 0),
            ("nst ticket len 0", rec_nst(life, age, nn, b"", [ed]), 50),
            ("nst early_data len 3", rec_nst(life, age, nn, tk, [(42, b"\0\0\4")]), 50),
            ("nst early_data len 5", rec_nst(life, age, nn, tk, [(42, b"\0\0\0\4\0")]), 50),
            ("nst dup early_data", rec_nst(life, age, nn, tk, [ed, ed]), 47),
            ("nst dup unknown", rec_nst(life, age, nn, tk, [(0xfafa, b""), (0xfafa, b"")]), 47),
            # RFC 9846 4.3: a recognised extension Table 1 does not allow in NST
            ("nst key_share", rec_nst(life, age, nn, tk, [ed, (51, b"\x00\x1d\x00\x00")]), 47),
            ("nst supported_versions", rec_nst(life, age, nn, tk, [(43, b"\x03\x04")]), 47),
            ("nst server_name", rec_nst(life, age, nn, tk, [(0, b"")]), 47),
            ("nst pre_shared_key", rec_nst(life, age, nn, tk, [(41, b"\x00\x00")]), 47),
            ("nst record_size_limit", rec_nst(life, age, nn, tk, [(28, b"\x40\x01")]), 47),
            ("nst trailing byte", rec_hs(4, b + b"\0"), 50),
            ("nst ext len overrun", rec_hs(4, b[:-10] + b"\x00\x09" + b[-8:]), 50),
            ("nst ext truncated", rec_hs(4, b[:-1]), 50),
            ("nst nonce overrun", rec_hs(4, b[:8] + b"\xff" + b[9:20]), 50),
            ("nst too short", rec_hs(4, b[:8]), 50),
            ("nst empty body", rec_hs(4, b""), 50)]
    for name, m, alert in msgs:
        got = rec_nst_parse(m)
        if (alert and got != alert) or (not alert and not isinstance(got, tuple)):
            die(f"NST row {name}: the Python reader says {got}")
    msgs += [("ku0", rec_hs(24, b"\0"), 0), ("ku1", rec_hs(24, b"\1"), 0),
             ("ku len 0", rec_hs(24, b""), 50), ("ku len 2", rec_hs(24, b"\0\0"), 50),
             ("ku value 2", rec_hs(24, b"\2"), 47), ("ku value 255", rec_hs(24, b"\xff"), 47),
             ("cr post-handshake", rec_hs(13, b"\0\0\0"), 10),  # 4.7.2: never offered
             ("finished again", rec_hs(20, bytes(32)), 10),
             ("server hello again", rec_hs(2, bytes(40)), 10),
             ("end of early data", rec_hs(5, b""), 10)]
    hsmsg = []
    for name, m, alert in msgs:
        got = rec_nst_parse(m) if m[0] == 4 else None
        fl = got if isinstance(got, tuple) else (0, 0, b"", b"", 0)
        hsmsg.append((name, m.hex(), alert, fl[0], fl[1], fl[4], fl[2].hex(), fl[3].hex()))

    # fuzz seeds: [chunk size] || sect 3 server records after its Finished (NST, app, alert), all
    # under s_ap, which fuzz/fuzz_tls13_rec.c installs as its receive key.
    post = [bytes.fromhex(r[13]) for r in rows[:n8448] if r[1] == 3 and r[2] == 1 and r[3] >= 2]
    seeds = [((bytes([c]) + b"".join(post)).hex(), f"sect 3 post-handshake, chunk {c}")
             for c in (0, 1, 7, 64, 255)]
    print(f"  tls13 records: {len(rows)} rows ({n8448} RFC 8448), {len(nonces)} nonces, "
          f"{len(hsmsg)} post-handshake messages")
    return rows, nonces, hsmsg, seeds, s_ap


def cesc(s):
    """A C string body. A row whose whole point is a non-ASCII octet (a U-label reference) is
    written out as escapes, so neither an editor nor -finput-charset can change what it tests;
    escaping EVERY octet of such a string is what keeps a hex escape unambiguous."""
    if all(0x20 <= ord(ch) < 0x7f and ch not in ('"', "\\") for ch in s):
        return s
    return "".join("\\x%02x" % b for b in s.encode())


def cpem(text):
    """A PEM fixture as one C string literal per line, so the file reads like the file it is.

    cstr() must not be used for this: it chops a string every 96 characters, which would cut an
    escape sequence in half. Only the four escapes below can occur - anything else in these
    fixtures would be a byte nobody meant to put there, so it dies rather than being encoded."""
    esc = {'"': '\\"', "\\": "\\\\", "\r": "\\r", "\t": "\\t"}
    lines = text.split("\n")
    out = []
    for i, ln in enumerate(lines):
        body = ""
        for ch in ln:
            if ch in esc:
                body += esc[ch]
            elif 0x20 <= ord(ch) < 0x7f:
                body += ch
            else:
                die("cpem: unexpected byte %#04x in a PEM fixture" % ord(ch))
        out.append('"' + body + ("\\n" if i < len(lines) - 1 else "") + '"')
    return " ".join(out)


def cstr(hx, width=96):
    if not hx:
        return '""'
    return " ".join(f'"{hx[i:i + width]}"' for i in range(0, len(hx), width))


def emit(name, decl, rows, fmt, append=False):
    body = ",\n".join("    {" + fmt(r) + "}" for r in rows)
    text = f"static const {decl}[] = {{\n{body}\n}};\n"
    if append:  # a second array in the same file
        text = (OUT / name).read_text() + text
    else:
        text = "/* generated by tools/kat.py - do not edit; sources in tests/kat/SOURCES.md */\n" + text
    (OUT / name).write_text(text, newline="\n")
    print(f"  {name}: {len(rows)} vectors")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print("fetching + verifying official vectors ...")
    cavp, monte = cavp_sha()
    hmacs = rfc4231() + wycheproof_hmac()
    kdfs = rfc5869() + wycheproof_hkdf()
    x8448, l8448 = rfc8448()
    x9001, l9001 = rfc9001()
    dhash, dmac, dkdf, million = differential()
    c8439, p8439, a8439 = rfc8439()
    awp = wycheproof_chacha20_poly1305()
    q9001 = rfc9001_chacha()
    dchacha, dpoly, daead = differential_chacha()
    aes_ecb, aes_mct, aes_ctr, aes_hp = aes_vectors()
    gcm_cavp, gcm_wp, gcm_quic = cavp_gcm(), wycheproof_aes_gcm(), rfc9001_gcm()
    gcm_diff, ghash = differential_gcm()
    x7748, x_iter = rfc7748()
    x25519 = x7748 + rfc8448_x25519() + wycheproof_x25519() + differential_x25519()

    global P256_G
    p256_params = rfc5903_params("3.1.", 256, P256)
    P256_G = (P256["gx"], P256["gy"])
    check_p256_source_constants()
    k5903, e5903 = rfc5903_ecdh()
    kcavp, ecavp, vcavp = cavp_p256()
    kdiff, ediff, vdiff = differential_p256()
    ksgen, vsgen = cavp_siggen()
    p256_keys = k5903 + kcavp + kdiff + ksgen
    p256_ecdh = e5903 + ecavp + wycheproof_p256_ecdh() + ediff
    p256_verify = vcavp + wycheproof_p256_ecdsa() + rfc6979_verify() + vdiff + vsgen
    p256_scalar = p256_scalar_vectors()
    p256_sign = rfc6979_sign() + differential_p256_sign()

    global P384_G
    p384_params = rfc5903_params("3.2.", 384, P384)
    P384_G = (P384["gx"], P384["gy"])
    check_p384_source_constants()
    p384_verify = cavp_p384_sigver() + cavp_p384_pkv() + rfc6979_verify_384()
    p384_flags = {}
    for src, hfn, sha in (("wp_p384_ecdsa_sha384", hashlib.sha384, "SHA-384"),
                          ("wp_p384_ecdsa_sha512", hashlib.sha512, "SHA-512")):
        rows, valid, wrong_len, flags = wycheproof_p384_ecdsa(src, hfn, sha)
        print(f"  wycheproof {src}: {len(rows)} rows, {valid} valid, {wrong_len} wrong width")
        # Pinned to the files named in tests/kat/SOURCES.md: 280 and 318 rows upstream, 19 of
        # each dropped on the 96/97-byte width filter (R3/R4 fix both widths).
        want = {"wp_p384_ecdsa_sha384": (261, 193, 19), "wp_p384_ecdsa_sha512": (299, 230, 19)}
        if (len(rows), valid, wrong_len) != want[src]:
            die(f"Wycheproof {src}: {len(rows)}/{valid}/{wrong_len}, expected {want[src]}")
        p384_flags.update({k: p384_flags.get(k, 0) + v for k, v in flags.items()})
        p384_verify += rows
    print("  wycheproof P-384 flags:", dict(sorted(p384_flags.items(), key=lambda kv: -kv[1])))
    p384_verify += differential_p384()

    global DIGESTINFO
    DIGESTINFO = rfc8017_digestinfo()
    check_rsa_source_constants()
    pkcs1, pss = [], []
    for src, fname in (("cavp_rsa2", "SigVer15_186-3.rsp"), ("cavp_rsa3", "SigVer15_186-3.rsp")):
        rows, np_, nf = cavp_rsa(src, fname, 0)
        print(f"  CAVP {src} {fname}: {np_} P / {nf} F")
        pkcs1 += rows
    for src, fname in (("cavp_rsa2", "SigVerPSS_186-3.rsp"), ("cavp_rsa3", "SigVerPSS_186-3.rsp")):
        rows, np_, nf = cavp_rsa(src, fname, 1)
        print(f"  CAVP {src} {fname}: {np_} P / {nf} F")
        pss += rows
    if len(pkcs1) != 216 or len(pss) != 180:
        die(f"CAVP RSA: {len(pkcs1)} v1.5 and {len(pss)} PSS rows, expected 216 and 180")
    wp_flags = {}
    for b in (2048, 3072, 4096):
        for s in ("sha256", "sha384", "sha512"):
            rows, counts, flags, skip = wycheproof_rsa(f"wp_rsa_pkcs1_{b}_{s}", 0, 2048)
            print(f"  wycheproof rsa_signature_{b}_{s}: {counts} (+{skip} out of scope)")
            wp_flags.update({k: wp_flags.get(k, 0) + v for k, v in flags.items()})
            pkcs1 += rows
    for v in ("2048_sha256_mgf1_0", "2048_sha256_mgf1_32", "2048_sha384_mgf1_48",
              "3072_sha256_mgf1_32", "4096_sha256_mgf1_32", "4096_sha384_mgf1_48",
              "4096_sha512_mgf1_32", "4096_sha512_mgf1_64", "misc"):
        rows, counts, flags, skip = wycheproof_rsa(f"wp_rsa_pss_{v}", 1, 2048)
        print(f"  wycheproof rsa_pss_{v}: {counts} (+{skip} out of scope)")
        wp_flags.update({k: wp_flags.get(k, 0) + v2 for k, v2 in flags.items()})
        pss += rows
    print("  wycheproof RSA flags:", dict(sorted(wp_flags.items(), key=lambda kv: -kv[1])))
    pkcs1 += rsa_em_corruption()
    pss += rsa_pss_em_corruption()
    bn = bn_vectors()
    der = der_generated() + der_wycheproof()
    der_val = der_values()
    check_x509_source_constants()
    global CHAIN_NOW
    CHAIN_NOW = py_asn1_time("270601000000Z")  # inside every row's window, above the floor
    check_x509_time_config()
    check_x509_anchor_max()
    x509_certs = x509_cert_vectors()
    x509_times = x509_time_vectors()
    x509_validity = x509_validity_vectors()
    global RSA_CHAIN_KEY
    # 2049 and not 2048: rsa_odd_modbits_key assembles its modulus out of published CAVP primes
    # and no product of those lands on exactly 2048 bits. Nothing in a certificate cares about
    # the size, and modBits % 8 == 1 puts the PSS rows on the emLen = k - 1 branch of RFC 8017
    # 8.1.2 step 2c for free.
    RSA_CHAIN_KEY = rsa_odd_modbits_key(2049)
    x509_chains = x509_chain_vectors()
    x509_sigs = x509_sig_vectors()
    x509_names = x509_name_vectors()
    x509_ips = x509_ip_vectors()
    x509_bundles = x509_bundle_vectors()
    x509_stores = x509_store_vectors()
    x509_pins = x509_pin_vectors()
    x509_limbo, x509_limbo_skipped = x509_limbo_vectors()
    tls13_rfc = rfc9846_constants()
    tls13_flows, tls13_parts = tls13_traces()
    tls13_fx, tls13_chw = tls13_fixture()
    tls13_mut = t_mutations(tls13_parts)
    tls13_cv_keys, tls13_cv = tls13_cv_vectors()
    tls13_pskf, psk_chw, psk_muts, tls13_mtls, tls13_psk1 = tls13_psk(tls13_parts)
    tls13_chw += psk_chw
    base = len(tls13_flows) + len(tls13_fx)
    for off, name, msg, alert, note in psk_muts:
        r = tls13_pskf[off]
        names = [n for n, i in (("hrr", 9), ("sh", 14), ("ee", 15), ("cr", 16), ("cert", 17),
                                ("cv", 18), ("sf", 19)) if r[i]]
        tls13_mut.append((base + off, names.index(name), msg.hex(), ALERT[alert], note))
    tls13_der = tls13_ecdsa_der()
    rec_rows, rec_nonces, rec_hsmsg, rec_seeds, rec_fuzz_key = tls13_records()

    emit("sha2.inc", "struct hash_kat SHA2_KAT", cavp + dhash, lambda r: f"{r[0]}, {cstr(r[1])}, {cstr(r[2])}")
    emit("sha2_monte.inc", "struct monte_kat SHA2_MONTE", monte,
         lambda r: f"{r[0]}, {cstr(r[1])}, {{" + ", ".join(cstr(x) for x in r[2]) + "}")
    emit("sha2_million.inc", "struct million_kat SHA2_MILLION", million, lambda r: f"{r[0]}, {cstr(r[1])}")
    emit("hmac.inc", "struct hmac_kat HMAC_KAT", hmacs + dmac,
         lambda r: f"{r[0]}, {cstr(r[1])}, {cstr(r[2])}, {cstr(r[3])}, {r[4]}")
    emit("hkdf.inc", "struct hkdf_kat HKDF_KAT", kdfs + dkdf,
         lambda r: f"{r[0]}, {cstr(r[1])}, {cstr(r[2])}, {cstr(r[3])}, {r[4]}, {cstr(r[5])}, {r[6]}, {cstr(r[7])}")
    emit("hkdf_extract.inc", "struct extract_kat EXTRACT_KAT", x8448 + x9001,
         lambda r: f"{r[0]}, {cstr(r[1])}, {cstr(r[2])}, {cstr(r[3])}")
    emit("expand_label.inc", "struct label_kat LABEL_KAT", l8448 + l9001,
         lambda r: f'{r[0]}, {cstr(r[1])}, "{r[2]}", {cstr(r[3])}, {cstr(r[4])}')

    hx = lambda b: cstr(b.hex())
    emit("chacha20.inc", "struct chacha_kat CHACHA_KAT", c8439 + dchacha,
         lambda r: f"{hx(r[0])}, 0x{r[1]:08x}u, {hx(r[2])}, {hx(r[3])}, {hx(r[4])}")
    emit("poly1305.inc", "struct poly_kat POLY_KAT", p8439 + dpoly, lambda r: ", ".join(hx(x) for x in r))
    emit("chacha20_poly1305.inc", "struct aead_kat AEAD_KAT", a8439 + awp + daead,
         lambda r: ", ".join(hx(x) for x in r[:6]) + f", {r[6]}")
    emit("quic_chacha.inc", "struct quic_chacha_kat QUIC_CHACHA_KAT", q9001,
         lambda r: f"{hx(r[0])}, {r[1]}u, " + ", ".join(hx(x) for x in r[2:]))

    emit("aes_ecb.inc", "struct aes_ecb_kat AES_ECB_KAT", aes_ecb, lambda r: ", ".join(hx(x) for x in r))
    emit("aes_mct.inc", "struct aes_mct_kat AES_MCT_KAT", aes_mct,
         lambda r: f"{r[0]}, " + ", ".join(hx(x) for x in r[1:]))
    emit("aes_ctr.inc", "struct aes_ctr_kat AES_CTR_KAT", aes_ctr, lambda r: ", ".join(hx(x) for x in r))
    emit("aes_quic_hp.inc", "struct aes_hp_kat AES_HP_KAT", aes_hp, lambda r: ", ".join(hx(x) for x in r))
    emit("aes_gcm.inc", "struct gcm_kat GCM_KAT", gcm_wp + gcm_cavp + gcm_diff,
         lambda r: ", ".join(hx(x) for x in r[:6]) + f", {r[6]}")
    emit("ghash.inc", "struct ghash_kat GHASH_KAT", ghash, lambda r: ", ".join(hx(x) for x in r))
    emit("quic_gcm.inc", "struct quic_gcm_kat QUIC_GCM_KAT", gcm_quic,
         lambda r: f"{hx(r[0])}, {r[1]}u, " + ", ".join(hx(x) for x in r[2:]))

    emit("x25519.inc", "struct x25519_kat X25519_KAT", x25519,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}, {cstr(r[2])}, {r[3]}, {r[4]}")
    emit("x25519_iter.inc", "struct x25519_iter_kat X25519_ITER_KAT", x_iter,
         lambda r: f"{r[0]}L, {cstr(r[1])}")

    emit("p256_params.inc", "struct p256_param P256_PARAM", p256_params,
         lambda r: f'"{r[0]}", {cstr(r[1])}')
    emit("p256_keygen.inc", "struct p256_keygen_kat P256_KEYGEN_KAT", p256_keys,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}, {r[2]}")
    emit("p256_ecdh.inc", "struct p256_ecdh_kat P256_ECDH_KAT", p256_ecdh,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}, {cstr(r[2])}, {r[3]}, {r[4]}")
    emit("p256_verify.inc", "struct p256_verify_kat P256_VERIFY_KAT", p256_verify,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}, {cstr(r[2])}, {r[3]}, {r[4]}")
    emit("p256_scalar.inc", "struct p256_scalar_kat P256_SCALAR_KAT", p256_scalar,
         lambda r: f"{r[0]}, {cstr(r[1])}, {cstr(r[2])}, {cstr(r[3])}")
    emit("p256_sign.inc", "struct p256_sign_kat P256_SIGN_KAT", p256_sign,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}, {cstr(r[2])}, {cstr(r[3])}, {r[4]}")

    emit("p384_params.inc", "struct p384_param P384_PARAM", p384_params,
         lambda r: f'"{r[0]}", {cstr(r[1])}')
    emit("p384_verify.inc", "struct p384_verify_kat P384_VERIFY_KAT", p384_verify,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}, {cstr(r[2])}, {r[3]}, {r[4]}")

    emit("rsa_key.inc", "struct rsa_key RSA_KEY", RSA_KEYS,
         lambda r: f"{cstr(r[0])}, {cstr(r[1])}")
    emit("rsa_pkcs1.inc", "struct rsa_kat RSA_PKCS1_KAT", pkcs1,
         lambda r: f"{r[0]}, {r[1]}, {r[2]}, {cstr(r[3])}, {cstr(r[4])}, {r[5]}, {r[6]}")
    emit("rsa_pss.inc", "struct rsa_kat RSA_PSS_KAT", pss,
         lambda r: f"{r[0]}, {r[1]}, {r[2]}, {cstr(r[3])}, {cstr(r[4])}, {r[5]}, {r[6]}")
    emit("bn_mod.inc", "struct bn_mod BN_MOD", BN_MODULI, lambda r: cstr(r))
    emit("bn.inc", "struct bn_kat BN_KAT", bn,
         lambda r: f"{r[0]}, {r[1]}, {cstr(r[2])}, {cstr(r[3])}, {cstr(r[4])}, {r[5]}")

    emit("der.inc", "struct der_kat DER_KAT", der,
         lambda r: f'{cstr(r[0])}, {r[1]}, "{r[2]}"')
    emit("der_val.inc", "struct der_val_kat DER_VAL_KAT", der_val,
         lambda r: f"{r[0]}, {cstr(r[1])}, {r[2]}, {cstr(r[3])}, {r[4]}u")

    emit("x509_time.inc", "struct x509_time_kat X509_TIME_KAT", x509_times,
         lambda r: f'0x{r[0]:02x}, "{r[1]}", {r[2]}, {r[3]}LL')
    emit("x509_cert.inc", "struct cert_kat X509_CERT_KAT", x509_certs,
         lambda r: f'{cstr(r[0])}, {r[1]}, "{r[2]}", {r[3]}, {r[4]}, {r[5]}, {r[6]}, {r[7]}, '
                   f'{r[8]}, {r[9]}u, {r[10]}u, {r[11]}, {r[12]}, {cstr(r[13])}, {cstr(r[14])}, '
                   f'{r[15]}LL, {r[16]}LL')
    emit("x509_validity.inc", "struct validity_kat X509_VALIDITY_KAT", x509_validity,
         lambda r: f'{cstr(r[0])}, {r[1]}LL, {{{r[2][0]}, {r[2][1]}, {r[2][2]}}}, "{r[3]}"')
    chain_fmt = lambda r: ("{" + ", ".join([cstr(c) for c in r[0]]
                                           + ["NULL"] * (CHAIN_MAX_CERTS - len(r[0]))) + "}, "
                           + "{" + ", ".join([cstr(a) for a in r[1]]
                                             + ["NULL"] * (CHAIN_MAX_ANCHORS - len(r[1]))) + "}, "
                           + f'{r[2]}, {r[3]}, {r[4]}LL, "{cesc(r[5])}"')
    emit("x509_chain.inc", "struct chain_kat X509_CHAIN_KAT", x509_chains, chain_fmt)
    emit("x509_limbo.inc", "struct chain_kat X509_LIMBO_KAT", x509_limbo, chain_fmt)
    emit("x509_sig.inc", "struct sig_kat X509_SIG_KAT", x509_sigs,
         lambda r: f'{cstr(r[0])}, {cstr(r[1])}, {r[2]}, {r[3]}, "{r[4]}"')
    emit("x509_name.inc", "struct name_kat X509_NAME_KAT", x509_names,
         lambda r: f'{cstr(r[0])}, "{cesc(r[1])}", {r[2]}, "{r[3]}"')
    emit("x509_ip.inc", "struct ip_kat X509_IP_KAT", x509_ips,
         lambda r: f'"{r[0]}", {cstr(r[1])}, "{r[2]}"')
    emit("x509_bundle.inc", "struct bundle_kat X509_BUNDLE_KAT", x509_bundles,
         lambda r: f'{cpem(r[0])}, '
                   + "{" + ", ".join([cstr(b) for b in r[1]]
                                     + ["NULL"] * (BUNDLE_MAX_BLOBS - len(r[1]))) + "}, "
                   + f'"{r[2]}"')
    emit("x509_store.inc", "struct store_kat X509_STORE_KAT", x509_stores,
         lambda r: f'{cpem(r[0])}, '
                   + "{" + ", ".join([cstr(c) for c in r[1]]
                                     + ["NULL"] * (STORE_MAX_CERTS - len(r[1]))) + "}, "
                   + f'{r[2]}, {r[3]}LL, "{r[4]}"')
    emit("x509_pin.inc", "struct pin_kat X509_PIN_KAT", x509_pins,
         lambda r: "{" + ", ".join([cstr(c) for c in r[0]]
                                   + ["NULL"] * (CHAIN_MAX_CERTS - len(r[0]))) + "}, "
                   + "{" + ", ".join([cstr(a) for a in r[1]]
                                     + ["NULL"] * (CHAIN_MAX_ANCHORS - len(r[1]))) + "}, "
                   + "{" + ", ".join([f'"{h}"' for h in r[2]]
                                     + ["NULL"] * (PIN_MAX - len(r[2]))) + "}, "
                   + f'{r[3]}, {r[4]}LL, "{r[5]}"')

    emit("tls13_trace.inc", "struct tls13_flow_kat TLS13_FLOW_KAT", tls13_flows + tls13_fx + tls13_pskf,
         lambda r: f'"{cesc(r[0])}", {cstr(r[1])}, "{r[2]}", {r[3]}LL, {r[4]}, {r[5]}, '
                   f'0x{r[6]:04x}u, {cstr(r[7])}, {cstr(r[8])}, {cstr(r[9])}, 0x{r[10]:04x}u, '
                   + ", ".join(cstr(x) for x in r[11:29])
                   + f', 0x{r[29]:04x}u, {r[30]}, "{r[31]}", {cstr(r[32])}, {cstr(r[33])}, '
                   f'{cstr(r[34])}')
    emit("tls13_trace.inc", "struct tls13_rfc_kat TLS13_RFC_KAT", tls13_rfc,
         lambda r: ", ".join(cstr(x) for x in r), append=True)
    emit("tls13_trace.inc", "struct tls13_chw_kat TLS13_CHW_KAT", tls13_chw,
         lambda r: ", ".join(cstr(x) for x in r[:5]) + f', "{r[5]}", 0x{r[6]:04x}u, '
                   + ", ".join(cstr(x) for x in r[7:11]) + f", {r[11]}, {cstr(r[12])}, "
                   f"{r[13]}u, {r[14]}", append=True)
    emit("tls13_psk.inc", "struct tls13_psk_kat TLS13_PSK_KAT", tls13_psk1,
         lambda r: ", ".join(cstr(x) for x in r[:8]) + f", {r[8]}LL, {r[9]}LL, {r[10]}u, "
                   f"{cstr(r[11])}, {cstr(r[12])}, {r[13]}u, {r[14]}u")
    emit("tls13_psk.inc", "struct tls13_mtls_kat TLS13_MTLS_KAT", tls13_mtls,
         lambda r: f'"{r[0]}", {cstr(r[1])}, {cstr(r[2])}, {r[3]}', append=True)
    emit("tls13_psk.inc", "struct tls13_der_kat TLS13_DER_KAT", tls13_der,
         lambda r: f'{cstr(r[0])}, {cstr(r[1])}, "{r[2]}"', append=True)
    # Seeds for fuzz/fuzz_ticket.c (tools/dev.py fuzz ticket): the one ticket blob.
    emit("tls13_ticket_fuzz.inc", "struct tls13_fuzz_seed TLS13_TICKET_FUZZ_SEED",
         [(tls13_psk1[0][7], "RFC 8448 sect 3 ticket, v1 blob")],
         lambda r: f'{cstr(r[0])}, "{r[1]}"')
    # Seeds for fuzz/fuzz_tls13_hs.c (tools/dev.py fuzz tls13_hs), not included by any test:
    # [ServerHello length] ServerHello || the HANDSHAKE flight, the harness's input format. The
    # sect 3 flight passes that harness's ServerHello checks, so the fuzzer starts deep.
    seeds = []
    for r in tls13_flows + tls13_fx + tls13_pskf:
        sh = bytes.fromhex(r[9] or r[14])
        rest = b"".join(bytes.fromhex(x) for x in r[15:20])
        if len(sh) < 256:
            seeds.append(((bytes([len(sh)]) + sh + rest).hex(), r[0]))
    emit("tls13_fuzz.inc", "struct tls13_fuzz_seed TLS13_FUZZ_SEED", seeds,
         lambda r: f'{cstr(r[0])}, "{cesc(r[1])}"')
    emit("tls13_mut.inc", "struct tls13_mut_kat TLS13_MUT_KAT", tls13_mut,
         lambda r: f'{r[0]}, {r[1]}, {cstr(r[2])}, {r[3]}, "{cesc(r[4])}"')
    emit("tls13_cv.inc", "struct tls13_cv_key TLS13_CV_KEY", tls13_cv_keys,
         lambda r: f"{r[0]}, {cstr(r[1])}")
    emit("tls13_cv.inc", "struct tls13_cv_kat TLS13_CV_KAT", tls13_cv,
         lambda r: f"{r[0]}, 0x{r[1]:04x}u, {cstr(r[2])}, {cstr(r[3])}, {r[4]}", append=True)
    emit("tls13_record.inc", "struct tls13_rec_kat TLS13_REC_KAT", rec_rows,
         lambda r: f'"{r[0]}", {r[1]}, {r[2]}, {r[3]}, 0x{r[4]:04x}u, {cstr(r[5])}, {cstr(r[6])}, '
                   f'{cstr(r[7])}, 0x{r[8]:016x}ULL, {r[9]}, 0x{r[10]:04x}u, {r[11]}u, {cstr(r[12])}, '
                   f'{cstr(r[13])}, {r[14]}')
    emit("tls13_record.inc", "struct tls13_nonce_kat TLS13_NONCE_KAT", rec_nonces,
         lambda r: f'{cstr(r[0])}, 0x{r[1]:016x}ULL, {cstr(r[2])}', append=True)
    emit("tls13_record.inc", "struct tls13_hsmsg_kat TLS13_HSMSG_KAT", rec_hsmsg,
         lambda r: f'"{r[0]}", {cstr(r[1])}, {r[2]}, {r[3]}u, {r[4]}u, {r[5]}u, {cstr(r[6])}, '
                   f'{cstr(r[7])}', append=True)
    # Seeds for fuzz/fuzz_tls13_rec.c (tools/dev.py fuzz tls13_rec), not included by any test,
    # and the receive secret the harness installs so the seeds decrypt.
    emit("tls13_rec_fuzz.inc", "struct tls13_fuzz_seed TLS13_REC_FUZZ_SEED", rec_seeds,
         lambda r: f'{cstr(r[0])}, "{cesc(r[1])}"')
    with open(OUT / "tls13_rec_fuzz.inc", "a", newline="\n") as fh:
        fh.write(f'static const char TLS13_REC_FUZZ_S_AP[] = "{rec_fuzz_key.hex()}";\n')

    rows = "\n".join(f"| {k} | {u} | `{h}` |" for k, (u, h) in sorted(fetched.items()))
    (OUT / "SOURCES.md").write_text(
        "# Known-answer vector sources\n\n"
        f"Generated by `python tools/kat.py` on {datetime.date.today()}. Each vector was re-checked\n"
        "against Python hashlib/hmac or the pure-Python ChaCha20/Poly1305/AES\n"
        "reference before emission. Differential vectors come from a fixed seed.\n\n"
        "| name | url | sha256 of download |\n|---|---|---|\n" + rows + "\n\n"
        "## Deliberately not used\n\n"
        "- `ecdsa_secp256r1_sha256_test.json` (the DER-encoded Wycheproof sibling of\n"
        "  `ecdsa_secp256r1_sha256_p1363_test.json`). `brisk__p256_ecdsa_verify` takes a fixed\n"
        "  64-byte r||s, so that suite's extra invalid cases are all ASN.1 encoding errors and\n"
        "  belong to the M2 DER parser, not here. Not forgotten - out of scope by design. (M3 does\n"
        "  use it, together with the P-384 `ecdsa_secp384r1_sha384_test.json`, through the\n"
        "  CertificateVerify path in `tests/kat/tls13_cv.inc`, where the DER unwrap belongs.)\n"
        "- CAVP `PKV.rsp` [P-256]: 4 of the 12 rows are \"Q_x or Q_y out of range\" with a 33-byte\n"
        "  coordinate, which the 65-byte encoding of RFC 9846 4.3.8.2 cannot express. The in-range\n"
        "  half of that check is pinned by generated `x == p` / `y == p` / `coord == 2^256-1` rows.\n"
        "- `ecdh_secp256r1_ecpoint_test.json`: 9 of the 355 rows carry a 0- or 33-byte encoding\n"
        "  (one empty, eight compressed, including the single \"acceptable\" one). `brisk__p256_ecdh`\n"
        "  takes a fixed `uint8_t[65]`, so those cannot reach it - the length check belongs to the\n"
        "  TLS layer reading `KeyShareEntry.key_exchange`. The rule behind them, that a compressed\n"
        "  point is rejected and never decompressed, is pinned instead by generated\n"
        "  0x02/0x03/0x06/0x07 rows and by the all-256-first-bytes sweep in `tests/test_p256.c`.\n"
        "- `ecdsa_secp256r1_sha256_p1363_test.json`: 21 of the 262 rows carry a signature that is\n"
        "  not 64 bytes (2 to 82), all of them \"invalid\". `brisk__p256_ecdsa_verify` takes a fixed\n"
        "  `uint8_t[64]`, so the width is settled by the caller that unwraps the DER\n"
        "  ECDSA-Sig-Value. Their substance - r or s outside [1, n-1] - is pinned at the right\n"
        "  width by generated r/s edge rows (0, n, n+1, 2^256-1 on each side).\n"
        "- CAVP `SigVer.rsp` `[P-256,SHA-1]` and `[P-256,SHA-224]`, and the RFC 6979 A.2.5\n"
        "  SHA-1 / SHA-224 rows. These are skipped for a *behavioural* reason, not an\n"
        "  encoding one: `brisk__p256_ecdsa_verify` requires `hash_len >= 32` and returns\n"
        "  `BRISK_E_ARG` below that, because RFC 9846 4.3.3 forbids SHA-224 and leaves SHA-1\n"
        "  legacy-only, and `include/brisk.h` compiles no digest shorter than SHA-256. The\n"
        "  `[P-256,SHA-384]` and `[P-256,SHA-512]` sections of the same file ARE used, 15 rows\n"
        "  each with 12 failing: they are what exercises the FIPS 186-5 6.4.2 leftmost-bits\n"
        "  rule with official negative vectors.\n"
        "- CAVP `PKV.rsp` `[P-384]`: 4 of the 12 rows carry a 385-bit (97 hex char) coordinate,\n"
        "  which the 97-byte encoding of RFC 9846 4.3.8.2 cannot express - truncating them would\n"
        "  turn them into different points. The remaining 8 are driven through\n"
        "  `brisk__p384_ecdsa_verify` with a fixed in-range `(r, s) = (7, 11)` that cannot\n"
        "  verify, so a valid point lands on `BRISK_E_AUTH` and an off-curve one on\n"
        "  `BRISK_E_ARG`. The in-range half of the coordinate check (p <= coord < 2^384) is\n"
        "  pinned by generated `x == p` / `y == p` / `coord == 2^384-1` rows instead.\n"
        "- CAVP `SigVer.rsp` `[P-384,SHA-1]`, `[P-384,SHA-224]` and `[P-384,SHA-256]`, and the\n"
        "  RFC 6979 A.2.6 SHA-1 / SHA-224 / SHA-256 rows. Skipped for a *behavioural* reason:\n"
        "  `brisk__p384_ecdsa_verify` requires `hash_len >= 48` and returns `BRISK_E_ARG` below\n"
        "  that (FIPS 186-5 6.4.2 reads only the leftmost 48 octets). RFC 9846 4.3.3 pairs the\n"
        "  curve with SHA-384 in `ecdsa_secp384r1_sha384`, so TLS never asks for the shorter\n"
        "  pairing; a P-384 key certified with `ecdsa-with-SHA256` exists in some private PKIs\n"
        "  and M2's certificate layer must reject it with `unsupported_certificate` rather than\n"
        "  call in with `hash_len 32`. The `[P-384,SHA-384]` and `[P-384,SHA-512]` sections ARE\n"
        "  used, 15 rows each with 12 failing.\n"
        "- `ecdsa_secp384r1_sha384_p1363_test.json` and `ecdsa_secp384r1_sha512_p1363_test.json`:\n"
        "  19 of 280 and 19 of 318 rows carry a signature that is not 96 bytes, all of them\n"
        "  \"invalid\". `brisk__p384_ecdsa_verify` takes a fixed `uint8_t[96]`, so the width is\n"
        "  settled by the caller that unwraps the DER ECDSA-Sig-Value. Their substance - r or s\n"
        "  outside [1, n-1] - is pinned at the right width by generated edge rows (0, n, n+1,\n"
        "  2^384-1 on each side). The DER siblings of both files are out of scope here for the\n"
        "  same reason the P-256 one is; the SHA-384 one is used by `tls13_cv.inc`.\n"
        "- TLS 1.3 handshake (`tls13_*.inc`): NIST CAVP has no handshake vectors, and the RFC 9001\n"
        "  A.2/A.3 QUIC Initial ClientHello/ServerHello belong to M6. Sect 6's client flight uses\n"
        "  an RSA client key this library cannot produce, so from there on the values are ours,\n"
        "  computed by the same Python cascade that reproduces sections 3, 5 and 7 byte for byte;\n"
        "  the ECDSA P-256 device-key flight (`tls13_trace.inc`, sect 6 shape) is generated the\n"
        "  same way with a fixture certificate and a fixed hedging input, and its CertificateVerify\n"
        "  is re-verified in Python and in C.\n"
        "- TLS 1.3 resumption (`tls13_psk.inc`, the PSK rows of `tls13_trace.inc`). OFFICIAL, from\n"
        "  RFC 8448: sect 3's NewSessionTicket and the PSK it yields, sect 4's binder over the\n"
        "  'ClientHello prefix', the binder hash, the early secret, and the sect 4 handshake /\n"
        "  application secrets and server Finished, all re-derived here from the official\n"
        "  messages. NOT usable, because they are 0-RTT specific: `c e traffic`, EndOfEarlyData,\n"
        "  sect 4's client Finished and its res master; sect 4's ClientHello itself carries\n"
        "  early_data, so the engine must refuse it (a negative row). GENERATED by the same\n"
        "  cascade: the resumed flow with a ClientHello in `brisk__tls13_ch_write`'s layout (no\n"
        "  early_data), a declined PSK, PSK + HelloRetryRequest (the binder over\n"
        "  message_hash(CH1) || HRR || Truncate(CH2) - no official vector exists), and the ticket\n"
        "  blob. No Wycheproof or NIST suite exists for PSK binders, ticket blobs or ALPN; RFC 7301\n"
        "  and RFC 6066 publish no vectors, so the ALPN/SNI encoding rows are generated and\n"
        "  tlsfuzzer's test-alpn-negotiation.py / test-sni-*.py served as a case catalogue only.\n"
        "  The ECDSA-Sig-Value ENCODER round-trips every 'valid' row of\n"
        "  `ecdsa_secp256r1_sha256_test.json`.\n"
        "- TLS 1.3 record layer (`tls13_record.inc`): Wycheproof has NO TLS record-layer suite and\n"
        "  NIST CAVP has no TLS 1.3 record set. The AEADs underneath are covered by M1\n"
        "  (`aes_gcm.inc`, `chacha20_poly1305.inc`, valid and invalid tags). The official rows are\n"
        "  every RFC 8448 sect 3-7 record, re-sealed from its payload under the trace's keys, and\n"
        "  the RFC 9001 A.5 nonce (a multi-byte XOR). ChaCha20-Poly1305 and AES-256-GCM/SHA-384\n"
        "  records, KeyUpdate ('traffic upd') chains, padding, the size limits and every invalid\n"
        "  row are generated with the same Python AEADs - no official vector exists for any of\n"
        "  them. tlsfuzzer's record/keyupdate/zero-length/record_size_limit scripts were used as a\n"
        "  case catalogue only (they test servers).\n"
        "- There is no P-384 *keygen*, *ECDH* or *signing* vector set here, and there never will\n"
        "  be: docs/ARCHITECTURE.md locks P-384 to verify only, so `KAS_ECC_CDH` `[P-384]`,\n"
        "  `KeyPair.rsp` `[P-384]`, `SigGen.txt` `[P-384]` and `ecdh_secp384r1_*` are all out of\n"
        "  scope by design rather than forgotten.\n"
        "- No Wycheproof ECDSA *signing* suite exists, for `brisk__p256_ecdsa_sign` or for\n"
        "  anyone else: signing has no attacker-controlled input, so there is nothing for a\n"
        "  test suite to attack. The invalid half of `p256_sign.inc` is therefore generated -\n"
        "  d in {0, n, n+1, 2^256-1} and hash_len in {31, 33, 47, 49, 63, 65}. The verify half\n"
        "  that the sign round trip leans on keeps `ecdsa_secp256r1_sha256_p1363_test.json` as\n"
        "  its invalid-input authority, and that suite's rejected r/s classes are what\n"
        "  guarantee our own signatures do not land in one.\n"
        "- No official vectors exist for the HEDGED nonce (RFC 6979 3.6), by construction: the\n"
        "  RFC says a variant \"ceases to be verifiable against the test vectors published in\n"
        "  this document\". The hedged rows come from the second, independent RFC 6979\n"
        "  implementation in tools/kat.py, and what anchors them is that the same code path\n"
        "  with k' absent reproduces RFC 6979 A.2.5 byte-for-byte - k as well as r and s.\n"
        "- CAVP `SigGenComponent.txt` is not in the 186-3 zip named above (it ships with the\n"
        "  186-4 one). `SigGen.txt` from this zip is used instead and carries d and k, so the\n"
        "  signing core is validated against NIST all the same.\n"
        "- **The i31 bignum kernel has NO official vector source.** None exists anywhere for a\n"
        "  bare big-integer library. What stands under `tests/kat/bn.inc` is a seeded\n"
        "  differential set against Python's arbitrary-precision `int`, generated at the i31 limb\n"
        "  boundaries (31*k - 1, 31*k, 31*k + 1), plus the NIST and Wycheproof RSA suites as the\n"
        "  end-to-end net. That is genuinely weaker than what SHA-2 or AES got. Recorded here as\n"
        "  an accepted gap rather than left implicit.\n"
        "- Wycheproof `rsa_signature_2048_sha256_test.json` has exactly one `acceptable` row\n"
        "  (flag `MissingNull`: a DigestInfo without the explicit NULL parameters). This library\n"
        "  calls it INVALID. RFC 8017 9.2 note 1 fixes T as the DER encoding *with* `05 00`, and\n"
        "  note 2's BER-lenient variant is explicitly not adopted - so absent NULL parameters,\n"
        "  BER-encoded padding and trailing octets after the digest are all rejected. That is a\n"
        "  decision, not a fact about the vector, and `tools/kat.py` maps `acceptable` to\n"
        "  `BRISK_E_AUTH` on purpose.\n"
        "- RFC 8017 itself publishes no test vectors. It is fetched and pinned anyway, because\n"
        "  the three DER DigestInfo prefixes of 9.2 note 1 are parsed out of its text instead of\n"
        "  being hand-typed - the same trick `check_p256_source_constants()` uses for the P-256\n"
        "  parameters, and the only way to get that table without typing a vector by hand.\n"
        "- RSA suites deliberately NOT used: `rsa_pkcs1_<bits>_test.json` and `rsa_oaep_*`\n"
        "  (encryption - not in this library); `rsa_*_sig_gen_test.json` (signing - locked out,\n"
        "  RSA is verify only); `rsa_signature_8192_*` (above `BRISK_RSA_MAX_BITS`);\n"
        "  `rsa_pss_*_params_test.json` and every `publicKeyAsn`/`Der`/`Pem`/`Jwk` field (DER -\n"
        "  that belongs to M2); every sha1/sha224/sha3/shake/sha512_224/sha512_256 suite and the\n"
        "  CAVP SHA-1 / SHA-224 sections (no such `brisk_hash_alg` value exists);\n"
        "  `rsa_pss_2048_sha256_mgf1sha1_20`, `rsa_pss_2048_sha512_mgf1sha256_32` and the\n"
        "  132 of 150 `rsa_pss_misc` groups whose `mgfSha` differs from `sha` (this API takes one\n"
        "  `alg` for both, which is what RFC 9846 4.3.3 mandates, so such a parameter set cannot\n"
        "  be expressed at all - the M2 DER parser rejects it before it gets here); CAVP\n"
        "  `mod = 1024` and `mod = 1536` sections (below the 2048 floor of NIST SP 800-57 Part 1\n"
        "  Rev 5 5.6.2); the `*_TruncatedSHAs.rsp` files (SHA-512/224, SHA-512/256); and\n"
        "  `SigVerRSA.rsp` / `SigVer931*` (X9.31, not PKCS#1).\n"
        "- The r == 0 / s == 0 retry (p ~ 2^-128) and the k-out-of-range retry (p ~ 2^-32) in\n"
        "  `brisk__p256_ecdsa_sign` ship with NO known-answer coverage. Neither can be reached\n"
        "  by any official vector and neither can be searched for at P-256 sizes. What stands\n"
        "  in for a vector is the bounded retry loop, the code review, and the fact that the\n"
        "  Python generator implements the same rejection logic. A real, accepted coverage gap.\n"
        "- **The DER reader has no official vector suite either**, because nobody publishes one\n"
        "  for ASN.1 encoding rules - X.690 is a specification, not a test corpus. `der.inc`\n"
        "  therefore has three parts, and only the middle one is adversarial data written by\n"
        "  someone else: (1) every `publicKeyDer` / `publicKeyAsn` blob in the cached Wycheproof\n"
        "  RSA, P-256 and P-384 suites, which a strict reader must accept; (2) the 481 distinct\n"
        "  signature blobs of `ecdsa_secp256r1_sha256_test.json` - the DER sibling of the p1363\n"
        "  file used for ECDSA itself, carrying 92 `InvalidEncoding`, 7 `BerEncodedSignature`\n"
        "  and the `IntegerOverflow` / `ModifiedInteger` families; (3) generated rows, one per\n"
        "  X.690 clause, for the shapes no real signature contains (a BIT STRING with 8 unused\n"
        "  bits, a 17-deep nesting, a constructed OCTET STRING).\n"
        "- The expected verdict for a Wycheproof blob is NEVER read off its flag. A flag\n"
        "  describes a *signature*, and a blob can be flawless DER encoding the wrong thing -\n"
        "  `InvalidTypesInSignature` (63 rows) is exactly that, valid DER that a signature\n"
        "  reader must reject and a DER reader must accept. The verdict comes from\n"
        "  `py_der_walk()`, a second implementation of clause 10/11 written against the text;\n"
        "  the flags are then asserted on the aggregate - every `valid` row must parse, every\n"
        "  `BerEncodedSignature` row must not - so a slip in either implementation fails here.\n"
        "- **The two implementations have correlated blind spots**, and saying otherwise would\n"
        "  overstate what this buys. `py_der_walk()` mirrors `brisk__der_walk` clause for\n"
        "  clause, so it catches a transcription slip but NOT a rule neither author wrote down:\n"
        "  the primitive SEQUENCE / SET and reserved-tag-0 acceptances both implementations\n"
        "  shared were found by review, not by this oracle, and only then turned into rows.\n"
        "  What does cross-check independently is part (1) - 337 DER encodings produced by\n"
        "  other people's tools, which pin the accepting side of every rule at once.\n"
        "- The DER *string* and *time* types carry no content rule in this layer, so no vector\n"
        "  pins one: PrintableString's alphabet and UTCTime's digits are checked by the name and\n"
        "  time code of the next ROADMAP items, which is where a violation has a meaning.\n\n"
        "## x509-limbo skip tally\n\n"
        f"limbo.json carries {len(x509_limbo) + sum(x509_limbo_skipped.values())} testcases and this "
        f"library exercises {len(x509_limbo)} of them.\n"
        "The rest answer questions brisk__x509_chain_verify does not ask - see the block above\n"
        "`x509_limbo_vectors` in tools/kat.py and the src/brisk_int.h block above\n"
        "`brisk__x509_chain_verify` for what is and is not enforced. Skip reasons:\n\n"
        + "".join(f"- `{r}`: {n}\n"
                  for r, n in sorted(x509_limbo_skipped.items(), key=lambda x: (-x[1], x[0]))),
        newline="\n")
    print("ok")


if __name__ == "__main__":
    main()
