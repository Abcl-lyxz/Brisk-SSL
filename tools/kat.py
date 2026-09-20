#!/usr/bin/env python3
"""Fetch official known-answer vectors and emit tests/kat/*.inc (stdlib only).

Every vector is re-computed with Python's hashlib/hmac (or a pure-Python RFC 8439 / FIPS 197 reference) before it is written, so a parsing slip fails
here instead of silently weakening the C tests. Downloads are cached in .cache/kat/.

    python tools/kat.py            # regenerate tests/kat/*.inc + tests/kat/SOURCES.md
"""
import datetime
import hashlib
import hmac
import io
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
    blocks, cur, field = [], None, None
    for ln in rfc_lines(fetch("rfc8448")):
        m = re.match(r"^\s*\{(client|server)\}\s+(.*)$", ln)
        if m:
            cur = {"_side": m.group(1), "_h": m.group(2), "_f": {}}
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


def rfc5903_params():
    """RFC 5903 3.1: p, curve b, group order n, and the generator G."""
    text = "\n".join(rfc_lines(fetch("rfc5903")))
    s = text[text.index("\n3.1.  256-Bit") : text.index("\n3.2.")]
    want = {"p": "Group Prime/Irreducible Polynomial", "b": "Group Curve b", "n": "Group Order"}
    for key, label in want.items():
        m = re.search(re.escape(label) + r":\n((?:\s+[0-9A-F ]+\n)+)", s)
        if not m:
            die(f"RFC 5903 3.1: {label} not found")
        P256[key] = int.from_bytes(hexbytes(m.group(1)), "big")
    for key in ("gx", "gy"):
        m = re.search(r"\n" + key + r":\n((?:\s+[0-9A-F ]+\n)+)", s)
        if not m:
            die(f"RFC 5903 3.1: generator {key} not found")
        P256[key] = int.from_bytes(hexbytes(m.group(1)), "big")

    # Self-consistency of what we parsed, against the closed forms the same section states.
    if P256["p"] != 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1:
        die("RFC 5903 3.1: p is not 2^256-2^224+2^192+2^96-1")
    for v in P256.values():
        if not 0 < v < 2 ** 256:
            die("RFC 5903 3.1: parameter out of range")
    if not py_p256_on_curve(P256["gx"], P256["gy"]):
        die("RFC 5903 3.1: G is not on the curve")
    if py_p256_mul(P256["n"], (P256["gx"], P256["gy"])) is not None:
        die("RFC 5903 3.1: n*G is not the point at infinity")
    return [(k, f"{P256[k]:064x}") for k in ("p", "b", "n", "gx", "gy")]


def check_p256_source_constants():
    """The five curve constants compiled into src/crypto/p256.c, byte-for-byte against the RFC.

    This is how "never hand-type vectors" is honoured for the parameters themselves: they are the
    one thing in the module that cannot come from a generated .inc (src/ does not include tests/),
    so the transcription is checked here instead of trusted. tests/test_p256.c pins G, n and p
    through behaviour as well; this catches a slip even in b, which no single vector names."""
    src = (ROOT / "src" / "crypto" / "p256.c").read_text(encoding="utf-8", errors="replace")
    for name, key in (("P256_P", "p"), ("P256_B", "b"), ("P256_N", "n"), ("P256_GX", "gx"),
                      ("P256_GY", "gy")):
        m = re.search(r"static const uint8_t " + name + r"\[32\] = \{(.*?)\};", src, re.S)
        if not m:
            die(f"src/crypto/p256.c: {name}[32] not found")
        got = bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
        if got != P256[key].to_bytes(32, "big"):
            die(f"src/crypto/p256.c: {name} does not match RFC 5903 3.1 ({got.hex()})")


def py_p256_on_curve(x, y):
    p = P256["p"]
    return 0 <= x < p and 0 <= y < p and (y * y - (x * x * x - 3 * x + P256["b"])) % p == 0


def py_p256_add(A, B):
    """Affine addition on y^2 = x^3 - 3x + b. None is the point at infinity."""
    if A is None or B is None:
        return B if A is None else A
    p = P256["p"]
    (x1, y1), (x2, y2) = A, B
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if A == B:
        lam = 3 * (x1 * x1 - 1) * pow(2 * y1, -1, p) % p  # a = -3
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def py_p256_mul(k, A):
    R, k = None, k % (P256["n"] * 2)
    while k:
        if k & 1:
            R = py_p256_add(R, A)
        A, k = py_p256_add(A, A), k >> 1
    return R


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


# ---------------------------------------------------------------- C emitters
def cstr(hx, width=96):
    if not hx:
        return '""'
    return " ".join(f'"{hx[i:i + width]}"' for i in range(0, len(hx), width))


def emit(name, decl, rows, fmt):
    body = ",\n".join("    {" + fmt(r) + "}" for r in rows)
    text = (f"/* generated by tools/kat.py - do not edit; sources in tests/kat/SOURCES.md */\n"
            f"static const {decl}[] = {{\n{body}\n}};\n")
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
    p256_params = rfc5903_params()
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
        "  belong to the M2 DER parser, not here. Not forgotten - out of scope by design.\n"
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
        "- The r == 0 / s == 0 retry (p ~ 2^-128) and the k-out-of-range retry (p ~ 2^-32) in\n"
        "  `brisk__p256_ecdsa_sign` ship with NO known-answer coverage. Neither can be reached\n"
        "  by any official vector and neither can be searched for at P-256 sizes. What stands\n"
        "  in for a vector is the bounded retry loop, the code review, and the fact that the\n"
        "  Python generator implements the same rejection logic. A real, accepted coverage gap.\n",
        newline="\n")
    print("ok")


if __name__ == "__main__":
    main()
