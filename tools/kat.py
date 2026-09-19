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
import sys
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
    **{f"cavp_aes_{k}": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
       f"documents/aes/{f}" for k, f in (("kat", "KAT_AES.zip"), ("mmt", "aesmmt.zip"), ("mct", "aesmct.zip"))},
    "cavp_gcm": "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/mac/gcmtestvectors.zip",
    "wp_chacha20_poly1305": f"{WP}chacha20_poly1305_test.json",
    "wp_aes_gcm": f"{WP}aes_gcm_test.json",
    **{f"wp_hmac_sha{b}": f"{WP}hmac_sha{b}_test.json" for b in (256, 384, 512)},
    **{f"wp_hkdf_sha{b}": f"{WP}hkdf_sha{b}_test.json" for b in (256, 384, 512)},
}
HASH = {256: hashlib.sha256, 384: hashlib.sha384, 512: hashlib.sha512}
fetched = {}  # name -> (url, sha256 of bytes)


def fetch(name):
    url = SRC[name]
    path = CACHE / url.rsplit("/", 1)[1]
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "brisk-kat/1"})
        with urllib.request.urlopen(req, timeout=60) as r:
            path.write_bytes(r.read())
    data = path.read_bytes()
    fetched[name] = (url, hashlib.sha256(data).hexdigest())
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
def rfc8448():
    """Every 'extract secret' and 'derive ...' block of the RFC 8448 traces (all SHA-256)."""
    extracts, labels, blocks, cur, field = [], [], [], None, None
    for ln in rfc_lines(fetch("rfc8448")):
        m = re.match(r"^\s*\{(?:client|server)\}\s+(.*)$", ln)
        if m:
            cur = {"_h": m.group(1), "_f": {}}
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
    seen = set()
    for b in blocks:
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

    rows = "\n".join(f"| {k} | {u} | `{h}` |" for k, (u, h) in sorted(fetched.items()))
    (OUT / "SOURCES.md").write_text(
        "# Known-answer vector sources\n\n"
        f"Generated by `python tools/kat.py` on {datetime.date.today()}. Each vector was re-checked\n"
        "against Python hashlib/hmac or the pure-Python ChaCha20/Poly1305/AES\n"
        "reference before emission. Differential vectors come from a fixed seed.\n\n"
        "| name | url | sha256 of download |\n|---|---|---|\n" + rows + "\n", newline="\n")
    print("ok")


if __name__ == "__main__":
    main()
