#!/usr/bin/env python3
"""Fetch official known-answer vectors and emit tests/kat/*.inc (stdlib only).

Every vector is re-computed with Python's hashlib/hmac (or a pure-Python RFC 8439 reference) before it is written, so a parsing slip fails
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
    "wp_chacha20_poly1305": f"{WP}chacha20_poly1305_test.json",
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

    rows = "\n".join(f"| {k} | {u} | `{h}` |" for k, (u, h) in sorted(fetched.items()))
    (OUT / "SOURCES.md").write_text(
        "# Known-answer vector sources\n\n"
        f"Generated by `python tools/kat.py` on {datetime.date.today()}. Each vector was re-checked\n"
        "against Python hashlib/hmac or the pure-Python ChaCha20/Poly1305\n"
        "reference before emission. Differential vectors come from a fixed seed.\n\n"
        "| name | url | sha256 of download |\n|---|---|---|\n" + rows + "\n", newline="\n")
    print("ok")


if __name__ == "__main__":
    main()
