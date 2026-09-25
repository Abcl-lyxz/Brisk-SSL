#!/usr/bin/env python3
"""Brisk-SSL developer entry point (stdlib only; runs on the Windows host, Linux and CI).

  python tools/dev.py test                       host presets (dev, dev32), natively
  python tools/dev.py test --arch all            every Docker preset (x86_64, asan, 9 cross archs)
  python tools/dev.py test --arch mips ppc       selected Docker presets
  python tools/dev.py size [--arch all|mipsel..] [--md] [--save] [--check] [--profile FULL]
  python tools/dev.py size --profiles [--doc]    TINY/DEFAULT/FULL totals vs size/budget.json
                                                 per-module flash/RAM from the linker map (-Os, static)
  python tools/dev.py ct                         constant-time check: the ct suite under valgrind
  python tools/dev.py fuzz [der|name|pem|tls13_hs|tls13_rec|ticket|conn|hpack|h2|quic_pkt|quic_tp|qpack|h3] [--seconds N]  libFuzzer over a parser, seeded from its .inc
  python tools/dev.py amalg                      dist/brisk.c: -Werror per profile (gcc, clang) + tests
  python tools/dev.py interop                    brisk_get vs s_server/nginx/Caddy; h2_get vs nginx/h2o/nghttpd
  python tools/dev.py badssl                     brisk_get vs badssl.com (needs internet)
  python tools/dev.py image                      (re)build the brisk-dev Docker image

Docker builds live in the named volume `brisk-build` (fast, and never collide with host builds).
"""
import argparse
import ast
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "brisk-dev"
HOST = ["dev", "dev32", "dev-tls13"]  # dev-tls13: BRISK_ENABLE_TLS12=OFF (M5)
CROSS = ["i686", "aarch64", "armv7hf", "armv5", "mips", "mipsel", "mips64", "riscv64", "ppc"]
DOCKER = ["x86_64", "asan"] + CROSS
SIZE_ARCHS = ["x86_64"] + CROSS
TRIPLET = {"x86_64": "", "i686": "i686-linux-gnu", "aarch64": "aarch64-linux-gnu",
           "armv7hf": "arm-linux-gnueabihf", "armv5": "arm-linux-gnueabi", "mips": "mips-linux-gnu",
           "mipsel": "mipsel-linux-gnu", "mips64": "mips64-linux-gnuabi64",
           "riscv64": "riscv64-linux-gnu", "ppc": "powerpc-linux-gnu"}
# 64-bit division pulls in slow, non-constant-time libgcc helpers on 32-bit CPUs; floats have no
# business in a TLS library. Any of these in our objects is a bug.
FORBIDDEN = re.compile(r"^(__u?(div|mod)di3|__muldi3|__ashldi3|__ashrdi3|__lshrdi3|__aeabi_l(mul|lsl|lsr|asr)|__aeabi_[lu]?l?divmod|__aeabi_[dfi]|__(add|sub|mul|div)[sd]f3"
                       r"|__float\w+|__fix\w+|__extend\w+|__trunc\w+)$")
BASELINE = ROOT / "size" / "baseline.json"


def docker_cmd(args):
    return ["docker", "run", "--rm", "-v", f"{ROOT}:/src", "-v", "brisk-build:/src/build",
            "-w", "/src", IMAGE] + args


def run(cmd, capture):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=capture, text=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


# ------------------------------------------------------------------------------------------- test
def cmd_test(archs, jobs):
    if not archs or archs == ["host"]:
        bad = [p for p in HOST if run(["cmake", "--workflow", "--preset", p], False)[0]]
        print("host:", "ALL PASSED" if not bad else "FAILED: " + " ".join(bad))
        return 1 if bad else 0
    presets = DOCKER if archs == ["all"] else archs
    unknown = [p for p in presets if p not in DOCKER]
    if unknown:
        sys.exit(f"unknown preset(s): {unknown}; choose from {DOCKER}")

    def one(p):
        rc, out = run(docker_cmd(["cmake", "--workflow", "--preset", p]), True)
        return p, rc, out

    results = {}
    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        for p, rc, out in ex.map(one, presets):
            results[p] = rc
            status = "ok" if rc == 0 else "FAILED"
            print(f"{p:<8} {status}", flush=True)
            if rc:
                print("\n".join(out.splitlines()[-40:]))
    bad = [p for p, rc in results.items() if rc]
    print("docker:", "ALL PASSED" if not bad else "FAILED: " + " ".join(bad))
    return 1 if bad else 0


# --------------------------------------------------------------------------------------------- ct
# ctgrind: build the tests with -DBRISK_CT_CHECK so tests/test_ct.c marks secrets "undefined", then
# let valgrind report any branch/index/division that depends on one. Native x86_64 only - valgrind
# does not run under qemu-user - so both AES/GHASH variants are built here instead: the 32-bit code
# is the same C either way, and what differs per arch (multiplier timing, cache) is beyond valgrind.
# ct32m: the multiply-free GHASH of armv5 / MIPS32 (BRISK_GHASH_MULFREE) under the same AEAD calls.
# FULL profile, so the QUIC packet protection (tests/test_quic.c quic_ct_run) is in the run too.
CT_VARIANTS = [("ct64", ""), ("ct32", " -DBRISK__AES_CT64=0 -DBRISK__FIAT_64=0"),
               ("ct32m", " -DBRISK__AES_CT64=0 -DBRISK__FIAT_64=0 -DBRISK_GHASH_MULFREE=1")]


def cmd_ct():
    bad = []
    for name, extra in CT_VARIANTS:
        bdir = f"build/ct-{name}"
        cfg = ["cmake", "-S", ".", "-B", bdir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Debug",
               "-DBRISK_PROFILE=FULL", "-DCMAKE_C_FLAGS=-O1 -g -DBRISK_CT_CHECK" + extra]
        rc, out = run(docker_cmd(cfg), True)
        if not rc:
            rc, out = run(docker_cmd(["cmake", "--build", bdir, "--target", "brisk_tests"]), True)
        if not rc:
            # --error-exitcode: memcheck findings must fail the run, not just print.
            rc, out = run(docker_cmd(["valgrind", "-q", "--error-exitcode=9", "--track-origins=yes",
                                      f"./{bdir}/brisk_tests", "ct"]), True)
        print(f"{name:<6} {'ok' if rc == 0 else 'FAILED'}", flush=True)
        if rc:
            bad.append(name)
            print("\n".join(out.splitlines()[-60:]))
    print("ct:", "ALL PASSED" if not bad else "FAILED: " + " ".join(bad))
    return 1 if bad else 0


# ------------------------------------------------------------------------------------------- size
SECTION_KIND = [(("text",), "text"), (("rodata", "srodata"), "rodata"),
                (("data", "sdata"), "data"), (("bss", "sbss"), "bss")]


def classify(sec):
    if sec == "COMMON":
        return "bss"
    name = sec.lstrip(".").split(".")[0]
    for prefixes, kind in SECTION_KIND:
        if name in prefixes:
            return kind
    return None  # .eh_frame, .comment, .MIPS.abiflags, ... are not counted


def parse_map(text):
    """Sum kept input sections of libbrisk.a(<module>.c.o) from a GNU ld map file."""
    text = text[text.find("Linker script and memory map"):]
    mods = {}
    pat = re.compile(r"^ (\.[\w.$@-]+|COMMON)\s*\n?\s+0x[0-9a-f]+\s+0x([0-9a-f]+)\s+\S*libbrisk\.a\((\w+)\.c\.o\)", re.M)
    for sec, size, mod in pat.findall(text):
        kind = classify(sec)
        if kind:
            m = mods.setdefault(mod, {"text": 0, "rodata": 0, "data": 0, "bss": 0})
            m[kind] += int(size, 16)
    return mods


def measure_inside(arch, profile=""):
    """Runs inside the container: -Os static build of the size probe, prints one JSON line."""
    bdir = f"build/size-{arch}" + (f"-{profile.lower()}" if profile else "")
    tc = [] if arch == "x86_64" else [f"-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/{arch}.cmake"]
    flags = "-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident"
    for cmd in (["cmake", "-S", ".", "-B", bdir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=MinSizeRel",
                 "-DBRISK_BUILD_TESTS=OFF", "-DBRISK_SIZE_PROBE=ON", f"-DCMAKE_C_FLAGS={flags}",
                 f"-DBRISK_PROFILE={profile}", *tc],
                ["cmake", "--build", bdir, "--target", "brisk_size_probe"]):
        rc, out = run(cmd, True)
        if rc:
            sys.exit(out)
    mods = parse_map(Path(bdir, "size_probe.map").read_text())
    pre = TRIPLET[arch] + "-" if TRIPLET[arch] else ""
    rc, out = run([pre + "nm", "-u", f"{bdir}/libbrisk.a"], True)
    forbidden = sorted({s.split()[-1] for s in out.splitlines() if s.strip() and FORBIDDEN.match(s.split()[-1])})
    rc, cc = run([pre + "gcc", "--version"], True)
    print(json.dumps({"arch": arch, "cc": cc.splitlines()[0], "modules": mods, "forbidden": forbidden}))


def flash(m):
    return m["text"] + m["rodata"] + m["data"]


def cmd_size(archs, md, save, check, jobs, profile=""):
    archs = SIZE_ARCHS if not archs or archs == ["all"] else archs
    key = (lambda a: a) if not profile else (lambda a: f"{a}:{profile}")  # baseline row per profile

    def one(a):
        rc, out = run(docker_cmd(["python3", "tools/dev.py", "_measure", a, "--profile", profile]), True)
        if rc:
            sys.exit(f"size {a} failed:\n{out}")
        return json.loads(out.strip().splitlines()[-1])

    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        res = {r["arch"]: r for r in ex.map(one, archs)}
    base = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    mods = sorted({m for r in res.values() for m in r["modules"]})
    lines = ["| module | " + " | ".join(archs) + " |", "|---" * (len(archs) + 1) + "|"]
    grew = []
    for m in mods + ["TOTAL flash", "TOTAL ram"]:
        cells = []
        for a in archs:
            ms = res[a]["modules"]
            if m == "TOTAL flash":
                v = sum(flash(x) for x in ms.values())
            elif m == "TOTAL ram":
                v = sum(x["data"] + x["bss"] for x in ms.values())
            else:
                v = flash(ms[m]) if m in ms else 0
            old = base.get(key(a), {}).get(m)
            cell = f"{v}"
            if old is not None and old != v:
                cell += f" ({v - old:+d})"
                if m.startswith("TOTAL") and v - old > max(old // 100, 256):
                    grew.append(f"{a} {m}: {old} -> {v}")
            cells.append(cell)
            base.setdefault("_new", {}).setdefault(key(a), {})[m] = v
        lines.append(f"| {m} | " + " | ".join(cells) + " |")
    table = "\n".join(lines)
    print(table if md else table.replace("|", " ").replace("---", "   "))
    print("\nflash = text+rodata+data, ram = data+bss (static, excludes libc and stack); bytes, -Os")
    bad = {a: r["forbidden"] for a, r in res.items() if r["forbidden"]}
    if bad:
        print("FORBIDDEN libgcc/float helpers referenced:", bad)
    if save:
        BASELINE.parent.mkdir(exist_ok=True)
        new = {a: v for a, v in base["_new"].items()}
        old = {k: v for k, v in base.items() if k != "_new"}
        old.update(new)
        BASELINE.write_text(json.dumps(old, indent=1, sort_keys=True) + "\n", newline="\n")
        print(f"baseline saved: {BASELINE.relative_to(ROOT)}")
    if grew:
        print("SIZE GREW beyond max(1%, 256 B):", "; ".join(grew))
    return 1 if bad or (check and grew) else 0


# Per-profile totals (M8): every profile on every arch, against size/budget.json - the most flash
# a profile may take on ANY arch, in bytes - and, with --doc, written into docs/CONFIG.md between
# the size-table markers. CI prints the table and fails a busted budget; the budgets move only
# deliberately, with the reason in the commit message (like the baseline).
PROFILES = ["TINY", "DEFAULT", "FULL"]
BUDGET = ROOT / "size" / "budget.json"
DOC_BEGIN = "<!-- size-table:begin (tools/dev.py size --profiles --doc) -->"
DOC_END = "<!-- size-table:end -->"


def cmd_size_profiles(archs, doc, jobs):
    archs = SIZE_ARCHS if not archs or archs == ["all"] else archs

    def one(job):
        a, p = job
        rc, out = run(docker_cmd(["python3", "tools/dev.py", "_measure", a, "--profile", p]), True)
        if rc:
            sys.exit(f"size {a} {p} failed:\n{out}")
        ms = json.loads(out.strip().splitlines()[-1])["modules"]
        return job, (sum(flash(x) for x in ms.values()),
                     sum(x["data"] + x["bss"] for x in ms.values()))

    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        res = dict(ex.map(one, [(a, p) for p in PROFILES for a in archs]))
    budget = json.loads(BUDGET.read_text()) if BUDGET.exists() else {}
    lines = ["| profile | budget | " + " | ".join(archs) + " |", "|---" * (len(archs) + 2) + "|"]
    over = []
    for p in PROFILES:
        b = budget.get(p)
        cells = []
        for a in archs:
            fl = res[(a, p)][0]
            cells.append(f"{fl / 1024:.1f}")
            if b is not None and fl > b:
                over.append(f"{p} {a}: {fl} > {b}")
        lines.append(f"| {p} | {b / 1024:.0f} | " if b else f"| {p} | - | ")
        lines[-1] += " | ".join(cells) + " |"
    ram = max(r[1] for r in res.values())
    table = "\n".join(lines) + (
        "\n\nKB of flash (text + rodata + data, -Os, static link map, libc excluded); budget = the "
        f"most any arch may take (size/budget.json). Static RAM is at most {ram} B on any arch and "
        "profile - every context is caller-owned.")
    print(table)
    if doc:
        cfg = ROOT / "docs" / "CONFIG.md"
        text = cfg.read_text(encoding="utf-8")
        i, j = text.index(DOC_BEGIN) + len(DOC_BEGIN), text.index(DOC_END)
        cfg.write_text(text[:i] + "\n" + table + "\n" + text[j:], encoding="utf-8", newline="\n")
        print(f"written: {cfg.relative_to(ROOT)}")
    if over:
        print("OVER BUDGET:", "; ".join(over))
    return 1 if over else 0


# ------------------------------------------------------------------------------------------- fuzz
# One .c file and one entry point, so this drives clang directly instead of teaching CMake about
# a build type nothing else uses. The seed corpus is not committed: tests/kat/der.inc already
# holds 874 blobs - real certificate keys and Wycheproof's adversarial ASN.1 - and unpacking them
# into files beats keeping the same bytes in the tree twice.
FUZZ = {"der": ("fuzz/fuzz_der.c src/x509/der.c", "tests/kat/der.inc"),
        "name": ("fuzz/fuzz_name.c src/x509/name.c src/x509/der.c",
                 "tests/kat/x509_name.inc"),
        # The engine links most of the library; its seeds are whole server flights (kat.py).
        "tls13_hs": ("fuzz/fuzz_tls13_hs.c src/tls/handshake.c src/tls/tls12.c src/tls/keyschedule.c src/util.c "
                     "src/crypto/sha2.c src/crypto/hkdf.c src/crypto/x25519.c src/crypto/p256.c "
                     "src/crypto/p384.c src/crypto/bn.c src/crypto/rsa.c src/x509/der.c "
                     "src/x509/cert.c src/x509/chain.c src/x509/name.c",
                     "tests/kat/tls13_fuzz.inc"),
        # The record layer over a CONNECTED engine; seeds are sect 3's post-handshake records.
        "tls13_rec": ("fuzz/fuzz_tls13_rec.c src/tls/record.c src/tls/handshake.c src/tls/tls12.c "
                      "src/tls/keyschedule.c src/util.c src/crypto/sha2.c src/crypto/hkdf.c "
                      "src/crypto/chacha20_poly1305.c src/crypto/aes_ct.c src/crypto/aes_ct64.c "
                      "src/crypto/gcm.c src/crypto/x25519.c src/crypto/p256.c src/crypto/p384.c "
                      "src/crypto/bn.c src/crypto/rsa.c src/x509/der.c src/x509/cert.c "
                      "src/x509/chain.c src/x509/name.c",
                      "tests/kat/tls13_rec_fuzz.inc"),
        # The public connection: whole server streams through brisk_feed (HRR/CH2, handshake).
        "conn": ("fuzz/fuzz_conn.c src/tls/conn.c src/tls/record.c src/tls/handshake.c src/tls/tls12.c "
                 "src/tls/keyschedule.c src/tls/ticket.c src/util.c src/crypto/sha2.c "
                 "src/crypto/hkdf.c src/crypto/chacha20_poly1305.c src/crypto/aes_ct.c "
                 "src/crypto/aes_ct64.c src/crypto/gcm.c src/crypto/x25519.c src/crypto/p256.c "
                 "src/crypto/p384.c src/crypto/bn.c src/crypto/rsa.c src/x509/der.c "
                 "src/x509/cert.c src/x509/chain.c src/x509/name.c src/x509/bundle.c",
                 "tests/kat/tls13_conn_fuzz.inc"),
        # The resumption ticket blob: the one parser of caller-stored bytes (src/tls/ticket.c).
        # The streaming PEM reader; seeds are the bundle rows' PEM text (not hex, see fuzz_corpus).
        "pem": ("fuzz/fuzz_pem.c src/x509/bundle.c src/x509/der.c src/util.c",
                "tests/kat/x509_bundle.inc"),
        "ticket": ("fuzz/fuzz_ticket.c src/tls/ticket.c src/util.c",
                   "tests/kat/tls13_ticket_fuzz.inc"),
        # HPACK (RFC 7541): block sequences through one decoder + Huffman + encoder round trip.
        # BRISK_ENABLE_H2 is on in the default profile, which is what this build uses.
        "hpack": ("fuzz/fuzz_hpack.c src/http/hpack.c src/http/huffman.c src/util.c",
                  "tests/kat/hpack_fuzz.inc"),
        # HTTP/2 frames + streams (RFC 9113): server byte streams through brisk__h2_feed, then the
        # blocking calls over the same handle. Seeds are the h2.inc scenario streams.
        "h2": ("fuzz/fuzz_h2.c src/http/h2.c src/http/hpack.c src/http/huffman.c src/util.c",
               "tests/kat/h2_fuzz.inc"),
        # QUIC (M6): datagrams through the header parser, Initial-key open and the frame parser;
        # seeds are every quic_pkt.inc packet. The -D rides in the source list: QUIC is FULL only.
        "quic_pkt": ("-DBRISK_ENABLE_QUIC=1 fuzz/fuzz_quic_pkt.c src/quic/packet.c src/quic/conn.c src/quic/recovery.c src/quic/stream.c "
                     "src/tls/handshake.c src/tls/tls12.c src/tls/keyschedule.c src/util.c "
                     "src/crypto/sha2.c src/crypto/hkdf.c src/crypto/chacha20_poly1305.c "
                     "src/crypto/aes_ct.c src/crypto/aes_ct64.c src/crypto/gcm.c src/crypto/x25519.c "
                     "src/crypto/p256.c src/crypto/p384.c src/crypto/bn.c src/crypto/rsa.c "
                     "src/x509/der.c src/x509/cert.c src/x509/chain.c src/x509/name.c",
                     "tests/kat/quic_pkt.inc"),
        # QUIC transport parameters (RFC 9000 18): parse, and write-back of what parsed.
        "quic_tp": ("-DBRISK_ENABLE_QUIC=1 fuzz/fuzz_quic_tp.c src/quic/packet.c src/quic/conn.c src/quic/recovery.c src/quic/stream.c "
                    "src/tls/handshake.c src/tls/tls12.c src/tls/keyschedule.c src/util.c "
                    "src/crypto/sha2.c src/crypto/hkdf.c src/crypto/chacha20_poly1305.c "
                    "src/crypto/aes_ct.c src/crypto/aes_ct64.c src/crypto/gcm.c src/crypto/x25519.c "
                    "src/crypto/p256.c src/crypto/p384.c src/crypto/bn.c src/crypto/rsa.c "
                    "src/x509/der.c src/x509/cert.c src/x509/chain.c src/x509/name.c",
                    "tests/kat/quic_tp.inc"),
        # QPACK (M7, RFC 9204): field sections + re-encode round trip, and the encoder / decoder
        # instruction streams whole vs split. H3 is FULL only: the -D rides in the source list.
        "qpack": ("-DBRISK_ENABLE_H3=1 fuzz/fuzz_qpack.c src/http/qpack.c src/http/hpack.c "
                  "src/http/huffman.c src/http/h2.c src/util.c", "tests/kat/qpack_fuzz.inc"),
        # HTTP/3 (M7, RFC 9114): server stream events through the brisk__h3_io seam while the
        # public calls run. Seeds are the h3.inc scenarios in binary form.
        "h3": ("-DBRISK_ENABLE_H3=1 fuzz/fuzz_h3.c src/http/h3.c src/http/qpack.c src/http/hpack.c "
               "src/http/huffman.c src/http/h2.c src/util.c", "tests/kat/h3_fuzz.inc")}


def fuzz_corpus(inc, out):
    out.mkdir(parents=True, exist_ok=True)
    for f in out.glob("*.der"):
        f.unlink()
    text = (ROOT / inc).read_text()
    if inc.endswith("x509_bundle.inc"):
        # first column: PEM as adjacent C string literals; seed = 1 chunk-seed byte + the text
        lit = r'"((?:[^"\\]|\\.)*)"'
        rows = re.findall(r'^\s*\{((?:' + lit + r'\s*)+),', text, re.M)
        for i, row in enumerate(rows):
            pem = "".join(ast.literal_eval(f'"{s}"') for s in re.findall(lit, row[0]))
            (out / f"{i:04d}.der").write_bytes(bytes([i & 0xFF]) + pem.encode("latin-1"))
        return len(rows)
    rows = re.findall(r'^\s*\{((?:"[0-9a-f]*"\s*)+),', text, re.M)
    for i, row in enumerate(rows):
        (out / f"{i:04d}.der").write_bytes(bytes.fromhex("".join(re.findall(r'"([0-9a-f]*)"', row))))
    return len(rows)


def cmd_fuzz(target, seconds):
    sources, inc = FUZZ[target]
    corpus = ROOT / ".cache" / "fuzz" / target
    n = fuzz_corpus(inc, corpus)
    exe = f"build/fuzz_{target}"
    # -fno-sanitize-recover: a UBSan finding must abort so libFuzzer records it as a crash.
    build = ["clang", "-g", "-O1", "-std=c99", "-fsanitize=fuzzer,address,undefined",
             "-fno-sanitize-recover=all", "-Iinclude", "-Isrc", "-Ivendor", *sources.split(), "-o", exe]
    rc, out = run(docker_cmd(build), True)
    if rc:
        print(out)
        return rc
    rel = str(corpus.relative_to(ROOT)).replace("\\", "/")
    rc, out = run(docker_cmd([f"./{exe}", rel, f"-max_total_time={seconds}", "-max_len=8192",
                              "-print_final_stats=1"]), True)
    print("\n".join(out.splitlines()[-18:]))
    print(f"fuzz {target}: {'ok' if rc == 0 else 'FAILED'} ({n} seeds, {seconds}s)")
    return rc


# ------------------------------------------------------------------------------------------ amalg
# dist/brisk.c + dist/brisk.h (tools/amalg.py): every profile must compile warning-free as ONE
# translation unit under gcc and clang (a file-local name used twice, a feature macro set too
# late, a macro leaking into the next file all show up here only), and the whole test suite must
# pass linked against it - including the 32-bit AES/fiat variants, which the x86_64 CMake build
# never compiles. Runs inside the container (`_amalg`).
AMALG_WARN = ["-std=c99", "-Wall", "-Wextra", "-Wpedantic", "-Wshadow", "-Wcast-align",
              "-Wstrict-prototypes", "-Wundef", "-Wvla", "-Werror"]
AMALG_VARIANTS = [("TINY", ""), ("DEFAULT", ""), ("FULL", ""),
                  ("FULL", "-DBRISK__AES_CT64=0 -DBRISK__FIAT_64=0")]


def amalg_inside():
    sh(["python3", "tools/amalg.py"])
    cm = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    block = cm[cm.index("add_executable(brisk_tests"):]
    tests = re.findall(r"tests/test_\w+\.c", block[:block.index(")")])
    # the Linux-only suites and their fault injection, as CMakeLists.txt adds them
    tests += ["tests/test_rand.c", "tests/test_sock.c",
              "-Wl,--wrap=syscall,--wrap=poll,--wrap=uname,--wrap=personality"]
    bad = []
    for profile, extra in AMALG_VARIANTS:
        defs = [f"-DBRISK_PROFILE=BRISK_PROFILE_{profile}", *extra.split()]
        name = f"{profile}{' 32-bit variants' if extra else ''}"
        for cc in ("gcc", "clang"):
            r = subprocess.run([cc, *AMALG_WARN, "-Os", *defs, "-c", "dist/brisk.c", "-o",
                                f"build/amalg-{cc}.o"], cwd=ROOT, capture_output=True, text=True)
            print(f"{name:<24} {cc:<6} {'ok' if r.returncode == 0 else 'FAILED'}", flush=True)
            if r.returncode:
                bad.append(f"{name} {cc}")
                print("\n".join((r.stdout + r.stderr).splitlines()[:40]))
        if profile == "TINY":
            continue  # the suite targets DEFAULT / FULL builds
        exe = "build/amalg-tests"
        r = subprocess.run(["gcc", "-std=c99", "-O1", *defs, "-Idist", "-Isrc", "-Itests",
                            "-Wno-overlength-strings", *tests, "dist/brisk.c", "-o", exe],
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            r = subprocess.run([f"./{exe}"], cwd=ROOT, capture_output=True, text=True)
        print(f"{name:<24} tests  {'ok' if r.returncode == 0 else 'FAILED'}", flush=True)
        if r.returncode:
            bad.append(f"{name} tests")
            print("\n".join((r.stdout + r.stderr).splitlines()[-30:]))
    print("amalg:", "ALL PASSED" if not bad else "FAILED: " + ", ".join(bad))
    return 1 if bad else 0


# ---------------------------------------------------------------------------------------- interop
# Both run INSIDE one container (`_interop` / `_badssl`): build brisk_get, then drive it against
# real servers. Each scenario asserts success (and what must appear on stdout/stderr) or the
# exact failure. brisk_get exits 0 on success, 2 on any connection failure, printing the error.
IOP = "build/interop"
PKI = f"{IOP}/pki"


def sh(cmd, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if r.returncode:
        sys.exit(f"command failed: {cmd}\n{r.stdout}{r.stderr}")
    return r.stdout


def build_brisk_get():
    sh(["cmake", "-S", ".", "-B", IOP, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
        "-DBRISK_BUILD_TESTS=OFF", "-DBRISK_BUILD_EXAMPLES=ON"])
    sh(["cmake", "--build", IOP, "--target", "brisk_get", "h2_get"])
    return f"./{IOP}/brisk_get"


def make_pki():
    """Throwaway test PKI: two roots, P-256 / RSA-2048 leaves, a P-384 intermediate, a client."""
    Path(PKI).mkdir(parents=True, exist_ok=True)
    ossl = lambda *a: sh(["openssl", *a], cwd=PKI)
    keyopt = {"p256": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
              "p384": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
              "rsa": ["-newkey", "rsa:2048"]}
    ca_ext = "basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n"
    leaf_ext = ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    Path(PKI, "ca.ext").write_text(ca_ext + "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    Path(PKI, "server.ext").write_text(leaf_ext + "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    Path(PKI, "client.ext").write_text(leaf_ext + "extendedKeyUsage=clientAuth\n")
    for root in ("root", "other"):
        ossl("req", "-x509", *keyopt["p256"], "-nodes", "-keyout", f"{root}.key", "-out",
             f"{root}.pem", "-days", "30", "-subj", f"/CN=Brisk interop {root}")

    def issue(name, kind, ca, ext, md="sha256"):
        ossl("req", "-new", *keyopt[kind], "-nodes", "-keyout", f"{name}.key", "-out",
             f"{name}.csr", "-subj", f"/CN={name}")
        ossl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key",
             "-days", "30", f"-{md}", "-extfile", ext, "-out", f"{name}.pem")

    issue("leaf-p256", "p256", "root", "server.ext")
    issue("leaf-rsa", "rsa", "root", "server.ext")
    issue("inter-p384", "p384", "root", "ca.ext")
    issue("leaf-via384", "p256", "inter-p384", "server.ext", "sha384")
    issue("client", "p256", "root", "client.ext")
    ossl("x509", "-in", "client.pem", "-outform", "DER", "-out", "client.der")
    der = subprocess.run(["openssl", "ec", "-in", "client.key", "-outform", "DER"], cwd=PKI,
                         capture_output=True, check=True).stdout
    assert der[5:7] == b"\x04\x20", "unexpected SEC1 layout"  # 30 77 02 01 01 04 20 <d>
    Path(PKI, "client.d").write_bytes(der[7:39])


def pki(f):
    return f"{PKI}/{f}"


def wait_port(port, proc, secs=15):
    import socket
    import time
    end = time.time() + secs
    while time.time() < end:
        if proc.poll() is not None:
            sys.exit(f"server on :{port} died:\n{proc.stdout.read() if proc.stdout else ''}")
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    sys.exit(f"server on :{port} never listened")


def serve(cmd, port, stdin=None):
    p = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True)
    wait_port(port, p)
    return p


def client(exe, args, host="localhost", port=443):
    r = subprocess.run([exe, *args, host, str(port)], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def check(res, expect):
    """expect: ("ok", stdout_needle, stderr_needle) or ("fail", stderr_needle)."""
    rc, out, err = res
    if expect[0] == "ok":
        good = rc == 0 and expect[1] in out and expect[2] in err
    else:  # a clean failure: exit 2 (never a crash signal), with the expected error named
        good = rc == 2 and expect[1] in err
    detail = err.strip().splitlines()[-1] if err.strip() else f"rc={rc}"
    return good, detail


def interop_inside():
    exe = build_brisk_get()
    make_pki()
    ca = ["-c", pki("root.pem")]
    ok = lambda out="", err="": ("ok", out, err)
    rows = []

    def s_server(extra, cert="leaf-p256", port=4433):
        return serve(["openssl", "s_server", "-accept", str(port), "-www", "-cert", pki(f"{cert}.pem"),
                      "-key", pki(f"{cert}.key"), *extra], port)

    # (name, s_server args, cert, brisk_get args, host, expectation)
    S = [
        ("default (TLS 1.3)", ["-tls1_3"], "leaf-p256", ca, "localhost", ok("TLSv1.3")),
        ("TLS_AES_128_GCM_SHA256", ["-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256"],
         "leaf-p256", ca, "localhost", ok("TLS_AES_128_GCM_SHA256")),
        ("TLS_AES_256_GCM_SHA384", ["-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384"],
         "leaf-p256", ca, "localhost", ok("TLS_AES_256_GCM_SHA384")),
        ("TLS_CHACHA20_POLY1305_SHA256", ["-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"],
         "leaf-p256", ca, "localhost", ok("TLS_CHACHA20_POLY1305_SHA256")),
        # our first key share is x25519, so a P-256-only server must send HelloRetryRequest
        ("HRR: -groups P-256", ["-tls1_3", "-groups", "P-256"], "leaf-p256", ca, "localhost",
         ok("TLSv1.3")),
        ("RSA-2048 leaf (rsa_pss_rsae)", ["-tls1_3"], "leaf-rsa", ca, "localhost", ok("TLSv1.3")),
        ("P-384 intermediate chain", ["-tls1_3", "-cert_chain", pki("inter-p384.pem")],
         "leaf-via384", ca, "localhost", ok("TLSv1.3")),
        ("ALPN h2,http/1.1 -> http/1.1", ["-tls1_3", "-alpn", "http/1.1"], "leaf-p256",
         ca + ["-a", "h2,http/1.1"], "localhost", ok("TLSv1.3", "alpn=http/1.1 ")),
        ("mTLS P-256 device cert", ["-tls1_3", "-Verify", "1", "-CAfile", pki("root.pem")],
         "leaf-p256", ca + ["-C", pki("client.der"), "-K", pki("client.d")], "localhost",
         ok("CN=client")),
        # TLS 1.3: the client finishes first; the server's certificate_required alert arrives
        # on the first read
        ("mTLS required, no cert -> fail", ["-tls1_3", "-Verify", "1", "-CAfile", pki("root.pem")],
         "leaf-p256", ca, "localhost", ("fail", "E_PEER_ALERT")),
        ("wrong host name -> fail", ["-tls1_3"], "leaf-p256", ca, "127.0.0.1", ("fail", "E_AUTH")),
        ("untrusted CA -> fail", ["-tls1_3"], "leaf-p256", ["-c", pki("other.pem")], "localhost",
         ("fail", "E_AUTH")),
    ]
    # TLS 1.2 (M5): every suite x {ECDSA P-256, RSA-2048} leaf x {X25519, P-256} ECDHE, the
    # combined ClientHello answered by a TLS 1.2-only server; -keylogfile keeps the secrets of a
    # failing run for comparison with tools/kat.py's cascade.
    kl = ["-keylogfile", f"{IOP}/keylog12.txt"]
    for suite, cert in (("ECDHE-ECDSA-AES128-GCM-SHA256", "leaf-p256"),
                        ("ECDHE-ECDSA-AES256-GCM-SHA384", "leaf-p256"),
                        ("ECDHE-ECDSA-CHACHA20-POLY1305", "leaf-p256"),
                        ("ECDHE-RSA-AES128-GCM-SHA256", "leaf-rsa"),
                        ("ECDHE-RSA-AES256-GCM-SHA384", "leaf-rsa"),
                        ("ECDHE-RSA-CHACHA20-POLY1305", "leaf-rsa")):
        for g in ("X25519", "P-256"):
            S.append((f"TLS 1.2 {suite} {g}", ["-tls1_2", "-cipher", suite, "-groups", g, *kl],
                      cert, ca, "localhost", ok(suite, "tls=0x0303")))
    S += [
        ("TLS 1.2 P-384 intermediate chain", ["-tls1_2", "-cert_chain", pki("inter-p384.pem")],
         "leaf-via384", ca, "localhost", ok("TLSv1.2", "tls=0x0303")),
        ("TLS 1.2 ALPN http/1.1", ["-tls1_2", "-alpn", "http/1.1"], "leaf-p256",
         ca + ["-a", "h2,http/1.1"], "localhost", ok("TLSv1.2", "alpn=http/1.1 ")),
        ("TLS 1.2 mTLS P-256 device cert", ["-tls1_2", "-Verify", "1", "-CAfile", pki("root.pem")],
         "leaf-p256", ca + ["-C", pki("client.der"), "-K", pki("client.d")], "localhost",
         ok("CN=client", "tls=0x0303")),
        # TLS 1.2: the server judges our (empty) Certificate before its Finished
        ("TLS 1.2 mTLS required, no cert -> fail",
         ["-tls1_2", "-Verify", "1", "-CAfile", pki("root.pem")], "leaf-p256", ca, "localhost",
         ("fail", "E_PEER_ALERT")),
        ("TLS 1.2 CBC-only server -> fail", ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-SHA"],
         "leaf-rsa", ca, "localhost", ("fail", "E_PEER_ALERT")),
        # RFC 7627 / RFC 9325 3.5: extended_main_secret is required
        ("TLS 1.2 server without EMS -> fail", ["-tls1_2", "-no_ems"], "leaf-p256", ca,
         "localhost", ("fail", "E_INSECURE")),
        ("TLS 1.1-only server -> fail", ["-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0"], "leaf-p256",
         ca, "localhost", ("fail", "E_")),
    ]
    for name, sargs, cert, cargs, host, expect in S:
        srv = s_server(sargs, cert)
        try:
            rows.append((name, *check(client(exe, cargs, host, 4433), expect)))
        finally:
            srv.kill()
            srv.wait()

    # resumption: same s_server process (same ticket key), two runs sharing one ticket file
    tk = f"{IOP}/ticket.bin"
    Path(tk).unlink(missing_ok=True)
    srv = s_server(["-tls1_3"])
    try:
        rows.append(("resumption: 1st run full", *check(client(exe, ca + ["-T", tk], port=4433),
                                                         ok("TLSv1.3", "resumed=0"))))
        rows.append(("resumption: 2nd run resumed", *check(client(exe, ca + ["-T", tk], port=4433),
                                                            ok("Reused", "resumed=1"))))
    finally:
        srv.kill()
        srv.wait()
    rows.append(keyupdate(exe, ca))
    rows.append(renegotiation(exe, ca))

    # nginx and Caddy: TLS 1.3, HTTP/1.1 GET of a known body
    Path(IOP, "nginx").mkdir(exist_ok=True)
    Path(IOP, "nginx.conf").write_text(f"""
pid /src/{IOP}/nginx/nginx.pid; error_log stderr; daemon off; events {{}}
http {{ access_log off; client_body_temp_path /src/{IOP}/nginx;
  server {{ listen 127.0.0.1:8443 ssl; ssl_protocols TLSv1.3;
    ssl_certificate /src/{pki('leaf-p256.pem')}; ssl_certificate_key /src/{pki('leaf-p256.key')};
    location / {{ return 200 "brisk-nginx-ok\\n"; }} }}
  server {{ listen 127.0.0.1:8445 ssl; ssl_protocols TLSv1.2;
    ssl_certificate /src/{pki('leaf-rsa.pem')}; ssl_certificate_key /src/{pki('leaf-rsa.key')};
    location / {{ return 200 "brisk-nginx12-ok\\n"; }} }} }}
""")
    Path(IOP, "Caddyfile").write_text(f"""{{
  admin off
  storage file_system /src/{IOP}/caddy
}}
https://localhost:8444 {{
  tls /src/{pki('leaf-p256.pem')} /src/{pki('leaf-p256.key')}
  respond "brisk-caddy-ok"
}}
https://localhost:8446 {{
  tls /src/{pki('leaf-p256.pem')} /src/{pki('leaf-p256.key')} {{
    protocols tls1.2 tls1.2
  }}
  respond "brisk-caddy12-ok"
}}
""")
    env = dict(os.environ, HOME=f"/src/{IOP}", XDG_DATA_HOME=f"/src/{IOP}/caddy",
               XDG_CONFIG_HOME=f"/src/{IOP}/caddy")
    for name, cmd, port, body in (
            ("nginx GET", ["nginx", "-c", f"/src/{IOP}/nginx.conf", "-p", f"/src/{IOP}/nginx"],
             8443, "brisk-nginx-ok"),
            ("Caddy GET", ["caddy", "run", "--config", f"{IOP}/Caddyfile", "--adapter", "caddyfile"],
             8444, "brisk-caddy-ok")):
        srv = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        wait_port(port, srv)
        try:
            rows.append((name, *check(client(exe, ca, port=port), ok(body))))
            if port == 8443:  # the same nginx: its TLS 1.2-only RSA server
                rows.append(("nginx GET (TLS 1.2, RSA)",
                             *check(client(exe, ca, port=8445), ok("brisk-nginx12-ok", "tls=0x0303"))))
            else:
                wait_port(8446, srv)
                rows.append(("Caddy GET (TLS 1.2)",
                             *check(client(exe, ca, port=8446), ok("brisk-caddy12-ok", "tls=0x0303"))))
        finally:
            srv.kill()
            srv.wait()
    rows += h2_interop(ca, env)
    return report(rows)


def fnv(data):
    """FNV-1a 32, as h2_get -q prints it."""
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return f"{h:08x}"


def echo_backend(port):
    """Plain HTTP/1.1 upstream for the proxies: answers POST/PUT with the request body."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Echo(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                data = b""
                while (n := int(self.rfile.readline().split(b";")[0], 16)) > 0:
                    data += self.rfile.read(n)
                    self.rfile.readline()
                while self.rfile.readline() not in (b"\r\n", b""):
                    pass
            else:
                data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_PUT = do_POST

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def h2_interop(ca, env):
    """h2_get (brisk_h2_*) vs nginx, h2o and nghttpd: TLS 1.3, ALPN h2, the test PKI."""
    h2 = f"./{IOP}/h2_get"
    www = Path(IOP, "www")
    www.mkdir(exist_ok=True)
    (www / "small.txt").write_text("brisk-h2-ok\n")
    big = os.urandom(1536 * 1024)  # > 1 MB: several times our 8 KB stream window
    (www / "big.bin").write_bytes(big)
    up = 300000                       # > 256 KB upload: send-side flow control
    big_line = f"status 200 bytes {len(big)} fnv {fnv(big)}"
    up_line = f"status 200 bytes {up} fnv {fnv(bytes(i % 251 for i in range(up)))}"
    cert, key = f"/src/{pki('leaf-p256.pem')}", f"/src/{pki('leaf-p256.key')}"
    echo = echo_backend(9080)
    rows = []

    def run(args, port, path):
        r = subprocess.run([h2, *ca, *args, "localhost", str(port), path], capture_output=True,
                           text=True, timeout=60)
        return r.returncode, r.stdout, r.stderr

    def row(name, res, good):
        rc, out, err = res
        tail = err.strip().splitlines()[-1] if err.strip() else f"rc={rc}"
        rows.append((name, bool(good(rc, out, err)), tail))

    Path(IOP, "nginx-h2").mkdir(exist_ok=True)
    Path(IOP, "nginx-h2.conf").write_text(f"""
pid /src/{IOP}/nginx-h2/nginx.pid; error_log stderr; daemon off; events {{}}
http {{ access_log off; client_body_temp_path /src/{IOP}/nginx-h2; proxy_temp_path /src/{IOP}/nginx-h2;
  ssl_protocols TLSv1.3; ssl_certificate {cert}; ssl_certificate_key {key}; root /src/{IOP}/www;
  server {{ listen 127.0.0.1:8453 ssl; http2 on;
    location /echo {{ client_max_body_size 4m; proxy_pass http://127.0.0.1:9080; }} }}
  # one request per connection: nginx answers it, then sends GOAWAY (last stream 1)
  server {{ listen 127.0.0.1:8454 ssl; http2 on; keepalive_requests 1; }}
  # HTTP/2 over TLS 1.2 (RFC 9113 9.2: every suite offered is ECDHE + AEAD)
  server {{ listen 127.0.0.1:8457 ssl; http2 on; ssl_protocols TLSv1.2; }} }}
""")
    Path(IOP, "h2o").mkdir(exist_ok=True)
    Path(IOP, "h2o.conf").write_text(f"""
user: nobody
pid-file: /tmp/h2o.pid
error-log: /src/{IOP}/h2o/error.log
listen:
  host: 127.0.0.1
  port: 8455
  ssl:
    certificate-file: {cert}
    key-file: {key}
    minimum-version: TLSv1.3
hosts:
  "localhost:8455":
    paths:
      /echo:
        proxy.reverse.url: http://127.0.0.1:9080/echo
      /:
        file.dir: /src/{IOP}/www
""")
    servers = {
        "nginx": (["nginx", "-c", f"/src/{IOP}/nginx-h2.conf", "-p", f"/src/{IOP}/nginx-h2"], 8453),
        "h2o": (["h2o", "-c", f"/src/{IOP}/h2o.conf"], 8455),
        # every nghttpd response carries a trailer field: the API discards it, the body must survive
        "nghttpd": (["nghttpd", "-d", f"/src/{IOP}/www", "--echo-upload",
                     "--trailer=x-brisk-trailer: yes", "8456", key, cert], 8456),
    }
    for name, (cmd, port) in servers.items():
        srv = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        wait_port(port, srv)
        try:
            row(f"h2 {name}: GET small + headers", run([], port, "/small.txt"),
                lambda rc, o, e: rc == 0 and o == "brisk-h2-ok\n" and "< :status: 200" in e
                and f"< server: {name}" in e)
            row(f"h2 {name}: GET 1.5 MB (recv flow ctl)", run(["-q"], port, "/big.bin"),
                lambda rc, o, e: rc == 0 and o.strip() == big_line)
            row(f"h2 {name}: POST 300 KB echo (send flow ctl)", run(["-q", "-D", str(up)], port, "/echo"),
                lambda rc, o, e: rc == 0 and o.strip() == up_line)
            row(f"h2 {name}: 4 parallel streams x 1.5 MB", run(["-q", "-n", "4"], port, "/big.bin"),
                lambda rc, o, e: rc == 0 and o.splitlines() == [big_line] * 4)
            row(f"h2 {name}: 404", run([], port, "/missing"),
                lambda rc, o, e: rc == 0 and "< :status: 404" in e)
        finally:
            srv.kill()
            srv.wait()

    srv = subprocess.Popen(servers["nginx"][0], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    wait_port(8454, srv)
    try:  # brisk.h: a request after GOAWAY, or above its last stream id, is BRISK_E_RETRY
        row("h2 nginx: GOAWAY after 1 request -> E_RETRY", run(["-r", "2"], 8454, "/small.txt"),
            lambda rc, o, e: rc == 2 and o == "brisk-h2-ok\n" and " 2: E_RETRY" in e)
        wait_port(8457, srv)
        row("h2 nginx over TLS 1.2: GET 1.5 MB", run(["-q"], 8457, "/big.bin"),
            lambda rc, o, e: rc == 0 and o.strip() == big_line)
    finally:
        srv.kill()
        srv.wait()
    echo.shutdown()

    # a server that ignores ALPN: the handshake completes with none selected, and brisk_h2_open
    # must refuse (no protocol switching). A server that answers the mismatch with
    # no_application_protocol (RFC 7301 3.2, what s_server -alpn http/1.1 does) never gets here.
    srv = serve(["openssl", "s_server", "-accept", "4433", "-www", "-tls1_3",
                 "-cert", pki("leaf-p256.pem"), "-key", pki("leaf-p256.key")], 4433)
    try:
        row("h2 server without ALPN -> h2_open E_ARG", run([], 4433, "/"),
            lambda rc, o, e: rc == 2 and "h2_open: E_ARG" in e)
    finally:
        srv.kill()
        srv.wait()
    return rows


def keyupdate(exe, ca):
    """s_server reads commands from stdin: "K" = KeyUpdate(update_requested), "q" = close."""
    import time
    srv = serve(["openssl", "s_server", "-accept", "4434", "-tls1_3", "-cert", pki("leaf-p256.pem"),
                 "-key", pki("leaf-p256.key")], 4434, stdin=subprocess.PIPE)
    cl = subprocess.Popen([exe, *ca, "-r", "hello\n", "localhost", "4434"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(2)  # handshake + "hello" (ponytail: fixed sleep; watch s_server stdout if flaky)
        for line in ("K\n", "after-keyupdate\n", "q\n"):  # one command per read(2)
            srv.stdin.write(line)
            srv.stdin.flush()
            time.sleep(0.5)
        out, err = cl.communicate(timeout=30)
    finally:
        cl.kill()
        srv.kill()
        srv.wait()
    good, detail = check((cl.returncode, out, err), ("ok", "after-keyupdate", ""))
    # s_server logs "SSL_do_handshake -> 1" once its KeyUpdate is out; an undecryptable answer
    # from us would log ERROR. (The ERROR before "hello" is wait_port's empty probe connection.)
    log = srv.stdout.read().partition("hello")[2]
    good = good and "SSL_do_handshake -> 1" in log and "ERROR" not in log
    return "KeyUpdate (server-initiated, requested)", good, detail


def renegotiation(exe, ca):
    """TLS 1.2 s_server "R" = HelloRequest. We answer with one warning no_renegotiation (RFC 5746
    4.2) and keep the connection; OpenSSL may then close it. Either way: a clean result (exit 0
    or 2, never a signal) and no renegotiation."""
    import time
    srv = serve(["openssl", "s_server", "-accept", "4435", "-tls1_2", "-cert", pki("leaf-p256.pem"),
                 "-key", pki("leaf-p256.key")], 4435, stdin=subprocess.PIPE)
    cl = subprocess.Popen([exe, *ca, "-r", "hello\n", "localhost", "4435"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(2)
        for line in ("R\n", "after-hellorequest\n", "q\n"):
            srv.stdin.write(line)
            srv.stdin.flush()
            time.sleep(0.5)
        out, err = cl.communicate(timeout=30)
    finally:
        cl.kill()
        srv.kill()
        srv.wait()
    log = srv.stdout.read().partition("hello")[2]
    good = cl.returncode in (0, 2) and "tls=0x0303" in err and "SSL renegotiation" not in log
    detail = err.strip().splitlines()[-1] if err.strip() else f"rc={cl.returncode}"
    return "TLS 1.2 HelloRequest -> no_renegotiation", good, detail


def report(rows):
    w = max(len(r[0]) for r in rows)
    for name, good, detail in rows:
        print(f"{name:<{w}}  {'PASS' if good else 'FAIL'}  {detail}")
    bad = sum(1 for r in rows if not r[1])
    print(f"\n{len(rows) - bad}/{len(rows)} passed")
    return 1 if bad else 0


# badssl.com speaks no TLS 1.3 (checked 2026-09-23 with `openssl s_client -tls1_3`), and since M5
# it answers our TLS 1.2 offer - but WITHOUT extended_main_secret: `openssl s_client -tls1_2`
# reports "Extended master secret: no" on every badssl host (re-checked 2026-09-24: sha256,
# ecc384, revoked, mozilla-modern, tls-v1-2, ...). EMS is REQUIRED here (RFC 7627 5.2, RFC 9325
# 3.5), so every badssl handshake ends in handshake_failure (E_INSECURE) before any certificate is
# looked at - the certificate rows (expired, wrong.host, revoked, ...) still prove nothing, and
# revoked.badssl.com cannot show the "no revocation checking" success it would otherwise be.
# What the table does pin: nothing below TLS 1.2, no CBC / 3DES / RC4 / static RSA / DHE suite
# (the server's handshake_failure = E_PEER_ALERT), and the TLS 1.3 positive controls for the
# system bundle. The certificate paths are covered by the interop run and the KAT suites.
BADSSL = [(f"{h}.badssl.com", 443, "fail") for h in (
    "sha256", "sha384", "sha512", "ecc256", "ecc384", "rsa2048", "rsa4096", "revoked",
    "mozilla-modern", "expired", "wrong.host", "self-signed", "untrusted-root",
    "incomplete-chain", "cbc", "3des", "rc4", "static-rsa", "dh2048", "rsa8192")] + [
    ("badssl.com", 443, "fail"), ("tls-v1-2.badssl.com", 1012, "fail"),
    ("tls-v1-1.badssl.com", 1011, "fail"), ("tls-v1-0.badssl.com", 1010, "fail"),
    ("www.cloudflare.com", 443, "ok"), ("www.google.com", 443, "ok")]


def badssl_inside():
    exe = build_brisk_get()
    rows = []
    for host, port, want in BADSSL:
        res = client(exe, ["-r", f"HEAD / HTTP/1.1\nHost: {host}\nConnection: close\n\n"], host, port)
        rows.append((f"{host}:{port} expect {want}",
                     *check(res, ("ok", "HTTP/", "") if want == "ok" else ("fail", "brisk:"))))
    # h2 against big real sites: their ~5.3 KB response headers need BRISK_H2_MAX_HEADER_LIST 8192
    h2 = exe.replace("brisk_get", "h2_get")
    for host in ("github.com", "www.cloudflare.com", "www.google.com"):
        r = subprocess.run([h2, "-q", host, "443", "/"], capture_output=True, text=True, timeout=60)
        rows.append((f"h2 {host} expect ok",
                     *check((r.returncode, r.stdout, r.stderr), ("ok", "status ", ""))))
    return report(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("test")
    t.add_argument("--arch", nargs="*", default=[])
    t.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    s = sub.add_parser("size")
    s.add_argument("--arch", nargs="*", default=[])
    s.add_argument("--md", action="store_true", help="markdown table")
    s.add_argument("--save", action="store_true", help="write size/baseline.json")
    s.add_argument("--check", action="store_true", help="exit 1 if a total grew > max(1%%, 256 B)")
    s.add_argument("--profile", default="", choices=["", "TINY", "DEFAULT", "FULL"],
                   help="build profile (default: the header's); FULL adds QUIC")
    s.add_argument("--profiles", action="store_true",
                   help="TINY/DEFAULT/FULL totals vs size/budget.json (exit 1 if over)")
    s.add_argument("--doc", action="store_true", help="with --profiles: update docs/CONFIG.md")
    s.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    sub.add_parser("ct")
    f = sub.add_parser("fuzz")
    f.add_argument("target", nargs="?", default="der", choices=sorted(FUZZ))
    f.add_argument("--seconds", type=int, default=60)
    sub.add_parser("amalg")
    sub.add_parser("_amalg")
    sub.add_parser("interop")
    sub.add_parser("badssl")
    sub.add_parser("_interop")
    sub.add_parser("_badssl")
    sub.add_parser("image")
    m = sub.add_parser("_measure")
    m.add_argument("arch")
    m.add_argument("--profile", default="")
    a = ap.parse_args()
    if a.cmd == "test":
        return cmd_test(a.arch, a.jobs)
    if a.cmd == "size" and a.profiles:
        return cmd_size_profiles(a.arch, a.doc, a.jobs)
    if a.cmd == "size":
        return cmd_size(a.arch, a.md, a.save, a.check, a.jobs, a.profile)
    if a.cmd == "ct":
        return cmd_ct()
    if a.cmd == "fuzz":
        return cmd_fuzz(a.target, a.seconds)
    if a.cmd in ("interop", "badssl", "amalg"):
        return run(docker_cmd(["python3", "tools/dev.py", "_" + a.cmd]), False)[0]
    if a.cmd == "_interop":
        return interop_inside()
    if a.cmd == "_badssl":
        return badssl_inside()
    if a.cmd == "_amalg":
        return amalg_inside()
    if a.cmd == "image":
        return run(["docker", "build", "-t", IMAGE, "docker/"], False)[0]
    if a.cmd == "_measure":
        return measure_inside(a.arch, a.profile)


if __name__ == "__main__":
    sys.exit(main())
