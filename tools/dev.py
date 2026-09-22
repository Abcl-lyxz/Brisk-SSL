#!/usr/bin/env python3
"""Brisk-SSL developer entry point (stdlib only; runs on the Windows host, Linux and CI).

  python tools/dev.py test                       host presets (dev, dev32), natively
  python tools/dev.py test --arch all            every Docker preset (x86_64, asan, 9 cross archs)
  python tools/dev.py test --arch mips ppc       selected Docker presets
  python tools/dev.py size [--arch all|mipsel..] [--md] [--save] [--check]
                                                 per-module flash/RAM from the linker map (-Os, static)
  python tools/dev.py ct                         constant-time check: the ct suite under valgrind
  python tools/dev.py fuzz [der|name] [--seconds N]  libFuzzer over a parser, seeded from its .inc
  python tools/dev.py image                      (re)build the brisk-dev Docker image

Docker builds live in the named volume `brisk-build` (fast, and never collide with host builds).
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "brisk-dev"
HOST = ["dev", "dev32"]
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
CT_VARIANTS = [("ct64", ""), ("ct32", " -DBRISK__AES_CT64=0 -DBRISK__FIAT_64=0")]


def cmd_ct():
    bad = []
    for name, extra in CT_VARIANTS:
        bdir = f"build/ct-{name}"
        cfg = ["cmake", "-S", ".", "-B", bdir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Debug",
               "-DCMAKE_C_FLAGS=-O1 -g -DBRISK_CT_CHECK" + extra]
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


def measure_inside(arch):
    """Runs inside the container: -Os static build of the size probe, prints one JSON line."""
    bdir = f"build/size-{arch}"
    tc = [] if arch == "x86_64" else [f"-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/{arch}.cmake"]
    flags = "-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident"
    for cmd in (["cmake", "-S", ".", "-B", bdir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=MinSizeRel",
                 "-DBRISK_BUILD_TESTS=OFF", "-DBRISK_SIZE_PROBE=ON", f"-DCMAKE_C_FLAGS={flags}", *tc],
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


def cmd_size(archs, md, save, check, jobs):
    archs = SIZE_ARCHS if not archs or archs == ["all"] else archs

    def one(a):
        rc, out = run(docker_cmd(["python3", "tools/dev.py", "_measure", a]), True)
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
            old = base.get(a, {}).get(m)
            cell = f"{v}"
            if old is not None and old != v:
                cell += f" ({v - old:+d})"
                if m.startswith("TOTAL") and v - old > max(old // 100, 256):
                    grew.append(f"{a} {m}: {old} -> {v}")
            cells.append(cell)
            base.setdefault("_new", {}).setdefault(a, {})[m] = v
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


# ------------------------------------------------------------------------------------------- fuzz
# One .c file and one entry point, so this drives clang directly instead of teaching CMake about
# a build type nothing else uses. The seed corpus is not committed: tests/kat/der.inc already
# holds 874 blobs - real certificate keys and Wycheproof's adversarial ASN.1 - and unpacking them
# into files beats keeping the same bytes in the tree twice.
FUZZ = {"der": ("fuzz/fuzz_der.c src/x509/der.c", "tests/kat/der.inc"),
        "name": ("fuzz/fuzz_name.c src/x509/name.c src/x509/der.c",
                 "tests/kat/x509_name.inc")}


def fuzz_corpus(inc, out):
    out.mkdir(parents=True, exist_ok=True)
    for f in out.glob("*.der"):
        f.unlink()
    rows = re.findall(r'^\s*\{((?:"[0-9a-f]*"\s*)+),', (ROOT / inc).read_text(), re.M)
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
             "-fno-sanitize-recover=all", "-Iinclude", "-Isrc", *sources.split(), "-o", exe]
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
    s.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    sub.add_parser("ct")
    f = sub.add_parser("fuzz")
    f.add_argument("target", nargs="?", default="der", choices=sorted(FUZZ))
    f.add_argument("--seconds", type=int, default=60)
    sub.add_parser("image")
    m = sub.add_parser("_measure")
    m.add_argument("arch")
    a = ap.parse_args()
    if a.cmd == "test":
        return cmd_test(a.arch, a.jobs)
    if a.cmd == "size":
        return cmd_size(a.arch, a.md, a.save, a.check, a.jobs)
    if a.cmd == "ct":
        return cmd_ct()
    if a.cmd == "fuzz":
        return cmd_fuzz(a.target, a.seconds)
    if a.cmd == "image":
        return run(["docker", "build", "-t", IMAGE, "docker/"], False)[0]
    if a.cmd == "_measure":
        return measure_inside(a.arch)


if __name__ == "__main__":
    sys.exit(main())
