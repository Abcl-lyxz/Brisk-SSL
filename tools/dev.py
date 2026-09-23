#!/usr/bin/env python3
"""Brisk-SSL developer entry point (stdlib only; runs on the Windows host, Linux and CI).

  python tools/dev.py test                       host presets (dev, dev32), natively
  python tools/dev.py test --arch all            every Docker preset (x86_64, asan, 9 cross archs)
  python tools/dev.py test --arch mips ppc       selected Docker presets
  python tools/dev.py size [--arch all|mipsel..] [--md] [--save] [--check]
                                                 per-module flash/RAM from the linker map (-Os, static)
  python tools/dev.py ct                         constant-time check: the ct suite under valgrind
  python tools/dev.py fuzz [der|name|tls13_hs|tls13_rec|ticket|conn] [--seconds N]  libFuzzer over a parser, seeded from its .inc
  python tools/dev.py interop                    brisk_get vs openssl s_server, nginx, Caddy (test PKI)
  python tools/dev.py badssl                     brisk_get vs badssl.com (needs internet)
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
                 "tests/kat/x509_name.inc"),
        # The engine links most of the library; its seeds are whole server flights (kat.py).
        "tls13_hs": ("fuzz/fuzz_tls13_hs.c src/tls/handshake.c src/tls/keyschedule.c src/util.c "
                     "src/crypto/sha2.c src/crypto/hkdf.c src/crypto/x25519.c src/crypto/p256.c "
                     "src/crypto/p384.c src/crypto/bn.c src/crypto/rsa.c src/x509/der.c "
                     "src/x509/cert.c src/x509/chain.c src/x509/name.c",
                     "tests/kat/tls13_fuzz.inc"),
        # The record layer over a CONNECTED engine; seeds are sect 3's post-handshake records.
        "tls13_rec": ("fuzz/fuzz_tls13_rec.c src/tls/record.c src/tls/handshake.c "
                      "src/tls/keyschedule.c src/util.c src/crypto/sha2.c src/crypto/hkdf.c "
                      "src/crypto/chacha20_poly1305.c src/crypto/aes_ct.c src/crypto/aes_ct64.c "
                      "src/crypto/gcm.c src/crypto/x25519.c src/crypto/p256.c src/crypto/p384.c "
                      "src/crypto/bn.c src/crypto/rsa.c src/x509/der.c src/x509/cert.c "
                      "src/x509/chain.c src/x509/name.c",
                      "tests/kat/tls13_rec_fuzz.inc"),
        # The public connection: whole server streams through brisk_feed (HRR/CH2, handshake).
        "conn": ("fuzz/fuzz_conn.c src/tls/conn.c src/tls/record.c src/tls/handshake.c "
                 "src/tls/keyschedule.c src/tls/ticket.c src/util.c src/crypto/sha2.c "
                 "src/crypto/hkdf.c src/crypto/chacha20_poly1305.c src/crypto/aes_ct.c "
                 "src/crypto/aes_ct64.c src/crypto/gcm.c src/crypto/x25519.c src/crypto/p256.c "
                 "src/crypto/p384.c src/crypto/bn.c src/crypto/rsa.c src/x509/der.c "
                 "src/x509/cert.c src/x509/chain.c src/x509/name.c src/x509/bundle.c",
                 "tests/kat/tls13_conn_fuzz.inc"),
        # The resumption ticket blob: the one parser of caller-stored bytes (src/tls/ticket.c).
        "ticket": ("fuzz/fuzz_ticket.c src/tls/ticket.c src/util.c",
                   "tests/kat/tls13_ticket_fuzz.inc")}


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
    sh(["cmake", "--build", IOP, "--target", "brisk_get"])
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
        ("TLS 1.2-only server -> fail (until M5)", ["-tls1_2"], "leaf-p256", ca, "localhost",
         ("fail", "E_PEER_ALERT")),
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

    # nginx and Caddy: TLS 1.3, HTTP/1.1 GET of a known body
    Path(IOP, "nginx").mkdir(exist_ok=True)
    Path(IOP, "nginx.conf").write_text(f"""
pid /src/{IOP}/nginx/nginx.pid; error_log stderr; daemon off; events {{}}
http {{ access_log off; client_body_temp_path /src/{IOP}/nginx;
  server {{ listen 127.0.0.1:8443 ssl; ssl_protocols TLSv1.3;
    ssl_certificate /src/{pki('leaf-p256.pem')}; ssl_certificate_key /src/{pki('leaf-p256.key')};
    location / {{ return 200 "brisk-nginx-ok\\n"; }} }} }}
""")
    Path(IOP, "Caddyfile").write_text(f"""{{
  admin off
  storage file_system /src/{IOP}/caddy
}}
https://localhost:8444 {{
  tls /src/{pki('leaf-p256.pem')} /src/{pki('leaf-p256.key')}
  respond "brisk-caddy-ok"
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
        finally:
            srv.kill()
            srv.wait()
    return report(rows)


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


def report(rows):
    w = max(len(r[0]) for r in rows)
    for name, good, detail in rows:
        print(f"{name:<{w}}  {'PASS' if good else 'FAIL'}  {detail}")
    bad = sum(1 for r in rows if not r[1])
    print(f"\n{len(rows) - bad}/{len(rows)} passed")
    return 1 if bad else 0


# badssl.com, checked empirically on 2026-09-23 with `openssl s_client -tls1_3`: NO badssl.com
# host negotiates TLS 1.3 (every one answers handshake_failure), so until M5 (TLS 1.2) every
# badssl host must fail - and the "bad certificate" rows fail for that reason, not the
# certificate. They are here so M5 only has to flip expectations. revoked.badssl.com will be
# EXPECTED TO SUCCEED then: Brisk-SSL does no revocation checking (no CRL/OCSP, by design).
# Two TLS 1.3 sites with public certificates are the positive control for the system bundle.
BADSSL = [(f"{h}.badssl.com", 443, "fail") for h in (
    "sha256", "sha384", "sha512", "ecc256", "ecc384", "rsa2048", "rsa4096", "expired",
    "wrong.host", "self-signed", "untrusted-root", "revoked", "incomplete-chain",
    "mozilla-modern")] + [("badssl.com", 443, "fail"), ("tls-v1-2.badssl.com", 1012, "fail"),
                          ("tls-v1-0.badssl.com", 1010, "fail"),
                          ("www.cloudflare.com", 443, "ok"), ("www.google.com", 443, "ok")]


def badssl_inside():
    exe = build_brisk_get()
    rows = []
    for host, port, want in BADSSL:
        res = client(exe, ["-r", f"HEAD / HTTP/1.1\nHost: {host}\nConnection: close\n\n"], host, port)
        rows.append((f"{host}:{port} expect {want}",
                     *check(res, ("ok", "HTTP/", "") if want == "ok" else ("fail", "brisk:"))))
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
    s.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    sub.add_parser("ct")
    f = sub.add_parser("fuzz")
    f.add_argument("target", nargs="?", default="der", choices=sorted(FUZZ))
    f.add_argument("--seconds", type=int, default=60)
    sub.add_parser("interop")
    sub.add_parser("badssl")
    sub.add_parser("_interop")
    sub.add_parser("_badssl")
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
    if a.cmd in ("interop", "badssl"):
        return run(docker_cmd(["python3", "tools/dev.py", "_" + a.cmd]), False)[0]
    if a.cmd == "_interop":
        return interop_inside()
    if a.cmd == "_badssl":
        return badssl_inside()
    if a.cmd == "image":
        return run(["docker", "build", "-t", IMAGE, "docker/"], False)[0]
    if a.cmd == "_measure":
        return measure_inside(a.arch)


if __name__ == "__main__":
    sys.exit(main())
