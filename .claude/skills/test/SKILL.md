---
description: Build and run Brisk-SSL tests - host (fast), chosen presets, or every CPU arch under qemu in Docker.
argument-hint: "[host | all | <preset>...]"
---
# Test

Run `python tools/dev.py test --arch $ARGUMENTS` (no argument = host presets `dev` + `dev32`).

- Host: `dev` (x64, UBSan) and `dev32` (-m32, exercises the 32-bit code paths)
- Docker: `x86_64 asan i686 aarch64 armv7hf armv5 mips mipsel mips64 riscv64 ppc`
  (`mips` and `ppc` are big-endian; `armv5` runs as an ARM926 - catches v6+ instructions)
- Missing image: `python tools/dev.py image`

On failure the suite prints `FAIL file:line: expr [vector N]`. Find the root cause (byte order,
alignment, 32-bit `size_t`, integer promotion...), fix it, rerun only the failing presets, then
`all` before committing.
