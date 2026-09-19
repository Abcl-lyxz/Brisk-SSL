---
description: Brisk-SSL code-size report - per-module flash/RAM on every arch (static -Os link map), delta vs size/baseline.json, forbidden libgcc/float helper check.
argument-hint: "[all | <arch>...] [--save] [--check]"
---
# Size report

Run `python tools/dev.py size --arch $ARGUMENTS --md` (no arch = all 10).

- Numbers are bytes of kept code+rodata+data per module (`libbrisk.a(<module>.c.o)`), libc excluded.
- `(+N)` is the change against `size/baseline.json`. Explain any growth in the commit message;
  run with `--save` only when the growth is intended.
- A `FORBIDDEN` line means library code pulled in `__udivdi3`-style 64-bit division or float
  helpers: fix the code (use shifts/masks, 32-bit arithmetic), never whitelist.
- When a feature knob lands, add its KB cost per arch to `docs/CONFIG.md`.
