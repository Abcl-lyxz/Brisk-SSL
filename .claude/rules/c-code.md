---
paths:
  - "src/**/*.{c,h}"
  - "include/**/*.h"
  - "tests/**/*.{c,h}"
---
# C conventions (Brisk-SSL)

- C99, no extensions. Warning-free with `-Wall -Wextra -Wpedantic -Wshadow -Wcast-align
  -Wstrict-prototypes -Wundef -Wvla` on gcc 10 (mingw host) and gcc 14 / clang 19 (Docker).
- Data types: `uint8_t`..`uint64_t`, `size_t` for lengths. Never `long` (32-bit on mingw and
  32-bit Linux). Never `time_t` for certificate dates (int64 seconds).
- Byte order/alignment: only `brisk__load_be*` / `brisk__store_be*` or byte access; never cast
  `uint8_t *` to a wider pointer.
- No 64-bit `/` or `%` and no floating point in library code (`tools/dev.py size` fails on
  `__udivdi3` / float helpers). Use shifts and masks.
- Core code: no malloc, no syscalls, no globals with mutable state. Only `src/os/` touches the OS.
  Callers own all memory; `brisk_*_size()` reports what is needed.
- Names: public `brisk_*`/`BRISK_*` declared **and documented** in `include/brisk.h`; internal
  `brisk__*` in `src/brisk_int.h`; file-local helpers `static` without prefix. Macros must be
  unique across files or `#undef`'d at file end (amalgamation). No generic public macros that
  collide with other libraries (use `BRISK_SSL_*` for versioning-style names).
- Status-returning functions return `BRISK_OK` or a negative `BRISK_E_*`.
- Always brace; `.clang-format` is applied automatically by the post-edit hook.
- Tests: vectors come from `tools/kat.py` (never hand-typed); cover unaligned buffers, split
  input, invalid inputs; `python tools/dev.py test --arch all` before every commit.
