---
description: Scaffold a new Brisk-SSL module (source, internal decls, test suite, CMake entry, config knob, ROADMAP line) following the project conventions.
argument-hint: "<layer/name, e.g. crypto/aead | x509/der | tls/record>"
---
# New module: $ARGUMENTS

1. `src/<layer>/<name>.c`: header comment (purpose + spec sections) and
   `SPDX-License-Identifier: Apache-2.0`, `#include "brisk_int.h"`. If the module is optional,
   wrap the body in `#if BRISK_ENABLE_<X>` and add `typedef int brisk__tu_<name>;` so the
   translation unit is never empty (-Wpedantic).
2. Internal prototypes in `src/brisk_int.h` (`brisk__` prefix). Public API only if users need it:
   `brisk_` prefix, declared **and documented** in `include/brisk.h` (the header is the reference).
3. Knob in `include/brisk_config.h` using the documented pattern: profile default, force what it
   depends on, `#error` on an explicit contradiction. Public struct sizes must not depend on it.
4. Wire up: source in `add_library(brisk ...)`, `tests/test_<name>.c` + suite in `tests/test.h`
   and `SUITES[]` in `tests/test_main.c`, `add_test(NAME <name> ...)` in `CMakeLists.txt`,
   entry points in `tests/size_probe.c`.
5. Add the ROADMAP checkbox, then go test-first with `/kat` and `/test`.
