---
paths:
  - "CMakeLists.txt"
  - "CMakePresets.json"
  - "cmake/**"
  - "docker/**"
  - "tools/**"
  - ".github/**"
---
# Build rules (Brisk-SSL)

- Feature/config logic lives only in `include/brisk_config.h`. CMake passes nothing but
  `BRISK_PROFILE` (and later `BRISK_ENABLE_<X>` for explicit ON/OFF) as PUBLIC definitions.
- `CMakePresets.json` stays at schema version 6 (Docker has CMake 3.31). Every preset has a
  matching build/test/workflow preset so `cmake --workflow --preset <p>` does everything.
- New arch = one 6-line `cmake/toolchains/<arch>.cmake` with `CMAKE_CROSSCOMPILING_EMULATOR`,
  a preset, and an entry in `tools/dev.py` (CROSS, TRIPLET).
- `docker/Dockerfile` is pinned to Debian trixie (later Debian drops the MIPS cross compilers);
  rebuild with `python tools/dev.py image` after editing it. Docker builds live in the
  `brisk-build` volume, host builds in `build/<preset>`.
- `size/baseline.json` changes only deliberately (`dev.py size --save`) with the reason in
  the commit message.
- Tools are stdlib-only Python 3; call `python` on the Windows host (`python3` is a Store stub),
  `python3` inside Docker/CI.
