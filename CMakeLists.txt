cmake_minimum_required(VERSION 3.20...4.4)
project(brisk_ssl VERSION 0.1.0 LANGUAGES C)

# Empty = let include/brisk_config.h decide (DEFAULT, or whatever a BRISK_USER_CONFIG header sets).
set(BRISK_PROFILE "" CACHE STRING "Feature profile: TINY, DEFAULT or FULL; empty = header default")
set_property(CACHE BRISK_PROFILE PROPERTY STRINGS "" TINY DEFAULT FULL)
option(BRISK_BUILD_TESTS "Build the test suite" ${PROJECT_IS_TOP_LEVEL})

# ponytail: static only until M8 (shared builds need BRISK_SHARED_BUILD + tests on internal symbols)
add_library(brisk STATIC
    src/util.c
    src/crypto/sha2.c
    src/crypto/hkdf.c
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux") # src/os/ is Linux-only; the mingw host skips it
    target_sources(brisk PRIVATE src/os/linux_rand.c)
endif()
set_target_properties(brisk PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                       C_VISIBILITY_PRESET hidden)
target_include_directories(brisk PUBLIC include PRIVATE src)
# PUBLIC: consumers see exactly the configuration the library was built with.
if(BRISK_PROFILE)
    target_compile_definitions(brisk PUBLIC BRISK_PROFILE=BRISK_PROFILE_${BRISK_PROFILE})
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(brisk PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wundef -Wvla
        -ffunction-sections -fdata-sections)
    if(NOT WIN32)
        # dead-code elimination needs the linker flag in the *final* link, so export it
        target_link_options(brisk INTERFACE -Wl,--gc-sections)
    endif()
endif()

if(BRISK_BUILD_TESTS)
    enable_testing()
    add_executable(brisk_tests tests/test_main.c tests/test_hash.c)
    set_target_properties(brisk_tests PROPERTIES C_STANDARD 99 C_EXTENSIONS OFF)
    target_link_libraries(brisk_tests PRIVATE brisk)
    target_include_directories(brisk_tests PRIVATE src tests)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        # KAT tables are long string literals by design
        target_compile_options(brisk_tests PRIVATE -Wall -Wextra -Wno-overlength-strings)
    endif()
    add_test(NAME hash COMMAND brisk_tests hash)
    set_tests_properties(hash PROPERTIES TIMEOUT 900) # qemu-emulated 32-bit targets are slow
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_sources(brisk_tests PRIVATE tests/test_rand.c)
        # fault injection for src/os/linux_rand.c (getrandom, /dev/random wait, kernel version)
        target_link_options(brisk_tests PRIVATE -Wl,--wrap=syscall,--wrap=poll,--wrap=uname,--wrap=personality)
        add_test(NAME rand COMMAND brisk_tests rand)
        set_tests_properties(rand PROPERTIES TIMEOUT 300) # a fill loop that never ends must fail
    endif()
endif()

# size probe: statically links every entry point so `tools/dev.py size` can read per-module
# flash/RAM from the linker map. Off by default (static linking clashes with sanitizers).
option(BRISK_SIZE_PROBE "Build the size-measurement probe" OFF)
if(BRISK_SIZE_PROBE)
    add_executable(brisk_size_probe tests/size_probe.c)
    target_link_libraries(brisk_size_probe PRIVATE brisk)
    target_include_directories(brisk_size_probe PRIVATE src)
    target_link_options(brisk_size_probe PRIVATE -static "-Wl,-Map=${CMAKE_BINARY_DIR}/size_probe.map")
endif()
