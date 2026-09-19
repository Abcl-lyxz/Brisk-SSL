cmake_minimum_required(VERSION 3.20...4.4)
project(brisk_ssl VERSION 0.1.0 LANGUAGES C)

set(BRISK_PROFILE "DEFAULT" CACHE STRING "Feature profile: TINY, DEFAULT or FULL (see include/brisk_config.h)")
set_property(CACHE BRISK_PROFILE PROPERTY STRINGS TINY DEFAULT FULL)
option(BRISK_BUILD_TESTS "Build the test suite" ${PROJECT_IS_TOP_LEVEL})

add_library(brisk
    src/util.c
    src/crypto/sha2.c
    src/crypto/hkdf.c
)
set_target_properties(brisk PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                       C_VISIBILITY_PRESET hidden)
target_include_directories(brisk PUBLIC include PRIVATE src)
# PUBLIC: consumers see exactly the configuration the library was built with.
target_compile_definitions(brisk PUBLIC BRISK_PROFILE=BRISK_PROFILE_${BRISK_PROFILE})

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
