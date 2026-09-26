cmake_minimum_required(VERSION 3.20...4.4)
project(brisk_ssl VERSION 0.1.0 LANGUAGES C)

# Empty = let include/brisk_config.h decide (DEFAULT, or whatever a BRISK_USER_CONFIG header sets).
set(BRISK_PROFILE "" CACHE STRING "Feature profile: TINY, DEFAULT or FULL; empty = header default")
set_property(CACHE BRISK_PROFILE PROPERTY STRINGS "" TINY DEFAULT FULL)
# Same rule for the X.509 time policy: empty = the header's default (FLOOR). A cache variable
# and not a raw -D so the two policies the default build never exercises can be run by name.
set(BRISK_X509_TIME_POLICY "" CACHE STRING
    "X.509 validity: STRICT, FLOOR or INSECURE_NO_TIME; empty = header default")
set_property(CACHE BRISK_X509_TIME_POLICY PROPERTY STRINGS "" STRICT FLOOR INSECURE_NO_TIME)
# Explicit ON/OFF for BRISK_ENABLE_TLS12 (empty = the profile decides, brisk_config.h).
set(BRISK_ENABLE_TLS12 "" CACHE STRING "TLS 1.2 client: ON, OFF or empty (profile default)")
set_property(CACHE BRISK_ENABLE_TLS12 PROPERTY STRINGS "" ON OFF)
option(BRISK_BUILD_TESTS "Build the test suite" ${PROJECT_IS_TOP_LEVEL})
option(BRISK_BUILD_EXAMPLES "Build examples/ (Linux only)" ${PROJECT_IS_TOP_LEVEL})

# ponytail: static only until M8 (shared builds need BRISK_SHARED_BUILD + tests on internal symbols)
add_library(brisk STATIC
    src/util.c
    src/crypto/sha2.c
    src/crypto/hkdf.c
    src/crypto/chacha20_poly1305.c
    src/crypto/aes_ct.c   # 32-bit targets (the file compiles to nothing on 64-bit)
    src/crypto/aes_ct64.c # 64-bit targets
    src/crypto/gcm.c      # GHASH ctmul32 / ctmul64 (same split) + AES-GCM
    src/crypto/x25519.c   # #includes vendor/fiat/curve25519_{32,64}.c (all-static, see VENDORED.md)
    src/crypto/p256.c     # #includes vendor/fiat/p256_{32,64}.c (same rule)
    src/crypto/bn.c       # i31 constant-time Montgomery big integers
    src/crypto/p384.c     # ECDSA P-384 verify on bn.c (empty TU when BRISK_ENABLE_P384 is 0)
    src/crypto/rsa.c      # RSASSA-PKCS1-v1_5 / RSASSA-PSS verify (RFC 8017)
    src/x509/der.c        # strict DER reader (ITU-T X.690), the X.509 foundation
    src/x509/cert.c       # one certificate: fields, extensions, validity dates
    src/x509/chain.c      # path building to a trust anchor + the signature checks
    src/x509/name.c       # RFC 9525 service identity: host name / IP against the SAN
    src/x509/bundle.c     # PEM certificates out of a byte stream, sans-I/O; strict one-shot PEM
    src/x509/key.c        # the device P-256 key: raw d, SEC1 / PKCS#8 DER, PEM (BRISK_ENABLE_MTLS)
    src/tls/keyschedule.c # TLS 1.3 key schedule (RFC 9846 sect 7.1) + Finished + exporter
    src/tls/handshake.c   # TLS 1.3 client handshake engine (RFC 9846 sect 4), sans-I/O
    src/tls/tls12.c       # TLS 1.2 client half of the engine (empty TU without BRISK_ENABLE_TLS12)
    src/tls/record.c      # TLS 1.3 record layer over TCP (RFC 9846 sect 5) + connection driver
    src/tls/ticket.c      # the resumption ticket blob (RFC 9846 4.7.1): export / import
    src/tls/conn.c        # the public connection (brisk_conn): sans-I/O glue over hs + record
    src/http/huffman.c    # HPACK/QPACK prefixed integer + Huffman decode (empty TU without H2)
    src/http/hpack.c      # HPACK (RFC 7541) decoder + encoder (empty TU without BRISK_ENABLE_H2)
    src/http/h2.c         # HTTP/2 frames, streams, flow control, brisk_h2_* (same rule)
    src/http/qpack.c      # QPACK (RFC 9204), static table only (empty TU without BRISK_ENABLE_H3)
    src/http/h3.c         # HTTP/3 frames, control stream, brisk_h3_* (same rule)
    src/quic/packet.c     # QUIC v1 packets + header protection (empty TU without BRISK_ENABLE_QUIC)
    src/quic/conn.c       # QUIC v1 client: TPs, frames, CRYPTO on the TLS 1.3 engine (same rule)
    src/quic/recovery.c   # QUIC ACK ranges, RTT, loss / PTO, NewReno (same rule)
    src/quic/stream.c     # QUIC streams + flow control (same rule)
    src/quic/api.c        # the public brisk_quic_* (sans-I/O glue; same rule)
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux") # src/os/ is Linux-only; the mingw host skips it
    target_sources(brisk PRIVATE src/os/linux_rand.c src/os/linux_ca.c src/os/linux_net.c
                                 src/os/linux_udp.c)
endif()
set_target_properties(brisk PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
                                       C_VISIBILITY_PRESET hidden)
target_include_directories(brisk PUBLIC include PRIVATE src vendor)
# PUBLIC: consumers see exactly the configuration the library was built with.
if(BRISK_PROFILE)
    target_compile_definitions(brisk PUBLIC BRISK_PROFILE=BRISK_PROFILE_${BRISK_PROFILE})
endif()
if(NOT BRISK_ENABLE_TLS12 STREQUAL "")
    if(BRISK_ENABLE_TLS12)
        target_compile_definitions(brisk PUBLIC BRISK_ENABLE_TLS12=1)
    else()
        target_compile_definitions(brisk PUBLIC BRISK_ENABLE_TLS12=0)
    endif()
endif()
if(BRISK_X509_TIME_POLICY)
    target_compile_definitions(brisk PUBLIC
        BRISK_X509_TIME_POLICY=BRISK_X509_TIME_POLICY_${BRISK_X509_TIME_POLICY})
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(brisk PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wcast-align -Wstrict-prototypes -Wundef -Wvla
        -ffunction-sections -fdata-sections
        # Pinned, and PRIVATE so only our own TUs get it. Every stack figure in the sources
        # (p256.c's header table) and every number in size/baseline.json is an -Os figure; -O3
        # inlines the P-256 ladder until ECDSA verify passes the 2 KB budget. Comes after
        # CMAKE_C_FLAGS/CMAKE_C_FLAGS_<CONFIG>, and the last -O wins, so it overrides the build
        # type on purpose. A consumer who wants -O3 for *their* code still gets it.
        -Os)
    if(NOT WIN32)
        # dead-code elimination needs the linker flag in the *final* link, so export it
        target_link_options(brisk INTERFACE -Wl,--gc-sections)
    endif()
endif()

if(BRISK_BUILD_TESTS)
    enable_testing()
    add_executable(brisk_tests tests/test_main.c tests/test_hash.c tests/test_aead.c tests/test_aes.c
                               tests/test_x25519.c tests/test_p256.c tests/test_p384.c
                               tests/test_rsa.c tests/test_der.c tests/test_x509.c tests/test_key.c
                               tests/test_ct.c tests/test_tls13_ks.c
                               tests/test_tls13_hs.c tests/test_tls13_rec.c tests/test_conn.c
                               tests/test_tls12_prf.c tests/test_tls12_rec.c tests/test_tls12_hs.c
                               tests/test_hpack.c tests/test_h2.c tests/test_quic.c
                               tests/test_quic_api.c tests/test_qpack.c tests/test_h3.c)
    set_target_properties(brisk_tests PROPERTIES C_STANDARD 99 C_EXTENSIONS OFF)
    target_link_libraries(brisk_tests PRIVATE brisk)
    target_include_directories(brisk_tests PRIVATE src tests)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        # KAT tables are long string literals by design
        target_compile_options(brisk_tests PRIVATE -Wall -Wextra -Wno-overlength-strings)
    endif()
    add_test(NAME hash COMMAND brisk_tests hash)
    set_tests_properties(hash PROPERTIES TIMEOUT 900) # qemu-emulated 32-bit targets are slow
    add_test(NAME aead COMMAND brisk_tests aead)
    set_tests_properties(aead PROPERTIES TIMEOUT 900)
    add_test(NAME aes COMMAND brisk_tests aes)
    set_tests_properties(aes PROPERTIES TIMEOUT 900)
    add_test(NAME x25519 COMMAND brisk_tests x25519)
    set_tests_properties(x25519 PROPERTIES TIMEOUT 900)
    add_test(NAME p256 COMMAND brisk_tests p256)
    set_tests_properties(p256 PROPERTIES TIMEOUT 900)
    add_test(NAME p384 COMMAND brisk_tests p384)
    # 900 like the others. The spec budgeted 1800 for this suite; MEASURED on qemu-armv5 it is
    # 42 s for ~1300 verifies (32 ms each), against 148 s for p256 - so the generic bignum turned
    # out far cheaper than the "several hundred ms per verify" the risk list assumed, and there is
    # no reason for a special case here. Re-measure before adding vectors in bulk.
    set_tests_properties(p384 PROPERTIES TIMEOUT 900)
    add_test(NAME rsa COMMAND brisk_tests rsa)
    set_tests_properties(rsa PROPERTIES TIMEOUT 900)
    add_test(NAME der COMMAND brisk_tests der)
    set_tests_properties(der PROPERTIES TIMEOUT 900)
    add_test(NAME x509 COMMAND brisk_tests x509)
    set_tests_properties(x509 PROPERTIES TIMEOUT 900)
    add_test(NAME key COMMAND brisk_tests key)
    set_tests_properties(key PROPERTIES TIMEOUT 900)
    add_test(NAME ct COMMAND brisk_tests ct) # under valgrind in `dev.py ct`; here just a smoke run
    set_tests_properties(ct PROPERTIES TIMEOUT 900)
    add_test(NAME tls13_ks COMMAND brisk_tests tls13_ks)
    set_tests_properties(tls13_ks PROPERTIES TIMEOUT 900)
    add_test(NAME tls13_hs COMMAND brisk_tests tls13_hs)
    set_tests_properties(tls13_hs PROPERTIES TIMEOUT 900)
    add_test(NAME tls13_rec COMMAND brisk_tests tls13_rec)
    set_tests_properties(tls13_rec PROPERTIES TIMEOUT 900)
    add_test(NAME conn COMMAND brisk_tests conn)
    set_tests_properties(conn PROPERTIES TIMEOUT 900)
    add_test(NAME tls12_prf COMMAND brisk_tests tls12_prf)
    set_tests_properties(tls12_prf PROPERTIES TIMEOUT 900)
    add_test(NAME tls12_rec COMMAND brisk_tests tls12_rec)
    set_tests_properties(tls12_rec PROPERTIES TIMEOUT 900)
    add_test(NAME tls12_hs COMMAND brisk_tests tls12_hs)
    set_tests_properties(tls12_hs PROPERTIES TIMEOUT 900)
    add_test(NAME hpack COMMAND brisk_tests hpack)
    set_tests_properties(hpack PROPERTIES TIMEOUT 900)
    add_test(NAME h2 COMMAND brisk_tests h2)
    set_tests_properties(h2 PROPERTIES TIMEOUT 900)
    add_test(NAME quic COMMAND brisk_tests quic)
    set_tests_properties(quic PROPERTIES TIMEOUT 900)
    add_test(NAME quic_api COMMAND brisk_tests quic_api)
    set_tests_properties(quic_api PROPERTIES TIMEOUT 900)
    add_test(NAME qpack COMMAND brisk_tests qpack)
    set_tests_properties(qpack PROPERTIES TIMEOUT 900)
    add_test(NAME h3 COMMAND brisk_tests h3)
    set_tests_properties(h3 PROPERTIES TIMEOUT 900)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_sources(brisk_tests PRIVATE tests/test_rand.c tests/test_sock.c)
        # fault injection for src/os/linux_rand.c (getrandom, /dev/random wait, kernel version)
        target_link_options(brisk_tests PRIVATE -Wl,--wrap=syscall,--wrap=poll,--wrap=uname,--wrap=personality)
        add_test(NAME rand COMMAND brisk_tests rand)
        set_tests_properties(rand PROPERTIES TIMEOUT 300) # a fill loop that never ends must fail
        add_test(NAME sock COMMAND brisk_tests sock) # loopback TCP + fork(), the blocking API
        set_tests_properties(sock PROPERTIES TIMEOUT 900)
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

if(BRISK_BUILD_EXAMPLES AND CMAKE_SYSTEM_NAME STREQUAL "Linux") # the blocking API is Linux-only
    foreach(ex brisk_get h2_get h3_get aws_iot_https mqtt_tls)
        add_executable(${ex} examples/${ex}.c)
        set_target_properties(${ex} PROPERTIES C_STANDARD 99 C_EXTENSIONS OFF)
        target_link_libraries(${ex} PRIVATE brisk)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${ex} PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    endforeach()
endif()

# `cmake --install`: the static library and the two public headers (OpenWrt: openwrt/brisk-ssl,
# which also ships brisk_get). The profile is baked into libbrisk.a; brisk.h declares the same
# API in every profile, so consumers need no matching -D.
include(GNUInstallDirs)
install(TARGETS brisk ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/brisk.h include/brisk_config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(BRISK_BUILD_EXAMPLES AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(TARGETS brisk_get h2_get h3_get RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
