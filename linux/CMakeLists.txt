cmake_minimum_required(VERSION 3.20)
project(rootherald_linux VERSION 0.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# Wave 6 — STATIC library on Linux.
#
#   librootherald.a    — embeddable STATIC archive; carries the public C ABI
#                        from <rootherald.h> and the legacy RootHerald*
#                        symbols. Customer apps link this archive directly
#                        into their own ELF and ship a single signed binary.
#   native_host        — browser-extension native-messaging shell. Static-
#                        links librootherald.a; no runtime .so dependency on
#                        Root Herald.
#
# Stub mode (ROOTHERALD_STUB=ON): when tpm2-tss / libcurl aren't installed
# (typical for build agents / CI cross-builds), build a stub archive that
# returns canned mock evidence so downstream bindings (Rust, Python, samples)
# still compile and link. Stub mode is OFF by default; CI sets it explicitly.
#
# System library list that customers must add to their own link line
# (transparent when building from this CMakeLists via target_link_libraries):
#   tpm2-tss   — libtss2-esys, libtss2-tctildr, libtss2-mu  (TPM access)
#   libcurl    — HTTPS transport
#   pthread    — thread primitives
#   libssl/libcrypto are pulled in transitively by curl when needed.
# -----------------------------------------------------------------------------

option(ROOTHERALD_STUB "Build a stub librootherald.a without TPM/curl deps (CI/binding tests only)" OFF)

if(ROOTHERALD_STUB)
    message(STATUS "Building librootherald.a as a STUB (no TPM/curl). Do not ship.")
    add_library(rootherald STATIC rootherald_stub.c)
    target_include_directories(rootherald PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
    pkg_check_modules(TSS2_TCTILDR REQUIRED tss2-tctildr)
    pkg_check_modules(TSS2_MU REQUIRED tss2-mu)
    pkg_check_modules(CURL REQUIRED libcurl)

    add_library(rootherald STATIC
        rootherald_client.c
        rootherald_linux.c
        tpm_esapi.c
        event_log.c
        http_curl.c
    )

    target_include_directories(rootherald PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
        ${TSS2_ESYS_INCLUDE_DIRS}
        ${CURL_INCLUDE_DIRS}
    )

    # PUBLIC: a static archive cannot resolve its own dependencies; the
    # consuming executable resolves them at final link. Propagate them
    # transitively so customer / shell consumers only need to link the
    # `rootherald` target.
    target_link_libraries(rootherald PUBLIC
        ${TSS2_ESYS_LIBRARIES}
        ${TSS2_TCTILDR_LIBRARIES}
        ${TSS2_MU_LIBRARIES}
        ${CURL_LIBRARIES}
        pthread
    )
endif()

# Alias kept for in-tree consumers that still link against `rootherald`.
add_library(rootherald ALIAS rootherald)

# -----------------------------------------------------------------------------
# native_host — thin browser-extension shell. Static-links librootherald.a
# for all real work; carries only JSON framing + stdio loop (~200 lines).
# The resulting executable has no runtime dependency on a Root-Herald-shipped
# shared object.
# -----------------------------------------------------------------------------
add_executable(native_host
    native_host/native_host.c
)

target_include_directories(native_host PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_link_libraries(native_host PRIVATE rootherald)

# Legacy executable name kept as an alias.
add_executable(rootherald-host ALIAS native_host)

# ARCHIVE destination, not LIBRARY: librootherald is a static archive.
install(TARGETS rootherald ARCHIVE DESTINATION lib)
install(TARGETS native_host RUNTIME DESTINATION bin)
