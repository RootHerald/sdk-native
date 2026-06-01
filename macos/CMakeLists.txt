cmake_minimum_required(VERSION 3.20)
project(rootherald_macos VERSION 0.2.0 LANGUAGES C OBJC)

set(CMAKE_C_STANDARD 11)

# -----------------------------------------------------------------------------
# Wave 6 — STATIC library on macOS.
#
#   librootherald.a    — embeddable STATIC archive; carries the public C ABI
#                        from <rootherald.h> and the legacy RootHerald*
#                        symbols. Customer apps (and our own native_host
#                        shell) static-link this archive directly.
#   native_host        — browser-extension native-messaging shell. Static-
#                        links librootherald.a + Foundation.framework. No
#                        runtime dependency on a Root-Herald-signed dylib.
#
# Design decision: previous waves shipped a Mach-O *framework* bundle so
# that SwiftPM / Xcode consumers could drag-and-drop a `.framework` into
# their project. With static linking, the framework wrapper would have to
# be a *static framework* (an unusual Apple artefact that some tools handle
# poorly) and the customer's own Developer ID covers the resulting binary
# either way. We therefore ship the simpler `librootherald.a` + headers
# pair; Xcode and SwiftPM both consume that directly via "Other Linker
# Flags" / `linkerSettings`. A repackaging step into a static `.framework`
# can be added back as a downstream packaging concern if a customer
# requests it without affecting the ABI.
#
# Stub mode (ROOTHERALD_STUB=ON): no Security/Foundation deps; canned data
# for binding development. Same semantics as the Linux stub.
#
# System frameworks customers must add to their own link line (transparent
# when consuming this CMakeLists via target_link_libraries):
#   Security.framework, Foundation.framework
# -----------------------------------------------------------------------------

option(ROOTHERALD_STUB "Build a stub librootherald.a (CI / binding tests only)" OFF)

if(ROOTHERALD_STUB)
    message(STATUS "Building librootherald.a as a STUB (no Secure Enclave). Do not ship.")
    add_library(rootherald STATIC ../linux/rootherald_stub.c)
    target_include_directories(rootherald PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
else()
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)

    add_library(rootherald STATIC
        rootherald_client.m
        rootherald_macos.m
        secure_enclave.m
        http_nsurlsession.m
    )

    target_include_directories(rootherald PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )

    # PUBLIC: a static archive defers its system-framework resolution to
    # the consuming executable's final link step. Propagating PUBLICly
    # means customer integrations only need to link the `rootherald`
    # target — the system frameworks come along automatically.
    target_link_libraries(rootherald PUBLIC
        ${SECURITY_FRAMEWORK}
        ${FOUNDATION_FRAMEWORK}
    )
endif()

add_library(rootherald ALIAS rootherald)

# -----------------------------------------------------------------------------
# native_host — thin browser-extension shell. Static-links librootherald.a.
# -----------------------------------------------------------------------------
add_executable(native_host
    native_host/native_host.m
)

target_include_directories(native_host PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_link_libraries(native_host PRIVATE rootherald)

add_executable(rootherald-host ALIAS native_host)
