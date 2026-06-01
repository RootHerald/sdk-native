cmake_minimum_required(VERSION 3.20)
project(rootherald_macos VERSION 0.2.0 LANGUAGES C OBJC)

set(CMAKE_C_STANDARD 11)

# -----------------------------------------------------------------------------
# librootherald.a — embeddable STATIC archive (macOS).
#
# Customer apps link this directly into their .app; the resulting binary is
# signed with the customer's Developer ID. No runtime dylib dependency on us.
#
# Layout (per the research reorg — see INTEGRATING.md):
#   src/client/    — RootHeraldClient lifecycle + macOS driver
#   src/tpm/       — Secure Enclave access
#   src/transport/ — HTTPS via NSURLSession
#   src/internal/  — Log shim (not exported)
#
# Stub mode (ROOTHERALD_STUB=ON) reuses the Linux stub implementation —
# canned data for CI / binding development. Never ship a stub build.
#
# System frameworks (propagated PUBLICly so consumers don't enumerate):
#   Security.framework + Foundation.framework
# -----------------------------------------------------------------------------

option(ROOTHERALD_STUB "Stub build (CI / binding tests only)" OFF)

if(ROOTHERALD_STUB)
    message(STATUS "Building librootherald.a as a STUB. Do not ship.")
    add_library(rootherald STATIC ../linux/src/client/rootherald_stub.c)
    target_include_directories(rootherald PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
else()
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)

    add_library(rootherald STATIC
        src/client/rootherald_client.m
        src/client/rootherald_macos.m
        src/tpm/secure_enclave.m
        src/transport/http_nsurlsession.m
        src/internal/log.m
    )

    target_include_directories(rootherald
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/../common
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/client
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tpm
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
            ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
    )

    target_link_libraries(rootherald PUBLIC
        ${SECURITY_FRAMEWORK}
        ${FOUNDATION_FRAMEWORK}
    )
endif()

install(TARGETS rootherald ARCHIVE DESTINATION lib)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/rootherald.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/protocol.h
    DESTINATION include
)
