cmake_minimum_required(VERSION 3.20)
project(rootherald_linux VERSION 0.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# librootherald.a — embeddable STATIC archive. Public C ABI from
# common/rootherald.h. Customer apps link this directly into their ELF.
#
# Stub mode (ROOTHERALD_STUB=ON): for CI / build agents without tpm2-tss +
# libcurl. Builds against rootherald_stub.c instead — returns canned mock
# evidence. Never ship a stub build to customers.
#
# Layout (per the research reorg — see INTEGRATING.md):
#   src/client/    — RootHeraldClient lifecycle + Linux driver
#   src/tpm/       — TPM access via tpm2-tss ESAPI
#   src/boot/      — Event log parsing
#   src/transport/ — HTTPS via libcurl
#   src/internal/  — Log shim (not exported)
# -----------------------------------------------------------------------------

option(ROOTHERALD_STUB "Stub build without tpm2-tss/curl deps (CI only)" OFF)

if(ROOTHERALD_STUB)
    message(STATUS "Building librootherald.a as a STUB. Do not ship.")
    add_library(rootherald STATIC src/client/rootherald_stub.c)
    target_include_directories(rootherald PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
    pkg_check_modules(TSS2_TCTILDR REQUIRED tss2-tctildr)
    pkg_check_modules(TSS2_MU REQUIRED tss2-mu)
    pkg_check_modules(CURL REQUIRED libcurl)

    add_library(rootherald STATIC
        src/client/rootherald_client.c
        src/client/rootherald_linux.c
        src/tpm/tpm_esapi.c
        src/boot/event_log.c
        src/transport/http_curl.c
        src/internal/log.c
    )

    target_include_directories(rootherald
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/../common
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/client
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tpm
            ${CMAKE_CURRENT_SOURCE_DIR}/src/boot
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
            ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
            ${TSS2_ESYS_INCLUDE_DIRS}
            ${CURL_INCLUDE_DIRS}
    )

    target_link_libraries(rootherald PUBLIC
        ${TSS2_ESYS_LIBRARIES}
        ${TSS2_TCTILDR_LIBRARIES}
        ${TSS2_MU_LIBRARIES}
        ${CURL_LIBRARIES}
        pthread
    )
endif()

install(TARGETS rootherald ARCHIVE DESTINATION lib)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/rootherald.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/protocol.h
    DESTINATION include
)
