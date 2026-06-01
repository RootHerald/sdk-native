cmake_minimum_required(VERSION 3.20)
project(rh_minimal_linux LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Pull in the SDK. The rootherald target propagates its include dir and
# tpm2-tss + libcurl link deps transitively.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../linux
                 ${CMAKE_BINARY_DIR}/rootherald-build)

add_executable(rh_minimal main.c)
target_link_libraries(rh_minimal PRIVATE rootherald)
