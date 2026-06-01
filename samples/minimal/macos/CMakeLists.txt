cmake_minimum_required(VERSION 3.20)
project(rh_minimal_macos LANGUAGES C OBJC)

set(CMAKE_C_STANDARD 11)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../macos
                 ${CMAKE_BINARY_DIR}/rootherald-build)

add_executable(rh_minimal main.m)
target_link_libraries(rh_minimal PRIVATE rootherald)
