cmake_minimum_required(VERSION 3.20)
project(rh_minimal_windows LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pull in the SDK. RootHerald target propagates its include dir and the
# system libraries (ncrypt/tbs/winhttp/bcrypt/crypt32) it depends on.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../windows
                 ${CMAKE_BINARY_DIR}/rootherald-build)

add_executable(rh_minimal main.cpp)
target_link_libraries(rh_minimal PRIVATE RootHerald)
