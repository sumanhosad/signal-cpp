cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 11)

project(signal-cpp)

include_directories(includes)
set(SOURCES
    src/x3dh.cc
    x3dh.cpp
)

add_executable(x3dh ${SOURCES})

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

include_directories(${LIBSODIUM_INCLUDE_DIRS})
link_directories(${LIBSODIUM_LIBRARY_DIRS})

target_link_libraries(x3dh ${LIBSODIUM_LIBRARIES})

