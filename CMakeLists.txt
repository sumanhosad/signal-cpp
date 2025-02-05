cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 11)

project(signal-cpp)

include_directories(includes)

add_executable(x3dh x3dh.cpp src/x3dh.cc)
add_executable(encrypt encrypt.cpp)
add_executable(yeah yeah.cpp src/x3dh.cc src/print_hex.cc)
add_executable(double-ratchet double-ratchet.cpp src/x3dh.cc src/double-ratchet.cc src/print_hex.cc)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

include_directories(${LIBSODIUM_INCLUDE_DIRS})
link_directories(${LIBSODIUM_LIBRARY_DIRS})

target_link_libraries(x3dh ${LIBSODIUM_LIBRARIES})
target_link_libraries(encrypt ${LIBSODIUM_LIBRARIES})
target_link_libraries(yeah ${LIBSODIUM_LIBRARIES})
target_link_libraries(double-ratchet ${LIBSODIUM_LIBRARIES})


