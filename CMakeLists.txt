cmake_minimum_required(VERSION 3.10)
project(signal-cpp)

# Use C++11.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories for header files.
include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Find libsodium using pkg-config.
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# Add libsodium include directories and library directories.
include_directories(${LIBSODIUM_INCLUDE_DIRS})
link_directories(${LIBSODIUM_LIBRARY_DIRS})

# Add the executable target.
# The main source is "example.cpp" in the project root.
add_executable(x3dh x3dh.cpp)

# (Optional) If you have additional source files in the src directory, you can add them:
# file(GLOB SRC_FILES ${CMAKE_SOURCE_DIR}/src/*.cc)
# target_sources(example PRIVATE ${SRC_FILES})

# Link libsodium.
target_link_libraries(x3dh ${LIBSODIUM_LIBRARIES})

