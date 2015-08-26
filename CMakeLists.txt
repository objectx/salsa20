cmake_minimum_required (VERSION 3.3)

project (salsa20
    VERSION 1.0.0.0
    LANGUAGES CXX)

set (CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake)

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include (EnableCatch)
include (EnableCppFormat)

add_subdirectory (src)
add_subdirectory (test)
