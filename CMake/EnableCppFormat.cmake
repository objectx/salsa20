#
# Enable CppFormat
#
# Copyright (c) 2015 Masashi Fujita

message ("Enable CppFormat")

# Download Catch
if (NOT EXISTS "${CMAKE_BINARY_DIR}/include/cppformat")
    message ("Downloading cppformat/format.h")
    file (MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/include/cppformat")
    file (DOWNLOAD
        "https://raw.githubusercontent.com/cppformat/cppformat/master/format.h"
        "${CMAKE_BINARY_DIR}/include/cppformat/format.h")
endif ()

if (NOT EXISTS "${CMAKE_BINARY_DIR}/cppformat")
    message ("Downloading cppformat/format.cc")
    file (MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/cppformat")
    file (DOWNLOAD
        "https://raw.githubusercontent.com/cppformat/cppformat/master/format.cc"
        "${CMAKE_BINARY_DIR}/cppformat/format.cc")
endif ()

add_library (cppformat STATIC "${CMAKE_BINARY_DIR}/cppformat/format.cc")
target_include_directories (cppformat PRIVATE
    "${CMAKE_BINARY_DIR}/include/cppformat")
target_compile_features (cppformat PUBLIC cxx_auto_type)
