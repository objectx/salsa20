
cmake_minimum_required (VERSION 3.3)

project (SALSA20
         VERSION 1.0.0.0
         LANGUAGES CXX)

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

setvar_default (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/CMake)
setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include (EnableCatch)

add_subdirectory (ext/fmt)

find_program (PYTHON3_EXECUTABLE python3)
add_subdirectory (src)
add_subdirectory (test)
