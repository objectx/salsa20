
cmake_minimum_required (VERSION 3.3)

include (TestBigEndian)
include (CheckCXXSourceRuns)
include (CheckCXXCompilerFlag)

enable_language (C)

if (NOT ${CMAKE_CROSSCOMPILING})
    TEST_BIG_ENDIAN (IS_BIG_ENDIAN)
    if (NOT ${IS_BIG_ENDIAN})
        set (TARGET_LITTLE_ENDIAN 0x1)
    endif ()
    check_cxx_source_runs ([=[
        #include <cstdint>
        int main () {
            char tmp [] = { 0, 4, 3, 2, 1 } ;
            int32_t v = *((const int32_t *)(&tmp [1])) ;
            if (v == 0x01020304u) {
                return 0 ;
            }
            return 1 ;
        }
        ]=] TARGET_ALLOWS_UNALIGNED_ACCESS)
    set (HAVE_CONFIG_H 1)
    if (${WIN32})
        CHECK_CXX_COMPILER_FLAG ("/arch:AVX" HAVE_SSE3)
    else ()
        CHECK_CXX_COMPILER_FLAG ("-msse3" HAVE_SSE3)
    endif ()
endif ()

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
                ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set (CONSTANT_TABLE ${CMAKE_CURRENT_BINARY_DIR}/salsa20_const.cxx)

set (SOURCE_FILES salsa20.cxx ${CONSTANT_TABLE})

add_custom_command (
    OUTPUT ${CONSTANT_TABLE}
    COMMENT "Create obfuscated constant table"
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/constgen.py
            --obfuscate-mask 0xABADCAFE -o ${CONSTANT_TABLE}
    DEPENDS constgen.py)

set (TARGET_NAME "salsa20")

add_library (${TARGET_NAME} ${SOURCE_FILES})
    target_compile_features (${TARGET_NAME} PUBLIC cxx_auto_type cxx_alias_templates cxx_alignas)
    target_include_directories (${TARGET_NAME}
        PUBLIC ${CMAKE_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_BINARY_DIR}/include)
    target_compile_definitions (${TARGET_NAME} PRIVATE $<$<BOOL:HAVE_CONFIG_H>:HAVE_CONFIG_H=1>)
