
cmake_minimum_required (VERSION 3.3)

include (CheckCXXCompilerFlag)

if (${WIN32})
    CHECK_CXX_COMPILER_FLAG ("/arch:AVX" HAVE_SSE3)
else ()
    CHECK_CXX_COMPILER_FLAG ("-msse3" HAVE_SSE3)
endif ()

if (${HAVE_SSE3})
    add_definitions ("-DHAVE_SSE3")
endif ()

set (SOURCE_FILES main.cxx md5.cxx sse.cxx)

set (TARGET_NAME "test-salsa20")
add_executable (${TARGET_NAME} ${SOURCE_FILES})
    target_link_libraries      (${TARGET_NAME} PRIVATE salsa20 cppformat)
    target_compile_definitions (${TARGET_NAME} PRIVATE "-DNOMINMAX")
    target_compile_features    (${TARGET_NAME} PRIVATE cxx_auto_type cxx_uniform_initialization)
    target_include_directories (${TARGET_NAME} PRIVATE ${CMAKE_BINARY_DIR}/include)
