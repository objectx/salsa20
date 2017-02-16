
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

include_directories (${CMAKE_BINARY_DIR}/include)
function (make_target TARGET_)
    add_executable (${TARGET_} ${SOURCE_FILES})
    target_link_libraries      (${TARGET_} PRIVATE salsa20 fmt)
    target_compile_definitions (${TARGET_} PRIVATE "-DNOMINMAX")
    target_compile_features    (${TARGET_} PRIVATE cxx_auto_type cxx_uniform_initialization cxx_alignas)
endfunction ()

make_target (test_salsa20)
