
cmake_minimum_required (VERSION 3.9)

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

function (make_target TARGET_)
    add_executable (${TARGET_} ${SOURCE_FILES})
    target_include_directories (${TARGET_} PRIVATE ${SALSA20_SOURCE_DIR}/ext)
    target_link_libraries      (${TARGET_} PRIVATE salsa20 fmt)
    target_compile_definitions (${TARGET_} PRIVATE "-DNOMINMAX=1")
    target_compile_features    (${TARGET_} PRIVATE cxx_std_14)
endfunction ()

make_target (test_salsa20)
