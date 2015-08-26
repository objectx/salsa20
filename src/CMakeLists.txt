
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES salsa20.cxx salsa20_const.cxx)

add_library (salsa20 ${SOURCE_FILES})
target_include_directories (salsa20 PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include)
