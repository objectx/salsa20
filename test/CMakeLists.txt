
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES main.cxx md5.cxx)

add_executable (test-salsa20 ${SOURCE_FILES})
target_link_libraries (test-salsa20 PRIVATE salsa20 cppformat)
target_compile_definitions (test-salsa20 PRIVATE "-DNOMINMAX")
target_compile_features (test-salsa20 PRIVATE cxx_auto_type cxx_uniform_initialization)
