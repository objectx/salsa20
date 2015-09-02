
cmake_minimum_required (VERSION 3.3)

set (SOURCE_FILES main.cxx md5.cxx)

set (TARGET_NAME "test-salsa20")
add_executable (${TARGET_NAME} ${SOURCE_FILES})
    target_link_libraries      (${TARGET_NAME} PRIVATE salsa20 cppformat)
    target_compile_definitions (${TARGET_NAME} PRIVATE "-DNOMINMAX")
    target_compile_features    (${TARGET_NAME} PRIVATE cxx_auto_type cxx_uniform_initialization)
    target_include_directories (${TARGET_NAME} PRIVATE ${CMAKE_BINARY_DIR}/include)
