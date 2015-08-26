
cmake_minimum_required (VERSION 3.3)

set (CONSTANT_TABLE ${CMAKE_CURRENT_BINARY_DIR}/salsa20_const.cxx)

set (SOURCE_FILES salsa20.cxx ${CONSTANT_TABLE})

add_custom_command (OUTPUT ${CONSTANT_TABLE}
    COMMENT "Create obfuscated constant table"
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/constgen.py --obfuscate-mask 0xABADCAFE -o ${CONSTANT_TABLE}
    DEPENDS constgen.py)

add_library (salsa20 ${SOURCE_FILES})
target_include_directories (salsa20 PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include)
