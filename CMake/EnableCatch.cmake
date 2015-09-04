# Enables Catch
#
# Copyright (c) 2015 Masashi Fujita
#
message ("Enable Catch")
# Download Catch
if (NOT EXISTS "${CMAKE_BINARY_DIR}/include/catch")
    message ("Downloading catch/catch.hpp")
    file (MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/include/catch")
    file (DOWNLOAD
        "https://raw.githubusercontent.com/philsquared/Catch/master/single_include/catch.hpp"
        "${CMAKE_BINARY_DIR}/include/catch/catch.hpp")
endif ()

