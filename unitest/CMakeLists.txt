cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)
## Use -std=c++11 as default.
set(CMAKE_CXX_STANDARD 11)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(runTests CXX)

# GOOGLE TEST
# add_custom_target(googletest_external)
# add_subdirectory(googletest)

get_target_property(
        GOOGLETEST_IMPORTED_LOCATION_LIBS
        googletest_external
        IMPORTED_LOCATION_LIBS)

get_target_property(
        GOOGLETEST_INTERFACE_INCLUDE_DIRECTORIES
        googletest_external
        INTERFACE_INCLUDE_DIRECTORIES)

include_directories(runTests ${GOOGLETEST_INTERFACE_INCLUDE_DIRECTORIES})

# SVKD LIBRARY
include_directories(${CYBERLIB_INCLUDE_DIR})

# GTEST CPP
file(GLOB GTEST_SRCS
        "${CYBERLIB_UNITEST_DIR}/*.cpp")

add_executable(runTests main.cpp ${GTEST_SRCS})
add_dependencies(runTests googletest_external)

set(CMAKE_INSTALL_RPATH  "${CYBERLIB_BINARY_DIR}")

target_link_libraries(runTests PRIVATE
        ${GOOGLETEST_IMPORTED_LOCATION_LIBS}
        cyber)

if(NOT ANDROID)
    target_link_libraries(runTests PRIVATE
            -lpthread)
endif()
