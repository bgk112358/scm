cmake_minimum_required(VERSION 3.14)
project(cyberlib_build LANGUAGES C CXX)

set(CMAKE_C_STANDARD   99)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE   "Release")
set(CMAKE_VERBOSE_MAKEFILE ON)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS   OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------- Compile parameter ----------------------------
option(BUILD_SHARED           "Build as shared library"                  ON)
option(ENABLE_GOOGLE_TEST     "Enable unit test using GoogleTest"        OFF)
option(ENABLE_SANITIZE        "Whether support sanitize"                 OFF)
option(ENABLE_ENGINE          "Enable USE ENGINE"                        OFF)

# ---------------------------- Folder Definitions ----------------------------
# Location of the dependencies
set(CYBERLIB_DEPENDENCIES_DIR "${PROJECT_SOURCE_DIR}/dependencies")
# Location of the header files
set(CYBERLIB_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
# Location of the source files
set(CYBERLIB_SOURCE_DIR  "${PROJECT_SOURCE_DIR}/src")
# Location of the binary files
set(CYBERLIB_BINARY_DIR  "${CMAKE_BINARY_DIR}/lib")
# Location of the google tests
set(CYBERLIB_UNITEST_DIR   "${PROJECT_SOURCE_DIR}/unitest")

include(GNUInstallDirs)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/lib)
# ---------------------------- Parameter Configure ----------------------------
# Google Test
if (ENABLE_GOOGLE_TEST)
    message(STATUS "Build unitest target.")
    add_subdirectory(${CYBERLIB_UNITEST_DIR})
endif (ENABLE_GOOGLE_TEST)

# Sanitize
if (ENABLE_SANITIZE)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -fvisibility=hidden -Wl,-Bsymbolic -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -Wl,-Bsymbolic -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=leak -fsanitize-recover=all -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope")
endif ()

# ------------------------------ Common Config ------------------------------
if (BUILD_SHARED)
SET(CMAKE_C_FLAGS   "-O2 -fPIC -g -pipe -Wl,-Bsymbolic-functions")
SET(CMAKE_CXX_FLAGS "-O2 -fPIC -g -pipe -Wl,-Bsymbolic-functions")
else ()
#SET(CMAKE_C_FLAGS   "-O2 -fPIC -g -pipe -Wl,-Bstatic")
#SET(CMAKE_CXX_FLAGS "-O2 -fPIC -g -pipe -Wl,-Bstatic")
SET(CMAKE_C_FLAGS   "-O2 -fPIC -g -fvisibility=default")
SET(CMAKE_CXX_FLAGS "-O2 -fPIC -g -fvisibility=default")
endif()

# ------------------------------ Build Project ------------------------------
if (BUILD_LIB_OTHER)
else ()
    include(${CMAKE_CURRENT_SOURCE_DIR}/toolchain/linux/Linux_x86.cmake)
endif ()

add_subdirectory(dependencies)
add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(unitest)