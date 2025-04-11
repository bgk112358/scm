
## Define standard installation directories (GNU)
#include(GNUInstallDirs)
#
## Set default output folder
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
#        "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
#        "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
#        "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}")

file(STRINGS "../src/VERSION" LIB_VERSION)

include_directories(include)
include_directories(include/openssl)

include_directories(${CYBERLIB_INCLUDE_DIR})
set(CMAKE_INSTALL_RPATH "${CYBERLIB_BINARY_DIR}")

# SM2
add_executable(cyber_test_sm2 cyber_test_sm2.c)
target_link_libraries(cyber_test_sm2 cyber
        -Wl,-Bdynamic
        pthread
        dl)

# SM9
add_executable(cyber_test_sm9 cyber_test_sm9.c)
target_link_libraries(cyber_test_sm9 cyber
        -Wl,-Bdynamic
        pthread
        dl)

# CLPKC 
add_executable(cyber_test_clpkc cyber_test_clpkc.c)
target_link_libraries(cyber_test_clpkc cyber
        -Wl,-Bdynamic
        pthread
        dl)
