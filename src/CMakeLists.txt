# PROJECT VERSION
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" PROJECT_VERSION LIMIT_COUNT 1)
    string(STRIP "${PROJECT_VERSION}" PROJECT_VERSION)
    message(STATUS "Project Version: v${PROJECT_VERSION}")
else()
    message(FATAL_ERROR "File ${CMAKE_CURRENT_SOURCE_DIR}/VERSION not found")
endif()

configure_file("${CYBERLIB_SOURCE_DIR}/common/version.in.h"
               "${CYBERLIB_SOURCE_DIR}/common/version.h" @ONLY)

get_target_property(
        PLOG_INCLUDE_DIR
        plog_external
        INTERFACE_INCLUDE_DIRECTORIES)

# Openssl
get_target_property(
        OPENSSL_INSTALL_DIR
        openssl_external
        INSTALL_DIRECTORIES
)
get_target_property(
        OPENSSL_INCLUDE_DIR
        openssl_external
        INTERFACE_INCLUDE_DIRECTORIES
)
get_target_property(
        OPENSSL_IMPORTED_LIBS
        openssl_external
        IMPORTED_LOCATION_LIBS
)

message(STATUS "OPENSSL INCLUDE DIR ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL IMPORTED LIBS: ${OPENSSL_IMPORTED_LIBS}")

file(GLOB CYBERLIB_SRCS
        "${CYBERLIB_SOURCE_DIR}/common/*.c*"
        "${CYBERLIB_SOURCE_DIR}/container/*.c*"
        "${CYBERLIB_SOURCE_DIR}/crypto/*.cpp"
        "${CYBERLIB_SOURCE_DIR}/crypto/*/*.cpp"
        "${CYBERLIB_SOURCE_DIR}/crypto/sm9/*.c*"
        "${CYBERLIB_SOURCE_DIR}/crypto/clpkc/*.c*"
        "${CYBERLIB_SOURCE_DIR}/external/*.c*"
        "${CYBERLIB_SOURCE_DIR}/handle/*.cpp"
        "${CYBERLIB_SOURCE_DIR}/storage/*.cpp"
        "${CYBERLIB_SOURCE_DIR}/util/*.cpp"
        "${CYBERLIB_SOURCE_DIR}/x509/*.cpp"
        "${CYBERLIB_SOURCE_DIR}/cyber_extend.c"
        "${CYBERLIB_SOURCE_DIR}/cyber_pki.c"
        "${CYBERLIB_SOURCE_DIR}/cyber_sm9.c"
        "${CYBERLIB_SOURCE_DIR}/cyber_clpkc.c"
        "${CYBERLIB_SOURCE_DIR}/cyber_secoc.c"
        "${CYBERLIB_SOURCE_DIR}/cyber_tls.c")

if (BUILD_SHARED)
    add_library(cyber SHARED ${CYBERLIB_SRCS})
else () #(BUILD_STATIC)
    add_library(cyber STATIC ${CYBERLIB_SRCS})
endif (BUILD_SHARED)

add_dependencies(cyber plog_external)
add_dependencies(cyber openssl_external)

# Set lib`s properties.
# POSITION_INDEPENDENT_CODE (-fPIC)
set_target_properties(cyber PROPERTIES POSITION_INDEPENDENT_CODE True)

# LINKER_LANGUAGE (language)
set_target_properties(cyber PROPERTIES LINKER_LANGUAGE CXX)

include_directories(${OPENSSL_INCLUDE_DIR})

# LINKER_INCLUDE_DIRECTORY
add_dependencies(cyber engine_external)
add_subdirectory(engine)
get_target_property(
        ENGINE_INCLUDE_DIR
        engine_external
        INTERFACE_INCLUDE_DIRECTORIES
)
get_target_property(
        ENGINE_IMPORTED_LIBS
        engine_external
        IMPORTED_LOCATION_LIBS
)


message(STATUS "Plog include dir: ${PLOG_INCLUDE_DIR}")

target_include_directories(cyber PRIVATE
        ${PLOG_INCLUDE_DIR}
        ${CURL_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${CYBERLIB_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${ENGINE_INCLUDE_DIR}
        ${CYBERLIB_SOURCE_DIR})

target_link_libraries(cyber PRIVATE
        ${CURL_IMPORTED_LIBS}
        ${OPENSSL_IMPORTED_LIBS}
        ${ENGINE_IMPORTED_LIBS}
        )
if(NOT ANDROID)
    target_link_libraries(cyber PRIVATE
            -lpthread
            -ldl
            )
endif()

# Strip svkdlib
if (BUILD_SHARED)
    #set(TARGET_LIB_PATH ${CMAKE_BINARY_DIR}/src/${CMAKE_SHARED_LIBRARY_PREFIX}cyber${CMAKE_SHARED_LIBRARY_SUFFIX})
    if(BUILD_TARGET_DIR_LINUX_ENV)
         set(TARGET_LIB_PATH ${TARGET_OUT_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}cyber${CMAKE_SHARED_LIBRARY_SUFFIX})
    else()
         set(TARGET_LIB_PATH ${CMAKE_BINARY_DIR}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}cyber${CMAKE_SHARED_LIBRARY_SUFFIX})
    endif()

else ()
    set(TARGET_LIB_PATH ${CMAKE_BINARY_DIR}/src/${CMAKE_STATIC_LIBRARY_PREFIX}cyber${CMAKE_STATIC_LIBRARY_SUFFIX})
endif (BUILD_SHARED)


message(STATUS "CMAKE_STRIP_TOOL: ${CMAKE_STRIP_TOOL}")

#add_custom_command(TARGET cyber POST_BUILD
#        COMMAND ${CMAKE_STRIP_TOOL} ${TARGET_LIB_PATH}
#        COMMENT "Stripping library")

add_subdirectory(store)