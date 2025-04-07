add_custom_target(engine_external ALL)

## PROJECT TARGET
if (ENABLE_ENGINE)
    message(STATUS "Build engine for Cyber.")
    file(GLOB ENGINE_DEPENDENCIES_SRC
            "${CMAKE_CURRENT_SOURCE_DIR}/cyber/*.c*")
    set(ENGINE_DEPENDENCIES_IMPORTED_LIBS
            "")
else ()
    message(STATUS "Build engine for Empty.")
    file(GLOB ENGINE_DEPENDENCIES_SRC)
    set(ENGINE_DEPENDENCIES_IMPORTED_LIBS
            "")
endif ()

if (PACKAGE_BUILD)
# Openssl
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

# PLog
get_target_property(
        PLOG_INCLUDE_DIR
        plog_external
        INTERFACE_INCLUDE_DIRECTORIES)
else()
message(STATUS "OPENSSL_INCLUDE_DIR is ${OPENSSL_INCLUDE_DIR}")
message(STATUS "PLOG_INCLUDE_DIR is ${PLOG_INCLUDE_DIR}")

endif()

include_directories(
        ${OPENSSL_INCLUDE_DIR}
        ${PLOG_INCLUDE_DIR}
        "${CYBERLIB_SOURCE_DIR}/drivers"
        "${CYBERLIB_SOURCE_DIR}/util")

file(GLOB ENGINE_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/*.c*")

add_library(cyber_engine STATIC ${ENGINE_DEPENDENCIES_SRC} ${ENGINE_SOURCES})

if (PACKAGE_BUILD)
add_dependencies(cyber_engine openssl_external)
endif()

add_dependencies(engine_external cyber_engine)
target_link_libraries(cyber_engine
        ${ENGINE_DEPENDENCIES_IMPORTED_LIBS}
        ${OPENSSL_IMPORTED_LIBS})

set_target_properties(cyber_engine PROPERTIES POSITION_INDEPENDENT_CODE True)

# Add include dirs and library path as properties of drivers_external imported
set_target_properties(
        engine_external
        PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}"
        IMPORTED_LOCATION_LIBS
        "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}/libcyber_engine${CMAKE_STATIC_LIBRARY_SUFFIX};${ENGINE_DEPENDENCIES_IMPORTED_LIBS}"
        )