include(ExternalProject)

set(PLOG_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../download/plog-1.1.10")

set_target_properties(
        plog_external
        PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES
        "${PLOG_SOURCE_DIR}/include"
        )