message(STATUS "Build for linux x86.")

set(CMAKE_STRIP_TOOL "strip")

if (ENABLE_ENGINE)
    add_definitions(-DENABLE_DRIVER)
    add_definitions(-DENABLE_CATARC_ENGINE)
endif ()

set(CMAKE_SYSTEM_NAME linux-x86_64)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -O0 -Wall -g -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -O0 -Wall -g -fPIC")