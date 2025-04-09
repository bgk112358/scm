cmake_minimum_required(VERSION 3.16)

project(dbobject)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set(HAVE_OBJECTSTORE_BACKEND_DB 1)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/pkcs11)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/datamgr)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/slotmgr)
include_directories(${SQLITE3_INCLUDE_DIRS})

set(SOURCE_COMMON
        ${CMAKE_CURRENT_SOURCE_DIR}/common/log.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/common/Directory.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/common/MutexFactory.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/common/osmutex.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/common/UUID.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/common/Configuration.cpp
)

set(SOURCE_PKCS11
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11/P11Attributes.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11/P11Objects.cpp
)

set(DATAMGR_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/datamgr/ByteString.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/datamgr/SecureMemoryRegistry.cpp
)

set(SLOTMGR_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/slotmgr/SlotManager.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/slotmgr/Token.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/slotmgr/Slot.cpp
)

set(SOURCE_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/DB.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/DBObject.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/DBToken.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ObjectStore.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ObjectStoreToken.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/OSAttribute.cpp
)

# message("SOURCE_COMMON = ${SOURCE_COMMON}")
# message("SOURCE_FILES = ${SOURCE_FILES}")
# message("DATAMGR_FILES = ${DATAMGR_FILES}")

# Build Modules Path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules
                      )

# Custom Modules
include(FindSQLite3)

# target_link_libraries(${PROJECT_NAME} ${SQLITE3_LIBRARIES})
LINK_LIBRARIES(${SQLITE3_LIBRARIES})

# ADD_LIBRARY(${PROJECT_NAME} SHARED ${SOURCE_COMMON} ${DATAMGR_FILES} ${SOURCE_FILES})
ADD_EXECUTABLE(${PROJECT_NAME} main.cpp ${SOURCE_PKCS11} ${DATAMGR_FILES} ${SLOTMGR_FILES} ${SOURCE_COMMON} ${SOURCE_FILES})
