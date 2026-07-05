cmake_minimum_required(VERSION 3.10)
project(nexcrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Check if we are building via vcpkg (Windows CI setup)
if(DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
    find_package(libsodium CONFIG REQUIRED)
    set(SODIUM_LIBRARIES libsodium::libsodium)
    # vcpkg handles includes automatically, so we don't need explicit include_directories for it
else()
    # 2. Linux/macOS standard lookup using your reliable fallback logic
    find_package(PkgConfig QUIET)

    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM_OK libsodium QUIET)
    endif()

    if(DEFINED SODIUM_OK_FOUND AND SODIUM_OK_FOUND)
        set(SODIUM_INCLUDE_DIRS ${SODIUM_OK_INCLUDE_DIRS})
        set(SODIUM_LIBRARIES ${SODIUM_OK_LIBRARIES})
    else()
        find_path(SODIUM_INCLUDE_DIR sodium.h)
        find_library(SODIUM_LIBRARY NAMES sodium libsodium)

        if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
            message(FATAL_ERROR "libsodium not found. Install pkg-config and libsodium-dev.")
        endif()

        set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
        set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
    endif()
    
    include_directories(${SODIUM_INCLUDE_DIRS})
endif()

# Include local source files path
include_directories(src)

set(SRC_FILES
    ${PROJECT_SOURCE_DIR}/main.cpp
    ${PROJECT_SOURCE_DIR}/src/app/encryptDecrypt/Cryption.cpp
    ${PROJECT_SOURCE_DIR}/src/app/fileHandling/IO.cpp
    ${PROJECT_SOURCE_DIR}/src/app/processes/ProcessManagement.cpp
)

add_executable(nexcrypt ${SRC_FILES})
target_link_libraries(nexcrypt PRIVATE ${SODIUM_LIBRARIES})

install(TARGETS nexcrypt DESTINATION bin)