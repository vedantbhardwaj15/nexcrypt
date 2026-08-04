cmake_minimum_required(VERSION 3.10)
project(nexcrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Release build if not explicitly specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Threading support
find_package(Threads REQUIRED)

# 1. Check if we are building via vcpkg (Windows CI setup)
if(DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
    find_package(unofficial-sodium CONFIG REQUIRED)
    set(SODIUM_LIBRARIES unofficial-sodium::sodium)
else()
    # 2. Linux standard lookup
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
    ${PROJECT_SOURCE_DIR}/src/app/processes/ProgressReporter.cpp
)

add_executable(nexcrypt ${SRC_FILES})

# Enable Link-Time Optimization (LTO / IPO) for Release builds when supported
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
    if(ipo_supported)
        set_target_properties(nexcrypt PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# MSVC windows.h defines max/min macros that break std::numeric_limits
if(MSVC)
    target_compile_definitions(nexcrypt PRIVATE NOMINMAX)
endif()

target_link_libraries(nexcrypt PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)

install(TARGETS nexcrypt DESTINATION bin)