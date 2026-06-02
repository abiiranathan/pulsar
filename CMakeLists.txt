cmake_minimum_required(VERSION 3.30)

project(
    pulsar
    VERSION 1.0.0
    DESCRIPTION "Pulsar web server library"
    LANGUAGES C
)

# ==============================================================================
# Language Configuration
# ==============================================================================

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

include(CTest)
enable_testing()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ==============================================================================
# Build Options
# ==============================================================================

option(ENABLE_PGO "Enable Profile-Guided Optimization" OFF)
option(ENABLE_NATIVE_OPTIMIZATION "Enable native optimization flags" ON)
option(ENABLE_UNIVERSAL_BINARY "Build universal macOS binaries" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_STATIC_LIBS "Build static library" ON)
option(BUILD_TESTS "Build tests" ON)
option(INSTALL_HEADERS "Install headers" ON)

# ==============================================================================
# Platform Detection
# ==============================================================================

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_MACOS TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_LINUX TRUE)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

if(APPLE AND ENABLE_UNIVERSAL_BINARY AND NOT DEFINED CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "" FORCE)
endif()

# ==============================================================================
# Dependencies
# ==============================================================================

find_package(solidc CONFIG REQUIRED)

# Temporary CI diagnostic
get_target_property(
    SOLIDC_INCLUDE_DIRS
    solidc::solidc
    INTERFACE_INCLUDE_DIRECTORIES
)

message(STATUS "SOLIDC_INCLUDE_DIRS=${SOLIDC_INCLUDE_DIRS}")

# ==============================================================================
# Compiler Flags
# ==============================================================================

if(ENABLE_NATIVE_OPTIMIZATION AND PLATFORM_LINUX)
    set(NATIVE_FLAGS
        -mtune=native
        -march=native
        -mavx2
    )
endif()

add_compile_options(
    -Wall
    -Wextra
    -Werror
    -pedantic
    -fPIC
    -Wno-unused-function
    -Wno-unused-result
    -Wno-gnu-zero-variadic-macro-arguments
)

set(CMAKE_C_FLAGS_DEBUG
    "-O0 -g3 -DDEBUG"
)

set(CMAKE_C_FLAGS_RELEASE
    "-O3 ${NATIVE_FLAGS} -flto"
)

set(CMAKE_C_FLAGS_PROFILE
    "-O3 ${NATIVE_FLAGS} -flto -fprofile-generate"
)

if(ENABLE_PGO AND CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -fprofile-use
        -fprofile-correction
    )

    add_link_options(
        -lgcov
    )
endif()

# ==============================================================================
# Sources
# ==============================================================================

set(BASE_SOURCES
    src/forms.c
    src/locals.c
    src/pulsar.c
    src/routing.c
)

if(PLATFORM_LINUX)
    list(APPEND BASE_SOURCES
        src/events/epoll.c
    )
elseif(PLATFORM_MACOS)
    list(APPEND BASE_SOURCES
        src/events/kqueue.c
    )
endif()

file(GLOB HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
)

# ==============================================================================
# Object Library
# ==============================================================================

add_library(pulsar_objects OBJECT
    ${BASE_SOURCES}
)

target_include_directories(pulsar_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_definitions(pulsar_objects
    PUBLIC
        DA_IMPLEMENTATION
        _GNU_SOURCE
)

#
# IMPORTANT:
# This is the fix that CI needs.
#
target_link_libraries(pulsar_objects
    PUBLIC
        solidc::solidc
)

# ==============================================================================
# Static Library
# ==============================================================================

if(BUILD_STATIC_LIBS)

    add_library(pulsar_static STATIC
        $<TARGET_OBJECTS:pulsar_objects>
    )

    set_target_properties(pulsar_static PROPERTIES
        OUTPUT_NAME pulsar
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )

    target_link_libraries(pulsar_static
        PUBLIC
            solidc::solidc
    )

endif()

# ==============================================================================
# Shared Library
# ==============================================================================

if(BUILD_SHARED_LIBS)

    add_library(pulsar_shared SHARED
        $<TARGET_OBJECTS:pulsar_objects>
    )

    set_target_properties(pulsar_shared PROPERTIES
        OUTPUT_NAME pulsar
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )

    target_link_libraries(pulsar_shared
        PUBLIC
            solidc::solidc
    )

    if(ENABLE_PGO AND CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_libraries(
            pulsar_shared
            PRIVATE
            gcov
        )
    endif()

endif()

# ==============================================================================
# Main Executable
# ==============================================================================

add_executable(server
    main.c
)

target_link_libraries(server
    PRIVATE
        pulsar_objects
)

set_target_properties(server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ==============================================================================
# Tests
# ==============================================================================

if(BUILD_TESTS)

    file(GLOB TEST_SOURCES
        "tests/*.c"
    )

    foreach(test_source ${TEST_SOURCES})

        get_filename_component(
            test_name
            ${test_source}
            NAME_WE
        )

        add_executable(
            test_${test_name}
            ${test_source}
        )

        target_link_libraries(
            test_${test_name}
            PRIVATE
                pulsar_objects
        )

        set_target_properties(
            test_${test_name}
            PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY
            ${CMAKE_BINARY_DIR}/tests
        )

        add_test(
            NAME ${test_name}
            COMMAND test_${test_name}
        )

    endforeach()

endif()
