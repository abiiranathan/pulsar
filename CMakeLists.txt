cmake_minimum_required(VERSION 3.20)

project(pulsar
    VERSION     1.0.0
    DESCRIPTION "Pulsar web server library"
    LANGUAGES   C
)

# ------------------------------------------------------------------------------
# Global settings
# ------------------------------------------------------------------------------

set(CMAKE_C_STANDARD          11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        ON)

include(CTest)
enable_testing()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------

option(BUILD_SHARED_LIBS          "Build shared library"              ON)
option(BUILD_STATIC_LIBS          "Build static library"              ON)
option(BUILD_TESTS                "Build tests"                       ON)
option(ENABLE_NATIVE_OPTIMIZATION "Enable CPU-specific optimizations" ON)
option(ENABLE_UNIVERSAL_BINARY    "Build universal macOS binaries"    ON)

# ------------------------------------------------------------------------------
# Platform detection
# ------------------------------------------------------------------------------

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_LINUX TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_MACOS TRUE)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

if(APPLE AND ENABLE_UNIVERSAL_BINARY AND NOT DEFINED CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "" FORCE)
endif()

# ------------------------------------------------------------------------------
# Link-Time Optimization (LTO / IPO)
# ------------------------------------------------------------------------------

cmake_policy(SET CMP0069 NEW)
include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)

if(IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    message(STATUS "Link-Time Optimization (LTO): ENABLED for Release")
else()
    message(WARNING "Link-Time Optimization (LTO) NOT supported: ${IPO_ERROR}")
endif()

# ------------------------------------------------------------------------------
# Release Optimization Compiler Flags
# ------------------------------------------------------------------------------

set(PULSAR_RELEASE_OPTS
    -O3
    -DNDEBUG
    -fomit-frame-pointer
    -fstrict-aliasing
)

if(PLATFORM_LINUX)
    list(APPEND PULSAR_RELEASE_OPTS
        -fno-plt                     # Eliminates PLT stubs for libc calls
        -fno-semantic-interposition  # Enables direct symbol resolution across files
    )
endif()

# Architecture-specific vectorization (AVX2 / BMI2 / Popcnt)
if(ENABLE_NATIVE_OPTIMIZATION)
    if(APPLE AND ENABLE_UNIVERSAL_BINARY)
        # Avoid -march=native when cross-compiling universal binaries
        message(STATUS "Native optimization skipped for Universal macOS build")
    else()
        list(APPEND PULSAR_RELEASE_OPTS -march=native -mtune=native)
    endif()
endif()

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

find_package(solidc CONFIG REQUIRED)

# Diagnostic while stabilizing CI
get_target_property(SOLIDC_INCLUDE_DIRS solidc::solidc INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "SOLIDC_INCLUDE_DIRS=${SOLIDC_INCLUDE_DIRS}")

add_compile_options(
    -Wall -Wextra -Werror
    -Wno-unused-function
    -Wno-unused-result
)

set(PULSAR_SOURCES
    src/forms.c
    src/pulsar.c
    src/routing.c
)

file(GLOB PULSAR_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

# ------------------------------------------------------------------------------
# Object library
# ------------------------------------------------------------------------------

add_library(pulsar_objects OBJECT ${PULSAR_SOURCES})

target_include_directories(pulsar_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/pulsar>
)

target_compile_definitions(pulsar_objects
    PUBLIC _GNU_SOURCE
)

target_compile_options(pulsar_objects PRIVATE
    $<$<CONFIG:Debug>:          -O0 -g3 -DDEBUG>
    $<$<CONFIG:Release>:        ${PULSAR_RELEASE_OPTS}>
    $<$<CONFIG:RelWithDebInfo>: -O2 -g>
)

target_link_libraries(pulsar_objects PUBLIC solidc::solidc)

# ------------------------------------------------------------------------------
# Static library
# ------------------------------------------------------------------------------

if(BUILD_STATIC_LIBS)
    add_library(pulsar_static STATIC $<TARGET_OBJECTS:pulsar_objects>)

    set_target_properties(pulsar_static PROPERTIES
        OUTPUT_NAME              pulsar
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )

    target_link_libraries(pulsar_static PUBLIC solidc::solidc)
endif()

# ------------------------------------------------------------------------------
# Shared library
# ------------------------------------------------------------------------------

if(BUILD_SHARED_LIBS)
    add_library(pulsar_shared SHARED $<TARGET_OBJECTS:pulsar_objects>)
    target_compile_options(pulsar_shared PRIVATE -fPIC -Wl,-z,defs)

    set_target_properties(pulsar_shared PROPERTIES
        OUTPUT_NAME              pulsar
        VERSION                  ${PROJECT_VERSION}
        SOVERSION                ${PROJECT_VERSION_MAJOR}
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )

    target_link_libraries(pulsar_shared PUBLIC solidc::solidc)
endif()

# ------------------------------------------------------------------------------
# Server executable
# ------------------------------------------------------------------------------

add_executable(server main.c)

target_compile_options(server PRIVATE
    $<$<CONFIG:Release>:${PULSAR_RELEASE_OPTS}>
)

if(PLATFORM_LINUX)
    target_link_options(server PRIVATE
        $<$<CONFIG:Release>:
            -Wl,-O1
            -Wl,--as-needed
            -Wl,-z,relro,-z,now # Full RELRO: resolves all GOT symbols at startup
        >
    )
endif()

target_link_libraries(server PRIVATE pulsar_objects)

set_target_properties(server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

if(BUILD_TESTS)
    file(GLOB TEST_SOURCES "tests/*.c")

    foreach(TEST_FILE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)

        add_executable(test_${TEST_NAME} ${TEST_FILE})

        target_link_libraries(test_${TEST_NAME} PRIVATE pulsar_objects)

        set_target_properties(test_${TEST_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        )

        add_test(NAME ${TEST_NAME} COMMAND test_${TEST_NAME})
    endforeach()
endif()

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(BUILD_STATIC_LIBS)
    install(TARGETS pulsar_static
        EXPORT  PulsarTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(BUILD_SHARED_LIBS)
    install(TARGETS pulsar_shared
        EXPORT  PulsarTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

install(FILES ${PULSAR_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pulsar
)

# ------------------------------------------------------------------------------
# Package export
# ------------------------------------------------------------------------------

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfigVersion.cmake"
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PulsarConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Pulsar
)

install(EXPORT PulsarTargets
    FILE      PulsarTargets.cmake
    NAMESPACE Pulsar::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Pulsar
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Pulsar
)

# ------------------------------------------------------------------------------
# pkg-config
# ------------------------------------------------------------------------------

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pulsar.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/pulsar.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pulsar.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
message(STATUS "")
message(STATUS "=== Pulsar Configuration ===")
message(STATUS "  Build Type     : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler       : ${CMAKE_C_COMPILER}")
message(STATUS "  System         : ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Architecture   : ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  Static lib     : ${BUILD_STATIC_LIBS}")
message(STATUS "  Shared lib     : ${BUILD_SHARED_LIBS}")
message(STATUS "  Tests          : ${BUILD_TESTS}")
message(STATUS "  Native opt     : ${ENABLE_NATIVE_OPTIMIZATION}")
message(STATUS "  LTO enabled    : ${IPO_SUPPORTED}")
message(STATUS "============================")
message(STATUS "")
