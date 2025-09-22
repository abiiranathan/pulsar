cmake_minimum_required(VERSION 3.20)

project(pulsar
    VERSION 1.0.0
    DESCRIPTION "Pulsar web server library"
    LANGUAGES C
)

# Set C standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Enable testing support
include(CTest)
enable_testing()

# Build type handling
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Build mode options
option(ENABLE_PGO "Enable Profile-Guided Optimization" OFF)
option(ENABLE_NATIVE_OPTIMIZATION "Enable native optimization flags (-march=native etc.)" ON)
option(ENABLE_UNIVERSAL_BINARY "Build fat binary for macOS (x86_64+arm64)" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_STATIC_LIBS "Build static libraries" ON)
option(BUILD_TESTS "Build test executables" ON)
option(INSTALL_HEADERS "Install header files" ON)

# Platform detection
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_MACOS TRUE)
    set(LIB_EXTENSION "dylib")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_LINUX TRUE)
    set(LIB_EXTENSION "so")
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

# macOS universal binary
if(APPLE AND ENABLE_UNIVERSAL_BINARY AND NOT DEFINED CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "" FORCE)
endif()

# Find solidc dependency
find_package(solidc REQUIRED)

# Compiler definitions
add_compile_definitions(
    DA_IMPLEMENTATION
    _GNU_SOURCE
)

# Base compiler flags
set(BASE_C_FLAGS
    -Wall -Werror -Wextra -pedantic -fPIC
    -Wno-unused-function -Wno-unused-result -Wno-gnu-zero-variadic-macro-arguments
    -std=c2x
)

if(ENABLE_NATIVE_OPTIMIZATION AND PLATFORM_LINUX)
    set(NATIVE_FLAGS "-mtune=native -march=native -mavx2")
endif()

# Build-type-specific flags
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 ${NATIVE_FLAGS} -flto")
set(CMAKE_C_FLAGS_PROFILE "-O3 ${NATIVE_FLAGS} -flto -fprofile-generate")

# Apply base flags to all configs
add_compile_options(${BASE_C_FLAGS})

# PGO support
if(ENABLE_PGO AND CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-fprofile-use -fprofile-correction)
    add_link_options(-lgcov)
endif()

# Source and header files
set(BASE_SOURCES
    src/forms.c
    src/locals.c
    src/pulsar.c
    src/routing.c
)

file(GLOB HEADERS "include/*.h")

# Create object library
add_library(pulsar_objects OBJECT ${BASE_SOURCES})

target_include_directories(pulsar_objects PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Static library
if(BUILD_STATIC_LIBS)
    add_library(pulsar_static STATIC $<TARGET_OBJECTS:pulsar_objects>)
    set_target_properties(pulsar_static PROPERTIES
        OUTPUT_NAME pulsar
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
    target_link_libraries(pulsar_static PUBLIC solidc::solidc)
endif()

# Shared library
if(BUILD_SHARED_LIBS)
    add_library(pulsar_shared SHARED $<TARGET_OBJECTS:pulsar_objects>)
    set_target_properties(pulsar_shared PROPERTIES
        OUTPUT_NAME pulsar
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
    target_link_libraries(pulsar_shared PUBLIC pthread solidc::solidc)

    if(ENABLE_PGO AND CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_libraries(pulsar_shared PRIVATE gcov)
    endif()
endif()

# Main executable
add_executable(server main.c)
target_link_libraries(server PRIVATE pulsar_objects pthread solidc::solidc)
set_target_properties(server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Tests
if(BUILD_TESTS)
    file(GLOB TEST_SOURCES "tests/*.c")
    foreach(test_source ${TEST_SOURCES})
        get_filename_component(test_name ${test_source} NAME_WE)
        add_executable(test_${test_name} ${test_source})
        target_link_libraries(test_${test_name} PRIVATE pulsar_objects pthread solidc::solidc)
        set_target_properties(test_${test_name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
        )
        add_test(NAME ${test_name} COMMAND test_${test_name})
        set_tests_properties(${test_name} PROPERTIES
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
        )
    endforeach()
endif()

# Valgrind check
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/glibc.supp")
        add_custom_target(check
            COMMAND ${VALGRIND_EXECUTABLE} --leak-check=full --show-leak-kinds=all 
                    --suppressions=${CMAKE_CURRENT_SOURCE_DIR}/glibc.supp 
                    ${CMAKE_BINARY_DIR}/bin/server
            DEPENDS server
            COMMENT "Running valgrind memory check with suppressions"
        )
    else()
        add_custom_target(check
            COMMAND ${VALGRIND_EXECUTABLE} --leak-check=full --show-leak-kinds=all 
                    ${CMAKE_BINARY_DIR}/bin/server
            DEPENDS server
            COMMENT "Running valgrind memory check (no suppressions)"
        )
    endif()
endif()

# Profile target
add_custom_target(profile
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Profile ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
    COMMENT "Building with profiling enabled"
)

# Install headers and libraries
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(BUILD_STATIC_LIBS)
    install(TARGETS pulsar_static
        EXPORT PulsarTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT Development
    )
endif()

if(BUILD_SHARED_LIBS)
    install(TARGETS pulsar_shared
        EXPORT PulsarTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
    )
endif()

if(INSTALL_HEADERS)
    install(FILES ${HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pulsar
        COMPONENT Development
    )
endif()

# Package config files
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PulsarConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Pulsar
)

install(EXPORT PulsarTargets
    FILE PulsarTargets.cmake
    NAMESPACE Pulsar::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Pulsar
    COMPONENT Development
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/PulsarConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Pulsar
    COMPONENT Development
)

# pkg-config support
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pulsar.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/pulsar.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pulsar.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    COMPONENT Development
)

# Linux-specific: update linker cache
if(PLATFORM_LINUX)
    install(CODE "execute_process(COMMAND ldconfig)")
endif()

# Packaging
set(CPACK_PACKAGE_NAME "pulsar")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Pulsar web server library")
set(CPACK_PACKAGE_VENDOR "Your Organization")
set(CPACK_PACKAGE_CONTACT "your-email@example.com")

if(PLATFORM_LINUX)
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.17)")
    set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.17")
elseif(PLATFORM_MACOS)
    set(CPACK_GENERATOR "TGZ;ZIP")
endif()

include(CPack)

# Print configuration summary
message(STATUS "=== Pulsar Build Configuration ===")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Build Shared: ${BUILD_SHARED_LIBS}")
message(STATUS "Build Static: ${BUILD_STATIC_LIBS}")
message(STATUS "Build Tests: ${BUILD_TESTS}")
message(STATUS "PGO Enabled: ${ENABLE_PGO}")
message(STATUS "Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "===================================")
