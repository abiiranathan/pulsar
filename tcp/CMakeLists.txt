# ==============================================================================
# tcp — standalone high-performance Linux TCP primitives
#
# Buildable on its own:
#     cmake -S tcp -B tcp/build && cmake --build tcp/build
# or consumed from the pulsar build via add_subdirectory(tcp).
# ==============================================================================
cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(tcp
        VERSION     1.0.0
        DESCRIPTION "High-performance Linux TCP primitives"
        LANGUAGES   C
    )
    set(TCP_STANDALONE ON)
else()
    set(TCP_STANDALONE OFF)
endif()

set(CMAKE_C_STANDARD          11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        ON)

option(TCP_BUILD_SHARED "Build shared libtcp" ON)
option(TCP_BUILD_STATIC "Build static libtcp" ON)
option(TCP_BUILD_TESTS  "Build tcp tests"     ON)

# Reuse the parent's release flags when embedded in pulsar; otherwise define a
# sensible local default.
if(NOT DEFINED PULSAR_RELEASE_OPTS)
    set(PULSAR_RELEASE_OPTS -O3 -DNDEBUG -fomit-frame-pointer -fstrict-aliasing)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND PULSAR_RELEASE_OPTS -fno-plt -fno-semantic-interposition)
    endif()
endif()

set(TCP_SOURCES
    src/tcp_buffer.c
    src/tcp_socket.c
    src/tcp_connection.c
    src/tcp_client.c
)

add_library(tcp_objects OBJECT ${TCP_SOURCES})
set_target_properties(tcp_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(tcp_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_definitions(tcp_objects PUBLIC _GNU_SOURCE)

target_compile_options(tcp_objects PRIVATE
    $<$<CONFIG:Debug>:          -O0 -g3 -DDEBUG>
    $<$<CONFIG:Release>:        ${PULSAR_RELEASE_OPTS}>
    $<$<CONFIG:RelWithDebInfo>: ${PULSAR_RELEASE_OPTS} -g>
)

# ------------------------------------------------------------------------------
# Static / shared libraries
# ------------------------------------------------------------------------------

if(TCP_BUILD_STATIC)
    add_library(tcp_static STATIC $<TARGET_OBJECTS:tcp_objects>)
    set_target_properties(tcp_static PROPERTIES
        OUTPUT_NAME              tcp
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )
    target_include_directories(tcp_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
endif()

if(TCP_BUILD_SHARED)
    add_library(tcp_shared SHARED $<TARGET_OBJECTS:tcp_objects>)
    set_target_properties(tcp_shared PROPERTIES
        OUTPUT_NAME              tcp
        VERSION                  ${PROJECT_VERSION}
        SOVERSION                ${PROJECT_VERSION_MAJOR}
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )
    target_include_directories(tcp_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
endif()

if(TCP_BUILD_STATIC)
    add_library(tcp::tcp ALIAS tcp_static)
elseif(TCP_BUILD_SHARED)
    add_library(tcp::tcp ALIAS tcp_shared)
endif()

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

if(TCP_BUILD_TESTS)
    if(TCP_STANDALONE)
        include(CTest)
        enable_testing()
    endif()

    file(GLOB TCP_TEST_SOURCES "tests/*.c")
    foreach(TEST_FILE ${TCP_TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
        add_executable(${TEST_NAME} ${TEST_FILE})
        target_link_libraries(${TEST_NAME} PRIVATE tcp::tcp)
        target_compile_options(${TEST_NAME} PRIVATE
            $<$<CONFIG:Debug>:-O0 -g3 -DDEBUG>
            $<$<CONFIG:Release>:${PULSAR_RELEASE_OPTS}>
        )
        # Keep assert() live even in Release (the release flags define NDEBUG,
        # and the tests are the specification).
        target_compile_options(${TEST_NAME} PRIVATE -UNDEBUG)
        set_target_properties(${TEST_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        )
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endforeach()
endif()

# ------------------------------------------------------------------------------
# Examples
# ------------------------------------------------------------------------------

option(TCP_BUILD_EXAMPLES "Build tcp examples" ON)
if(TCP_BUILD_EXAMPLES)
    file(GLOB TCP_EXAMPLE_SOURCES "examples/*.c")
    foreach(EXAMPLE_FILE ${TCP_EXAMPLE_SOURCES})
        get_filename_component(EXAMPLE_NAME ${EXAMPLE_FILE} NAME_WE)
        add_executable(${EXAMPLE_NAME} ${EXAMPLE_FILE})
        target_link_libraries(${EXAMPLE_NAME} PRIVATE tcp::tcp)
        set_target_properties(${EXAMPLE_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
        )
    endforeach()
endif()

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(TCP_INSTALL_TARGETS)
if(TCP_BUILD_STATIC)
    list(APPEND TCP_INSTALL_TARGETS tcp_static)
endif()
if(TCP_BUILD_SHARED)
    list(APPEND TCP_INSTALL_TARGETS tcp_shared)
endif()

install(TARGETS ${TCP_INSTALL_TARGETS}
    EXPORT  TcpTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/tcp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/TcpConfigVersion.cmake"
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TcpConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TcpConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Tcp
)

install(EXPORT TcpTargets
    FILE      TcpTargets.cmake
    NAMESPACE Tcp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Tcp
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TcpConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/TcpConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Tcp
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/tcp.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/tcp.pc"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tcp.pc"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
