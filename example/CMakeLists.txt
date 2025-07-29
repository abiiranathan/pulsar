cmake_minimum_required(VERSION 3.20)

project(pulsar VERSION 1.0.0 DESCRIPTION "Pulsar web server library" LANGUAGES C)

find_package(Pulsar REQUIRED)

add_executable(server server.c)
target_link_libraries(server PRIVATE Pulsar::pulsar_shared)
