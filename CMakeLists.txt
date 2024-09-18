# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

include(cmake/arch.cmake)
include(cmake/coverage.cmake)
include(cmake/checkGit.cmake)

get_git_commit()

project(FCS
        VERSION 0.1
        LANGUAGES ASM C CXX
        DESCRIPTION "Library for FPGA Crypto Services for Altera SoCFPGAs")

message("-- PROJECT NAME      : ${PROJECT_NAME}")
message("-- PROJECT VERSION   : ${PROJECT_VERSION}")
message("-- PROJECT GIT SHA1  : ${GIT_HASH}")

include(cmake/doxygen.cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(UNIT_TEST "Enable Unit testing of libfcs" OFF)
option(NEED_STATIC_LIB "Override building of library as static" OFF)

if(SHARED_LIB AND NOT NEED_STATIC_LIB)
  set(LIBRARY_TYPE SHARED)
else()
  set(LIBRARY_TYPE STATIC)
endif()


if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

add_library(FCS ${LIBRARY_TYPE} "")
target_include_directories(FCS PUBLIC "${CMAKE_SOURCE_DIR}/include")

set_target_properties(FCS PROPERTIES VERSION ${PROJECT_VERSION})

add_subdirectory(third_party)
add_subdirectory(lib)
add_subdirectory(app)

add_subdirectory(toolchain)

target_include_directories(FCS PUBLIC "${CMAKE_BINARY_DIR}/libkcapi/include")

# Custom clean target to delete the source directory
add_custom_target(clean-all
#   DEPENDS clean-libkcapi-source
  COMMAND ${CMAKE_COMMAND} -E rm -rf ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libkcapi
  COMMAND ${CMAKE_COMMAND} -E rm -rf ${CMAKE_BINARY_DIR}
)
