# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.24)

include(CMakePackageConfigHelpers)

include(cmake/arch.cmake)
include(cmake/coverage.cmake)
include(cmake/checkGit.cmake)

get_git_commit()

# Option to build fcs_prepare tool
if(BUILD_FCS_PREPARE)
  message(STATUS "Configuring fcs_prepare tool")
  # 1st argument: <source_dir>, 2nd argument: <binary_dir>
  add_subdirectory(tools/fcs_prepare tools/fcs_prepare)
  return()
endif()

project(FCS
        VERSION 3.00
        LANGUAGES ASM C CXX
        DESCRIPTION "Library for FPGA Crypto Services for Altera SoCFPGAs")

message("-- PROJECT NAME      : ${PROJECT_NAME}")
message("-- PROJECT VERSION   : ${PROJECT_VERSION}")
message("-- PROJECT GIT SHA1  : ${GIT_HASH}")

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/fcs_version.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/fcs_version.h
  @ONLY
)

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

# include dir
include_directories(FCS PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/include)

add_library(FCS ${LIBRARY_TYPE} "")

set_target_properties(FCS PROPERTIES
                      VERSION ${PROJECT_VERSION_MAJOR}
                      SOVERSION ${PROJECT_VERSION_MAJOR})

write_basic_package_version_file(FCS.cmake
                                  VERSION ${PROJECT_VERSION}
                                  COMPATIBILITY SameMajorVersion)

add_subdirectory(third_party)
add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(app)

add_subdirectory(toolchain)
