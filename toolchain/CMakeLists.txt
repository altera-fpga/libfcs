# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

if (NOT DEFINED ARCH)
  set(DEFAULT_ARCH    host)
  message(STATUS "OS is not defined. Using ${DEFAULT_OS}")
  set(ARCH ${DEFAULT_ARCH})
endif ()

target_include_directories(FCS PUBLIC "${CMAKE_SOURCE_DIR}/toolchain/${ARCH}/include")

# Include directories for the FCS target
target_include_directories(FCS PRIVATE "${CMAKE_SOURCE_DIR}/lib/include/os/${OS}")
add_subdirectory(${ARCH})
