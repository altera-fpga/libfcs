# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.24)

# Include necessary CMake modules
include(ProcessorCount)
include(ExternalProject)

# Get the number of available CPU cores
ProcessorCount(NPROC)

find_library(FDT_LIBRARY NAMES fdt libfdt)

if(FDT_LIBRARY STREQUAL FDT_LIBRARY-NOTFOUND)
  ######################
  # libfdt compilation #
  ######################
  # Define directories for the libfdt project
  set(LIBFDT_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/_deps/libfdt)
  set(LIBFDT_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/_deps/libfdt)

  # Define commands for configuring, building, and installing libfdt
  set(LIBFDT_CONFIGURE_COMMAND echo "")
  set(LIBFDT_BUILD_COMMAND CC=${CROSS_COMPILE}-gcc make -C ../libfdt libfdt > /dev/null)
  set(LIBFDT_INSTALL_COMMAND mkdir -p ${LIBFDT_INSTALL_DIR} &&
      cp ../libfdt/libfdt/libfdt.so ${LIBFDT_INSTALL_DIR}/ &&
      cp ../libfdt/libfdt/libfdt.h ${LIBFDT_INSTALL_DIR} &&
      cp ../libfdt/libfdt/libfdt_env.h ${LIBFDT_INSTALL_DIR} &&
      cp ../libfdt/libfdt/fdt.h ${LIBFDT_INSTALL_DIR})

  # Add an external project for libfdt
  ExternalProject_Add(libfdt
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/_deps
    GIT_REPOSITORY https://git.kernel.org/pub/scm/utils/dtc/dtc.git # Git repository URL
    GIT_TAG b75515af4576173850734d6aed87069cef733961 #TODO: v1.7.3 or above
    CONFIGURE_COMMAND ${LIBFDT_CONFIGURE_COMMAND} # Command to configure the project
    BUILD_COMMAND ${LIBFDT_BUILD_COMMAND} # Command to build the project
    INSTALL_COMMAND ${LIBFDT_INSTALL_COMMAND} # Command to install the project
    BUILD_BYPRODUCTS ${LIBFDT_INSTALL_DIR}/libfdt.so
  )

  # Add libfdt and libkcapi dependency for fcs
  add_dependencies(FCS libfdt)

  # link fdt library with FCS
  target_link_libraries(
    FCS
    PUBLIC
    ${LIBFDT_INSTALL_DIR}/libfdt.so
  )

  target_include_directories(FCS PRIVATE "${LIBFDT_INSTALL_DIR}")

else()
  message("libfdt" ${FDT_LIBRARY})
  target_link_libraries(FCS PUBLIC ${FDT_LIBRARY})
endif()

