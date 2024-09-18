# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

# Include necessary CMake modules
include(ProcessorCount)
include(ExternalProject)

# Get the number of available CPU cores
ProcessorCount(NPROC)

########################
# libkcapi compilation #
########################
# Define directories for the libkcapi project
set(LIBKCAPI_INSTALL_DIR ${CMAKE_BINARY_DIR}/libkcapi)
set(LIBKCAPI_BUILD_DIR ${CMAKE_BINARY_DIR}/_deps)

# Define commands for configuring, building, and installing libkcapi
set(LIBKCAPI_CONFIGURE_COMMAND autoreconf -i ${LIBKCAPI_BUILD_DIR}/src/libkcapi &&
	${LIBKCAPI_BUILD_DIR}/src/libkcapi/configure
	--prefix=${LIBKCAPI_INSTALL_DIR}
	--host=${CROSS_COMPILE} > /dev/null)
set(LIBKCAPI_BUILD_COMMAND make -j${NPROC} > /dev/null)
set(LIBKCAPI_INSTALL_COMMAND make install > /dev/null)

# Add an external project for libkcapi
ExternalProject_Add(libkcapi
  PREFIX ${LIBKCAPI_BUILD_DIR}/  # Directory to store the built project
  GIT_REPOSITORY https://github.com/smuellerDD/libkcapi.git  # Git repository URL
  GIT_TAG v1.5.0  # Specific tag to checkout
  CONFIGURE_COMMAND ${LIBKCAPI_CONFIGURE_COMMAND}  # Command to configure the project
  BUILD_COMMAND ${LIBKCAPI_BUILD_COMMAND}  # Command to build the project
  INSTALL_COMMAND ${LIBKCAPI_INSTALL_COMMAND}  # Command to install the project
)

# link libkcapi library with FCS
target_link_libraries(FCS PUBLIC ${LIBKCAPI_INSTALL_DIR}/lib/libkcapi.so.1)
target_include_directories(FCS PUBLIC ${LIBKCAPI_INSTALL_DIR}/include)

######################
# libfdt compilation #
######################
# Define directories for the libfdt project
set(LIBFDT_BUILD_DIR ${CMAKE_BINARY_DIR}/libfdt)
set(LIBFDT_INSTALL_DIR ${CMAKE_BINARY_DIR}/libfdt)

# Define commands for configuring, building, and installing libfdt
set(LIBFDT_CONFIGURE_COMMAND echo "")
set(LIBFDT_BUILD_COMMAND CC=${CROSS_COMPILE}-gcc make -C ../libfdt libfdt > /dev/null)
set(LIBFDT_INSTALL_COMMAND mkdir -p ${LIBFDT_INSTALL_DIR} &&
		cp ../libfdt/libfdt/libfdt.a ${LIBFDT_INSTALL_DIR}/ &&
		cp ../libfdt/libfdt/libfdt.h ${LIBFDT_INSTALL_DIR} &&
		cp ../libfdt/libfdt/libfdt_env.h ${LIBFDT_INSTALL_DIR} &&
		cp ../libfdt/libfdt/fdt.h ${LIBFDT_INSTALL_DIR})

# Add an external project for libfdt
ExternalProject_Add(libfdt
  PREFIX ${CMAKE_BINARY_DIR}/_deps
  GIT_REPOSITORY https://git.kernel.org/pub/scm/utils/dtc/dtc.git # Git repository URL
  GIT_TAG b75515af4576173850734d6aed87069cef733961 #TODO: v1.7.3 or above
  CONFIGURE_COMMAND ${LIBFDT_CONFIGURE_COMMAND} # Command to configure the project
  BUILD_COMMAND ${LIBFDT_BUILD_COMMAND} # Command to build the project
  INSTALL_COMMAND ${LIBFDT_INSTALL_COMMAND} # Command to install the project
)

# Add libfdt and libkcapi dependency for fcs
add_dependencies(FCS libfdt)
add_dependencies(FCS libkcapi)

# link fdt library with FCS
target_link_libraries(
  FCS
  PUBLIC
  ${LIBFDT_INSTALL_DIR}/libfdt.a
)

target_include_directories(FCS PRIVATE "${LIBFDT_INSTALL_DIR}")
target_include_directories(FCS PRIVATE "${CMAKE_BINARY_DIR}/libkcapi/include")

# Add the include directories and library paths
include_directories(${CMAKE_SOURCE_DIR}/lib)  # Include directory for headers
