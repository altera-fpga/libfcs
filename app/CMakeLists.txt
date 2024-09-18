# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

# Add the executable
add_executable(fcs_client src/fcs_client.c)

# Find the libfcs library
find_package( Threads REQUIRED )

target_link_libraries(
  fcs_client
  PRIVATE
  FCS
  ${CMAKE_THREAD_LIBS_INIT}
)

# Include the libfcs headers
include_directories(${CMAKE_SOURCE_DIR}/lib/include)
