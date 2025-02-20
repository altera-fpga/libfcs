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

if(${ARCH} STREQUAL linux_aarch64)

  set_target_properties(fcs_client PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/bin"
  )

  install(TARGETS fcs_client
    RUNTIME
      DESTINATION usr/bin
      COMPONENT FCS_client_Runtime
  )
endif()
