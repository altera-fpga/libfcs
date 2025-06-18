# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

# Set output directories for different types of build artifacts
set_target_properties(FCS PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/lib"  # Directory for static libraries
    LIBRARY_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/lib"  # Directory for shared libraries
    RUNTIME_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/bin"  # Directory for executables
)

# Set compile options for the FCS target
target_compile_options(FCS PRIVATE
  -Wall                        # Enable all warnings
  -Wextra                      # Enable extra warnings
  -Wformat
  -Wno-unused-parameter
  -Wformat-security
  -D_FORTIFY_SOURCE=2
  -march=armv8-a
  -mtune=cortex-a55
  -mstrict-align
  -g
)

target_include_directories(FCS
        PUBLIC
        ${PROJECT_SOURCE_DIR}/../FreeRTOS/Fat-Fs/portable/common/
        ${PROJECT_SOURCE_DIR}/../FreeRTOS/Fat-Fs/include/
        ${PROJECT_SOURCE_DIR}/../osal/freertos/
        ${FREERTOS_CONFIG_HEADER_PATH}
        ${driver_include_dirs}
        ${RTOS_INCLUDES}
    )
add_subdirectory(include)
