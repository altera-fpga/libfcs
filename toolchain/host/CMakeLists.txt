# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

# Set output directories for different types of build artifacts
set_target_properties(FCS PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/lib"  # Directory for static libraries
    LIBRARY_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/lib"  # Directory for shared libraries
    RUNTIME_OUTPUT_DIRECTORY    "${CMAKE_BINARY_DIR}/bin"  # Directory for executables
)

# Set compile options for the uniLibFCS target
target_compile_options(FCS PRIVATE
  -Wall                        # Enable all warnings
  -Wextra                      # Enable extra warnings
  -Wno-unused-parameter        # Disable warning for unused parameters
  -Wno-missing-field-initializer # Disable warning for missing field initializers
  -Wmissing-prototypes         # Warn if a global function is defined without a prototype
  -Wstrict-prototypes          # Require strict prototypes
  -Wold-style-definition       # Warn if a function is defined with an old-style definition
  -Wshadow                     # Warn if a variable declaration shadows a previous local variable
  -Wpointer-arith              # Warn about anything that depends on the "size of" a function or void
  -Wcast-qual                  # Warn whenever a pointer is cast so as to remove a type qualifier
)

add_subdirectory(include)
