# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

if (NOT DEFINED OS)
  set(DEFAULT_OS    host)
  message(STATUS "'OS' is not defined. Using '${DEFAULT_OS}'")
  set(OS            ${DEFAULT_OS})
endif ()

# Setup platform toolchain file.
include(${CMAKE_CURRENT_SOURCE_DIR}/toolchain/${OS}/toolchain.cmake)
