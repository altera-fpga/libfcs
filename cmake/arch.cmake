# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

if (NOT DEFINED ARCH)
  set(DEFAULT_ARCH    host)
  message(STATUS "'ARCH' is not defined. Using '${DEFAULT_ARCH}'")
  set(ARCH ${DEFAULT_ARCH})
endif ()

# Setup platform toolchain file.
include(${CMAKE_CURRENT_SOURCE_DIR}/toolchain/${ARCH}/toolchain.cmake)
