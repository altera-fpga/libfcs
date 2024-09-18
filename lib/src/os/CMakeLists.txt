# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

if (NOT DEFINED OS)
  set(DEFAULT_OS    linux)
  message(STATUS "OS is not defined. Using ${DEFAULT_OS}")
  set(OS ${DEFAULT_OS})
endif ()

add_subdirectory(${OS})
