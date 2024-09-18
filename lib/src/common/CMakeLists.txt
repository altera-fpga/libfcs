# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

target_include_directories(FCS PRIVATE "${CMAKE_SOURCE_DIR}/lib/include/common")

target_sources(FCS PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libfcs.c")
