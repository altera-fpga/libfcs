# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

add_subdirectory(common)
add_subdirectory(os/linux)
target_include_directories(FCS PRIVATE "${CMAKE_SOURCE_DIR}/lib/include")
