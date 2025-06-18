# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

target_include_directories(FCS PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_sources(FCS PUBLIC
FILE_SET public_headers
TYPE HEADERS
BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
FILES ${CMAKE_CURRENT_SOURCE_DIR}/libfcs_osal_types.h)
