# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

target_sources(FCS PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libfcs_logging.c")
target_sources(FCS PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libfcs_osal.c")
target_sources(FCS PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libfcs_utils.c")
target_sources(FCS PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libfcs_file_ops.c")
