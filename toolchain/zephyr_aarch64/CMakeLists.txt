# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

cmake_minimum_required(VERSION 3.20)

# Link the FCS target with the Zephyr interface library
target_link_libraries(FCS PUBLIC zephyr_interface)
