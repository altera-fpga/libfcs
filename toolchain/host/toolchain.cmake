# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

# Check if CMAKE_TOOLCHAIN_FILE is not already defined
if (NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    # Set the default toolchain to the cross-compiler GCC
    set(DEFAULT_TOOLCHAIN ${CROSS_COMPILE}gcc)

    # If TOOLCHAIN is not defined, use the default toolchain
    if (NOT DEFINED TOOLCHAIN)
    # Print a message indicating that TOOLCHAIN is not defined and the default toolchain will be used
    message(STATUS "'TOOLCHAIN' is not defined. Using '${DEFAULT_TOOLCHAIN}'")
    # Set TOOLCHAIN to the default toolchain
    set(TOOLCHAIN ${DEFAULT_TOOLCHAIN})
    endif ()

    # Set the CMAKE_TOOLCHAIN_FILE to the path of the toolchain file
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/${TOOLCHAIN}.cmake)
endif ()
# Enable shared library building
set(SHARED_LIB ON)
# Add common compile options
add_compile_options(-Wall -Wextra -Wpedantic)
