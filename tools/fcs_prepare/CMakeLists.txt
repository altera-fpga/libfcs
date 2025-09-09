cmake_minimum_required(VERSION 3.24)

project(fcs_prepare
        LANGUAGES C
        VERSION 1.00)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/fcs_version.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/tools/include/fcs_version.h
  @ONLY
)

set(CMAKE_C_STANDARD 11)

# Collect sources
file(GLOB SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nettle/src/*.c
)

# Define executable
add_executable(fcs_prepare ${SRC_FILES})

# Includes
target_include_directories(fcs_prepare PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/tools/fcs_prepare/tools/include
    ${CMAKE_CURRENT_SOURCE_DIR}/nettle/include
)

# Compiler flags
target_compile_options(fcs_prepare PRIVATE -Wall)
