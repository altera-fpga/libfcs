# SPDX-License-Identifier: MIT-0
# Copyright (C) 2025 Altera

add_subdirectory(src)
add_subdirectory(include)

if(${ARCH} STREQUAL linux_aarch64)

  install(TARGETS FCS
    LIBRARY
      DESTINATION usr/lib
      COMPONENT FCS_lib_Development
    ARCHIVE
      DESTINATION usr/lib
      COMPONENT FCS_lib_Development
    FILE_SET public_headers
      DESTINATION usr/include
      COMPONENT FCS_lib_Development
  )

  install(TARGETS FCS
    LIBRARY
      DESTINATION usr/lib
      COMPONENT FCS_lib_Runtime
      NAMELINK_SKIP
    ARCHIVE
      DESTINATION usr/lib
      COMPONENT FCS_lib_Runtime
    FILE_SET public_headers
      DESTINATION usr/include
      COMPONENT FCS_lib_Runtime
  )
endif()
