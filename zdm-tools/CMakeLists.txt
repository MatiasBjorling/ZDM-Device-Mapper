#* ---------------------------------------------------------------------------------------------
#* Copyright (c) 2015 Seagate Technologies
#* All rights reserved.
#* ---------------------------------------------------------------------------------------------

cmake_minimum_required (VERSION 2.8.12)
project (zdm_tools)

if (EXISTS /usr/include/linux/blk-zoned-ctrl.h)
   message ("System provided blk-zoned-ctrl.h GOOD.")
else (EXISTS /usr/include/linux/blk-zoned-ctrl.h)
   message ("No blk-zoned-ctrl.h using local verson.")
   include_directories ("${PROJECT_SOURCE_DIR}/uapi-missing")
endif (EXISTS /usr/include/linux/blk-zoned-ctrl.h)

INCLUDE(FindPkgConfig)

pkg_check_modules(UUID REQUIRED uuid)
pkg_check_modules(LIBSSL REQUIRED libssl)

include_directories ("${PROJECT_SOURCE_DIR}/h")
include_directories ("${PROJECT_BINARY_DIR}/h")

# For O_DIRECT
add_definitions(-D_GNU_SOURCE)

# For pread64/pwrite64
add_definitions(-D_LARGEFILE64_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)

set(LIBSRC lib/crc64.c lib/is_mounted.c lib/libcrc.c lib/libsort.c lib/libzdm.c lib/zbc-ctrl.c)

add_library(zdm ${LIBSRC})

set (zdm_VERSION_MAJOR 0)
set (zdm_VERSION_MINOR 104)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/h/zdm_version.h.in"
  "${PROJECT_BINARY_DIR}/h/zdm_version.h"
  )

add_executable(zdmadm     src/zdmadm.c)
add_executable(zdm-rawio  src/zdm-rawio.c)
add_executable(zdm-mlog   src/zdm-mlog.c)
add_executable(zdm-status src/zdm-status.c)
add_executable(zdm-zones  src/zdm-zones.c)

target_link_libraries (zdmadm     zdm uuid ssl)
target_link_libraries (zdm-rawio  zdm uuid ssl)
target_link_libraries (zdm-mlog   zdm uuid ssl)
target_link_libraries (zdm-status zdm uuid ssl)
target_link_libraries (zdm-zones  zdm uuid ssl)

install(TARGETS zdmadm zdm-rawio zdm-mlog zdm-status zdm-zones zdm
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

set(INCFILES
        h/crc64.h
        h/dm-zoned.h
        h/is_mounted.h
        h/libcrc.h
        h/libsort.h
        h/libzdm.h
        h/libzdm-compat.h
        h/libzoned.h
        h/list.h
        h/utypes.h
        h/zbc-ctrl.h
        h/zdmioctl.h
        "${PROJECT_BINARY_DIR}/h/zdm_version.h"
)
install(FILES ${INCFILES} DESTINATION include/zdm)
