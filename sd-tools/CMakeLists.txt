#* ---------------------------------------------------------------------------------------------
#* Copyright (c) 2015 Seagate Technologies
#* All rights reserved.
#* ---------------------------------------------------------------------------------------------

cmake_minimum_required (VERSION 2.8.12)
project (sd_tools)

if (EXISTS /usr/include/linux/blk-zoned-ctrl.h)
   message ("System provided blk-zoned-ctrl.h GOOD.")
else (EXISTS /usr/include/linux/blk-zoned-ctrl.h)
   message ("No blk-zoned-ctrl.h using local verson.")
   include_directories ("${PROJECT_SOURCE_DIR}/uapi-missing")
endif (EXISTS /usr/include/linux/blk-zoned-ctrl.h)

set (sdtools_VERSION_MAJOR 1)
set (sdtools_VERSION_MINOR 1)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/include/sdtools_version.h.in"
  "${PROJECT_BINARY_DIR}/include/sdtools_version.h"
  )

include_directories ("${PROJECT_SOURCE_DIR}/include")
include_directories ("${PROJECT_BINARY_DIR}/include")
include_directories ("${PROJECT_SOURCE_DIR}/sd_reset_wp") # For: is_mounted.h

add_executable(sd_reset_wp     sd_reset_wp/sd_reset_wp.c    sd_reset_wp/is_mounted.c)
add_executable(sd_zone_finish  sd_reset_wp/sd_zone_finish.c sd_reset_wp/is_mounted.c)
add_executable(sd_zone_close   sd_reset_wp/sd_zone_close.c  sd_reset_wp/is_mounted.c)
add_executable(sd_zone_open    sd_reset_wp/sd_zone_open.c   sd_reset_wp/is_mounted.c)
add_executable(sd_identify     sd_identify/sd_identify.c)
add_executable(sd_report_zones sd_report_zones/sd_report_zones.c)
add_executable(blkreport       sd_report_zones/blkreport.c)

install(TARGETS
            sd_reset_wp
            sd_zone_finish
            sd_zone_close
            sd_zone_open
            sd_identify
            sd_report_zones
            blkreport
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
