#* ---------------------------------------------------------------------------------------------
#* Copyright (c) 2015 Seagate Technologies
#* All rights reserved.
#* ---------------------------------------------------------------------------------------------

cmake_minimum_required (VERSION 2.8.12)
project(zdmon)

include_directories ("${PROJECT_SOURCE_DIR}/../h")

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(Qt5Widgets REQUIRED)

qt5_wrap_ui(UI_HEADERS zdmon.ui)

# If we gain .qrc:
# qt5_add_resources(UI_RESOURCES zdmon.qrc)
# Include ${UI_RESOURCES} to: add_executable(<existing> ${UI_RESOURCES})

add_executable(zdmon zdmon.cpp zdmon_main.cpp zoneswidget.cpp ${UI_HEADERS})
target_link_libraries(zdmon zdm uuid ssl)
qt5_use_modules(zdmon Widgets)

install(TARGETS zdmon
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
