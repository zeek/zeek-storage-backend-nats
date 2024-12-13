
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginNats)

include(ZeekPlugin)

find_library(CNATS_LIBRARY nats REQUIRED)
find_path(CNATS_INCLUDE_DIR nats/nats.h REQUIRED)
# TODO min version?

if(NOT CNATS_LIBRARY OR NOT CNATS_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find CNATS library")
endif()

include_directories(${CNATS_INCLUDE_DIR})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

zeek_plugin_begin(Storage Nats ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/Nats.cc)
zeek_plugin_bif(src/nats.bif)
zeek_plugin_link_library(${CNATS_LIBRARY})
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(
        scripts/__load__.zeek
        scripts/__preload__.zeek
        scripts/types.zeek
        scripts/Storage/Nats/__load__.zeek
)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
