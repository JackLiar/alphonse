cmake_minimum_required(VERSION 3.19.0)
project(alphonse VERSION 0.1.0)

cmake_policy(SET CMP0109 NEW)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(macros)
include(projects)

add_custom_target(alphonse ALL
    # COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && cargo build
    COMMAND echo "All the dependencies of alphonse are built successfully!"
)

find_library(libpcap_LIBRARY pcap
    HINTS "${CMAKE_CURRENT_BINARY_DIR}/install/lib"
    PATHS /usr/lib/x86_64-linux-gnu/
)

option(BUILD_LIBPCAP "build libpcap" ON)
if(NOT libpcap_LIBRARY OR BUILD_LIBPCAP)
    add_dependencies(alphonse libpcap)
endif()

# Currently DPDK is only for Linux, FreeBSD and Windows
# We only target for Linux in current stage
option(BUILD_DPDK "build dpdk" OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_DPDK)
    add_dependencies(alphonse dpdk)
endif()

option(BUILD_DPDK_KMODS "build DPDK igb_uio kmods" OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_DPDK_KMODS)
    add_dependencies(alphonse dpdk-kmods)
endif()

option(BUILD_TCMALLOC "build tcmalloc" OFF)
if(BUILD_TCMALLOC)
    add_dependencies(alphonse gperftools)
endif()

add_dependencies(alphonse llhttp hyperscan)

print_configuration()
