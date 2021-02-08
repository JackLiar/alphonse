if(OFFLINE_ENVIRONMENT)
    set(dpdk_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/dpdk-20.11.tar.xz)
else()
    set(dpdk_url http://fast.dpdk.org/rel/dpdk-20.11.tar.xz)
endif()

ExternalProject_Add(dpdk
    URL ${dpdk_url}
    EXCLUDE_FROM_ALL ON
    PREFIX dpdk
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env 
        PATH=${CMAKE_CURRENT_BINARY_DIR}/install/bin:$ENV{PATH}
        LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib:${CMAKE_CURRENT_BINARY_DIR}/install/lib64
        C_INCLUDE_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/include
        PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib/pkgconfig
        meson setup -Denable_kmods=false -Dtests=false -Dprefix=<INSTALL_DIR> --includedir=${CMAKE_INSTALL_INCLUDEDIR}/dpdk --default-library=shared <BINARY_DIR> <SOURCE_DIR>
    BUILD_COMMAND ${CMAKE_COMMAND} -E env
        LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib:${CMAKE_CURRENT_BINARY_DIR}/install/lib64
        C_INCLUDE_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/include
        ninja
        # echo
    INSTALL_COMMAND ninja install
    # INSTALL_COMMAND echo
)

execute_process(COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_MODULE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
find_program(SUDO NAMES sudo sudoedit HINTS /usr/bin /usr)
if(NOT SUDO)
    set(SUDO "")
endif()
ExternalProject_Add(dpdk-kmods
    GIT_REPOSITORY http://dpdk.org/git/dpdk-kmods
    GIT_TAG main
    GIT_SHALLOW ON
    EXCLUDE_FROM_ALL ON
    BUILD_IN_SOURCE ON
    PREFIX dpdk-kmods
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CONFIGURE_COMMAND echo ""
    COMMAND sed -i.bak -e "s/supported(udev->pdev)/supported(udev->pdev)||true/g" <SOURCE_DIR>/linux/igb_uio/igb_uio.c
    BUILD_COMMAND cd linux/igb_uio && make 
    INSTALL_COMMAND ${SUDO} ${CMAKE_COMMAND} -E copy <SOURCE_DIR>/linux/igb_uio/igb_uio.ko /lib/modules/${KERNEL_MODULE_DIR}/extra/dpdk/igb_uio.ko
)

# yum install numactl-devel elfutils-libelf-devel jansson-devel libfdt-devel bcc-devel
