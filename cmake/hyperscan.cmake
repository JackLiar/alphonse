if(OFFLINE_ENVIRONMENT)
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(hyperscan_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hyperscan-5.4.0.tar.gz)
        set(url_md5 65e08385038c24470a248f6ff2fa379b)
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        set(hyperscan_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hyperscan-5.3.0.aarch64.tar.gz)
        set(url_md5 ef337257bde6583242a739fab6fb161f)
    endif()
else()
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(hyperscan_url https://github.com/intel/hyperscan/archive/v5.4.0.tar.gz)
        set(url_md5 65e08385038c24470a248f6ff2fa379b)
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        set(hyperscan_url https://github.com/kunpengcompute/hyperscan/archive/v5.3.0.aarch64.tar.gz)
        set(url_md5 ef337257bde6583242a739fab6fb161f)
    endif()
endif()

set(FLAGS "-I${CMAKE_CURRENT_BINARY_DIR}/install/include -L${CMAKE_CURRENT_BINARY_DIR}/install/${CMAKE_INSTALL_LIBDIR}")

ExternalProject_Add(hyperscan
    URL ${hyperscan_url}
    URL_MD5 ${url_md5}
    EXCLUDE_FROM_ALL ON
    PREFIX hyperscan
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                -D BUILD_STATIC_AND_SHARED=ON
                -D BOOST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/boost/src/boost
                -D PCRE_SOURCE=${CMAKE_CURRENT_BINARY_DIR}/pcre/src/libpcre
                -D CMAKE_PREFIX_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/bin
                -D CMAKE_C_FLAGS=${FLAGS}
                -D CMAKE_CXX_FLAGS=${FLAGS}
                -D CMAKE_POSITION_INDEPENDENT_CODE=ON
)
