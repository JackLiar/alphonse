# Since official release doesn't contain CMakeLists.txt, use git tag to retrive from network
if(OFFLINE_ENVIRONMENT)
    ExternalProject_Add(gperftools
        URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/gperftools-2.9.1.tar.gz
        EXCLUDE_FROM_ALL ON
        PREFIX gperftools
        INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
        CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                    -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                    -D BUILD_TESTING=OFF
                    -D gperftools_build_benchmark=OFF
                    -D GPERFTOOLS_BUILD_CPU_PROFILER=OFF
                    -D CMAKE_POSITION_INDEPENDENT_CODE=ON
    )
else()
    ExternalProject_Add(gperftools
        GIT_REPOSITORY https://github.com/gperftools/gperftools.git
        GIT_TAG gperftools-2.9.1
        GIT_SHALLOW ON
        EXCLUDE_FROM_ALL ON
        PREFIX gperftools
        INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
        CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                    -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                    -D BUILD_TESTING=OFF
                    -D gperftools_build_benchmark=OFF
                    -D GPERFTOOLS_BUILD_CPU_PROFILER=OFF
                    -D CMAKE_POSITION_INDEPENDENT_CODE=ON
    )
endif()