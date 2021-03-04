include(ExternalProject)

include(gperftools)
include(libpcap)
include(ragel)
include(boost)
include(pcre)
include(hyperscan)
include(llhttp)
include(dpdk)

ExternalProject_Add_StepDependencies(dpdk configure libpcap)
ExternalProject_Add_StepDependencies(hyperscan configure ragel boost libpcre)
