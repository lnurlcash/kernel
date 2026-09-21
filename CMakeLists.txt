cmake_minimum_required(VERSION 3.22)
project(lnurlcashkernel LANGUAGES NONE)

# Builds Bitcoin Core's libbitcoinkernel from the pinned, UNMODIFIED submodule
# at vendor/bitcoin, and installs the shared library into the Python package.
#
# Core's own CMake is driven as an ExternalProject rather than add_subdirectory:
# it is a full top-level project with its own install rules and options, and
# keeping it at arm's length is what lets the submodule stay byte-for-byte
# upstream. Nothing here patches or reconfigures Core's sources - it only
# selects which of Core's OWN build options are on.
include(ExternalProject)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/bitcoin/CMakeLists.txt")
  message(FATAL_ERROR
    "vendor/bitcoin is empty - run: git submodule update --init --depth 1")
endif()

# Core's CMake unconditionally requires Boost >= 1.74 *headers* (its own TODO
# says the check is not yet scoped per target). Point at a header tree with
# -DBoost_DIR=<dir containing BoostConfig.cmake>, or install Boost's dev
# package. See UPSTREAM.md.
set(BOOST_ARGS "")
if(Boost_DIR)
  list(APPEND BOOST_ARGS -DBoost_DIR=${Boost_DIR})
endif()

ExternalProject_Add(bitcoin_kernel
  SOURCE_DIR        ${CMAKE_CURRENT_SOURCE_DIR}/vendor/bitcoin
  BINARY_DIR        ${CMAKE_CURRENT_BINARY_DIR}/kernel
  CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=ON
    -DBUILD_KERNEL_LIB=ON
    -DBUILD_KERNEL_TEST=OFF
    -DBUILD_BITCOIN_BIN=OFF
    -DBUILD_DAEMON=OFF
    -DBUILD_CLI=OFF
    -DBUILD_TESTS=OFF
    -DBUILD_TX=OFF
    -DBUILD_UTIL=OFF
    -DBUILD_UTIL_CHAINSTATE=OFF
    -DBUILD_GUI=OFF
    -DBUILD_BENCH=OFF
    -DBUILD_FUZZ_BINARY=OFF
    -DENABLE_WALLET=OFF
    -DENABLE_IPC=OFF
    -DWITH_ZMQ=OFF
    -DINSTALL_MAN=OFF
    ${BOOST_ARGS}
  BUILD_COMMAND     ${CMAKE_COMMAND} --build <BINARY_DIR> --target bitcoinkernel
  INSTALL_COMMAND   ""
  BUILD_ALWAYS      OFF
)

ExternalProject_Get_Property(bitcoin_kernel BINARY_DIR)
install(
  DIRECTORY ${BINARY_DIR}/lib/
  DESTINATION lnurlcashkernel/_lib
  FILES_MATCHING PATTERN "libbitcoinkernel.so*" PATTERN "libbitcoinkernel*.dylib"
                 PATTERN "bitcoinkernel.dll"
)
