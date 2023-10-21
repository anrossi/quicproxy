# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.16)

message(STATUS "quicproxy: Configuration start...")
project(quicproxy)

set(QPROXY_VER_BUILD_ID "0" CACHE STRING "The version build ID")
message(STATUS "quicproxy: Version Build ID: ${QPROXY_VER_BUILD_ID}")

set(QPROXY_VER_SUFFIX "-private" CACHE STRING "The version suffix")
message(STATUS "quicproxy: Version Suffix: ${QPROXY_VER_SUFFIX}")

# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if (WIN32)
    # Statically link the OS included part of the runtime.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /NODEFAULTLIB:libucrt.lib /DEFAULTLIB:ucrt.lib")
    set(QUIC_COMMON_DEFINES WIN32_LEAN_AND_MEAN SECURITY_WIN32)
    # TODO - Get these to work on Linux
    list(APPEND QPROXY_COMMON_DEFINES VER_BUILD_ID=${QPROXY_VER_BUILD_ID})
    list(APPEND QPROXY_COMMON_DEFINES VER_SUFFIX=${QPROXY_VER_SUFFIX})
    if(HAS_SPECTRE)
        list(APPEND QUIC_COMMON_FLAGS /Qspectre)
    endif()
    # Compile/link flags
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
else()
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${CMAKE_C_FLAGS_RELEASE} -g -Og")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${CMAKE_CXX_FLAGS_RELEASE} -g -Og")
    set(QUIC_COMMON_DEFINES _GNU_SOURCE)
endif()


set(QPROXY_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/bin CACHE STRING "Output directory for build artifacts")
message(STATUS "quicproxy: Output set to ${QPROXY_OUTPUT_DIR}")
set(QUIC_OUTPUT_DIR ${QPROXY_OUTPUT_DIR} CACHE STRING "Output directory for build artifacts")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${QPROXY_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${QPROXY_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${QPROXY_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${QPROXY_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${QPROXY_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${QPROXY_OUTPUT_DIR})


# Configure and build msquic dependency.
if (WIN32)
    set(QUIC_TLS "schannel" CACHE STRING "TLS Library to use")
else()
    set(QUIC_TLS "openssl" CACHE STRING "TLS Library to use")
endif()
set(QUIC_BUILD_SHARED ON CACHE BOOL "Builds MsQuic as a dynamic library")
set(QUIC_ENABLE_LOGGING ON CACHE BOOL "Enable MsQuic logging")
set(CMAKE_BUILD_TYPE "Release")
add_subdirectory(msquic)
target_compile_features(inc INTERFACE cxx_std_20)

# build tool
add_executable (quicproxy "quicproxy.cpp")
target_link_libraries(quicproxy inc warnings msquic base_link)
