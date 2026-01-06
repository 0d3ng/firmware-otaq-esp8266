# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(firmware-otaq-s3)
set(EXTRA_COMPONENT_DIRS components)

# ==== Handle firmware version from CI/CD ====
if(NOT DEFINED FIRMWARE_VERSION)
    # fallback kalau build lokal
    execute_process(COMMAND git rev-parse --short HEAD OUTPUT_VARIABLE GIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND "C:/Program Files/Git/bin/bash.exe" -c "date '+%Y%m%dT%H%M'" OUTPUT_VARIABLE BUILD_DATE OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(FIRMWARE_VERSION "${GIT_HASH}-${BUILD_DATE}-local")
endif()

message(STATUS "Building firmware version: ${FIRMWARE_VERSION}")

# Add version to compile definitions for all components
idf_build_set_property(COMPILE_DEFINITIONS "-DFIRMWARE_VERSION=\"${FIRMWARE_VERSION}\"" APPEND)
# ========================================
# ==== Handle firmware algorithm from CI/CD ====
if(NOT DEFINED FIRMWARE_ALGORITHM)
    # default algorithm for local builds
    set(FIRMWARE_ALGORITHM "ED25519_0MB")
endif()

message(STATUS "Using firmware algorithm: ${FIRMWARE_ALGORITHM}")

# Add algorithm to compile definitions for all components
idf_build_set_property(COMPILE_DEFINITIONS "-DFIRMWARE_ALGORITHM=\"${FIRMWARE_ALGORITHM}\"" APPEND)

# Add TLS configurations to compile definitions for all components
idf_build_set_property(COMPILE_DEFINITIONS "-DFIRMWARE_TLS=1" APPEND)