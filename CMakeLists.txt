cmake_minimum_required(VERSION 3.24)
project(ttp_https VERSION 4.2.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(cmake/xp_runtime.cmake)
include(cmake/size_release.cmake)
# SDK declarations include condition variables; the runtime target remains XP.
add_compile_definitions(_WIN32_WINNT=0x0600 WINVER=0x0600 WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
  _CRT_SECURE_NO_WARNINGS)
add_compile_options(/utf-8)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/mtm_config.h" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/mtm_crypto_config.h" CACHE FILEPATH "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(mtm_mbedtls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.2.0/mbedtls-4.2.0.tar.bz2
  URL_HASH SHA256=2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(mtm_mbedtls)

set(MTM_CA_FILE "${CMAKE_CURRENT_BINARY_DIR}/downloads/cacert-2026-08-13.pem" CACHE FILEPATH "Pinned Mozilla trust bundle")
if(NOT EXISTS "${MTM_CA_FILE}")
  file(DOWNLOAD https://curl.se/ca/cacert-2026-08-13.pem "${MTM_CA_FILE}"
    EXPECTED_HASH SHA256=f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9
    TLS_VERIFY ON)
endif()
file(SHA256 "${MTM_CA_FILE}" ca_hash)
if(NOT ca_hash STREQUAL "f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9")
  message(FATAL_ERROR "Unexpected CA bundle hash")
endif()
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
find_package(Python3 COMPONENTS Interpreter REQUIRED)
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_ca.py"
  "${MTM_CA_FILE}" "${CMAKE_CURRENT_BINARY_DIR}/generated/ca_bundle.h"
  COMMAND_ERROR_IS_FATAL ANY)
include(cmake/version.cmake)
add_library(ttp_https SHARED src/mbed_tls_min.c src/https_client.cpp src/ttp_https.def src/capabilities.rc "${CMAKE_CURRENT_BINARY_DIR}/generated/version.rc")
add_dependencies(ttp_https ttp_https_version)
target_compile_options(ttp_https PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/EHsc> $<$<COMPILE_LANGUAGE:CXX>:/permissive->)
target_include_directories(ttp_https PUBLIC include PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(ttp_https PRIVATE mbedtls mbedx509 tfpsacrypto advapi32 ws2_32 winhttp shlwapi secur32)
target_link_options(ttp_https PRIVATE /OPT:REF /OPT:ICF /SUBSYSTEM:WINDOWS,5.01)
set_target_properties(ttp_https PROPERTIES PREFIX "" OUTPUT_NAME ttp_https RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>/AddIn")
add_custom_command(TARGET ttp_https POST_BUILD
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_legacy_imports.py"
    "$<TARGET_FILE:ttp_https>"
    --exports "${mtm_yy_thunks_SOURCE_DIR}/Config/x86/5.1.2600.txt"
    --exports "${mtm_yy_thunks_SOURCE_DIR}/Config/x86/6.1.7600.txt"
    --report "$<TARGET_FILE_DIR:ttp_https>/../legacy-imports.json"
  COMMAND "${CMAKE_COMMAND}" -DINPUT=$<TARGET_FILE:ttp_https>
    -DOUTPUT=$<TARGET_FILE_DIR:ttp_https>/../SHA256SUMS.txt -DNAME=AddIn/ttp_https.dll
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/hash.cmake" VERBATIM)
install(TARGETS ttp_https RUNTIME DESTINATION AddIn COMPONENT Runtime)
install(FILES "$<TARGET_FILE_DIR:ttp_https>/../SHA256SUMS.txt" DESTINATION . COMPONENT Runtime)
# Source, notices and licenses stay in this repository, outside runtime packages.
# Local test sources are never downloaded or built by Actions.
set(TTP_HTTPS_TEST_SOURCE "" CACHE FILEPATH "Optional local public HTTP ABI probe")
if(TTP_HTTPS_TEST_SOURCE)
  add_executable(ttp_https_probe "${TTP_HTTPS_TEST_SOURCE}")
  target_include_directories(ttp_https_probe PRIVATE include)
  get_filename_component(_https_test_dir "${TTP_HTTPS_TEST_SOURCE}" DIRECTORY)
  if(EXISTS "${_https_test_dir}/ttp_https_invalid.c")
    add_library(ttp_https_invalid SHARED "${_https_test_dir}/ttp_https_invalid.c" "${_https_test_dir}/ttp_https_invalid.def")
    target_include_directories(ttp_https_invalid PRIVATE include)
  endif()
endif()
set(TTP_HTTPS_CODEC_TEST_SOURCE "" CACHE FILEPATH "Optional local HTTP codec tests")
if(TTP_HTTPS_CODEC_TEST_SOURCE)
  add_executable(ttp_https_contract_tests "${TTP_HTTPS_CODEC_TEST_SOURCE}" src/mbed_tls_min.c)
  target_include_directories(ttp_https_contract_tests PRIVATE include src "${CMAKE_CURRENT_BINARY_DIR}/generated")
  target_compile_options(ttp_https_contract_tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/EHsc>)
  target_link_libraries(ttp_https_contract_tests PRIVATE mbedtls mbedx509 tfpsacrypto advapi32 ws2_32 winhttp shlwapi secur32)
endif()
