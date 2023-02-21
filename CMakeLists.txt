cmake_minimum_required(VERSION 3.23)
project(nxlog_test_cpp)

set(CMAKE_CXX_STANDARD 11)

include(ExternalProject)

set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/3party)
#from rapidjson repository:
#
# RapidJSON is a header-only C++ library. Just copy the include/rapidjson folder to system or project's include path.
#
# so did I.
#
ExternalProject_Add(rapidjson
        GIT_REPOSITORY https://github.com/Tencent/rapidjson
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
        )

include_directories(${EXTERNAL_INSTALL_LOCATION}/include tlv)
link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)

add_executable(nxlog_test_cpp src/tests.cpp tlv/tlv.h tlv/tlv.cpp tlv/tlv_box.cpp tlv/tlv_box.h src/error_codes.h src/json_to_tlv_processor.cpp src/json_to_tlv_processor.h)
add_dependencies(nxlog_test_cpp rapidjson)

add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/test/test.json
        ${CMAKE_CURRENT_BINARY_DIR}/test.json)
