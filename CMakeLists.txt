cmake_minimum_required(VERSION 3.22)
project(morgana_playground)

set(CMAKE_CXX_STANDARD 20)

#list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
#        "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
#        "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

find_package(CM)
include(CMConfig)
include(CMSetupVersion)

#cm_workspace(morgana-playground)
#cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME})

add_library(morgana-playground STATIC library.cpp)
