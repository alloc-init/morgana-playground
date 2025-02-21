cmake_minimum_required(VERSION 3.22)
project(morgana_playground)

set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE SRCS *.cpp)
file(GLOB_RECURSE HRCS *.hpp)
file(GLOB_RECURSE HDRS *.h)

add_library(morgana_playground STATIC ${SRCS} ${HRCS} ${HDRS})
set_target_properties(morgana_playground PROPERTIES LINKER_LANGUAGE CXX)
