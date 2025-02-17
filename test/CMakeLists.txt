#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2020 Alexey Moskvin
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

macro(define_test test)
    string(REPLACE "/" "_" full_test_name ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}_${test}_test)

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp)

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 17)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

endmacro()

set(TESTS_NAMES
        "hash"
)

foreach(TEST_NAME ${TESTS_NAMES})
    define_test(${TEST_NAME})
endforeach()


include_directories(${CMAKE_WORKSPACE_SOURCES_DIR})
