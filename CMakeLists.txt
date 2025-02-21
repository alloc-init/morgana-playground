cmake_minimum_required(VERSION 3.22)
set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
        "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

find_package(CM)
include(CMConfig)
include(CMSetupVersion)

cm_workspace(morgana)
cm_project(playground WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})
cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME})

set(Boost_USE_STATIC_LIBS ${BUILD_WITH_BOOST_STATIC_LIBS})
find_package(Boost REQUIRED COMPONENTS container random filesystem log log_setup program_options thread system)
if(CMAKE_ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework timer)
endif()

add_subdirectory(libs/crypto3)
add_subdirectory(libs/blueprint)
add_subdirectory(src)

cm_test_link_libraries(
        crypto3::algebra
        crypto3::block
        crypto3::codec
        crypto3::containers
        crypto3::functional
        crypto3::hash
        crypto3::kdf
        crypto3::mac
        crypto3::math
        crypto3::modes
        crypto3::multiprecision
        crypto3::passhash
        crypto3::pbkdf
        crypto3::pkpad
        crypto3::pubkey
        crypto3::random
        crypto3::stream
        crypto3::threshold
        crypto3::vdf
        crypto3::witness
        crypto3::zk

        crypto3::blueprint

        marshalling::crypto3_algebra
        marshalling::core
        marshalling::crypto3_multiprecision
        marshalling::crypto3_zk

        Boost::unit_test_framework
)

include(CMTest)
cm_add_test_subdirectory(test)