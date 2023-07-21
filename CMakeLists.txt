set(CMAKE_TOOLCHAIN_FILE "~/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")

set(CMAKE_CXX_STANDARD 20)
cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

project(SecureCloudStorage CXX)

find_package(google_cloud_cpp_storage REQUIRED)

include(FetchContent)
FetchContent_Declare(
        cli
        GIT_REPOSITORY https://github.com/daniele77/cli.git
        GIT_TAG v2.0.2
)
FetchContent_MakeAvailable(cli)

include_directories(lib-puncturable-key-wrapping-cpp)
add_subdirectory(lib-puncturable-key-wrapping-cpp)

set(HEADERS
        client_operator.h
        interactive_client.h
        util/file_util.h
        util/tag_util.h
        cloud_communicator.h
        gcs_cloud_communicator.h
        id.h
        id_provider.h
        flat_id_provider.h
        hierarch_id_provider.h
        client_operator_multi_pkw.h
        flat_dir_id_provider.h
        )

set(SOURCES
        interactive_client.cpp
        util/file_util.cpp
        util/tag_util.cpp
        )

add_executable(client ${HEADERS} ${SOURCES})
# private linking is cleaner: https://stackoverflow.com/questions/26037954/cmake-target-link-libraries-interface-dependencies
target_link_libraries(client PRIVATE PKWLib google-cloud-cpp::storage cli::cli)

# For testing, enable it, make the code available as library
add_library(client_tests ${HEADERS} ${SOURCES})
target_link_libraries(client_tests PKWLib google-cloud-cpp::storage cli::cli)
enable_testing()
add_subdirectory(tests)

add_subdirectory(benchmarks)