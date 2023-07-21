project(tests)
include(FetchContent)

find_package(GTest REQUIRED)

file(GLOB_RECURSE TEST_SOURCES "*test.cpp")

add_executable(client_operator_test ${TEST_SOURCES})
target_link_libraries(client_operator_test GTest::gtest GTest::gtest_main client_tests)

add_test(client_operator_gtest client_operator_test)

add_custom_command(TARGET client_operator_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/ $<TARGET_FILE_DIR:client_operator_test>/resources)