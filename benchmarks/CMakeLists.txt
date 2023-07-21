project(Benchmarks)

find_package(benchmark REQUIRED)

add_executable(bench benchmarks_simple.cpp benchmark_client_operator.h benchmark_local_hierarch_client.h benchmark_local_hierarch_multi_pkw_client.h)

add_executable(bench2 benchmark_git_hist.cpp benchmark_local_client.h mock_cloud_communicator.h)

target_link_libraries(bench client_tests benchmark::benchmark)
target_link_libraries(bench2 client_tests)

add_custom_command(TARGET bench POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/data/ $<TARGET_FILE_DIR:bench>/data)

add_custom_command(TARGET bench2 POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/ $<TARGET_FILE_DIR:bench2>/resources)