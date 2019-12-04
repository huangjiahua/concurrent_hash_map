cmake_minimum_required(VERSION 3.12)
project(concurrent_hash_map)

set(CMAKE_CXX_STANDARD 14)

include_directories(bench)
include_directories(.)

add_executable(hash_map_bench hash_map/hash_map_bench.cpp my_haz_ptr/haz_ptr/haz_ptr.cpp hash_map/thread.cpp)
target_link_libraries(hash_map_bench pthread)
if(${DISABLE_FAST_TABLE})
    target_compile_definitions(hash_map_bench PUBLIC DISABLE_FAST_TABLE)
endif()
