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
if(${DISABLE_INPLACE_UPDATE})
    target_compile_definitions(hash_map_bench PUBLIC DISABLE_INPLACE_UPDATE)
endif()

add_executable(hash_dict_bench hash_map/hash_map_bench.cpp dict/concurrent_dict.cpp)
target_link_libraries(hash_dict_bench pthread)
target_compile_definitions(hash_dict_bench PUBLIC USE_DICT)

add_executable(dict_test dict/concurrent_dict.cpp dict/dict_bench.cpp)
