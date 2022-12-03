cmake_minimum_required(VERSION 3.21.2)
project(lc3)
set(LC3_ROOT ${PROJECT_SOURCE_DIR})

set(SOURCE_FILES
    vm_main.c)

include_directories(${LC3_ROOT}/../utils)
add_executable(lc3 ${SOURCE_FILES})