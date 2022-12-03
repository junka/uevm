cmake_minimum_required(VERSION 3.21.2)
project(lc3)
set(LC3_ROOT ${PROJECT_SOURCE_DIR})

set(SOURCE_FILES
    vm_main.c)

file(GLOB UTILS_SOURCE "${LC3_ROOT}/../utils/log.c"
    "${LC3_ROOT}/../utils/options.c")

include_directories(${LC3_ROOT}/../utils)
add_executable(lc3-vm ${SOURCE_FILES} ${UTILS_SOURCE})