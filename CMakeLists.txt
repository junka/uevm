cmake_minimum_required(VERSION 3.21.2)
project(vcvm)

set(VCVM_ROOT ${PROJECT_SOURCE_DIR})

add_subdirectory(utils)

add_subdirectory(lc3)

add_subdirectory(vbpf)