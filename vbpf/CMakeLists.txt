cmake_minimum_required(VERSION 3.21.2)
project(vbpf)

set(VBPF_ROOT ${PROJECT_SOURCE_DIR})
set(CMAKE_MODULE_PATH "${VBPF_ROOT}/cmake"
    ${CMAKE_MODULE_PATH})
find_package(LibELF REQUIRED)

if(NOT LibELF_FOUND)
    message(FATAL_ERROR "libelf not found!")
endif(NOT LibELF_FOUND)

set(SOURCE_FILES
    vm_main.c)

file(GLOB UTILS_SOURCE "${VBPF_ROOT}/../utils/log.c")

include_directories(${VBPF_ROOT}/../utils)

include_directories(${LibELF_INCLUDE_DIRS})

add_executable(vbpf ${SOURCE_FILES} ${UTILS_SOURCE})

target_link_libraries(vbpf ${LibELF_LIBRARIES})
