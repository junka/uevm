# ========================================================================================
# FindLibELF.cmake
#
# Find libelf include dirs and libraries
#
# ----------------------------------------
#
# Use this module by invoking find_package with the form::
#
# find_package(LibELF
# [version] [EXACT]      # Minimum or EXACT version e.g. 0.173
# [REQUIRED]             # Fail with error if libelf is not found
# )
#
# This module reads hints about search locations from variables::
#
# LibELF_ROOT_DIR		- Base directory the of libelf installation
# LibELF_INCLUDEDIR	- Hint directory that contains the libelf headers files
# LibELF_LIBRARYDIR	- Hint directory that contains the libelf library files
#
# and saves search results persistently in CMake cache entries::
#
# LibELF_FOUND			- True if headers and requested libraries were found
# LibELF_INCLUDE_DIRS 	- libelf include directories
# LibELF_LIBRARY_DIRS		- Link directories for libelf libraries
# LibELF_LIBRARIES		- libelf library files
#
#
# Based on the version by Bernhard Walle <bernhard.walle@gmx.de> Copyright (c) 2008
#
# ========================================================================================

# Non-standard subdirectories to search
set(_path_suffixes libelf libelfls elfutils)
set(SYS_USER_INCLUDE "/usr/local/include")
find_path(
    LibELF_INCLUDE_DIR
    NAMES libelf.h
    HINTS ${LibELF_ROOT_DIR}/include ${LibELF_ROOT_DIR} ${LibELF_INCLUDEDIR}
    PATHS ${SYS_USER_INCLUDE}
    PATH_SUFFIXES ${_path_suffixes}
    DOC "libelf include directories")

find_library(
    LibELF_LIBRARIES
    NAMES libelf.so.1 libelf.so libelf.a
    HINTS ${LibELF_ROOT_DIR}/lib ${LibELF_ROOT_DIR} ${LibELF_LIBRARYDIR}
    PATH_SUFFIXES ${_path_suffixes})

# Find the library with the highest version
set(_max_ver 0.0)
set(_max_ver_lib)

foreach(l ${LibELF_LIBRARIES})
    get_filename_component(_elf_realpath ${LibELF_LIBRARIES} REALPATH)
    string(REGEX MATCH "libelf\\-(.+)\\.so\\.*$" res ${_elf_realpath})
    string(REGEX MATCH "libelf\.a" res ${_elf_realpath})

    # The library version number is stored in CMAKE_MATCH_1
    # set(_cur_ver ${CMAKE_MATCH_1})

    # if(${_cur_ver} VERSION_GREATER ${_max_ver})
    # set(_max_ver ${_cur_ver})
    # set(_max_ver_lib ${l})
    # endif()
endforeach()

# Set the exported variables to the best match
set(LibELF_LIBRARIES ${_max_ver_lib})
set(LibELF_VERSION ${_max_ver})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LibELF
    FOUND_VAR LibELF_FOUND
    REQUIRED_VARS LibELF_LIBRARIES LibELF_INCLUDE_DIR
    VERSION_VAR LibELF_VERSION)

# Export cache variables
if(LibELF_FOUND)
    set(LibELF_INCLUDE_DIRS ${LibELF_INCLUDE_DIR} ${SYS_USER_INCLUDE})
    set(LibELF_LIBRARIES ${LibELF_LIBRARIES})
    add_compile_definitions(HAVE_ELF)

    # Because we only report the library with the largest version, we are guaranteed there
    # is only one file in LibELF_LIBRARIES
    get_filename_component(_elf_dir ${LibELF_LIBRARIES} DIRECTORY)
    set(LibELF_LIBRARY_DIRS ${_elf_dir} "${_elf_dir}/elfutils")
endif()
