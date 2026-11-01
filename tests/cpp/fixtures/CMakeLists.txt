# An ordinary OpenFHE CMake project. Nothing here knows about CipherScope:
# `cipherscope profile ./build/<program>` discovers this build and creates an
# instrumented shadow build of its own.
cmake_minimum_required(VERSION 3.16)
project(cipherscope_cpp_fixtures CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenFHE CONFIG REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS} -Wno-error")
include_directories(${OPENMP_INCLUDES} ${OpenFHE_INCLUDE} ${OpenFHE_INCLUDE}/third-party/include
                    ${OpenFHE_INCLUDE}/core ${OpenFHE_INCLUDE}/pke ${OpenFHE_INCLUDE}/binfhe)
link_directories(${OpenFHE_LIBDIR} ${OPENMP_LIBRARIES})
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenFHE_EXE_LINKER_FLAGS}")

# checkpoints.cpp opts into cipherscope/annotate.h (inline no-ops unless the
# CipherScope launcher compiles the unit, so a plain build needs no runtime).
# The header ships with the repository; point at it when the fixtures are built
# from a copy.
if(NOT DEFINED CIPHERSCOPE_INCLUDE_DIR)
  get_filename_component(CIPHERSCOPE_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../native/include" ABSOLUTE)
endif()
include_directories(${CIPHERSCOPE_INCLUDE_DIR})

file(GLOB FIXTURES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
foreach(source ${FIXTURES})
  get_filename_component(name ${source} NAME_WE)
  add_executable(${name} ${source})
  target_link_libraries(${name} ${OpenFHE_SHARED_LIBRARIES})
endforeach()
