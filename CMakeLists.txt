cmake_minimum_required(VERSION 3.9)
project(xendbg)

set(CMAKE_CXX_STANDARD 17)
set(CLANG_DEFAULT_CXX_STDLIB "libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

include_directories(
  include
  third_party/CLI11/include
  third_party/ELFIO/include
  third_party/uvw/src)

file(GLOB_RECURSE SRC_FILES src/*.cpp)
file(GLOB_RECURSE INCLUDE_FILES include/*.hpp)

add_executable(xendbg ${SRC_FILES} ${INCLUDE_FILES})

target_link_libraries(xendbg
  capstone
  pthread
  readline
  uv
  xencall
  xenctrl
  xendevicemodel
  xenevtchn
  xenforeignmemory
  xenlight
  xenstore
  xlutil)
