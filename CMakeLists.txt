cmake_minimum_required(VERSION 3.9)
project(xendbg)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release ... FORCE)
endif()

# xendbg must be built with clang/libc++; it won't compile with gcc/libstdc++.
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

set(SEC_FLAGS "-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE")
set(SEC_LINK_FLAGS "-Wl,-z,relro,-z,now,-z,noexecstack -pie")

set(WARNING_EXCEPTIONS "-Wno-unused-private-field -Wno-unused-parameter -Wno-unused-function")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcolor-diagnostics -Wall -Wextra -pedantic ${WARNING_EXCEPTIONS} -O3 ${SEC_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3") # for Valgrind
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -g3 -fsanitize=address,undefined -Wno-macro-redefined")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_REQUIRED_FLAGS -std=c++17)
set(CLANG_DEFAULT_CXX_STDLIB "libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcolor-diagnostics -stdlib=libc++ -Wall -Wextra -pedantic ${WARNING_EXCEPTIONS} -O3 ${SEC_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3") #valgrind
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -g3 -fsanitize=address,undefined -Wno-macro-redefined")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SEC_LINK_FLAGS}")

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
  c++experimental
  uv
  xencall
  xenctrl
  xendevicemodel
  xenevtchn
  xenforeignmemory
  xenlight
  xenstore
  xlutil)

install(TARGETS xendbg DESTINATION bin)
