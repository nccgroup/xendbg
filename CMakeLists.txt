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

add_executable(xendbg
        include/Debugger/Debugger.hpp
        include/Debugger/Debugger.hpp
        include/Debugger/DebuggerPV.hpp
  include/GDBServer/GDBConnection.hpp
        include/GDBServer/GDBPacketQueue.hpp
        include/GDBServer/GDBRequest/GDBRequest.hpp
        include/GDBServer/GDBResponse/GDBResponse.hpp
        include/Registers/Register.hpp
  include/Registers/RegisterContext.hpp
  include/Registers/RegistersX86.hpp
  include/Registers/RegistersX86Any.hpp
  include/Registers/RegistersX86_64.hpp
  include/Util/clear.hpp
  include/Util/overloaded.hpp
  include/Util/pop_ret.hpp
  include/Util/string.hpp
  include/Xen/BridgeHeaders/domctl.h
  include/Xen/BridgeHeaders/xenctrl.h
  include/Xen/BridgeHeaders/xenforeignmemory.h
  include/Xen/BridgeHeaders/xenguest.h
  include/Xen/BridgeHeaders/xenstore.h
  include/Xen/Common.hpp
  include/Xen/Domain.hpp
  include/Xen/DomainAny.hpp
  include/Xen/PageTableEntry.hpp
  include/Xen/PrivCmd.hpp
  include/Xen/XenCtrl.hpp
  include/Xen/XenEventChannel.hpp
  include/Xen/XenException.hpp
  include/Xen/XenForeignMemory.hpp
  include/Xen/XenStore.hpp
  src/CommandLine.cpp
  src/CommandLine.hpp
        src/Debugger/Debugger.cpp
  src/GDBServer/GDBConnection.cpp
        src/GDBServer/GDBPacketQueue.cpp
        src/ServerModeController.cpp
        src/ServerModeController.hpp
  src/Xen/Domain.cpp
  src/Xen/DomainAny.cpp
  src/Xen/PageTableEntry.cpp
  src/Xen/PrivCmd.cpp
  src/Xen/XenCtrl.cpp
  src/Xen/XenEventChannel.cpp
  src/Xen/XenForeignMemory.cpp
  src/Xen/XenStore.cpp
  src/main.cpp
        src/Debugger/Debugger.cpp
        src/Debugger/DebuggerPV.cpp
        include/Xen/DomainPV.hpp include/Xen/DomainHVM.hpp src/Xen/DomainPV.cpp src/Xen/DomainHVM.cpp include/Xen/DomainAny.hpp src/Xen/DomainAny.cpp
        include/GDBServer/GDBPacketHandler.hpp
        src/GDBServer/GDBPacketHandler.cpp
        include/GDBServer/GDBServer.hpp
        src/GDBServer/GDBServer.cpp
        src/DebugSession.hpp
        include/GDBServer/GDBRequest/GDBRequestBase.hpp include/GDBServer/GDBRequest/GDBQueryRequest.hpp include/GDBServer/GDBRequest/GDBRegisterRequest.hpp include/GDBServer/GDBRequest/GDBMemoryRequest.hpp include/GDBServer/GDBRequest/GDBBreakpointRequest.hpp include/GDBServer/GDBRequest/GDBStepContinueRequest.hpp include/GDBServer/GDBResponse/GDBQueryResponse.hpp include/GDBServer/GDBResponse/GDBResponseBase.hpp include/GDBServer/GDBResponse/GDBRegisterResponse.hpp include/GDBServer/GDBResponse/GDBMemoryResponse.hpp)

target_link_libraries(xendbg
  capstone
  pthread
  readline
  uv
  xenctrl
  xenevtchn
  xenforeignmemory
  xenlight
  xenstore
  xlutil)
