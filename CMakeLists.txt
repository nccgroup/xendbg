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
        include/Debugger/DebuggerPV.hpp
        src/Debugger/DebuggerPV.cpp
        include/Debugger/DebuggerHVM.hpp
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
  include/Xen/BridgeHeaders/xendevicemodel.h
  include/Xen/BridgeHeaders/xenforeignmemory.h
  include/Xen/BridgeHeaders/xenguest.h
  include/Xen/BridgeHeaders/xenstore.h
  include/Xen/Common.hpp
  include/Xen/Domain.hpp
        include/Xen/HVMMonitor.hpp
  include/Xen/PageTableEntry.hpp
  include/Xen/XenCall.hpp
  include/Xen/XenCtrl.hpp
  include/Xen/XenDeviceModel.hpp
  include/Xen/XenEventChannel.hpp
  include/Xen/XenException.hpp
  include/Xen/XenForeignMemory.hpp
  include/Xen/XenStore.hpp
  src/CommandLine.cpp
  src/CommandLine.hpp
        src/GDBServer/GDBConnection.cpp
        src/GDBServer/GDBPacketQueue.cpp
  src/GDBServer/GDBResponse/GDBResponse.cpp
        src/ServerModeController.cpp
        src/ServerModeController.hpp
  src/Xen/Domain.cpp
        src/Xen/HVMMonitor.cpp
  src/Xen/PageTableEntry.cpp
  src/Xen/XenCall.cpp
  src/Xen/XenCtrl.cpp
  src/Xen/XenDeviceModel.cpp
  src/Xen/XenEventChannel.cpp
  src/Xen/XenForeignMemory.cpp
  src/Xen/XenStore.cpp
  src/main.cpp
        include/Xen/DomainPV.hpp include/Xen/DomainHVM.hpp src/Xen/DomainPV.cpp src/Xen/DomainHVM.cpp
        include/GDBServer/GDBRequestHandler.hpp
        src/GDBServer/GDBRequestHandler.cpp
        include/GDBServer/GDBServer.hpp
        src/GDBServer/GDBServer.cpp
        src/DebugSession.cpp
        src/DebugSession.hpp
        include/GDBServer/GDBRequest/GDBRequestBase.hpp include/GDBServer/GDBRequest/GDBQueryRequest.hpp include/GDBServer/GDBRequest/GDBRegisterRequest.hpp include/GDBServer/GDBRequest/GDBMemoryRequest.hpp include/GDBServer/GDBRequest/GDBBreakpointRequest.hpp include/GDBServer/GDBRequest/GDBStepContinueRequest.hpp include/GDBServer/GDBResponse/GDBQueryResponse.hpp include/GDBServer/GDBResponse/GDBResponseBase.hpp include/GDBServer/GDBResponse/GDBRegisterResponse.hpp include/GDBServer/GDBResponse/GDBMemoryResponse.hpp src/GDBServer/GDBRequest/GDBMemoryRequest.cpp src/GDBServer/GDBRequest/GDBQueryRequest.cpp src/GDBServer/GDBRequest/GDBRegisterRequest.cpp src/GDBServer/GDBResponse/GDBMemoryResponse.cpp src/GDBServer/GDBResponse/GDBQueryResponse.cpp src/GDBServer/GDBResponse/GDBRegisterResponse.cpp include/GDBServer/GDBPacket.hpp src/GDBServer/GDBPacket.cpp src/Debugger/Debugger.cpp src/Debugger/DebuggerHVM.cpp src/Xen/Xen.cpp)

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
