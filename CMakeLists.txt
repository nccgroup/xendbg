cmake_minimum_required(VERSION 3.9)
project(xendbg)

set(CMAKE_CXX_STANDARD 17)
set(CLANG_DEFAULT_CXX_STDLIB "libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

include_directories(
  include
  third_party/CLI11/include
  third_party/ELFIO/include)

add_executable(xendbg
  src/Debugger/DebugSession.cpp
        include/Debugger/DebugSession.hpp
  src/Debugger/DebugSessionPV.cpp
        include/Debugger/DebugSessionPV.hpp
        include/GDBServer/GDBRequestPacket.hpp
        include/GDBServer/GDBResponsePacket.hpp
  src/REPL/Command/Action.hpp
  src/REPL/Command/ArgsHandle.cpp
  src/REPL/Command/ArgsHandle.hpp
  src/REPL/Command/Argument.cpp
  src/REPL/Command/Argument.hpp
  src/REPL/Command/Command.cpp
  src/REPL/Command/Command.hpp
  src/REPL/Command/CommandBase.hpp
  src/REPL/Command/CommandVerb.cpp
  src/REPL/Command/CommandVerb.hpp
  src/REPL/Command/Flag.cpp
  src/REPL/Command/Flag.hpp
  src/REPL/Command/FlagsHandle.cpp
  src/REPL/Command/FlagsHandle.hpp
  src/REPL/Command/MakeCommand.cpp
  src/REPL/Command/MakeCommand.hpp
  src/REPL/Command/Match.cpp
  src/REPL/Command/Match.hpp
  src/REPL/Command/MatchHelper.hpp
  src/REPL/Command/Verb.cpp
  src/REPL/Command/Verb.hpp
  src/REPL/Parser/Expression/Expression.hpp
  src/REPL/Parser/Expression/ExpressionGeneric.hpp
  src/REPL/Parser/Expression/Operator/BinaryOperator.hpp
  src/REPL/Parser/Expression/Operator/Precedence.hpp
  src/REPL/Parser/Expression/Operator/UnaryOperator.hpp
  src/REPL/Parser/Parser.cpp
  src/REPL/Parser/ParserException.hpp
  src/REPL/Parser/Predicate.hpp
  src/REPL/Parser/Sentinel.hpp
  src/REPL/Parser/Token/Label.hpp
  src/REPL/Parser/Token/Match.hpp
  src/REPL/Parser/Token/String.hpp
  src/REPL/Parser/Token/Symbol.hpp
  src/REPL/Parser/Token/Variable.hpp
  src/REPL/Parser/Tokenizer.hpp
  src/REPL/REPL.cpp
  src/REPL/REPL.hpp
        include/Registers/Register.hpp
        include/Registers/RegisterContext.hpp
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
  src/Xen/Domain.cpp
        include/Xen/Domain.hpp
  src/Xen/MemoryPermissions.cpp
  src/Xen/PrivCmd.cpp
        include/Xen/PrivCmd.hpp
  src/Xen/XenCtrl.cpp
        include/Xen/XenCtrl.hpp
        include/Xen/XenException.hpp
  src/Xen/XenForeignMemory.cpp
        include/Xen/XenForeignMemory.hpp
        include/Xen/XenHandle.hpp
  src/Xen/XenStore.cpp
        include/Xen/XenStore.hpp
  src/main.cpp src/Xen/XenHandle.cpp src/CommandLine.cpp src/CommandLine.hpp
  src/Debugger/DebugSession.cpp include/Debugger/DebugSession.hpp
  src/GDBServer/GDBPacketQueue.cpp include/GDBServer/GDBPacketQueue.hpp
  src/GDBServer/GDBServer.cpp include/GDBServer/GDBServer.hpp
  src/GDBServer/GDBPacketInterpreter.cpp include/GDBServer/GDBPacketInterpreter.hpp
  src/GDBServer/GDBConnection.cpp include/GDBServer/GDBConnection.hpp
  src/ServerModeController.hpp src/ServerModeController.cpp
        include/UV/UVLoop.hpp src/UV/UVLoop.cpp
        include/UV/UVIdle.hpp src/UV/UVIdle.cpp
        include/UV/UVSignal.hpp src/UV/UVSignal.cpp
        include/UV/UVPoll.hpp src/UV/UVPoll.cpp
        include/UV/UVTCP.hpp src/UV/UVTCP.cpp
        include/UV/UVTimer.hpp src/UV/UVTimer.cpp include/Registers/RegistersX86.hpp)

target_link_libraries(xendbg
  capstone
  pthread
  readline
  uv
  xenctrl
  xenforeignmemory
  xenlight
  xenstore
  xlutil)
