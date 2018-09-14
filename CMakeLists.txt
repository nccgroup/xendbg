cmake_minimum_required(VERSION 3.9)
project(xendbg)

set(CMAKE_CXX_STANDARD 17)
set(CLANG_DEFAULT_CXX_STDLIB "libc++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

# Apple clang doesn't actually support all C++17 features...
# Assume xen has been cloned into /opt
if (APPLE)
    set(CMAKE_C_COMPILER "/usr/local/opt/llvm/bin/clang")
    set(CMAKE_CXX_COMPILER "/usr/local/opt/llvm/bin/clang++")
    include_directories("/usr/local/opt/xen/tools/xenstore/include")
    include_directories("/usr/local/opt/xen/tools/libxc/include")
    include_directories("/usr/local/opt/xen/tools/libs/foreignmemory/include")
    include_directories("/usr/local/opt/xen/xen/include/public")
endif()

add_executable(xendbg main.cpp Parser/Parser.cpp
  Parser/Expression/ExpressionGeneric.hpp
  Parser/Expression/Operator/BinaryOperator.hpp
  Parser/Expression/Operator/Precedence.hpp
  Parser/Expression/Operator/UnaryOperator.hpp Parser/ParserException.hpp
  Parser/Sentinel.hpp Parser/Tokenizer.hpp Parser/Token/Variable.hpp
  Parser/Token/Label.hpp Parser/Token/Symbol.hpp Parser/Token/Match.hpp
  Parser/Predicate.hpp Util/overloaded.hpp Util/pop_ret.hpp Util/clear.hpp
  REPL/REPL.cpp REPL/REPL.hpp Xen/Domain.cpp Xen/Domain.hpp
  Xen/XenException.hpp Xen/XenStore.cpp Xen/XenStore.hpp Xen/XenCtrl.cpp
  Xen/XenCtrl.hpp Xen/XenForeignMemory.cpp Xen/XenForeignMemory.hpp
  Xen/Common.hpp Xen/BridgeHeaders/xenctrl.h
  Xen/BridgeHeaders/xenstore.h Xen/BridgeHeaders/xenforeignmemory.h
  Xen/BridgeHeaders/xenguest.h Xen/BridgeHeaders/domctl.h Xen/PrivCmd.cpp
  Xen/PrivCmd.hpp REPL/Command/Action.hpp REPL/Command/Command.cpp
  REPL/Command/Command.hpp Util/string.hpp Util/string.cpp
  REPL/Command/Verb.cpp REPL/Command/Verb.hpp REPL/Command/Argument.cpp
  REPL/Command/Argument.hpp REPL/Command/Flag.cpp REPL/Command/Flag.hpp
  REPL/Command/ArgsHandle.cpp REPL/Command/ArgsHandle.hpp
  REPL/Command/FlagsHandle.cpp REPL/Command/FlagsHandle.hpp
  REPL/Command/Match.hpp REPL/Command/Match.cpp REPL/Command/CommandBase.hpp
  REPL/Command/CommandVerb.cpp REPL/Command/CommandVerb.hpp
  REPL/Command/MakeCommand.hpp REPL/Command/MakeCommand.cpp
  Util/IndentHelper.hpp Util/IndentHelper.cpp Xen/XenHandle.hpp
  Debugger/Debugger.cpp Debugger/Debugger.hpp Parser/Token/String.hpp
  REPL/Command/MatchHelper.hpp REPL/Command/MatchHelper.cpp
  Parser/Expression/Expression.hpp Debugger/GDBStub/GDBStub.cpp
  Debugger/GDBStub/GDBStub.hpp Debugger/GDBStub/GDBPacketIO.cpp
  Debugger/GDBStub/GDBPacketIO.hpp Debugger/GDBStub/GDBResponsePacket.hpp
  Debugger/GDBStub/GDBRequestPacket.hpp Registers/RegisterContext.hpp
  Registers/Register.hpp Registers/RegistersX86_64.hpp
  Registers/RegistersX86.hpp Xen/MemoryPermissions.hpp
  Xen/MemoryPermissions.cpp)

target_link_libraries(xendbg readline xenctrl xenforeignmemory xenstore
  xenlight xlutil capstone pthread)
