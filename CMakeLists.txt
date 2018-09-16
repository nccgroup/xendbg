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

add_executable(xendbg main.cpp REPL/Parser/Parser.cpp
        REPL/Parser/Expression/ExpressionGeneric.hpp
        REPL/Parser/Expression/Operator/BinaryOperator.hpp
        REPL/Parser/Expression/Operator/Precedence.hpp
        REPL/Parser/Expression/Operator/UnaryOperator.hpp REPL/Parser/ParserException.hpp
        REPL/Parser/Sentinel.hpp REPL/Parser/Tokenizer.hpp REPL/Parser/Token/Variable.hpp
        REPL/Parser/Token/Label.hpp REPL/Parser/Token/Symbol.hpp REPL/Parser/Token/Match.hpp
        REPL/Parser/Predicate.hpp Util/overloaded.hpp Util/pop_ret.hpp Util/clear.hpp
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
  Debugger/Debugger.cpp Debugger/Debugger.hpp REPL/Parser/Token/String.hpp
  REPL/Command/MatchHelper.hpp REPL/Command/MatchHelper.cpp
        REPL/Parser/Expression/Expression.hpp GDBStub/GDBStub.cpp
        GDBStub/GDBStub.hpp GDBStub/GDBPacketIO.cpp
        GDBStub/GDBPacketIO.hpp GDBStub/GDBResponsePacket.hpp
        GDBStub/GDBRequestPacket.hpp Registers/RegisterContext.hpp
  Registers/Register.hpp Registers/RegistersX86_64.hpp
  Registers/RegistersX86.hpp Registers/RegisterContextIterator.hpp)

target_link_libraries(xendbg readline xenctrl xenforeignmemory xenstore
  xenlight xlutil capstone pthread)
