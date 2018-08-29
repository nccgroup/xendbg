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

add_executable(xendbg
    main.cpp
    Parser/Parser.cpp
    Parser/Expression/Constant.hpp
    Parser/Expression/Expression.hpp
    Parser/Expression/Label.hpp
    Parser/Expression/Variable.hpp
    Parser/Expression/UnaryExpression.hpp
    Parser/Expression/BinaryExpression.hpp
    Parser/Operator/BinaryOperator.hpp
    Parser/Operator/Precedence.hpp
    Parser/Operator/UnaryOperator.hpp
    Parser/ParserException.hpp
    Parser/Sentinel.hpp
    Parser/Tokenizer.hpp
    Parser/Token/Constant.hpp
    Parser/Token/Variable.hpp
    Parser/Token/Label.hpp
    Parser/Token/Symbol.hpp
    Parser/Token/Match.hpp
        Parser/Predicate.hpp
    Util/overloaded.hpp
    Util/pop_ret.hpp
    Util/clear.hpp
    REPL/REPL.cpp
    REPL/REPL.hpp
        Xen/Domain.cpp
    Xen/Domain.hpp Xen/XenException.hpp Xen/XenStore.cpp Xen/XenStore.hpp
    Xen/XenCtrl.cpp Xen/XenCtrl.hpp Xen/XenForeignMemory.cpp
    Xen/XenForeignMemory.hpp Xen/Common.hpp Xen/Registers.hpp
    Xen/BridgeHeaders/xenctrl.h Xen/BridgeHeaders/xenstore.h
    Xen/BridgeHeaders/xenforeignmemory.h Xen/BridgeHeaders/xenguest.h
    Xen/BridgeHeaders/domctl.h Xen/PrivCmd.cpp Xen/PrivCmd.hpp
        REPL/Command/Action.hpp REPL/Command/Command.cpp
    REPL/Command/Command.hpp Util/string.hpp Util/string.cpp
    REPL/Command/Verb.cpp REPL/Command/Verb.hpp REPL/Command/Argument.cpp
    REPL/Command/Argument.hpp REPL/Command/Flag.cpp REPL/Command/Flag.hpp
    REPL/Command/ArgsHandle.cpp REPL/Command/ArgsHandle.hpp
    REPL/Command/FlagsHandle.cpp REPL/Command/FlagsHandle.hpp
    REPL/Command/Match.hpp REPL/Command/Match.cpp REPL/Command/CommandBase.hpp
    REPL/Command/CommandVerb.cpp REPL/Command/CommandVerb.hpp
    REPL/Command/MakeCommand.hpp REPL/Command/MakeCommand.cpp
    Util/IndentHelper.hpp Util/IndentHelper.cpp Xen/XenHandle.hpp Debugger.cpp Debugger.hpp DebuggerREPL.cpp DebuggerREPL.hpp Parser/Token/String.hpp)

target_link_libraries(xendbg readline xenctrl xenforeignmemory xenstore)
